from __future__ import annotations

import json
import sqlite3
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qdev_runner.claim_scope import ClaimScope, ScopedJob
from qdev_runner.models import QueuedJob
from qdev_runner.policy import PolicyError, ProjectPriorityPolicy
from qdev_runner.store import PROJECT_PRIORITY_POLICY_AUDIT, Store


def job(
    delivery: str = "delivery-1",
    job_id: int = 100,
    profile: str = "qdev-ci",
    *,
    repository: str = "belilovsky/private-repo",
    head_sha: str = "a" * 40,
    queued_at: str | None = None,
) -> QueuedJob:
    return QueuedJob(
        delivery_id=delivery,
        job_id=job_id,
        run_id=200,
        repository=repository,
        repository_id=1,
        installation_id=300,
        labels=("self-hosted", "Linux", "X64", profile),
        head_sha=head_sha,
        head_branch="main",
        payload={
            "workflow_job": {"created_at": queued_at}
        }
        if queued_at is not None
        else {},
    )


def manual_priority_policy() -> ProjectPriorityPolicy:
    return ProjectPriorityPolicy.from_data(
        {
            "schema": "qdev-runner-project-priority-v1",
            "policy_id": "manual-p0-test",
            "default_priority": 100,
            "priorities": {
                "belilovsky/qazstack": 0,
                "belilovsky/qazpipe": 1,
            },
        }
    )


def test_enqueue_is_idempotent(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job()) is True
    assert store.enqueue(job()) is False
    assert store.health()["jobs"]["pending"] == 1


def test_write_lock_retries_transient_sqlite_busy(monkeypatch: pytest.MonkeyPatch) -> None:
    class BusyThenReadyConnection:
        def __init__(self) -> None:
            self.attempts = 0

        def execute(self, statement: str) -> None:
            assert statement == "BEGIN IMMEDIATE"
            self.attempts += 1
            if self.attempts < 3:
                raise sqlite3.OperationalError("database is locked")

    connection = BusyThenReadyConnection()
    monkeypatch.setattr("qdev_runner.store.time.sleep", lambda _: None)

    Store._begin_immediate(connection)  # type: ignore[arg-type]

    assert connection.attempts == 3


def _legacy_database(path: Path) -> None:
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE jobs (
                job_id INTEGER PRIMARY KEY, delivery_id TEXT NOT NULL UNIQUE,
                run_id INTEGER NOT NULL, repository TEXT NOT NULL,
                repository_id INTEGER NOT NULL, installation_id INTEGER NOT NULL,
                labels_json TEXT NOT NULL, head_sha TEXT NOT NULL,
                head_branch TEXT NOT NULL, payload_json TEXT NOT NULL,
                status TEXT NOT NULL, worker_name TEXT, profile TEXT,
                created_at REAL NOT NULL, updated_at REAL NOT NULL,
                claimed_at REAL, completed_at REAL, result TEXT,
                attempts INTEGER NOT NULL DEFAULT 0
            );
            """
        )


def _insert_legacy_job(
    path: Path,
    *,
    job_id: int,
    created_at: float,
    updated_at: float,
    payload: dict[str, object],
) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO jobs(
                job_id, delivery_id, run_id, repository, repository_id, installation_id,
                labels_json, head_sha, head_branch, payload_json, status, created_at,
                updated_at, attempts
            ) VALUES(?,?,?,?,?,?,?,?,?,?, 'pending', ?,?,0)
            """,
            (
                job_id,
                f"legacy-{job_id}",
                200,
                "belilovsky/private-repo",
                1,
                300,
                json.dumps(["self-hosted", "Linux", "X64", "qdev-ci"]),
                "a" * 40,
                "main",
                json.dumps(payload),
                created_at,
                updated_at,
            ),
        )


def test_store_backfills_invalid_legacy_timestamp_from_signed_payload(tmp_path: Path) -> None:
    database = tmp_path / "broker.db"
    _legacy_database(database)
    payload = {"workflow_job": {"created_at": "2026-08-27T13:46:59Z"}}
    _insert_legacy_job(
        database,
        job_id=100,
        created_at=-1_000_000_000_000,
        updated_at=0,
        payload=payload,
    )

    recovered = Store(database).job(100)

    assert recovered is not None
    assert recovered["created_at"] == -1_000_000_000_000
    assert recovered["github_queued_at"] == 1787838419.0
    assert recovered["queue_time_source"] == "github_workflow_job_created_at"
    assert recovered["required_profile"] == "qdev-ci"
    with Store(database).connect() as connection:
        migration = connection.execute(
            "SELECT name FROM schema_migrations WHERE name=?",
            ("20260827_immutable_github_fifo_v1",),
        ).fetchone()
    assert migration is not None


def test_store_marks_legacy_fallback_and_accepts_minimum_timestamp(tmp_path: Path) -> None:
    database = tmp_path / "broker.db"
    _legacy_database(database)
    expected = 1_700_000_000.0
    _insert_legacy_job(
        database,
        job_id=100,
        created_at=-29_999,
        updated_at=expected,
        payload={},
    )
    _insert_legacy_job(
        database,
        job_id=101,
        created_at=-9e299,
        updated_at=expected,
        payload={"workflow_job": {"created_at": "2020-01-01T00:00:00Z"}},
    )

    store = Store(database)
    fallback = store.job(100)
    boundary = store.job(101)

    assert fallback is not None and boundary is not None
    assert fallback["github_queued_at"] == expected
    assert fallback["queue_time_source"] == "legacy_updated_at"
    assert boundary["github_queued_at"] == 1_577_836_800.0
    assert boundary["queue_time_source"] == "github_workflow_job_created_at"


def test_queue_key_is_immutable_after_acceptance(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job(queued_at="2026-08-27T13:46:59Z"))
    with store.connect() as connection:
        try:
            connection.execute("UPDATE jobs SET github_queued_at=0 WHERE job_id=100")
        except sqlite3.IntegrityError as error:
            assert "immutable queue key" in str(error)
        else:
            raise AssertionError("queue key update unexpectedly succeeded")


def test_store_repairs_pre_trigger_pending_row_without_leaving_queue_mutable(
    tmp_path: Path,
) -> None:
    database = tmp_path / "broker.db"
    store = Store(database)
    assert store.enqueue(job(queued_at="2026-08-27T13:46:59Z"))

    # Simulate a job that was received by the old ingress after the
    # immutability trigger was installed but before it supplied queue keys.
    with store.connect() as connection:
        connection.execute("DROP TRIGGER jobs_queue_key_immutable")
        connection.execute(
            """
            UPDATE jobs SET github_queued_at=NULL, queue_sequence=NULL,
                queue_time_source=NULL, required_profile=NULL
            WHERE job_id=100
            """
        )
        connection.execute(
            """
            CREATE TRIGGER jobs_queue_key_immutable
            BEFORE UPDATE OF github_queued_at, queue_sequence, queue_time_source,
                required_profile ON jobs
            FOR EACH ROW
            WHEN NEW.github_queued_at IS NOT OLD.github_queued_at
               OR NEW.queue_sequence IS NOT OLD.queue_sequence
               OR NEW.queue_time_source IS NOT OLD.queue_time_source
               OR NEW.required_profile IS NOT OLD.required_profile
            BEGIN
                SELECT RAISE(ABORT, 'immutable queue key');
            END
            """
        )

    repaired = Store(database).job(100)

    assert repaired is not None
    assert repaired["github_queued_at"] == 1787838419.0
    assert repaired["queue_sequence"] == 1
    assert repaired["queue_time_source"] == "github_workflow_job_created_at"
    assert repaired["required_profile"] == "qdev-ci"
    with (
        Store(database).connect() as connection,
        pytest.raises(sqlite3.IntegrityError, match="immutable queue key"),
    ):
        connection.execute("UPDATE jobs SET queue_sequence=2 WHERE job_id=100")


def test_claim_is_atomic_and_profile_aware(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    claimed = store.claim("worker-1", ("qdev-ci",))
    assert claimed is not None
    assert claimed["job_id"] == 100
    assert store.claim("worker-2", ("qdev-ci",)) is None


def test_scoped_claim_is_exact_fifo_and_cannot_claim_other_work(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job("first", 100, "qdev-ci", repository="belilovsky/qazagents"))
    assert store.enqueue(job("second", 101, "qdev-ci-docker", repository="belilovsky/qazagents"))
    assert store.enqueue(job("foreign", 102, "qdev-ci", repository="belilovsky/other"))
    scope = ClaimScope(
        scope_id="maturity-20260828",
        worker_name="qdev-maturity-primary",
        tier="primary",
        repository="belilovsky/qazagents",
        head_sha="a" * 40,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(ScopedJob(100, "qdev-ci"), ScopedJob(101, "qdev-ci-docker")),
    )

    first = store.claim(
        "qdev-maturity-primary", ("qdev-ci", "qdev-ci-docker"), claim_scope=scope
    )
    second = store.claim(
        "qdev-maturity-primary", ("qdev-ci", "qdev-ci-docker"), claim_scope=scope
    )

    assert first is not None and first["job_id"] == 100
    assert second is not None and second["job_id"] == 101
    assert store.job_status(102) == "pending"
    assert store.claim(
        "qdev-maturity-primary", ("qdev-ci", "qdev-ci-docker"), claim_scope=scope
    ) is None


def test_scoped_claim_rejects_wrong_sha_and_profile(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(
        job("wrong-sha", 100, "qdev-ci", repository="belilovsky/qazagents", head_sha="b" * 40)
    )
    scope = ClaimScope(
        scope_id="maturity-20260828",
        worker_name="qdev-maturity-primary",
        tier="primary",
        repository="belilovsky/qazagents",
        head_sha="a" * 40,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(ScopedJob(100, "qdev-ci-docker"),),
    )

    assert store.claim("qdev-maturity-primary", ("qdev-ci",), claim_scope=scope) is None
    assert store.job_status(100) == "pending"


def test_claim_does_not_starve_eligible_job_behind_large_ineligible_backlog(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    for index in range(101):
        assert store.enqueue(job(f"browser-{index}", index + 1, "qdev-ci-browser"))
    assert store.enqueue(job("eligible", 1000, "qdev-ci"))

    claimed = store.claim("worker-1", ("qdev-ci",))

    assert claimed is not None
    assert claimed["job_id"] == 1000


def test_claim_uses_github_fifo_within_a_profile(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job("later-delivery", 100, queued_at="2026-08-27T14:00:00Z"))
    store.enqueue(job("earlier-delivery", 101, queued_at="2026-08-27T13:00:00Z"))

    claimed = store.claim("worker-1", ("qdev-ci",))

    assert claimed is not None
    assert claimed["job_id"] == 101


def test_manual_project_priority_is_audited_without_changing_queue_keys(tmp_path: Path) -> None:
    policy = manual_priority_policy()
    store = Store(tmp_path / "broker.db", policy)
    assert store.enqueue(
        job(
            "default-earlier",
            100,
            queued_at="2026-08-27T13:00:00Z",
            repository="belilovsky/private-repo",
        )
    )
    assert store.enqueue(
        job(
            "p0-later",
            101,
            queued_at="2026-08-27T14:00:00Z",
            repository="belilovsky/qazstack",
        )
    )
    before = store.job(101)

    claimed = store.claim("worker-1", ("qdev-ci",))

    assert claimed is not None
    assert claimed["job_id"] == 101
    after = store.job(101)
    assert before is not None and after is not None
    assert (after["github_queued_at"], after["queue_sequence"]) == (
        before["github_queued_at"],
        before["queue_sequence"],
    )
    health = store.health()
    assert health["pending_by_priority"] == {"100": 1}
    assert health["project_priority_policy"]["policy_id"] == "manual-p0-test"
    with store.connect() as connection:
        audit = connection.execute(
            """
            SELECT policy_id, definition_json FROM project_priority_policy_audits
            WHERE policy_sha256=?
            """,
            (policy.sha256,),
        ).fetchone()
        migration = connection.execute(
            "SELECT name FROM schema_migrations WHERE name=?", (PROJECT_PRIORITY_POLICY_AUDIT,)
        ).fetchone()
    assert audit is not None
    assert audit["policy_id"] == "manual-p0-test"
    assert migration is not None


def test_manual_project_priority_preserves_github_fifo_inside_tier(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db", manual_priority_policy())
    store.enqueue(
        job(
            "qazpipe-earliest",
            100,
            queued_at="2026-08-27T12:00:00Z",
            repository="belilovsky/qazpipe",
        )
    )
    store.enqueue(
        job(
            "qazstack-later",
            101,
            queued_at="2026-08-27T14:00:00Z",
            repository="belilovsky/qazstack",
        )
    )
    store.enqueue(
        job(
            "qazstack-earlier",
            102,
            queued_at="2026-08-27T13:00:00Z",
            repository="belilovsky/qazstack",
        )
    )

    first = store.claim("worker-1", ("qdev-ci",))
    second = store.claim("worker-2", ("qdev-ci",))
    third = store.claim("worker-3", ("qdev-ci",))

    assert first is not None and first["job_id"] == 102
    assert second is not None and second["job_id"] == 101
    assert third is not None and third["job_id"] == 100


def test_project_priority_policy_rejects_invalid_priority() -> None:
    with pytest.raises(PolicyError, match="non-negative integer"):
        ProjectPriorityPolicy.from_data(
            {
                "schema": "qdev-runner-project-priority-v1",
                "policy_id": "invalid",
                "default_priority": -1,
                "priorities": {},
            }
        )


def test_project_priority_audit_is_immutable(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db", manual_priority_policy())
    with store.connect() as connection, pytest.raises(
        sqlite3.IntegrityError, match="project-priority policy audit is immutable"
    ):
        connection.execute("UPDATE project_priority_policy_audits SET policy_id='changed'")


def test_claim_reserves_profile_disk_above_worker_floor(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job(profile="qdev-ci-docker"))
    store.enqueue(job("delivery-2", 101, "qdev-ci"))

    claimed = store.claim(
        "primary-1",
        ("qdev-ci-docker", "qdev-ci"),
        disk_free_gib=45,
        min_disk_free_gib=30,
        profile_disk_mb={"qdev-ci": 12288, "qdev-ci-docker": 20480},
    )

    assert claimed is not None
    assert claimed["job_id"] == 101


def test_reserve_claims_profile_that_primary_cannot_fit(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job(profile="qdev-ci-docker"))
    store.heartbeat(
        "primary-1",
        ("qdev-ci-docker",),
        0,
        (),
        {
            "tier": "primary",
            "allowed": True,
            "concurrency": 1,
            "disk_free_gib": 45,
            "min_disk_free_gib": 30,
        },
    )

    claimed = store.claim(
        "reserve-1",
        ("qdev-ci-docker",),
        tier="reserve",
        disk_free_gib=60,
        min_disk_free_gib=30,
        profile_disk_mb={"qdev-ci-docker": 20480},
    )

    assert claimed is not None
    assert claimed["job_id"] == 100


def test_reserve_waits_when_primary_has_profile_headroom(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job(profile="qdev-ci-docker"))
    store.heartbeat(
        "primary-1",
        ("qdev-ci-docker",),
        0,
        (),
        {
            "tier": "primary",
            "allowed": True,
            "concurrency": 1,
            "disk_free_gib": 55,
            "min_disk_free_gib": 30,
        },
    )

    assert (
        store.claim(
            "reserve-1",
            ("qdev-ci-docker",),
            tier="reserve",
            disk_free_gib=60,
            min_disk_free_gib=30,
            profile_disk_mb={"qdev-ci-docker": 20480},
        )
        is None
    )


def test_completed_job_is_not_overwritten_by_late_worker_failure(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("worker-1", ("qdev-ci",))
    store.set_status(100, "running")
    store.complete_from_webhook(100, "cancelled")
    assert store.job_status(100) == "completed"
    assert store.fail_if_active(100, "late container exit") is False
    assert store.job_status(100) == "completed"


def test_runner_exit_before_pickup_requeues_active_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("worker-1", ("qdev-ci",))
    store.set_status(100, "running")
    assert store.requeue_active(100, "runner exited before pickup") is True
    assert store.job_status(100) == "pending"
    assert store.claim("worker-2", ("qdev-ci",)) is None
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET retry_not_before=0 WHERE job_id=100")
    assert store.claim("worker-2", ("qdev-ci",)) is not None


def test_requeue_restores_pending_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job(queued_at="2026-08-27T13:46:59Z"))
    store.enqueue(job("delivery-2", 101, queued_at="2026-08-27T13:47:00Z"))
    original = store.job(100)
    assert original is not None
    store.claim("worker-1", ("qdev-ci",))
    store.requeue(100, "temporary GitHub error")
    restored = store.job(100)
    assert restored is not None
    assert (restored["github_queued_at"], restored["queue_sequence"]) == (
        original["github_queued_at"],
        original["queue_sequence"],
    )
    claimed = store.claim("worker-2", ("qdev-ci",))
    assert claimed is not None
    assert claimed["job_id"] == 101
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET retry_not_before=0 WHERE job_id=100")
    retried = store.claim("worker-3", ("qdev-ci",))
    assert retried is not None
    assert retried["job_id"] == 100


def test_busy_primary_does_not_block_reserve_and_renews_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("primary-1", ("qdev-ci",))
    store.heartbeat(
        "primary-1",
        ("qdev-ci",),
        1,
        (100,),
        {"tier": "primary", "concurrency": 1},
    )
    assert not store.has_available_tier_slot("primary", 90)
    assert store.recover_stale_jobs(300) == 0


def test_idle_primary_blocks_reserve(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.heartbeat(
        "primary-1",
        ("qdev-ci",),
        0,
        (),
        {"tier": "primary", "concurrency": 1},
    )
    assert store.has_available_tier_slot("primary", 90)


def test_capacity_blocked_primary_does_not_block_reserve(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.heartbeat(
        "primary-1",
        ("qdev-ci",),
        0,
        (),
        {"tier": "primary", "allowed": False, "blockers": ["load_15"]},
    )
    assert not store.has_available_tier_slot("primary", 90)
    worker = store.health()["workers"][0]
    assert worker["available"] is False
    assert worker["capacity_allowed"] is False


def test_health_distinguishes_capacity_from_free_slots(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.heartbeat(
        "primary-1",
        ("qdev-ci",),
        1,
        (),
        {"tier": "primary", "allowed": True, "concurrency": 2},
    )
    worker = store.health()["workers"][0]
    assert worker["capacity_allowed"] is True
    assert worker["concurrency"] == 2
    assert worker["slots_available"] == 1
    assert worker["available"] is True


def test_health_exposes_profile_queue_and_block_reason(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job(profile="qdev-ci-browser", queued_at="2026-08-27T13:00:00Z"))
    store.heartbeat(
        "light-1",
        ("qdev-ci",),
        2,
        (),
        {"tier": "primary", "allowed": True, "concurrency": 2},
    )

    health = store.health()

    assert health["pending_by_profile"] == {"qdev-ci-browser": 1}
    assert health["available_slots_by_profile"] == {"qdev-ci-browser": 0}
    assert health["blocked_profiles"] == {
        "qdev-ci-browser": "no_fresh_compatible_worker"
    }
    assert health["oldest_pending_age_seconds"] is not None


def test_stale_worker_job_is_recovered(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("lost-worker", ("qdev-ci",))
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET updated_at=? WHERE job_id=100", (time.time() - 600,))
    assert store.recover_stale_jobs(300) == 1
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET retry_not_before=0 WHERE job_id=100")
    assert store.claim("reserve-1", ("qdev-ci",)) is not None


def test_heartbeat_requeues_jobs_worker_no_longer_reports(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("primary-1", ("qdev-ci",))
    store.set_status(100, "running")
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET updated_at=? WHERE job_id=100", (time.time() - 60,))
    store.heartbeat("primary-1", ("qdev-ci",), 0, (), {"tier": "primary"})
    assert store.job_status(100) == "pending"


def test_heartbeat_renews_only_reported_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("primary-1", ("qdev-ci",))
    store.set_status(100, "running")
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET updated_at=? WHERE job_id=100", (time.time() - 60,))
    store.heartbeat("primary-1", ("qdev-ci",), 1, (100,), {"tier": "primary"})
    assert store.job_status(100) == "running"
