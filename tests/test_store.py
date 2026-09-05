from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qdev_runner.claim_scope import SCHEMA_V2, ClaimScope, ScopedFifoSkip, ScopedJob
from qdev_runner.models import QueuedJob
from qdev_runner.store import MINIMUM_QUEUE_TIMESTAMP, Store


def job(
    delivery: str = "delivery-1",
    job_id: int = 100,
    profile: str = "qdev-ci",
    *,
    repository: str = "belilovsky/private-repo",
    head_sha: str = "a" * 40,
    run_id: int = 200,
    attempt: int = 1,
) -> QueuedJob:
    return QueuedJob(
        delivery_id=delivery,
        job_id=job_id,
        run_id=run_id,
        repository=repository,
        repository_id=1,
        installation_id=300,
        labels=("self-hosted", "Linux", "X64", profile),
        head_sha=head_sha,
        head_branch="main",
        payload={"workflow_job": {"run_attempt": attempt}},
    )


def test_enqueue_is_idempotent(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job()) is True
    assert store.enqueue(job()) is False
    assert store.health()["jobs"]["pending"] == 1


def test_coverage_baseline_is_immutable_and_idempotent(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    values = {
        "repository": "belilovsky/private-repo",
        "ref": "main",
        "metric": "line",
        "scope": "src",
        "commit_sha": "a" * 40,
        "covered": 7,
        "denominator": 10,
        "measured_at": "2026-09-04T00:00:00Z",
    }
    first, idempotent = store.record_coverage_baseline(**values)
    assert first["percentage"] == 70.0
    assert idempotent is False
    duplicate, idempotent = store.record_coverage_baseline(**values)
    assert duplicate["id"] == first["id"]
    assert idempotent is True
    try:
        store.record_coverage_baseline(**{**values, "covered": 8})
    except ValueError as error:
        assert "conflicting" in str(error)
    else:  # pragma: no cover - defensive assertion
        raise AssertionError("conflicting baseline was accepted")


def test_store_repairs_invalid_legacy_queue_timestamp_from_workflow_payload(tmp_path: Path) -> None:
    database = tmp_path / "broker.db"
    store = Store(database)
    assert store.enqueue(job()) is True
    payload = {"workflow_job": {"created_at": "2026-08-27T13:46:59Z"}}
    with store.connect() as connection:
        connection.execute(
            "UPDATE jobs SET created_at=?, payload_json=? WHERE job_id=?",
            (-1_000_000_000_000, json.dumps(payload), 100),
        )

    repaired = Store(database).job(100)

    assert repaired is not None
    assert repaired["created_at"] == 1787838419.0


def test_store_repairs_invalid_legacy_queue_timestamp_from_updated_at(tmp_path: Path) -> None:
    database = tmp_path / "broker.db"
    store = Store(database)
    assert store.enqueue(job()) is True
    expected = time.time()
    with store.connect() as connection:
        connection.execute(
            "UPDATE jobs SET created_at=?, updated_at=? WHERE job_id=?",
            (-29_999, expected, 100),
        )

    repaired = Store(database).job(100)

    assert repaired is not None
    assert repaired["created_at"] == expected


def test_claim_is_atomic_and_profile_aware(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    claimed = store.claim("worker-1", ("qdev-ci",))
    assert claimed is not None
    assert claimed["job_id"] == 100
    assert store.claim("worker-2", ("qdev-ci",)) is None


def test_repository_bound_claim_cannot_leapfrog_profile_fifo(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job("foreign", 100, repository="belilovsky/qazstack"))
    assert store.enqueue(job("target", 101, repository="belilovsky/qazlake"))

    claimed = store.claim(
        "worker-1",
        ("qdev-ci",),
        repository="belilovsky/qazlake",
    )

    assert claimed is None
    assert store.job_status(100) == "pending"
    assert store.job_status(101) == "pending"

    head = store.claim(
        "worker-1",
        ("qdev-ci",),
        repository="belilovsky/qazstack",
    )
    assert head is not None
    assert head["job_id"] == 100


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

    first = store.claim("qdev-maturity-primary", ("qdev-ci", "qdev-ci-docker"), claim_scope=scope)
    second = store.claim("qdev-maturity-primary", ("qdev-ci", "qdev-ci-docker"), claim_scope=scope)

    assert first is not None and first["job_id"] == 100
    assert second is not None and second["job_id"] == 101
    assert store.job(100)["claim_scope_id"] == scope.scope_id
    assert store.job(101)["claim_scope_id"] == scope.scope_id
    assert store.job_status(102) == "pending"
    assert (
        store.claim("qdev-maturity-primary", ("qdev-ci", "qdev-ci-docker"), claim_scope=scope)
        is None
    )


def test_scoped_claim_follows_allowlist_order_not_queue_arrival_order(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job("second", 101, "qdev-ci-docker", repository="belilovsky/qazagents"))
    assert store.enqueue(job("first", 100, "qdev-ci", repository="belilovsky/qazagents"))
    scope = ClaimScope(
        scope_id="maturity-20260828",
        worker_name="qdev-maturity-primary",
        tier="primary",
        repository="belilovsky/qazagents",
        head_sha="a" * 40,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(ScopedJob(100, "qdev-ci"), ScopedJob(101, "qdev-ci-docker")),
    )

    first = store.claim("qdev-maturity-primary", ("qdev-ci", "qdev-ci-docker"), claim_scope=scope)
    second = store.claim("qdev-maturity-primary", ("qdev-ci", "qdev-ci-docker"), claim_scope=scope)

    assert first is not None and first["job_id"] == 100
    assert second is not None and second["job_id"] == 101


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


def test_v2_scope_preserves_fifo_within_a_profile(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job("older", 100, repository="belilovsky/qazlake", head_sha="a" * 40))
    assert store.enqueue(
        job(
            "authorized-later",
            101,
            repository="belilovsky/qazstack",
            head_sha="b" * 40,
            run_id=201,
        )
    )
    scope = ClaimScope(
        scope_id="portfolio-20260901",
        worker_name="qdev-portfolio-primary",
        tier="primary",
        repository=None,
        head_sha=None,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(
            ScopedJob(
                101,
                "qdev-ci",
                repository="belilovsky/qazstack",
                run_id=201,
                attempt=1,
                exact_sha="b" * 40,
            ),
        ),
        schema=SCHEMA_V2,
    )

    assert store.claim("qdev-portfolio-primary", ("qdev-ci",), claim_scope=scope) is None
    assert store.job_status(100) == "pending"
    assert store.job_status(101) == "pending"


def test_exact_capacity_directive_uses_fifo_within_its_validated_tuple(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job("inadmissible-older", 100, repository="belilovsky/other"))
    assert store.enqueue(
        job(
            "authorized-later",
            101,
            repository="belilovsky/platform-portal",
            head_sha="b" * 40,
            run_id=201,
        )
    )
    scope = ClaimScope(
        scope_id="platform-contract-20260905",
        worker_name="qdev-platform-primary",
        tier="primary",
        repository=None,
        head_sha=None,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(
            ScopedJob(
                101,
                "qdev-ci",
                repository="belilovsky/platform-portal",
                run_id=201,
                attempt=1,
                exact_sha="b" * 40,
            ),
        ),
        schema=SCHEMA_V2,
    )

    claimed = store.claim(
        "qdev-platform-primary",
        ("qdev-ci",),
        claim_scope=scope,
        repository="belilovsky/platform-portal",
        head_sha="b" * 40,
    )

    assert claimed is not None
    assert claimed["job_id"] == 101
    assert store.job_status(100) == "pending"


def test_fifo_skip_requires_an_exact_v2_scope(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job("older", 100))

    with pytest.raises(ValueError, match="FIFO skips require an exact v2 claim scope"):
        store.claim("worker-1", ("qdev-ci",), fifo_skip_job_ids=frozenset({100}))


def test_v2_scope_can_skip_only_an_exact_signed_stale_fifo_tuple(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(
        job(
            "stale-admin-row",
            100,
            repository="belilovsky/qazposter",
            head_sha="a" * 40,
            run_id=200,
        )
    )
    assert store.enqueue(
        job(
            "authorized-later",
            101,
            repository="belilovsky/qazstack",
            head_sha="b" * 40,
            run_id=201,
        )
    )
    scope = ClaimScope(
        scope_id="portfolio-20260901",
        worker_name="qdev-portfolio-primary",
        tier="primary",
        repository="belilovsky/qazstack",
        head_sha="b" * 40,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(
            ScopedJob(
                101,
                "qdev-ci",
                repository="belilovsky/qazstack",
                run_id=201,
                attempt=1,
                exact_sha="b" * 40,
            ),
        ),
        schema=SCHEMA_V2,
        fifo_skipped=(
            ScopedFifoSkip(
                job_id=100,
                profile="qdev-ci",
                repository="belilovsky/qazposter",
                run_id=200,
                attempt=1,
                exact_sha="a" * 40,
                managed_registry_entry="qazposter",
                reason="admin-platform-candidate-not-active",
            ),
        ),
    )

    claimed = store.claim("qdev-portfolio-primary", ("qdev-ci",), claim_scope=scope)

    assert claimed is not None
    assert claimed["job_id"] == 101
    assert store.job_status(100) == "pending"


def test_v2_scope_tampered_fifo_skip_tuple_does_not_bypass_head(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job("older", 100, repository="belilovsky/qazposter", run_id=200))
    assert store.enqueue(
        job(
            "authorized-later",
            101,
            repository="belilovsky/qazstack",
            head_sha="b" * 40,
            run_id=201,
        )
    )
    scope = ClaimScope(
        scope_id="portfolio-20260901",
        worker_name="qdev-portfolio-primary",
        tier="primary",
        repository="belilovsky/qazstack",
        head_sha="b" * 40,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(
            ScopedJob(
                101,
                "qdev-ci",
                repository="belilovsky/qazstack",
                run_id=201,
                attempt=1,
                exact_sha="b" * 40,
            ),
        ),
        schema=SCHEMA_V2,
        fifo_skipped=(
            ScopedFifoSkip(
                job_id=100,
                profile="qdev-ci",
                repository="belilovsky/qazposter",
                run_id=200,
                attempt=2,
                exact_sha="a" * 40,
                managed_registry_entry="qazposter",
                reason="admin-platform-candidate-not-active",
            ),
        ),
    )

    assert store.claim("qdev-portfolio-primary", ("qdev-ci",), claim_scope=scope) is None
    assert store.job_status(100) == "pending"
    assert store.job_status(101) == "pending"


def test_v2_scope_rejects_a_different_run_attempt(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(
        job(
            repository="belilovsky/qazlake",
            head_sha="a" * 40,
            run_id=200,
            attempt=2,
        )
    )
    scope = ClaimScope(
        scope_id="portfolio-20260901",
        worker_name="qdev-portfolio-primary",
        tier="primary",
        repository=None,
        head_sha=None,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(
            ScopedJob(
                100,
                "qdev-ci",
                repository="belilovsky/qazlake",
                run_id=200,
                attempt=1,
                exact_sha="a" * 40,
            ),
        ),
        schema=SCHEMA_V2,
    )

    assert store.claim("qdev-portfolio-primary", ("qdev-ci",), claim_scope=scope) is None
    assert store.job_status(100) == "pending"


def test_requeue_clears_scope_binding_before_a_job_can_return_to_fifo(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job(repository="belilovsky/qazagents"))
    scope = ClaimScope(
        scope_id="maturity-20260828",
        worker_name="qdev-maturity-primary",
        tier="primary",
        repository="belilovsky/qazagents",
        head_sha="a" * 40,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(ScopedJob(100, "qdev-ci"),),
    )

    assert store.claim("qdev-maturity-primary", ("qdev-ci",), claim_scope=scope) is not None
    assert store.requeue_active(100, "worker exited")
    released = store.job(100)
    assert released is not None
    assert released["status"] == "pending"
    assert released["claim_scope_id"] is None


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


def test_claim_repairs_late_invalid_timestamp_without_reordering_valid_jobs(
    tmp_path: Path,
) -> None:
    database = tmp_path / "broker.db"
    store = Store(database)
    assert store.enqueue(job("valid", 100))
    assert store.enqueue(job("invalid", 101))
    payload = {"workflow_job": {"created_at": "2099-01-01T00:00:00Z"}}
    with store.connect() as connection:
        connection.execute(
            "UPDATE jobs SET created_at=?, payload_json=? WHERE job_id=?",
            (MINIMUM_QUEUE_TIMESTAMP, json.dumps(payload), 101),
        )

    claimed = store.claim("worker-1", ("qdev-ci",))

    assert claimed is not None
    assert claimed["job_id"] == 100
    repaired = store.job(101)
    assert repaired is not None
    assert repaired["created_at"] == 4070908800.0


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


def test_repository_disk_override_does_not_lower_other_repository_reservation(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(
        job(
            "qazshield",
            100,
            "qdev-ci-docker",
            repository="belilovsky/qazshield",
        )
    )
    assert store.enqueue(
        job(
            "other",
            101,
            "qdev-ci-docker",
            repository="belilovsky/other",
        )
    )
    profile_disk_mb = {"qdev-ci-docker": 20480}
    repository_profile_disk_mb = {
        ("belilovsky/qazshield", "qdev-ci-docker"): 15360
    }

    claimed = store.claim(
        "primary-1",
        ("qdev-ci-docker",),
        disk_free_gib=22,
        min_disk_free_gib=6.5,
        profile_disk_mb=profile_disk_mb,
        repository_profile_disk_mb=repository_profile_disk_mb,
    )

    assert claimed is not None
    assert claimed["job_id"] == 100
    assert (
        store.claim(
            "primary-1",
            ("qdev-ci-docker",),
            disk_free_gib=22,
            min_disk_free_gib=6.5,
            profile_disk_mb=profile_disk_mb,
            repository_profile_disk_mb=repository_profile_disk_mb,
        )
        is None
    )
    assert store.job_status(101) == "pending"


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
    assert store.claim("worker-2", ("qdev-ci",)) is not None


def test_requeue_restores_pending_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.enqueue(job("delivery-2", 101))
    store.claim("worker-1", ("qdev-ci",))
    store.requeue(100, "temporary GitHub error")
    claimed = store.claim("worker-2", ("qdev-ci",))
    assert claimed is not None
    assert claimed["job_id"] == 100


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
    assert store.stale_jobs(300) == []


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


def test_stale_worker_job_is_recovered(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("lost-worker", ("qdev-ci",))
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET updated_at=? WHERE job_id=100", (time.time() - 600,))
    stale = store.stale_jobs(300)
    assert [row["job_id"] for row in stale] == [100]
    assert store.release_stale_job(100, "provider reconciled", 300) is True
    assert store.claim("reserve-1", ("qdev-ci",)) is not None


def test_fresh_idle_worker_orphaned_claim_is_recoverable(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("primary-1", ("qdev-ci",))
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET updated_at=? WHERE job_id=100", (time.time() - 600,))
    store.heartbeat("primary-1", ("qdev-ci",), 0, (), {"tier": "primary"})
    stale = store.stale_jobs(300)
    assert [row["job_id"] for row in stale] == [100]
    assert store.release_stale_job(100, "worker no longer reports job", 300) is True
    assert store.job_status(100) == "pending"


def test_failed_worker_job_is_released_atomically_without_losing_fifo(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("primary-1", ("qdev-ci",))
    assert store.fail_if_active(100, "worker=primary-1 exit=143 capacity expiry") is True
    failed = store.failed_worker_jobs()
    assert [row["job_id"] for row in failed] == [100]
    original = failed[0]

    assert store.release_failed_job(
        100,
        "provider reconciled queued",
        expected_updated_at=float(original["updated_at"]),
    ) is True
    released = store.job(100)
    assert released is not None
    assert released["status"] == "pending"
    assert released["completed_at"] is None
    assert float(released["created_at"]) == float(original["created_at"])
    assert store.release_failed_job(
        100,
        "must not release twice",
        expected_updated_at=float(original["updated_at"]),
    ) is False


def test_non_worker_failure_is_not_recoverable_as_failed_worker_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("primary-1", ("qdev-ci",))
    store.set_status(100, "failed", "policy failure")

    assert store.failed_worker_jobs() == []


def test_heartbeat_does_not_requeue_jobs_worker_no_longer_reports(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("primary-1", ("qdev-ci",))
    store.set_status(100, "running")
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET updated_at=? WHERE job_id=100", (time.time() - 60,))
    store.heartbeat("primary-1", ("qdev-ci",), 0, (), {"tier": "primary"})
    assert store.job_status(100) == "running"


def test_heartbeat_renews_only_reported_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("primary-1", ("qdev-ci",))
    store.set_status(100, "running")
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET updated_at=? WHERE job_id=100", (time.time() - 60,))
    store.heartbeat("primary-1", ("qdev-ci",), 1, (100,), {"tier": "primary"})
    assert store.job_status(100) == "running"
