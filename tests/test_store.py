from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from qdev_runner.models import QueuedJob
from qdev_runner.store import Store


def job(delivery: str = "delivery-1") -> QueuedJob:
    return QueuedJob(
        delivery_id=delivery,
        job_id=100,
        run_id=200,
        repository="belilovsky/private-repo",
        repository_id=1,
        installation_id=300,
        labels=("self-hosted", "Linux", "X64", "qdev-ci"),
        head_sha="a" * 40,
        head_branch="main",
        payload={},
    )


def _report(
    *,
    status: str = "passed",
    job_id: int = 100,
    attempt: int = 1,
    commit_sha: str = "a" * 40,
) -> dict[str, object]:
    failed = 1 if status == "failed" else 0
    executed = 0 if status == "not_run" else 2
    total = 0 if status == "not_run" else 2
    return {
        "schema": "qdev-test-run-v1",
        "contract_version": 1,
        "project": "private-repo",
        "repository": "belilovsky/private-repo",
        "commit_sha": commit_sha,
        "suite": "unit",
        "workflow": "tests.yml",
        "job_id": job_id,
        "attempt": attempt,
        "execution": {
            "environment": "self-hosted:qdev-ci",
            "started_at": "2026-09-04T00:00:00Z",
            "finished_at": "2026-09-04T00:00:03Z",
            "status": "completed",
        },
        "result": {
            "status": status,
            "total": total,
            "executed": executed,
            "failed": failed,
            "skipped": 0,
        },
        "coverage": [{"status": "unknown"}],
        "critical_scenarios": [],
        "reports": [],
        "flags": {"flaky": False, "quarantined": False},
    }


def test_enqueue_is_idempotent(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job()) is True
    assert store.enqueue(job()) is False
    assert store.health()["jobs"]["pending"] == 1


def test_concurrent_broker_startup_serializes_legacy_migrations(tmp_path: Path) -> None:
    database = tmp_path / "broker.db"

    def start_broker() -> dict[str, object]:
        return Store(database).health()

    with ThreadPoolExecutor(max_workers=2) as executor:
        health = list(executor.map(lambda _index: start_broker(), range(2)))

    assert len(health) == 2
    assert all(item["jobs"].get("pending", 0) == 0 for item in health)


def test_claim_is_atomic_and_profile_aware(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    claimed = store.claim("worker-1", ("qdev-ci",))
    assert claimed is not None
    assert claimed["job_id"] == 100
    assert store.claim("worker-2", ("qdev-ci",)) is None


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


def test_infrastructure_recovery_is_limited_to_one_retry(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("worker-1", ("qdev-ci",))
    store.set_status(100, "running")
    assert store.requeue_infrastructure(100, "runner setup failed") is True
    assert store.job(100)["infra_retries"] == 1
    store.claim("worker-2", ("qdev-ci",))
    assert store.requeue_infrastructure(100, "runner setup failed again") is True
    assert store.job_status(100) == "failed"
    assert store.claim("worker-3", ("qdev-ci",)) is None


def test_requeue_restores_pending_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("worker-1", ("qdev-ci",))
    store.requeue(100, "temporary GitHub error")
    assert store.claim("worker-2", ("qdev-ci",)) is not None


def test_primary_heartbeat_blocks_reserve_and_renews_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("primary-1", ("qdev-ci",))
    store.heartbeat("primary-1", ("qdev-ci",), 1, (100,), {"tier": "primary"})
    assert store.has_fresh_tier("primary", 90)
    assert store.recover_stale_jobs(300) == 0


def test_capacity_blocked_primary_does_not_block_reserve(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.heartbeat(
        "primary-1",
        ("qdev-ci",),
        0,
        (),
        {"tier": "primary", "allowed": False, "blockers": ["load_15"]},
    )
    assert not store.has_fresh_tier("primary", 90)
    worker = store.health()["workers"][0]
    assert worker["available"] is False


def test_stale_worker_job_is_recovered(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("lost-worker", ("qdev-ci",))
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET updated_at=? WHERE job_id=100", (time.time() - 600,))
    assert store.recover_stale_jobs(300) == 1
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


def test_test_result_delivery_is_idempotent_and_conflicts_are_rejected(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    first, idempotent = store.record_test_run(_report(), "d" * 64)
    assert first["test_status"] == "passed"
    assert idempotent is False
    second, idempotent = store.record_test_run(_report(), "d" * 64)
    assert second["id"] == first["id"]
    assert idempotent is True
    with pytest.raises(ValueError, match="conflicting"):
        store.record_test_run(_report(status="failed"), "e" * 64)


def test_retry_guard_can_be_rearmed_after_a_new_receipt(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.request_test_retry(100, "operator@example.test") is True
    assert store.request_test_retry(100, "operator@example.test") is False
    store.clear_test_retry(100)
    assert store.request_test_retry(100, "operator@example.test") is True


def test_test_summary_keeps_not_run_and_project_latest(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.record_test_run(_report(), "a" * 64)
    store.record_test_run(_report(status="not_run", attempt=2), "b" * 64)
    summary = store.test_summary()
    assert summary["runs_total"] == 2
    assert summary["passed"] == 1
    assert summary["not_run"] == 1
    assert summary["projects"][0]["latest"][0]["attempt"] == 2
    assert [item["attempt"] for item in summary["projects"][0]["history"]] == [2, 1]
    assert "payload" not in summary["projects"][0]["history"][0]


def test_expired_quarantine_is_exposed_as_blocked_quality(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.record_test_run(
        _report(
            commit_sha="b" * 40,
        )
        | {
            "flags": {
                "flaky": True,
                "quarantined": True,
                "quarantine_reason": "intermittent dependency",
                "quarantine_owner": "qa@example.invalid",
                "quarantine_until": "2020-01-01T00:00:00Z",
            }
        },
        "c" * 64,
    )
    project = store.test_summary()["projects"][0]
    assert project["latest"][0]["quality_status"] == "blocked"
    assert project["latest"][0]["quarantine_expired"] is True
    assert project["history"][0]["quality_status"] == "blocked"
    assert store.test_summary()["blocked"] == 1


def test_test_summary_includes_next_schedule_without_a_run(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.upsert_test_schedule(
        repository="belilovsky/private-repo",
        workflow=".github/workflows/tests.yml",
        suite="unit",
        installation_id=300,
        ref="main",
        interval_seconds=60,
        next_run_at=100,
    )
    summary = store.test_summary()
    project = summary["projects"][0]
    assert project["latest"] == []
    assert project["history"] == []
    assert project["next_run_at"] == 100
    assert project["schedules"][0]["suite"] == "unit"


def test_test_schedule_claim_advances_once_and_survives_reload(tmp_path: Path) -> None:
    database = tmp_path / "broker.db"
    store = Store(database)
    created = store.upsert_test_schedule(
        repository="belilovsky/private-repo",
        workflow=".github/workflows/tests.yml",
        suite="unit",
        installation_id=300,
        ref="main",
        interval_seconds=60,
        next_run_at=100,
    )
    assert created["next_run_at"] == 100
    assert len(store.due_test_schedules(now=100)) == 1
    claimed = store.claim_test_schedule(
        repository="belilovsky/private-repo",
        workflow=".github/workflows/tests.yml",
        suite="unit",
        ref="main",
        now=100,
    )
    assert claimed is not None
    assert claimed["next_run_at"] == 160
    assert (
        store.claim_test_schedule(
            repository="belilovsky/private-repo",
            workflow=".github/workflows/tests.yml",
            suite="unit",
            ref="main",
            now=100,
        )
        is None
    )
    reloaded = Store(database)
    assert reloaded.due_test_schedules(now=159) == []
    assert len(reloaded.due_test_schedules(now=160)) == 1
