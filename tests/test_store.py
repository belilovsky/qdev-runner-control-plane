from __future__ import annotations

import time
from pathlib import Path

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


def test_enqueue_is_idempotent(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job()) is True
    assert store.enqueue(job()) is False
    assert store.health()["jobs"]["pending"] == 1


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
    store.heartbeat("primary-1", ("qdev-ci",), 1, {"tier": "primary"})
    assert store.has_fresh_tier("primary", 90)
    assert store.recover_stale_jobs(300) == 0


def test_capacity_blocked_primary_does_not_block_reserve(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.heartbeat(
        "primary-1",
        ("qdev-ci",),
        0,
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
        connection.execute(
            "UPDATE jobs SET updated_at=? WHERE job_id=100", (time.time() - 600,)
        )
    assert store.recover_stale_jobs(300) == 1
    assert store.claim("reserve-1", ("qdev-ci",)) is not None
