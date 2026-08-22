from __future__ import annotations

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


def test_requeue_restores_pending_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.claim("worker-1", ("qdev-ci",))
    store.requeue(100, "temporary GitHub error")
    assert store.claim("worker-2", ("qdev-ci",)) is not None
