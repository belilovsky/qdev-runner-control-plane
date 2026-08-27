from __future__ import annotations

import json
import time
from pathlib import Path

from qdev_runner.models import QueuedJob
from qdev_runner.store import Store


def job(
    delivery: str = "delivery-1", job_id: int = 100, profile: str = "qdev-ci"
) -> QueuedJob:
    return QueuedJob(
        delivery_id=delivery,
        job_id=job_id,
        run_id=200,
        repository="belilovsky/private-repo",
        repository_id=1,
        installation_id=300,
        labels=("self-hosted", "Linux", "X64", profile),
        head_sha="a" * 40,
        head_branch="main",
        payload={},
    )


def test_enqueue_is_idempotent(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job()) is True
    assert store.enqueue(job()) is False
    assert store.health()["jobs"]["pending"] == 1


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
    assert store.claim("worker-2", ("qdev-ci",)) is not None


def test_requeue_restores_pending_job(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    store.enqueue(job("delivery-2", 101))
    store.claim("worker-1", ("qdev-ci",))
    store.requeue(100, "temporary GitHub error")
    claimed = store.claim("worker-2", ("qdev-ci",))
    assert claimed is not None
    assert claimed["job_id"] == 101


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
