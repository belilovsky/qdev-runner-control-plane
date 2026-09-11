"""Acceptance checks that close the 2026-09-11 four-VPS CI incident.

These tests exercise the queue guarantees the incident mandate calls out
explicitly and that were not yet pinned by the existing suite: broker restart
without queue loss or duplicate claims, reserve failover when the primary
heartbeat is stale, and the slot gate that keeps one worker from taking a
second job above its concurrency.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from qdev_runner.claim_scope import SCHEMA_V2, ClaimScope, ScopedJob
from qdev_runner.models import QueuedJob
from qdev_runner.store import Store


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


def _heartbeat(
    store: Store,
    name: str,
    profiles: tuple[str, ...],
    *,
    active_jobs: int,
    tier: str = "primary",
    concurrency: int = 1,
    scope_id: str | None = None,
) -> None:
    capacity = {
        "allowed": True,
        "disk_free_gib": 64.0,
        "disk_used_pct": 50.0,
        "blockers": [],
    }
    detail: dict[str, object] = {
        **capacity,
        "tier": tier,
        "raw_capacity": capacity,
        "baseline_capacity": capacity,
        "effective_capacity": capacity,
        "effective_profiles": list(profiles),
        "concurrency": concurrency,
        "slots_available": max(concurrency - active_jobs, 0),
        "min_disk_free_gib": 30.0,
    }
    if scope_id is not None:
        detail["configured_claim_scope_id"] = scope_id
    store.heartbeat(name, profiles, active_jobs, (), detail)


def test_restart_preserves_pending_fifo_and_never_double_claims(tmp_path: Path) -> None:
    database = tmp_path / "broker.db"
    store = Store(database)
    assert store.enqueue(job("first", 100))
    assert store.enqueue(job("second", 101))
    assert store.enqueue(job("third", 102))

    claimed = store.claim("primary-1", ("qdev-ci",))
    assert claimed is not None and claimed["job_id"] == 100

    restarted = Store(database)

    assert [row["job_id"] for row in restarted.pending_jobs()] == [101, 102]
    assert restarted.job_status(100) == "claimed"
    assert restarted.job(100)["worker_name"] == "primary-1"
    assert restarted.health()["jobs"]["pending"] == 2

    next_claim = restarted.claim("reserve-1", ("qdev-ci",))
    assert next_claim is not None and next_claim["job_id"] == 101
    assert restarted.job_status(100) == "claimed"
    assert restarted.job(100)["worker_name"] == "primary-1"
    assert restarted.claim("reserve-2", ("qdev-ci",))["job_id"] == 102


def test_reserve_takes_fifo_head_when_primary_heartbeat_is_stale(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job("head", 100))
    assert store.enqueue(job("tail", 101, "qdev-ci-docker"))

    _heartbeat(store, "primary-1", ("qdev-ci", "qdev-ci-docker"), active_jobs=1, concurrency=2)
    with store.connect() as connection:
        connection.execute("UPDATE workers SET last_seen=? WHERE name='primary-1'", (0.0,))

    assert store.has_available_tier_slot("primary", 90) is False

    claimed = store.claim("reserve-1", ("qdev-ci", "qdev-ci-docker"), tier="reserve")
    assert claimed is not None and claimed["job_id"] == 100
    assert store.job(100)["worker_name"] == "reserve-1"


def test_healthy_primary_headroom_keeps_reserve_from_leapfrogging(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job("head", 100))

    _heartbeat(store, "primary-1", ("qdev-ci",), active_jobs=0, concurrency=2)
    assert store.has_available_tier_slot("primary", 90) is True

    assert store.claim("reserve-1", ("qdev-ci",), tier="reserve") is None
    assert store.job_status(100) == "pending"
    assert store.claim("primary-1", ("qdev-ci",))["job_id"] == 100


def test_busy_v2_worker_cannot_take_a_second_slot(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(job("first", 100, repository="belilovsky/qazstack"))
    assert store.enqueue(job("second", 101, repository="belilovsky/qazstack"))
    scope = ClaimScope(
        scope_id="incident-20260911",
        worker_name="qdev-incident-primary",
        tier="primary",
        repository="belilovsky/qazstack",
        head_sha="a" * 40,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(
            ScopedJob(
                100,
                "qdev-ci",
                repository="belilovsky/qazstack",
                run_id=200,
                attempt=1,
                exact_sha="a" * 40,
            ),
            ScopedJob(
                101,
                "qdev-ci",
                repository="belilovsky/qazstack",
                run_id=200,
                attempt=1,
                exact_sha="a" * 40,
            ),
        ),
        schema=SCHEMA_V2,
    )
    _heartbeat(store, scope.worker_name, ("qdev-ci",), active_jobs=0, scope_id=scope.scope_id)

    first = store.claim(scope.worker_name, ("qdev-ci",), claim_scope=scope)
    assert first is not None and first["job_id"] == 100

    _heartbeat(store, scope.worker_name, ("qdev-ci",), active_jobs=1, scope_id=scope.scope_id)
    assert store.claim(scope.worker_name, ("qdev-ci",), claim_scope=scope) is None
    assert store.job_status(101) == "pending"
