from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from test_store import job

from qdev_runner.store import Store

FENCE = "a" * 64


def registered(tmp_path: Path) -> Store:
    store = Store(tmp_path / "broker.db")
    store.heartbeat("existing-worker", ("qdev-ci",), 0, (), {"tier": "primary"})
    return store


def test_hold_survives_reopen_and_preserves_fifo(tmp_path: Path):
    store = registered(tmp_path)
    store.enqueue(job("first", 100))
    store.enqueue(job("second", 101))
    before = [store.job(100), store.job(101)]
    assert store.acquire_recovery_hold("existing-worker", FENCE) == 0
    reopened = Store(tmp_path / "broker.db")
    assert reopened.claim("existing-worker", ("qdev-ci",)) is None
    assert [store.job(100), store.job(101)] == before
    reopened.release_recovery_hold("existing-worker", "b" * 64)
    assert reopened.claim("existing-worker", ("qdev-ci",)) is None
    reopened.release_recovery_hold("existing-worker", FENCE)
    assert reopened.claim("existing-worker", ("qdev-ci",))["job_id"] == 100


def test_running_job_blocks_even_when_heartbeat_claims_zero(tmp_path: Path):
    store = registered(tmp_path)
    store.enqueue(job())
    assert store.claim("existing-worker", ("qdev-ci",))
    store.heartbeat("existing-worker", ("qdev-ci",), 0, (), {"tier": "primary"})
    assert store.acquire_recovery_hold("existing-worker", FENCE) == 1
    with store.connect() as connection:
        assert connection.execute("SELECT COUNT(*) FROM worker_recovery_holds").fetchone()[0] == 0


def test_hold_rejects_other_operation_and_unknown_worker(tmp_path: Path):
    store = registered(tmp_path)
    with pytest.raises(ValueError, match="not registered"):
        store.acquire_recovery_hold("unknown-worker", FENCE)
    assert store.acquire_recovery_hold("existing-worker", FENCE) == 0
    assert store.acquire_recovery_hold("existing-worker", FENCE) == 0
    with pytest.raises(ValueError, match="already fenced"):
        store.acquire_recovery_hold("existing-worker", "b" * 64)


def test_claim_and_recovery_are_mutually_exclusive(tmp_path: Path):
    store = registered(tmp_path)
    store.enqueue(job())
    start = Barrier(2)

    def claim():
        start.wait()
        return store.claim("existing-worker", ("qdev-ci",))

    def recover():
        start.wait()
        return store.acquire_recovery_hold("existing-worker", FENCE)

    with ThreadPoolExecutor(max_workers=2) as executor:
        claimed = executor.submit(claim)
        recovery = executor.submit(recover)
        row, active = claimed.result(), recovery.result()
    assert (row is None and active == 0) or (row is not None and active == 1)
