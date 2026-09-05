from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Barrier

import pytest
from test_store import job
from worker_evidence import seed_worker, worker_detail

from qdev_runner.admission import worker_admission
from qdev_runner.store import Store


def evidence():
    return {
        "name": "worker-1", "last_seen": time.time(), "active_jobs": 0,
        "profiles_json": '["qdev-ci"]', "detail_json": worker_detail(),
    }


def test_complete_admission_and_audit_match(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    seed_worker(store)
    assert store.health()["workers"][0]["available"] is True
    assert worker_admission(evidence(), now=time.time()).allowed is True
    store.enqueue(job())
    assert store.claim("worker-1", ("qdev-ci",)) is not None
    worker = store.health()["workers"][0]
    assert worker["available"] is False
    assert worker["slots_available"] == 0
    assert "worker_busy" in worker["admission_blockers"]


@pytest.mark.parametrize("path,value", [
    (("last_seen",), 0), (("last_seen",), 999999999999),
    (("detail_json", "controller_enrollment"), {}),
    (("detail_json", "controller_enrollment", "worker_name"), "foreign-reserve"),
    (("detail_json", "controller_enrollment", "authenticated"), False),
    (("profiles_json",), '["unknown"]'),
    (("detail_json", "effective_profiles"), ["qdev-ci-browser"]),
    (("detail_json", "runtime_audit", "observed_at"), 0),
    (("detail_json", "runtime_audit", "image_release", "status"), "not_checked"),
    (("detail_json", "runtime_audit", "image_release", "manifest_digest"), "unknown"),
    (("detail_json", "runtime_audit", "images"), []),
    (("detail_json", "runtime_audit", "images"), [{"configuration": []}]),
    (("detail_json", "raw_capacity"), {}),
    (("detail_json", "baseline_capacity"), {}),
    (("detail_json", "effective_capacity"), {}),
    (("detail_json", "raw_capacity", "cpus"), float("nan")),
    (("detail_json", "raw_capacity", "load_15"), float("inf")),
    (("detail_json", "effective_capacity", "cpu_psi_avg10"), -1),
    (("detail_json", "baseline_capacity", "allowed"), False),
    (("detail_json", "effective_capacity", "blockers"), ["cpu_psi_avg10"]),
    (("detail_json", "min_disk_free_gib"), 4),
    (("detail_json", "min_disk_free_gib"), 20),
    (("detail_json", "concurrency"), True),
    (("active_jobs",), 1),
    (("detail_json", "active_job_ids"), [None]),
])
def test_invalid_evidence_never_allows_admission_or_claim(tmp_path: Path, path, value) -> None:
    row = evidence()
    target = row
    for component in path[:-1]:
        target = target[component]
    target[path[-1]] = value
    decision = worker_admission(row, now=time.time())
    assert not decision.allowed
    assert decision.slots == 0
    assert decision.blockers
    store = Store(tmp_path / "broker.db")
    seed_worker(store)
    with store.connect() as connection:
        connection.execute(
            "UPDATE workers SET last_seen=?, active_jobs=?, profiles_json=?, detail_json=?",
            (row["last_seen"], row["active_jobs"], row["profiles_json"],
             json.dumps(row["detail_json"])),
        )
    store.enqueue(job())
    assert not store.health()["workers"][0]["available"]
    assert store.claim("worker-1", ("qdev-ci",)) is None
    assert store.job_status(100) == "pending"


def test_legacy_and_unknown_worker_keep_lease_but_cannot_claim(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    store.enqueue(job())
    assert store.claim("unknown-primary", ("qdev-ci",)) is None
    seed_worker(store)
    assert store.claim("worker-1", ("qdev-ci",)) is not None
    store.heartbeat("worker-1", ("qdev-ci",), 1, (100,), {"tier": "primary"})
    assert not store.health()["workers"][0]["available"]
    assert store.job_status(100) == "claimed"
    assert store.stale_jobs(300) == []


@pytest.mark.parametrize("metric,value", [
    ("memory_available_gib", 3), ("load_15", 8), ("cpu_psi_avg10", -1),
])
def test_allowed_boolean_cannot_override_required_metrics(metric, value) -> None:
    row = evidence()
    for key in ("raw_capacity", "baseline_capacity", "effective_capacity"):
        row["detail_json"][key][metric] = value
    assert not worker_admission(row, now=time.time()).allowed


def test_override_cannot_be_used_after_expiry_or_for_non_disk_blockers() -> None:
    row = evidence()
    detail = row["detail_json"]
    detail.update(min_disk_free_gib=6, max_disk_used_pct=96,
                  capacity_directive_id="signed-test-operation",
                  capacity_directive_expires_at=time.time() + 300)
    detail["baseline_capacity"].update(allowed=False, blockers=["disk_used_pct"])
    for key in ("raw_capacity", "baseline_capacity", "effective_capacity"):
        detail[key]["disk_used_pct"] = 90
    assert worker_admission(row, now=time.time()).allowed
    detail["capacity_directive_expires_at"] = time.time() - 1
    assert not worker_admission(row, now=time.time()).allowed
    detail["capacity_directive_expires_at"] = time.time() + 901
    assert not worker_admission(row, now=time.time()).allowed
    detail["capacity_directive_expires_at"] = time.time() + 300
    detail["baseline_capacity"]["blockers"].append("load_15")
    assert not worker_admission(row, now=time.time()).allowed


def test_competing_claims_cannot_overbook_an_idle_heartbeat(tmp_path: Path) -> None:
    database = tmp_path / "broker.db"
    first, second = Store(database), Store(database)
    seed_worker(first)
    first.enqueue(job())
    first.enqueue(job("second", 101))
    barrier = Barrier(2)

    def claim(store):
        barrier.wait(timeout=10)
        return store.claim("worker-1", ("qdev-ci",))

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(claim, (first, second)))
    assert sum(result is not None for result in results) == 1
    assert first.job_status(100) == "claimed"
    assert first.job_status(101) == "pending"


def test_unhealthy_primary_does_not_hide_healthy_reserve(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    seed_worker(store, "primary-1")
    seed_worker(store, "reserve-1", tier="reserve")
    with store.connect() as connection:
        connection.execute("UPDATE workers SET last_seen=0 WHERE name='primary-1'")
    store.enqueue(job())
    assert store.claim("reserve-1", ("qdev-ci",), tier="reserve") is not None
