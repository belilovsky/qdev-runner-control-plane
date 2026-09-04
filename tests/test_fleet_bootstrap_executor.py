from __future__ import annotations

import json
from pathlib import Path

import yaml

from qdev_runner.fleet_bootstrap import (
    REQUEST_SCHEMA,
    BootstrapOperationStore,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
)
from qdev_runner.fleet_bootstrap_executor import execute_existing_worker_recovery

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "fleet-bootstrap.yml"
RELEASE_LANES = ROOT / "config" / "release-lanes.yml"
_ACTIVATION = yaml.safe_load(POLICY.read_text(encoding="utf-8"))["activation"]


def _request(worker_name: str = "qdev-platform-ci-187") -> FleetBootstrapRequest:
    return FleetBootstrapRequest.model_validate(
        {
            "schema": REQUEST_SCHEMA,
            "action": "restore-existing-worker",
            "source_sha": "a" * 40,
            "run_id": 123,
            "job_id": 456,
            "attempt": 1,
            "claim_ttl_seconds": 300,
            "controller_revision": _ACTIVATION["controller_revision"],
            "controller_release_digest": _ACTIVATION["controller_release_digest"],
            "release_lane": None,
            "worker_name": worker_name,
        }
    )


def _adapter(path: Path, *, status: str = "completed") -> Path:
    path.write_text(
        "#!/bin/sh\n"
        "python3 -c 'import json,sys; x=json.load(sys.stdin); t=x[\"target\"]; "
        f"print(json.dumps({{\"schema\":\"qdev-fleet-worker-recovery-result-v1\","
        f"\"status\":\"{status}\",\"worker_name\":t[\"worker_name\"],"
        "\"target_id\":t[\"target_id\"],\"service_unit\":t[\"service_unit\"],"
        "\"active_jobs\":0,\"result\":{\"native\":\"ok\"}}))'\n",
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def test_missing_adapter_is_access_blocked_and_stays_pending(tmp_path: Path) -> None:
    request = _request()
    result = execute_existing_worker_recovery(
        policy=FleetBootstrapPolicy(POLICY, RELEASE_LANES),
        store=BootstrapOperationStore(tmp_path / "operation.json"),
        request=request,
        idempotency_key="worker-recovery-001",
        active_jobs=0,
        adapter=tmp_path / "not-installed",
        receipt_path=tmp_path / "receipt.json",
    )
    assert result.status == "access_blocked"
    assert result.operation_status == "pending"
    assert json.loads((tmp_path / "operation.json").read_text())["status"] == "pending"
    receipt = json.loads((tmp_path / "receipt.json").read_text())
    assert receipt["status"] == "access_blocked"


def test_active_work_is_never_restarted(tmp_path: Path) -> None:
    request = _request()
    adapter = _adapter(tmp_path / "adapter")
    result = execute_existing_worker_recovery(
        policy=FleetBootstrapPolicy(POLICY, RELEASE_LANES),
        store=BootstrapOperationStore(tmp_path / "operation.json"),
        request=request,
        idempotency_key="worker-recovery-002",
        active_jobs=1,
        adapter=adapter,
    )
    assert result.status == "active_work"
    assert result.operation_status == "pending"


def test_success_is_completed_and_retry_is_idempotent(tmp_path: Path) -> None:
    request = _request("qdev-qazstack-01")
    store = BootstrapOperationStore(tmp_path / "operation.json")
    adapter = _adapter(tmp_path / "adapter")
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    first = execute_existing_worker_recovery(
        policy=policy,
        store=store,
        request=request,
        idempotency_key="worker-recovery-003",
        active_jobs=0,
        adapter=adapter,
    )
    second = execute_existing_worker_recovery(
        policy=policy,
        store=store,
        request=request,
        idempotency_key="worker-recovery-003",
        active_jobs=0,
        adapter=tmp_path / "adapter-no-longer-needed",
    )
    assert first.status == second.status == "completed"
    assert second.operation_status == "completed"
    assert store.begin("worker-recovery-003", request).status == "completed"


def test_adapter_identity_mismatch_fails_closed(tmp_path: Path) -> None:
    request = _request()
    adapter = _adapter(tmp_path / "adapter", status="completed")
    # The adapter above is valid; an active-work observation mismatch from the
    # adapter is covered by replacing its output with an unsafe identity.
    adapter.write_text(
        "#!/bin/sh\n"
        "printf '%s' '{\"schema\":\"qdev-fleet-worker-recovery-result-v1\","
        "\"status\":\"completed\",\"worker_name\":\"other\","
        "\"target_id\":\"other\",\"service_unit\":\"other.service\","
        "\"active_jobs\":0,\"result\":{}}'\n",
        encoding="utf-8",
    )
    adapter.chmod(0o700)
    result = execute_existing_worker_recovery(
        policy=FleetBootstrapPolicy(POLICY, RELEASE_LANES),
        store=BootstrapOperationStore(tmp_path / "operation.json"),
        request=request,
        idempotency_key="worker-recovery-004",
        active_jobs=0,
        adapter=adapter,
    )
    assert result.status == "failed"
    assert result.error_code == "adapter_identity_mismatch"
