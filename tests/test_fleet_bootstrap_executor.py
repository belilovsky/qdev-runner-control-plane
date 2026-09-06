from __future__ import annotations

import json
from pathlib import Path

from qdev_runner.fleet_bootstrap import (
    REQUEST_SCHEMA,
    BootstrapOperationStore,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
)
from qdev_runner.fleet_bootstrap_executor import (
    execute_bootstrap_operation,
    execute_existing_worker_recovery,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "fleet-bootstrap.yml"
RELEASE_LANES = ROOT / "config" / "release-lanes.yml"
_CONTROLLER_DIGEST = "sha256:" + "b" * 64
_CONTROLLER_IMAGE_DIGEST = "sha256:" + "c" * 64
_ACTIVATION_ENVELOPE_DIGEST = "sha256:" + "d" * 64


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
            "controller_revision": None,
            "controller_release_digest": None,
            "controller_image_digest": None,
            "activation_envelope_digest": None,
            "release_lane": None,
            "worker_name": worker_name,
        }
    )


def _bootstrap_request(
    action: str,
    *,
    release_lane: str | None = None,
) -> FleetBootstrapRequest:
    return FleetBootstrapRequest.model_validate(
        {
            "schema": REQUEST_SCHEMA,
            "action": action,
            "source_sha": "a" * 40,
            "run_id": 123,
            "job_id": 456,
            "attempt": 1,
            "claim_ttl_seconds": 300,
            "controller_revision": "a" * 40,
            "controller_release_digest": _CONTROLLER_DIGEST,
            "controller_image_digest": _CONTROLLER_IMAGE_DIGEST,
            "activation_envelope_digest": _ACTIVATION_ENVELOPE_DIGEST,
            "release_lane": release_lane,
            "worker_name": None,
        }
    )


def _adapter(path: Path, *, status: str = "completed") -> Path:
    path.write_text(
        "#!/bin/sh\n"
        'python3 -c \'import json,sys; x=json.load(sys.stdin); t=x["target"]; '
        f'print(json.dumps({{"schema":"qdev-fleet-worker-recovery-result-v1",'
        f'"status":"{status}","worker_name":t["worker_name"],'
        '"target_id":t["target_id"],"service_unit":t["service_unit"],'
        '"active_jobs":0,"result":{"native":"ok"}}))\'\n',
        encoding="utf-8",
    )
    path.chmod(0o700)
    return path


def _bootstrap_adapter(
    path: Path,
    *,
    identity_mismatch: bool = False,
) -> Path:
    revision_expression = "'0' * 40" if identity_mismatch else "r['controller_revision']"
    path.write_text(
        "#!/usr/bin/env python3\n"
        "import json, sys\n"
        "x = json.load(sys.stdin)\n"
        "r, t = x['request'], x['target']\n"
        "lane = t.get('release_lane')\n"
        "host = t.get('host_agent_mtls_identity')\n"
        "rollback_sha = 'c' * 40\n"
        "rollback_digest = 'sha256:' + 'e' * 64\n"
        f"revision = {revision_expression}\n"
        "print(json.dumps({\n"
        "  'schema': 'qdev-fleet-bootstrap-adapter-result-v2',\n"
        "  'status': 'completed',\n"
        "  'action': r['action'],\n"
        "  'controller_revision': revision,\n"
        "  'controller_release_digest': r['controller_release_digest'],\n"
        "  'controller_image_digest': r['controller_image_digest'],\n"
        "  'controller_internal_image_digest': r['controller_internal_image_digest'],\n"
        "  'activation_envelope_digest': r['activation_envelope_digest'],\n"
        "  'release_lane': lane,\n"
        "  'host_agent_mtls_identity': host,\n"
        "  'rollback_source_sha': rollback_sha,\n"
        "  'rollback_artifact_digest': rollback_digest,\n"
        "  'rollback_internal_artifact_digest': rollback_digest,\n"
        "  'rollback_policy_digest': 'sha256:' + 'f' * 64,\n"
        "  'rollback_generation': 7,\n"
        "  'result': {'native_status': 'verified'}\n"
        "}))\n",
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
        'printf \'%s\' \'{"schema":"qdev-fleet-worker-recovery-result-v1",'
        '"status":"completed","worker_name":"other",'
        '"target_id":"other","service_unit":"other.service",'
        '"active_jobs":0,"result":{}}\'\n',
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


def test_controller_activation_missing_adapter_remains_pending(tmp_path: Path) -> None:
    request = _bootstrap_request("activate-controller")
    result = execute_bootstrap_operation(
        policy=FleetBootstrapPolicy(POLICY, RELEASE_LANES),
        store=BootstrapOperationStore(tmp_path / "activation.json"),
        request=request,
        idempotency_key="controller-activation-001",
        adapter=tmp_path / "not-installed",
        receipt_path=tmp_path / "receipt.json",
    )
    assert result.status == "access_blocked"
    assert result.operation_status == "pending"
    assert result.error_code == "activation_adapter_unavailable"
    assert not (tmp_path / "receipt.json").exists()


def test_controller_activation_is_verified_and_idempotent(tmp_path: Path) -> None:
    request = _bootstrap_request("activate-controller")
    store = BootstrapOperationStore(tmp_path / "activation.json")
    adapter = _bootstrap_adapter(tmp_path / "activate")
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    first = execute_bootstrap_operation(
        policy=policy,
        store=store,
        request=request,
        idempotency_key="controller-activation-002",
        adapter=adapter,
        receipt_path=tmp_path / "receipt.json",
    )
    second = execute_bootstrap_operation(
        policy=policy,
        store=store,
        request=request,
        idempotency_key="controller-activation-002",
        adapter=tmp_path / "no-longer-needed",
    )
    assert first.status == second.status == "completed"
    assert first.operation_status == second.operation_status == "completed"
    assert first.result is not None
    assert first.result["rollback_source_sha"] == "c" * 40
    assert first.result["rollback_policy_digest"] == "sha256:" + "f" * 64
    assert first.result["rollback_generation"] == 7
    assert json.loads((tmp_path / "receipt.json").read_text())["status"] == "completed"


def test_controller_activation_rejects_adapter_identity_mismatch(tmp_path: Path) -> None:
    result = execute_bootstrap_operation(
        policy=FleetBootstrapPolicy(POLICY, RELEASE_LANES),
        store=BootstrapOperationStore(tmp_path / "activation.json"),
        request=_bootstrap_request("activate-controller"),
        idempotency_key="controller-activation-003",
        adapter=_bootstrap_adapter(tmp_path / "activate", identity_mismatch=True),
    )
    assert result.status == "failed"
    assert result.operation_status == "pending"
    assert result.error_code == "adapter_identity_mismatch"


def test_host_enrolment_binds_allowlisted_lane_and_rollback_anchor(tmp_path: Path) -> None:
    request = _bootstrap_request("enrol-host-agent", release_lane="qdev-release-total")
    result = execute_bootstrap_operation(
        policy=FleetBootstrapPolicy(POLICY, RELEASE_LANES),
        store=BootstrapOperationStore(tmp_path / "enrolment.json"),
        request=request,
        idempotency_key="host-enrolment-001",
        adapter=_bootstrap_adapter(tmp_path / "enrol"),
    )
    assert result.status == "completed"
    assert result.release_lane == "qdev-release-total"
    assert result.host_agent_mtls_identity == "qdev-host-agent:total-qdev-origin"
    assert result.result is not None
    assert result.result["rollback_source_sha"] == "c" * 40
    assert result.result["rollback_artifact_digest"] == "sha256:" + "e" * 64
