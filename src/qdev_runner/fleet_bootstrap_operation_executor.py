"""Privileged execution for controller activation and host-agent enrolment.

The workflow contributes only a signed, source-bound intent.  This boundary
derives every artifact, lane identity and executable from controller policy,
then records an idempotent completion before returning success.
"""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from .bootstrap_authority import (
    VerifiedBootstrapOperation,
    create_quiescence_receipt,
    renew_bootstrap_operation,
    verify_directive,
)
from .fleet_bootstrap import (
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    bootstrap_request_fingerprint,
)
from .fleet_bootstrap_executor import _adapter_path, _persist_receipt, _safe_adapter_result
from .store import Store

RESULT_SCHEMA = "qdev-fleet-bootstrap-adapter-result-v1"
RECEIPT_SCHEMA = "qdev-fleet-bootstrap-receipt-v1"
_ADAPTER_STATUSES = frozenset({"completed", "already_completed", "access_blocked", "failed"})


@dataclass(frozen=True)
class BootstrapExecution:
    status: Literal["completed", "access_blocked", "active_work", "failed"]
    operation_status: Literal["pending", "completed"]
    action: Literal["activate-controller", "enrol-host-agent"]
    idempotency_key: str
    request_fingerprint: str
    target_id: str
    active_jobs: int | None = None
    error_code: str | None = None
    result: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema": RECEIPT_SCHEMA,
            "status": self.status,
            "operation_status": self.operation_status,
            "action": self.action,
            "idempotency_key": self.idempotency_key,
            "request_fingerprint": self.request_fingerprint,
            "target_id": self.target_id,
            "active_jobs": self.active_jobs,
        }
        if self.error_code is not None:
            value["error_code"] = self.error_code
        if self.result is not None:
            value["result"] = self.result
        return value


def _target(
    policy: FleetBootstrapPolicy, request: FleetBootstrapRequest
) -> tuple[str, dict[str, Any]]:
    if request.action == "activate-controller":
        target_id = f"controller:{request.controller_revision}"
        return target_id, {
            "target_id": target_id,
            "revision": request.controller_revision,
            "release_digest": request.controller_release_digest,
            "artifact_ref": policy.controller_artifact_ref(request),
            "rollback_revision": policy.activation.rollback_revision,
            "rollback_release_digest": policy.activation.rollback_release_digest,
        }
    if request.action == "enrol-host-agent" and request.release_lane is not None:
        lane = policy.release_lane(request.release_lane)
        target_id = f"release-lane:{lane.name}"
        return target_id, {
            "target_id": target_id,
            "release_lane": lane.name,
            "project_id": lane.project_id,
            "placement": lane.placement,
            "client_mtls_identity": lane.client_mtls_identity,
            "host_agent_mtls_identity": lane.host_agent_mtls_identity,
            "artifact_ref_prefix": lane.artifact_ref_prefix,
            "native_host_adapter": lane.native_host_adapter,
            "runtime_endpoints": list(lane.runtime_endpoints),
            "rollback_reference": lane.rollback_reference,
            "required_readiness": list(lane.required_readiness),
        }
    raise FleetBootstrapError("executor action is unsupported")


def _reconcile_authority(
    store: BootstrapOperationStore,
    operation: VerifiedBootstrapOperation,
    *,
    policy: FleetBootstrapPolicy,
    signing_key: str,
) -> VerifiedBootstrapOperation:
    authority_path = store.path.with_suffix(".authority.json")
    try:
        original = json.loads(authority_path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        original = None
    except (OSError, json.JSONDecodeError) as error:
        raise FleetBootstrapError("bootstrap authority journal is unreadable") from error
    if original is None:
        _persist_receipt(authority_path, operation.directive)
        return operation
    admitted = operation
    operation = renew_bootstrap_operation(
        original, admitted, policy=policy, signing_key=signing_key
    )
    _persist_receipt(
        store.path.with_suffix(f".admission-{admitted.fence}.json"),
        {
            "original_fence": operation.fence,
            "admission_fence": admitted.fence,
            "request": admitted.request.model_dump(mode="json", by_alias=True),
        },
    )
    return operation


def _invoke(
    adapter: Path,
    *,
    operation: VerifiedBootstrapOperation,
    request: FleetBootstrapRequest,
    target_id: str,
    target: dict[str, Any],
    active_jobs: int | None,
    quiescence: dict[str, Any] | None,
    timeout_seconds: float,
) -> tuple[str, dict[str, Any] | None]:
    envelope = {
        "schema": "qdev-fleet-bootstrap-adapter-request-v1",
        "operation": operation.directive,
        "request": request.model_dump(mode="json", by_alias=True),
        "target": target,
        "active_jobs": active_jobs,
        "quiescence": quiescence,
    }
    try:
        completed = subprocess.run(  # noqa: S603
            [str(adapter)],
            input=json.dumps(envelope, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
            capture_output=True,
            text=True,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired):
        return "failed", {"error_code": "adapter_unavailable"}
    if completed.returncode != 0:
        return "failed", {"error_code": "adapter_exit"}
    try:
        raw = json.loads(completed.stdout)
    except (TypeError, UnicodeDecodeError, json.JSONDecodeError):
        return "failed", {"error_code": "adapter_response_invalid"}
    if not isinstance(raw, dict) or set(raw) != {
        "schema",
        "status",
        "action",
        "target_id",
        "result",
        "operation_fence",
    }:
        return "failed", {"error_code": "adapter_response_invalid"}
    if (
        raw.get("schema") != RESULT_SCHEMA
        or raw.get("status") not in _ADAPTER_STATUSES
        or raw.get("action") != request.action
        or raw.get("target_id") != target_id
        or raw.get("operation_fence") != operation.fence
    ):
        return "failed", {"error_code": "adapter_identity_mismatch"}
    result = _safe_adapter_result(raw.get("result"))
    if result is None:
        return "failed", {"error_code": "adapter_result_invalid"}
    return str(raw["status"]), result


def execute_bootstrap_operation(
    *,
    policy: FleetBootstrapPolicy,
    store: BootstrapOperationStore,
    operation: VerifiedBootstrapOperation,
    signing_key: str,
    controller_store: Store,
    activation_adapter: Path | None,
    enrolment_adapter: Path | None,
    timeout_seconds: float = 120,
    receipt_path: Path | None = None,
) -> BootstrapExecution:
    """Execute one policy-derived activation or enrolment transition."""

    operation = verify_directive(operation.directive, policy=policy, signing_key=signing_key)
    if operation.request.action not in {"activate-controller", "enrol-host-agent"}:
        raise FleetBootstrapError("executor action is unsupported")
    with store.execution_lock():
        operation = verify_directive(operation.directive, policy=policy, signing_key=signing_key)
        operation = _reconcile_authority(store, operation, policy=policy, signing_key=signing_key)
        request = operation.request
        record = store.begin(operation.idempotency_key, request)
        target_id, target = _target(policy, request)
        fingerprint = bootstrap_request_fingerprint(request)
        if record.status == "completed":
            completed_result = record.result or {}
            recorded_active_jobs = completed_result.get("active_jobs")
            if type(recorded_active_jobs) is not int:
                recorded_active_jobs = None
            execution = BootstrapExecution(
                status="completed",
                operation_status="completed",
                action=request.action,  # type: ignore[arg-type]
                idempotency_key=operation.idempotency_key,
                request_fingerprint=fingerprint,
                target_id=target_id,
                active_jobs=recorded_active_jobs,
                result=completed_result,
            )
            # Completion is durable before the scheduler hold and receipt are
            # finalized.  A process failure in either window must therefore be
            # repairable without invoking the privileged adapter again.  The
            # store deletes only a hold owned by this exact operation fence.
            if request.action == "activate-controller":
                controller_store.release_controller_hold(operation.fence)
            if receipt_path is not None:
                _persist_receipt(receipt_path, execution.as_dict())
            return execution
        configured = (
            activation_adapter if request.action == "activate-controller" else enrolment_adapter
        )
        active_jobs: int | None = None
        quiescence: dict[str, Any] | None = None
        adapter = _adapter_path(configured)
        if adapter is None:
            return BootstrapExecution(
                status="access_blocked",
                operation_status="pending",
                action=request.action,  # type: ignore[arg-type]
                idempotency_key=operation.idempotency_key,
                request_fingerprint=fingerprint,
                target_id=target_id,
                active_jobs=active_jobs,
                error_code="bootstrap_adapter_unavailable",
            )
        if request.action == "activate-controller":
            try:
                active_jobs, state_revision = controller_store.acquire_controller_hold(
                    operation.fence, target_id, exclude_job_id=request.job_id
                )
            except ValueError as error:
                raise FleetBootstrapError("controller scheduler is already fenced") from error
            if active_jobs:
                return BootstrapExecution(
                    status="active_work",
                    operation_status="pending",
                    action="activate-controller",
                    idempotency_key=operation.idempotency_key,
                    request_fingerprint=fingerprint,
                    target_id=target_id,
                    active_jobs=active_jobs,
                    error_code="active_work",
                )
            quiescence = create_quiescence_receipt(
                operation,
                target_id=target_id,
                state_revision=state_revision,
                active_jobs=active_jobs,
                signing_key=signing_key,
            )
        operation = verify_directive(operation.directive, policy=policy, signing_key=signing_key)
        adapter_status, adapter_result = _invoke(
            adapter,
            operation=operation,
            request=request,
            target_id=target_id,
            target=target,
            active_jobs=active_jobs,
            quiescence=quiescence,
            timeout_seconds=timeout_seconds,
        )
        if adapter_status not in {"completed", "already_completed"}:
            status = adapter_status if adapter_status in {"access_blocked", "failed"} else "failed"
            return BootstrapExecution(
                status=status,  # type: ignore[arg-type]
                operation_status="pending",
                action=request.action,  # type: ignore[arg-type]
                idempotency_key=operation.idempotency_key,
                request_fingerprint=fingerprint,
                target_id=target_id,
                active_jobs=active_jobs,
                error_code=(adapter_result or {}).get("error_code", "adapter_rejected"),
            )
        completion = {
            "action": request.action,
            "target_id": target_id,
            "adapter_status": adapter_status,
            "active_jobs": active_jobs,
            "controller_revision": request.controller_revision,
            "controller_release_digest": request.controller_release_digest,
        }
        completed_record = store.complete(operation.idempotency_key, request, completion)
        if request.action == "activate-controller":
            controller_store.release_controller_hold(operation.fence)
        execution = BootstrapExecution(
            status="completed",
            operation_status="completed",
            action=request.action,  # type: ignore[arg-type]
            idempotency_key=operation.idempotency_key,
            request_fingerprint=fingerprint,
            target_id=target_id,
            active_jobs=active_jobs,
            result=completed_record.result,
        )
        if receipt_path is not None:
            _persist_receipt(receipt_path, execution.as_dict())
        return execution
