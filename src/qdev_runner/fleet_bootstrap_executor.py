"""Controller-side execution for allowlisted fleet bootstrap operations.

The GitHub workflow only validates and records a signed request.  This module
is intentionally a separate, privileged boundary: it accepts a request that
has already passed policy/OIDC validation, verifies the exact registered
worker target and an independent no-active-work observation, and invokes one
controller-installed recovery adapter.  It never accepts a hostname,
service-unit, shell fragment or executable from the request.
"""

from __future__ import annotations

import json
import os
import subprocess
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, cast

from .fleet_bootstrap import (
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    WorkerRecoveryTarget,
)
from .release_lane import ReleaseLane

RECOVERY_RESULT_SCHEMA = "qdev-fleet-worker-recovery-result-v1"
RECOVERY_RECEIPT_SCHEMA = "qdev-fleet-worker-recovery-receipt-v1"
RECOVERY_STATUSES = frozenset(
    {"completed", "access_blocked", "active_work", "target_unregistered", "failed"}
)
_ADAPTER_STATUSES = frozenset(
    {"completed", "already_completed", "access_blocked", "target_unregistered", "failed"}
)
_DEFAULT_ADAPTER = Path("/usr/local/sbin/qdev-fleet-worker-recovery")
_DEFAULT_ACTIVATION_ADAPTER = Path("/usr/local/sbin/qdev-controller-activate")
_DEFAULT_ENROLMENT_ADAPTER = Path("/usr/local/sbin/qdev-release-host-agent-enrol")
BOOTSTRAP_ADAPTER_RESULT_SCHEMA = "qdev-fleet-bootstrap-adapter-result-v2"
BOOTSTRAP_EXECUTION_RECEIPT_SCHEMA = "qdev-fleet-bootstrap-execution-receipt-v2"
_BOOTSTRAP_ADAPTER_STATUSES = frozenset(
    {"completed", "already_completed", "access_blocked", "failed"}
)


@dataclass(frozen=True)
class RecoveryExecution:
    """A non-secret result suitable for a private operator receipt."""

    status: Literal["completed", "access_blocked", "active_work", "target_unregistered", "failed"]
    operation_status: Literal["pending", "completed"]
    idempotency_key: str
    request_fingerprint: str
    worker_name: str
    target_id: str | None
    service_unit: str | None
    error_code: str | None = None
    result: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema": RECOVERY_RECEIPT_SCHEMA,
            "status": self.status,
            "operation_status": self.operation_status,
            "idempotency_key": self.idempotency_key,
            "request_fingerprint": self.request_fingerprint,
            "worker_name": self.worker_name,
            "target_id": self.target_id,
            "service_unit": self.service_unit,
        }
        if self.error_code is not None:
            value["error_code"] = self.error_code
        if self.result is not None:
            value["result"] = self.result
        return value


@dataclass(frozen=True)
class BootstrapExecution:
    """Non-secret evidence for controller activation or host enrolment."""

    status: Literal["completed", "access_blocked", "failed"]
    operation_status: Literal["pending", "completed"]
    action: Literal["activate-controller", "enrol-host-agent"]
    idempotency_key: str
    request_fingerprint: str
    controller_revision: str
    controller_release_digest: str
    controller_image_digest: str
    controller_internal_image_digest: str
    activation_envelope_digest: str
    release_lane: str | None = None
    host_agent_mtls_identity: str | None = None
    error_code: str | None = None
    result: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema": BOOTSTRAP_EXECUTION_RECEIPT_SCHEMA,
            "status": self.status,
            "operation_status": self.operation_status,
            "action": self.action,
            "idempotency_key": self.idempotency_key,
            "request_fingerprint": self.request_fingerprint,
            "controller_revision": self.controller_revision,
            "controller_release_digest": self.controller_release_digest,
            "controller_image_digest": self.controller_image_digest,
            "controller_internal_image_digest": self.controller_internal_image_digest,
            "activation_envelope_digest": self.activation_envelope_digest,
            "release_lane": self.release_lane,
            "host_agent_mtls_identity": self.host_agent_mtls_identity,
            "error_code": self.error_code,
            "result": self.result,
        }
        return value


def _safe_adapter_result(value: object) -> dict[str, Any] | None:
    if not isinstance(value, dict):
        return None
    # BootstrapOperationStore applies the same sensitive-key and scalar-value
    # checks before any result can become durable state.
    try:
        BootstrapOperationStore._validate_result(value)  # noqa: SLF001
    except FleetBootstrapError:
        return None
    return dict(value)


def _adapter_path(value: Path | None) -> Path | None:
    candidate = value
    if candidate is None:
        configured = os.environ.get("QDEV_FLEET_RECOVERY_EXECUTABLE", "").strip()
        candidate = Path(configured) if configured else _DEFAULT_ADAPTER
    if not candidate.is_absolute() or not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    return candidate


def _bootstrap_adapter_path(
    value: Path | None,
    *,
    action: Literal["activate-controller", "enrol-host-agent"],
) -> Path | None:
    candidate = value
    if candidate is None:
        if action == "activate-controller":
            configured = os.environ.get("QDEV_FLEET_ACTIVATION_EXECUTABLE", "").strip()
            candidate = Path(configured) if configured else _DEFAULT_ACTIVATION_ADAPTER
        else:
            configured = os.environ.get("QDEV_FLEET_ENROLMENT_EXECUTABLE", "").strip()
            candidate = Path(configured) if configured else _DEFAULT_ENROLMENT_ADAPTER
    if not candidate.is_absolute() or not candidate.is_file() or not os.access(candidate, os.X_OK):
        return None
    return candidate


def _bootstrap_target(
    *,
    policy: FleetBootstrapPolicy,
    request: FleetBootstrapRequest,
    controller_runtime: tuple[str, str] | None = None,
) -> tuple[dict[str, Any], ReleaseLane | None]:
    if request.action == "activate-controller":
        rollback_revision = controller_runtime[0] if controller_runtime is not None else None
        rollback_release_digest = controller_runtime[1] if controller_runtime is not None else None
        return (
            {
                "controller_revision": request.controller_revision,
                "controller_release_digest": request.controller_release_digest,
                "controller_image_digest": request.controller_image_digest,
                "controller_internal_image_digest": request.controller_internal_image_digest,
                "activation_envelope_digest": request.activation_envelope_digest,
                "activation_mode": policy.activation.mode,
                "activation_envelope_schema": policy.activation.envelope_schema,
                "activation_public_key_binding": policy.activation.public_key_binding,
                "activation_max_envelope_ttl_seconds": (policy.activation.max_envelope_ttl_seconds),
                "rollback_revision": rollback_revision,
                "rollback_release_digest": rollback_release_digest,
            },
            None,
        )
    if request.action != "enrol-host-agent" or request.release_lane is None:
        raise FleetBootstrapError("executor accepts only activation or host-agent enrolment")
    lane = policy.release_lane(request.release_lane)
    return (
        {
            "release_lane": lane.name,
            "project_id": lane.project_id,
            "placement": lane.placement,
            "host_agent_mtls_identity": lane.host_agent_mtls_identity,
            "native_host_adapter": lane.native_host_adapter,
            "rollback_reference": lane.rollback_reference,
        },
        lane,
    )


def _invoke_bootstrap_adapter(
    adapter: Path,
    *,
    request: FleetBootstrapRequest,
    target: dict[str, Any],
    lane: ReleaseLane | None,
    timeout_seconds: float,
) -> tuple[str, dict[str, Any] | None]:
    envelope = {
        "schema": "qdev-fleet-bootstrap-adapter-request-v2",
        "request": request.model_dump(mode="json", by_alias=True),
        "target": target,
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
    expected_fields = {
        "schema",
        "status",
        "action",
        "controller_revision",
        "controller_release_digest",
        "controller_image_digest",
        "controller_internal_image_digest",
        "activation_envelope_digest",
        "release_lane",
        "host_agent_mtls_identity",
        "rollback_source_sha",
        "rollback_artifact_digest",
        "rollback_internal_artifact_digest",
        "rollback_policy_digest",
        "rollback_generation",
        "result",
    }
    if not isinstance(raw, dict) or set(raw) != expected_fields:
        return "failed", {"error_code": "adapter_response_invalid"}
    if (
        raw.get("schema") != BOOTSTRAP_ADAPTER_RESULT_SCHEMA
        or raw.get("status") not in _BOOTSTRAP_ADAPTER_STATUSES
        or raw.get("action") != request.action
        or raw.get("controller_revision") != request.controller_revision
        or raw.get("controller_release_digest") != request.controller_release_digest
        or raw.get("controller_image_digest") != request.controller_image_digest
        or raw.get("controller_internal_image_digest") != request.controller_internal_image_digest
        or raw.get("activation_envelope_digest") != request.activation_envelope_digest
    ):
        return "failed", {"error_code": "adapter_identity_mismatch"}
    rollback_sha = raw.get("rollback_source_sha")
    rollback_digest = raw.get("rollback_artifact_digest")
    rollback_internal_digest = raw.get("rollback_internal_artifact_digest")
    rollback_policy_digest = raw.get("rollback_policy_digest")
    rollback_generation = raw.get("rollback_generation")
    if (
        not isinstance(rollback_sha, str)
        or len(rollback_sha) != 40
        or any(character not in "0123456789abcdef" for character in rollback_sha)
        or not isinstance(rollback_digest, str)
        or len(rollback_digest) != 71
        or not rollback_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in rollback_digest[7:])
        or not isinstance(rollback_internal_digest, str)
        or len(rollback_internal_digest) != 71
        or not rollback_internal_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in rollback_internal_digest[7:])
        or not isinstance(rollback_policy_digest, str)
        or len(rollback_policy_digest) != 71
        or not rollback_policy_digest.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in rollback_policy_digest[7:])
        or isinstance(rollback_generation, bool)
        or not isinstance(rollback_generation, int)
        or rollback_generation < 0
    ):
        return "failed", {"error_code": "adapter_identity_mismatch"}
    if lane is None:
        if raw.get("release_lane") is not None or raw.get("host_agent_mtls_identity") is not None:
            return "failed", {"error_code": "adapter_identity_mismatch"}
    else:
        if (
            raw.get("release_lane") != lane.name
            or raw.get("host_agent_mtls_identity") != lane.host_agent_mtls_identity
        ):
            return "failed", {"error_code": "adapter_identity_mismatch"}
    result = _safe_adapter_result(raw.get("result"))
    if result is None:
        return "failed", {"error_code": "adapter_result_invalid"}
    result.update(
        {
            "rollback_source_sha": raw["rollback_source_sha"],
            "rollback_artifact_digest": raw["rollback_artifact_digest"],
            "rollback_policy_digest": raw["rollback_policy_digest"],
            "rollback_generation": raw["rollback_generation"],
        }
    )
    return str(raw["status"]), result


def _invoke_adapter(
    adapter: Path,
    *,
    request: FleetBootstrapRequest,
    target: WorkerRecoveryTarget,
    active_jobs: int,
    timeout_seconds: float,
) -> tuple[str, dict[str, Any] | None]:
    envelope = {
        "schema": "qdev-fleet-worker-recovery-request-v1",
        "request": request.model_dump(mode="json", by_alias=True),
        "target": {
            "worker_name": target.worker_name,
            "target_id": target.target_id,
            "service_unit": target.service_unit,
            "host_binding": target.host_binding,
            "labels": list(target.labels),
        },
        "active_jobs": active_jobs,
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
        "worker_name",
        "target_id",
        "service_unit",
        "active_jobs",
        "result",
    }:
        return "failed", {"error_code": "adapter_response_invalid"}
    if (
        raw.get("schema") != RECOVERY_RESULT_SCHEMA
        or raw.get("status") not in _ADAPTER_STATUSES
        or raw.get("worker_name") != target.worker_name
        or raw.get("target_id") != target.target_id
        or raw.get("service_unit") != target.service_unit
        or raw.get("active_jobs") != 0
    ):
        return "failed", {"error_code": "adapter_identity_mismatch"}
    result = _safe_adapter_result(raw.get("result"))
    if result is None:
        return "failed", {"error_code": "adapter_result_invalid"}
    return str(raw["status"]), result


def _persist_receipt(path: Path, receipt: dict[str, Any]) -> None:
    """Write one immutable private receipt, allowing an identical retry."""

    encoded = json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        try:
            if path.read_text(encoding="utf-8") == encoded:
                return
        except OSError as error:
            raise FleetBootstrapError("recovery receipt is unreadable") from error
        raise FleetBootstrapError("recovery receipt cannot be replaced")
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            # Another identical idempotent invocation won the race.  Compare
            # bytes and never overwrite its receipt.
            if path.read_text(encoding="utf-8") != encoded:
                raise FleetBootstrapError("recovery receipt cannot be replaced") from None
        finally:
            with suppress(OSError):
                os.unlink(temporary)
    except OSError as error:
        with suppress(OSError):
            os.unlink(temporary)
        raise FleetBootstrapError("recovery receipt cannot be written") from error


def execute_bootstrap_operation(
    *,
    policy: FleetBootstrapPolicy,
    store: BootstrapOperationStore,
    request: FleetBootstrapRequest,
    idempotency_key: str,
    adapter: Path | None = None,
    timeout_seconds: float = 120,
    receipt_path: Path | None = None,
    controller_runtime: tuple[str, str] | None = None,
) -> BootstrapExecution:
    """Activate the controller or enrol one allowlisted product host agent.

    The caller cannot supply an executable, host, URL, service name or native
    product command through the request.  The parsed bootstrap and release-lane
    policies resolve the complete target, and the controller selects one fixed
    installed adapter for the action.
    """

    policy.validate(request)
    if request.action not in {"activate-controller", "enrol-host-agent"}:
        raise FleetBootstrapError("executor accepts only activation or host-agent enrolment")
    controller_revision = request.controller_revision
    controller_release_digest = request.controller_release_digest
    controller_image_digest = request.controller_image_digest
    controller_internal_image_digest = request.controller_internal_image_digest
    activation_envelope_digest = request.activation_envelope_digest
    if (
        controller_revision is None
        or controller_release_digest is None
        or controller_image_digest is None
        or controller_internal_image_digest is None
        or activation_envelope_digest is None
    ):
        raise FleetBootstrapError("controller activation binding is incomplete")
    action = cast(Literal["activate-controller", "enrol-host-agent"], request.action)
    target, lane = _bootstrap_target(
        policy=policy,
        request=request,
        controller_runtime=controller_runtime,
    )
    record = store.begin(idempotency_key, request)
    fingerprint = record.request_fingerprint

    def execution(
        status: Literal["completed", "access_blocked", "failed"],
        operation_status: Literal["pending", "completed"],
        *,
        error_code: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> BootstrapExecution:
        value = BootstrapExecution(
            status=status,
            operation_status=operation_status,
            action=action,
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint,
            controller_revision=controller_revision,
            controller_release_digest=controller_release_digest,
            controller_image_digest=controller_image_digest,
            controller_internal_image_digest=controller_internal_image_digest,
            activation_envelope_digest=activation_envelope_digest,
            release_lane=lane.name if lane else None,
            host_agent_mtls_identity=lane.host_agent_mtls_identity if lane else None,
            error_code=error_code,
            result=result,
        )
        # Only terminal evidence receives the canonical immutable receipt URI.
        # Pending/failed attempts remain visible in the signed controller
        # response and durable operation state without blocking a later safe
        # retry from creating the final receipt.
        if receipt_path is not None and operation_status == "completed":
            _persist_receipt(receipt_path, value.as_dict())
        return value

    if record.status == "completed":
        return execution("completed", "completed", result=record.result)
    adapter_path = _bootstrap_adapter_path(adapter, action=action)
    if adapter_path is None:
        return execution(
            "access_blocked",
            "pending",
            error_code=(
                "activation_adapter_unavailable"
                if action == "activate-controller"
                else "enrolment_adapter_unavailable"
            ),
        )
    adapter_status, adapter_result = _invoke_bootstrap_adapter(
        adapter_path,
        request=request,
        target=target,
        lane=lane,
        timeout_seconds=timeout_seconds,
    )
    if adapter_status not in {"completed", "already_completed"}:
        return execution(
            "access_blocked" if adapter_status == "access_blocked" else "failed",
            "pending",
            error_code=(adapter_result or {}).get("error_code", "adapter_rejected"),
        )
    completion_result: dict[str, Any] = {
        "action": action,
        "controller_revision": request.controller_revision,
        "controller_release_digest": request.controller_release_digest,
        "controller_image_digest": request.controller_image_digest,
        "controller_internal_image_digest": request.controller_internal_image_digest,
        "activation_envelope_digest": request.activation_envelope_digest,
        "adapter_status": adapter_status,
    }
    if lane is not None:
        completion_result.update(
            {
                "release_lane": lane.name,
                "project_id": lane.project_id,
                "placement": lane.placement,
                "host_agent_mtls_identity": lane.host_agent_mtls_identity,
                "native_host_adapter": lane.native_host_adapter,
            }
        )
    if adapter_result:
        completion_result.update(adapter_result)
    completed = store.complete(idempotency_key, request, completion_result)
    return execution("completed", completed.status, result=completed.result)


def execute_existing_worker_recovery(
    *,
    policy: FleetBootstrapPolicy,
    store: BootstrapOperationStore,
    request: FleetBootstrapRequest,
    idempotency_key: str,
    active_jobs: int,
    adapter: Path | None = None,
    timeout_seconds: float = 120,
    receipt_path: Path | None = None,
) -> RecoveryExecution:
    """Execute only a controller-registered worker recovery transition.

    The caller must provide a controller-observed active job count.  Missing
    or non-zero work is never treated as safe.  A missing adapter or registry
    target leaves the operation pending and returns ``access_blocked``;
    ``completed`` is emitted only after the adapter reports success.
    """

    policy.validate(request)
    if request.action != "restore-existing-worker" or request.worker_name is None:
        raise FleetBootstrapError("executor accepts only existing-worker recovery")
    record = store.begin(idempotency_key, request)
    fingerprint = record.request_fingerprint
    target = policy.worker_target(request.worker_name)

    def finish(value: RecoveryExecution) -> RecoveryExecution:
        if receipt_path is not None:
            _persist_receipt(receipt_path, value.as_dict())
        return value

    if record.status == "completed":
        return finish(
            RecoveryExecution(
                status="completed",
                operation_status="completed",
                idempotency_key=idempotency_key,
                request_fingerprint=fingerprint,
                worker_name=request.worker_name,
                target_id=target.target_id if target else None,
                service_unit=target.service_unit if target else None,
                result=record.result,
            )
        )
    if target is None:
        return finish(
            RecoveryExecution(
                status="target_unregistered",
                operation_status="pending",
                idempotency_key=idempotency_key,
                request_fingerprint=fingerprint,
                worker_name=request.worker_name,
                target_id=None,
                service_unit=None,
                error_code="target_unregistered",
            )
        )
    if isinstance(active_jobs, bool) or not isinstance(active_jobs, int) or active_jobs < 0:
        raise FleetBootstrapError("active work observation is invalid")
    if active_jobs:
        return finish(
            RecoveryExecution(
                status="active_work",
                operation_status="pending",
                idempotency_key=idempotency_key,
                request_fingerprint=fingerprint,
                worker_name=request.worker_name,
                target_id=target.target_id,
                service_unit=target.service_unit,
                error_code="active_work",
            )
        )
    adapter_path = _adapter_path(adapter)
    if adapter_path is None:
        return finish(
            RecoveryExecution(
                status="access_blocked",
                operation_status="pending",
                idempotency_key=idempotency_key,
                request_fingerprint=fingerprint,
                worker_name=request.worker_name,
                target_id=target.target_id,
                service_unit=target.service_unit,
                error_code="recovery_adapter_unavailable",
            )
        )
    adapter_status, adapter_result = _invoke_adapter(
        adapter_path,
        request=request,
        target=target,
        active_jobs=active_jobs,
        timeout_seconds=timeout_seconds,
    )
    if adapter_status not in {"completed", "already_completed"}:
        mapped = adapter_status if adapter_status in RECOVERY_STATUSES else "failed"
        return finish(
            RecoveryExecution(
                status=mapped,  # type: ignore[arg-type]
                operation_status="pending",
                idempotency_key=idempotency_key,
                request_fingerprint=fingerprint,
                worker_name=request.worker_name,
                target_id=target.target_id,
                service_unit=target.service_unit,
                error_code=(adapter_result or {}).get("error_code", "adapter_rejected"),
            )
        )
    completion_result = {
        "action": "restore-existing-worker",
        "worker_name": target.worker_name,
        "target_id": target.target_id,
        "service_unit": target.service_unit,
        "host_binding": target.host_binding,
        "adapter_status": adapter_status,
        "active_jobs": active_jobs,
    }
    if adapter_result:
        completion_result.update(adapter_result)
    completed = store.complete(idempotency_key, request, completion_result)
    return finish(
        RecoveryExecution(
            status="completed",
            operation_status=completed.status,
            idempotency_key=idempotency_key,
            request_fingerprint=fingerprint,
            worker_name=request.worker_name,
            target_id=target.target_id,
            service_unit=target.service_unit,
            result=completed.result,
        )
    )
