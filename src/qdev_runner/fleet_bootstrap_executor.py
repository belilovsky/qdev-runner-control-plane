"""Controller-side execution for an allowlisted existing-worker recovery.

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
from typing import Any, Literal

from .fleet_bootstrap import (
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    WorkerRecoveryTarget,
    bootstrap_request_fingerprint,
)

RECOVERY_RESULT_SCHEMA = "qdev-fleet-worker-recovery-result-v1"
RECOVERY_RECEIPT_SCHEMA = "qdev-fleet-worker-recovery-receipt-v1"
RECOVERY_STATUSES = frozenset(
    {"completed", "access_blocked", "active_work", "target_unregistered", "failed"}
)
_ADAPTER_STATUSES = frozenset(
    {"completed", "already_completed", "access_blocked", "target_unregistered", "failed"}
)
_DEFAULT_ADAPTER = Path("/usr/local/sbin/qdev-fleet-worker-recovery")


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
    fingerprint = bootstrap_request_fingerprint(request)
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
