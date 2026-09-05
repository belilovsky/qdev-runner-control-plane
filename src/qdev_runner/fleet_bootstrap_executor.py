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
import stat
import subprocess
import tempfile
import time
from contextlib import suppress
from dataclasses import dataclass, replace
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
    WorkerRecoveryTarget,
    bootstrap_request_fingerprint,
)
from .store import Store

RECOVERY_RESULT_SCHEMA = "qdev-fleet-worker-recovery-result-v1"
RECOVERY_RECEIPT_SCHEMA = "qdev-fleet-worker-recovery-receipt-v1"
RECOVERY_STATUSES = frozenset(
    {
        "completed",
        "capacity_pending",
        "access_blocked",
        "active_work",
        "target_unregistered",
        "failed",
    }
)
_ADAPTER_STATUSES = frozenset(
    {"completed", "already_completed", "access_blocked", "target_unregistered", "failed"}
)
_DEFAULT_ADAPTER = Path("/usr/local/sbin/qdev-fleet-worker-recovery")


@dataclass(frozen=True)
class RecoveryExecution:
    """A non-secret result suitable for a private operator receipt."""

    status: Literal[
        "completed",
        "capacity_pending",
        "access_blocked",
        "active_work",
        "target_unregistered",
        "failed",
    ]
    operation_status: Literal["pending", "completed"]
    idempotency_key: str
    request_fingerprint: str
    worker_name: str
    target_id: str | None
    service_unit: str | None
    error_code: str | None = None
    result: dict[str, Any] | None = None
    active_jobs: int | None = None

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
            "active_jobs": self.active_jobs,
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
    candidate = value or _DEFAULT_ADAPTER
    if not candidate.is_absolute():
        return None
    try:
        for path in (candidate, *candidate.parents):
            metadata = path.lstat()
            if metadata.st_uid != 0 or metadata.st_mode & 0o022 or stat.S_ISLNK(metadata.st_mode):
                return None
            expected = stat.S_ISREG if path == candidate else stat.S_ISDIR
            if not expected(metadata.st_mode):
                return None
        if not os.access(candidate, os.X_OK):
            return None
    except OSError:
        return None
    return candidate


def _invoke_adapter(
    adapter: Path,
    *,
    operation: VerifiedBootstrapOperation,
    request: FleetBootstrapRequest,
    target: WorkerRecoveryTarget,
    active_jobs: int,
    quiescence: dict[str, Any],
    timeout_seconds: float,
) -> tuple[str, dict[str, Any] | None]:
    envelope = {
        "schema": "qdev-fleet-worker-recovery-request-v2",
        "operation": operation.directive,
        "request": request.model_dump(mode="json", by_alias=True),
        "target": {
            "worker_name": target.worker_name,
            "target_id": target.target_id,
            "service_unit": target.service_unit,
            "host_binding": target.host_binding,
            "labels": list(target.labels),
            "certificate_fingerprint_sha256": target.certificate_fingerprint_sha256,
        },
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
        "worker_name",
        "target_id",
        "service_unit",
        "active_jobs",
        "result",
        "operation_fence",
    }:
        return "failed", {"error_code": "adapter_response_invalid"}
    if (
        raw.get("schema") != RECOVERY_RESULT_SCHEMA
        or raw.get("status") not in _ADAPTER_STATUSES
        or raw.get("worker_name") != target.worker_name
        or raw.get("target_id") != target.target_id
        or raw.get("service_unit") != target.service_unit
        or type(raw.get("active_jobs")) is not int
        or raw.get("active_jobs") != 0
        or raw.get("operation_fence") != operation.fence
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
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
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
    operation: VerifiedBootstrapOperation,
    signing_key: str,
    controller_store: Store,
    adapter: Path | None = None,
    timeout_seconds: float = 120,
    heartbeat_timeout_seconds: float = 30,
    heartbeat_poll_seconds: float = 0.25,
    receipt_path: Path | None = None,
) -> RecoveryExecution:
    """Verify authority and fence the target before any privileged side effect."""
    operation = verify_directive(operation.directive, policy=policy, signing_key=signing_key)
    request = operation.request
    if request.action != "restore-existing-worker" or request.worker_name is None:
        raise FleetBootstrapError("executor accepts only existing-worker recovery")
    with store.execution_lock():
        operation = verify_directive(operation.directive, policy=policy, signing_key=signing_key)
        authority_path = store.path.with_suffix(".authority.json")
        try:
            original_authority = json.loads(authority_path.read_text(encoding="utf-8"))
        except FileNotFoundError:
            original_authority = None
        except (OSError, json.JSONDecodeError) as error:
            raise FleetBootstrapError("bootstrap authority journal is unreadable") from error
        if original_authority is not None:
            admitted = operation
            operation = renew_bootstrap_operation(
                original_authority,
                admitted,
                policy=policy,
                signing_key=signing_key,
            )
            # Keep every fresh workflow attempt independently auditable without
            # changing the immutable intent or the privileged adapter's fence.
            audit_path = store.path.with_suffix(f".admission-{admitted.fence}.json")
            # One attempt can mint multiple equivalent short-lived credentials;
            # audit the immutable identity rather than its changing timestamps.
            _persist_receipt(
                audit_path,
                {
                    "original_fence": operation.fence,
                    "admission_fence": admitted.fence,
                    "request": admitted.request.model_dump(mode="json", by_alias=True),
                },
            )
        else:
            _persist_receipt(authority_path, operation.directive)
        request = operation.request
        if request.action != "restore-existing-worker" or request.worker_name is None:
            raise FleetBootstrapError("executor accepts only existing-worker recovery")
        record = store.begin(operation.idempotency_key, request)
        # A completed replay never restarts a worker, including after a crash
        # between durable completion and releasing its scheduling hold.
        active_jobs = 0
        observed = record.status == "completed"
        resolved_adapter = _adapter_path(adapter) if record.status != "completed" else None
        if record.status != "completed" and resolved_adapter is not None:
            active_jobs, state_revision = controller_store.acquire_recovery_hold_state(
                request.worker_name,
                operation.fence,
            )
            baseline = (
                controller_store.worker_recovery_observation(
                    request.worker_name,
                    operation.fence,
                )
                if active_jobs == 0
                else None
            )
            quiescence = create_quiescence_receipt(
                operation,
                target_id=policy.worker_target(request.worker_name).target_id,  # type: ignore[union-attr]
                state_revision=state_revision,
                active_jobs=active_jobs,
                signing_key=signing_key,
            )
            observed = True
        else:
            baseline = None
            quiescence = None
        result = _execute_existing_worker_recovery(
            policy=policy,
            store=store,
            request=request,
            operation=operation,
            idempotency_key=operation.idempotency_key,
            active_jobs=active_jobs,
            quiescence=quiescence,
            adapter=resolved_adapter,
            signing_key=signing_key,
            timeout_seconds=timeout_seconds,
            controller_store=controller_store,
            baseline=baseline,
            heartbeat_timeout_seconds=heartbeat_timeout_seconds,
            heartbeat_poll_seconds=heartbeat_poll_seconds,
            receipt_path=receipt_path,
        )
        if result.operation_status == "completed":
            controller_store.release_recovery_hold(request.worker_name, operation.fence)
        # An uncertain adapter result leaves the hold in place. Recovery must
        # retry the same signed operation/fence, never silently resume scheduling.
        return replace(result, active_jobs=active_jobs if observed else None)


def _execute_existing_worker_recovery(
    *,
    policy: FleetBootstrapPolicy,
    store: BootstrapOperationStore,
    request: FleetBootstrapRequest,
    operation: VerifiedBootstrapOperation,
    idempotency_key: str,
    active_jobs: int,
    quiescence: dict[str, Any] | None,
    signing_key: str,
    controller_store: Store,
    baseline: dict[str, Any] | None,
    heartbeat_timeout_seconds: float,
    heartbeat_poll_seconds: float,
    adapter: Path | None = None,
    timeout_seconds: float = 120,
    receipt_path: Path | None = None,
) -> RecoveryExecution:
    """Execute only a controller-registered worker recovery transition.

    The caller must provide a controller-observed active job count.  Missing
    or non-zero work is never treated as safe.  A missing adapter or registry
    target leaves the operation pending and returns ``access_blocked``;
    ``completed`` is emitted only after the adapter reports success and the
    controller observes a later healthy heartbeat from the same worker.
    """

    policy.validate(request)
    if request.action != "restore-existing-worker" or request.worker_name is None:
        raise FleetBootstrapError("executor accepts only existing-worker recovery")
    record = store.begin(idempotency_key, request)
    fingerprint = bootstrap_request_fingerprint(request)
    target = policy.worker_target(request.worker_name)

    def finish(value: RecoveryExecution) -> RecoveryExecution:
        value = replace(value, active_jobs=active_jobs)
        if receipt_path is not None and value.operation_status == "completed":
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
    # The outer boundary resolves the root-owned path exactly once and acquires
    # the durable scheduler hold before passing it here. Never re-discover it:
    # an adapter installed mid-request must not skip hold acquisition.
    if adapter is None:
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
    # No privileged side effect may start after its short-lived authority expires.
    # SQLite hold acquisition and journal I/O may have waited past the TTL.
    operation = verify_directive(operation.directive, policy=policy, signing_key=signing_key)
    if quiescence is None:
        raise FleetBootstrapError("signed worker quiescence receipt is unavailable")
    if baseline is None:
        raise FleetBootstrapError("worker recovery baseline is unavailable")
    adapter_started = time.monotonic()
    adapter_status, adapter_result = _invoke_adapter(
        adapter,
        operation=operation,
        request=request,
        target=target,
        active_jobs=active_jobs,
        quiescence=quiescence,
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
    if (
        not isinstance(heartbeat_timeout_seconds, (int, float))
        or isinstance(heartbeat_timeout_seconds, bool)
        or heartbeat_timeout_seconds < 0
        or not isinstance(heartbeat_poll_seconds, (int, float))
        or isinstance(heartbeat_poll_seconds, bool)
        or heartbeat_poll_seconds <= 0
    ):
        raise FleetBootstrapError("worker heartbeat observation timeout is invalid")
    adapter_elapsed = time.monotonic() - adapter_started
    heartbeat_budget = min(
        float(heartbeat_timeout_seconds),
        max(0.0, float(timeout_seconds) - adapter_elapsed),
    )
    deadline = time.monotonic() + heartbeat_budget
    observation: dict[str, Any] | None = None
    expected_profiles = tuple(
        label for label in target.labels if label not in {"self-hosted", "Linux", "X64"}
    )
    while True:
        current = controller_store.worker_recovery_observation(
            target.worker_name,
            operation.fence,
        )
        if (
            current["last_seen"] > baseline["last_seen"]
            and current["profiles"] == expected_profiles
            and current["active_jobs"] == 0
            and current["allowed"]
            and current["slots_available"] > 0
            and current["authenticated_certificate_sha256"] == target.certificate_fingerprint_sha256
        ):
            observation = current
            break
        if time.monotonic() >= deadline:
            break
        time.sleep(min(float(heartbeat_poll_seconds), max(0.0, deadline - time.monotonic())))
    if observation is None:
        return finish(
            RecoveryExecution(
                status="capacity_pending",
                operation_status="pending",
                idempotency_key=idempotency_key,
                request_fingerprint=fingerprint,
                worker_name=request.worker_name,
                target_id=target.target_id,
                service_unit=target.service_unit,
                error_code="fresh_worker_heartbeat_pending",
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
        "heartbeat_last_seen": observation["last_seen"],
        "profiles_json": json.dumps(
            observation["profiles"], ensure_ascii=True, separators=(",", ":")
        ),
        "capacity_slots": observation["slots_available"],
    }
    # Adapter output may not overwrite controller-verified identity fields.
    # Its bounded result was validated above; immutable identities come only
    # from the registered target and the signed operation.
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
