"""Root-only native recovery for one policy-registered existing worker."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

from .fleet_bootstrap import FleetBootstrapError, FleetBootstrapPolicy, FleetBootstrapRequest
from .fleet_bootstrap_executor import RECOVERY_RESULT_SCHEMA
from .privileged_bootstrap_client import MAX_MESSAGE_BYTES
from .privileged_bootstrap_executor import DEFAULT_POLICY, DEFAULT_RELEASE_LANES


class WorkerRecoveryError(RuntimeError):
    """The fixed worker recovery operation is unsafe or unavailable."""


def _read() -> dict[str, Any]:
    data = sys.stdin.buffer.read(MAX_MESSAGE_BYTES + 1)
    if not data or len(data) > MAX_MESSAGE_BYTES:
        raise WorkerRecoveryError("worker recovery request is empty or too large")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise WorkerRecoveryError("worker recovery request is not JSON") from error
    if not isinstance(value, dict):
        raise WorkerRecoveryError("worker recovery request is not an object")
    return value


def _run_systemctl(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        ["/usr/bin/systemctl", *arguments],
        capture_output=True,
        text=True,
        check=False,
        timeout=60,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C"},
    )


def execute(
    envelope: dict[str, Any],
    *,
    policy: FleetBootstrapPolicy,
) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise WorkerRecoveryError("worker recovery requires root")
    if set(envelope) != {"schema", "operation", "request", "target", "active_jobs"}:
        raise WorkerRecoveryError("worker recovery request shape is invalid")
    if envelope.get("schema") != "qdev-fleet-worker-recovery-request-v2":
        raise WorkerRecoveryError("worker recovery schema is invalid")
    try:
        request = FleetBootstrapRequest.model_validate(envelope.get("request"))
    except (ValueError, TypeError) as error:
        raise WorkerRecoveryError("worker recovery intent is invalid") from error
    if request.action != "restore-existing-worker" or request.worker_name is None:
        raise WorkerRecoveryError("worker recovery action is invalid")
    target = policy.worker_target(request.worker_name)
    if target is None:
        raise WorkerRecoveryError("worker recovery target is unregistered")
    expected = {
        "worker_name": target.worker_name,
        "target_id": target.target_id,
        "service_unit": target.service_unit,
        "host_binding": target.host_binding,
        "labels": list(target.labels),
        "certificate_fingerprint_sha256": target.certificate_fingerprint_sha256,
    }
    if envelope.get("target") != expected or envelope.get("active_jobs") != 0:
        raise WorkerRecoveryError("worker recovery target differs from policy")
    operation = envelope.get("operation")
    fence = (
        operation.get("payload", {}).get("fence")
        if isinstance(operation, dict) and isinstance(operation.get("payload"), dict)
        else None
    )
    if not isinstance(fence, str) or len(fence) < 24:
        raise WorkerRecoveryError("worker recovery fence is invalid")

    current = _run_systemctl("is-active", target.service_unit)
    if current.returncode == 0 and current.stdout.strip() == "active":
        status = "already_completed"
    else:
        restarted = _run_systemctl("restart", target.service_unit)
        verified = _run_systemctl("is-active", target.service_unit)
        if (
            restarted.returncode != 0
            or verified.returncode != 0
            or verified.stdout.strip() != "active"
        ):
            status = "failed"
        else:
            status = "completed"
    native_result: dict[str, Any] = {
        "service_active": status in {"completed", "already_completed"},
    }
    if status == "failed":
        native_result["error_code"] = "service_restart_failed"
    return {
        "schema": RECOVERY_RESULT_SCHEMA,
        "status": status,
        "worker_name": target.worker_name,
        "target_id": target.target_id,
        "service_unit": target.service_unit,
        "active_jobs": 0,
        "result": native_result,
        "operation_fence": fence,
    }


def main() -> int:
    try:
        result = execute(
            _read(),
            policy=FleetBootstrapPolicy(
                Path(os.environ.get("QDEV_FLEET_BOOTSTRAP_POLICY", DEFAULT_POLICY)),
                Path(os.environ.get("QDEV_RELEASE_LANES", DEFAULT_RELEASE_LANES)),
            ),
        )
    except (WorkerRecoveryError, FleetBootstrapError, OSError, subprocess.SubprocessError):
        print("worker_recovery_failed", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if result["status"] in {"completed", "already_completed"} else 2


if __name__ == "__main__":
    raise SystemExit(main())
