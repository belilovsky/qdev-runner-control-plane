"""Fixed controller-side transport for the existing QMT host-agent.

The privileged bootstrap executor has already verified the signed operation.
This adapter adds a second, compiled allowlist and can reach only the existing
QMT bootstrap SSH identity. The server key and forced command are configured
outside the repository by the existing QDev administrative bootstrap.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from .fleet_bootstrap_operation_executor import RESULT_SCHEMA

SSH = Path("/usr/bin/ssh")
SSH_CONFIG = Path("/etc/qdev-runner/bootstrap-ssh-config")
KNOWN_HOSTS = Path("/etc/qdev-runner/bootstrap-known-hosts")
REMOTE_ALIAS = "qdev-bootstrap-srv138jump"
REMOTE_COMMAND = "/opt/qdev-release-bootstrap/current/venv/bin/qdev-qmt-host-agent-enrol-native"
TIMEOUT_SECONDS = 120

QMT_TARGET: dict[str, Any] = {
    "target_id": "release-lane:qdev-release-qmt",
    "release_lane": "qdev-release-qmt",
    "project_id": "kaztilshi",
    "placement": "srv138jump",
    "client_mtls_identity": "qdev-release-client:kaztilshi",
    "host_agent_mtls_identity": "qdev-host-agent:srv138jump",
    "artifact_ref_prefix": "registry.ci.qdev.run/kaztilshi",
    "native_host_adapter": "product-compose-v2",
    "runtime_endpoints": ["https://qmt.digital/release.json"],
    "rollback_reference": "qdev-release-host-state-v1",
    "required_readiness": ["local", "startup", "public"],
}


class HostEnrolmentError(RuntimeError):
    """The request cannot safely reach the fixed host enrolment command."""


def _read_request() -> dict[str, Any]:
    try:
        value = json.load(sys.stdin)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise HostEnrolmentError("host enrolment request is not JSON") from error
    if not isinstance(value, dict):
        raise HostEnrolmentError("host enrolment request is not an object")
    return value


def _validate(envelope: dict[str, Any]) -> str:
    if set(envelope) != {"schema", "operation", "request", "target", "active_jobs"}:
        raise HostEnrolmentError("host enrolment request shape is invalid")
    if envelope.get("schema") != "qdev-fleet-bootstrap-adapter-request-v1":
        raise HostEnrolmentError("host enrolment request schema is invalid")
    request = envelope.get("request")
    operation = envelope.get("operation")
    if (
        not isinstance(request, dict)
        or request.get("action") != "enrol-host-agent"
        or request.get("release_lane") != "qdev-release-qmt"
        or request.get("worker_name") is not None
        or envelope.get("target") != QMT_TARGET
        or envelope.get("active_jobs") is not None
        or not isinstance(operation, dict)
    ):
        raise HostEnrolmentError("host enrolment target is not allowlisted")
    payload = operation.get("payload")
    if not isinstance(payload, dict):
        raise HostEnrolmentError("host enrolment directive is invalid")
    fence = payload.get("fence")
    if not isinstance(fence, str) or not 24 <= len(fence) <= 128:
        raise HostEnrolmentError("host enrolment fence is invalid")
    return fence


def enrol(envelope: dict[str, Any]) -> dict[str, Any]:
    fence = _validate(envelope)
    command = [
        str(SSH),
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-F",
        str(SSH_CONFIG),
        REMOTE_ALIAS,
        REMOTE_COMMAND,
    ]
    try:
        completed = subprocess.run(  # noqa: S603
            command,
            input=json.dumps(envelope, ensure_ascii=True, sort_keys=True, separators=(",", ":")),
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise HostEnrolmentError("fixed host enrolment transport is unavailable") from error
    if completed.returncode != 0 or len(completed.stdout) > 262_144:
        raise HostEnrolmentError("fixed host enrolment command failed")
    try:
        result = json.loads(completed.stdout)
    except (TypeError, json.JSONDecodeError) as error:
        raise HostEnrolmentError("fixed host enrolment result is invalid") from error
    if (
        not isinstance(result, dict)
        or set(result) != {"schema", "status", "action", "target_id", "result", "operation_fence"}
        or result.get("schema") != RESULT_SCHEMA
        or result.get("status") not in {"completed", "already_completed", "access_blocked"}
        or result.get("action") != "enrol-host-agent"
        or result.get("target_id") != QMT_TARGET["target_id"]
        or result.get("operation_fence") != fence
        or not isinstance(result.get("result"), dict)
        or (
            result.get("status") in {"completed", "already_completed"}
            and set(result["result"])
            != {
                "release_lane",
                "host_agent_identity",
                "certificate_fingerprint_sha256",
                "service_status",
                "enrolment_ack",
            }
        )
    ):
        raise HostEnrolmentError("fixed host enrolment result identity mismatch")
    return result


def main() -> int:
    try:
        result = enrol(_read_request())
    except HostEnrolmentError:
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
