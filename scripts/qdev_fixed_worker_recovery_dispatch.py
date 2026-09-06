#!/usr/bin/python3
"""Start one fixed recovery agent through a controller-owned SSH binding."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

SCHEMA = "qdev-fleet-worker-recovery-result-v1"
REQUEST_SCHEMA = "qdev-fleet-worker-recovery-request-v1"
SSH = Path("/usr/bin/ssh")
IDENTITY_ROOT = Path("/etc/qdev-runner/worker-recovery-dispatch")
IDENTITY = IDENTITY_ROOT / "id_ed25519"
KNOWN_HOSTS = IDENTITY_ROOT / "known_hosts"
ENROL = Path("/usr/local/sbin/qdev-recovery-host-enrol")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
TARGETS: dict[str, dict[str, object]] = {
    "actions.runner.belilovsky-platform-portal.qdev-platform-ci-187": {
        "worker_name": "qdev-platform-ci-187",
        "service_unit": ("actions.runner.belilovsky-platform-portal.qdev-platform-ci-187.service"),
        "labels": ["self-hosted", "Linux", "X64", "qdev-platform-ci"],
        "host": "187.55.228.239",
        "profile": "platform",
        "recovery_service": "qdev-runner-recovery-platform.service",
    },
    "actions.runner.belilovsky-qazstack.qdev-qazstack-01": {
        "worker_name": "qdev-qazstack-01",
        "service_unit": "actions.runner.belilovsky-qazstack.qdev-qazstack-01.service",
        "labels": ["self-hosted", "Linux", "X64", "qdev-ci"],
        "host": "148.230.117.131",
        "profile": "qazstack",
        "recovery_service": "qdev-runner-recovery-qazstack.service",
    },
}


class DispatchError(RuntimeError):
    pass


def _root_private_file(path: Path, mode: int) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise DispatchError("dispatch_identity_permissions_invalid")


def _validate_private_identity() -> None:
    metadata = IDENTITY_ROOT.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise DispatchError("dispatch_identity_permissions_invalid")
    _root_private_file(IDENTITY, 0o600)
    _root_private_file(KNOWN_HOSTS, 0o600)
    if not SSH.is_file() or SSH.is_symlink():
        raise DispatchError("ssh_client_unavailable")
    enrol = ENROL.lstat()
    if (
        not stat.S_ISREG(enrol.st_mode)
        or stat.S_ISLNK(enrol.st_mode)
        or enrol.st_uid != 0
        or stat.S_IMODE(enrol.st_mode) != 0o755
    ):
        raise DispatchError("host_enrol_adapter_invalid")


def _enrol(target_id: str, expected: dict[str, object]) -> dict[str, str]:
    completed = subprocess.run(
        [str(ENROL), "--target-id", target_id],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        timeout=420,
        check=False,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    )
    if completed.returncode != 0:
        raise DispatchError("host_enrol_failed")
    try:
        response = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DispatchError("host_enrol_response_invalid") from error
    fields = {
        "schema",
        "status",
        "profile",
        "controller_revision",
        "controller_release_digest",
        "agent_release_digest",
        "agent_certificate_sha256",
        "rollback_agent_release_digest",
        "receipt_digest",
    }
    if (
        not isinstance(response, dict)
        or set(response) != fields
        or response.get("schema") != "qdev-recovery-host-enrol-result-v1"
        or response.get("status") not in {"completed", "already_completed"}
        or response.get("profile") != expected["profile"]
        or not isinstance(response.get("controller_revision"), str)
        or SHA.fullmatch(response["controller_revision"]) is None
        or not isinstance(response.get("controller_release_digest"), str)
        or DIGEST.fullmatch(response["controller_release_digest"]) is None
        or not isinstance(response.get("agent_release_digest"), str)
        or DIGEST.fullmatch(response["agent_release_digest"]) is None
        or not isinstance(response.get("agent_certificate_sha256"), str)
        or HEX.fullmatch(response["agent_certificate_sha256"]) is None
        or not isinstance(response.get("rollback_agent_release_digest"), str)
        or (
            response["rollback_agent_release_digest"] != "none"
            and DIGEST.fullmatch(response["rollback_agent_release_digest"]) is None
        )
        or not isinstance(response.get("receipt_digest"), str)
        or DIGEST.fullmatch(response["receipt_digest"]) is None
    ):
        raise DispatchError("host_enrol_response_invalid")
    return {key: str(value) for key, value in response.items()}


def _parse() -> tuple[dict[str, Any], dict[str, object]]:
    payload = sys.stdin.buffer.read(65537)
    if not payload or len(payload) > 65536:
        raise DispatchError("request_size_invalid")
    envelope = json.loads(payload)
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema",
        "request",
        "target",
        "active_jobs",
    }:
        raise DispatchError("request_envelope_invalid")
    if envelope.get("schema") != REQUEST_SCHEMA or envelope.get("active_jobs") != 0:
        raise DispatchError("request_identity_invalid")
    request = envelope.get("request")
    target = envelope.get("target")
    if not isinstance(request, dict) or not isinstance(target, dict):
        raise DispatchError("request_shape_invalid")
    target_id = target.get("target_id")
    expected = TARGETS.get(target_id) if isinstance(target_id, str) else None
    if expected is None:
        raise DispatchError("target_not_allowlisted")
    expected_target = {
        "worker_name": expected["worker_name"],
        "target_id": target_id,
        "service_unit": expected["service_unit"],
        "host_binding": "controller-registry",
        "labels": expected["labels"],
    }
    if (
        target != expected_target
        or request.get("action") != "restore-existing-worker"
        or request.get("worker_name") != expected["worker_name"]
    ):
        raise DispatchError("target_identity_mismatch")
    return envelope, expected


def _result(
    envelope: dict[str, Any],
    expected: dict[str, object],
    *,
    status: str,
    enrolment: dict[str, str] | None = None,
    error_code: str | None = None,
) -> dict[str, object]:
    target = envelope["target"]
    details: dict[str, object] = {
        "dispatch_binding": "controller-fixed-ssh-v1",
        "native_status": "started" if status == "completed" else "not_started",
        "recovery_service_unit": expected["recovery_service"],
    }
    if error_code is not None:
        details["error_code"] = error_code
    if enrolment is not None:
        details.update(
            {
                "enrolment_status": enrolment["status"],
                "enrolment_receipt_digest": enrolment["receipt_digest"],
                "controller_revision": enrolment["controller_revision"],
                "controller_release_digest": enrolment["controller_release_digest"],
                "agent_release_digest": enrolment["agent_release_digest"],
                "agent_certificate_sha256": enrolment["agent_certificate_sha256"],
                "rollback_agent_release_digest": enrolment["rollback_agent_release_digest"],
            }
        )
    return {
        "schema": SCHEMA,
        "status": status,
        "worker_name": target["worker_name"],
        "target_id": target["target_id"],
        "service_unit": target["service_unit"],
        "active_jobs": 0,
        "result": details,
    }


def main() -> int:
    if os.geteuid() != 0:
        raise DispatchError("root_identity_required")
    envelope, expected = _parse()
    _validate_private_identity()
    try:
        enrolment = _enrol(str(envelope["target"]["target_id"]), expected)
    except DispatchError as error:
        response = _result(
            envelope,
            expected,
            status="access_blocked",
            error_code=str(error),
        )
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
        return 0
    command = [
        str(SSH),
        "-F",
        "/dev/null",
        "-i",
        str(IDENTITY),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o",
        "ConnectTimeout=15",
        f"root@{expected['host']}",
        "/usr/bin/systemctl",
        "start",
        str(expected["recovery_service"]),
    ]
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=120,
        check=False,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    )
    response = _result(
        envelope,
        expected,
        status="completed" if completed.returncode == 0 else "access_blocked",
        enrolment=enrolment,
        error_code=None if completed.returncode == 0 else "fixed_host_dispatch_failed",
    )
    print(json.dumps(response, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        DispatchError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
