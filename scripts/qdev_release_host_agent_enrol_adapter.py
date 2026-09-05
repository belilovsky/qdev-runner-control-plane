#!/usr/bin/python3
"""Dispatch one allowlisted host-agent enrolment to a private fixed adapter."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

REGISTRY = Path("/etc/qdev-runner/release-host-enrolment-targets.json")
SCHEMA = "qdev-fleet-bootstrap-adapter-result-v1"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{0,127}$")
ENVELOPE_FIELDS = {"schema", "request", "target"}
REQUEST_FIELDS = {
    "schema",
    "action",
    "source_sha",
    "run_id",
    "job_id",
    "attempt",
    "claim_ttl_seconds",
    "controller_revision",
    "controller_release_digest",
    "release_lane",
    "worker_name",
}
TARGET_FIELDS = {
    "release_lane",
    "project_id",
    "placement",
    "host_agent_mtls_identity",
    "native_host_adapter",
    "rollback_reference",
}


class AdapterError(RuntimeError):
    pass


def _validate_target(target: dict[str, Any]) -> None:
    if set(target) != TARGET_FIELDS:
        raise AdapterError("target_shape_invalid")
    if any(
        not isinstance(target.get(name), str)
        or not target[name]
        or len(target[name]) > 256
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in target[name])
        for name in TARGET_FIELDS
    ):
        raise AdapterError("target_value_invalid")
    if any(
        SLUG.fullmatch(target[name]) is None
        for name in ("release_lane", "project_id", "placement", "native_host_adapter")
    ):
        raise AdapterError("target_value_invalid")
    if target["host_agent_mtls_identity"] != f"qdev-host-agent:{target['placement']}":
        raise AdapterError("target_identity_invalid")


def _read_private_json(path: Path) -> dict[str, Any]:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise AdapterError("registry_permissions_invalid")
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise AdapterError("registry_invalid")
    return value


def _parse() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    payload = sys.stdin.buffer.read(65537)
    if not payload or len(payload) > 65536:
        raise AdapterError("request_size_invalid")
    envelope = json.loads(payload)
    if not isinstance(envelope, dict) or set(envelope) != ENVELOPE_FIELDS:
        raise AdapterError("request_envelope_invalid")
    if envelope.get("schema") != "qdev-fleet-bootstrap-adapter-request-v1":
        raise AdapterError("request_schema_invalid")
    request = envelope.get("request")
    target = envelope.get("target")
    if (
        not isinstance(request, dict)
        or set(request) != REQUEST_FIELDS
        or not isinstance(target, dict)
    ):
        raise AdapterError("request_shape_invalid")
    if any(
        isinstance(request.get(name), bool)
        or not isinstance(request.get(name), int)
        or request[name] < 1
        for name in ("run_id", "job_id", "attempt", "claim_ttl_seconds")
    ):
        raise AdapterError("request_integer_invalid")
    if (
        request.get("schema") != "qdev-fleet-bootstrap-request-v1"
        or request.get("action") != "enrol-host-agent"
        or not isinstance(request.get("controller_revision"), str)
        or not SHA.fullmatch(request["controller_revision"])
        or request.get("source_sha") != request.get("controller_revision")
        or not isinstance(request.get("controller_release_digest"), str)
        or not DIGEST.fullmatch(request["controller_release_digest"])
        or request.get("worker_name") is not None
        or not isinstance(request.get("release_lane"), str)
    ):
        raise AdapterError("request_identity_invalid")
    _validate_target(target)
    if target.get("release_lane") != request.get("release_lane"):
        raise AdapterError("target_shape_invalid")
    return envelope, request, target


def _safe_result(value: object) -> bool:
    if not isinstance(value, dict):
        return False
    for key, item in value.items():
        if (
            not isinstance(key, str)
            or any(fragment in key.lower() for fragment in ("token", "password", "secret", "key"))
            or isinstance(item, (dict, list))
        ):
            return False
    return True


def _fallback(request: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "access_blocked",
        "action": "enrol-host-agent",
        "controller_revision": request["controller_revision"],
        "controller_release_digest": request["controller_release_digest"],
        "release_lane": target["release_lane"],
        "host_agent_mtls_identity": target["host_agent_mtls_identity"],
        "rollback_source_sha": request["controller_revision"],
        "rollback_artifact_digest": request["controller_release_digest"],
        "result": {"error_code": "target_unregistered"},
    }


def _registered_adapter(target: dict[str, Any]) -> Path | None:
    registry = _read_private_json(REGISTRY)
    if (
        set(registry) != {"schema", "targets"}
        or registry.get("schema") != "qdev-release-host-enrolment-targets-v1"
    ):
        raise AdapterError("registry_schema_invalid")
    targets = registry.get("targets")
    if not isinstance(targets, dict):
        raise AdapterError("registry_targets_invalid")
    entry = targets.get(target["release_lane"])
    if entry is None:
        return None
    expected = TARGET_FIELDS | {"adapter_path"}
    if not isinstance(entry, dict) or set(entry) != expected:
        raise AdapterError("registry_entry_invalid")
    if any(entry[name] != target[name] for name in TARGET_FIELDS):
        raise AdapterError("registry_identity_mismatch")
    path = Path(str(entry["adapter_path"]))
    if not path.is_absolute() or path.parent != Path("/usr/local/sbin"):
        raise AdapterError("registry_adapter_path_invalid")
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not os.access(path, os.X_OK)
    ):
        raise AdapterError("registry_adapter_invalid")
    return path


def _validate_child(raw: object, request: dict[str, Any], target: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "schema",
        "status",
        "action",
        "controller_revision",
        "controller_release_digest",
        "release_lane",
        "host_agent_mtls_identity",
        "rollback_source_sha",
        "rollback_artifact_digest",
        "result",
    }
    if not isinstance(raw, dict) or set(raw) != expected:
        raise AdapterError("child_response_invalid")
    if (
        raw.get("schema") != SCHEMA
        or raw.get("status") not in {"completed", "already_completed", "access_blocked", "failed"}
        or raw.get("action") != "enrol-host-agent"
        or raw.get("controller_revision") != request["controller_revision"]
        or raw.get("controller_release_digest") != request["controller_release_digest"]
        or raw.get("release_lane") != target["release_lane"]
        or raw.get("host_agent_mtls_identity") != target["host_agent_mtls_identity"]
        or not isinstance(raw.get("rollback_source_sha"), str)
        or not SHA.fullmatch(raw["rollback_source_sha"])
        or not isinstance(raw.get("rollback_artifact_digest"), str)
        or not DIGEST.fullmatch(raw["rollback_artifact_digest"])
        or not _safe_result(raw.get("result"))
    ):
        raise AdapterError("child_identity_invalid")
    return raw


def main() -> int:
    if os.geteuid() != 0:
        raise AdapterError("root_identity_required")
    envelope, request, target = _parse()
    adapter = _registered_adapter(target)
    if adapter is None:
        print(json.dumps(_fallback(request, target), sort_keys=True, separators=(",", ":")))
        return 0
    completed = subprocess.run(
        [str(adapter)],
        input=json.dumps(envelope, sort_keys=True, separators=(",", ":")),
        text=True,
        capture_output=True,
        check=False,
        timeout=900,
        env={
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
        },
    )
    if completed.returncode != 0:
        raise AdapterError("child_adapter_failed")
    response = _validate_child(json.loads(completed.stdout), request, target)
    print(json.dumps(response, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        AdapterError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
