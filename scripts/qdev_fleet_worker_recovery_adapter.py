#!/usr/bin/python3
"""Recover one existing worker only through a root-private fixed registry."""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

REGISTRY = Path("/etc/qdev-runner/fleet-worker-recovery-targets.json")
SCHEMA = "qdev-fleet-worker-recovery-result-v1"
SHA = re.compile(r"^[0-9a-f]{40}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,255}$")
SERVICE_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,254}\.service$")
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
    "controller_image_digest",
    "controller_internal_image_digest",
    "activation_envelope_digest",
    "release_lane",
    "worker_name",
}
TARGET_FIELDS = {"worker_name", "target_id", "service_unit", "host_binding", "labels"}


class AdapterError(RuntimeError):
    pass


def _validate_target(target: dict[str, Any]) -> None:
    if set(target) != TARGET_FIELDS:
        raise AdapterError("target_shape_invalid")
    if any(
        not isinstance(target.get(name), str) or IDENTIFIER.fullmatch(target[name]) is None
        for name in ("worker_name", "target_id")
    ):
        raise AdapterError("target_value_invalid")
    if (
        not isinstance(target.get("service_unit"), str)
        or SERVICE_UNIT.fullmatch(target["service_unit"]) is None
        or target.get("host_binding") != "controller-registry"
    ):
        raise AdapterError("target_value_invalid")
    labels = target.get("labels")
    if (
        not isinstance(labels, list)
        or not labels
        or len(labels) > 32
        or len(labels) != len(set(labels))
        or any(
            not isinstance(label, str) or IDENTIFIER.fullmatch(label) is None for label in labels
        )
    ):
        raise AdapterError("target_value_invalid")


def _parse() -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
    payload = sys.stdin.buffer.read(65537)
    if not payload or len(payload) > 65536:
        raise AdapterError("request_size_invalid")
    envelope = json.loads(payload)
    if not isinstance(envelope, dict) or set(envelope) != {
        "schema",
        "request",
        "target",
        "active_jobs",
    }:
        raise AdapterError("request_envelope_invalid")
    if envelope.get("schema") != "qdev-fleet-worker-recovery-request-v1":
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
        request.get("schema") != "qdev-fleet-bootstrap-request-v2"
        or request.get("action") != "restore-existing-worker"
        or not isinstance(request.get("source_sha"), str)
        or SHA.fullmatch(request["source_sha"]) is None
        or request.get("worker_name") != target.get("worker_name")
        or any(
            request.get(name) is not None
            for name in (
                "controller_revision",
                "controller_release_digest",
                "controller_image_digest",
                "controller_internal_image_digest",
                "activation_envelope_digest",
                "release_lane",
            )
        )
        or isinstance(envelope.get("active_jobs"), bool)
        or not isinstance(envelope.get("active_jobs"), int)
        or envelope["active_jobs"] != 0
    ):
        raise AdapterError("request_identity_invalid")
    _validate_target(target)
    return envelope, request, target


def _registry_entry(target: dict[str, Any]) -> Path | None:
    metadata = REGISTRY.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise AdapterError("registry_permissions_invalid")
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    if (
        not isinstance(registry, dict)
        or set(registry) != {"schema", "targets"}
        or registry.get("schema") != "qdev-fleet-worker-recovery-targets-v1"
        or not isinstance(registry.get("targets"), dict)
    ):
        raise AdapterError("registry_schema_invalid")
    entry = registry["targets"].get(target["target_id"])
    if entry is None:
        return None
    if not isinstance(entry, dict) or set(entry) != TARGET_FIELDS | {"adapter_path"}:
        raise AdapterError("registry_entry_invalid")
    if any(entry[name] != target[name] for name in TARGET_FIELDS):
        raise AdapterError("registry_identity_mismatch")
    adapter = Path(str(entry["adapter_path"]))
    if not adapter.is_absolute() or adapter.parent != Path("/usr/local/sbin"):
        raise AdapterError("registry_adapter_path_invalid")
    adapter_stat = adapter.lstat()
    if (
        not stat.S_ISREG(adapter_stat.st_mode)
        or stat.S_ISLNK(adapter_stat.st_mode)
        or adapter_stat.st_uid != 0
        or stat.S_IMODE(adapter_stat.st_mode) & 0o022
        or not os.access(adapter, os.X_OK)
    ):
        raise AdapterError("registry_adapter_invalid")
    return adapter


def _fallback(target: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": "target_unregistered",
        "worker_name": target["worker_name"],
        "target_id": target["target_id"],
        "service_unit": target["service_unit"],
        "active_jobs": 0,
        "result": {"error_code": "target_unregistered"},
    }


def _safe_result(value: object) -> bool:
    return isinstance(value, dict) and all(
        isinstance(key, str)
        and not any(fragment in key.lower() for fragment in ("token", "password", "secret", "key"))
        and not isinstance(item, (dict, list))
        for key, item in value.items()
    )


def _validate_child(raw: object, target: dict[str, Any]) -> dict[str, Any]:
    expected = {
        "schema",
        "status",
        "worker_name",
        "target_id",
        "service_unit",
        "active_jobs",
        "result",
    }
    if not isinstance(raw, dict) or set(raw) != expected:
        raise AdapterError("child_response_invalid")
    if (
        raw.get("schema") != SCHEMA
        or raw.get("status")
        not in {"completed", "already_completed", "access_blocked", "target_unregistered", "failed"}
        or raw.get("worker_name") != target["worker_name"]
        or raw.get("target_id") != target["target_id"]
        or raw.get("service_unit") != target["service_unit"]
        or raw.get("active_jobs") != 0
        or not _safe_result(raw.get("result"))
    ):
        raise AdapterError("child_identity_invalid")
    return raw


def main() -> int:
    if os.geteuid() != 0:
        raise AdapterError("root_identity_required")
    envelope, _request, target = _parse()
    adapter = _registry_entry(target)
    if adapter is None:
        print(json.dumps(_fallback(target), sort_keys=True, separators=(",", ":")))
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
    response = _validate_child(json.loads(completed.stdout), target)
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
