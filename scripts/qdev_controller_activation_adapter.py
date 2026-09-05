#!/usr/bin/python3
"""Root-owned, fixed-target controller activation adapter.

The adapter deliberately accepts no argv or environment-selected paths.  It
validates the complete controller-produced envelope, derives the candidate
checkout from the exact revision, recomputes its immutable digest, and invokes
the candidate's fixed activation entrypoint with compare-and-swap semantics.
"""

from __future__ import annotations

import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any

RELEASES_ROOT = Path("/opt/qdev-runner-control-plane/releases")
STATUS_PATH = Path("/var/lib/qdev-runner/controller-status/controller-release.json")
SCHEMA = "qdev-fleet-bootstrap-adapter-result-v1"
REQUEST_SCHEMA = "qdev-fleet-bootstrap-adapter-request-v1"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
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
    "controller_revision",
    "controller_release_digest",
    "rollback_revision",
    "rollback_release_digest",
}


class AdapterError(RuntimeError):
    """A safe, non-secret activation rejection."""


def _read_json_stdin() -> dict[str, Any]:
    payload = sys.stdin.buffer.read(65537)
    if not payload or len(payload) > 65536:
        raise AdapterError("request_size_invalid")
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("request_json_invalid") from exc
    if not isinstance(value, dict) or set(value) != {"schema", "request", "target"}:
        raise AdapterError("request_envelope_invalid")
    if value.get("schema") != REQUEST_SCHEMA:
        raise AdapterError("request_schema_invalid")
    return value


def _validate_request(envelope: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    request = envelope.get("request")
    target = envelope.get("target")
    if not isinstance(request, dict) or set(request) != REQUEST_FIELDS:
        raise AdapterError("request_shape_invalid")
    if not isinstance(target, dict) or set(target) != TARGET_FIELDS:
        raise AdapterError("target_shape_invalid")
    if (
        request.get("schema") != "qdev-fleet-bootstrap-request-v1"
        or request.get("action") != "activate-controller"
        or request.get("release_lane") is not None
        or request.get("worker_name") is not None
    ):
        raise AdapterError("request_action_invalid")
    for name in ("run_id", "job_id", "attempt", "claim_ttl_seconds"):
        value = request.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise AdapterError("request_integer_invalid")
    revision = request.get("controller_revision")
    release_digest = request.get("controller_release_digest")
    source_sha = request.get("source_sha")
    if not isinstance(revision, str) or not SHA.fullmatch(revision):
        raise AdapterError("controller_revision_invalid")
    if source_sha != revision:
        raise AdapterError("source_binding_invalid")
    if not isinstance(release_digest, str) or not DIGEST.fullmatch(release_digest):
        raise AdapterError("controller_digest_invalid")
    if (
        target.get("controller_revision") != revision
        or target.get("controller_release_digest") != release_digest
        or not isinstance(target.get("rollback_revision"), str)
        or not SHA.fullmatch(str(target["rollback_revision"]))
        or not isinstance(target.get("rollback_release_digest"), str)
        or not DIGEST.fullmatch(str(target["rollback_release_digest"]))
    ):
        raise AdapterError("target_identity_invalid")
    return request, target


def _validate_root_directory(path: Path) -> Path:
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as exc:
        raise AdapterError("release_unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise AdapterError("release_ownership_invalid")
    return resolved


def _candidate(revision: str) -> Path:
    releases = _validate_root_directory(RELEASES_ROOT)
    candidate = _validate_root_directory(releases / revision)
    if candidate.parent != releases or candidate.name != revision:
        raise AdapterError("release_path_invalid")
    activation = candidate / "scripts" / "activate_controller_release.sh"
    identity = candidate / "src" / "qdev_runner" / "controller_release.py"
    for path in (activation, identity):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise AdapterError("release_entrypoint_unavailable") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise AdapterError("release_entrypoint_invalid")
    if not os.access(activation, os.X_OK):
        raise AdapterError("release_entrypoint_not_executable")
    return candidate


def _release_digest(candidate: Path) -> str:
    try:
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                "-c",
                (
                    "import sys; "
                    "sys.path.insert(0, sys.argv.pop(1)); "
                    "from qdev_runner.controller_release import main; main()"
                ),
                str(candidate / "src"),
                str(candidate),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterError("release_identity_unavailable") from exc
    digest = completed.stdout.strip()
    if completed.returncode != 0 or not DIGEST.fullmatch(digest):
        raise AdapterError("release_identity_invalid")
    return digest


def _read_status() -> tuple[str, str]:
    try:
        metadata = STATUS_PATH.lstat()
        payload = json.loads(STATUS_PATH.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("runtime_status_unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not isinstance(payload, dict)
        or set(payload)
        != {
            "schema",
            "state",
            "revision",
            "release_digest",
            "activated_at",
            "runtime_identity",
            "dependency_identity",
        }
        or payload.get("schema") != "qdev-controller-release-status-v2"
        or payload.get("state") != "active"
    ):
        raise AdapterError("runtime_status_invalid")
    revision = payload.get("revision")
    digest = payload.get("release_digest")
    if not isinstance(revision, str) or not SHA.fullmatch(revision):
        raise AdapterError("runtime_revision_invalid")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise AdapterError("runtime_digest_invalid")
    runtime_identity = payload.get("runtime_identity")
    dependency_identity = payload.get("dependency_identity")
    if (
        not isinstance(runtime_identity, dict)
        or set(runtime_identity)
        != {
            "source_revision",
            "source_digest",
            "public_image_id",
            "internal_image_id",
        }
        or runtime_identity.get("source_revision") != revision
        or not isinstance(dependency_identity, dict)
        or set(dependency_identity)
        != {
            "requirements_digest",
            "public_installed_digest",
            "internal_installed_digest",
        }
    ):
        raise AdapterError("runtime_measurements_invalid")
    measured_digests = (
        runtime_identity.get("source_digest"),
        runtime_identity.get("public_image_id"),
        runtime_identity.get("internal_image_id"),
        dependency_identity.get("requirements_digest"),
        dependency_identity.get("public_installed_digest"),
        dependency_identity.get("internal_installed_digest"),
    )
    if any(not isinstance(value, str) or not DIGEST.fullmatch(value) for value in measured_digests):
        raise AdapterError("runtime_measurements_invalid")
    if (
        dependency_identity["public_installed_digest"]
        != dependency_identity["internal_installed_digest"]
    ):
        raise AdapterError("runtime_dependencies_inconsistent")
    return revision, digest


def _response(
    request: dict[str, Any],
    target: dict[str, Any],
    *,
    status: str,
    result: dict[str, str | int | bool | None],
) -> dict[str, Any]:
    return {
        "schema": SCHEMA,
        "status": status,
        "action": "activate-controller",
        "controller_revision": request["controller_revision"],
        "controller_release_digest": request["controller_release_digest"],
        "release_lane": None,
        "host_agent_mtls_identity": None,
        "rollback_source_sha": target["rollback_revision"],
        "rollback_artifact_digest": target["rollback_release_digest"],
        "result": result,
    }


def main() -> int:
    if os.geteuid() != 0:
        raise AdapterError("root_identity_required")
    envelope = _read_json_stdin()
    request, target = _validate_request(envelope)
    candidate = _candidate(str(request["controller_revision"]))
    if _release_digest(candidate) != request["controller_release_digest"]:
        raise AdapterError("release_digest_mismatch")
    current_revision, current_digest = _read_status()
    if (
        current_revision == request["controller_revision"]
        and current_digest == request["controller_release_digest"]
    ):
        response = _response(
            request,
            target,
            status="already_completed",
            result={"runtime_revision": current_revision, "runtime_digest": current_digest},
        )
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
        return 0
    if (
        current_revision != target["rollback_revision"]
        or current_digest != target["rollback_release_digest"]
    ):
        raise AdapterError("rollback_anchor_mismatch")
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION": current_revision,
    }
    try:
        completed = subprocess.run(
            [str(candidate / "scripts" / "activate_controller_release.sh"), str(candidate)],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            timeout=1800,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterError("activation_outcome_unknown") from exc
    if completed.returncode != 0:
        raise AdapterError("activation_failed")
    runtime_revision, runtime_digest = _read_status()
    if (
        runtime_revision != request["controller_revision"]
        or runtime_digest != request["controller_release_digest"]
    ):
        raise AdapterError("activation_identity_mismatch")
    response = _response(
        request,
        target,
        status="completed",
        result={"runtime_revision": runtime_revision, "runtime_digest": runtime_digest},
    )
    print(json.dumps(response, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AdapterError as error:
        # A non-zero exit is deliberate: the root dispatcher records an
        # unknown/failed outcome and will never guess that a mutation succeeded.
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
