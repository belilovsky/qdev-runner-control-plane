#!/usr/bin/python3
"""Root-owned, fixed-target controller activation adapter.

The adapter deliberately accepts no argv or environment-selected paths.  It
validates the complete controller-produced envelope, derives the candidate
checkout from the exact revision, recomputes its immutable digest, and invokes
the candidate's fixed activation entrypoint with compare-and-swap semantics.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

RELEASES_ROOT = Path("/opt/qdev-runner-control-plane/releases")
CURRENT_RELEASE = Path("/opt/qdev-runner-control-plane/current")
STATUS_PATH = Path("/var/lib/qdev-runner/controller-status/controller-release.json")
ACTIVATION_STATUS_PATH = Path("/var/lib/qdev-runner/controller-activation/activation-status.json")
ACTIVATION_ASSETS_ROOT = Path("/var/lib/qdev-runner/controller-activation")
ACTIVATION_PUBLIC_KEY = Path("/etc/qdev-runner/trust/controller-activation-ed25519.pub")
ACTIVATION_TRUST_BINDING = Path("/etc/qdev-runner/trust/controller-activation-trust-binding.json")
ADMISSION_PUBLIC_KEY = Path("/etc/qdev-runner/admission/ed25519-public.pem")
SCHEMA = "qdev-fleet-bootstrap-adapter-result-v2"
REQUEST_SCHEMA = "qdev-fleet-bootstrap-adapter-request-v2"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
TRANSACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
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
TARGET_FIELDS = {
    "controller_revision",
    "controller_release_digest",
    "controller_image_digest",
    "controller_internal_image_digest",
    "activation_envelope_digest",
    "activation_mode",
    "activation_envelope_schema",
    "activation_public_key_binding",
    "activation_max_envelope_ttl_seconds",
    # The dispatcher obtains these values from the measured runtime immediately
    # before it invokes us.  They are a compare-and-swap anchor: an envelope
    # prepared for an earlier runtime must never activate a candidate.
    "rollback_revision",
    "rollback_release_digest",
}
LEGACY_REQUEST_FIELDS = REQUEST_FIELDS - {"controller_internal_image_digest"}
LEGACY_TARGET_FIELDS = TARGET_FIELDS - {
    "controller_internal_image_digest",
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
    if not isinstance(request, dict) or set(request) not in {
        frozenset(REQUEST_FIELDS),
        frozenset(LEGACY_REQUEST_FIELDS),
    }:
        raise AdapterError("request_shape_invalid")
    if not isinstance(target, dict) or set(target) not in {
        frozenset(TARGET_FIELDS),
        frozenset(LEGACY_TARGET_FIELDS),
    }:
        raise AdapterError("target_shape_invalid")
    request = dict(request)
    target = dict(target)
    request.setdefault("controller_internal_image_digest", request.get("controller_image_digest"))
    target.setdefault("controller_internal_image_digest", target.get("controller_image_digest"))
    if (
        request.get("schema") != "qdev-fleet-bootstrap-request-v2"
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
    image_digest = request.get("controller_image_digest")
    internal_image_digest = request.get("controller_internal_image_digest")
    envelope_digest = request.get("activation_envelope_digest")
    source_sha = request.get("source_sha")
    if not isinstance(revision, str) or not SHA.fullmatch(revision):
        raise AdapterError("controller_revision_invalid")
    if source_sha != revision:
        raise AdapterError("source_binding_invalid")
    if not isinstance(release_digest, str) or not DIGEST.fullmatch(release_digest):
        raise AdapterError("controller_digest_invalid")
    if not isinstance(image_digest, str) or not DIGEST.fullmatch(image_digest):
        raise AdapterError("controller_image_digest_invalid")
    if not isinstance(internal_image_digest, str) or not DIGEST.fullmatch(internal_image_digest):
        raise AdapterError("controller_internal_image_digest_invalid")
    if not isinstance(envelope_digest, str) or not DIGEST.fullmatch(envelope_digest):
        raise AdapterError("activation_envelope_digest_invalid")
    rollback_revision = target.get("rollback_revision")
    rollback_release_digest = target.get("rollback_release_digest")
    if rollback_revision is not None and (
        not isinstance(rollback_revision, str) or not SHA.fullmatch(rollback_revision)
    ):
        raise AdapterError("rollback_revision_invalid")
    if rollback_release_digest is not None and (
        not isinstance(rollback_release_digest, str)
        or not DIGEST.fullmatch(rollback_release_digest)
    ):
        raise AdapterError("rollback_release_digest_invalid")
    if (
        target.get("controller_revision") != revision
        or target.get("controller_release_digest") != release_digest
        or target.get("controller_image_digest") != image_digest
        or target.get("controller_internal_image_digest") != internal_image_digest
        or target.get("activation_envelope_digest") != envelope_digest
        or target.get("activation_mode") != "signed-external-envelope"
        or target.get("activation_envelope_schema") != "qdev-controller-activation-envelope-v1"
        or target.get("activation_public_key_binding") != "controller-registry"
        or isinstance(target.get("activation_max_envelope_ttl_seconds"), bool)
        or target.get("activation_max_envelope_ttl_seconds") != 1800
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


def _validate_trusted_path_chain(path: Path, *, stop: Path) -> None:
    """Reject writable or non-root ancestors on the executable trust path."""

    stop_resolved = stop.resolve(strict=True)
    current = path.resolve(strict=True)
    while True:
        try:
            metadata = current.lstat()
        except OSError as exc:
            raise AdapterError("trusted_path_unavailable") from exc
        if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise AdapterError("trusted_path_ownership_invalid")
        if current == stop_resolved:
            return
        if stop_resolved not in current.parents:
            raise AdapterError("trusted_path_boundary_invalid")
        current = current.parent


def _candidate(revision: str) -> Path:
    releases = _validate_root_directory(RELEASES_ROOT)
    candidate = _validate_root_directory(releases / revision)
    if candidate.parent != releases or candidate.name != revision:
        raise AdapterError("release_path_invalid")
    return candidate


def _trusted_current(revision: str, release_digest: str) -> tuple[Path, Path]:
    """Resolve the active, measured release as the only executable trust root.

    A candidate checkout is untrusted input until the already-active wrapper
    verifies its signed envelope and source fingerprint.  In particular, the
    adapter must never execute a helper or activation script from the candidate.
    """

    try:
        link_metadata = CURRENT_RELEASE.lstat()
    except OSError as exc:
        raise AdapterError("current_release_unavailable") from exc
    if not stat.S_ISLNK(link_metadata.st_mode) or link_metadata.st_uid != 0:
        raise AdapterError("current_release_link_invalid")
    releases = _validate_root_directory(RELEASES_ROOT)
    current = _validate_root_directory(CURRENT_RELEASE)
    if current.parent != releases or current.name != revision:
        raise AdapterError("current_release_identity_invalid")
    activation = current / "scripts" / "activate_controller_release.sh"
    identity = current / "src" / "qdev_runner" / "controller_release.py"
    for path in (activation, identity):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise AdapterError("trusted_entrypoint_unavailable") from exc
        if (
            not stat.S_ISREG(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise AdapterError("trusted_entrypoint_invalid")
        _validate_trusted_path_chain(path.parent, stop=releases)
    if not os.access(activation, os.X_OK):
        raise AdapterError("trusted_entrypoint_not_executable")
    try:
        completed = subprocess.run(
            [
                "/usr/bin/python3",
                "-I",
                str(identity),
                str(current),
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterError("trusted_release_identity_unavailable") from exc
    digest = completed.stdout.strip()
    if completed.returncode != 0 or digest != release_digest:
        raise AdapterError("trusted_release_identity_invalid")
    return current, activation


def _private_file(path: Path, *, mode: int | None = None) -> Path:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise AdapterError("activation_asset_unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (mode is not None and stat.S_IMODE(metadata.st_mode) != mode)
    ):
        raise AdapterError("activation_asset_invalid")
    return path


def _activation_public_key() -> Path:
    """Resolve the activation verifier only through the admitted key binding.

    The activation key is deliberately not a caller-selected file.  It is a
    byte-for-byte copy of the controller admission public key, bound by a
    root-owned record installed by the fixed provisioning helper.  Keeping the
    binding separate from the request prevents a controller policy entry from
    silently retargeting activation to an unrelated local key.
    """

    public_key = _private_file(ACTIVATION_PUBLIC_KEY)
    admission_key = _private_file(ADMISSION_PUBLIC_KEY)
    binding_path = _private_file(ACTIVATION_TRUST_BINDING)
    try:
        public_key_bytes = public_key.read_bytes()
        admission_key_bytes = admission_key.read_bytes()
        binding = json.loads(binding_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("activation_trust_binding_unavailable") from exc
    expected = {
        "schema": "qdev-controller-activation-trust-binding-v1",
        "binding": "controller-registry",
        "authority": "controller-admission",
        "source_path": str(ADMISSION_PUBLIC_KEY),
        "source_sha256": "sha256:" + hashlib.sha256(admission_key_bytes).hexdigest(),
        "activation_public_key_path": str(ACTIVATION_PUBLIC_KEY),
        "activation_public_key_sha256": "sha256:" + hashlib.sha256(public_key_bytes).hexdigest(),
    }
    if (
        not isinstance(binding, dict)
        or binding != expected
        or public_key_bytes != admission_key_bytes
    ):
        raise AdapterError("activation_trust_binding_invalid")
    return public_key


def _read_status() -> tuple[str, str, str, str]:
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
    runtime = payload.get("runtime_identity")
    dependencies = payload.get("dependency_identity")
    if not isinstance(revision, str) or not SHA.fullmatch(revision):
        raise AdapterError("runtime_revision_invalid")
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise AdapterError("runtime_digest_invalid")
    if (
        not isinstance(runtime, dict)
        or set(runtime)
        != {"source_revision", "source_digest", "public_image_id", "internal_image_id"}
        or runtime.get("source_revision") != revision
        or not isinstance(dependencies, dict)
        or set(dependencies)
        != {
            "requirements_digest",
            "public_installed_digest",
            "internal_installed_digest",
        }
    ):
        raise AdapterError("runtime_measurements_invalid")
    measured_digests = (
        runtime.get("source_digest"),
        runtime.get("public_image_id"),
        runtime.get("internal_image_id"),
        dependencies.get("requirements_digest"),
        dependencies.get("public_installed_digest"),
        dependencies.get("internal_installed_digest"),
    )
    if any(not isinstance(value, str) or not DIGEST.fullmatch(value) for value in measured_digests):
        raise AdapterError("runtime_measurements_invalid")
    if dependencies["public_installed_digest"] != dependencies["internal_installed_digest"]:
        raise AdapterError("runtime_dependencies_inconsistent")
    return revision, digest, runtime["public_image_id"], runtime["internal_image_id"]


def _read_activation_status(
    *,
    expected_source_sha: str,
    expected_public_image_digest: str,
    expected_internal_image_digest: str,
    expected_policy_digest: str,
    expected_transaction_id: str,
) -> tuple[str, str, str, str, int]:
    path = _private_file(ACTIVATION_STATUS_PATH)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("activation_status_unavailable") from exc
    legacy_required = {
        "schema",
        "state",
        "generation",
        "source_sha",
        "image_digest",
        "policy_bundle_digest",
        "previous",
        "transaction_id",
        "activated_at",
    }
    current_required = (legacy_required - {"image_digest"}) | {
        "public_image_digest",
        "internal_image_digest",
    }
    is_legacy = isinstance(payload, dict) and set(payload) == legacy_required
    public_image_digest = payload.get("image_digest" if is_legacy else "public_image_digest")
    internal_image_digest = (
        public_image_digest if is_legacy else payload.get("internal_image_digest")
    )
    previous = payload.get("previous") if isinstance(payload, dict) else None
    activated_at = payload.get("activated_at") if isinstance(payload, dict) else None
    try:
        parsed_activated_at = (
            datetime.fromisoformat(activated_at.replace("Z", "+00:00"))
            if isinstance(activated_at, str) and activated_at.endswith("Z")
            else None
        )
    except ValueError:
        parsed_activated_at = None
    if (
        not isinstance(payload, dict)
        or set(payload) not in {frozenset(legacy_required), frozenset(current_required)}
        or payload.get("schema")
        != (
            "qdev-controller-activation-status-v1"
            if is_legacy
            else "qdev-controller-activation-status-v2"
        )
        or payload.get("state") != "active"
        or isinstance(payload.get("generation"), bool)
        or not isinstance(payload.get("generation"), int)
        or payload["generation"] < 1
        or payload.get("source_sha") != expected_source_sha
        or public_image_digest != expected_public_image_digest
        or internal_image_digest != expected_internal_image_digest
        or payload.get("policy_bundle_digest") != expected_policy_digest
        or payload.get("transaction_id") != expected_transaction_id
        or not TRANSACTION_ID.fullmatch(expected_transaction_id)
        or parsed_activated_at is None
        or parsed_activated_at.tzinfo is None
        or parsed_activated_at.astimezone(UTC) != parsed_activated_at
        or not isinstance(previous, dict)
        or set(previous)
        not in {
            frozenset({"generation", "source_sha", "image_digest", "policy_bundle_digest"}),
            frozenset(
                {
                    "generation",
                    "source_sha",
                    "public_image_digest",
                    "internal_image_digest",
                    "policy_bundle_digest",
                }
            ),
        }
        or isinstance(previous.get("generation"), bool)
        or not isinstance(previous.get("generation"), int)
        or previous["generation"] < 0
        or previous["generation"] >= payload["generation"]
        or not isinstance(previous.get("source_sha"), str)
        or not SHA.fullmatch(previous["source_sha"])
        or not isinstance(previous.get("policy_bundle_digest"), str)
        or not HEX_DIGEST.fullmatch(previous["policy_bundle_digest"])
    ):
        raise AdapterError("activation_status_invalid")
    previous_public = previous.get("image_digest", previous.get("public_image_digest"))
    previous_internal = previous.get("image_digest", previous.get("internal_image_digest"))
    if (
        not isinstance(previous_public, str)
        or not HEX_DIGEST.fullmatch(previous_public)
        or not isinstance(previous_internal, str)
        or not HEX_DIGEST.fullmatch(previous_internal)
    ):
        raise AdapterError("activation_status_invalid")
    return (
        previous["source_sha"],
        "sha256:" + previous_public,
        "sha256:" + previous_internal,
        "sha256:" + previous["policy_bundle_digest"],
        previous["generation"],
    )


def _activation_assets(request: dict[str, Any]) -> tuple[Path, Path, Path, str, str]:
    digest = str(request["activation_envelope_digest"])
    envelope_path = _private_file(
        ACTIVATION_ASSETS_ROOT / "envelopes" / f"{digest[7:]}.json", mode=0o600
    )
    try:
        envelope = json.loads(envelope_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("activation_envelope_invalid") from exc
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest() != digest:
        raise AdapterError("activation_envelope_digest_mismatch")
    candidate = envelope.get("candidate") if isinstance(envelope, dict) else None
    manifest_digest = (
        envelope.get("artifact_manifest_digest") if isinstance(envelope, dict) else None
    )
    candidate_release_digest = (
        envelope.get("candidate_release_digest") if isinstance(envelope, dict) else None
    )
    transaction_id = envelope.get("transaction_id") if isinstance(envelope, dict) else None
    candidate_policy_digest = (
        candidate.get("policy_bundle_digest") if isinstance(candidate, dict) else None
    )
    requested_internal_image = request.get(
        "controller_internal_image_digest", request.get("controller_image_digest")
    )
    if (
        envelope.get("schema") != "qdev-controller-activation-envelope-v1"
        or not isinstance(candidate, dict)
        or candidate.get("source_sha") != request["controller_revision"]
        or candidate.get("public_image_digest", candidate.get("image_digest"))
        != str(request["controller_image_digest"])[7:]
        or candidate.get("internal_image_digest", candidate.get("image_digest"))
        != str(requested_internal_image)[7:]
        or candidate_release_digest != str(request["controller_release_digest"])[7:]
        or not isinstance(manifest_digest, str)
        or not HEX_DIGEST.fullmatch(manifest_digest)
        or not isinstance(candidate_policy_digest, str)
        or not HEX_DIGEST.fullmatch(candidate_policy_digest)
        or not isinstance(transaction_id, str)
        or not TRANSACTION_ID.fullmatch(transaction_id)
    ):
        raise AdapterError("activation_envelope_identity_mismatch")
    manifest_path = _private_file(
        ACTIVATION_ASSETS_ROOT / "artifacts" / f"{manifest_digest}.json", mode=0o600
    )
    public_key = _activation_public_key()
    return envelope_path, manifest_path, public_key, candidate_policy_digest, transaction_id


def _response(
    request: dict[str, Any],
    rollback: tuple[str, str, str, str, int],
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
        "controller_image_digest": request["controller_image_digest"],
        "controller_internal_image_digest": request["controller_internal_image_digest"],
        "activation_envelope_digest": request["activation_envelope_digest"],
        "release_lane": None,
        "host_agent_mtls_identity": None,
        "rollback_source_sha": rollback[0],
        "rollback_artifact_digest": rollback[1],
        "rollback_internal_artifact_digest": rollback[2],
        "rollback_policy_digest": rollback[3],
        "rollback_generation": rollback[4],
        "result": result,
    }


def main() -> int:
    if os.geteuid() != 0:
        raise AdapterError("root_identity_required")
    envelope = _read_json_stdin()
    request, target = _validate_request(envelope)
    candidate = _candidate(str(request["controller_revision"]))
    (
        activation_envelope,
        artifact_manifest,
        public_key,
        candidate_policy_digest,
        transaction_id,
    ) = _activation_assets(request)
    current_revision, current_digest, current_image, current_internal_image = _read_status()
    # Current dispatcher requests always carry the measured rollback anchor.
    # Retain the old target shape only for a completed historical request; a
    # present anchor must match the just-read runtime before any payload runs.
    if target.get("rollback_revision") is not None and (
        target["rollback_revision"] != current_revision
        or target["rollback_release_digest"] != current_digest
    ):
        raise AdapterError("rollback_anchor_mismatch")
    _current, activation = _trusted_current(current_revision, current_digest)
    was_already_active = (
        current_revision == request["controller_revision"]
        and current_digest == request["controller_release_digest"]
        and current_image == request["controller_image_digest"]
        and current_internal_image == request["controller_internal_image_digest"]
    )
    environment = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PYTHONNOUSERSITE": "1",
        "QDEV_CONTROLLER_ACTIVATION_ENVELOPE": str(activation_envelope),
        "QDEV_CONTROLLER_ACTIVATION_PUBLIC_KEY": str(public_key),
        "QDEV_CONTROLLER_ARTIFACT_MANIFEST": str(artifact_manifest),
    }
    if not ACTIVATION_STATUS_PATH.exists():
        environment["QDEV_CONTROLLER_ALLOW_MEASURED_STATUS_BOOTSTRAP"] = "true"
    try:
        completed = subprocess.run(
            [str(activation), str(candidate)],
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
    runtime_revision, runtime_digest, runtime_image, runtime_internal_image = _read_status()
    if (
        runtime_revision != request["controller_revision"]
        or runtime_digest != request["controller_release_digest"]
        or runtime_image != request["controller_image_digest"]
        or runtime_internal_image != request["controller_internal_image_digest"]
    ):
        raise AdapterError("activation_identity_mismatch")
    rollback = _read_activation_status(
        expected_source_sha=str(request["controller_revision"]),
        expected_public_image_digest=str(request["controller_image_digest"])[7:],
        expected_internal_image_digest=str(request["controller_internal_image_digest"])[7:],
        expected_policy_digest=candidate_policy_digest,
        expected_transaction_id=transaction_id,
    )
    response = _response(
        request,
        rollback,
        status="already_completed" if was_already_active else "completed",
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
