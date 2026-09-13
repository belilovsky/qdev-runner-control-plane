#!/usr/bin/python3
"""Root-owned, fixed-target controller activation adapter.

The adapter deliberately accepts no argv or environment-selected paths.  It
validates the complete controller-produced envelope, derives the candidate
checkout from the exact revision, recomputes its immutable digest, and invokes
the candidate's fixed activation entrypoint with compare-and-swap semantics.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

RELEASES_ROOT = Path("/opt/qdev-runner-control-plane/releases")
CURRENT_RELEASE = Path("/opt/qdev-runner-control-plane/current")
STATUS_PATH = Path("/var/lib/qdev-runner/controller-status/controller-release.json")
ACTIVATION_STATUS_PATH = Path("/var/lib/qdev-runner/controller-activation/activation-status.json")
ACTIVATION_ASSETS_ROOT = Path("/var/lib/qdev-runner/controller-activation")
ACTIVATION_PROJECTION_PATH = Path(
    "/var/lib/qdev-runner/controller-status/controller-activation.json"
)
ACTIVATION_TRANSACTION_ROOT = Path("/var/lib/qdev-runner/controller-activation-transactions")
ROLLBACK_ANCHOR_PATH = Path("/etc/qdev-runner/controller-rollback-anchor.json")
ACTIVATION_PUBLIC_KEY = Path("/etc/qdev-runner/trust/controller-activation-ed25519.pub")
ACTIVATION_TRUST_BINDING = Path("/etc/qdev-runner/trust/controller-activation-trust-binding.json")
ADMISSION_PUBLIC_KEY = Path("/etc/qdev-runner/admission/ed25519-public.pem")
SCHEMA = "qdev-fleet-bootstrap-adapter-result-v2"
REQUEST_SCHEMA = "qdev-fleet-bootstrap-adapter-request-v2"
ACTIVATE_ACTION = "activate-controller"
RECONCILE_ACTION = "reconcile-controller-activation"
ACTIONS = (ACTIVATE_ACTION, RECONCILE_ACTION)
ACTIVATION_ENVELOPE_SCHEMA = "qdev-controller-activation-envelope-v1"
ACTIVATION_STATUS_SCHEMA = "qdev-controller-activation-status-v2"
LEGACY_ACTIVATION_STATUS_SCHEMA = "qdev-controller-activation-status-v1"
ACTIVATION_TRANSACTION_SCHEMA = "qdev-controller-activation-transaction-v1"
ACTIVATION_PROJECTION_SCHEMA = "qdev-controller-activation-projection-v1"
ROLLBACK_ANCHOR_SCHEMA = "qdev-controller-rollback-anchor-v1"
MATERIAL_SCHEMA = "qdev-controller-activation-material-v1"
RECONCILE_SCHEMA = "qdev-controller-reconciliation-v1"
MAX_ENVELOPE_TTL_SECONDS = 1800
MAX_CLOCK_SKEW_SECONDS = 60
ENVELOPE_FIELDS = {
    "schema",
    "transaction_id",
    "issued_at",
    "expires_at",
    "expected_generation",
    "expected_current",
    "expected_current_status_digest",
    "expected_current_config_digest",
    "candidate",
    "candidate_release_digest",
    "candidate_config_digest",
    "artifact_manifest_digest",
    "entrypoint_reconciliation_digest",
    "signature",
}
TUPLE_FIELDS = {
    "source_sha",
    "public_image_digest",
    "internal_image_digest",
    "policy_bundle_digest",
}
# The exact effective configuration the activation entrypoint fingerprints for
# the current runtime.  Reconciliation recomputes the same digest from the same
# logical names so a drifted host can never be reconciled into a candidate.
CONTROLLER_CONFIG_FILES = {
    "repos.json": Path("/etc/qdev-runner/repos.json"),
    "profiles.yml": Path("/etc/qdev-runner/profiles.yml"),
    "admin-platform-package-bindings.json": Path(
        "/etc/qdev-runner/admin-platform-package-bindings.json"
    ),
    "release-lanes.yml": Path("/etc/qdev-runner/release-lanes.yml"),
    "managed-registry.yml": Path("/etc/qdev-runner/managed-registry.yml"),
    "fleet-bootstrap.yml": Path("/etc/qdev-runner/fleet-bootstrap.yml"),
    "managed-release-ledger.yml": Path("/etc/qdev-runner/managed-release-ledger.yml"),
}
MATERIAL_TRANSACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ENVELOPE_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
TRANSACTION_FIELDS = {
    "schema",
    "transaction_id",
    "envelope_digest",
    "expected_generation",
    "expected_current",
    "expected_current_status_digest",
    "expected_current_config_digest",
    "candidate",
    "candidate_release_digest",
    "candidate_config_digest",
    "artifact_manifest_digest",
    "entrypoint_reconciliation_digest",
    "reserved_status_digest",
    "committed_status_digest",
    "committed_activated_at",
    "expires_at",
}
CANDIDATE_FIELDS = {
    "source_sha",
    "public_image_digest",
    "internal_image_digest",
    "policy_bundle_digest",
}
STATUS_FIELDS = {
    "schema",
    "state",
    "generation",
    "source_sha",
    "public_image_digest",
    "internal_image_digest",
    "policy_bundle_digest",
    "previous",
    "transaction_id",
    "activated_at",
}
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
# Reconciliation finalises an already committed transaction; the live rollback
# anchor is deliberately not an input to that operation, so the anchor fields
# are optional for it (the dispatcher still supplies them, which must also be
# accepted).
RECONCILE_TARGET_FIELDS = TARGET_FIELDS - {"rollback_revision", "rollback_release_digest"}


class AdapterError(RuntimeError):
    """A safe, non-secret activation rejection."""


FAILURE_SCHEMA = "qdev-controller-activation-failure-v1"
FAILURE_CODE = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
PERMITTED_ACTION_RECONCILE = "reconcile-controller-activation"
PERMITTED_ACTION_RETRY = "retry-fleet-bootstrap"
PERMITTED_ACTION_REVIEW = "operator-review"
# Codes that may follow a payload that had already begun mutating the runtime.
# They require the signed root-dispatch reconciliation operation rather than an
# unbounded retry, and never authorise an automatic rollback.
_RECONCILE_CODES = frozenset(
    {
        "activation_failed",
        "activation_outcome_unknown",
        "activation_identity_mismatch",
        "rollback_anchor_mismatch",
        "activation_mutating_failed",
        "activation_rollback_anchor_failed",
        "activation_configuration_failed",
        "activation_activate_link_failed",
        "activation_broker_state_failed",
        "activation_host_dispatch_failed",
        "activation_config_installed_failed",
        "activation_compose_failed",
        "activation_public_health_failed",
        "activation_operator_identity_failed",
        "activation_runtime_identity_failed",
        "activation_release_status_failed",
        "activation_runtime_health_failed",
        "activation_candidate_active_failed",
        "activation_commit_candidate_failed",
        "activation_external_guard_failed",
        "activation_finalization_failed",
        "activation_entrypoint_setup_failed",
        "activation_entrypoint_attestation_failed",
        "activation_entrypoint_config_failed",
        "activation_entrypoint_envelope_failed",
        "activation_entrypoint_reservation_failed",
        "activation_entrypoint_image_failed",
        "activation_entrypoint_cas_failed",
        "activation_payload_preflight_failed",
        "activation_entrypoint_finalize_failed",
    }
)
_FAILURE_CONTEXT: dict[str, Any] = {}
_PAYLOAD_FAILURE_STAGE = re.compile(
    r"(?m)^qdev_activation_failure_stage=("
    r"preflight_cas|preflight_hook|preflight_status|mutating|rollback_anchor|"
    r"configuration|activate_link|broker_state|"
    r"host_dispatch|config_installed|compose|public_health|operator_identity|"
    r"runtime_identity|release_status|runtime_health|"
    r"candidate_active|commit_candidate|external_guard|finalization|"
    r"entrypoint_setup|entrypoint_attestation|entrypoint_config|"
    r"entrypoint_envelope|entrypoint_reservation|entrypoint_image|"
    r"entrypoint_cas|payload_preflight|entrypoint_finalize"
    r")$"
)


def _payload_failure_code(stderr: str) -> str | None:
    """Return one closed payload failure code, never its raw stderr."""

    stages = _PAYLOAD_FAILURE_STAGE.findall(stderr)
    if not stages:
        return None
    # The trusted wrapper can emit a broad pre-payload boundary before the
    # payload supplies a more specific closed-vocabulary stage. The final
    # marker wins; raw stderr never becomes durable diagnostic state.
    return f"activation_{stages[-1]}_failed"


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
    action = request.get("action")
    if action == ACTIVATE_ACTION:
        accepted_targets = {frozenset(TARGET_FIELDS), frozenset(LEGACY_TARGET_FIELDS)}
    elif action == RECONCILE_ACTION:
        accepted_targets = {
            frozenset(TARGET_FIELDS),
            frozenset(RECONCILE_TARGET_FIELDS),
            frozenset(LEGACY_TARGET_FIELDS),
        }
    else:
        raise AdapterError("request_action_invalid")
    if not isinstance(target, dict) or frozenset(target) not in accepted_targets:
        raise AdapterError("target_shape_invalid")
    request = dict(request)
    target = dict(target)
    request.setdefault("controller_internal_image_digest", request.get("controller_image_digest"))
    target.setdefault("controller_internal_image_digest", target.get("controller_image_digest"))
    if (
        request.get("schema") != "qdev-fleet-bootstrap-request-v2"
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
    envelope = _read_envelope_document(envelope_path, expected_digest=digest)
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
    # New releases stage each manifest with its relative artifact descriptors
    # under a digest-addressed bundle.  Retain the former flat manifest path
    # for an already active historical release during adapter upgrades.
    bundle_manifest = (
        ACTIVATION_ASSETS_ROOT / "artifacts" / manifest_digest / "controller-artifact-manifest.json"
    )
    legacy_manifest = ACTIVATION_ASSETS_ROOT / "artifacts" / f"{manifest_digest}.json"
    manifest_path = _private_file(
        bundle_manifest if bundle_manifest.exists() else legacy_manifest, mode=0o600
    )
    public_key = _activation_public_key()
    return envelope_path, manifest_path, public_key, candidate_policy_digest, transaction_id


def _canonical(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _parse_time(value: object) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        return None
    return parsed.astimezone(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _parse_tuple(value: object) -> dict[str, str] | None:
    """Normalise a current or legacy controller tuple to one exact shape."""

    legacy_fields = {"source_sha", "image_digest", "policy_bundle_digest"}
    current_fields = {
        "source_sha",
        "public_image_digest",
        "internal_image_digest",
        "policy_bundle_digest",
    }
    if not isinstance(value, dict):
        return None
    if set(value) == legacy_fields:
        public_image_digest = value["image_digest"]
        internal_image_digest = public_image_digest
    elif set(value) == current_fields:
        public_image_digest = value["public_image_digest"]
        internal_image_digest = value["internal_image_digest"]
    else:
        return None
    source_sha = value["source_sha"]
    policy_bundle_digest = value["policy_bundle_digest"]
    if not isinstance(source_sha, str) or not SHA.fullmatch(source_sha):
        return None
    if (
        not isinstance(public_image_digest, str)
        or not HEX_DIGEST.fullmatch(public_image_digest)
        or not isinstance(internal_image_digest, str)
        or not HEX_DIGEST.fullmatch(internal_image_digest)
        or not isinstance(policy_bundle_digest, str)
        or not HEX_DIGEST.fullmatch(policy_bundle_digest)
    ):
        return None
    return {
        "source_sha": source_sha,
        "public_image_digest": public_image_digest,
        "internal_image_digest": internal_image_digest,
        "policy_bundle_digest": policy_bundle_digest,
    }


def _read_envelope_document(path: Path, *, expected_digest: str) -> dict[str, Any]:
    """Read one digest-addressed staged envelope and re-prove its raw digest."""

    envelope_path = _private_file(path, mode=0o600)
    try:
        document = json.loads(envelope_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("activation_envelope_invalid") from exc
    if not isinstance(document, dict):
        raise AdapterError("activation_envelope_invalid")
    if "sha256:" + hashlib.sha256(_canonical(document)).hexdigest() != expected_digest:
        raise AdapterError("activation_envelope_digest_mismatch")
    return document


def _verify_activation_envelope(
    document: dict[str, Any],
    *,
    public_key: Path,
    expected_digest: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Verify a signed activation envelope, tolerating an expired one.

    Expiry is accepted only as an *input* to the committed-transaction proof.
    Reconciliation never replays the envelope into a runtime mutation, so an
    expired signature is still the durable evidence that this exact candidate
    was authorised; every other property of the envelope remains mandatory.
    """

    if set(document) != ENVELOPE_FIELDS:
        raise AdapterError("activation_envelope_shape_invalid")
    if document.get("schema") != ACTIVATION_ENVELOPE_SCHEMA:
        raise AdapterError("activation_envelope_schema_invalid")
    transaction_id = document.get("transaction_id")
    signature = document.get("signature")
    if not isinstance(transaction_id, str) or not TRANSACTION_ID.fullmatch(transaction_id):
        raise AdapterError("activation_transaction_id_invalid")
    if not isinstance(signature, str) or not ENVELOPE_SIGNATURE.fullmatch(signature):
        raise AdapterError("activation_envelope_signature_invalid")
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    try:
        signature_bytes = base64.urlsafe_b64decode(f"{signature}==")
        verifier = load_pem_public_key(_private_file(public_key).read_bytes())
        verifier.verify(signature_bytes, _canonical(unsigned))
        canonical_signature = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")
    except (InvalidSignature, ValueError, OSError, UnicodeDecodeError) as exc:
        raise AdapterError("activation_envelope_signature_invalid") from exc
    if len(signature_bytes) != 64 or canonical_signature != signature:
        raise AdapterError("activation_envelope_signature_invalid")
    issued_at = _parse_time(document.get("issued_at"))
    expires_at = _parse_time(document.get("expires_at"))
    if issued_at is None or expires_at is None:
        raise AdapterError("activation_envelope_time_invalid")
    observed_at = (now or datetime.now(UTC)).astimezone(UTC)
    if issued_at > observed_at + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS):
        raise AdapterError("activation_envelope_not_yet_valid")
    if (
        expires_at <= issued_at
        or (expires_at - issued_at).total_seconds() > MAX_ENVELOPE_TTL_SECONDS
    ):
        raise AdapterError("activation_envelope_ttl_invalid")
    expected_generation = document.get("expected_generation")
    if (
        isinstance(expected_generation, bool)
        or not isinstance(expected_generation, int)
        or expected_generation < 0
    ):
        raise AdapterError("activation_expected_generation_invalid")
    expected_current = _parse_tuple(document.get("expected_current"))
    candidate = _parse_tuple(document.get("candidate"))
    if expected_current is None:
        raise AdapterError("activation_expected_current_invalid")
    if candidate is None:
        raise AdapterError("activation_candidate_invalid")
    digests = {
        "expected_current_status_digest": document.get("expected_current_status_digest"),
        "expected_current_config_digest": document.get("expected_current_config_digest"),
        "candidate_release_digest": document.get("candidate_release_digest"),
        "candidate_config_digest": document.get("candidate_config_digest"),
        "artifact_manifest_digest": document.get("artifact_manifest_digest"),
        "entrypoint_reconciliation_digest": document.get("entrypoint_reconciliation_digest"),
    }
    if any(
        not isinstance(value, str) or not HEX_DIGEST.fullmatch(value) for value in digests.values()
    ):
        raise AdapterError("activation_envelope_digest_invalid")
    if candidate == expected_current:
        raise AdapterError("activation_candidate_unchanged")
    digest = hashlib.sha256(_canonical(document)).hexdigest()
    if "sha256:" + digest != expected_digest:
        raise AdapterError("activation_envelope_digest_mismatch")
    return {
        "transaction_id": transaction_id,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "expected_generation": expected_generation,
        "expected_current": expected_current,
        "candidate": candidate,
        "digest": digest,
        **digests,
    }


def _fingerprint_config_files(files: dict[str, Path]) -> str:
    """Reproduce the activation entrypoint's effective configuration digest."""

    records: dict[str, dict[str, object]] = {}
    for logical_name, path in files.items():
        raw = _private_file(path).read_bytes()
        records[logical_name] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
    return hashlib.sha256(_canonical(records)).hexdigest()


def _read_private_bytes(path: Path) -> tuple[bytes, str]:
    """Read a root-owned state file and return its raw bytes with their digest."""

    target = _private_file(path)
    try:
        raw = target.read_bytes()
    except OSError as exc:
        raise AdapterError("controller_state_unavailable") from exc
    return raw, hashlib.sha256(raw).hexdigest()


def _parse_release_status(raw: bytes) -> dict[str, Any] | None:
    """Parse the durable activation ledger into the exact committed shape."""

    try:
        value = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
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
    if not isinstance(value, dict) or set(value) not in {
        frozenset(legacy_required),
        frozenset(current_required),
    }:
        return None
    is_legacy = set(value) == legacy_required
    expected_schema = LEGACY_ACTIVATION_STATUS_SCHEMA if is_legacy else ACTIVATION_STATUS_SCHEMA
    if value.get("schema") != expected_schema or value.get("state") != "active":
        return None
    generation = value.get("generation")
    if isinstance(generation, bool) or not isinstance(generation, int) or generation < 0:
        return None
    current_value: dict[str, Any] = {
        "source_sha": value.get("source_sha"),
        "policy_bundle_digest": value.get("policy_bundle_digest"),
    }
    if is_legacy:
        current_value["image_digest"] = value.get("image_digest")
    else:
        current_value["public_image_digest"] = value.get("public_image_digest")
        current_value["internal_image_digest"] = value.get("internal_image_digest")
    current = _parse_tuple(current_value)
    if current is None:
        return None
    transaction_id = value.get("transaction_id")
    if not isinstance(transaction_id, str) or not TRANSACTION_ID.fullmatch(transaction_id):
        return None
    activated_at = _parse_time(value.get("activated_at"))
    if activated_at is None:
        return None
    previous: tuple[int, dict[str, str]] | None = None
    previous_raw = value.get("previous")
    if previous_raw is not None:
        if not isinstance(previous_raw, dict):
            return None
        previous_generation = previous_raw.get("generation")
        parsed_previous = _parse_tuple(
            {key: item for key, item in previous_raw.items() if key != "generation"}
        )
        if (
            parsed_previous is None
            or isinstance(previous_generation, bool)
            or not isinstance(previous_generation, int)
            or previous_generation < 0
            or previous_generation >= generation
        ):
            return None
        previous = (previous_generation, parsed_previous)
    return {
        "generation": generation,
        "current": current,
        "previous": previous,
        "transaction_id": transaction_id,
        "activated_at": activated_at,
    }


def _transaction_mapping(
    envelope: dict[str, Any],
    *,
    reserved_status_digest: str,
    committed_status_digest: str | None,
    committed_activated_at: datetime | None,
) -> dict[str, Any]:
    """Rebuild the exact durable transaction the signed envelope must own."""

    if (committed_status_digest is None) != (committed_activated_at is None):
        raise AdapterError("activation_transaction_metadata_incomplete")
    return {
        "schema": ACTIVATION_TRANSACTION_SCHEMA,
        "transaction_id": envelope["transaction_id"],
        "envelope_digest": envelope["digest"],
        "expected_generation": envelope["expected_generation"],
        "expected_current": dict(envelope["expected_current"]),
        "expected_current_status_digest": envelope["expected_current_status_digest"],
        "expected_current_config_digest": envelope["expected_current_config_digest"],
        "candidate": dict(envelope["candidate"]),
        "candidate_release_digest": envelope["candidate_release_digest"],
        "candidate_config_digest": envelope["candidate_config_digest"],
        "artifact_manifest_digest": envelope["artifact_manifest_digest"],
        "entrypoint_reconciliation_digest": envelope["entrypoint_reconciliation_digest"],
        "reserved_status_digest": reserved_status_digest,
        "committed_status_digest": committed_status_digest,
        "committed_activated_at": (
            None if committed_activated_at is None else _format_time(committed_activated_at)
        ),
        "expires_at": _format_time(envelope["expires_at"]),
    }


def _assert_transaction(envelope: dict[str, Any], transaction_path: Path) -> dict[str, Any]:
    """Require the durable transaction body to be exactly this envelope's own."""

    raw_bytes, _digest = _read_private_bytes(transaction_path)
    try:
        raw = json.loads(raw_bytes.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AdapterError("activation_transaction_invalid") from exc
    if not isinstance(raw, dict) or set(raw) != TRANSACTION_FIELDS:
        raise AdapterError("activation_transaction_ownership_failed")
    reserved_status_digest = raw.get("reserved_status_digest")
    if not isinstance(reserved_status_digest, str) or not HEX_DIGEST.fullmatch(
        reserved_status_digest
    ):
        raise AdapterError("activation_transaction_ownership_failed")
    committed_raw = raw.get("committed_status_digest")
    committed_status_digest: str | None = None
    if committed_raw is not None:
        if not isinstance(committed_raw, str) or not HEX_DIGEST.fullmatch(committed_raw):
            raise AdapterError("activation_transaction_ownership_failed")
        committed_status_digest = committed_raw
    committed_activated_at: datetime | None = None
    committed_activated_at_raw = raw.get("committed_activated_at")
    if committed_activated_at_raw is not None:
        committed_activated_at = _parse_time(committed_activated_at_raw)
        if committed_activated_at is None:
            raise AdapterError("activation_transaction_ownership_failed")
    expected = _transaction_mapping(
        envelope,
        reserved_status_digest=reserved_status_digest,
        committed_status_digest=committed_status_digest,
        committed_activated_at=committed_activated_at,
    )
    if raw != expected:
        raise AdapterError("activation_transaction_ownership_failed")
    return expected


@contextmanager
def _activation_lock(status_path: Path) -> Iterator[None]:
    """Take the same cross-process lock the reference activation store uses."""

    lock_path = status_path.with_suffix(f"{status_path.suffix}.lock")
    try:
        descriptor = os.open(
            lock_path,
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
    except OSError as exc:
        raise AdapterError("controller_activation_lock_unavailable") from exc
    try:
        metadata = lock_path.lstat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise AdapterError("controller_activation_lock_unsafe")
        os.fchmod(descriptor, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        yield
    finally:
        with suppress(OSError):
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        os.close(descriptor)


def _durable_unlink(path: Path) -> None:
    """Durably remove an exact regular state file without following links."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise AdapterError("controller_state_unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise AdapterError("controller_state_unsafe")
    try:
        path.unlink()
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except OSError as exc:
        raise AdapterError("controller_state_unremovable") from exc


def _reconcile_activation_state(
    envelope: dict[str, Any],
    *,
    status_path: Path,
    observed_public_image_digest: str,
    observed_internal_image_digest: str,
    observed_config_digest: str,
) -> dict[str, Any]:
    """Finalise one exact expired-but-committed transaction without re-mutating.

    The proof requires the running ledger to already show the signed candidate
    as ``generation + 1``, the measured runtime image and configuration digests
    to match that candidate, and the durable transaction body to reproduce the
    committed status digest.  A stale, foreign or mismatched anchor fails
    closed before a single byte changes; the live rollback anchor is never read
    or written here.
    """

    transaction_path = status_path.with_suffix(f"{status_path.suffix}.transaction")
    observed = (
        observed_public_image_digest,
        observed_internal_image_digest,
        observed_config_digest,
    )
    candidate_observed = (
        envelope["candidate"]["public_image_digest"],
        envelope["candidate"]["internal_image_digest"],
        envelope["candidate_config_digest"],
    )
    with _activation_lock(status_path):
        raw_status, status_digest = _read_private_bytes(status_path)
        status = _parse_release_status(raw_status)
        if status is None:
            raise AdapterError("activation_status_invalid")
        expected_previous = (
            envelope["expected_generation"],
            envelope["expected_current"],
        )
        if (
            status["generation"] != envelope["expected_generation"] + 1
            or status["current"] != envelope["candidate"]
            or status["previous"] != expected_previous
            or status["transaction_id"] != envelope["transaction_id"]
        ):
            raise AdapterError("reconciliation_committed_shape_invalid")
        if observed != candidate_observed:
            raise AdapterError("reconciliation_runtime_mismatch")
        transaction: dict[str, Any] | None = None
        if transaction_path.exists() or transaction_path.is_symlink():
            transaction = _assert_transaction(envelope, transaction_path)
            committed_status_digest = transaction["committed_status_digest"]
            if committed_status_digest is None:
                raise AdapterError("reconciliation_committed_fingerprint_unavailable")
            if status_digest != committed_status_digest:
                raise AdapterError("reconciliation_status_fingerprint_mismatch")
            _durable_unlink(transaction_path)
            outcome = "finalized"
        else:
            committed_status_digest = status_digest
            outcome = "already-finalized"
    current = {"generation": status["generation"], **status["current"]}
    previous = {
        "generation": envelope["expected_generation"],
        **envelope["expected_current"],
    }
    return {
        "schema": RECONCILE_SCHEMA,
        "outcome": outcome,
        "transaction_id": envelope["transaction_id"],
        "envelope_digest": envelope["digest"],
        "expected_generation": envelope["expected_generation"],
        "recovery_state": "committed",
        "reserved_status_digest": (
            None if transaction is None else transaction["reserved_status_digest"]
        ),
        "committed_status_digest": committed_status_digest,
        "observed_status_digest": status_digest,
        "previous": previous,
        "current": current,
        "post": {**current, "transaction_closed": outcome == "finalized"},
        "activated_at": _format_time(status["activated_at"]),
    }


def _atomic_write_json(path: Path, value: dict[str, Any], *, mode: int) -> None:
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        with suppress(FileNotFoundError):
            temporary.unlink()


def _publish_activation_projection(receipt: dict[str, Any]) -> dict[str, Any]:
    """Republish the sanitized public activation aggregate from the ledger."""

    body = {
        "schema": ACTIVATION_PROJECTION_SCHEMA,
        "state": "active",
        "generation": receipt["current"]["generation"],
        "source_revision": receipt["current"]["source_sha"],
        "activated_at": receipt["activated_at"],
    }
    projection = {
        **body,
        "projection_digest": "sha256:" + hashlib.sha256(_canonical(body)).hexdigest(),
    }
    _atomic_write_json(ACTIVATION_PROJECTION_PATH, projection, mode=0o644)
    return projection


def _reconciliation_result(receipt: dict[str, Any]) -> dict[str, str | int | bool | None]:
    """Flatten the reconciliation receipt into the dispatcher's scalar contract.

    The durable bootstrap operation store accepts only scalars and rejects any
    key containing an authentication-shaped substring, so the pre/post tuples
    are projected field-by-field instead of nested.
    """

    previous = receipt["previous"]
    current = receipt["current"]
    return {
        "schema": receipt["schema"],
        "outcome": receipt["outcome"],
        "transaction_id": receipt["transaction_id"],
        "envelope_digest": receipt["envelope_digest"],
        "expected_generation": receipt["expected_generation"],
        "recovery_state": receipt["recovery_state"],
        "reserved_status_digest": receipt["reserved_status_digest"],
        "committed_status_digest": receipt["committed_status_digest"],
        "observed_status_digest": receipt["observed_status_digest"],
        "activated_at": receipt["activated_at"],
        "transaction_closed": receipt["post"]["transaction_closed"],
        "previous_generation": previous["generation"],
        "previous_source_sha": previous["source_sha"],
        "previous_public_image_digest": previous["public_image_digest"],
        "previous_internal_image_digest": previous["internal_image_digest"],
        "previous_policy_bundle_digest": previous["policy_bundle_digest"],
        "current_generation": current["generation"],
        "current_source_sha": current["source_sha"],
        "current_public_image_digest": current["public_image_digest"],
        "current_internal_image_digest": current["internal_image_digest"],
        "current_policy_bundle_digest": current["policy_bundle_digest"],
        "projection_digest": receipt["projection_digest"],
    }


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
        "action": request["action"],
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


def _failure_permitted_action(failure_code: str) -> str:
    if failure_code in _RECONCILE_CODES:
        return PERMITTED_ACTION_RECONCILE
    if failure_code == "activation_adapter_internal_error":
        return PERMITTED_ACTION_REVIEW
    return PERMITTED_ACTION_RETRY


def activation_failure_receipt(error: BaseException) -> dict[str, Any]:
    """Build one structured, non-secret failure receipt for the root dispatcher.

    Only closed-vocabulary scalars leave the adapter: the opaque free-text
    rejection is replaced by a stable ``failure_code``, a digest over safe
    diagnostic metadata (never the raw stderr body), the immutable transaction
    id when it is known, and the single action the operator is allowed to take.
    """

    code = str(error)
    if not FAILURE_CODE.fullmatch(code):
        code = "activation_adapter_internal_error"
    context = _FAILURE_CONTEXT
    diagnostic = {
        "failure_code": code,
        "stage": str(context.get("stage", "unknown")),
        "transaction_id": str(context.get("transaction_id", "unavailable")),
        "controller_revision": str(context.get("controller_revision", "unavailable")),
        "activation_envelope_digest": str(context.get("activation_envelope_digest", "unavailable")),
        "entrypoint_returncode": int(context.get("entrypoint_returncode", -1)),
        "entrypoint_stderr_digest": str(context.get("entrypoint_stderr_digest", "unavailable")),
    }
    canonical = json.dumps(diagnostic, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return {
        "schema": FAILURE_SCHEMA,
        "failure_code": code,
        "diagnostic_digest": "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest(),
        "transaction_id": diagnostic["transaction_id"],
        "permitted_action": _failure_permitted_action(code),
    }


def main() -> int:
    if os.geteuid() != 0:
        raise AdapterError("root_identity_required")
    envelope = _read_json_stdin()
    request, target = _validate_request(envelope)
    _FAILURE_CONTEXT.clear()
    _FAILURE_CONTEXT.update(
        {
            "stage": "request",
            "controller_revision": request["controller_revision"],
            "activation_envelope_digest": request["activation_envelope_digest"],
        }
    )
    action = str(request["action"])
    # Activating executes the candidate checkout; reconciling only closes a
    # transaction the measured runtime already committed to, so it must never
    # depend on executing or even requiring staged candidate code.
    candidate = (
        _candidate(str(request["controller_revision"])) if action == ACTIVATE_ACTION else None
    )
    (
        activation_envelope,
        artifact_manifest,
        public_key,
        candidate_policy_digest,
        transaction_id,
    ) = _activation_assets(request)
    _FAILURE_CONTEXT["stage"] = "assets"
    _FAILURE_CONTEXT["transaction_id"] = transaction_id
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
    if action == RECONCILE_ACTION:
        recipient = _read_envelope_document(
            activation_envelope,
            expected_digest=str(request["activation_envelope_digest"]),
        )
        signed = _verify_activation_envelope(
            recipient,
            public_key=public_key,
            expected_digest=str(request["activation_envelope_digest"]),
        )
        _FAILURE_CONTEXT["stage"] = "reconcile"
        if (
            current_revision != signed["candidate"]["source_sha"]
            or "sha256:" + signed["candidate"]["public_image_digest"] != current_image
            or "sha256:" + signed["candidate"]["internal_image_digest"] != current_internal_image
        ):
            raise AdapterError("reconciliation_runtime_mismatch")
        observed_config = _fingerprint_config_files(CONTROLLER_CONFIG_FILES)
        receipt = _reconcile_activation_state(
            signed,
            status_path=ACTIVATION_STATUS_PATH,
            observed_public_image_digest=current_image[7:],
            observed_internal_image_digest=current_internal_image[7:],
            observed_config_digest=observed_config,
        )
        projection = _publish_activation_projection(receipt)
        receipt["projection_digest"] = projection["projection_digest"]
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
            status=(
                "already_completed" if receipt["outcome"] == "already-finalized" else "completed"
            ),
            result=_reconciliation_result(receipt),
        )
        print(json.dumps(response, sort_keys=True, separators=(",", ":")))
        return 0
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
    _FAILURE_CONTEXT["stage"] = "entrypoint"
    try:
        completed = subprocess.run(
            [str(activation), str(candidate)],
            check=False,
            capture_output=True,
            text=True,
            errors="replace",
            env=environment,
            timeout=1800,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AdapterError("activation_outcome_unknown") from exc
    _FAILURE_CONTEXT["entrypoint_returncode"] = completed.returncode
    if completed.stderr:
        _FAILURE_CONTEXT["entrypoint_stderr_digest"] = (
            "sha256:" + hashlib.sha256(completed.stderr.encode("utf-8")).hexdigest()
        )
    if completed.returncode != 0:
        failure_code = _payload_failure_code(completed.stderr)
        if failure_code is not None:
            _FAILURE_CONTEXT["stage"] = "payload"
            raise AdapterError(failure_code)
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
        # The structured receipt on stdout replaces the former opaque code while
        # the short stderr line carries no payload diagnostics.
        print(
            json.dumps(
                activation_failure_receipt(error),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
    except Exception as error:  # noqa: BLE001
        # A root adapter must fail closed with a parseable receipt instead of
        # ever letting a traceback or raw diagnostic escape to the dispatcher.
        receipt = activation_failure_receipt(error)
        print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
        print(receipt["failure_code"], file=sys.stderr)
        raise SystemExit(1) from error
