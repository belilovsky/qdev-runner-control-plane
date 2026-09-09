"""Root-only issuance of controller-signed Admin Platform package bindings.

The controller broker intentionally has no admission private key.  Package
publication therefore uses this small, fixed host-side step after the broker
has recorded the immutable upload receipt.  It never accepts a repository,
workflow, key path, or output path from the caller: those values are matched
against the root-owned policy and all mutable files live below one protected
spool directory.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any

from .admin_platform_release_binding import (
    AdminPlatformReleaseBindingError,
    sign_release_binding,
    validate_payload,
)
from .controller_admission import ControllerAdmissionError, canonical_payload

POLICY_SCHEMA = "qdev-admin-platform-package-binding-policy-v1"
REQUEST_SCHEMA = "qdev-admin-platform-package-binding-request-v1"
ISSUED_SCHEMA = "qdev-admin-platform-package-binding-issued-v1"

DEFAULT_POLICY_PATH = Path("/etc/qdev-runner/admin-platform-package-bindings.json")
DEFAULT_PRIVATE_KEY_PATH = Path("/etc/qdev-runner/admission/ed25519-private.pem")
DEFAULT_REQUEST_ROOT = Path("/run/qdev-controller/admin-platform-package-bindings")

_REQUEST_ID = re.compile(r"^[a-z0-9][a-z0-9-]{7,95}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_URI_PREFIX = re.compile(r"^https://[^\s/][^\s]*/$")
_HEX = re.compile(r"^[0-9a-f]{64}$")


class AdminPlatformPackageIssuerError(RuntimeError):
    """A package-binding request cannot be issued safely."""


def _trusted_file(path: Path, label: str, *, owner_only: bool) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AdminPlatformPackageIssuerError(f"{label} is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        mode = stat.S_IMODE(metadata.st_mode)
        # The installed command runs only through the root-owned host wrapper.
        # Accepting the current owner here keeps library tests deterministic.
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.geteuid():
            raise AdminPlatformPackageIssuerError(f"{label} has an unexpected owner")
        if owner_only:
            if mode != 0o600:
                raise AdminPlatformPackageIssuerError(f"{label} must have mode 0600")
        elif mode & 0o022:
            raise AdminPlatformPackageIssuerError(f"{label} must not be writable by group or world")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    except OSError as error:
        raise AdminPlatformPackageIssuerError(f"{label} is unreadable") from error
    finally:
        os.close(descriptor)


def _trusted_directory(path: Path, label: str) -> None:
    try:
        metadata = path.stat()
    except OSError as error:
        raise AdminPlatformPackageIssuerError(f"{label} is unavailable") from error
    if (
        path.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise AdminPlatformPackageIssuerError(f"{label} is unsafe")


def _json_document(raw: bytes, label: str) -> dict[str, Any]:
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AdminPlatformPackageIssuerError(f"{label} is invalid JSON") from error
    if not isinstance(document, dict):
        raise AdminPlatformPackageIssuerError(f"{label} must be an object")
    return document


def _policy(path: Path) -> dict[str, dict[str, str]]:
    document = _json_document(
        _trusted_file(path, "package binding policy", owner_only=False), "policy"
    )
    if (
        set(document) != {"schema_version", "subjects"}
        or document["schema_version"] != POLICY_SCHEMA
    ):
        raise AdminPlatformPackageIssuerError("package binding policy shape is invalid")
    subjects = document["subjects"]
    if not isinstance(subjects, dict) or not subjects:
        raise AdminPlatformPackageIssuerError("package binding policy subjects are invalid")
    normalised: dict[str, dict[str, str]] = {}
    for subject, entry in subjects.items():
        if (
            not isinstance(subject, str)
            or not isinstance(entry, dict)
            or set(entry)
            != {
                "package",
                "repository",
                "workflow",
                "artifact_uri_prefix",
            }
        ):
            raise AdminPlatformPackageIssuerError("package binding policy entry is invalid")
        package = entry["package"]
        repository = entry["repository"]
        workflow = entry["workflow"]
        prefix = entry["artifact_uri_prefix"]
        if (
            not isinstance(package, str)
            or not package
            or not isinstance(repository, str)
            or not _REPOSITORY.fullmatch(repository)
            or not isinstance(workflow, str)
            or not workflow
            or not isinstance(prefix, str)
            or not _URI_PREFIX.fullmatch(prefix)
        ):
            raise AdminPlatformPackageIssuerError("package binding policy values are invalid")
        normalised[subject] = {
            "package": package,
            "repository": repository,
            "workflow": workflow,
            "artifact_uri_prefix": prefix,
        }
    return normalised


def _request(path: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    document = _json_document(
        _trusted_file(path, "package binding request", owner_only=False), "request"
    )
    if set(document) != {
        "schema_version",
        "request_id",
        "repository",
        "ci_receipt_sha256",
        "payload",
    }:
        raise AdminPlatformPackageIssuerError("package binding request shape is invalid")
    if document["schema_version"] != REQUEST_SCHEMA:
        raise AdminPlatformPackageIssuerError("package binding request schema is invalid")
    request_id = document["request_id"]
    repository = document["repository"]
    receipt_sha = document["ci_receipt_sha256"]
    if (
        not isinstance(request_id, str)
        or not _REQUEST_ID.fullmatch(request_id)
        or not isinstance(repository, str)
        or not _REPOSITORY.fullmatch(repository)
        or not isinstance(receipt_sha, str)
        or not _HEX.fullmatch(receipt_sha)
    ):
        raise AdminPlatformPackageIssuerError("package binding request identity is invalid")
    try:
        payload = validate_payload(document["payload"])
    except AdminPlatformReleaseBindingError as error:
        raise AdminPlatformPackageIssuerError(str(error)) from error
    return document, payload


def _atomic_write(path: Path, value: object) -> None:
    encoded = canonical_payload(value) + b"\n"
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def issue_binding(
    request_id: str,
    *,
    policy_path: Path = DEFAULT_POLICY_PATH,
    private_key_path: Path = DEFAULT_PRIVATE_KEY_PATH,
    request_root: Path = DEFAULT_REQUEST_ROOT,
) -> dict[str, Any]:
    """Issue exactly one policy-bound package binding, idempotently.

    A request is pre-recorded by the controller after it observes CI and the
    immutable artifact.  This host-side issuer checks the static policy again,
    signs only that tuple, and writes an immutable result for the broker to
    reconcile.  A same request ID may be retried only when its signed result
    has the identical request digest.
    """

    if not _REQUEST_ID.fullmatch(request_id):
        raise AdminPlatformPackageIssuerError("package binding request ID is invalid")
    _trusted_directory(request_root, "package binding root")
    incoming = request_root / "incoming"
    issued = request_root / "issued"
    _trusted_directory(incoming, "package binding incoming directory")
    _trusted_directory(issued, "package binding issued directory")
    request_path = incoming / f"{request_id}.json"
    issued_path = issued / f"{request_id}.json"
    request, payload = _request(request_path)
    if request["request_id"] != request_id:
        raise AdminPlatformPackageIssuerError("package binding request ID does not match filename")
    request_digest = "sha256:" + hashlib.sha256(canonical_payload(request)).hexdigest()
    if issued_path.exists():
        result = _json_document(
            _trusted_file(issued_path, "issued package binding", owner_only=True),
            "issued binding",
        )
        if (
            set(result) != {"schema_version", "request_id", "request_sha256", "binding"}
            or result.get("schema_version") != ISSUED_SCHEMA
            or result.get("request_id") != request_id
            or result.get("request_sha256") != request_digest
        ):
            raise AdminPlatformPackageIssuerError("issued package binding conflicts with request")
        return result
    policy_entry = _policy(policy_path).get(payload["subject"])
    if policy_entry is None:
        raise AdminPlatformPackageIssuerError("package subject is not allowlisted")
    if (
        request["repository"] != policy_entry["repository"]
        or payload["package"] != policy_entry["package"]
        or payload["workflow"]["name"] != policy_entry["workflow"]
        or not payload["artifact_uri"].startswith(policy_entry["artifact_uri_prefix"])
    ):
        raise AdminPlatformPackageIssuerError("package binding request does not match policy")
    try:
        binding = sign_release_binding(payload, private_key_path)
    except ControllerAdmissionError as error:
        raise AdminPlatformPackageIssuerError(str(error)) from error
    result = {
        "schema_version": ISSUED_SCHEMA,
        "request_id": request_id,
        "request_sha256": request_digest,
        "binding": binding,
    }
    _atomic_write(issued_path, result)
    return result


__all__ = [
    "AdminPlatformPackageIssuerError",
    "DEFAULT_POLICY_PATH",
    "DEFAULT_PRIVATE_KEY_PATH",
    "DEFAULT_REQUEST_ROOT",
    "ISSUED_SCHEMA",
    "POLICY_SCHEMA",
    "REQUEST_SCHEMA",
    "issue_binding",
]
