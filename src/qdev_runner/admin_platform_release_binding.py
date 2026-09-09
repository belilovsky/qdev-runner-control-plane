"""Controller-signed immutable bindings for Admin Platform package releases.

CI can prove that a package was built, but it is not the authority that makes
an artifact admissible to a product's ``shared`` admin surface.  The controller
signs this compact, exact binding only after the immutable upload receipt is
known.  Product images verify it against the separately provisioned controller
public key; the wheel, evidence JSON, and binding therefore cannot attest to
each other merely by being replaced together.
"""

from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature

from .controller_admission import (
    _load_private_key,
    _load_public_key,
    canonical_payload,
    payload_digest,
    public_key_id,
)

SCHEMA_VERSION = "qdev-admin-release-binding-v2"
ALGORITHM = "Ed25519"

_SHA = re.compile(r"^[0-9a-f]{40}$")
_CHECKSUM = re.compile(r"^[0-9a-f]{64}$")
_SUBJECT = re.compile(r"^[a-z][a-z0-9-]{1,127}$")
_PACKAGE = re.compile(r"^@?[A-Za-z0-9][A-Za-z0-9._/@-]{0,127}$")
_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9.+_-]{0,127}$")
_WORKFLOW_NAME = re.compile(r"^[\w][\w .:/\-\u2013]{0,191}$")
_DECIMAL = re.compile(r"^[1-9][0-9]{0,19}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")

_TOP_LEVEL_FIELDS = frozenset({"schema_version", "payload", "signature"})
_PAYLOAD_FIELDS = frozenset(
    {
        "subject",
        "package",
        "version",
        "source_sha",
        "artifact_checksum",
        "artifact_uri",
        "workflow",
    }
)
_OPTIONAL_PAYLOAD_FIELDS = frozenset({"asset_manifest"})
_WORKFLOW_FIELDS = frozenset({"name", "run_id", "job_id", "attempt", "head_sha"})
_SIGNATURE_FIELDS = frozenset({"algorithm", "key_id", "payload_sha256", "value"})


class AdminPlatformReleaseBindingError(ValueError):
    """Raised when a package binding is incomplete, forged, or untrusted."""


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdminPlatformReleaseBindingError(f"{label} must be an object")
    return value


def _exact_fields(value: Mapping[str, object], fields: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        parts: list[str] = []
        if missing:
            parts.append("missing " + ", ".join(missing))
        if extra:
            parts.append("unexpected " + ", ".join(extra))
        raise AdminPlatformReleaseBindingError(f"{label} has invalid fields: {'; '.join(parts)}")


def _matched(value: object, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise AdminPlatformReleaseBindingError(f"{label} is invalid")
    return value


def _immutable_uri(value: object, label: str) -> str:
    uri = _matched(value, re.compile(r"^https://[^\s/][^\s]*$"), label)
    if uri.endswith("/") or "latest" in uri.lower():
        raise AdminPlatformReleaseBindingError(f"{label} must be immutable")
    return uri


def _asset_manifest(value: object) -> dict[str, str]:
    manifest = _mapping(value, "payload.asset_manifest")
    if not manifest:
        raise AdminPlatformReleaseBindingError("payload.asset_manifest cannot be empty")
    normalised: dict[str, str] = {}
    for path, checksum in manifest.items():
        if not isinstance(path, str) or not path or path.startswith("/") or ".." in path.split("/"):
            raise AdminPlatformReleaseBindingError("payload.asset_manifest path is invalid")
        normalised[path] = _matched(checksum, _CHECKSUM, "payload.asset_manifest checksum")
    return normalised


def validate_payload(value: object) -> dict[str, Any]:
    """Validate the complete immutable tuple before it is signed or trusted."""

    payload = _mapping(value, "payload")
    fields = frozenset(payload)
    if not _PAYLOAD_FIELDS.issubset(fields) or not fields.issubset(
        _PAYLOAD_FIELDS | _OPTIONAL_PAYLOAD_FIELDS
    ):
        expected = _PAYLOAD_FIELDS | (
            _OPTIONAL_PAYLOAD_FIELDS if "asset_manifest" in fields else frozenset()
        )
        _exact_fields(payload, expected, "payload")
    _matched(payload["subject"], _SUBJECT, "payload.subject")
    _matched(payload["package"], _PACKAGE, "payload.package")
    _matched(payload["version"], _VERSION, "payload.version")
    _matched(payload["source_sha"], _SHA, "payload.source_sha")
    _matched(payload["artifact_checksum"], _CHECKSUM, "payload.artifact_checksum")
    _immutable_uri(payload["artifact_uri"], "payload.artifact_uri")
    workflow = _mapping(payload["workflow"], "payload.workflow")
    _exact_fields(workflow, _WORKFLOW_FIELDS, "payload.workflow")
    _matched(workflow["name"], _WORKFLOW_NAME, "payload.workflow.name")
    for field in ("run_id", "job_id", "attempt"):
        _matched(workflow[field], _DECIMAL, f"payload.workflow.{field}")
    if _matched(workflow["head_sha"], _SHA, "payload.workflow.head_sha") != payload["source_sha"]:
        raise AdminPlatformReleaseBindingError("payload.workflow.head_sha differs from source_sha")
    if "asset_manifest" in payload:
        _asset_manifest(payload["asset_manifest"])
    return payload


def sign_release_binding(payload: object, private_key_path: Path) -> dict[str, Any]:
    """Sign a release tuple with the controller's protected Ed25519 authority."""

    validated = validate_payload(payload)
    key = _load_private_key(private_key_path)
    raw = canonical_payload(validated)
    signature = base64.urlsafe_b64encode(key.sign(raw)).rstrip(b"=").decode("ascii")
    return {
        "schema_version": SCHEMA_VERSION,
        "payload": validated,
        "signature": {
            "algorithm": ALGORITHM,
            "key_id": public_key_id(key.public_key()),
            "payload_sha256": payload_digest(validated),
            "value": signature,
        },
    }


def verify_release_binding(binding: object, public_key_path: Path) -> dict[str, Any]:
    """Verify a binding against the controller's pinned public authority."""

    envelope = _mapping(binding, "release binding")
    _exact_fields(envelope, _TOP_LEVEL_FIELDS, "release binding")
    if envelope["schema_version"] != SCHEMA_VERSION:
        raise AdminPlatformReleaseBindingError("release binding schema is unsupported")
    payload = validate_payload(envelope["payload"])
    signature = _mapping(envelope["signature"], "release binding signature")
    _exact_fields(signature, _SIGNATURE_FIELDS, "release binding signature")
    if signature["algorithm"] != ALGORITHM:
        raise AdminPlatformReleaseBindingError("release binding must use Ed25519")
    _matched(signature["key_id"], _KEY_ID, "release binding signature key_id")
    _matched(signature["payload_sha256"], _KEY_ID, "release binding signature payload_sha256")
    encoded = _matched(signature["value"], _SIGNATURE, "release binding signature value")
    public_key = _load_public_key(public_key_path)
    if signature["key_id"] != public_key_id(public_key):
        raise AdminPlatformReleaseBindingError("release binding is signed by an unknown authority")
    raw = canonical_payload(payload)
    if signature["payload_sha256"] != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise AdminPlatformReleaseBindingError("release binding payload digest does not match")
    try:
        public_key.verify(base64.urlsafe_b64decode(encoded + "=="), raw)
    except (InvalidSignature, ValueError) as error:
        raise AdminPlatformReleaseBindingError(
            "release binding signature verification failed"
        ) from error
    return payload


__all__ = [
    "ALGORITHM",
    "SCHEMA_VERSION",
    "AdminPlatformReleaseBindingError",
    "sign_release_binding",
    "validate_payload",
    "verify_release_binding",
]
