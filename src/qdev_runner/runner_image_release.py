"""Validate the digest-only runner image release envelope.

The controller never treats a registry tag as an executable identity.  This
module deliberately validates only the compact, non-secret evidence envelope:
the OCI reference and the digests of its SBOM, provenance, signature evidence
and vulnerability review.  Artifact contents and credentials stay in their
respective protected stores.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_URL = re.compile(r"^https://[^\s]+$")

SCHEMA = "qdev-runner-image-release-v1"
REQUIRED_IMAGES = frozenset(
    {
        "QDEV_RUNNER_IMAGE",
        "QDEV_RUNNER_BROWSER_IMAGE",
        "QDEV_RUNNER_DOCKER_IMAGE",
        "QDEV_DOCKER_SIDECAR_IMAGE",
    }
)


class RunnerImageReleaseError(ValueError):
    """Raised when an image release cannot identify verified immutable inputs."""


def _require_mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise RunnerImageReleaseError(f"{field} must be an object")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not _DIGEST.fullmatch(value):
        raise RunnerImageReleaseError(f"{field} must be a sha256 digest")
    return value


def _require_url(value: object, field: str) -> str:
    if not isinstance(value, str) or not _URL.fullmatch(value):
        raise RunnerImageReleaseError(f"{field} must be an https URL")
    return value


def _reference_digest(reference: str) -> str:
    return "sha256:" + reference.rsplit("@sha256:", maxsplit=1)[1]


def validate(value: object, *, expected_revision: str | None = None) -> dict[str, str]:
    """Return immutable references keyed by worker environment variable.

    Validation is intentionally strict: each enabled executor image (including
    the Docker sidecar) needs evidence tied to its exact content digest.  High
    findings are permitted only with an immutable remediation receipt; Critical
    findings can never be admitted.
    """

    manifest = _require_mapping(value, "manifest")
    if manifest.get("schema") != SCHEMA:
        raise RunnerImageReleaseError("schema is not qdev-runner-image-release-v1")
    revision = manifest.get("release_revision")
    if not isinstance(revision, str) or not _REVISION.fullmatch(revision):
        raise RunnerImageReleaseError("release_revision must be an exact git revision")
    if expected_revision is not None and revision != expected_revision:
        raise RunnerImageReleaseError("release_revision does not match the expected revision")

    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, list):
        raise RunnerImageReleaseError("artifacts must be a list")

    references: dict[str, str] = {}
    for index, raw_artifact in enumerate(artifacts):
        artifact = _require_mapping(raw_artifact, f"artifacts[{index}]")
        key = artifact.get("environment_key")
        if not isinstance(key, str) or key not in REQUIRED_IMAGES:
            raise RunnerImageReleaseError(f"artifacts[{index}].environment_key is not recognized")
        if key in references:
            raise RunnerImageReleaseError(f"duplicate artifact for {key}")

        reference = artifact.get("reference")
        if not isinstance(reference, str) or not _REFERENCE.fullmatch(reference):
            raise RunnerImageReleaseError(f"artifacts[{index}].reference must be immutable")
        image_digest = _reference_digest(reference)

        _require_digest(artifact.get("sbom_digest"), f"artifacts[{index}].sbom_digest")
        _require_digest(artifact.get("provenance_digest"), f"artifacts[{index}].provenance_digest")

        signature = _require_mapping(artifact.get("signature"), f"artifacts[{index}].signature")
        subject_digest = _require_digest(
            signature.get("subject_digest"), f"artifacts[{index}].signature.subject_digest"
        )
        if subject_digest != image_digest:
            raise RunnerImageReleaseError(f"artifacts[{index}].signature is not bound to reference")
        _require_digest(
            signature.get("evidence_digest"), f"artifacts[{index}].signature.evidence_digest"
        )
        _require_url(signature.get("issuer"), f"artifacts[{index}].signature.issuer")
        _require_url(signature.get("identity"), f"artifacts[{index}].signature.identity")

        vulnerability = _require_mapping(
            artifact.get("vulnerability_review"), f"artifacts[{index}].vulnerability_review"
        )
        _require_digest(
            vulnerability.get("report_digest"),
            f"artifacts[{index}].vulnerability_review.report_digest",
        )
        scanner = vulnerability.get("scanner")
        if not isinstance(scanner, str) or not scanner.strip():
            raise RunnerImageReleaseError(
                f"artifacts[{index}].vulnerability_review.scanner is required"
            )
        critical = vulnerability.get("critical")
        high = vulnerability.get("high")
        if not isinstance(critical, int) or isinstance(critical, bool) or critical != 0:
            raise RunnerImageReleaseError(f"artifacts[{index}] has Critical vulnerabilities")
        if not isinstance(high, int) or isinstance(high, bool) or high < 0:
            raise RunnerImageReleaseError(
                f"artifacts[{index}].vulnerability_review.high must be non-negative"
            )
        if high > 0 or "remediation_digest" in vulnerability:
            _require_digest(
                vulnerability.get("remediation_digest"),
                f"artifacts[{index}].vulnerability_review.remediation_digest",
            )
        references[key] = reference

    missing = sorted(REQUIRED_IMAGES - references.keys())
    if missing:
        raise RunnerImageReleaseError("missing required artifacts: " + ", ".join(missing))
    extra = sorted(references.keys() - REQUIRED_IMAGES)
    if extra:
        raise RunnerImageReleaseError("unexpected artifacts: " + ", ".join(extra))
    return references


def load(path: Path, *, expected_revision: str | None = None) -> tuple[dict[str, str], str]:
    """Load a release manifest and return its references and file digest."""

    try:
        raw = path.read_bytes()
    except OSError as error:
        raise RunnerImageReleaseError("runner image release manifest is unavailable") from error
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as error:
        raise RunnerImageReleaseError("runner image release manifest is not JSON") from error
    manifest_digest = "sha256:" + hashlib.sha256(raw).hexdigest()
    return validate(value, expected_revision=expected_revision), manifest_digest
