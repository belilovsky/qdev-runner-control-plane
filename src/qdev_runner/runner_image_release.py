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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

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
EVIDENCE_PREFIXES = {
    "QDEV_RUNNER_IMAGE": "general",
    "QDEV_RUNNER_BROWSER_IMAGE": "browser",
    "QDEV_RUNNER_DOCKER_IMAGE": "docker",
    "QDEV_DOCKER_SIDECAR_IMAGE": "sidecar",
}


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


def _sha256(path: Path) -> str:
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise RunnerImageReleaseError(f"evidence file is unavailable: {path.name}") from error
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _load_json(path: Path, field: str) -> tuple[dict[str, Any], bytes]:
    try:
        raw = path.read_bytes()
        value = json.loads(raw)
    except (OSError, json.JSONDecodeError) as error:
        raise RunnerImageReleaseError(f"{field} is unavailable or invalid") from error
    return _require_mapping(value, field), raw


def verify_evidence(value: object, *, manifest_path: Path | None = None) -> None:
    """Cryptographically verify the protected evidence behind a release envelope.

    Older v1 manifests without the additive evidence file map remain structurally
    readable during migration.  A strict verification request always fails closed
    unless every artifact provides the new map and the signing public key is bound
    by the top-level digest.
    """

    manifest = _require_mapping(value, "manifest")
    validate(manifest)
    evidence_root_value = manifest.get("evidence_root")
    if not isinstance(evidence_root_value, str) or not evidence_root_value:
        raise RunnerImageReleaseError("evidence_root is required for strict verification")
    evidence_root = Path(evidence_root_value)
    if not evidence_root.is_absolute():
        if manifest_path is None:
            raise RunnerImageReleaseError("relative evidence_root requires manifest_path")
        evidence_root = manifest_path.resolve().parent / evidence_root

    signing = _require_mapping(manifest.get("signing"), "signing")
    if signing.get("algorithm") != "Ed25519":
        raise RunnerImageReleaseError("signing.algorithm must be Ed25519")
    public_key_name = signing.get("public_key_file")
    if not isinstance(public_key_name, str) or Path(public_key_name).name != public_key_name:
        raise RunnerImageReleaseError("signing.public_key_file must be a local filename")
    public_key_path = evidence_root / public_key_name
    try:
        public_key_raw = public_key_path.read_bytes()
        loaded_key = serialization.load_pem_public_key(public_key_raw)
    except (OSError, ValueError) as error:
        raise RunnerImageReleaseError("signing public key is unavailable or invalid") from error
    if not isinstance(loaded_key, Ed25519PublicKey):
        raise RunnerImageReleaseError("signing public key is not Ed25519")
    expected_key_digest = _require_digest(
        signing.get("public_key_sha256"), "signing.public_key_sha256"
    )
    if "sha256:" + hashlib.sha256(public_key_raw).hexdigest() != expected_key_digest:
        raise RunnerImageReleaseError("signing public key digest mismatch")

    artifacts = manifest.get("artifacts")
    assert isinstance(artifacts, list)
    for index, raw_artifact in enumerate(artifacts):
        artifact = _require_mapping(raw_artifact, f"artifacts[{index}]")
        key = artifact.get("environment_key")
        assert isinstance(key, str)
        files = _require_mapping(
            artifact.get("evidence_files"), f"artifacts[{index}].evidence_files"
        )
        names: dict[str, str] = {}
        for name in ("sbom", "provenance", "signature", "security", "license"):
            filename = files.get(name)
            if not isinstance(filename, str) or Path(filename).name != filename:
                raise RunnerImageReleaseError(
                    f"artifacts[{index}].evidence_files.{name} must be a local filename"
                )
            names[name] = filename

        sbom_path = evidence_root / names["sbom"]
        provenance_path = evidence_root / names["provenance"]
        signature_path = evidence_root / names["signature"]
        security_path = evidence_root / names["security"]
        license_path = evidence_root / names["license"]
        if _sha256(sbom_path) != artifact.get("sbom_digest"):
            raise RunnerImageReleaseError(f"{key} SBOM digest mismatch")
        if _sha256(provenance_path) != artifact.get("provenance_digest"):
            raise RunnerImageReleaseError(f"{key} provenance digest mismatch")
        signature = _require_mapping(artifact.get("signature"), f"artifacts[{index}].signature")
        if signature.get("issuer") != signing.get("issuer") or signature.get(
            "identity"
        ) != signing.get("identity"):
            raise RunnerImageReleaseError(f"{key} signature identity mismatch")
        if _sha256(signature_path) != signature.get("evidence_digest"):
            raise RunnerImageReleaseError(f"{key} signature digest mismatch")
        review = _require_mapping(
            artifact.get("vulnerability_review"), f"artifacts[{index}].vulnerability_review"
        )
        if _sha256(security_path) != review.get("report_digest"):
            raise RunnerImageReleaseError(f"{key} security report digest mismatch")

        provenance, provenance_raw = _load_json(provenance_path, f"{key} provenance")
        subject = _require_mapping(provenance.get("subject"), f"{key} provenance.subject")
        if (
            subject.get("reference") != artifact.get("reference")
            or subject.get("environment_key") != key
        ):
            raise RunnerImageReleaseError(f"{key} provenance subject mismatch")
        if subject.get("digest") != signature.get("subject_digest"):
            raise RunnerImageReleaseError(f"{key} provenance digest binding mismatch")
        scans = _require_mapping(provenance.get("scans"), f"{key} provenance.scans")
        provenance_signing = _require_mapping(
            provenance.get("signing"), f"{key} provenance.signing"
        )
        expected_signing = dict(signing)
        expected_signing.pop("public_key_file", None)
        if provenance_signing != expected_signing:
            raise RunnerImageReleaseError(f"{key} provenance signing identity mismatch")
        provenance_source = _require_mapping(
            provenance.get("source_binding"), f"{key} provenance.source_binding"
        )
        if provenance_source.get("revision") != manifest.get("release_revision"):
            raise RunnerImageReleaseError(f"{key} provenance source revision mismatch")
        if scans.get("sbom") != artifact.get("sbom_digest"):
            raise RunnerImageReleaseError(f"{key} provenance SBOM binding mismatch")
        if scans.get("security") != review.get("report_digest"):
            raise RunnerImageReleaseError(f"{key} provenance security binding mismatch")
        if scans.get("license") != _sha256(license_path):
            raise RunnerImageReleaseError(f"{key} provenance license binding mismatch")
        try:
            loaded_key.verify(signature_path.read_bytes(), provenance_raw)
        except (OSError, InvalidSignature) as error:
            raise RunnerImageReleaseError(f"{key} provenance signature is invalid") from error


def load(
    path: Path,
    *,
    expected_revision: str | None = None,
    strict_evidence: bool = False,
) -> tuple[dict[str, str], str]:
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
    references = validate(value, expected_revision=expected_revision)
    if strict_evidence:
        verify_evidence(value, manifest_path=path)
    return references, manifest_digest
