"""Build and reconcile one owner-authorized controller recovery artifact.

The recovery lane is deliberately split in two.  A non-production build host
creates and scans the image, then this module reconciles the exact successful
GitHub job before producing provenance.  An offline operator may subsequently
sign an activation envelope that is bound to the reconciled bytes.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tarfile
import urllib.error
import urllib.request
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path, PurePosixPath
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .controller_activation import (
    ARTIFACT_MANIFEST_SCHEMA,
    ARTIFACT_PROVENANCE_SCHEMA,
    CONTROLLER_REPOSITORY,
    ENVELOPE_SCHEMA,
    MAX_ENVELOPE_TTL,
    ActivationEnvelope,
    ControllerActivationError,
    ControllerReleaseStatus,
    ControllerTuple,
    MeasuredControllerReleaseStatus,
    fingerprint_config_files,
    fingerprint_release_tree,
    verify_controller_artifact_manifest,
)
from .controller_release import ControllerReleaseIdentityError, controller_release_digest
from .operator import verify_controller_receipt

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_WORKFLOW = ".github/workflows/runner-smoke.yml"
_CONFIG_FILES = {
    "repos.json": Path("inventory/repos.json"),
    "profiles.yml": Path("config/profiles.yml"),
    "release-lanes.yml": Path("config/release-lanes.yml"),
    "managed-registry.yml": Path("config/managed-registry.yml"),
    "fleet-bootstrap.yml": Path("config/fleet-bootstrap.yml"),
    "managed-release-ledger.yml": Path("config/managed-release-ledger.yml"),
}
_MAX_JSON_MEMBER = 4 * 1024 * 1024


class ControllerRecoveryArtifactError(ValueError):
    """Raised when recovery artifact production cannot prove exact identity."""


def _canonical_tar_member_name(name: object, *, label: str, directory: bool = False) -> str:
    """Return one canonical relative POSIX archive member name."""

    if not isinstance(name, str) or not name or "\x00" in name or "\\" in name:
        raise ControllerRecoveryArtifactError(f"{label} is unsafe")
    candidate = name[:-1] if directory and name.endswith("/") else name
    if (
        not candidate
        or candidate.startswith("/")
        or any(part in {"", ".", ".."} for part in candidate.split("/"))
        or PurePosixPath(candidate).as_posix() != candidate
    ):
        raise ControllerRecoveryArtifactError(f"{label} is unsafe")
    return candidate


def _layer_link_stays_inside(member: tarfile.TarInfo) -> bool:
    """Return whether a layer link resolves inside the image root."""

    link = member.linkname
    if not isinstance(link, str) or not link or "\x00" in link or "\\" in link:
        return False
    parts: list[str] = []
    if member.issym() and not link.startswith("/"):
        parts.extend(PurePosixPath(member.name).parent.parts)
    for part in link.lstrip("/").split("/"):
        if part in {"", "."}:
            continue
        if part == "..":
            if not parts:
                return False
            parts.pop()
        else:
            parts.append(part)
    return bool(parts)


def _inspect_layer_archive(bundle: tarfile.TarFile, member: tarfile.TarInfo) -> None:
    """Fail closed unless one Docker layer is a canonical extractable tar."""

    stream = bundle.extractfile(member)
    if stream is None:
        raise ControllerRecoveryArtifactError("controller image layer is unavailable")
    try:
        with tarfile.open(fileobj=stream, mode="r:*") as layer:
            nested = layer.getmembers()
            names: set[str] = set()
            for nested_member in nested:
                name = _canonical_tar_member_name(
                    nested_member.name,
                    label="controller image layer member",
                    directory=nested_member.isdir(),
                )
                if name in names:
                    raise ControllerRecoveryArtifactError(
                        "controller image layer has duplicate paths"
                    )
                names.add(name)
                if not (
                    nested_member.isfile()
                    or nested_member.isdir()
                    or nested_member.issym()
                    or nested_member.islnk()
                ):
                    raise ControllerRecoveryArtifactError(
                        "controller image layer member type is unsafe"
                    )
                is_link = nested_member.issym() or nested_member.islnk()
                if is_link and not _layer_link_stays_inside(nested_member):
                    raise ControllerRecoveryArtifactError("controller image layer link is unsafe")
    except (OSError, tarfile.TarError) as error:
        raise ControllerRecoveryArtifactError("controller image layer is invalid") from error


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def _require_sha(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA.fullmatch(value) is None:
        raise ControllerRecoveryArtifactError(f"{label} must be an exact SHA")
    return value


def _require_positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ControllerRecoveryArtifactError(f"{label} must be a positive integer")
    return value


def _strict_json(raw: bytes, label: str) -> Any:
    def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ControllerRecoveryArtifactError(f"{label} contains duplicate keys")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControllerRecoveryArtifactError(f"{label} is not strict JSON") from error


def trivy_high_critical_count(report: object) -> int:
    """Count actionable vulnerability and secret findings in one Trivy JSON report."""

    if (
        not isinstance(report, dict)
        or not isinstance(report.get("SchemaVersion"), int)
        or not isinstance(report.get("ArtifactName"), str)
        or not isinstance(report.get("ArtifactType"), str)
        or not isinstance(report.get("Trivy"), dict)
        or not isinstance(report["Trivy"].get("Version"), str)
    ):
        raise ControllerRecoveryArtifactError("Trivy report is invalid")
    if "Results" not in report:
        return 0
    results = report["Results"]
    if not isinstance(results, list):
        raise ControllerRecoveryArtifactError("Trivy report is invalid")
    total = 0
    for result in results:
        if not isinstance(result, dict):
            raise ControllerRecoveryArtifactError("Trivy result is invalid")
        vulnerabilities = result.get("Vulnerabilities")
        secrets = result.get("Secrets")
        if vulnerabilities is None:
            vulnerabilities = []
        if secrets is None:
            secrets = []
        if not isinstance(vulnerabilities, list) or not isinstance(secrets, list):
            raise ControllerRecoveryArtifactError("Trivy findings are invalid")
        for finding in vulnerabilities:
            if not isinstance(finding, dict) or finding.get("Severity") not in {"HIGH", "CRITICAL"}:
                raise ControllerRecoveryArtifactError("Trivy vulnerability is invalid")
            total += 1
        if not all(isinstance(secret, dict) for secret in secrets):
            raise ControllerRecoveryArtifactError("Trivy secret is invalid")
        total += len(secrets)
    return total


def candidate_config_digest(release_root: Path) -> str:
    """Fingerprint the six activation-controlled candidate configuration files."""

    return fingerprint_config_files(
        {name: release_root / relative for name, relative in _CONFIG_FILES.items()},
        require_root_owner=False,
    )


def inspect_docker_archive(
    archive: Path,
    *,
    expected_source_sha: str,
    expected_policy_digest: str,
) -> tuple[str, int]:
    """Return the image ID and measured regular-member size of one Docker archive."""

    source_sha = _require_sha(expected_source_sha, "source SHA")
    if _DIGEST.fullmatch(expected_policy_digest) is None:
        raise ControllerRecoveryArtifactError("policy bundle digest is invalid")
    try:
        with tarfile.open(archive, mode="r:*") as bundle:
            members = bundle.getmembers()
            if not members or any(member.issym() or member.islnk() for member in members):
                raise ControllerRecoveryArtifactError("controller image archive is unsafe")
            member_by_name = {
                _canonical_tar_member_name(
                    member.name,
                    label="controller image archive member",
                    directory=member.isdir(),
                ): member
                for member in members
            }
            if len(member_by_name) != len(members):
                raise ControllerRecoveryArtifactError(
                    "controller image archive has duplicate paths"
                )
            manifest_member = member_by_name.get("manifest.json")
            if (
                manifest_member is None
                or not manifest_member.isfile()
                or manifest_member.size > _MAX_JSON_MEMBER
            ):
                raise ControllerRecoveryArtifactError("controller image manifest is unavailable")
            manifest_stream = bundle.extractfile(manifest_member)
            if manifest_stream is None:
                raise ControllerRecoveryArtifactError("controller image manifest is unavailable")
            manifest = _strict_json(manifest_stream.read(), "controller image manifest")
            if (
                not isinstance(manifest, list)
                or len(manifest) != 1
                or not isinstance(manifest[0], dict)
            ):
                raise ControllerRecoveryArtifactError("controller archive must contain one image")
            descriptor = manifest[0]
            config_name = descriptor.get("Config")
            layers = descriptor.get("Layers")
            if (
                not isinstance(config_name, str)
                or not re.fullmatch(r"[0-9a-f]{64}\.json", config_name)
                or not isinstance(layers, list)
                or not layers
            ):
                raise ControllerRecoveryArtifactError("controller image descriptor is invalid")
            layer_names = [
                _canonical_tar_member_name(name, label="controller image layer reference")
                for name in layers
            ]
            if len(set(layer_names)) != len(layer_names):
                raise ControllerRecoveryArtifactError(
                    "controller image descriptor has duplicate layers"
                )
            for layer_name in layer_names:
                layer_member = member_by_name.get(layer_name)
                if layer_member is None or not layer_member.isfile():
                    raise ControllerRecoveryArtifactError("controller image layer is unavailable")
                _inspect_layer_archive(bundle, layer_member)
            config_member = member_by_name.get(config_name)
            if (
                config_member is None
                or not config_member.isfile()
                or config_member.size > _MAX_JSON_MEMBER
            ):
                raise ControllerRecoveryArtifactError("controller image config is unavailable")
            config_stream = bundle.extractfile(config_member)
            if config_stream is None:
                raise ControllerRecoveryArtifactError("controller image config is unavailable")
            config_raw = config_stream.read()
            image_digest = hashlib.sha256(config_raw).hexdigest()
            if config_name != f"{image_digest}.json":
                raise ControllerRecoveryArtifactError("controller image config digest is invalid")
            config = _strict_json(config_raw, "controller image config")
            labels = config.get("config", {}).get("Labels") if isinstance(config, dict) else None
            if (
                not isinstance(labels, dict)
                or labels.get("org.opencontainers.image.revision") != source_sha
                or labels.get("run.qdev.controller.policy-bundle-digest")
                not in {
                    expected_policy_digest,
                    f"sha256:{expected_policy_digest}",
                }
            ):
                raise ControllerRecoveryArtifactError("controller image OCI labels are not exact")
            unpacked_size = sum(member.size for member in members if member.isfile())
    except (OSError, tarfile.TarError) as error:
        raise ControllerRecoveryArtifactError("controller image archive is unavailable") from error
    if unpacked_size < 1:
        raise ControllerRecoveryArtifactError("controller image archive is empty")
    return image_digest, unpacked_size


def github_json(path: str, *, token: str) -> dict[str, Any]:
    """Fetch one authenticated GitHub API object without persisting credentials."""

    if not token:
        raise ControllerRecoveryArtifactError("GitHub API token is unavailable")
    request = urllib.request.Request(
        f"https://api.github.com{path}",
        headers={
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "User-Agent": "qdev-controller-recovery-artifact/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            raw = response.read(_MAX_JSON_MEMBER + 1)
    except (OSError, urllib.error.HTTPError) as error:
        raise ControllerRecoveryArtifactError("GitHub workflow reconciliation failed") from error
    if len(raw) > _MAX_JSON_MEMBER:
        raise ControllerRecoveryArtifactError("GitHub workflow response is too large")
    value = _strict_json(raw, "GitHub workflow response")
    if not isinstance(value, dict):
        raise ControllerRecoveryArtifactError("GitHub workflow response is invalid")
    return value


def reconcile_workflow_identity(
    run: Mapping[str, Any],
    job: Mapping[str, Any],
    *,
    source_sha: str,
    run_id: int,
    job_id: int,
    attempt: int,
    admission_nonce: str,
    idempotency_key: str,
    now: datetime | None = None,
) -> dict[str, object]:
    """Validate exact provider facts and create a short-lived recovery identity."""

    exact_sha = _require_sha(source_sha, "source SHA")
    exact_run = _require_positive_int(run_id, "run ID")
    exact_job = _require_positive_int(job_id, "job ID")
    exact_attempt = _require_positive_int(attempt, "attempt")
    for value, label in (
        (admission_nonce, "admission nonce"),
        (idempotency_key, "idempotency key"),
    ):
        if _IDENTIFIER.fullmatch(value) is None:
            raise ControllerRecoveryArtifactError(f"{label} is invalid")
    repository = run.get("repository")
    repository_name = repository.get("full_name") if isinstance(repository, Mapping) else None
    head_branch = run.get("head_branch")
    ref = f"refs/heads/{head_branch}" if isinstance(head_branch, str) else ""
    labels = job.get("labels")
    expected_labels = {
        "self-hosted",
        "Linux",
        "X64",
        "qdev-ci",
        f"qdev-job-{exact_run}-{exact_attempt}-smoke",
    }
    if (
        run.get("id") != exact_run
        or run.get("run_attempt") != exact_attempt
        or run.get("event") != "workflow_dispatch"
        or run.get("head_sha") != exact_sha
        or run.get("conclusion") != "success"
        or run.get("path") != _WORKFLOW
        or repository_name != CONTROLLER_REPOSITORY
        or not ref.startswith("refs/heads/")
        or ref == "refs/heads/"
        or job.get("id") != exact_job
        or job.get("run_id") != exact_run
        or job.get("run_attempt") != exact_attempt
        or job.get("head_sha") != exact_sha
        or job.get("name") != "runner-smoke"
        or job.get("conclusion") != "success"
        or not isinstance(labels, list)
        or not all(isinstance(label, str) for label in labels)
        or len(labels) != len(set(labels))
        or set(labels) != expected_labels
    ):
        raise ControllerRecoveryArtifactError("GitHub workflow identity is not exact")
    observed_at = (now or datetime.now(UTC)).astimezone(UTC)
    expires_at = observed_at + timedelta(minutes=15)
    return {
        "issuer": "https://api.github.com",
        "subject": f"repo:{CONTROLLER_REPOSITORY}:ref:{ref}",
        "workflow_ref": f"{CONTROLLER_REPOSITORY}/{_WORKFLOW}@{ref}",
        "event": "workflow_dispatch",
        "ref": ref,
        "run_id": exact_run,
        "job_id": exact_job,
        "attempt": exact_attempt,
        "reconciled_at": observed_at.isoformat().replace("+00:00", "Z"),
        "head_sha": exact_sha,
        "job_name": "runner-smoke",
        "labels": labels,
        "owner_recovery": True,
        "execution_lane": "recovery",
        "expected_sha": exact_sha,
        "admission_nonce": admission_nonce,
        "idempotency_key": idempotency_key,
        "issued_at": observed_at.isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.isoformat().replace("+00:00", "Z"),
        "conclusion": "success",
    }


def verify_recovery_claim_receipt(
    document: Mapping[str, Any],
    *,
    receipt_key: str,
    source_sha: str,
    run_id: int,
    job_id: int,
    attempt: int,
    now: datetime | None = None,
) -> str:
    """Verify the controller-issued exact-job claim and return its bound nonce."""

    exact_sha = _require_sha(source_sha, "source SHA")
    exact_run = _require_positive_int(run_id, "run ID")
    exact_job = _require_positive_int(job_id, "job ID")
    exact_attempt = _require_positive_int(attempt, "attempt")
    if not receipt_key:
        raise ControllerRecoveryArtifactError("controller receipt key is unavailable")
    try:
        verified = verify_controller_receipt(document, receipt_key=receipt_key)
    except ValueError as error:
        raise ControllerRecoveryArtifactError("controller claim receipt is invalid") from error
    payload = verified["payload"]
    immutable = payload.get("immutable_tuple")
    scope = payload.get("claim_scope")
    jobs = scope.get("jobs") if isinstance(scope, dict) else None
    exact_scope_job = jobs[0] if isinstance(jobs, list) and len(jobs) == 1 else None
    try:
        expires_at = datetime.fromisoformat(str(scope["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, TypeError, ValueError) as error:
        raise ControllerRecoveryArtifactError(
            "controller claim receipt expiry is invalid"
        ) from error
    observed_at = (now or datetime.now(UTC)).astimezone(UTC)
    expected = {
        "repository": CONTROLLER_REPOSITORY,
        "run_id": exact_run,
        "job_id": exact_job,
        "attempt": exact_attempt,
        "exact_sha": exact_sha,
        "profile": "qdev-ci",
    }
    if (
        payload.get("kind") != "fifo-claim-scope-issued"
        or payload.get("operator_session") != "verified"
        or payload.get("admission_ledger") != "admin-platform"
        or payload.get("admin_platform_ledger_entry") != "controller"
        or payload.get("managed_release_ledger_entry") is not None
        or payload.get("managed_registry_entry") is not None
        or not isinstance(immutable, dict)
        or any(immutable.get(field) != value for field, value in expected.items())
        or not isinstance(immutable.get("runner"), str)
        or not immutable["runner"]
        or not isinstance(immutable.get("host"), str)
        or not immutable["host"]
        or not isinstance(scope, dict)
        or scope.get("schema") != "claim-scope-v2"
        or scope.get("runner") != immutable.get("runner")
        or scope.get("host") != immutable.get("host")
        or not isinstance(exact_scope_job, dict)
        or any(exact_scope_job.get(field) != value for field, value in expected.items())
        or expires_at.tzinfo is None
        or expires_at.astimezone(UTC) <= observed_at
    ):
        raise ControllerRecoveryArtifactError("controller claim receipt is not exact")
    receipt_id = verified["receipt_id"]
    return f"controller-claim:{receipt_id}"


def reconcile_artifact(
    release_root: Path,
    archive: Path,
    sbom_path: Path,
    security_scans_path: Path,
    source_scan_path: Path,
    image_scan_path: Path,
    output_directory: Path,
    workflow_identity: Mapping[str, object],
    claim_receipt_path: Path,
) -> Path:
    """Write provenance and a manifest for exact locally measured bytes."""

    try:
        source_sha = subprocess.check_output(  # noqa: S603
            ["/usr/bin/git", "-C", os.fspath(release_root), "rev-parse", "HEAD"], text=True
        ).strip()
        dirty = subprocess.check_output(  # noqa: S603
            ["/usr/bin/git", "-C", os.fspath(release_root), "status", "--porcelain"],
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise ControllerRecoveryArtifactError(
            "controller checkout identity is unavailable"
        ) from error
    _require_sha(source_sha, "source SHA")
    if dirty:
        raise ControllerRecoveryArtifactError("controller checkout is not clean")
    if workflow_identity.get("expected_sha") != source_sha:
        raise ControllerRecoveryArtifactError("workflow identity does not match checkout")
    policy_digest = candidate_config_digest(release_root)
    image_digest, unpacked_size = inspect_docker_archive(
        archive,
        expected_source_sha=source_sha,
        expected_policy_digest=policy_digest,
    )
    sbom = _strict_json(sbom_path.read_bytes(), "controller SBOM")
    if not isinstance(sbom, dict) or sbom.get("spdxVersion") != "SPDX-2.3":
        raise ControllerRecoveryArtifactError("controller SBOM is not SPDX 2.3")
    security_scans = _strict_json(security_scans_path.read_bytes(), "controller security scans")
    source_scan = _strict_json(source_scan_path.read_bytes(), "controller source scan")
    image_scan = _strict_json(image_scan_path.read_bytes(), "controller image scan")
    source_findings = trivy_high_critical_count(source_scan)
    image_findings = trivy_high_critical_count(image_scan)
    if (
        not isinstance(security_scans, dict)
        or security_scans.get("schema") != "qdev-controller-security-scans-v1"
        or security_scans.get("status") != "passed"
        or security_scans.get("source_high_critical") != 0
        or security_scans.get("image_high_critical") != 0
        or security_scans.get("source_report_sha256") != _sha256(source_scan_path)
        or security_scans.get("image_report_sha256") != _sha256(image_scan_path)
        or source_findings != 0
        or image_findings != 0
    ):
        raise ControllerRecoveryArtifactError("controller security scans did not pass")
    output_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(output_directory.iterdir()):
        raise ControllerRecoveryArtifactError("artifact output directory must be empty")
    output_archive = output_directory / "controller-image.tar"
    output_sbom = output_directory / "controller-sbom.spdx.json"
    output_scans = output_directory / "controller-security-scans.json"
    output_source_scan = output_directory / "controller-source-trivy.json"
    output_image_scan = output_directory / "controller-image-trivy.json"
    output_claim_receipt = output_directory / "controller-claim-receipt.json"
    shutil.copyfile(archive, output_archive)
    shutil.copyfile(sbom_path, output_sbom)
    shutil.copyfile(security_scans_path, output_scans)
    shutil.copyfile(source_scan_path, output_source_scan)
    shutil.copyfile(image_scan_path, output_image_scan)
    shutil.copyfile(claim_receipt_path, output_claim_receipt)
    entrypoint_digest = fingerprint_release_tree(release_root, require_root_owner=False)
    provenance = {
        "schema": ARTIFACT_PROVENANCE_SCHEMA,
        "repository": CONTROLLER_REPOSITORY,
        "source_sha": source_sha,
        "image_digest": image_digest,
        "policy_bundle_digest": policy_digest,
        "entrypoint_reconciliation_digest": entrypoint_digest,
        "image_unpacked_size": unpacked_size,
        "image_archive_sha256": _sha256(output_archive),
        "sbom_sha256": _sha256(output_sbom),
        "security_scans_sha256": _sha256(output_scans),
        "source_scan_sha256": _sha256(output_source_scan),
        "image_scan_sha256": _sha256(output_image_scan),
        "claim_receipt_sha256": _sha256(output_claim_receipt),
        "workflow_identity": dict(workflow_identity),
    }
    provenance_path = output_directory / "controller-provenance.json"
    provenance_path.write_bytes(_canonical(provenance) + b"\n")

    def descriptor(path: Path) -> dict[str, object]:
        return {"path": path.name, "sha256": _sha256(path), "size": path.stat().st_size}

    manifest = {
        "schema": ARTIFACT_MANIFEST_SCHEMA,
        "repository": CONTROLLER_REPOSITORY,
        "source_sha": source_sha,
        "image_digest": image_digest,
        "policy_bundle_digest": policy_digest,
        "entrypoint_reconciliation_digest": entrypoint_digest,
        "image_unpacked_size": unpacked_size,
        "image_archive": descriptor(output_archive),
        "sbom": descriptor(output_sbom),
        "security_scans": descriptor(output_scans),
        "source_scan": descriptor(output_source_scan),
        "image_scan": descriptor(output_image_scan),
        "claim_receipt": descriptor(output_claim_receipt),
        "provenance": descriptor(provenance_path),
    }
    manifest_path = output_directory / "controller-artifact-manifest.json"
    manifest_path.write_bytes(_canonical(manifest) + b"\n")
    try:
        verify_controller_artifact_manifest(
            manifest_path,
            require_root_owner=False,
        )
    except ControllerActivationError as error:
        raise ControllerRecoveryArtifactError(str(error)) from error
    return manifest_path


def sign_activation_envelope(
    unsigned_path: Path,
    artifact_manifest: Path,
    release_root: Path,
    current_status_path: Path,
    current_config_root: Path,
    private_key_path: Path,
    controller_receipt_key: str,
    output_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, object]:
    """Sign one exact candidate-bound envelope with an offline Ed25519 key."""

    observed_at = (now or datetime.now(UTC)).astimezone(UTC)
    unsigned = _strict_json(unsigned_path.read_bytes(), "unsigned activation envelope")
    if not isinstance(unsigned, dict) or "signature" in unsigned:
        raise ControllerRecoveryArtifactError("unsigned activation envelope shape is invalid")
    if not envelope_ttl_is_bounded(unsigned):
        raise ControllerRecoveryArtifactError("activation envelope TTL is invalid")
    artifact = verify_controller_artifact_manifest(
        artifact_manifest,
        require_root_owner=False,
        now=observed_at,
    )
    identity = artifact.workflow_identity
    if identity.get("execution_lane") == "recovery":
        if artifact.claim_receipt is None:
            raise ControllerRecoveryArtifactError("controller claim receipt is unavailable")
        claim_receipt = _strict_json(
            artifact.claim_receipt.read_bytes(), "controller claim receipt"
        )
        if not isinstance(claim_receipt, dict):
            raise ControllerRecoveryArtifactError("controller claim receipt is invalid")
        nonce = verify_recovery_claim_receipt(
            claim_receipt,
            receipt_key=controller_receipt_key,
            source_sha=artifact.source_sha,
            run_id=_require_positive_int(identity.get("run_id"), "run ID"),
            job_id=_require_positive_int(identity.get("job_id"), "job ID"),
            attempt=_require_positive_int(identity.get("attempt"), "attempt"),
            now=observed_at,
        )
        if identity.get("admission_nonce") != nonce:
            raise ControllerRecoveryArtifactError(
                "controller claim receipt does not bind recovery identity"
            )
    manifest_digest = _sha256(artifact_manifest)
    try:
        release_digest = controller_release_digest(release_root).removeprefix("sha256:")
    except ControllerReleaseIdentityError as error:
        raise ControllerRecoveryArtifactError(str(error)) from error
    config_digest = candidate_config_digest(release_root)
    entrypoint_digest = fingerprint_release_tree(release_root, require_root_owner=False)
    candidate = unsigned.get("candidate")
    if (
        unsigned.get("schema") != ENVELOPE_SCHEMA
        or not isinstance(candidate, dict)
        or candidate.get("source_sha") != artifact.source_sha
        or candidate.get("public_image_digest") != artifact.image_digest
        or candidate.get("internal_image_digest") != artifact.image_digest
        or candidate.get("policy_bundle_digest") != artifact.policy_bundle_digest
        or unsigned.get("artifact_manifest_digest") != manifest_digest
        or unsigned.get("candidate_release_digest") != release_digest
        or unsigned.get("candidate_config_digest") != config_digest
        or unsigned.get("entrypoint_reconciliation_digest") != entrypoint_digest
        or artifact.entrypoint_reconciliation_digest != entrypoint_digest
    ):
        raise ControllerRecoveryArtifactError("activation envelope is not bound to candidate bytes")
    verify_current_snapshot(
        unsigned,
        current_status_path=current_status_path,
        current_config_root=current_config_root,
    )
    try:
        metadata = private_key_path.stat()
        if metadata.st_mode & 0o077:
            raise ControllerRecoveryArtifactError("activation private key permissions are unsafe")
        key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    except (OSError, TypeError, ValueError) as error:
        raise ControllerRecoveryArtifactError("activation private key is unavailable") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise ControllerRecoveryArtifactError("activation private key is not Ed25519")
    signature = base64.urlsafe_b64encode(key.sign(_canonical(unsigned))).rstrip(b"=").decode()
    envelope = dict(unsigned)
    envelope["signature"] = signature
    try:
        ActivationEnvelope.verify(envelope, public_key=key.public_key(), now=observed_at)
    except ControllerActivationError as error:
        raise ControllerRecoveryArtifactError(str(error)) from error
    output_path.write_bytes(_canonical(envelope) + b"\n")
    output_path.chmod(0o600)
    return envelope


def verify_current_snapshot(
    unsigned: Mapping[str, object],
    *,
    current_status_path: Path,
    current_config_root: Path,
) -> None:
    """Bind signing to independently captured current status and configuration bytes.

    A mature activation supplies the durable activation-status document.  The
    one-time generation-zero bootstrap instead supplies the controller's public
    measured v2 status; the signer derives the exact status document that the
    activation store will initialize before the flip.
    """

    try:
        raw_status = current_status_path.read_bytes()
        status_document = _strict_json(raw_status, "current controller status")
        expected_generation = unsigned["expected_generation"]
        expected_current = unsigned["expected_current"]
        expected_status_digest = unsigned["expected_current_status_digest"]
        expected_config_digest = unsigned["expected_current_config_digest"]
        transaction_id = unsigned["transaction_id"]
    except (OSError, KeyError) as error:
        raise ControllerRecoveryArtifactError(
            "current controller snapshot is unavailable"
        ) from error
    if not isinstance(expected_generation, int) or isinstance(expected_generation, bool):
        raise ControllerRecoveryArtifactError("current controller generation is invalid")
    if (
        not isinstance(expected_status_digest, str)
        or _DIGEST.fullmatch(expected_status_digest) is None
    ):
        raise ControllerRecoveryArtifactError("current controller status digest is invalid")
    if (
        not isinstance(expected_config_digest, str)
        or _DIGEST.fullmatch(expected_config_digest) is None
    ):
        raise ControllerRecoveryArtifactError("current controller config digest is invalid")
    if not isinstance(transaction_id, str) or _IDENTIFIER.fullmatch(transaction_id) is None:
        raise ControllerRecoveryArtifactError("activation transaction ID is invalid")
    try:
        config_digest = candidate_config_digest(current_config_root)
    except ControllerActivationError as error:
        raise ControllerRecoveryArtifactError(str(error)) from error
    if config_digest != expected_config_digest:
        raise ControllerRecoveryArtifactError("current controller config snapshot does not match")
    try:
        if isinstance(status_document, dict) and status_document.get("schema") in {
            "qdev-controller-activation-status-v1",
            "qdev-controller-activation-status-v2",
        }:
            status = ControllerReleaseStatus.parse(status_document)
            status_digest = hashlib.sha256(_canonical(status.mapping()) + b"\n").hexdigest()
        else:
            measured = MeasuredControllerReleaseStatus.parse(status_document)
            if expected_generation != 0:
                raise ControllerRecoveryArtifactError(
                    "measured status may sign only the generation-zero bootstrap"
                )
            expected_tuple = ControllerTuple.parse(expected_current, field="expected current")
            if (
                measured.revision != expected_tuple.source_sha
                or measured.public_image_digest != expected_tuple.image_digest
                or measured.internal_image_digest != expected_tuple.effective_internal_image_digest
            ):
                raise ControllerRecoveryArtifactError(
                    "measured controller runtime does not match expected current tuple"
                )
            status = ControllerReleaseStatus(
                generation=0,
                current=expected_tuple,
                previous=None,
                transaction_id=f"bootstrap:{transaction_id}",
                activated_at=measured.activated_at,
            )
            status_digest = hashlib.sha256(_canonical(status.mapping()) + b"\n").hexdigest()
    except ControllerActivationError as error:
        raise ControllerRecoveryArtifactError(str(error)) from error
    if (
        status.generation != expected_generation
        or status.current.mapping() != expected_current
        or status_digest != expected_status_digest
    ):
        raise ControllerRecoveryArtifactError("current controller status snapshot does not match")


def envelope_ttl_is_bounded(unsigned: Mapping[str, object]) -> bool:
    """Small explicit helper used by production checks and regression tests."""

    try:
        issued = datetime.fromisoformat(str(unsigned["issued_at"]).replace("Z", "+00:00"))
        expires = datetime.fromisoformat(str(unsigned["expires_at"]).replace("Z", "+00:00"))
    except (KeyError, ValueError):
        return False
    return (
        issued.tzinfo is not None
        and expires.tzinfo is not None
        and timedelta(0) < (expires - issued) <= MAX_ENVELOPE_TTL
    )
