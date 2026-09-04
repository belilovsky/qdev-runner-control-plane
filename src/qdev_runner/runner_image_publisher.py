"""Build a fail-closed, signed evidence release for immutable runner images."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qdev_runner.runner_image_release import RunnerImageReleaseError, validate, verify_evidence

_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
_REVISION = re.compile(r"^[0-9a-f]{40}$")


@dataclass(frozen=True)
class ImageInput:
    environment_key: str
    prefix: str
    reference: str
    dockerfile: str | None


CommandRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[str]]


def canonical_json(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def default_runner(command: Sequence[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=True, capture_output=True, text=True)  # noqa: S603


def _write_private(path: Path, value: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(value)


def initialize_key(private_key_path: Path, public_key_path: Path) -> None:
    """Create a host-local Ed25519 identity, refusing every overwrite."""

    if private_key_path.exists() or public_key_path.exists():
        raise RunnerImageReleaseError("signing key path already exists")
    private_key_path.parent.mkdir(parents=True, exist_ok=True)
    public_key_path.parent.mkdir(parents=True, exist_ok=True)
    key = Ed25519PrivateKey.generate()
    private_raw = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    _write_private(private_key_path, private_raw)
    try:
        descriptor = os.open(public_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(public_raw)
    except Exception:
        private_key_path.unlink(missing_ok=True)
        raise


def load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        mode = path.stat().st_mode & 0o777
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    except (OSError, ValueError) as error:
        raise RunnerImageReleaseError("signing private key is unavailable or invalid") from error
    if mode & 0o077:
        raise RunnerImageReleaseError("signing private key permissions must be 0600")
    if not isinstance(key, Ed25519PrivateKey):
        raise RunnerImageReleaseError("signing private key is not Ed25519")
    return key


def count_findings(report: object) -> tuple[int, int]:
    value = report if isinstance(report, dict) else {}
    critical = high = 0
    results = value.get("Results", [])
    if not isinstance(results, list):
        raise RunnerImageReleaseError("Trivy security report Results must be a list")
    for result in results:
        if not isinstance(result, dict):
            continue
        findings: list[object] = []
        for field in ("Vulnerabilities", "Secrets", "Misconfigurations"):
            raw = result.get(field, [])
            if isinstance(raw, list):
                findings.extend(raw)
        for finding in findings:
            if not isinstance(finding, dict):
                continue
            severity = str(finding.get("Severity", "")).upper()
            critical += severity == "CRITICAL"
            high += severity == "HIGH"
    return critical, high


def _run_to_file(runner: CommandRunner, command: list[str], output: Path) -> None:
    completed = runner(command)
    if output.exists():
        return
    if completed.stdout:
        output.write_text(completed.stdout, encoding="utf-8")
    if not output.exists():
        raise RunnerImageReleaseError(f"evidence command did not create {output.name}")


def _git_clean_exact(repo: Path, revision: str, runner: CommandRunner) -> None:
    if not _REVISION.fullmatch(revision):
        raise RunnerImageReleaseError("release revision must be an exact git revision")
    head = runner(["git", "-C", str(repo), "rev-parse", "HEAD"]).stdout.strip()
    if head != revision:
        raise RunnerImageReleaseError("release revision does not match checkout HEAD")
    dirty = runner(["git", "-C", str(repo), "status", "--porcelain"]).stdout.strip()
    if dirty:
        raise RunnerImageReleaseError("release checkout must be clean")


def publish(
    *,
    repo: Path,
    revision: str,
    images: Sequence[ImageInput],
    evidence_root: Path,
    manifest_path: Path,
    private_key_path: Path,
    public_key_path: Path,
    source_ci_run: str,
    source_ci_status: str,
    repository: str = "belilovsky/qdev-runner-control-plane",
    issuer: str = "https://ci.qdev.run",
    identity: str = "https://ci.qdev.run/runner-images",
    runner: CommandRunner = default_runner,
) -> dict[str, Any]:
    """Scan, bind, sign, verify, and atomically publish one image release."""

    _git_clean_exact(repo, revision, runner)
    if source_ci_status not in {"passed", "locally_verified_provider_blocked"}:
        raise RunnerImageReleaseError("source CI status is not an accepted verified state")
    if len(images) != 4 or len({image.environment_key for image in images}) != 4:
        raise RunnerImageReleaseError("exactly four distinct executor images are required")
    if evidence_root.exists():
        raise RunnerImageReleaseError("evidence root already exists")
    key = load_private_key(private_key_path)
    public_raw = public_key_path.read_bytes()
    expected_public = key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    if public_raw != expected_public:
        raise RunnerImageReleaseError("public key does not match private key")

    evidence_root.mkdir(parents=True, mode=0o750)
    (evidence_root / "signing-public-key.pem").write_bytes(public_raw)
    now = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    scanner_version = runner(["trivy", "--version"]).stdout.splitlines()[0].strip()
    artifacts: list[dict[str, Any]] = []
    dockerfile_hash = sha256_file(repo / "images/runner/Dockerfile")
    source_binding = {
        "repository": repository,
        "revision": revision,
        "source_ci_run": source_ci_run,
        "source_ci_status": source_ci_status,
    }
    try:
        for image in images:
            if not _REFERENCE.fullmatch(image.reference):
                raise RunnerImageReleaseError(f"{image.environment_key} reference is not immutable")
            prefix = image.prefix
            paths = {
                "sbom": evidence_root / f"{prefix}.sbom.json",
                "security": evidence_root / f"{prefix}.security.json",
                "license": evidence_root / f"{prefix}.license.json",
                "provenance": evidence_root / f"{prefix}.provenance.json",
                "signature": evidence_root / f"{prefix}.provenance.sig",
            }
            _run_to_file(
                runner,
                [
                    "trivy",
                    "image",
                    "--quiet",
                    "--format",
                    "cyclonedx",
                    "--output",
                    str(paths["sbom"]),
                    image.reference,
                ],
                paths["sbom"],
            )
            _run_to_file(
                runner,
                [
                    "trivy",
                    "image",
                    "--quiet",
                    "--scanners",
                    "vuln,secret,misconfig",
                    "--severity",
                    "HIGH,CRITICAL",
                    "--ignore-unfixed",
                    "--format",
                    "json",
                    "--output",
                    str(paths["security"]),
                    image.reference,
                ],
                paths["security"],
            )
            _run_to_file(
                runner,
                [
                    "trivy",
                    "image",
                    "--quiet",
                    "--scanners",
                    "license",
                    "--format",
                    "json",
                    "--output",
                    str(paths["license"]),
                    image.reference,
                ],
                paths["license"],
            )
            report = json.loads(paths["security"].read_text(encoding="utf-8"))
            critical, high = count_findings(report)
            if critical:
                raise RunnerImageReleaseError(
                    f"{image.environment_key} has Critical vulnerabilities"
                )
            if high:
                raise RunnerImageReleaseError(
                    f"{image.environment_key} has High vulnerabilities without remediation receipt"
                )
            digest = "sha256:" + image.reference.rsplit("@sha256:", 1)[1]
            binding = source_binding | {
                "dockerfile": image.dockerfile,
                "dockerfile_sha256": dockerfile_hash if image.dockerfile else None,
            }
            provenance = {
                "schema": "qdev-runner-supply-chain-provenance-v1",
                "generated_at": now,
                "subject": {
                    "environment_key": image.environment_key,
                    "reference": image.reference,
                    "digest": digest,
                },
                "source_binding": binding,
                "scans": {
                    "scanner": scanner_version,
                    "security_scope": (
                        "vulnerability,secret,misconfig; HIGH,CRITICAL; ignore-unfixed"
                    ),
                    "critical": critical,
                    "high": high,
                    "sbom": sha256_file(paths["sbom"]),
                    "security": sha256_file(paths["security"]),
                    "license": sha256_file(paths["license"]),
                },
                "signing": {
                    "algorithm": "Ed25519",
                    "issuer": issuer,
                    "identity": identity,
                    "public_key_sha256": sha256_bytes(public_raw),
                },
            }
            provenance_raw = canonical_json(provenance)
            paths["provenance"].write_bytes(provenance_raw)
            paths["signature"].write_bytes(key.sign(provenance_raw))
            artifacts.append(
                {
                    "environment_key": image.environment_key,
                    "reference": image.reference,
                    "sbom_digest": sha256_file(paths["sbom"]),
                    "provenance_digest": sha256_file(paths["provenance"]),
                    "evidence_files": {name: path.name for name, path in paths.items()},
                    "signature": {
                        "subject_digest": digest,
                        "evidence_digest": sha256_file(paths["signature"]),
                        "issuer": issuer,
                        "identity": identity,
                    },
                    "vulnerability_review": {
                        "report_digest": sha256_file(paths["security"]),
                        "scanner": scanner_version,
                        "critical": critical,
                        "high": high,
                    },
                }
            )
        manifest: dict[str, Any] = {
            "schema": "qdev-runner-image-release-v1",
            "release_revision": revision,
            "generated_at": now,
            "evidence_root": str(evidence_root.resolve()),
            "source_binding": source_binding | {"dockerfile_sha256": dockerfile_hash},
            "signing": {
                "algorithm": "Ed25519",
                "issuer": issuer,
                "identity": identity,
                "public_key_file": "signing-public-key.pem",
                "public_key_sha256": sha256_bytes(public_raw),
            },
            "artifacts": artifacts,
        }
        validate(manifest, expected_revision=revision)
        verify_evidence(manifest)
        manifest_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = manifest_path.with_name(manifest_path.name + ".tmp")
        temporary.write_bytes(canonical_json(manifest))
        os.replace(temporary, manifest_path)
        return manifest
    except Exception:
        if not artifacts:
            # Preserve completed scan evidence for diagnosis once scanning began.
            pass
        raise
