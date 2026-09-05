from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qdev_runner.runner_image_release import (
    REQUIRED_IMAGES,
    RunnerImageReleaseError,
    load,
    validate,
    verify_evidence,
)


def digest(character: str) -> str:
    return "sha256:" + character * 64


def artifact(environment_key: str, character: str, *, high: int = 0) -> dict[str, object]:
    reference = f"registry.ci.qdev.run/qdev/{environment_key.lower()}@{digest(character)}"
    vulnerability: dict[str, object] = {
        "report_digest": digest("b"),
        "scanner": "trivy",
        "critical": 0,
        "high": high,
    }
    if high:
        vulnerability["remediation_digest"] = digest("c")
    return {
        "environment_key": environment_key,
        "reference": reference,
        "sbom_digest": digest("d"),
        "provenance_digest": digest("e"),
        "signature": {
            "subject_digest": digest(character),
            "evidence_digest": digest("f"),
            "issuer": "https://ci.qdev.run",
            "identity": "https://ci.qdev.run/runner-images",
        },
        "vulnerability_review": vulnerability,
    }


def manifest() -> dict[str, object]:
    return {
        "schema": "qdev-runner-image-release-v1",
        "release_revision": "a" * 40,
        "artifacts": [
            artifact("QDEV_RUNNER_IMAGE", "1"),
            artifact("QDEV_RUNNER_BROWSER_IMAGE", "2"),
            artifact("QDEV_RUNNER_DOCKER_IMAGE", "3"),
            artifact("QDEV_DOCKER_SIDECAR_IMAGE", "4"),
        ],
    }


def test_valid_manifest_covers_all_executor_images() -> None:
    references = validate(manifest(), expected_revision="a" * 40)

    assert set(references) == REQUIRED_IMAGES
    assert all("@sha256:" in reference for reference in references.values())


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (
            lambda value: value["artifacts"].pop(),  # type: ignore[index,union-attr]
            "missing required artifacts",
        ),
        (
            lambda value: value["artifacts"][0].update(  # type: ignore[index,union-attr]
                {"reference": "registry.ci.qdev.run/qdev/runner:latest"}
            ),
            "reference must be immutable",
        ),
        (
            lambda value: value["artifacts"][0]["signature"].update(  # type: ignore[index,union-attr]
                {"subject_digest": digest("0")}
            ),
            "not bound to reference",
        ),
        (
            lambda value: value["artifacts"][0]["vulnerability_review"].update(  # type: ignore[index,union-attr]
                {"critical": 1}
            ),
            "Critical vulnerabilities",
        ),
    ],
)
def test_manifest_rejects_unverified_release_evidence(mutate: object, message: str) -> None:
    value = manifest()
    mutate(value)  # type: ignore[operator]

    with pytest.raises(RunnerImageReleaseError, match=message):
        validate(value)


def test_high_findings_need_immutable_remediation_receipt() -> None:
    value = manifest()
    review = value["artifacts"][0]["vulnerability_review"]  # type: ignore[index,union-attr]
    review.update({"high": 1})  # type: ignore[union-attr]
    review.pop("remediation_digest", None)  # type: ignore[union-attr]

    with pytest.raises(RunnerImageReleaseError, match="remediation_digest"):
        validate(value)

    review["remediation_digest"] = digest("9")  # type: ignore[index,union-attr]
    assert validate(value)["QDEV_RUNNER_IMAGE"].endswith("@" + digest("1"))


def test_load_returns_the_raw_manifest_digest(tmp_path: Path) -> None:
    path = tmp_path / "runner-images.json"
    path.write_text(json.dumps(manifest(), sort_keys=True), encoding="utf-8")

    references, manifest_digest = load(path)

    assert references["QDEV_RUNNER_DOCKER_IMAGE"].endswith("@" + digest("3"))
    assert manifest_digest.startswith("sha256:")


def test_strict_evidence_verifies_digests_subject_and_ed25519_signature(tmp_path: Path) -> None:
    value = manifest()
    value["artifacts"][2]["vulnerability_review"].update(  # type: ignore[index,union-attr]
        {"high": 2, "remediation_digest": digest("c")}
    )
    value["evidence_root"] = str(tmp_path)
    key = Ed25519PrivateKey.generate()
    public_raw = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    (tmp_path / "signing-public-key.pem").write_bytes(public_raw)
    value["signing"] = {
        "algorithm": "Ed25519",
        "issuer": "https://ci.qdev.run",
        "identity": "https://ci.qdev.run/runner-images",
        "public_key_file": "signing-public-key.pem",
        "public_key_sha256": "sha256:" + hashlib.sha256(public_raw).hexdigest(),
    }
    for index, raw_artifact in enumerate(value["artifacts"]):  # type: ignore[index,union-attr]
        artifact_value = raw_artifact  # type: ignore[assignment]
        prefix = f"image-{index}"
        reference = artifact_value["reference"]
        signature = artifact_value["signature"]
        sbom = tmp_path / f"{prefix}.sbom.json"
        security = tmp_path / f"{prefix}.security.json"
        license_report = tmp_path / f"{prefix}.license.json"
        provenance = tmp_path / f"{prefix}.provenance.json"
        signature_file = tmp_path / f"{prefix}.provenance.sig"
        sbom.write_text("{}\n", encoding="utf-8")
        security.write_text("{}\n", encoding="utf-8")
        license_report.write_text("{}\n", encoding="utf-8")

        def digest_file(path: Path) -> str:
            return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

        artifact_value["sbom_digest"] = digest_file(sbom)
        artifact_value["vulnerability_review"]["report_digest"] = digest_file(security)
        remediation_digest = None
        remediation_name = None
        if artifact_value["vulnerability_review"]["high"]:
            remediation = tmp_path / f"{prefix}.remediation.json"
            remediation.write_text(
                json.dumps(
                    {
                        "schema": "qdev-runner-remediation-v1",
                        "image_reference": reference,
                        "findings": {
                            "critical": 0,
                            "high": artifact_value["vulnerability_review"]["high"],
                        },
                        "decision": {
                            "status": "accepted",
                            "decision_id": "runner-test-remediation",
                            "owner": "Test owner",
                            "reviewed_at": "2026-09-05T10:00:00Z",
                            "review_by": "2026-10-05T10:00:00Z",
                            "reason": "Bounded test fixture.",
                            "compensating_controls": ["Exact digest binding"],
                        },
                    },
                    sort_keys=True,
                )
                + "\n",
                encoding="utf-8",
            )
            remediation_name = remediation.name
            remediation_digest = digest_file(remediation)
            artifact_value["vulnerability_review"]["remediation_digest"] = remediation_digest

        scans = {
            "sbom": digest_file(sbom),
            "security": digest_file(security),
            "license": digest_file(license_report),
        }
        if remediation_digest is not None:
            scans["remediation"] = remediation_digest
        provenance_value = {
            "subject": {
                "environment_key": artifact_value["environment_key"],
                "reference": reference,
                "digest": signature["subject_digest"],
            },
            "scans": scans,
            "signing": {
                "algorithm": "Ed25519",
                "issuer": "https://ci.qdev.run",
                "identity": "https://ci.qdev.run/runner-images",
                "public_key_sha256": value["signing"]["public_key_sha256"],  # type: ignore[index]
            },
            "source_binding": {"revision": value["release_revision"]},
        }
        provenance_raw = (json.dumps(provenance_value, sort_keys=True) + "\n").encode()
        provenance.write_bytes(provenance_raw)
        signature_file.write_bytes(key.sign(provenance_raw))
        artifact_value["provenance_digest"] = digest_file(provenance)
        signature["evidence_digest"] = digest_file(signature_file)
        artifact_value["evidence_files"] = {
            "sbom": sbom.name,
            "security": security.name,
            "license": license_report.name,
            "provenance": provenance.name,
            "signature": signature_file.name,
        }
        if remediation_name is not None:
            artifact_value["evidence_files"]["remediation"] = remediation_name

    verify_evidence(value)
    remediation_path = tmp_path / "image-2.remediation.json"
    remediation_raw = remediation_path.read_bytes()
    remediation_path.write_text("{}\n", encoding="utf-8")
    with pytest.raises(RunnerImageReleaseError, match="remediation receipt digest mismatch"):
        verify_evidence(value)
    remediation_path.write_bytes(remediation_raw)

    (tmp_path / "image-0.provenance.sig").write_bytes(b"x" * 64)
    with pytest.raises(RunnerImageReleaseError, match="signature digest mismatch"):
        verify_evidence(value)
