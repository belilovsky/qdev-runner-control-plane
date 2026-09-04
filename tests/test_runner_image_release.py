from __future__ import annotations

import json
from pathlib import Path

import pytest

from qdev_runner.runner_image_release import (
    REQUIRED_IMAGES,
    RunnerImageReleaseError,
    load,
    validate,
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
