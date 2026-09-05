from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType

import pytest


def load_module() -> ModuleType:
    path = (
        Path(__file__).resolve().parents[1]
        / "src/qdev_runner/worker_runtime_audit.py"
    )
    spec = importlib.util.spec_from_file_location("audit_worker_runtime", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_audit_checks_only_images_required_by_enabled_profiles(tmp_path: Path) -> None:
    module = load_module()
    env_file = tmp_path / "worker.env"
    env_file.write_text(
        "QDEV_WORKER_NAME=mail-qdev-reserve\n"
        "QDEV_WORKER_TIER=reserve\n"
        'QDEV_WORKER_PROFILES="qdev-ci,qdev-ci-docker"\n'
        "QDEV_RUNNER_IMAGE=registry.example/qdev/general@sha256:"
        + "a" * 64
        + "\n"
        + "QDEV_RUNNER_BROWSER_IMAGE=registry.example/qdev/browser@sha256:"
        + "b" * 64
        + "\n"
        + "QDEV_RUNNER_DOCKER_IMAGE=registry.example/qdev/buildkit@sha256:"
        + "c" * 64
        + "\n"
        + "QDEV_DOCKER_SIDECAR_IMAGE=registry.example/qdev/sidecar@sha256:"
        + "d" * 64
        + "\n",
        encoding="utf-8",
    )
    inspected: list[str] = []

    def inspector(_engine: str, reference: str) -> tuple[bool, str]:
        inspected.append(reference)
        return True, f"id:{reference}"

    result = module.evaluate(module.load_contract(env_file), inspector=inspector)
    assert result["errors"] == []
    assert inspected == [
        "registry.example/qdev/general@sha256:" + "a" * 64,
        "registry.example/qdev/buildkit@sha256:" + "c" * 64,
        "registry.example/qdev/sidecar@sha256:" + "d" * 64,
    ]
    assert "registry.example/qdev/browser@sha256:" + "b" * 64 not in inspected


def test_audit_rejects_missing_executor_image() -> None:
    module = load_module()
    values = {
        "QDEV_WORKER_NAME": "srv-qdev-primary",
        "QDEV_WORKER_TIER": "primary",
        "QDEV_WORKER_PROFILES": "qdev-ci",
        "QDEV_RUNNER_IMAGE": "registry.example/qdev/missing@sha256:" + "a" * 64,
    }

    result = module.evaluate(values, inspector=lambda _engine, _reference: (False, None))

    assert result["errors"] == ["image_missing:QDEV_RUNNER_IMAGE"]
    assert result["images"][0]["present"] is False


def test_audit_rejects_name_tier_mismatch() -> None:
    module = load_module()
    values = {
        "QDEV_WORKER_NAME": "mail-qdev-primary",
        "QDEV_WORKER_TIER": "reserve",
        "QDEV_WORKER_PROFILES": "qdev-ci",
        "QDEV_RUNNER_IMAGE": "registry.example/qdev/general@sha256:" + "a" * 64,
    }

    result = module.evaluate(values, inspector=lambda _engine, _reference: (True, "id"))

    assert result["errors"] == ["worker_name_tier_mismatch"]


def test_audit_rejects_mutable_or_missing_executor_references() -> None:
    module = load_module()
    values = {
        "QDEV_WORKER_NAME": "srv-qdev-primary",
        "QDEV_WORKER_TIER": "primary",
        "QDEV_WORKER_PROFILES": "qdev-ci,qdev-ci-docker",
        "QDEV_RUNNER_IMAGE": "registry.ci.qdev.run/qdev/actions-runner:2.336.0-r2",
        "QDEV_DOCKER_SIDECAR_IMAGE": "docker.io/library/docker:latest",
    }

    result = module.evaluate(values, inspector=lambda _engine, _reference: (True, "id"))

    assert result["errors"] == [
        "image_not_immutable:QDEV_RUNNER_IMAGE",
        "image_reference_missing:QDEV_RUNNER_DOCKER_IMAGE",
        "image_not_immutable:QDEV_DOCKER_SIDECAR_IMAGE",
    ]


@pytest.mark.parametrize("profiles", ["", " , ", "qdev-ci-brower", "qdev-ci,unknown"])
def test_audit_rejects_empty_or_unknown_profiles(profiles: str) -> None:
    module = load_module()
    inspected: list[str] = []

    def inspector(_engine: str, reference: str) -> tuple[bool, str]:
        inspected.append(reference)
        return True, "id"

    values = {
        "QDEV_WORKER_NAME": "srv-qdev-primary",
        "QDEV_WORKER_TIER": "primary",
        "QDEV_WORKER_PROFILES": profiles,
        "QDEV_RUNNER_IMAGE": "registry.example/qdev/general@sha256:" + "a" * 64,
    }
    result = module.evaluate(values, inspector=inspector)
    assert result["errors"] == ["invalid_worker_profiles"]
    assert result["image_release"]["status"] != "verified"
    assert inspected == []


def test_default_profiles_still_require_every_executor_image() -> None:
    module = load_module()
    assert {key for key, _ in module.required_images({})} == set(module.IMAGE_KEYS)


def test_profile_whitespace_and_duplicates_do_not_duplicate_image_checks() -> None:
    module = load_module()
    assert module.required_images({"QDEV_WORKER_PROFILES": " qdev-ci, qdev-ci ,"}) == [
        ("QDEV_RUNNER_IMAGE", "")
    ]


def test_audit_requires_manifest_to_bind_the_enabled_image_references(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module = load_module()
    values = {
        "QDEV_WORKER_NAME": "srv-qdev-primary",
        "QDEV_WORKER_TIER": "primary",
        "QDEV_WORKER_PROFILES": "qdev-ci",
        "QDEV_RUNNER_IMAGE": "registry.example/qdev/general@sha256:" + "a" * 64,
    }
    manifest = tmp_path / "runner-images.json"
    artifacts = []
    for key, character in (
        ("QDEV_RUNNER_IMAGE", "a"),
        ("QDEV_RUNNER_BROWSER_IMAGE", "b"),
        ("QDEV_RUNNER_DOCKER_IMAGE", "c"),
        ("QDEV_DOCKER_SIDECAR_IMAGE", "d"),
    ):
        image_digest = "sha256:" + character * 64
        reference = (
            "registry.example/qdev/general@" + image_digest
            if key == "QDEV_RUNNER_IMAGE"
            else f"registry.example/qdev/{key.lower()}@{image_digest}"
        )
        artifacts.append(
            {
                "environment_key": key,
                "reference": reference,
                "sbom_digest": "sha256:" + "e" * 64,
                "provenance_digest": "sha256:" + "f" * 64,
                "signature": {
                    "subject_digest": image_digest,
                    "evidence_digest": "sha256:" + "1" * 64,
                    "issuer": "https://ci.qdev.run",
                    "identity": "https://ci.qdev.run/runner-images",
                },
                "vulnerability_review": {
                    "report_digest": "sha256:" + "2" * 64,
                    "scanner": "trivy",
                    "critical": 0,
                    "high": 0,
                },
            }
        )
    manifest.write_text(
        json.dumps(
            {
                "schema": "qdev-runner-image-release-v1",
                "release_revision": "a" * 40,
                "artifacts": artifacts,
            }
        ),
        encoding="utf-8",
    )

    result = module.evaluate(
        values,
        inspector=lambda _engine, _reference: (True, "id"),
        image_release_manifest=manifest,
    )

    # A structurally valid envelope without its signed evidence must fail closed.
    assert result["errors"] == ["image_release_manifest_invalid"]
    assert result["image_release"]["status"] == "invalid"

    # Isolate reference binding after the strict evidence verifier has succeeded.
    # Cryptographic failure/tampering cases are exercised in test_runner_image_release.py.
    original_load = module.load_image_release

    def verified_load(path: Path, *, strict_evidence: bool = False) -> tuple[dict[str, str], str]:
        assert strict_evidence is True
        return original_load(path)

    monkeypatch.setattr(module, "load_image_release", verified_load)
    result = module.evaluate(
        values,
        inspector=lambda _engine, _reference: (True, "id"),
        image_release_manifest=manifest,
    )
    assert result["errors"] == []
    assert result["image_release"]["status"] == "verified"
    assert result["image_release"]["checked_artifacts"] == ["QDEV_RUNNER_IMAGE"]

    values["QDEV_RUNNER_IMAGE"] = "registry.example/qdev/other@sha256:" + "a" * 64
    mismatch = module.evaluate(
        values,
        inspector=lambda _engine, _reference: (True, "id"),
        image_release_manifest=manifest,
    )
    assert mismatch["errors"] == ["image_release_reference_mismatch:QDEV_RUNNER_IMAGE"]
    assert mismatch["image_release"]["status"] == "mismatch"
