from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def load_module() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts/audit_worker_runtime.py"
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
        "QDEV_WORKER_PROFILES": "",
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
