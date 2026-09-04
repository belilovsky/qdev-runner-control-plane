from __future__ import annotations

import base64
import importlib.util
import subprocess
from pathlib import Path
from types import ModuleType

import pytest


def load_refresh_inventory() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts/refresh_inventory.py"
    spec = importlib.util.spec_from_file_location("refresh_inventory", path)
    if spec is None or spec.loader is None:
        raise AssertionError("unable to load refresh_inventory.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def encoded(value: str) -> dict[str, str]:
    return {"content": base64.b64encode(value.encode()).decode()}


def test_inspect_repo_honours_declared_docker_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_refresh_inventory()
    responses = {
        "/repos/belilovsky/qazpolit": {"id": 1},
        "/repos/belilovsky/qazpolit/actions/workflows?per_page=100&ref=main": {
            "workflows": [{"id": 10}]
        },
        "/repos/belilovsky/qazpolit/contents/.github/qdev-runner.yml?ref=main": encoded(
            "profiles:\n  - qdev-ci\n  - qdev-ci-docker\n"
        ),
        "/repos/belilovsky/qazpolit/contents/.github/workflows?ref=main": [
            {"path": ".github/workflows/ci.yml", "sha": "workflow-sha"}
        ],
        "/repos/belilovsky/qazpolit/contents/.github/workflows/ci.yml?ref=main": encoded(
            "name: CI\n"
        ),
    }

    monkeypatch.setattr(module, "api", responses.__getitem__)
    item = module.inspect_repo(
        {
            "nameWithOwner": "belilovsky/qazpolit",
            "isPrivate": True,
            "isArchived": False,
            "defaultBranchRef": {"name": "main"},
        },
        ref="main",
    )

    assert item is not None
    assert item["profiles"] == ["qdev-ci", "qdev-ci-docker"]


def test_declared_profiles_reject_unknown_profile(monkeypatch: pytest.MonkeyPatch) -> None:
    module = load_refresh_inventory()
    monkeypatch.setattr(
        module,
        "api",
        lambda endpoint: encoded("profiles:\n  - qdev-ci-future\n"),
    )

    with pytest.raises(RuntimeError, match="unsupported profiles"):
        module.declared_profiles("belilovsky/example", ref="main")


def test_declared_profiles_treat_missing_contract_as_legacy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = load_refresh_inventory()

    def missing(_: str) -> dict[str, str]:
        raise subprocess.CalledProcessError(1, "gh")

    monkeypatch.setattr(module, "api", missing)
    assert module.declared_profiles("belilovsky/legacy", ref="main") == set()
