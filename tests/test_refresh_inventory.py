from __future__ import annotations

import base64
import importlib.util
import json
import subprocess
import sys
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


def test_validate_add_candidate_rejects_identity_drift() -> None:
    module = load_refresh_inventory()
    repo = {
        "id": 42,
        "nameWithOwner": "belilovsky/qazcoop",
        "owner": "belilovsky",
        "isPrivate": True,
        "isArchived": False,
        "defaultBranchRef": {"name": "main"},
    }

    with pytest.raises(RuntimeError, match="default branch expected"):
        module.validate_add_candidate(
            repo,
            owner="belilovsky",
            expected_repository_id=42,
            expected_full_name="belilovsky/qazcoop",
            expected_default_branch="codex/qazcoop-mvp",
        )


def test_add_repository_preserves_existing_records(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = load_refresh_inventory()
    inventory = tmp_path / "inventory"
    inventory.mkdir()
    original_record = {
        "id": 1,
        "full_name": "belilovsky/existing",
        "private": True,
        "archived": False,
        "default_branch": "main",
        "profiles": ["qdev-ci"],
        "workflow_count": 1,
        "workflow_files": [],
        "preserved_extension": {"value": "exact"},
    }
    (inventory / "repos.json").write_text(
        json.dumps(
            {
                "schema_version": "qdev-runner-inventory-v1",
                "generated_at": "2026-01-01T00:00:00Z",
                "owner": "belilovsky",
                "active_repository_count": 103,
                "runner_repository_count": 1,
                "repositories": [original_record],
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(module, "ROOT", tmp_path)
    monkeypatch.setattr(
        module,
        "repository_metadata",
        lambda _: {
            "id": 42,
            "nameWithOwner": "belilovsky/qazcoop",
            "owner": "belilovsky",
            "isPrivate": True,
            "isArchived": False,
            "defaultBranchRef": {"name": "codex/qazcoop-mvp"},
        },
    )
    monkeypatch.setattr(
        module,
        "inspect_repo",
        lambda repo, ref: {
            "id": repo["id"],
            "full_name": repo["nameWithOwner"],
            "private": True,
            "archived": False,
            "default_branch": "codex/qazcoop-mvp",
            "profiles": ["qdev-ci"],
            "workflow_count": 1,
            "workflow_files": [],
        },
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "refresh_inventory.py",
            "--add-repository",
            "belilovsky/qazcoop",
            "--ref",
            "exact-sha",
            "--expected-repository-id",
            "42",
            "--expected-full-name",
            "belilovsky/qazcoop",
            "--expected-default-branch",
            "codex/qazcoop-mvp",
            "--expected",
            "2",
        ],
    )

    module.main()

    payload = json.loads((inventory / "repos.json").read_text(encoding="utf-8"))
    assert payload["active_repository_count"] == 103
    assert payload["runner_repository_count"] == 2
    assert payload["repositories"][0] == original_record
    assert payload["repositories"][1]["full_name"] == "belilovsky/qazcoop"
