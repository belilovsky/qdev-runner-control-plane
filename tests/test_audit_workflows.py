from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def load_auditor() -> ModuleType:
    path = ROOT / "scripts/audit_workflows.py"
    spec = importlib.util.spec_from_file_location("audit_workflows", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def audit(deploy_workflow: str) -> dict[str, object]:
    module = load_auditor()
    paths = [
        ".github/workflows/ci.yml",
        ".github/workflows/deploy.yml",
        ".github/workflows/qdev-runner-contract.yml",
        ".github/workflows/runner-smoke.yml",
    ]
    contents = {
        ".github/qdev-runner.yml": (
            "schema_version: qdev-runner-v2\n"
            "execution_mode: github-hosted-primary\n"
            "self_hosted_recovery: true\n"
            "profiles:\n  - qdev-ci\n"
            "release_registry_workflows:\n  - deploy.yml\n"
        ),
        "AGENTS.md": (
            "<!-- qdev-runner-policy:start -->\n"
            "managed\n"
            "<!-- qdev-runner-policy:end -->\n"
        ),
        ".github/QDEV_RUNNERS.md": "managed\n",
        ".github/scripts/qdev-runner-policy.py": "managed\n",
        ".github/workflows/ci.yml": "jobs: {}\n",
        ".github/workflows/deploy.yml": deploy_workflow,
        ".github/workflows/qdev-runner-contract.yml": "jobs: {}\n",
        ".github/workflows/runner-smoke.yml": "jobs: {}\n",
    }

    def content_text(_full_name: str, path: str, _ref: str) -> str:
        return contents[path]

    def workflow_paths(_full_name: str, _ref: str) -> list[str]:
        return paths

    module.content_text = content_text
    module.workflow_paths = workflow_paths
    return module.audit_repository(
        {"full_name": "belilovsky/example", "default_branch": "main"},
        None,
    )


def test_fleet_audit_allows_declared_non_pr_ghcr_release() -> None:
    result = audit(
        """on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: docker push ghcr.io/example/product:${{ github.sha }}
"""
    )
    assert result["violations"] == []


def test_fleet_audit_keeps_pr_and_cache_guards_in_release_workflow() -> None:
    result = audit(
        """on:
  pull_request:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: docker push ghcr.io/example/product:${{ github.sha }}
      - uses: actions/cache@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"""
    )
    kinds = {item["kind"] for item in result["violations"]}
    assert kinds == {"release-registry-workflow-pull-request", "github-cache"}
