from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "guard_public_fork_jobs.py"
SPEC = importlib.util.spec_from_file_location("guard_public_fork_jobs", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_adds_guard_to_qdev_job_in_pull_request_workflow() -> None:
    source = """on:
  pull_request:
jobs:
  test:
    runs-on: [self-hosted, Linux, X64, qdev-ci, qdev-job-test]
    steps: []
"""

    result = MODULE.rewrite(source)

    assert f"    if: {MODULE.FORK_GUARD}\n" in result
    assert MODULE.rewrite(result) == result


def test_combines_existing_expression_with_guard() -> None:
    source = """on: [push, pull_request]
jobs:
  browser:
    if: ${{ github.event_name == 'workflow_dispatch' }}
    runs-on: [self-hosted, Linux, X64, qdev-ci-browser, qdev-job-browser]
"""

    result = MODULE.rewrite(source)

    assert "if: (github.event_name == 'workflow_dispatch') && (" in result
    assert MODULE.FORK_GUARD in result


def test_leaves_non_pr_and_release_runner_workflows_unchanged() -> None:
    push_only = """on: push
jobs:
  test:
    runs-on: [self-hosted, Linux, X64, qdev-ci, qdev-job-test]
"""
    release = """on:
  pull_request:
jobs:
  deploy:
    runs-on: product-release
"""

    assert MODULE.rewrite(push_only) == push_only
    assert MODULE.rewrite(release) == release


def test_rejects_multiline_if_for_manual_resolution() -> None:
    source = """on:
  pull_request:
jobs:
  test:
    if: >-
      github.event_name == 'push'
    runs-on: [self-hosted, Linux, X64, qdev-ci, qdev-job-test]
"""

    with pytest.raises(ValueError, match="multiline"):
        MODULE.rewrite(source)
