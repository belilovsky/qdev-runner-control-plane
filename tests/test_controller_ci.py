from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "controller_ci", ROOT / "scripts/verify_controller_ci.py"
)
assert SPEC and SPEC.loader
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)
SHA = "1" * 40


def recovery() -> dict[str, str]:
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_SHA": SHA,
        "QDEV_EXPECTED_SHA": SHA,
        "RUNNER_ENVIRONMENT": "self-hosted",
        "GITHUB_REPOSITORY_OWNER": "belilovsky",
        "GITHUB_REPOSITORY": "belilovsky/qdev-runner-control-plane",
        "GITHUB_ACTOR": "belilovsky",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_REF": "refs/heads/codex/controller-recovery",
        "GITHUB_WORKFLOW_REF": (
            "belilovsky/qdev-runner-control-plane/.github/workflows/"
            "runner-smoke.yml@refs/heads/codex/controller-recovery"
        ),
        "GITHUB_JOB": "runner-smoke",
        "GITHUB_RUN_ID": "101",
        "GITHUB_RUN_ATTEMPT": "1",
        "QDEV_OWNER_RECOVERY": "true",
    }


def managed() -> dict[str, str]:
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_SHA": SHA,
        "QDEV_EXPECTED_SHA": SHA,
        "QDEV_MANAGED_CI": "true",
        "RUNNER_ENVIRONMENT": "self-hosted",
        "RUNNER_NAME": "qdev-ephemeral-1",
        "GITHUB_REPOSITORY_OWNER": "belilovsky",
        "GITHUB_REPOSITORY": "belilovsky/qdev-runner-control-plane",
        "GITHUB_EVENT_NAME": "push",
    }


def hosted() -> dict[str, str]:
    return {
        "GITHUB_ACTIONS": "true",
        "GITHUB_SHA": SHA,
        "QDEV_EXPECTED_SHA": SHA,
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_REPOSITORY_OWNER": "belilovsky",
        "GITHUB_REPOSITORY": "belilovsky/qdev-runner-control-plane",
        "GITHUB_EVENT_NAME": "pull_request",
        "GITHUB_RUN_ID": "101",
        "GITHUB_RUN_ATTEMPT": "1",
    }


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_ACTIONS", "false"),
        ("GITHUB_ACTOR", ""),
        ("GITHUB_ACTOR", "someone-else"),
        ("GITHUB_REPOSITORY_OWNER", ""),
        ("GITHUB_REPOSITORY", "belilovsky/foreign"),
        ("GITHUB_EVENT_NAME", "push"),
        ("GITHUB_REF", "refs/tags/controller"),
        (
            "GITHUB_WORKFLOW_REF",
            "belilovsky/qdev-runner-control-plane/.github/workflows/ci.yml@refs/heads/codex/controller-recovery",
        ),
        ("GITHUB_JOB", "verify"),
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_RUN_ATTEMPT", "x"),
        ("QDEV_OWNER_RECOVERY", "false"),
        ("QDEV_EXPECTED_SHA", ""),
        ("QDEV_EXPECTED_SHA", "2" * 40),
        ("GITHUB_SHA", "2" * 40),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
    ],
)
def test_recovery_rejects_untrusted_context(key: str, value: str) -> None:
    environment = recovery()
    environment[key] = value
    with pytest.raises(ValueError):
        CI.validate_context("controller-recovery", environment, SHA)


def test_recovery_accepts_owner_dispatch_but_does_not_claim_hosted() -> None:
    CI.validate_context("controller-recovery", recovery(), SHA)
    with pytest.raises(ValueError):
        CI.validate_context("github-hosted", recovery(), SHA)
    with pytest.raises(ValueError):
        CI.validate_context("local", recovery(), SHA)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("QDEV_EXPECTED_SHA", ""),
        ("QDEV_EXPECTED_SHA", "2" * 40),
        ("QDEV_MANAGED_CI", "false"),
        ("RUNNER_ENVIRONMENT", "github-hosted"),
        ("RUNNER_NAME", ""),
        ("GITHUB_REPOSITORY_OWNER", ""),
        ("GITHUB_REPOSITORY", "someone/else"),
        ("GITHUB_EVENT_NAME", "schedule"),
    ],
)
def test_managed_rejects_unbound_context(key: str, value: str) -> None:
    environment = managed()
    environment[key] = value
    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


def test_managed_accepts_controller_bound_self_hosted_job() -> None:
    CI.validate_context("managed", managed(), SHA)
    with pytest.raises(ValueError):
        CI.validate_context("github-hosted", managed(), SHA)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_REPOSITORY_OWNER", ""),
        ("GITHUB_REPOSITORY", "someone/else"),
        ("GITHUB_EVENT_NAME", "schedule"),
        ("GITHUB_RUN_ID", "0x1"),
        ("GITHUB_RUN_ATTEMPT", ""),
        ("RUNNER_ENVIRONMENT", "self-hosted"),
    ],
)
def test_hosted_rejects_unbound_context(key: str, value: str) -> None:
    environment = hosted()
    environment[key] = value
    with pytest.raises(ValueError):
        CI.validate_context("github-hosted", environment, SHA)


def test_hosted_accepts_exact_provider_context() -> None:
    CI.validate_context("github-hosted", hosted(), SHA)


def test_local_is_never_provider_evidence() -> None:
    CI.validate_context("local", {}, SHA)
    with pytest.raises(ValueError):
        CI.validate_context("github-hosted", {}, SHA)


def test_every_lane_uses_full_shared_suite() -> None:
    commands = CI.commands("python")
    assert commands == [
        ["python", "-m", "ruff", "check", "."],
        ["python", "-m", "ruff", "format", "--check", "."],
        ["python", "-m", "mypy"],
        ["python", "-m", "pytest", "-q"],
        ["python", ".github/scripts/qdev-runner-policy.py", "--root", "."],
        ["python", "scripts/verify_runtime_install.py"],
    ]
    normal = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    manual = yaml.safe_load((ROOT / ".github/workflows/runner-smoke.yml").read_text())
    assert manual[True]["workflow_dispatch"]["inputs"]["execution_lane"]["default"] == "recovery"
    assert manual["concurrency"]["cancel-in-progress"] is False
    for job in [normal["jobs"]["verify"], *manual["jobs"].values()]:
        assert any("scripts/verify_controller_ci.py" in s.get("run", "") for s in job["steps"])
    normal_step = next(
        step
        for step in normal["jobs"]["verify"]["steps"]
        if "scripts/verify_controller_ci.py" in step.get("run", "")
    )
    assert normal_step["run"].endswith("--lane github-hosted")
    assert normal_step["env"] == {
        "QDEV_EXPECTED_SHA": "${{ github.sha }}",
    }
    assert normal["jobs"]["verify"]["runs-on"] == "ubuntu-24.04"


def test_runner_smoke_declares_exact_recovery_inputs_and_full_verification() -> None:
    workflow = yaml.safe_load((ROOT / ".github/workflows/runner-smoke.yml").read_text())
    triggers = workflow.get("on", workflow.get(True))
    inputs = triggers["workflow_dispatch"]["inputs"]
    assert inputs["execution_lane"] == {
        "type": "choice",
        "options": ["recovery"],
        "default": "recovery",
        "required": True,
        "description": "Explicit execution lane; no automatic fallback",
    }
    assert inputs["expected_sha"]["required"] is True
    assert inputs["owner_recovery"]["type"] == "boolean"
    job_condition = workflow["jobs"]["runner-smoke"]["if"]
    assert "startsWith(github.ref, 'refs/heads/')" in job_condition
    assert "github.ref == 'refs/heads/main'" not in job_condition
    verify = next(
        step
        for step in workflow["jobs"]["runner-smoke"]["steps"]
        if "scripts/verify_controller_ci.py" in step.get("run", "")
    )
    assert verify["run"].endswith("--lane controller-recovery")
    assert verify["env"] == {
        "QDEV_EXPECTED_SHA": "${{ inputs.expected_sha }}",
        "QDEV_OWNER_RECOVERY": "${{ inputs.owner_recovery }}",
    }


def test_runner_contract_push_is_limited_to_default_branch() -> None:
    workflow = (ROOT / ".github/workflows/qdev-runner-contract.yml").read_text()
    assert "push:\n    branches:\n      - main" in workflow
    assert "runs-on: ubuntu-24.04" in workflow


def test_runtime_gate_cannot_resolve_missing_dependencies_from_dev_environment() -> None:
    script = (ROOT / "scripts/verify_runtime_install.py").read_text()
    assert "venv.EnvBuilder(with_pip=True)" in script
    assert '"--no-deps"' in script
    assert '"requirements.runtime.txt"' in script
    assert '"pip", "check"' in script
    assert '"-I"' in script
