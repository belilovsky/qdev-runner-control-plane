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
        "GITHUB_ACTOR": "belilovsky",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "QDEV_OWNER_RECOVERY": "true",
    }


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_ACTIONS", "false"),
        ("GITHUB_ACTOR", ""),
        ("GITHUB_ACTOR", "someone-else"),
        ("GITHUB_REPOSITORY_OWNER", ""),
        ("GITHUB_EVENT_NAME", "push"),
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
        CI.validate_context("hosted", recovery(), SHA)
    with pytest.raises(ValueError):
        CI.validate_context("local", recovery(), SHA)


def test_self_hosted_accepts_normal_actions_context_without_recovery_claim() -> None:
    environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_SHA": SHA,
        "RUNNER_ENVIRONMENT": "self-hosted",
        "GITHUB_EVENT_NAME": "pull_request",
    }
    CI.validate_context("self-hosted", environment, SHA)
    with pytest.raises(ValueError):
        CI.validate_context("hosted", environment, SHA)


def test_local_is_never_provider_evidence() -> None:
    CI.validate_context("local", {}, SHA)
    with pytest.raises(ValueError):
        CI.validate_context("hosted", {}, SHA)


def test_every_lane_uses_full_shared_suite() -> None:
    commands = CI.commands("python")
    assert commands == [
        ["python", "-m", "ruff", "check", "."],
        ["python", "-m", "mypy"],
        ["python", "-m", "pytest", "-q"],
        ["python", ".github/scripts/qdev-runner-policy.py", "--root", "."],
        ["python", "scripts/verify_runtime_install.py"],
    ]
    normal = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    manual = yaml.safe_load((ROOT / ".github/workflows/runner-smoke.yml").read_text())
    assert manual[True]["workflow_dispatch"]["inputs"]["execution_lane"]["default"] == "hosted"
    assert manual["concurrency"]["cancel-in-progress"] is False
    normal_verify = normal["jobs"]["verify"]
    assert "self-hosted" in normal_verify["runs-on"]
    assert any(
        s.get("run") == "python scripts/verify_controller_ci.py --lane self-hosted"
        for s in normal_verify["steps"]
    )
    for job in [normal["jobs"]["verify"], *manual["jobs"].values()]:
        assert any("scripts/verify_controller_ci.py" in s.get("run", "") for s in job["steps"])


def test_runner_contract_push_is_limited_to_default_branch() -> None:
    workflow = (ROOT / ".github/workflows/qdev-runner-contract.yml").read_text()
    assert "push:\n    branches:\n      - main" in workflow


def test_runtime_gate_cannot_resolve_missing_dependencies_from_dev_environment() -> None:
    script = (ROOT / "scripts/verify_runtime_install.py").read_text()
    assert "venv.EnvBuilder(with_pip=True)" in script
    assert '"--no-deps"' in script
    assert '"requirements.runtime.txt"' in script
    assert '"pip", "check"' in script
    assert '"-I"' in script
