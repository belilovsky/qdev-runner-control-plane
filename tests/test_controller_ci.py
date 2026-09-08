from __future__ import annotations

import importlib.util
import json
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
MERGE_SHA = "2" * 40
REPOSITORY = {"id": 42, "full_name": "belilovsky/qdev-runner-control-plane"}


def context(tmp_path: Path, event_name: str = "workflow_dispatch") -> dict[str, str]:
    event = {
        "repository": REPOSITORY,
        "sender": {"login": "belilovsky"},
        "ref": "refs/heads/main",
    }
    environment = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_SHA": SHA,
        "QDEV_EXPECTED_SHA": SHA,
        "RUNNER_ENVIRONMENT": "self-hosted",
        "GITHUB_REPOSITORY_OWNER": "belilovsky",
        "GITHUB_REPOSITORY": REPOSITORY["full_name"],
        "GITHUB_REPOSITORY_ID": "42",
        "GITHUB_REF": "refs/heads/main",
        "GITHUB_ACTOR": "belilovsky",
        "GITHUB_EVENT_NAME": event_name,
        "GITHUB_EVENT_PATH": str(tmp_path / "event.json"),
        "GITHUB_SERVER_URL": "https://github.com",
        "GITHUB_API_URL": "https://api.github.com",
        "GITHUB_GRAPHQL_URL": "https://api.github.com/graphql",
        "GITHUB_WORKFLOW_REF": (
            "belilovsky/qdev-runner-control-plane/.github/workflows/"
            "runner-smoke.yml@refs/heads/main"
        ),
        "GITHUB_JOB": "runner-smoke",
        "GITHUB_RUN_ID": "101",
        "GITHUB_RUN_ATTEMPT": "1",
        "QDEV_OWNER_RECOVERY": "true",
    }
    if event_name == "push":
        event["after"] = SHA
        environment.update(
            {
                "GITHUB_WORKFLOW_REF": (
                    "belilovsky/qdev-runner-control-plane/.github/workflows/ci.yml@refs/heads/main"
                ),
                "GITHUB_JOB": "verify",
            }
        )
    if event_name == "pull_request":
        event.update(
            {
                "action": "synchronize",
                "number": 99,
                "pull_request": {
                    "number": 99,
                    "merge_commit_sha": MERGE_SHA,
                    "base": {"ref": "main", "sha": "3" * 40, "repo": REPOSITORY},
                    "head": {"ref": "candidate", "sha": SHA, "repo": REPOSITORY},
                },
            }
        )
        environment.update(
            {
                "GITHUB_SHA": MERGE_SHA,
                "GITHUB_REF": "refs/pull/99/merge",
                "GITHUB_BASE_REF": "main",
                "GITHUB_HEAD_REF": "candidate",
                "GITHUB_WORKFLOW_REF": (
                    "belilovsky/qdev-runner-control-plane/.github/workflows/"
                    "ci.yml@refs/pull/99/merge"
                ),
                "GITHUB_JOB": "verify",
            }
        )
    (tmp_path / "event.json").write_text(json.dumps(event))
    return environment


def managed(tmp_path: Path) -> dict[str, str]:
    environment = context(tmp_path, "push")
    environment.update(
        {
            "QDEV_MANAGED_CI": "true",
            "RUNNER_NAME": "qdev-ephemeral-1",
            "GITHUB_JOB": "verify",
        }
    )
    return environment


def hosted(tmp_path: Path) -> dict[str, str]:
    environment = context(tmp_path, "pull_request")
    environment["RUNNER_ENVIRONMENT"] = "github-hosted"
    return environment


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
def test_recovery_rejects_untrusted_context(tmp_path: Path, key: str, value: str) -> None:
    environment = context(tmp_path)
    environment[key] = value
    with pytest.raises(ValueError):
        CI.validate_context("controller-recovery", environment, SHA)


def test_recovery_accepts_owner_dispatch_but_does_not_claim_hosted(tmp_path: Path) -> None:
    environment = context(tmp_path)
    CI.validate_context("controller-recovery", environment, SHA)
    with pytest.raises(ValueError):
        CI.validate_context("github-hosted", environment, SHA)
    with pytest.raises(ValueError):
        CI.validate_context("local", environment, SHA)


@pytest.mark.parametrize("lane", ["github-hosted", "managed"])
def test_internal_pr_binds_head_and_preserves_provider_merge(tmp_path: Path, lane: str) -> None:
    environment = context(tmp_path, "pull_request")
    environment["RUNNER_ENVIRONMENT"] = (
        "github-hosted" if lane == "github-hosted" else "self-hosted"
    )
    if lane == "managed":
        environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    binding = CI.validate_context(lane, environment, SHA)
    assert binding == {
        "api_url": "https://api.github.com",
        "graphql_url": "https://api.github.com/graphql",
        "server_url": "https://github.com",
        "event": "pull_request",
        "repository": REPOSITORY["full_name"],
        "repository_id": 42,
        "checkout_sha": SHA,
        "provider_sha": MERGE_SHA,
        "provider_merge_sha": MERGE_SHA,
        "pull_request": 99,
        "workflow_ref": (
            "belilovsky/qdev-runner-control-plane/.github/workflows/ci.yml@refs/pull/99/merge"
        ),
        "job": "verify",
        "ref": "refs/pull/99/merge",
        "run_id": 101,
        "run_attempt": 1,
    }
    assert environment["GITHUB_SHA"] == MERGE_SHA
    with pytest.raises(ValueError):
        CI.validate_context(lane, environment, MERGE_SHA)


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("GITHUB_SHA", SHA),
        ("GITHUB_SHA", ""),
        ("GITHUB_REPOSITORY", "someone/other"),
        ("GITHUB_REPOSITORY_ID", "43"),
        ("GITHUB_REF", "refs/pull/100/merge"),
        ("GITHUB_BASE_REF", "wrong"),
        ("GITHUB_HEAD_REF", "wrong"),
        ("GITHUB_EVENT_NAME", "pull_request_target"),
        ("GITHUB_EVENT_NAME", "push"),
        ("GITHUB_EVENT_NAME", ""),
        ("GITHUB_EVENT_PATH", ""),
    ],
)
def test_pr_rejects_conflicting_provider_context(tmp_path: Path, key: str, value: str) -> None:
    environment = context(tmp_path, "pull_request")
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    environment[key] = value
    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


@pytest.mark.parametrize("include_field", [False, True])
def test_pr_preserves_provider_merge_when_computed_field_is_pending(
    tmp_path: Path, include_field: bool
) -> None:
    environment = context(tmp_path, "pull_request")
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event["pull_request"].pop("merge_commit_sha")
    if include_field:
        event["pull_request"]["merge_commit_sha"] = None
    path.write_text(json.dumps(event))
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    binding = CI.validate_context("managed", environment, SHA)
    assert binding["checkout_sha"] == SHA
    assert binding["provider_merge_sha"] == MERGE_SHA
    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, MERGE_SHA)


def test_pr_accepts_provider_regenerated_merge_ref(tmp_path: Path) -> None:
    environment = context(tmp_path, "pull_request")
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event["pull_request"]["merge_commit_sha"] = "3" * 40
    path.write_text(json.dumps(event))
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    binding = CI.validate_context("managed", environment, SHA)
    assert binding["checkout_sha"] == SHA
    assert binding["provider_merge_sha"] == MERGE_SHA


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository.full_name", "someone/other"),
        ("repository.id", 43),
        ("pull_request.head.repo.full_name", "fork/other"),
        ("pull_request.head.repo.id", 43),
        ("pull_request.base.repo.full_name", "someone/other"),
        ("pull_request.base.repo.id", True),
        ("pull_request.head.sha", "3" * 40),
        ("pull_request.head.ref", "wrong"),
        ("pull_request.base.ref", "wrong"),
        ("pull_request.base.sha", "short"),
        ("pull_request.head", None),
        ("pull_request.merge_commit_sha", "short"),
        ("pull_request.number", 100),
        ("number", True),
        ("action", "closed"),
        ("pull_request", None),
    ],
)
def test_pr_rejects_inconsistent_or_missing_payload(
    tmp_path: Path, field: str, value: object
) -> None:
    environment = context(tmp_path, "pull_request")
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    target = event
    parts = field.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value
    path.write_text(json.dumps(event))
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


@pytest.mark.parametrize("payload", ["{", "[]", "null", " " * (1024 * 1024 + 1)])
def test_provider_event_must_be_bounded_valid_json(tmp_path: Path, payload: str) -> None:
    environment = context(tmp_path)
    Path(environment["GITHUB_EVENT_PATH"]).write_text(payload)
    with pytest.raises(ValueError):
        CI.validate_context("controller-recovery", environment, SHA)


@pytest.mark.parametrize("event_name", ["push", "workflow_dispatch"])
def test_non_pr_events_keep_exact_provider_sha(tmp_path: Path, event_name: str) -> None:
    environment = context(tmp_path, event_name)
    lane = "controller-recovery"
    if event_name == "push":
        lane = "managed"
        environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    assert CI.validate_context(lane, environment, SHA)["provider_sha"] == SHA
    environment["GITHUB_SHA"] = MERGE_SHA
    with pytest.raises(ValueError):
        CI.validate_context(lane, environment, SHA)


def test_dispatch_accepts_provider_short_branch_ref(tmp_path: Path) -> None:
    environment = context(tmp_path)
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event["ref"] = "main"
    path.write_text(json.dumps(event))
    assert CI.validate_context("controller-recovery", environment, SHA)["checkout_sha"] == SHA


@pytest.mark.parametrize(
    ("event_name", "field", "value"),
    [
        ("push", "after", "3" * 40),
        ("push", "ref", "refs/heads/wrong"),
        ("workflow_dispatch", "sender", {"login": "other"}),
        ("workflow_dispatch", "sender", None),
        ("workflow_dispatch", "ref", "wrong"),
    ],
)
def test_push_dispatch_reject_unbound_payload(
    tmp_path: Path,
    event_name: str,
    field: str,
    value: object,
) -> None:
    environment = context(tmp_path, event_name)
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event[field] = value
    path.write_text(json.dumps(event))
    with pytest.raises(ValueError):
        lane = "managed" if event_name == "push" else "controller-recovery"
        if lane == "managed":
            environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
        CI.validate_context(lane, environment, SHA)


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
        ("GITHUB_SERVER_URL", "https://example.invalid"),
        ("GITHUB_API_URL", "https://example.invalid/api"),
        ("GITHUB_GRAPHQL_URL", "https://example.invalid/graphql"),
        (
            "GITHUB_WORKFLOW_REF",
            "belilovsky/qdev-runner-control-plane/.github/workflows/other.yml@refs/heads/main",
        ),
        ("GITHUB_JOB", "other"),
        ("GITHUB_RUN_ID", "0"),
        ("GITHUB_RUN_ATTEMPT", "0"),
    ],
)
def test_managed_rejects_unbound_context(tmp_path: Path, key: str, value: str) -> None:
    environment = managed(tmp_path)
    environment[key] = value
    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


def test_managed_accepts_controller_bound_self_hosted_job(tmp_path: Path) -> None:
    environment = managed(tmp_path)
    CI.validate_context("managed", environment, SHA)
    with pytest.raises(ValueError):
        CI.validate_context("github-hosted", environment, SHA)


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
def test_hosted_rejects_unbound_context(tmp_path: Path, key: str, value: str) -> None:
    environment = hosted(tmp_path)
    environment[key] = value
    with pytest.raises(ValueError):
        CI.validate_context("github-hosted", environment, SHA)


def test_hosted_accepts_exact_provider_context(tmp_path: Path) -> None:
    CI.validate_context("github-hosted", hosted(tmp_path), SHA)


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
        "QDEV_EXPECTED_SHA": "${{ github.event.pull_request.head.sha || github.sha }}"
    }
    assert normal["jobs"]["verify"]["runs-on"] == "ubuntu-latest"
    assert (
        "github.event.pull_request.head.repo.full_name == github.repository"
        in normal["jobs"]["verify"]["if"]
    )
    assert "primary_self_hosted_workflows" not in (ROOT / ".github/qdev-runner.yml").read_text()


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


def test_controller_recovery_build_retains_a_verified_bootstrap_artifact() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/controller-recovery-build.yml").read_text()
    )
    job = workflow["jobs"]["controller-recovery-build"]
    steps = job["steps"]
    retain = next(
        step for step in steps if step.get("name") == "Retain sealed recovery material in GitHub"
    )
    delivery = next(
        step for step in steps if step.get("name") == "Deliver through authenticated QDev artifact store"
    )
    limitation = next(
        step for step in steps if step.get("name") == "Record QDev delivery limitation"
    )
    assert retain["uses"] == "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02"
    assert retain["with"]["retention-days"] == 7
    assert delivery["id"] == "qdev_delivery"
    assert delivery["continue-on-error"] is True
    assert limitation["if"] == "steps.qdev_delivery.outcome == 'failure'"


def test_runner_contract_push_is_limited_to_default_branch() -> None:
    workflow = (ROOT / ".github/workflows/qdev-runner-contract.yml").read_text()
    assert "push:\n    branches:\n      - main" in workflow
    assert "runs-on: ubuntu-latest" in workflow
    assert "self-hosted" not in workflow
    assert "ref: ${{ github.event.pull_request.head.sha || github.sha }}" in workflow


def test_runtime_gate_cannot_resolve_missing_dependencies_from_dev_environment() -> None:
    script = (ROOT / "scripts/verify_runtime_install.py").read_text()
    assert "venv.EnvBuilder(with_pip=True)" in script
    assert '"--no-deps"' in script
    assert '"requirements.runtime.txt"' in script
    assert '"pip", "check"' in script
    assert '"-I"' in script
