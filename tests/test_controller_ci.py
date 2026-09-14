from __future__ import annotations

import importlib.util
import json
import re
import sys
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "scripts.verify_controller_ci", ROOT / "scripts/verify_controller_ci.py"
)
assert SPEC and SPEC.loader
CI = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(CI)
SHA = "1" * 40
MERGE_SHA = "2" * 40
REPOSITORY_FULL_NAME = "belilovsky/qdev-runner-control-plane"
REPOSITORY = {"id": 42, "full_name": REPOSITORY_FULL_NAME}


def assert_exact_value_error(expected: str, action: object) -> None:
    """Keep fail-closed rejection codes stable for operators and callers."""
    assert callable(action)
    with pytest.raises(ValueError, match=f"^{re.escape(expected)}$"):
        action()


def pull_request_payload(event: dict[str, object]) -> dict[str, object]:
    payload = event["pull_request"]
    assert isinstance(payload, dict)
    return cast(dict[str, object], payload)


def context(tmp_path: Path, event_name: str = "workflow_dispatch") -> dict[str, str]:
    event = {
        "repository": REPOSITORY,
        "sender": {"login": "belilovsky"},
        "ref": "refs/heads/main",
    }
    environment: dict[str, str] = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_SHA": SHA,
        "QDEV_EXPECTED_SHA": SHA,
        "RUNNER_ENVIRONMENT": "self-hosted",
        "GITHUB_REPOSITORY_OWNER": "belilovsky",
        "GITHUB_REPOSITORY": REPOSITORY_FULL_NAME,
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


def test_hosted_recovery_build_requires_owner_dispatch_on_main(tmp_path: Path) -> None:
    environment = context(tmp_path)
    environment.update(
        {
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_WORKFLOW_REF": (
                "belilovsky/qdev-runner-control-plane/.github/workflows/"
                "controller-recovery-build.yml@refs/heads/main"
            ),
            "GITHUB_JOB": "controller-recovery-build",
        }
    )
    assert CI.validate_context("controller-recovery-build", environment, SHA)
    environment["GITHUB_REF"] = "refs/heads/candidate"
    environment["GITHUB_WORKFLOW_REF"] = (
        "belilovsky/qdev-runner-control-plane/.github/workflows/"
        "controller-recovery-build.yml@refs/heads/candidate"
    )
    event_path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(event_path.read_text())
    event["ref"] = "refs/heads/candidate"
    event_path.write_text(json.dumps(event))
    with pytest.raises(ValueError, match="default branch"):
        CI.validate_context("controller-recovery-build", environment, SHA)


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


@pytest.mark.parametrize("event_merge_sha", ["3" * 40, "4" * 40])
def test_pr_does_not_confuse_computed_merge_field_with_provider_merge(
    tmp_path: Path, event_merge_sha: str
) -> None:
    environment = context(tmp_path, "pull_request")
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event["pull_request"]["merge_commit_sha"] = event_merge_sha
    path.write_text(json.dumps(event))
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})

    binding = CI.validate_context("managed", environment, SHA)

    assert binding["provider_merge_sha"] == MERGE_SHA
    assert binding["checkout_sha"] == SHA


@pytest.mark.parametrize("action", ["opened", "reopened"])
def test_pr_accepts_each_documented_open_action(tmp_path: Path, action: str) -> None:
    environment = context(tmp_path, "pull_request")
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event["action"] = action
    path.write_text(json.dumps(event))
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})

    assert CI.validate_context("managed", environment, SHA)["pull_request"] == 99


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
        ("pull_request.merge_commit_sha", "not-a-sha"),
        ("pull_request.merge_commit_sha", True),
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
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    target = event
    parts = field.split(".")
    for part in parts[:-1]:
        target = target[part]
    target[parts[-1]] = value
    path.write_text(json.dumps(event))
    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


@pytest.mark.parametrize("field", ["GITHUB_SHA", "GITHUB_EVENT_PATH"])
def test_pr_rejects_missing_required_provider_fields(tmp_path: Path, field: str) -> None:
    environment = context(tmp_path, "pull_request")
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    environment.pop(field)

    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


def test_pr_rejects_boolean_repository_id_even_when_other_bindings_match(tmp_path: Path) -> None:
    environment = context(tmp_path, "pull_request")
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event["repository"]["id"] = True
    event["pull_request"]["base"]["repo"]["id"] = True
    event["pull_request"]["head"]["repo"]["id"] = True
    environment["GITHUB_REPOSITORY_ID"] = "True"
    path.write_text(json.dumps(event))

    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


def test_pr_rejects_zero_repository_id(tmp_path: Path) -> None:
    environment = context(tmp_path, "pull_request")
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event["repository"]["id"] = 0
    event["pull_request"]["base"]["repo"]["id"] = 0
    event["pull_request"]["head"]["repo"]["id"] = 0
    environment["GITHUB_REPOSITORY_ID"] = "0"
    path.write_text(json.dumps(event))

    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


def test_pr_accepts_positive_repository_id_one(tmp_path: Path) -> None:
    environment = context(tmp_path, "pull_request")
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event["repository"]["id"] = 1
    event["pull_request"]["base"]["repo"]["id"] = 1
    event["pull_request"]["head"]["repo"]["id"] = 1
    environment["GITHUB_REPOSITORY_ID"] = "1"
    path.write_text(json.dumps(event))

    assert CI.validate_context("managed", environment, SHA)["repository_id"] == 1


@pytest.mark.parametrize("number", [0, True])
def test_pr_rejects_nonpositive_or_boolean_number(tmp_path: Path, number: int | bool) -> None:
    environment = context(tmp_path, "pull_request")
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event["number"] = number
    event["pull_request"]["number"] = number
    environment["GITHUB_REF"] = f"refs/pull/{number}/merge"
    path.write_text(json.dumps(event))

    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


def test_pr_rejects_uppercase_provider_computed_or_base_revision_sha(tmp_path: Path) -> None:
    environment = context(tmp_path, "pull_request")
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    path = Path(environment["GITHUB_EVENT_PATH"])
    event = json.loads(path.read_text())
    event["pull_request"]["merge_commit_sha"] = "A" * 40
    path.write_text(json.dumps(event))

    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)

    event["pull_request"]["merge_commit_sha"] = MERGE_SHA
    event["pull_request"]["base"]["sha"] = "A" * 40
    path.write_text(json.dumps(event))
    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


@pytest.mark.parametrize("payload", ["{", "[]", "null", " " * (1024 * 1024 + 1)])
def test_provider_event_must_be_bounded_valid_json(tmp_path: Path, payload: str) -> None:
    environment = context(tmp_path)
    Path(environment["GITHUB_EVENT_PATH"]).write_text(payload)
    with pytest.raises(ValueError):
        CI.validate_context("controller-recovery", environment, SHA)


def test_provider_event_size_limit_is_exact_and_not_truncated(tmp_path: Path) -> None:
    environment = context(tmp_path, "push")
    environment.update({"QDEV_MANAGED_CI": "true", "RUNNER_NAME": "qdev-ephemeral-1"})
    path = Path(environment["GITHUB_EVENT_PATH"])
    payload = json.dumps(json.loads(path.read_text())).encode()
    at_limit = payload + b" " * (1024 * 1024 - len(payload))
    path.write_bytes(at_limit)
    assert CI.validate_context("managed", environment, SHA)["checkout_sha"] == SHA

    path.write_bytes(at_limit + b" ")
    with pytest.raises(ValueError):
        CI.validate_context("managed", environment, SHA)


def test_provider_binding_rejection_codes_are_exact(tmp_path: Path) -> None:
    """Each provider failure is an observable fail-closed contract, not just any error."""

    def remove_pr_base(event: dict[str, object]) -> None:
        pull_request_payload(event)["base"] = None

    def corrupt_pr_base_sha(event: dict[str, object]) -> None:
        base = pull_request_payload(event)["base"]
        assert isinstance(base, dict)
        base["sha"] = "not-a-sha"

    def rejects(
        message: str,
        *,
        event_name: str = "workflow_dispatch",
        environment_update: dict[str, str] | None = None,
        event_update: Callable[[dict[str, object]], None] | None = None,
        raw_payload: str | None = None,
    ) -> None:
        environment = context(tmp_path, event_name)
        event_path = Path(environment["GITHUB_EVENT_PATH"])
        if environment_update:
            environment.update(environment_update)
        event = json.loads(event_path.read_text())
        if event_update:
            event_update(event)
        event_path.write_text(raw_payload if raw_payload is not None else json.dumps(event))
        assert_exact_value_error(message, lambda: CI.provider_binding(environment, SHA))

    rejects("exact provider SHA is required", environment_update={"GITHUB_SHA": ""})
    rejects(
        "readable provider event is required",
        environment_update={"GITHUB_EVENT_PATH": str(tmp_path / "missing-event.json")},
    )
    rejects(
        "provider event must be an object",
        raw_payload="[]",
    )
    rejects(
        "provider repository identity mismatch",
        environment_update={"GITHUB_REPOSITORY": "someone/other"},
    )
    rejects(
        "pull request merge context mismatch",
        event_name="pull_request",
        event_update=lambda event: event.update({"action": "closed"}),
    )
    rejects(
        "pull request source identity missing",
        event_name="pull_request",
        event_update=remove_pr_base,
    )
    rejects(
        "pull request source identity mismatch",
        event_name="pull_request",
        event_update=corrupt_pr_base_sha,
    )
    rejects(
        "pull request head does not match checkout",
        event_name="pull_request",
        environment_update={"GITHUB_SHA": SHA},
    )
    rejects(
        "provider SHA does not match checkout",
        event_name="push",
        environment_update={"GITHUB_SHA": MERGE_SHA},
    )
    rejects(
        "provider branch ref is required",
        event_name="push",
        environment_update={"GITHUB_REF": "refs/heads/"},
    )
    rejects(
        "push event does not match checkout",
        event_name="push",
        event_update=lambda event: event.update({"after": MERGE_SHA}),
    )
    rejects(
        "dispatch requires a confirmed owner and exact branch",
        event_update=lambda event: event.update({"sender": {"login": "someone-else"}}),
    )
    rejects(
        "unsupported provider event",
        environment_update={"GITHUB_EVENT_NAME": "schedule"},
    )


def test_provider_binding_uses_the_exact_bounded_read_and_lowercase_sha(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """The event cap and SHA grammar are part of the source-binding boundary."""
    lowercase_sha = "a" * 40
    environment = context(tmp_path, "push")
    environment["GITHUB_SHA"] = lowercase_sha
    payload = {
        "repository": REPOSITORY,
        "sender": {"login": "belilovsky"},
        "ref": "refs/heads/main",
        "after": lowercase_sha,
    }
    reads: list[int] = []

    class Stream:
        def __enter__(self) -> Stream:
            return self

        def __exit__(self, *_args: object) -> None:
            return None

        def read(self, size: int) -> bytes:
            reads.append(size)
            return json.dumps(payload).encode()

    class EventPath:
        def open(self, mode: str) -> Stream:
            assert mode == "rb"
            return Stream()

    monkeypatch.setattr(CI, "Path", lambda _path: EventPath())
    assert CI.provider_binding(environment, lowercase_sha)["checkout_sha"] == lowercase_sha
    assert reads == [1024 * 1024 + 1]


def test_validate_context_rejection_codes_are_exact(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Lane checks keep their distinct audit reasons after provider binding succeeds."""
    assert_exact_value_error(
        "unknown execution lane", lambda: CI.validate_context("other", {}, SHA)
    )
    assert_exact_value_error(
        "exact checkout SHA is required", lambda: CI.validate_context("local", {}, "A" * 40)
    )
    assert_exact_value_error(
        "checkout does not match requested SHA",
        lambda: CI.validate_context("local", {"QDEV_EXPECTED_SHA": MERGE_SHA}, SHA),
    )
    assert_exact_value_error(
        "provider CI evidence requires a real Actions execution",
        lambda: CI.validate_context("managed", {}, SHA),
    )
    assert_exact_value_error(
        "Actions must identify its real execution lane",
        lambda: CI.validate_context("local", {"GITHUB_ACTIONS": "true"}, SHA),
    )

    environment = managed(tmp_path)
    environment["RUNNER_ENVIRONMENT"] = "github-hosted"
    assert_exact_value_error(
        "runner environment does not match requested execution lane",
        lambda: CI.validate_context("managed", environment, SHA),
    )

    environment = managed(tmp_path)
    environment.pop("QDEV_EXPECTED_SHA")
    assert_exact_value_error(
        "managed CI requires an exact controller-bound checkout",
        lambda: CI.validate_context("managed", environment, SHA),
    )

    environment = managed(tmp_path)
    environment.pop("RUNNER_NAME")
    assert_exact_value_error(
        "managed CI requires an enrolled ephemeral runner",
        lambda: CI.validate_context("managed", environment, SHA),
    )

    monkeypatch.setattr(CI, "provider_binding", lambda _environment, _sha: {})
    environment = managed(tmp_path)
    environment["GITHUB_EVENT_NAME"] = "schedule"
    assert_exact_value_error(
        "managed CI received an untrusted event",
        lambda: CI.validate_context("managed", environment, SHA),
    )
    environment = context(tmp_path)
    environment["GITHUB_ACTOR"] = ""
    assert_exact_value_error(
        "recovery requires the nonempty repository owner actor",
        lambda: CI.validate_context("controller-recovery", environment, SHA),
    )
    environment = context(tmp_path)
    environment["GITHUB_EVENT_NAME"] = "push"
    assert_exact_value_error(
        "recovery requires manual workflow_dispatch",
        lambda: CI.validate_context("controller-recovery", environment, SHA),
    )
    environment = context(tmp_path)
    environment["QDEV_OWNER_RECOVERY"] = "false"
    assert_exact_value_error(
        "explicit owner recovery confirmation and exact SHA are required",
        lambda: CI.validate_context("controller-recovery", environment, SHA),
    )


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


def test_main_emits_a_complete_local_receipt_without_provider_binding(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def check_output(command: list[str], **kwargs: object) -> str:
        if command == ["git", "rev-parse", "HEAD"]:
            assert kwargs == {"cwd": ROOT, "text": True}
            return SHA
        assert command == ["git", "status", "--porcelain"]
        assert kwargs == {"cwd": ROOT}
        return ""

    commands: list[list[str]] = []

    def run(command: list[str], **kwargs: object) -> None:
        assert kwargs == {"cwd": ROOT, "check": True}
        commands.append(command)

    monkeypatch.setattr(CI.subprocess, "check_output", check_output)
    monkeypatch.setattr(CI.subprocess, "run", run)
    monkeypatch.setattr(
        CI.os,
        "environ",
        {
            "RUNNER_ENVIRONMENT": "local-proof",
            "GITHUB_RUN_ID": "42",
            "GITHUB_RUN_ATTEMPT": "3",
        },
    )
    monkeypatch.setattr(sys, "argv", ["verify_controller_ci.py", "--lane", "local"])

    assert CI.main() == 0

    output = capsys.readouterr().out
    receipt = json.loads(output)
    assert output == json.dumps(receipt, sort_keys=True) + "\n"
    assert receipt == {
        "schema": "qdev-controller-ci-execution-v1",
        "sha": SHA,
        "source_scope": "commit",
        "dirty": False,
        "lane": "local",
        "source_binding": None,
        "runner_environment": "local-proof",
        "run_id": "42",
        "attempt": "3",
        "checks": ["lint", "format", "typing", "pytest", "runner-policy", "runtime-install"],
        "status": "passed",
        "signed": False,
    }
    assert commands == CI.commands(sys.executable)


@pytest.mark.parametrize("lane", ["github-hosted", "managed", "controller-recovery"])
def test_main_accepts_every_declared_provider_lane(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], lane: str
) -> None:
    def check_output(command: list[str], **_kwargs: object) -> str:
        return SHA if command == ["git", "rev-parse", "HEAD"] else ""

    monkeypatch.setattr(CI.subprocess, "check_output", check_output)
    monkeypatch.setattr(CI.subprocess, "run", lambda _command, **_kwargs: None)
    monkeypatch.setattr(
        CI,
        "validate_context",
        lambda actual_lane, _environment, _sha: {"lane": actual_lane},
    )
    monkeypatch.setattr(sys, "argv", ["verify_controller_ci.py", "--lane", lane])

    assert CI.main() == 0
    assert json.loads(capsys.readouterr().out)["lane"] == lane


def test_main_parser_requires_a_declared_lane(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(sys, "argv", ["verify_controller_ci.py"])
    with pytest.raises(SystemExit) as error:
        CI.main()
    assert error.value.code == 2
    assert "the following arguments are required: --lane" in capsys.readouterr().err

    monkeypatch.setattr(sys, "argv", ["verify_controller_ci.py", "--lane", "other"])
    with pytest.raises(SystemExit) as error:
        CI.main()
    assert error.value.code == 2
    assert "invalid choice" in capsys.readouterr().err


def test_main_rejects_dirty_provider_evidence_before_running_checks(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def check_output(command: list[str], **_kwargs: object) -> str:
        if command == ["git", "rev-parse", "HEAD"]:
            return SHA
        assert command == ["git", "status", "--porcelain"]
        return " M scripts/verify_controller_ci.py\n"

    monkeypatch.setattr(CI.subprocess, "check_output", check_output)
    monkeypatch.setattr(sys, "argv", ["verify_controller_ci.py", "--lane", "managed"])

    with pytest.raises(SystemExit) as error:
        CI.main()
    assert error.value.code == 2
    assert "provider evidence requires an unchanged exact-SHA checkout" in capsys.readouterr().err


def test_managed_specific_guards_reject_after_provider_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    environment = managed(tmp_path)
    monkeypatch.setattr(CI, "provider_binding", lambda _environment, _sha: {})

    environment["GITHUB_EVENT_NAME"] = "schedule"
    with pytest.raises(ValueError, match="managed CI received an untrusted event"):
        CI.validate_context("managed", environment, SHA)

    environment["GITHUB_EVENT_NAME"] = "push"
    environment["GITHUB_REPOSITORY"] = "belilovsky/other"
    with pytest.raises(ValueError, match="managed CI is bound to the controller repository"):
        CI.validate_context("managed", environment, SHA)


def test_recovery_specific_guard_rejects_non_dispatch_after_provider_binding(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    environment = context(tmp_path)
    monkeypatch.setattr(CI, "provider_binding", lambda _environment, _sha: {})
    environment["GITHUB_EVENT_NAME"] = "push"

    with pytest.raises(ValueError, match="recovery requires manual workflow_dispatch"):
        CI.validate_context("controller-recovery", environment, SHA)


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


def test_recovery_build_uses_hosted_lane_and_full_verification() -> None:
    workflow = yaml.safe_load(
        (ROOT / ".github/workflows/controller-recovery-build.yml").read_text()
    )
    job = workflow["jobs"]["controller-recovery-build"]
    assert job["runs-on"] == "ubuntu-latest"
    verify = next(
        step for step in job["steps"] if "scripts/verify_controller_ci.py" in step.get("run", "")
    )
    assert verify["run"].endswith("--lane controller-recovery-build")
    assert verify["env"] == {
        "QDEV_EXPECTED_SHA": "${{ inputs.expected_sha }}",
        "QDEV_OWNER_RECOVERY": "true",
    }


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
