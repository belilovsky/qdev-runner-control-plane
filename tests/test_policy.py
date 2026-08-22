from __future__ import annotations

from pathlib import Path

import pytest

from qdev_runner.policy import Policy, PolicyError


def test_profile_requires_complete_labels(policy_files: tuple[Path, Path]) -> None:
    inventory, profiles = policy_files
    policy = Policy(inventory, profiles)
    selected = policy.profile_for_labels(
        "belilovsky/private-repo", ["self-hosted", "Linux", "X64", "qdev-ci"]
    )
    assert selected.name == "qdev-ci"
    with pytest.raises(PolicyError):
        policy.profile_for_labels("belilovsky/private-repo", ["self-hosted", "qdev-ci"])


def test_public_fork_is_rejected(policy_files: tuple[Path, Path]) -> None:
    inventory, profiles = policy_files
    policy = Policy(inventory, profiles)
    selected = policy.profile_for_labels(
        "belilovsky/public-repo", ["self-hosted", "Linux", "X64", "qdev-ci"]
    )
    with pytest.raises(PolicyError, match="public fork"):
        policy.authorize_run(
            "belilovsky/public-repo",
            selected,
            {"event": "pull_request", "pull_requests": [{"head": {"repo": {"id": 999}}}]},
        )


def test_private_pull_request_is_allowed(policy_files: tuple[Path, Path]) -> None:
    inventory, profiles = policy_files
    policy = Policy(inventory, profiles)
    selected = policy.profile_for_labels(
        "belilovsky/private-repo", ["self-hosted", "Linux", "X64", "qdev-ci"]
    )
    policy.authorize_run("belilovsky/private-repo", selected, {"event": "pull_request"})
