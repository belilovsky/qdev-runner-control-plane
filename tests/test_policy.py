from __future__ import annotations

import json
from pathlib import Path

import pytest

from qdev_runner.policy import Policy, PolicyError


def add_repository_disk_override(
    profiles: Path,
    *,
    repository: str,
    profile: str,
    disk_mb: int,
) -> None:
    profiles.write_text(
        "repository_admission_disk_mb:\n"
        f"  {repository}:\n"
        f"    {profile}: {disk_mb}\n"
        + profiles.read_text(encoding="utf-8"),
        encoding="utf-8",
    )


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


def test_same_repository_public_pull_request_is_allowed(
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    policy = Policy(inventory, profiles)
    selected = policy.profile_for_labels(
        "belilovsky/public-repo", ["self-hosted", "Linux", "X64", "qdev-ci"]
    )
    policy.authorize_run(
        "belilovsky/public-repo",
        selected,
        {"event": "pull_request", "pull_requests": [{"head": {"repo": {"id": 2}}}]},
    )


def test_public_pull_request_without_head_repository_is_rejected(
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    policy = Policy(inventory, profiles)
    selected = policy.profile_for_labels(
        "belilovsky/public-repo", ["self-hosted", "Linux", "X64", "qdev-ci"]
    )
    with pytest.raises(PolicyError, match="public fork"):
        policy.authorize_run(
            "belilovsky/public-repo",
            selected,
            {"event": "pull_request", "pull_requests": []},
        )


def test_private_pull_request_is_allowed(policy_files: tuple[Path, Path]) -> None:
    inventory, profiles = policy_files
    policy = Policy(inventory, profiles)
    selected = policy.profile_for_labels(
        "belilovsky/private-repo", ["self-hosted", "Linux", "X64", "qdev-ci"]
    )
    policy.authorize_run("belilovsky/private-repo", selected, {"event": "pull_request"})


def test_repository_profile_disk_override_is_exact(policy_files: tuple[Path, Path]) -> None:
    inventory, profiles = policy_files
    add_repository_disk_override(
        profiles,
        repository="belilovsky/private-repo",
        profile="qdev-ci-browser",
        disk_mb=14336,
    )

    policy = Policy(inventory, profiles)

    assert policy.repository_profile_disk_mb == {
        ("belilovsky/private-repo", "qdev-ci-browser"): 14336
    }


@pytest.mark.parametrize("disk_mb", [4095, 15360, 16000])
def test_repository_profile_disk_override_stays_bounded(
    policy_files: tuple[Path, Path], disk_mb: int
) -> None:
    inventory, profiles = policy_files
    add_repository_disk_override(
        profiles,
        repository="belilovsky/private-repo",
        profile="qdev-ci-browser",
        disk_mb=disk_mb,
    )

    with pytest.raises(PolicyError, match="below the profile default"):
        Policy(inventory, profiles)


def test_repository_profile_disk_override_rejects_disallowed_profile(
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    add_repository_disk_override(
        profiles,
        repository="belilovsky/public-repo",
        profile="qdev-ci-browser",
        disk_mb=14336,
    )

    with pytest.raises(PolicyError, match="disallowed profile"):
        Policy(inventory, profiles)


@pytest.mark.parametrize("disk_mb", [8192, 10240])
def test_qdevrun_ordinary_admission_is_explicit_and_bounded(
    policy_files: tuple[Path, Path], disk_mb: int
) -> None:
    inventory, profiles = policy_files
    data = json.loads(inventory.read_text(encoding="utf-8"))
    data["repositories"][0]["full_name"] = "belilovsky/qdev-run-site"
    inventory.write_text(json.dumps(data), encoding="utf-8")
    before = Policy(inventory, profiles)
    assert before.repository_profile_disk_mb == {}
    add_repository_disk_override(
        profiles, repository="belilovsky/qdev-run-site", profile="qdev-ci", disk_mb=disk_mb
    )
    policy = Policy(inventory, profiles)
    assert policy.repository_profile_disk_mb == {
        ("belilovsky/qdev-run-site", "qdev-ci"): disk_mb
    }
    assert policy.profiles == before.profiles
    assert policy.repositories == before.repositories


@pytest.mark.parametrize("disk_mb", [0, -1, 4096, 8191, 12288, 16384, True, 8.0])
def test_qdevrun_ordinary_admission_rejects_invalid_budgets(
    policy_files: tuple[Path, Path], disk_mb: int
) -> None:
    inventory, profiles = policy_files
    data = json.loads(inventory.read_text(encoding="utf-8"))
    data["repositories"][0]["full_name"] = "belilovsky/qdev-run-site"
    inventory.write_text(json.dumps(data), encoding="utf-8")
    add_repository_disk_override(
        profiles, repository="belilovsky/qdev-run-site", profile="qdev-ci", disk_mb=disk_mb
    )
    with pytest.raises(PolicyError):
        Policy(inventory, profiles)


def test_source_config_only_changes_qdevrun_ordinary_admission() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")
    qdevrun_overrides = {
        key: value
        for key, value in policy.repository_profile_disk_mb.items()
        if key[0] == "belilovsky/qdev-run-site"
    }
    assert qdevrun_overrides == {("belilovsky/qdev-run-site", "qdev-ci"): 8192}
    assert policy.profiles["qdev-ci"].disk_mb == 12288
    assert policy.profiles["qdev-ci-browser"].disk_mb == 5120
