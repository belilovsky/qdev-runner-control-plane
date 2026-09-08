from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

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
        f"    {profile}: {disk_mb}\n" + profiles.read_text(encoding="utf-8"),
        encoding="utf-8",
    )


def add_repository_constraints(
    profiles: Path,
    *,
    repository: str,
    constraints: dict[str, object],
) -> None:
    document = yaml.safe_load(profiles.read_text(encoding="utf-8"))
    document["repository_admission_constraints"] = {repository: constraints}
    profiles.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


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


def test_catalog_includes_critical_scenarios_from_required_suites(
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    data = json.loads(inventory.read_text(encoding="utf-8"))
    data["repositories"][0]["quality"] = {
        "suites": [
            {
                "id": "unit",
                "required": True,
                "critical_scenarios": ["login", "isolation"],
            },
            {"id": "optional", "required": False, "critical_scenarios": ["nice-to-have"]},
        ]
    }
    inventory.write_text(json.dumps(data), encoding="utf-8")

    policy = Policy(inventory, profiles)
    catalog = policy.test_catalog()
    assert catalog[0]["required_suites"] == ["unit"]
    assert catalog[0]["critical_scenarios_required"] == ["isolation", "login"]


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


def test_repository_constraints_enforce_disk_floor_and_concurrency_ceiling(
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    add_repository_constraints(
        profiles,
        repository="belilovsky/private-repo",
        constraints={"min_disk_free_gib": 35, "max_concurrency": 1},
    )
    policy = Policy(inventory, profiles)

    policy.authorize_worker_resources(
        "belilovsky/private-repo",
        disk_free_gib=35,
        concurrency=1,
    )
    with pytest.raises(PolicyError, match="at least 35 GiB"):
        policy.authorize_worker_resources(
            "belilovsky/private-repo",
            disk_free_gib=34.999,
            concurrency=1,
        )
    with pytest.raises(PolicyError, match="concurrency at most 1"):
        policy.authorize_worker_resources(
            "belilovsky/private-repo",
            disk_free_gib=35,
            concurrency=2,
        )


@pytest.mark.parametrize(
    ("disk_free_gib", "concurrency", "message"),
    [
        (None, 1, "at least 35 GiB"),
        (True, 1, "at least 35 GiB"),
        (35, None, "concurrency at most 1"),
        (35, True, "concurrency at most 1"),
    ],
)
def test_repository_constraints_fail_closed_on_missing_or_malformed_observation(
    policy_files: tuple[Path, Path],
    disk_free_gib: object,
    concurrency: object,
    message: str,
) -> None:
    inventory, profiles = policy_files
    add_repository_constraints(
        profiles,
        repository="belilovsky/private-repo",
        constraints={"min_disk_free_gib": 35, "max_concurrency": 1},
    )
    policy = Policy(inventory, profiles)

    with pytest.raises(PolicyError, match=message):
        policy.authorize_worker_resources(
            "belilovsky/private-repo",
            disk_free_gib=disk_free_gib,
            concurrency=concurrency,
        )


def test_repository_constraints_reject_foreign_repository_configuration(
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    add_repository_constraints(
        profiles,
        repository="foreign-owner/foreign-repo",
        constraints={"min_disk_free_gib": 35, "max_concurrency": 1},
    )

    with pytest.raises(PolicyError, match="not in the active allowlist"):
        Policy(inventory, profiles)


def test_repository_constraints_do_not_leak_to_another_allowed_repository(
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    add_repository_constraints(
        profiles,
        repository="belilovsky/private-repo",
        constraints={"min_disk_free_gib": 35, "max_concurrency": 1},
    )
    policy = Policy(inventory, profiles)

    policy.authorize_worker_resources(
        "belilovsky/public-repo",
        disk_free_gib=None,
        concurrency=None,
    )


@pytest.mark.parametrize(
    "constraints",
    [
        {},
        {"min_disk_free_gib": 0},
        {"min_disk_free_gib": float("inf")},
        {"max_concurrency": 0},
        {"max_concurrency": True},
        {"unexpected": 1},
    ],
)
def test_repository_constraints_reject_invalid_policy_values(
    policy_files: tuple[Path, Path], constraints: dict[str, object]
) -> None:
    inventory, profiles = policy_files
    add_repository_constraints(
        profiles,
        repository="belilovsky/private-repo",
        constraints=constraints,
    )

    with pytest.raises(PolicyError):
        Policy(inventory, profiles)


@pytest.mark.parametrize("disk_mb", [4096, 8192, 10240])
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
    assert policy.repository_profile_disk_mb == {("belilovsky/qdev-run-site", "qdev-ci"): disk_mb}
    assert policy.profiles == before.profiles
    assert policy.repositories == before.repositories


@pytest.mark.parametrize("disk_mb", [0, -1, 4095, 12288, 16384, True, 8.0])
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


def test_source_config_bounds_qdevrun_ordinary_admission_by_profile() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")
    qdevrun_overrides = {
        key: value
        for key, value in policy.repository_profile_disk_mb.items()
        if key[0] == "belilovsky/qdev-run-site"
    }
    assert qdevrun_overrides == {}
    assert policy.profiles["qdev-ci"].disk_mb == 4096
    assert policy.profiles["qdev-ci-browser"].disk_mb == 5120


def test_source_config_bounds_qazknowledge_fifo_head_by_profile() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert ("belilovsky/qazknowledge", "qdev-ci") not in policy.repository_profile_disk_mb
    assert policy.profiles["qdev-ci"].disk_mb == 4096


def test_policy_rejects_casefold_repository_collision(
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    data = json.loads(inventory.read_text(encoding="utf-8"))
    data["repositories"][1]["full_name"] = "BELILOVSKY/PRIVATE-REPO"
    inventory.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PolicyError, match="duplicate repository name"):
        Policy(inventory, profiles)


def test_policy_rejects_repository_id_collision(
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    data = json.loads(inventory.read_text(encoding="utf-8"))
    data["repositories"][1]["id"] = data["repositories"][0]["id"]
    inventory.write_text(json.dumps(data), encoding="utf-8")
    with pytest.raises(PolicyError, match="duplicate repository id"):
        Policy(inventory, profiles)


def test_policy_binds_repository_name_to_id(policy_files: tuple[Path, Path]) -> None:
    inventory, profiles = policy_files
    policy = Policy(inventory, profiles)
    with pytest.raises(PolicyError, match="repository id does not match"):
        policy.repository("belilovsky/private-repo", repository_id=2)
