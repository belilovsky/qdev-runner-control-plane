import sys
from pathlib import Path

from qdev_runner.policy import Policy

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts.refresh_inventory import apply_profile_overrides, inventory_payload


def test_qazcompute_docker_admission_is_repository_scoped() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert policy.repository_profile_disk_mb[
        ("belilovsky/qazcompute", "qdev-ci-docker")
    ] == 18 * 1024
    assert policy.profiles["qdev-ci-docker"].disk_mb == 20 * 1024


def test_mcp_servers_docker_admission_is_repository_scoped() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert policy.repository_profile_disk_mb[
        ("belilovsky/mcp-servers", "qdev-ci-docker")
    ] == 12 * 1024
    assert policy.profiles["qdev-ci-docker"].disk_mb == 20 * 1024


def test_adilet_digest_docker_admission_matches_its_source_manifest() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert policy.repository_profile_disk_mb[
        ("belilovsky/adilet-digest-studio", "qdev-ci-docker")
    ] == 12 * 1024
    assert policy.profiles["qdev-ci-docker"].disk_mb == 20 * 1024


def test_bounded_inventory_merge_preserves_unselected_records() -> None:
    other = {"full_name": "belilovsky/other", "profiles": ["qdev-ci"]}
    target = {"full_name": "belilovsky/tokaev-module", "profiles": ["qdev-ci"]}
    replacement = {
        "full_name": "belilovsky/tokaev-module",
        "profiles": ["qdev-ci", "qdev-ci-docker"],
    }

    merged = inventory_payload(
        existing={
            "schema_version": "qdev-runner-inventory-v1",
            "owner": "belilovsky",
            "active_repository_count": 2,
            "repositories": [target, other],
        },
        replacements=[replacement],
        generated_at="2026-09-04T00:00:00+00:00",
    )

    assert merged["runner_repository_count"] == 2
    assert merged["repositories"][0] == replacement
    assert merged["repositories"][1] == other


def test_bounded_profile_override_is_additive_and_known() -> None:
    item = {"full_name": "belilovsky/tokaev-module", "profiles": ["qdev-ci"]}

    overridden = apply_profile_overrides(item, ["qdev-ci-docker"])

    assert overridden["profiles"] == ["qdev-ci", "qdev-ci-docker"]
    assert item["profiles"] == ["qdev-ci"]
