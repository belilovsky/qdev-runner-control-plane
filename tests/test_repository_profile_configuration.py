from pathlib import Path

from qdev_runner.policy import Policy


def test_qazposter_contract_admission_uses_bounded_qdev_ci_profile() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert ("belilovsky/qazposter", "qdev-ci") not in policy.repository_profile_disk_mb
    assert policy.profiles["qdev-ci"].disk_mb == 4 * 1024


def test_controller_verification_admission_uses_bounded_qdev_ci_profile() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert (
        "belilovsky/qdev-runner-control-plane",
        "qdev-ci",
    ) not in policy.repository_profile_disk_mb
    assert policy.profiles["qdev-ci"].disk_mb == 4 * 1024


def test_platform_portal_contract_admission_uses_bounded_qdev_ci_profile() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert ("belilovsky/platform-portal", "qdev-ci") not in policy.repository_profile_disk_mb
    assert policy.profiles["qdev-ci"].disk_mb == 4 * 1024


def test_qazcompute_docker_admission_is_repository_scoped() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert (
        policy.repository_profile_disk_mb[("belilovsky/qazcompute", "qdev-ci-docker")] == 18 * 1024
    )
    assert policy.profiles["qdev-ci-docker"].disk_mb == 20 * 1024


def test_mcp_servers_docker_admission_is_repository_scoped() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert (
        policy.repository_profile_disk_mb[("belilovsky/mcp-servers", "qdev-ci-docker")] == 12 * 1024
    )
    assert policy.profiles["qdev-ci-docker"].disk_mb == 20 * 1024


def test_adilet_digest_docker_admission_matches_its_source_manifest() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert (
        policy.repository_profile_disk_mb[("belilovsky/adilet-digest-studio", "qdev-ci-docker")]
        == 12 * 1024
    )
    assert policy.profiles["qdev-ci-docker"].disk_mb == 20 * 1024


def test_qgeo_recovery_admission_preserves_absolute_capacity_constraints() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert policy.repository_profile_disk_mb[("belilovsky/qazgeo", "qdev-ci-docker")] == 15 * 1024
    assert policy.profiles["qdev-ci-docker"].disk_mb == 20 * 1024
    assert policy.repository_min_disk_free_gib["belilovsky/qazgeo"] == 35
    assert policy.repository_max_concurrency["belilovsky/qazgeo"] == 1


def test_qazvision_docker_admission_matches_measured_bounded_build() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert (
        policy.repository_profile_disk_mb[("belilovsky/tokaev-module", "qdev-ci-docker")]
        == 8 * 1024
    )
    assert policy.profiles["qdev-ci-docker"].disk_mb == 20 * 1024
