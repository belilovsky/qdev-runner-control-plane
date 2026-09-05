from pathlib import Path

from qdev_runner.policy import Policy


def test_qazposter_contract_admission_is_repository_scoped() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert policy.repository_profile_disk_mb[
        ("belilovsky/qazposter", "qdev-ci")
    ] == 4 * 1024
    assert policy.profiles["qdev-ci"].disk_mb == 12 * 1024


def test_controller_verification_admission_is_repository_scoped() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert policy.repository_profile_disk_mb[
        ("belilovsky/qdev-runner-control-plane", "qdev-ci")
    ] == 4 * 1024
    assert policy.profiles["qdev-ci"].disk_mb == 12 * 1024


def test_platform_portal_contract_admission_is_repository_scoped() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert policy.repository_profile_disk_mb[
        ("belilovsky/platform-portal", "qdev-ci")
    ] == 4 * 1024
    assert policy.profiles["qdev-ci"].disk_mb == 12 * 1024


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


def test_qazgeo_docker_admission_matches_measured_candidate() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert policy.repository_profile_disk_mb[
        ("belilovsky/qazgeo", "qdev-ci-docker")
    ] == 4 * 1024
    assert policy.profiles["qdev-ci-docker"].disk_mb == 20 * 1024
