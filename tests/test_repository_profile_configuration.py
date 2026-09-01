from pathlib import Path

from qdev_runner.policy import Policy


def test_qazcompute_docker_admission_is_repository_scoped() -> None:
    root = Path(__file__).resolve().parents[1]
    policy = Policy(root / "inventory/repos.json", root / "config/profiles.yml")

    assert policy.repository_profile_disk_mb[
        ("belilovsky/qazcompute", "qdev-ci-docker")
    ] == 18 * 1024
    assert policy.profiles["qdev-ci-docker"].disk_mb == 20 * 1024
