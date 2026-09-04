from __future__ import annotations

from pathlib import Path

import pytest

from qdev_runner.runner_image_publisher import count_findings, initialize_key, load_private_key
from qdev_runner.runner_image_release import RunnerImageReleaseError


def test_signing_key_initialization_is_private_and_refuses_overwrite(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"

    initialize_key(private_key, public_key)

    assert private_key.stat().st_mode & 0o777 == 0o600
    assert public_key.stat().st_mode & 0o777 == 0o644
    assert load_private_key(private_key).public_key() is not None
    with pytest.raises(RunnerImageReleaseError, match="already exists"):
        initialize_key(private_key, public_key)


def test_private_signing_key_rejects_group_or_world_permissions(tmp_path: Path) -> None:
    private_key = tmp_path / "private.pem"
    public_key = tmp_path / "public.pem"
    initialize_key(private_key, public_key)
    private_key.chmod(0o640)

    with pytest.raises(RunnerImageReleaseError, match="permissions"):
        load_private_key(private_key)


def test_security_finding_count_covers_all_trivy_result_types() -> None:
    report = {
        "Results": [
            {
                "Vulnerabilities": [{"Severity": "CRITICAL"}, {"Severity": "LOW"}],
                "Secrets": [{"Severity": "HIGH"}],
                "Misconfigurations": [{"Severity": "HIGH"}],
            }
        ]
    }

    assert count_findings(report) == (1, 2)
