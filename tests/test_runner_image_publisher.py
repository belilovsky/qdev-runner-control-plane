from __future__ import annotations

import json
from pathlib import Path

import pytest

from qdev_runner.runner_image_publisher import (
    count_findings,
    initialize_key,
    load_private_key,
    load_remediation_receipt,
)
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


def test_remediation_receipt_is_bound_to_exact_image_and_findings(tmp_path: Path) -> None:
    reference = "registry.example/runner@sha256:" + "a" * 64
    receipt = tmp_path / "receipt.json"
    receipt.write_text(
        json.dumps(
            {
                "schema": "qdev-runner-remediation-v1",
                "image_reference": reference,
                "findings": {"critical": 0, "high": 82},
                "decision": {
                    "status": "accepted",
                    "decision_id": "runner-buildkit-20260905",
                    "owner": "QDev owner/operator",
                    "reviewed_at": "2026-09-04T00:00:00Z",
                    "review_by": "2026-10-04T00:00:00Z",
                    "reason": "No fixed upstream BuildKit release is available.",
                    "compensating_controls": ["Disposable isolated Docker sidecar"],
                },
            }
        )
        + "\n",
        encoding="utf-8",
    )

    assert (
        load_remediation_receipt(receipt, image_reference=reference, critical=0, high=82)["schema"]
        == "qdev-runner-remediation-v1"
    )
    with pytest.raises(RunnerImageReleaseError, match="finding counts mismatch"):
        load_remediation_receipt(receipt, image_reference=reference, critical=0, high=81)
