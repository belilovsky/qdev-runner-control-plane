from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qdev_runner.runner_image_publisher import (
    ImageInput,
    canonical_json,
    count_findings,
    initialize_key,
    load_private_key,
    load_remediation_receipt,
    publish,
    sha256_file,
)
from qdev_runner.runner_image_release import RunnerImageReleaseError, verify_evidence


def test_scoped_publisher_signs_scope_and_rejects_tampering(tmp_path: Path) -> None:
    repo = tmp_path / "repo"
    (repo / "images/runner").mkdir(parents=True)
    (repo / "images/runner/Dockerfile").write_text("FROM scratch\n")
    private_key, public_key = tmp_path / "private.pem", tmp_path / "public.pem"
    initialize_key(private_key, public_key)

    def fake_runner(command: object) -> subprocess.CompletedProcess[str]:
        assert isinstance(command, list)
        if command[0] == "git":
            output = "a" * 40 if "rev-parse" in command else ""
        elif command[1] == "--version":
            output = "Version: 0.74.0\n"
        else:
            Path(command[command.index("--output") + 1]).write_text('{"Results": []}\n')
            output = ""
        return subprocess.CompletedProcess(command, 0, output, "")

    value = publish(
        repo=repo,
        revision="a" * 40,
        images=[
            ImageInput(
                "QDEV_RUNNER_IMAGE",
                "general",
                "registry.example/runner@sha256:" + "b" * 64,
                "images/runner/Dockerfile",
            )
        ],
        profiles=["qdev-ci"],
        evidence_root=tmp_path / "evidence",
        manifest_path=tmp_path / "manifest.json",
        private_key_path=private_key,
        public_key_path=public_key,
        source_ci_run="https://github.com/example/actions/runs/1",
        source_ci_status="passed",
        runner=fake_runner,
    )
    assert value["profiles"] == ["qdev-ci"]
    verify_evidence(value)
    value.pop("profiles")
    with pytest.raises(RunnerImageReleaseError, match="missing required"):
        verify_evidence(value)
    value["profiles"] = ["qdev-ci"]
    provenance = tmp_path / "evidence/general.provenance.json"
    signed = json.loads(provenance.read_text())
    assert signed["source_binding"]["profiles"] == ["qdev-ci"]
    signed["source_binding"].pop("profiles")
    provenance.write_bytes(canonical_json(signed))
    value["artifacts"][0]["provenance_digest"] = sha256_file(provenance)
    with pytest.raises(RunnerImageReleaseError, match="profile scope mismatch"):
        verify_evidence(value)


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
    fixture_now = datetime.now(UTC).replace(microsecond=0)
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
                    "reviewed_at": (
                        (fixture_now - timedelta(days=1)).isoformat().replace("+00:00", "Z")
                    ),
                    "review_by": (
                        (fixture_now + timedelta(days=29)).isoformat().replace("+00:00", "Z")
                    ),
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
