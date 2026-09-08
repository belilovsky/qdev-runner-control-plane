from __future__ import annotations

import hashlib
import json
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from qdev_runner import controller_activation_assets as assets
from qdev_runner.controller_activation import ControllerTuple
from qdev_runner.controller_recovery_artifact import candidate_config_digest

CURRENT_SHA = "1" * 40
CANDIDATE_SHA = "2" * 40
CURRENT_PUBLIC_IMAGE = "3" * 64
CURRENT_INTERNAL_IMAGE = "4" * 64
CANDIDATE_IMAGE = "5" * 64
CANDIDATE_POLICY = "6" * 64
RELEASE_DIGEST = "7" * 64
ENTRYPOINT_DIGEST = "8" * 64
NOW = datetime(2026, 9, 8, 8, 0, tzinfo=UTC)


def _config_root(root: Path) -> tuple[Path, dict[str, Path]]:
    files = {
        "repos.json": root / "inventory/repos.json",
        "profiles.yml": root / "config/profiles.yml",
        "release-lanes.yml": root / "config/release-lanes.yml",
        "managed-registry.yml": root / "config/managed-registry.yml",
        "fleet-bootstrap.yml": root / "config/fleet-bootstrap.yml",
        "managed-release-ledger.yml": root / "config/managed-release-ledger.yml",
    }
    for name, path in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{name}: exact-current-input\\n", encoding="utf-8")
        path.chmod(0o600)
    return root, files


def _measured_status() -> dict[str, object]:
    return {
        "schema": "qdev-controller-release-status-v2",
        "state": "active",
        "revision": CURRENT_SHA,
        "release_digest": "sha256:" + "9" * 64,
        "activated_at": "2026-09-08T07:45:00Z",
        "runtime_identity": {
            "source_revision": CURRENT_SHA,
            "source_digest": "sha256:" + "a" * 64,
            "public_image_id": "sha256:" + CURRENT_PUBLIC_IMAGE,
            "internal_image_id": "sha256:" + CURRENT_INTERNAL_IMAGE,
        },
        "dependency_identity": {
            "requirements_digest": "sha256:" + "b" * 64,
            "public_installed_digest": "sha256:" + "c" * 64,
            "internal_installed_digest": "sha256:" + "c" * 64,
        },
    }


def _artifact(*, manifest_digest: str = "d" * 64) -> SimpleNamespace:
    return SimpleNamespace(
        source_sha=CANDIDATE_SHA,
        image_digest=CANDIDATE_IMAGE,
        policy_bundle_digest=CANDIDATE_POLICY,
        entrypoint_reconciliation_digest=ENTRYPOINT_DIGEST,
        manifest_digest=manifest_digest,
        workflow_identity={
            "run_id": 341,
            "job_id": 957,
            "attempt": 1,
            "expires_at": "2026-09-08T08:02:00Z",
        },
    )


def test_snapshot_current_material_is_private_and_transaction_scoped(tmp_path: Path) -> None:
    _, files = _config_root(tmp_path / "current")
    status = tmp_path / "status.json"
    status.write_text(json.dumps(_measured_status()), encoding="utf-8")
    status.chmod(0o600)
    snapshots = tmp_path / "assets" / "snapshots"
    snapshots.parent.mkdir(mode=0o700)
    snapshots.mkdir(mode=0o700)

    snapshot_status, snapshot_config = assets.snapshot_current_material(
        status_path=status,
        current_config_files=files,
        snapshot_root=snapshots,
        transaction_id="assets-snapshot-0001",
        require_root_owner=False,
    )

    assert snapshot_status.read_bytes() == status.read_bytes()
    assert (snapshot_config / "inventory/repos.json").read_bytes() == files[
        "repos.json"
    ].read_bytes()
    assert stat.S_IMODE(snapshot_status.stat().st_mode) == 0o600
    assert stat.S_IMODE(snapshot_config.stat().st_mode) == 0o700
    with pytest.raises(assets.ControllerActivationAssetsError, match="already exists"):
        assets.snapshot_current_material(
            status_path=status,
            current_config_files=files,
            snapshot_root=snapshots,
            transaction_id="assets-snapshot-0001",
            require_root_owner=False,
        )


def test_issue_binds_generation_zero_to_status_and_config_captured_at_issue(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    current_root, _ = _config_root(tmp_path / "current")
    current_config_digest = candidate_config_digest(current_root)
    status = tmp_path / "measured-status.json"
    status.write_text(json.dumps(_measured_status()), encoding="utf-8")
    status.chmod(0o600)

    monkeypatch.setattr(
        assets, "verify_controller_artifact_manifest", lambda *args, **kwargs: _artifact()
    )
    monkeypatch.setattr(
        assets, "controller_release_digest", lambda *args: "sha256:" + RELEASE_DIGEST
    )
    monkeypatch.setattr(
        assets,
        "candidate_config_digest",
        lambda root: current_config_digest if root == current_root else CANDIDATE_POLICY,
    )
    monkeypatch.setattr(
        assets, "fingerprint_release_tree", lambda *args, **kwargs: ENTRYPOINT_DIGEST
    )

    unsigned = assets.issue_unsigned_activation_envelope(
        release_root=tmp_path / "candidate-release",
        source_sha=CANDIDATE_SHA,
        artifact_manifest=tmp_path / "controller-artifact-manifest.json",
        current_status_path=status,
        current_config_root=current_root,
        transaction_id="assets-issue-0001",
        ttl_seconds=600,
        now=NOW,
        require_root_owner=False,
    )

    assert unsigned["expected_generation"] == 0
    assert (
        unsigned["expected_current"]
        == ControllerTuple(
            CURRENT_SHA,
            CURRENT_PUBLIC_IMAGE,
            current_config_digest,
            CURRENT_INTERNAL_IMAGE,
        ).mapping()
    )
    assert unsigned["expected_current_config_digest"] == current_config_digest
    assert unsigned["candidate_config_digest"] == CANDIDATE_POLICY
    assert unsigned["expires_at"] == "2026-09-08T08:02:00Z"


def _artifact_manifest(directory: Path) -> tuple[Path, str]:
    descriptors: dict[str, dict[str, object]] = {}
    for field, name in (
        ("image_archive", "controller-image.tar"),
        ("sbom", "controller-sbom.spdx.json"),
        ("security_scans", "controller-security-scans.json"),
        ("source_scan", "controller-source-trivy.json"),
        ("image_scan", "controller-image-trivy.json"),
        ("provenance", "controller-provenance.json"),
    ):
        payload = f"{field} bytes".encode()
        (directory / name).write_bytes(payload)
        (directory / name).chmod(0o600)
        descriptors[field] = {
            "path": name,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }
    path = directory / "controller-artifact-manifest.json"
    path.write_bytes(json.dumps(descriptors, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    path.chmod(0o600)
    return path, hashlib.sha256(path.read_bytes()).hexdigest()


def test_stage_publishes_verified_members_before_no_overwrite_envelope(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    artifact_manifest, manifest_digest = _artifact_manifest(tmp_path)
    signed = tmp_path / "signed.json"
    signed.write_text("{}", encoding="utf-8")
    signed.chmod(0o600)
    envelope_digest = hashlib.sha256(b"{}").hexdigest()
    envelope = SimpleNamespace(
        transaction_id="assets-stage-0001",
        candidate=ControllerTuple(CANDIDATE_SHA, CANDIDATE_IMAGE, CANDIDATE_POLICY),
        artifact_manifest_digest=manifest_digest,
        candidate_release_digest=RELEASE_DIGEST,
        candidate_config_digest=CANDIDATE_POLICY,
        entrypoint_reconciliation_digest=ENTRYPOINT_DIGEST,
        digest=envelope_digest,
    )
    monkeypatch.setattr(assets, "_verify_trust_binding", lambda **kwargs: object())
    monkeypatch.setattr(assets, "load_and_verify_envelope", lambda *args, **kwargs: envelope)
    monkeypatch.setattr(
        assets,
        "verify_controller_artifact_manifest",
        lambda *args, **kwargs: _artifact(manifest_digest=manifest_digest),
    )
    monkeypatch.setattr(
        assets, "controller_release_digest", lambda *args: "sha256:" + RELEASE_DIGEST
    )
    monkeypatch.setattr(assets, "candidate_config_digest", lambda *args: CANDIDATE_POLICY)
    monkeypatch.setattr(
        assets, "fingerprint_release_tree", lambda *args, **kwargs: ENTRYPOINT_DIGEST
    )

    assets_root = tmp_path / "assets"
    assets_root.mkdir(mode=0o700)
    receipt = assets.stage_activation_assets(
        release_root=tmp_path / "candidate-release",
        source_sha=CANDIDATE_SHA,
        artifact_manifest=artifact_manifest,
        signed_envelope=signed,
        assets_root=assets_root,
        activation_public_key=tmp_path / "activation.pub",
        admission_public_key=tmp_path / "admission.pub",
        trust_binding=tmp_path / "binding.json",
        now=NOW + timedelta(minutes=1),
        require_root_owner=False,
    )

    manifest_target = assets_root / "artifacts" / f"{manifest_digest}.json"
    envelope_target = assets_root / "envelopes" / f"{envelope_digest}.json"
    assert receipt["status"] == "staged"
    assert receipt["activation_envelope_digest"] == "sha256:" + envelope_digest
    assert receipt["workflow_run_id"] == 341
    assert receipt["workflow_job_id"] == 957
    assert receipt["workflow_attempt"] == 1
    assert manifest_target.read_bytes() == artifact_manifest.read_bytes()
    assert envelope_target.read_bytes() == b"{}\n"
    assert stat.S_IMODE(manifest_target.stat().st_mode) == 0o600
    assert stat.S_IMODE(envelope_target.stat().st_mode) == 0o600

    image_target = assets_root / "artifacts" / "controller-image.tar"
    image_target.write_bytes(b"tampered")
    image_target.chmod(0o600)
    with pytest.raises(assets.ControllerActivationAssetsError, match="refusing to replace"):
        assets.stage_activation_assets(
            release_root=tmp_path / "candidate-release",
            source_sha=CANDIDATE_SHA,
            artifact_manifest=artifact_manifest,
            signed_envelope=signed,
            assets_root=assets_root,
            activation_public_key=tmp_path / "activation.pub",
            admission_public_key=tmp_path / "admission.pub",
            trust_binding=tmp_path / "binding.json",
            now=NOW + timedelta(minutes=1),
            require_root_owner=False,
        )
