from __future__ import annotations

import hashlib
import io
import json
import tarfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qdev_runner.controller_activation import ControllerReleaseStatus, ControllerTuple
from qdev_runner.controller_recovery_artifact import (
    ControllerRecoveryArtifactError,
    candidate_config_digest,
    inspect_docker_archive,
    reconcile_workflow_identity,
    verify_current_snapshot,
    verify_recovery_claim_receipt,
)
from qdev_runner.operations import payload_digest, sign_payload

SOURCE_SHA = "1" * 40
IMAGE_DIGEST = "2" * 64
POLICY_DIGEST = "3" * 64
NOW = datetime(2026, 9, 6, 8, 0, tzinfo=UTC)
RECEIPT_KEY = "controller-recovery-test-receipt-key"


def _claim_receipt(*, now: datetime = NOW) -> dict[str, object]:
    job = {
        "repository": "belilovsky/qdev-runner-control-plane",
        "run_id": 101,
        "job_id": 202,
        "attempt": 1,
        "exact_sha": SOURCE_SHA,
        "profile": "qdev-ci",
    }
    scope = {
        "schema": "claim-scope-v2",
        "scope_id": "controller-recovery-scope",
        "worker_name": "qdev-controller-recovery",
        "tier": "recovery",
        "expires_at": (now + timedelta(minutes=10)).isoformat(),
        "worker_certificate_sha256": "a" * 64,
        "host": "recovery-build-host",
        "runner": "qdev-job-101-1-smoke",
        "correlation_id": "controller-recovery-correlation",
        "fifo_exception": False,
        "jobs": [job],
        "fifo_skipped": [],
    }
    payload: dict[str, object] = {
        "kind": "fifo-claim-scope-issued",
        "operator_session": "verified",
        "mtls_identity": "qdev-fleet-operations",
        "idempotent": True,
        "claim_scope": scope,
        "immutable_tuple": {
            **job,
            "runner": "qdev-job-101-1-smoke",
            "host": "recovery-build-host",
        },
        "fifo_skipped": [],
        "worker": {},
        "managed_registry_entry": None,
        "admission_ledger": "admin-platform",
        "admin_platform_ledger_entry": "controller",
        "managed_release_ledger_entry": None,
    }
    digest = payload_digest(payload)
    unsigned: dict[str, object] = {
        "schema": "qdev-controller-receipt-v2",
        "receipt_id": digest,
        "payload": payload,
        "digest": digest,
        "enforcement": "enforced",
    }
    return {**unsigned, "signature": sign_payload(unsigned, RECEIPT_KEY)}


def _add_tar_bytes(bundle: tarfile.TarFile, name: str, raw: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(raw)
    member.mode = 0o644
    bundle.addfile(member, io.BytesIO(raw))


def _archive(path: Path, *, source_sha: str = SOURCE_SHA, unsafe: bool = False) -> str:
    config = json.dumps(
        {
            "config": {
                "Labels": {
                    "org.opencontainers.image.revision": source_sha,
                    "run.qdev.controller.policy-bundle-digest": POLICY_DIGEST,
                }
            }
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    config_digest = hashlib.sha256(config).hexdigest()
    manifest = json.dumps(
        [{"Config": f"{config_digest}.json", "RepoTags": [], "Layers": ["layer.tar"]}],
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    with tarfile.open(path, "w") as bundle:
        _add_tar_bytes(bundle, "manifest.json", manifest)
        _add_tar_bytes(bundle, f"{config_digest}.json", config)
        _add_tar_bytes(bundle, "layer.tar", b"layer")
        if unsafe:
            _add_tar_bytes(bundle, "../escape", b"unsafe")
    return config_digest


def _workflow() -> tuple[dict[str, object], dict[str, object]]:
    run: dict[str, object] = {
        "id": 101,
        "run_attempt": 1,
        "event": "workflow_dispatch",
        "head_sha": SOURCE_SHA,
        "head_branch": "codex/controller-recovery",
        "conclusion": "success",
        "path": ".github/workflows/runner-smoke.yml",
        "repository": {"full_name": "belilovsky/qdev-runner-control-plane"},
    }
    job: dict[str, object] = {
        "id": 202,
        "run_id": 101,
        "run_attempt": 1,
        "head_sha": SOURCE_SHA,
        "name": "runner-smoke",
        "conclusion": "success",
        "labels": [
            "self-hosted",
            "Linux",
            "X64",
            "qdev-ci",
            "qdev-job-101-1-smoke",
        ],
    }
    return run, job


def _config_root(tmp_path: Path) -> Path:
    root = tmp_path / "current"
    for relative in (
        "inventory/repos.json",
        "config/profiles.yml",
        "config/release-lanes.yml",
        "config/managed-registry.yml",
        "config/fleet-bootstrap.yml",
        "config/managed-release-ledger.yml",
    ):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{relative}\n", encoding="utf-8")
    return root


def test_inspect_docker_archive_binds_labels_and_rejects_traversal(tmp_path: Path) -> None:
    archive = tmp_path / "controller.tar"
    expected = _archive(archive)
    digest, size = inspect_docker_archive(
        archive,
        expected_source_sha=SOURCE_SHA,
        expected_policy_digest=POLICY_DIGEST,
    )
    assert digest == expected
    assert size > 0

    bad = tmp_path / "unsafe.tar"
    _archive(bad, unsafe=True)
    with pytest.raises(ControllerRecoveryArtifactError, match="unsafe"):
        inspect_docker_archive(
            bad,
            expected_source_sha=SOURCE_SHA,
            expected_policy_digest=POLICY_DIGEST,
        )


def test_reconcile_workflow_identity_requires_exact_provider_job() -> None:
    run, job = _workflow()
    identity = reconcile_workflow_identity(
        run,
        job,
        source_sha=SOURCE_SHA,
        run_id=101,
        job_id=202,
        attempt=1,
        admission_nonce="recovery-nonce-0001",
        idempotency_key="recovery-artifact-0001",
        now=NOW,
    )
    assert identity["expected_sha"] == SOURCE_SHA
    assert identity["expires_at"] == "2026-09-06T08:15:00Z"

    forged = dict(job)
    forged["labels"] = [*job["labels"], "foreign"]  # type: ignore[index]
    with pytest.raises(ControllerRecoveryArtifactError, match="not exact"):
        reconcile_workflow_identity(
            run,
            forged,
            source_sha=SOURCE_SHA,
            run_id=101,
            job_id=202,
            attempt=1,
            admission_nonce="recovery-nonce-0001",
            idempotency_key="recovery-artifact-0001",
            now=NOW,
        )


def test_recovery_claim_receipt_binds_controller_signature_and_exact_job() -> None:
    receipt = _claim_receipt()
    nonce = verify_recovery_claim_receipt(
        receipt,
        receipt_key=RECEIPT_KEY,
        source_sha=SOURCE_SHA,
        run_id=101,
        job_id=202,
        attempt=1,
        now=NOW,
    )
    assert nonce == f"controller-claim:{receipt['receipt_id']}"

    forged = dict(receipt)
    forged["signature"] = "0" * 64
    with pytest.raises(ControllerRecoveryArtifactError, match="receipt is invalid"):
        verify_recovery_claim_receipt(
            forged,
            receipt_key=RECEIPT_KEY,
            source_sha=SOURCE_SHA,
            run_id=101,
            job_id=202,
            attempt=1,
            now=NOW,
        )

    with pytest.raises(ControllerRecoveryArtifactError, match="not exact"):
        verify_recovery_claim_receipt(
            receipt,
            receipt_key=RECEIPT_KEY,
            source_sha=SOURCE_SHA,
            run_id=101,
            job_id=999,
            attempt=1,
            now=NOW,
        )


def test_signer_binds_mature_current_status_and_config_snapshot(tmp_path: Path) -> None:
    config_root = _config_root(tmp_path)
    config_digest = candidate_config_digest(config_root)
    current = ControllerTuple(SOURCE_SHA, IMAGE_DIGEST, POLICY_DIGEST, "4" * 64)
    status = ControllerReleaseStatus(
        generation=9,
        current=current,
        previous=None,
        transaction_id="prior-transaction-0001",
        activated_at=NOW,
    )
    status_path = tmp_path / "status.json"
    raw = json.dumps(status.mapping(), sort_keys=True, separators=(",", ":")).encode() + b"\n"
    status_path.write_bytes(raw)
    unsigned: dict[str, object] = {
        "transaction_id": "next-transaction-0001",
        "expected_generation": 9,
        "expected_current": current.mapping(),
        "expected_current_status_digest": hashlib.sha256(raw).hexdigest(),
        "expected_current_config_digest": config_digest,
    }
    verify_current_snapshot(
        unsigned,
        current_status_path=status_path,
        current_config_root=config_root,
    )

    unsigned["expected_generation"] = 8
    with pytest.raises(ControllerRecoveryArtifactError, match="does not match"):
        verify_current_snapshot(
            unsigned,
            current_status_path=status_path,
            current_config_root=config_root,
        )


def test_signer_binds_generation_zero_measured_status(tmp_path: Path) -> None:
    config_root = _config_root(tmp_path)
    config_digest = candidate_config_digest(config_root)
    current = ControllerTuple(SOURCE_SHA, IMAGE_DIGEST, POLICY_DIGEST, "4" * 64)
    measured = {
        "schema": "qdev-controller-release-status-v2",
        "state": "active",
        "revision": SOURCE_SHA,
        "release_digest": f"sha256:{'5' * 64}",
        "activated_at": "2026-09-06T08:00:00Z",
        "runtime_identity": {
            "source_revision": SOURCE_SHA,
            "source_digest": f"sha256:{'6' * 64}",
            "public_image_id": f"sha256:{IMAGE_DIGEST}",
            "internal_image_id": f"sha256:{'4' * 64}",
        },
        "dependency_identity": {
            "requirements_digest": f"sha256:{'7' * 64}",
            "public_installed_digest": f"sha256:{'8' * 64}",
            "internal_installed_digest": f"sha256:{'8' * 64}",
        },
    }
    status_path = tmp_path / "measured.json"
    status_path.write_text(json.dumps(measured), encoding="utf-8")
    initialized = ControllerReleaseStatus(
        generation=0,
        current=current,
        previous=None,
        transaction_id="bootstrap:recovery-transaction-0001",
        activated_at=NOW,
    )
    initialized_raw = (
        json.dumps(initialized.mapping(), sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    unsigned: dict[str, object] = {
        "transaction_id": "recovery-transaction-0001",
        "expected_generation": 0,
        "expected_current": current.mapping(),
        "expected_current_status_digest": hashlib.sha256(initialized_raw).hexdigest(),
        "expected_current_config_digest": config_digest,
    }
    verify_current_snapshot(
        unsigned,
        current_status_path=status_path,
        current_config_root=config_root,
    )
