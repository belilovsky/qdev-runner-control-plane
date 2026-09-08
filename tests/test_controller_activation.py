from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qdev_runner.controller_activation import (
    ARTIFACT_MANIFEST_SCHEMA,
    ARTIFACT_PROVENANCE_SCHEMA,
    CONTROLLER_REPOSITORY,
    ENVELOPE_SCHEMA,
    LEGACY_STATUS_SCHEMA,
    STATUS_SCHEMA,
    ActivationEnvelope,
    ActivationStateStore,
    ControllerActivationError,
    ControllerReleaseStatus,
    ControllerTuple,
    LegacyMeasuredControllerReleaseStatus,
    MeasuredControllerReleaseStatus,
    _trivy_actionable_findings,
    fingerprint_config_files,
    fingerprint_release_tree,
    verify_controller_artifact_manifest,
)
from qdev_runner.operations import payload_digest, sign_payload

PRIVATE_KEY = Ed25519PrivateKey.generate()
PUBLIC_KEY = PRIVATE_KEY.public_key()
OLD = ControllerTuple("1" * 40, "2" * 64, "3" * 64)
NEW = ControllerTuple("4" * 40, "5" * 64, "6" * 64)
OLD_CONFIG = "7" * 64
NEW_CONFIG = "8" * 64
ARTIFACT_MANIFEST = "9" * 64
ENTRYPOINT_RECONCILIATION = "a" * 64
CANDIDATE_RELEASE_DIGEST = "b" * 64
ROOT = Path(__file__).resolve().parents[1]
RECEIPT_KEY = "controller-activation-test-receipt-key"

_CLI_HARNESS = """
import importlib.util
import os
import sys
from pathlib import Path

import qdev_runner.controller_activation as core

original_read = core._read_regular_bytes

def read_test_fixture(path, *, description, require_root_owner, mode_mask=0o022):
    return original_read(
        path,
        description=description,
        require_root_owner=False,
        mode_mask=mode_mask,
    )

core._read_regular_bytes = read_test_fixture
script_path = Path(os.environ["QDEV_ACTIVATION_SCRIPT"])
spec = importlib.util.spec_from_file_location("controller_activation_cli", script_path)
if spec is None or spec.loader is None:
    raise RuntimeError("controller activation CLI could not be loaded")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
module._require_root_owned_state = lambda *args, **kwargs: None
module._require_safe_regular = lambda *args, **kwargs: None
sys.argv = [str(script_path), *sys.argv[1:]]
raise SystemExit(module.main())
"""


def _sign(payload: dict[str, object]) -> dict[str, object]:
    canonical = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    signature = base64.urlsafe_b64encode(PRIVATE_KEY.sign(canonical)).rstrip(b"=").decode("ascii")
    return {**payload, "signature": signature}


def _status(*, generation: int = 7) -> ControllerReleaseStatus:
    return ControllerReleaseStatus(
        generation=generation,
        current=OLD,
        previous=None,
        transaction_id="bootstrap-transaction",
        activated_at=datetime(2026, 9, 5, tzinfo=UTC),
    )


def _encoded_status(*, generation: int = 7) -> bytes:
    return (
        json.dumps(
            _status(generation=generation).mapping(),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def _status_digest(*, generation: int = 7) -> str:
    return hashlib.sha256(_encoded_status(generation=generation)).hexdigest()


def _measured_status(
    controller: ControllerTuple,
    *,
    release_digest: str = "b" * 64,
    activated_at: str = "2026-09-05T01:00:00Z",
) -> dict[str, object]:
    return {
        "schema": "qdev-controller-release-status-v2",
        "state": "active",
        "revision": controller.source_sha,
        "release_digest": f"sha256:{release_digest}",
        "activated_at": activated_at,
        "runtime_identity": {
            "source_revision": controller.source_sha,
            "source_digest": "sha256:" + "c" * 64,
            "public_image_id": f"sha256:{controller.image_digest}",
            "internal_image_id": f"sha256:{controller.image_digest}",
        },
        "dependency_identity": {
            "requirements_digest": "sha256:" + "d" * 64,
            "public_installed_digest": "sha256:" + "e" * 64,
            "internal_installed_digest": "sha256:" + "e" * 64,
        },
    }


def _envelope_document(
    *,
    transaction_id: str = "transaction-0001",
    now: datetime | None = None,
    expected_generation: int = 7,
    expected: ControllerTuple = OLD,
    candidate: ControllerTuple = NEW,
    expected_status_digest: str | None = None,
    expected_config_digest: str = OLD_CONFIG,
    candidate_config_digest: str = NEW_CONFIG,
) -> dict[str, object]:
    issued_at = now or datetime(2026, 9, 5, 1, tzinfo=UTC)
    return _sign(
        {
            "schema": ENVELOPE_SCHEMA,
            "transaction_id": transaction_id,
            "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
            "expires_at": (issued_at + timedelta(minutes=15)).isoformat().replace("+00:00", "Z"),
            "expected_generation": expected_generation,
            "expected_current": expected.mapping(),
            "expected_current_status_digest": expected_status_digest
            or _status_digest(generation=expected_generation),
            "expected_current_config_digest": expected_config_digest,
            "candidate": candidate.mapping(),
            "candidate_release_digest": CANDIDATE_RELEASE_DIGEST,
            "candidate_config_digest": candidate_config_digest,
            "artifact_manifest_digest": ARTIFACT_MANIFEST,
            "entrypoint_reconciliation_digest": ENTRYPOINT_RECONCILIATION,
        }
    )


def _envelope(**overrides: object) -> ActivationEnvelope:
    now = overrides.pop("now", datetime(2026, 9, 5, 1, 1, tzinfo=UTC))
    document = _envelope_document(**overrides)
    assert isinstance(now, datetime)
    return ActivationEnvelope.verify(document, public_key=PUBLIC_KEY, now=now)


def _store(tmp_path: Path, *, generation: int = 7) -> ActivationStateStore:
    path = tmp_path / "controller-release.json"
    path.write_bytes(_encoded_status(generation=generation))
    return ActivationStateStore(path)


def _run_activation_cli(
    *,
    status: Path,
    envelope: Path,
    public_key: Path,
    command: str,
    observations: tuple[str, str] | None = None,
    rollback_config: str | None = None,
    extra_arguments: tuple[str, ...] = (),
) -> subprocess.CompletedProcess[str]:
    arguments = [
        sys.executable,
        "-c",
        _CLI_HARNESS,
        command,
        "--status",
        str(status),
        "--envelope",
        str(envelope),
        "--key",
        str(public_key),
        "--candidate-source",
        NEW.source_sha,
        "--candidate-image",
        NEW.image_digest,
        "--candidate-policy",
        NEW.policy_bundle_digest,
        "--candidate-release-digest",
        CANDIDATE_RELEASE_DIGEST,
        "--candidate-config-digest",
        NEW_CONFIG,
        "--artifact-manifest-digest",
        ARTIFACT_MANIFEST,
        "--entrypoint-reconciliation-digest",
        ENTRYPOINT_RECONCILIATION,
    ]
    if observations is not None:
        arguments.extend(
            [
                "--observed-current-image",
                observations[0],
                "--observed-current-config",
                observations[1],
            ]
        )
    if rollback_config is not None:
        arguments.extend(["--rollback-config", rollback_config])
    arguments.extend(extra_arguments)
    environment = {
        **os.environ,
        "PYTHONPATH": str(ROOT / "src"),
        "QDEV_ACTIVATION_SCRIPT": str(ROOT / "scripts" / "controller_activation.py"),
    }
    return subprocess.run(  # noqa: S603 - exact interpreter and repository script fixture
        arguments,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        check=False,
    )


def test_valid_envelope_cli_recovers_every_durable_crash_state(tmp_path: Path) -> None:
    status = tmp_path / "controller-release.json"
    status.write_bytes(_encoded_status())
    envelope = tmp_path / "activation-envelope.json"
    envelope.write_text(
        json.dumps(
            _envelope_document(now=datetime.now(UTC)),
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    public_key = tmp_path / "activation-public-key.pem"
    public_key.write_bytes(
        PUBLIC_KEY.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    reserve = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="reserve",
        observations=(OLD.image_digest, OLD_CONFIG),
    )
    assert reserve.returncode == 0, reserve.stderr
    assert status.with_suffix(".json.transaction").is_file()

    config_installed = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="verify-recovery-envelope",
        observations=(OLD.image_digest, NEW_CONFIG),
    )
    assert config_installed.returncode == 0, config_installed.stderr
    assert json.loads(config_installed.stdout)["recovery_state"] == "pending-config-installed"

    config_transition = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="verify-recovery-envelope",
        observations=(OLD.image_digest, "c" * 64),
        extra_arguments=("--allow-config-transition",),
    )
    assert config_transition.returncode == 0, config_transition.stderr
    assert json.loads(config_transition.stdout)["recovery_state"] == "pending-mutating"

    candidate_active = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="verify-recovery-envelope",
        observations=(NEW.image_digest, NEW_CONFIG),
    )
    assert candidate_active.returncode == 0, candidate_active.stderr
    assert json.loads(candidate_active.stdout)["recovery_state"] == "pending-candidate-active"

    commit = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="commit",
        observations=(NEW.image_digest, NEW_CONFIG),
    )
    assert commit.returncode == 0, commit.stderr

    committed_healthy = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="verify-recovery-envelope",
        observations=(NEW.image_digest, NEW_CONFIG),
    )
    assert committed_healthy.returncode == 0, committed_healthy.stderr
    assert json.loads(committed_healthy.stdout)["recovery_state"] == "committed"

    committed_foreign_runtime = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="verify-recovery-envelope",
        observations=(OLD.image_digest, OLD_CONFIG),
    )
    assert committed_foreign_runtime.returncode == 78
    assert "runtime does not match committed" in committed_foreign_runtime.stderr


def _recovery_claim_receipt(*, now: datetime) -> dict[str, object]:
    job = {
        "repository": CONTROLLER_REPOSITORY,
        "run_id": 101,
        "job_id": 202,
        "attempt": 1,
        "exact_sha": NEW.source_sha,
        "profile": "qdev-ci",
    }
    scope = {
        "schema": "claim-scope-v2",
        "scope_id": "controller-recovery-scope",
        "worker_name": "qdev-controller-recovery",
        "tier": "recovery",
        "expires_at": (now + timedelta(minutes=10)).isoformat(),
        "worker_certificate_sha256": "c" * 64,
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


def _trivy_report(
    artifact_name: str,
    artifact_type: str,
    *,
    results: object = None,
) -> dict[str, object]:
    report: dict[str, object] = {
        "SchemaVersion": 2,
        "ArtifactName": artifact_name,
        "ArtifactType": artifact_type,
        "Trivy": {"Version": "0.74.0"},
    }
    if results is not None:
        report["Results"] = results
    return report


@pytest.mark.parametrize(
    "result",
    [
        {"Vulnerabilities": False, "Secrets": []},
        {"Vulnerabilities": [None], "Secrets": []},
        {"Vulnerabilities": [{"VulnerabilityID": "CVE-EXAMPLE"}], "Secrets": []},
        {"Vulnerabilities": [{"Severity": "LOW"}], "Secrets": []},
        {"Vulnerabilities": [], "Secrets": False},
        {"Vulnerabilities": [], "Secrets": [None]},
    ],
)
def test_activation_rejects_malformed_trivy_findings(result: object) -> None:
    report = _trivy_report(
        "controller-source",
        "repository",
        results=[result],
    )
    with pytest.raises(ControllerActivationError, match="invalid"):
        _trivy_actionable_findings(report)


def test_activation_accepts_omitted_results_and_rejects_explicit_null() -> None:
    report = _trivy_report("controller-source", "repository")
    assert _trivy_actionable_findings(report) == 0
    report["Results"] = None
    with pytest.raises(ControllerActivationError, match="invalid"):
        _trivy_actionable_findings(report)


def _artifact_bundle(
    tmp_path: Path,
    *,
    workflow_identity: dict[str, object] | None = None,
) -> tuple[Path, dict[str, object]]:
    archive = tmp_path / "controller-image.tar"
    archive.write_bytes(b"exact controller image archive")
    sbom = tmp_path / "controller.spdx.json"
    sbom.write_text(json.dumps({"spdxVersion": "SPDX-2.3", "name": "controller"}), encoding="utf-8")
    scans = tmp_path / "controller-security-scans.json"
    source_scan = tmp_path / "controller-source-trivy.json"
    image_scan = tmp_path / "controller-image-trivy.json"
    source_scan.write_text(
        json.dumps(_trivy_report("controller-source", "repository")), encoding="utf-8"
    )
    image_scan.write_text(
        json.dumps(_trivy_report("controller-image", "container_image", results=[])),
        encoding="utf-8",
    )
    source_scan_digest = hashlib.sha256(source_scan.read_bytes()).hexdigest()
    image_scan_digest = hashlib.sha256(image_scan.read_bytes()).hexdigest()
    scans.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-security-scans-v1",
                "status": "passed",
                "source_high_critical": 0,
                "image_high_critical": 0,
                "source_report_sha256": source_scan_digest,
                "image_report_sha256": image_scan_digest,
            }
        ),
        encoding="utf-8",
    )
    archive_digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    sbom_digest = hashlib.sha256(sbom.read_bytes()).hexdigest()
    scans_digest = hashlib.sha256(scans.read_bytes()).hexdigest()
    claim_receipt: Path | None = None
    claim_receipt_digest: str | None = None
    if workflow_identity is not None and workflow_identity.get("execution_lane") == "recovery":
        reconciled_at = datetime.fromisoformat(
            str(workflow_identity["reconciled_at"]).replace("Z", "+00:00")
        )
        claim_document = _recovery_claim_receipt(now=reconciled_at)
        claim_receipt = tmp_path / "controller-claim-receipt.json"
        claim_receipt.write_text(
            json.dumps(claim_document, sort_keys=True, separators=(",", ":")),
            encoding="utf-8",
        )
        claim_receipt_digest = hashlib.sha256(claim_receipt.read_bytes()).hexdigest()
    provenance = tmp_path / "provenance.json"
    provenance_document: dict[str, object] = {
        "schema": ARTIFACT_PROVENANCE_SCHEMA,
        "repository": CONTROLLER_REPOSITORY,
        "source_sha": NEW.source_sha,
        "image_digest": NEW.image_digest,
        "policy_bundle_digest": NEW.policy_bundle_digest,
        "entrypoint_reconciliation_digest": ENTRYPOINT_RECONCILIATION,
        "image_unpacked_size": 123456789,
        "image_archive_sha256": archive_digest,
        "sbom_sha256": sbom_digest,
        "security_scans_sha256": scans_digest,
        "source_scan_sha256": source_scan_digest,
        "image_scan_sha256": image_scan_digest,
        "workflow_identity": workflow_identity
        or {
            "issuer": "https://token.actions.githubusercontent.com",
            "subject": (f"repo:{CONTROLLER_REPOSITORY}:ref:refs/heads/main"),
            "workflow_ref": (f"{CONTROLLER_REPOSITORY}/.github/workflows/ci.yml@refs/heads/main"),
            "event": "push",
            "ref": "refs/heads/main",
            "run_id": 101,
            "job_id": 202,
            "attempt": 1,
            "reconciled_at": "2026-09-05T01:00:00Z",
        },
    }
    if claim_receipt_digest is not None:
        provenance_document["claim_receipt_sha256"] = claim_receipt_digest
    provenance.write_text(
        json.dumps(provenance_document, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )

    def descriptor(path: Path) -> dict[str, object]:
        raw = path.read_bytes()
        return {"path": path.name, "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}

    document: dict[str, object] = {
        "schema": ARTIFACT_MANIFEST_SCHEMA,
        "repository": CONTROLLER_REPOSITORY,
        "source_sha": NEW.source_sha,
        "image_digest": NEW.image_digest,
        "policy_bundle_digest": NEW.policy_bundle_digest,
        "entrypoint_reconciliation_digest": ENTRYPOINT_RECONCILIATION,
        "image_unpacked_size": 123456789,
        "image_archive": descriptor(archive),
        "sbom": descriptor(sbom),
        "security_scans": descriptor(scans),
        "source_scan": descriptor(source_scan),
        "image_scan": descriptor(image_scan),
        "provenance": descriptor(provenance),
    }
    if claim_receipt is not None:
        document["claim_receipt"] = descriptor(claim_receipt)
    manifest = tmp_path / "artifact-manifest.json"
    manifest.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")), encoding="utf-8"
    )
    return manifest, document


def test_artifact_manifest_binds_exact_archive_sbom_and_provenance(tmp_path: Path) -> None:
    manifest, _ = _artifact_bundle(tmp_path)
    manifest_digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
    verified = verify_controller_artifact_manifest(
        manifest,
        expected_manifest_digest=manifest_digest,
        require_root_owner=False,
    )
    assert verified.source_sha == NEW.source_sha
    assert verified.image_digest == NEW.image_digest
    assert verified.policy_bundle_digest == NEW.policy_bundle_digest
    assert verified.entrypoint_reconciliation_digest == ENTRYPOINT_RECONCILIATION
    assert verified.image_unpacked_size == 123456789
    assert verified.image_archive.name == "controller-image.tar"
    assert (
        verified.source_scan_digest
        == hashlib.sha256((tmp_path / "controller-source-trivy.json").read_bytes()).hexdigest()
    )

    (tmp_path / "controller-image.tar").write_bytes(b"forged archive")
    with pytest.raises(ControllerActivationError, match="bytes do not match"):
        verify_controller_artifact_manifest(manifest, require_root_owner=False)


def test_artifact_manifest_rejects_wrong_identity_and_traversal(tmp_path: Path) -> None:
    manifest, document = _artifact_bundle(tmp_path)
    document["repository"] = "foreign/controller"
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ControllerActivationError, match="identity"):
        verify_controller_artifact_manifest(manifest, require_root_owner=False)

    manifest, document = _artifact_bundle(tmp_path)
    archive = dict(document["image_archive"])  # type: ignore[arg-type]
    archive["path"] = "../controller-image.tar"
    document["image_archive"] = archive
    manifest.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ControllerActivationError, match="path"):
        verify_controller_artifact_manifest(manifest, require_root_owner=False)


def test_artifact_manifest_rejects_raw_trivy_findings_despite_green_summary(
    tmp_path: Path,
) -> None:
    manifest, document = _artifact_bundle(tmp_path)
    source_scan = tmp_path / "controller-source-trivy.json"
    source_scan.write_text(
        json.dumps(
            _trivy_report(
                "controller-source",
                "repository",
                results=[
                    {
                        "Vulnerabilities": [{"Severity": "CRITICAL"}],
                        "Secrets": [],
                    }
                ],
            )
        ),
        encoding="utf-8",
    )
    source_descriptor = dict(document["source_scan"])  # type: ignore[arg-type]
    source_descriptor["sha256"] = hashlib.sha256(source_scan.read_bytes()).hexdigest()
    source_descriptor["size"] = source_scan.stat().st_size
    document["source_scan"] = source_descriptor
    scans = tmp_path / "controller-security-scans.json"
    scans_document = json.loads(scans.read_text(encoding="utf-8"))
    scans_document["source_report_sha256"] = source_descriptor["sha256"]
    scans.write_text(json.dumps(scans_document), encoding="utf-8")
    scans_descriptor = dict(document["security_scans"])  # type: ignore[arg-type]
    scans_descriptor["sha256"] = hashlib.sha256(scans.read_bytes()).hexdigest()
    scans_descriptor["size"] = scans.stat().st_size
    document["security_scans"] = scans_descriptor
    provenance = tmp_path / "provenance.json"
    provenance_document = json.loads(provenance.read_text(encoding="utf-8"))
    provenance_document["source_scan_sha256"] = source_descriptor["sha256"]
    provenance_document["security_scans_sha256"] = scans_descriptor["sha256"]
    provenance.write_text(json.dumps(provenance_document), encoding="utf-8")
    provenance_descriptor = dict(document["provenance"])  # type: ignore[arg-type]
    provenance_descriptor["sha256"] = hashlib.sha256(provenance.read_bytes()).hexdigest()
    provenance_descriptor["size"] = provenance.stat().st_size
    document["provenance"] = provenance_descriptor
    manifest.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ControllerActivationError, match="security scans did not pass"):
        verify_controller_artifact_manifest(manifest, require_root_owner=False)


def _recovery_workflow_identity(*, now: datetime) -> dict[str, object]:
    ref = "refs/heads/codex/controller-recovery"
    receipt = _recovery_claim_receipt(now=now)
    return {
        "issuer": "https://api.github.com",
        "subject": f"repo:{CONTROLLER_REPOSITORY}:ref:{ref}",
        "workflow_ref": f"{CONTROLLER_REPOSITORY}/.github/workflows/runner-smoke.yml@{ref}",
        "event": "workflow_dispatch",
        "ref": ref,
        "run_id": 101,
        "job_id": 202,
        "attempt": 1,
        "reconciled_at": now.isoformat().replace("+00:00", "Z"),
        "head_sha": NEW.source_sha,
        "job_name": "runner-smoke",
        "labels": [
            "self-hosted",
            "Linux",
            "X64",
            "qdev-ci",
            "qdev-job-101-1-smoke",
        ],
        "owner_recovery": True,
        "execution_lane": "recovery",
        "expected_sha": NEW.source_sha,
        "admission_nonce": f"controller-claim:{receipt['receipt_id']}",
        "idempotency_key": "recovery-artifact-0001",
        "issued_at": (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z"),
        "expires_at": (now + timedelta(minutes=14)).isoformat().replace("+00:00", "Z"),
        "conclusion": "success",
    }


@pytest.mark.parametrize("tamper", [None, "expired", "expected_sha", "labels", "ref"])
def test_hosted_artifact_requires_fresh_exact_identity(tmp_path: Path, tamper: str | None) -> None:
    now = datetime(2026, 9, 6, 12, tzinfo=UTC)
    identity = _recovery_workflow_identity(now=now)
    identity.pop("admission_nonce")
    identity.update(
        {
            "workflow_ref": (
                f"{CONTROLLER_REPOSITORY}/.github/workflows/"
                "controller-recovery-build.yml@refs/heads/main"
            ),
            "subject": f"repo:{CONTROLLER_REPOSITORY}:ref:refs/heads/main",
            "ref": "refs/heads/main",
            "job_name": "controller-recovery-build",
            "labels": ["ubuntu-latest"],
            "execution_lane": "github-hosted-recovery-build",
            "idempotency_key": "hosted-recovery:101:202:1",
            "issued_at": identity["reconciled_at"],
        }
    )
    if tamper == "expected_sha":
        identity[tamper] = "0" * 40
    elif tamper == "labels":
        identity[tamper] = ["self-hosted"]
    elif tamper == "ref":
        identity[tamper] = "refs/heads/other"
    manifest, _ = _artifact_bundle(tmp_path, workflow_identity=identity)
    if tamper:
        with pytest.raises(ControllerActivationError):
            verify_controller_artifact_manifest(
                manifest,
                require_root_owner=False,
                now=now + timedelta(hours=1) if tamper == "expired" else now,
            )
    else:
        assert (
            verify_controller_artifact_manifest(
                manifest,
                require_root_owner=False,
                now=now,
            ).source_sha
            == NEW.source_sha
        )


def test_artifact_manifest_accepts_fresh_exact_recovery_identity(tmp_path: Path) -> None:
    now = datetime(2026, 9, 6, 12, tzinfo=UTC)
    manifest, _ = _artifact_bundle(
        tmp_path,
        workflow_identity=_recovery_workflow_identity(now=now),
    )
    verified = verify_controller_artifact_manifest(
        manifest,
        require_root_owner=False,
        now=now,
    )
    assert verified.source_sha == NEW.source_sha


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("expected_sha", "0" * 40),
        ("job_id", 0),
        ("labels", ["self-hosted", "Linux", "X64", "qdev-ci"]),
        ("admission_nonce", "bad"),
        ("conclusion", "failure"),
    ],
)
def test_artifact_manifest_rejects_forged_recovery_identity(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    now = datetime(2026, 9, 6, 12, tzinfo=UTC)
    identity = _recovery_workflow_identity(now=now)
    identity[field] = value
    manifest, _ = _artifact_bundle(tmp_path, workflow_identity=identity)
    with pytest.raises(ControllerActivationError, match="workflow identity"):
        verify_controller_artifact_manifest(
            manifest,
            require_root_owner=False,
            now=now,
        )


def test_artifact_manifest_rejects_expired_recovery_identity(tmp_path: Path) -> None:
    issued = datetime(2026, 9, 6, 11, tzinfo=UTC)
    identity = _recovery_workflow_identity(now=issued)
    manifest, _ = _artifact_bundle(tmp_path, workflow_identity=identity)
    with pytest.raises(ControllerActivationError, match="recovery workflow identity"):
        verify_controller_artifact_manifest(
            manifest,
            require_root_owner=False,
            now=issued + timedelta(minutes=31),
        )


def test_config_fingerprint_binds_logical_names_and_bytes(tmp_path: Path) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.write_text("alpha", encoding="utf-8")
    second.write_text("beta", encoding="utf-8")
    digest = fingerprint_config_files({"etc/a": first, "etc/b": second}, require_root_owner=False)
    assert digest != fingerprint_config_files(
        {"etc/a": second, "etc/b": first}, require_root_owner=False
    )
    second.write_text("changed", encoding="utf-8")
    assert digest != fingerprint_config_files(
        {"etc/a": first, "etc/b": second}, require_root_owner=False
    )


def test_release_tree_fingerprint_binds_paths_modes_and_bytes(tmp_path: Path) -> None:
    release = tmp_path / "release"
    scripts = release / "scripts"
    scripts.mkdir(parents=True)
    entrypoint = scripts / "activate.sh"
    entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    entrypoint.chmod(0o755)
    compose = release / "compose.yml"
    compose.write_text("services: {}\n", encoding="utf-8")

    digest = fingerprint_release_tree(release, require_root_owner=False)
    entrypoint.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    assert digest != fingerprint_release_tree(release, require_root_owner=False)

    entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    entrypoint.chmod(0o700)
    assert digest != fingerprint_release_tree(release, require_root_owner=False)


def test_release_tree_fingerprint_rejects_links_and_writable_entries(tmp_path: Path) -> None:
    release = tmp_path / "release"
    release.mkdir()
    entrypoint = release / "activate.sh"
    entrypoint.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    link = release / "linked-entrypoint"
    link.symlink_to(entrypoint)
    with pytest.raises(ControllerActivationError, match="unsafe"):
        fingerprint_release_tree(release, require_root_owner=False)

    link.unlink()
    entrypoint.chmod(0o775)
    with pytest.raises(ControllerActivationError, match="permissions"):
        fingerprint_release_tree(release, require_root_owner=False)


def test_release_tree_fingerprint_ignores_checkout_metadata(tmp_path: Path) -> None:
    release = tmp_path / "release"
    release.mkdir()
    (release / "entrypoint.sh").write_text("#!/bin/sh\\nexit 0\\n", encoding="utf-8")
    baseline = fingerprint_release_tree(release, require_root_owner=False)

    checkout = release / ".git"
    checkout.mkdir()
    (checkout / "config").write_text("different checkout transport\\n", encoding="utf-8")

    assert fingerprint_release_tree(release, require_root_owner=False) == baseline


def test_release_tree_fingerprint_ignores_derived_python_cache(tmp_path: Path) -> None:
    release = tmp_path / "release"
    source = release / "src" / "qdev_runner"
    source.mkdir(parents=True)
    (source / "controller_activation.py").write_text("VALUE = 1\n", encoding="utf-8")
    baseline = fingerprint_release_tree(release, require_root_owner=False)

    cache = source / "__pycache__"
    cache.mkdir()
    (cache / "controller_activation.cpython-312.pyc").write_bytes(b"derived-bytecode")

    assert fingerprint_release_tree(release, require_root_owner=False) == baseline

    cache.chmod(0o775)
    with pytest.raises(ControllerActivationError, match="permissions"):
        fingerprint_release_tree(release, require_root_owner=False)
    cache.chmod(0o755)

    (source / "controller_activation.pyc").write_bytes(b"unexpected-bytecode")
    assert fingerprint_release_tree(release, require_root_owner=False) != baseline


def test_signed_envelope_rejects_tampering_expiry_and_excessive_ttl() -> None:
    now = datetime(2026, 9, 5, 1, tzinfo=UTC)
    document = _envelope_document(now=now)
    tampered = dict(document)
    tampered["candidate"] = {**NEW.mapping(), "image_digest": "9" * 64}
    with pytest.raises(ControllerActivationError, match="signature"):
        ActivationEnvelope.verify(tampered, public_key=PUBLIC_KEY, now=now)

    with pytest.raises(ControllerActivationError, match="expired"):
        ActivationEnvelope.verify(
            document,
            public_key=PUBLIC_KEY,
            now=now + timedelta(minutes=16),
        )

    with pytest.raises(ControllerActivationError, match="signature"):
        ActivationEnvelope.verify(
            document,
            public_key=Ed25519PrivateKey.generate().public_key(),
            now=now,
        )

    unsigned = dict(document)
    del unsigned["signature"]
    unsigned["expires_at"] = (now + timedelta(minutes=31)).isoformat().replace("+00:00", "Z")
    excessive = _sign(unsigned)
    with pytest.raises(ControllerActivationError, match="TTL"):
        ActivationEnvelope.verify(excessive, public_key=PUBLIC_KEY, now=now)


def test_signed_envelope_rejects_noncanonical_base64url_signature() -> None:
    now = datetime(2026, 9, 5, 1, tzinfo=UTC)
    document = _envelope_document(now=now)
    signature = document["signature"]
    assert isinstance(signature, str)
    # A different final base64url character can decode to the same 64 bytes
    # when its unused low bits are non-zero. It must not create another digest.
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    original_index = alphabet.index(signature[-1])
    replacement_index = original_index | 0b01
    if replacement_index == original_index:
        replacement_index = original_index | 0b10
    noncanonical = {**document, "signature": signature[:-1] + alphabet[replacement_index]}
    decoded_original = base64.urlsafe_b64decode(f"{signature}==")
    decoded_noncanonical = base64.urlsafe_b64decode(f"{noncanonical['signature']}==")
    assert decoded_noncanonical == decoded_original
    with pytest.raises(ControllerActivationError, match="signature"):
        ActivationEnvelope.verify(noncanonical, public_key=PUBLIC_KEY, now=now)


def test_commit_is_monotonic_preserves_previous_and_is_idempotent(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelope = _envelope()

    assert (
        store.reserve(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )
        == "new"
    )
    store.assert_current(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    committed = store.commit(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
        activated_at=datetime(2026, 9, 5, 2, tzinfo=UTC),
    )

    assert committed.generation == 8
    assert committed.current == NEW
    assert committed.previous == (7, OLD)
    assert committed.transaction_id == envelope.transaction_id
    assert store.transaction_path.exists()
    assert (
        store.reserve(
            envelope,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
        )
        == "committed"
    )
    assert store.finalize(envelope) == committed
    assert not store.transaction_path.exists()
    assert (
        store.reserve(
            envelope,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
        )
        == "finalized"
    )
    assert (
        store.commit(
            envelope,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
        )
        == committed
    )


def test_distinct_current_public_and_internal_images_are_bound_exactly(tmp_path: Path) -> None:
    distinct_current = ControllerTuple(
        OLD.source_sha,
        OLD.public_image_digest,
        OLD.policy_bundle_digest,
        "c" * 64,
    )
    status = ControllerReleaseStatus(
        generation=7,
        current=distinct_current,
        previous=None,
        transaction_id="bootstrap-transaction",
        activated_at=datetime(2026, 9, 5, tzinfo=UTC),
    )
    encoded = (json.dumps(status.mapping(), sort_keys=True, separators=(",", ":")) + "\n").encode()
    status_path = tmp_path / "controller-release.json"
    status_path.write_bytes(encoded)
    store = ActivationStateStore(status_path)
    envelope = _envelope(
        expected=distinct_current,
        expected_status_digest=hashlib.sha256(encoded).hexdigest(),
    )

    assert (
        store.reserve(
            envelope,
            observed_image_digest=distinct_current.public_image_digest,
            observed_internal_image_digest=distinct_current.effective_internal_image_digest,
            observed_config_digest=OLD_CONFIG,
        )
        == "new"
    )
    with pytest.raises(ControllerActivationError, match="reserved transaction"):
        store.reserve(
            envelope,
            observed_image_digest=distinct_current.effective_internal_image_digest,
            observed_internal_image_digest=distinct_current.public_image_digest,
            observed_config_digest=OLD_CONFIG,
        )


def test_commit_failure_before_transaction_precommit_keeps_old_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    original_write = ActivationStateStore._atomic_write

    def fail_precommit(path: Path, value: dict[str, object], *, mode: int) -> None:
        if path == store.transaction_path and value.get("committed_status_digest") is not None:
            raise OSError("injected transaction fsync failure")
        original_write(path, value, mode=mode)

    monkeypatch.setattr(ActivationStateStore, "_atomic_write", staticmethod(fail_precommit))
    with pytest.raises(OSError, match="injected transaction"):
        store.commit(
            envelope,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
        )

    assert store.read_status() == _status()
    transaction = json.loads(store.transaction_path.read_text(encoding="utf-8"))
    assert transaction["committed_status_digest"] is None
    assert transaction["committed_activated_at"] is None


def test_commit_status_write_failure_replays_exact_precommit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    original_write = ActivationStateStore._atomic_write
    failed = False

    def fail_first_status(path: Path, value: dict[str, object], *, mode: int) -> None:
        nonlocal failed
        if path == store.status_path and not failed:
            failed = True
            raise OSError("injected status fsync failure")
        original_write(path, value, mode=mode)

    monkeypatch.setattr(ActivationStateStore, "_atomic_write", staticmethod(fail_first_status))
    with pytest.raises(OSError, match="injected status"):
        store.commit(
            envelope,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
            activated_at=datetime(2026, 9, 5, 2, tzinfo=UTC),
        )

    assert store.read_status() == _status()
    transaction = json.loads(store.transaction_path.read_text(encoding="utf-8"))
    assert isinstance(transaction["committed_status_digest"], str)
    assert transaction["committed_activated_at"] == "2026-09-05T02:00:00Z"

    monkeypatch.setattr(ActivationStateStore, "_atomic_write", staticmethod(original_write))
    committed = store.commit(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
    )
    assert committed.generation == 8
    assert committed.activated_at == datetime(2026, 9, 5, 2, tzinfo=UTC)


def test_atomic_unlink_rejects_symlink_and_fsyncs_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}\n", encoding="utf-8")
    link = tmp_path / "transaction.json"
    link.symlink_to(target)
    with pytest.raises(ControllerActivationError, match="state is unsafe"):
        ActivationStateStore._atomic_unlink(link)
    assert link.is_symlink()

    link.unlink()
    link.write_text("{}\n", encoding="utf-8")
    original_fsync = os.fsync
    fsync_calls: list[int] = []

    def record_fsync(descriptor: int) -> None:
        fsync_calls.append(descriptor)
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", record_fsync)
    ActivationStateStore._atomic_unlink(link)
    assert not link.exists()
    assert len(fsync_calls) == 1


def test_exact_pending_replay_allows_only_old_or_candidate_running_image(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    assert (
        store.reserve(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )
        == "new"
    )
    assert (
        store.reserve(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )
        == "pending-before-mutation"
    )
    assert (
        store.reserve(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=NEW_CONFIG,
        )
        == "pending-config-installed"
    )
    assert (
        store.reserve(
            envelope,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
        )
        == "pending-candidate-active"
    )
    with pytest.raises(ControllerActivationError, match="reserved transaction"):
        store.reserve(
            envelope,
            observed_image_digest="a" * 64,
            observed_config_digest=NEW_CONFIG,
        )
    with pytest.raises(ControllerActivationError, match="reserved transaction"):
        store.reserve(
            envelope,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=OLD_CONFIG,
        )


def test_rollback_rejects_unsigned_current_config_state(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    with pytest.raises(ControllerActivationError, match="running config is foreign"):
        store.authorize_rollback(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest="a" * 64,
            rollback_config_digest=OLD_CONFIG,
        )


def test_recovery_classifies_trusted_images_with_validated_config_transition(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    transition_digest = "a" * 64
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )

    with pytest.raises(ControllerActivationError, match="runtime is foreign"):
        store.recovery_state(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=transition_digest,
        )
    assert (
        store.recovery_state(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=transition_digest,
            allow_config_transition=True,
        )
        == "pending-mutating"
    )
    assert (
        store.recovery_state(
            envelope,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=transition_digest,
            allow_config_transition=True,
        )
        == "pending-mutating"
    )


def test_rollback_allows_host_validated_config_transition_on_trusted_runtime(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    transition_digest = "a" * 64
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )

    with pytest.raises(ControllerActivationError, match="running config is foreign"):
        store.authorize_rollback(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=transition_digest,
            rollback_config_digest=OLD_CONFIG,
        )
    store.authorize_rollback(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=transition_digest,
        rollback_config_digest=OLD_CONFIG,
        allow_config_transition=True,
    )
    store.authorize_rollback(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=transition_digest,
        rollback_config_digest=OLD_CONFIG,
        allow_config_transition=True,
    )


def test_reserve_binds_exact_status_and_config_fingerprints(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    with pytest.raises(ControllerActivationError, match="config"):
        store.reserve(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest="f" * 64,
        )

    # Semantically equivalent JSON is still a different signed status artifact.
    store.status_path.write_text(json.dumps(_status().mapping(), indent=2), encoding="utf-8")
    with pytest.raises(ControllerActivationError, match="status fingerprint"):
        store.reserve(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )


def test_stale_generation_and_foreign_current_tuple_fail_closed(tmp_path: Path) -> None:
    store = _store(tmp_path)
    with pytest.raises(ControllerActivationError, match="generation CAS"):
        store.reserve(
            _envelope(expected_generation=6),
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )
    with pytest.raises(ControllerActivationError, match="current tuple CAS"):
        store.reserve(
            _envelope(expected=ControllerTuple("a" * 40, "b" * 64, "c" * 64)),
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )


def test_rollback_is_owned_by_reserving_transaction_and_leaves_generation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    owner = _envelope(transaction_id="transaction-owner")
    foreign = _envelope(transaction_id="transaction-foreign")
    store.reserve(
        owner,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )

    with pytest.raises(ControllerActivationError, match="ownership"):
        store.authorize_rollback(
            foreign,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
            rollback_config_digest=OLD_CONFIG,
        )
    store.authorize_rollback(
        owner,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
        rollback_config_digest=OLD_CONFIG,
    )
    store.abort(
        owner,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )

    current = store.read_status()
    assert current.generation == 7
    assert current.current == OLD
    assert not store.transaction_path.exists()


def test_expired_signed_owner_can_rollback_but_not_advance(tmp_path: Path) -> None:
    store = _store(tmp_path)
    issued_at = datetime(2026, 9, 5, 1, tzinfo=UTC)
    document = _envelope_document(transaction_id="transaction-owner", now=issued_at)
    owner = ActivationEnvelope.verify(document, public_key=PUBLIC_KEY, now=issued_at)
    store.reserve(
        owner,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
        now=issued_at,
    )

    expired_owner = ActivationEnvelope.verify(
        document,
        public_key=PUBLIC_KEY,
        now=issued_at + timedelta(hours=1),
        allow_expired_for_rollback=True,
    )
    with pytest.raises(ControllerActivationError, match="expired"):
        ActivationEnvelope.verify(
            document,
            public_key=PUBLIC_KEY,
            now=issued_at + timedelta(hours=1),
        )

    store.authorize_rollback(
        expired_owner,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
        rollback_config_digest=OLD_CONFIG,
    )
    store.abort(
        expired_owner,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    assert store.read_status().generation == 7


def test_expired_rollback_rejects_foreign_owner_and_changed_generation(tmp_path: Path) -> None:
    store = _store(tmp_path)
    issued_at = datetime(2026, 9, 5, 1, tzinfo=UTC)
    owner_document = _envelope_document(transaction_id="transaction-owner", now=issued_at)
    owner = ActivationEnvelope.verify(owner_document, public_key=PUBLIC_KEY, now=issued_at)
    store.reserve(
        owner,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
        now=issued_at,
    )

    foreign_document = _envelope_document(
        transaction_id="transaction-foreign",
        now=issued_at,
    )
    foreign = ActivationEnvelope.verify(
        foreign_document,
        public_key=PUBLIC_KEY,
        now=issued_at + timedelta(hours=1),
        allow_expired_for_rollback=True,
    )
    with pytest.raises(ControllerActivationError, match="ownership"):
        store.authorize_rollback(
            foreign,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
            rollback_config_digest=OLD_CONFIG,
        )

    changed = ControllerReleaseStatus(
        generation=8,
        current=OLD,
        previous=(7, OLD),
        transaction_id="another-transaction",
        activated_at=issued_at + timedelta(minutes=30),
    )
    store.status_path.write_text(json.dumps(changed.mapping()), encoding="utf-8")
    expired_owner = ActivationEnvelope.verify(
        owner_document,
        public_key=PUBLIC_KEY,
        now=issued_at + timedelta(hours=1),
        allow_expired_for_rollback=True,
    )
    with pytest.raises(ControllerActivationError, match="generation CAS"):
        store.authorize_rollback(
            expired_owner,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
            rollback_config_digest=OLD_CONFIG,
        )


def test_only_one_concurrent_activation_can_reserve(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelopes = [_envelope(transaction_id=f"transaction-{index:04d}") for index in range(8)]

    def reserve(envelope: ActivationEnvelope) -> str:
        try:
            store.reserve(
                envelope,
                observed_image_digest=OLD.image_digest,
                observed_config_digest=OLD_CONFIG,
                now=datetime(2026, 9, 5, 1, 2, tzinfo=UTC),
            )
        except ControllerActivationError:
            return "blocked"
        return "reserved"

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(reserve, envelopes))

    assert results.count("reserved") == 1
    assert results.count("blocked") == 7


def test_stale_transaction_eviction_rejects_unknown_fields(tmp_path: Path) -> None:
    store = _store(tmp_path)
    owner = _envelope(transaction_id="transaction-owner")
    store.reserve(
        owner,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    raw = json.loads(store.transaction_path.read_text(encoding="utf-8"))
    raw["unexpected"] = True
    raw["expires_at"] = "2026-09-05T00:00:00Z"
    store.transaction_path.write_text(json.dumps(raw), encoding="utf-8")

    with pytest.raises(ControllerActivationError, match="transaction is invalid"):
        store.reserve(
            _envelope(transaction_id="transaction-next"),
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
            now=datetime(2026, 9, 5, 2, tzinfo=UTC),
        )


def test_expired_transaction_with_candidate_running_is_retained(tmp_path: Path) -> None:
    store = _store(tmp_path)
    issued_at = datetime(2026, 9, 5, 1, tzinfo=UTC)
    owner = _envelope(transaction_id="transaction-owner", now=issued_at)
    store.reserve(
        owner,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
        now=issued_at,
    )
    retained = store.transaction_path.read_bytes()
    observed_at = issued_at + timedelta(hours=1)
    next_envelope = ActivationEnvelope.verify(
        _envelope_document(transaction_id="transaction-next", now=observed_at),
        public_key=PUBLIC_KEY,
        now=observed_at,
    )

    with pytest.raises(ControllerActivationError, match="cannot be safely evicted"):
        store.reserve(
            next_envelope,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
            now=observed_at,
        )

    assert store.transaction_path.read_bytes() == retained


def test_expired_transaction_with_candidate_config_is_retained(tmp_path: Path) -> None:
    store = _store(tmp_path)
    issued_at = datetime(2026, 9, 5, 1, tzinfo=UTC)
    owner = _envelope(transaction_id="transaction-owner", now=issued_at)
    store.reserve(
        owner,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
        now=issued_at,
    )
    retained = store.transaction_path.read_bytes()
    observed_at = issued_at + timedelta(hours=1)
    next_envelope = ActivationEnvelope.verify(
        _envelope_document(transaction_id="transaction-next", now=observed_at),
        public_key=PUBLIC_KEY,
        now=observed_at,
    )

    with pytest.raises(ControllerActivationError, match="cannot be safely evicted"):
        store.reserve(
            next_envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=NEW_CONFIG,
            now=observed_at,
        )
    assert store.transaction_path.read_bytes() == retained


def test_committed_rollback_is_owned_and_monotonic(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelope = _envelope(transaction_id="transaction-owner")
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    committed = store.commit(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
    )
    assert committed.generation == 8
    store.authorize_rollback(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
        rollback_config_digest=OLD_CONFIG,
    )
    rolled_back = store.complete_rollback(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    assert rolled_back.generation == 9
    assert rolled_back.current == OLD
    assert rolled_back.previous == (8, NEW)
    assert rolled_back.transaction_id == "rollback:transaction-owner"
    assert not store.transaction_path.exists()
    assert (
        store.verify_rollback_terminal(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )
        == rolled_back
    )

    assert (
        store.complete_rollback(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )
        == rolled_back
    )
    with pytest.raises(ControllerActivationError, match="terminal image CAS"):
        store.complete_rollback(
            envelope,
            observed_image_digest="a" * 64,
            observed_config_digest=OLD_CONFIG,
        )
    with pytest.raises(ControllerActivationError, match="terminal config CAS"):
        store.complete_rollback(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest="b" * 64,
        )
    with pytest.raises(ControllerActivationError, match="terminal image CAS"):
        store.verify_rollback_terminal(
            envelope,
            observed_image_digest="a" * 64,
            observed_config_digest=OLD_CONFIG,
        )


def test_activation_cli_executes_commit_failure_and_owned_rollback(tmp_path: Path) -> None:
    status = tmp_path / "controller-release.json"
    status.write_bytes(_encoded_status())
    envelope = tmp_path / "activation-envelope.json"
    envelope.write_text(
        json.dumps(
            _envelope_document(now=datetime.now(UTC)),
            sort_keys=True,
            separators=(",", ":"),
        ),
        encoding="utf-8",
    )
    public_key = tmp_path / "activation-public-key.pem"
    public_key.write_bytes(
        PUBLIC_KEY.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )

    reserve = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="reserve",
        observations=(OLD.image_digest, OLD_CONFIG),
    )
    assert reserve.returncode == 0, reserve.stderr
    assert json.loads(reserve.stdout)["reservation_state"] == "new"

    current = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="assert-current",
        observations=(OLD.image_digest, OLD_CONFIG),
    )
    assert current.returncode == 0, current.stderr

    commit = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="commit",
        observations=(NEW.image_digest, NEW_CONFIG),
    )
    assert commit.returncode == 0, commit.stderr
    committed = json.loads(commit.stdout)
    assert committed["generation"] == 8
    assert {field: committed[field] for field in NEW.mapping()} == NEW.mapping()

    authorize = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="authorize-rollback",
        observations=(NEW.image_digest, NEW_CONFIG),
        rollback_config=OLD_CONFIG,
    )
    assert authorize.returncode == 0, authorize.stderr

    status_after_commit = status.read_bytes()
    failed = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="complete-rollback",
        observations=("b" * 64, OLD_CONFIG),
    )
    assert failed.returncode == 78
    assert "rollback image restore CAS failed" in failed.stderr
    assert status.read_bytes() == status_after_commit

    rollback = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="complete-rollback",
        observations=(OLD.image_digest, OLD_CONFIG),
    )
    assert rollback.returncode == 0, rollback.stderr
    rolled_back = json.loads(rollback.stdout)
    assert rolled_back["generation"] == 9
    assert {field: rolled_back[field] for field in OLD.mapping()} == OLD.mapping()

    replay = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="complete-rollback",
        observations=(OLD.image_digest, OLD_CONFIG),
    )
    assert replay.returncode == 0, replay.stderr
    assert json.loads(replay.stdout) == rolled_back

    terminal = _run_activation_cli(
        status=status,
        envelope=envelope,
        public_key=public_key,
        command="verify-rollback-terminal",
        observations=(OLD.image_digest, OLD_CONFIG),
    )
    assert terminal.returncode == 0, terminal.stderr
    assert json.loads(terminal.stdout) == rolled_back


def test_terminal_rollback_replay_rejects_foreign_open_transaction(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelope = _envelope(transaction_id="transaction-owner")
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    store.commit(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
    )
    store.complete_rollback(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )

    foreign = _envelope(transaction_id="transaction-foreign")
    transaction = store._transaction_mapping(  # noqa: SLF001 - adversarial state fixture
        foreign,
        reserved_status_digest=_status_digest(),
    )
    store._atomic_write(  # noqa: SLF001 - adversarial state fixture
        store.transaction_path,
        transaction,
        mode=0o600,
    )
    with pytest.raises(ControllerActivationError, match="ownership failed"):
        store.complete_rollback(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )


def test_committed_status_fingerprint_is_required_for_finalize_and_rollback(
    tmp_path: Path,
) -> None:
    store = _store(tmp_path)
    envelope = _envelope(transaction_id="transaction-owner")
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    store.commit(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
    )
    parsed = json.loads(store.status_path.read_text(encoding="utf-8"))
    store.status_path.write_text(json.dumps(parsed, indent=2), encoding="utf-8")

    with pytest.raises(ControllerActivationError, match="status fingerprint"):
        store.authorize_rollback(
            envelope,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
            rollback_config_digest=OLD_CONFIG,
        )
    with pytest.raises(ControllerActivationError, match="status fingerprint"):
        store.finalize(envelope)


def test_legacy_import_requires_exact_signed_tuple_and_observed_image(tmp_path: Path) -> None:
    status_path = tmp_path / "controller-release.json"
    legacy_bytes = json.dumps(
        {
            "schema": LEGACY_STATUS_SCHEMA,
            "state": "active",
            "revision": OLD.source_sha,
            "release_digest": OLD.policy_bundle_digest,
            "activated_at": "2026-09-05T00:00:00Z",
        }
    ).encode()
    status_path.write_bytes(legacy_bytes)
    store = ActivationStateStore(status_path)
    envelope = _envelope(
        expected_generation=0,
        expected_status_digest=hashlib.sha256(legacy_bytes).hexdigest(),
    )

    with pytest.raises(ControllerActivationError, match="config"):
        store.reserve(
            envelope,
            allow_legacy_import=True,
            observed_image_digest=OLD.image_digest,
            observed_config_digest="f" * 64,
        )
    assert status_path.read_bytes() == legacy_bytes

    with pytest.raises(ControllerActivationError, match="legacy.*not exact"):
        store.reserve(
            envelope,
            allow_legacy_import=True,
            observed_image_digest="f" * 64,
            observed_config_digest=OLD_CONFIG,
        )
    assert status_path.read_bytes() == legacy_bytes

    assert (
        store.reserve(
            envelope,
            allow_legacy_import=True,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )
        == "new"
    )
    migrated = store.read_status()
    assert migrated.mapping()["schema"] == STATUS_SCHEMA
    assert migrated.generation == 0
    assert migrated.current == OLD


def test_measured_bootstrap_creates_the_exact_signed_activation_status(
    tmp_path: Path,
) -> None:
    measured_path = tmp_path / "measured-controller-release.json"
    measured_path.write_text(json.dumps(_measured_status(OLD)), encoding="utf-8")
    activated_at = datetime(2026, 9, 5, 1, tzinfo=UTC)
    bootstrap_status = ControllerReleaseStatus(
        generation=0,
        current=OLD,
        previous=None,
        transaction_id="bootstrap:transaction-0001",
        activated_at=activated_at,
    )
    expected_status_digest = hashlib.sha256(
        json.dumps(
            bootstrap_status.mapping(),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        + b"\n"
    ).hexdigest()
    envelope = _envelope(
        expected_generation=0,
        expected_status_digest=expected_status_digest,
    )
    store = ActivationStateStore(tmp_path / "controller-activation.json")

    bootstrapped = store.bootstrap_from_measured(
        envelope,
        measured_status_path=measured_path,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )

    assert bootstrapped == bootstrap_status
    assert hashlib.sha256(store.status_path.read_bytes()).hexdigest() == expected_status_digest
    assert (
        store.reserve(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )
        == "new"
    )


def test_finalize_requires_equal_local_and_public_measured_identity(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    committed = store.commit(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
    )
    local = MeasuredControllerReleaseStatus.parse(_measured_status(NEW))
    foreign_public = MeasuredControllerReleaseStatus.parse(
        _measured_status(NEW, release_digest="f" * 64)
    )

    with pytest.raises(ControllerActivationError, match="public measured"):
        store.finalize_measured(
            envelope,
            measured_status=local,
            public_status=foreign_public,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
        )
    assert store.transaction_path.exists()

    finalized = store.finalize_measured(
        envelope,
        measured_status=local,
        public_status=local,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
    )
    assert finalized == committed
    assert not store.transaction_path.exists()


def test_finalize_measured_requires_signed_candidate_release_digest(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    store.commit(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
    )
    forged = MeasuredControllerReleaseStatus.parse(_measured_status(NEW, release_digest="f" * 64))

    with pytest.raises(ControllerActivationError, match="release does not prove"):
        store.finalize_measured(
            envelope,
            measured_status=forged,
            public_status=forged,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
        )
    assert store.transaction_path.exists()


def test_historical_finalize_binds_exact_v1_revision_release_and_runtime(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    committed = store.commit(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
    )
    historical = LegacyMeasuredControllerReleaseStatus.parse(
        {
            "schema": LEGACY_STATUS_SCHEMA,
            "state": "active",
            "revision": NEW.source_sha,
            "release_digest": CANDIDATE_RELEASE_DIGEST,
            "activated_at": "2026-09-05T01:00:00Z",
        }
    )

    finalized = store.finalize_historical(
        envelope,
        measured_status=historical,
        public_status=historical,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
    )

    assert finalized == committed
    assert not store.transaction_path.exists()


def test_historical_finalize_rejects_wrong_release_digest(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    store.commit(
        envelope,
        observed_image_digest=NEW.image_digest,
        observed_config_digest=NEW_CONFIG,
    )
    forged = LegacyMeasuredControllerReleaseStatus.parse(
        {
            "schema": LEGACY_STATUS_SCHEMA,
            "state": "active",
            "revision": NEW.source_sha,
            "release_digest": "f" * 64,
            "activated_at": "2026-09-05T01:00:00Z",
        }
    )

    with pytest.raises(ControllerActivationError, match="release does not prove"):
        store.finalize_historical(
            envelope,
            measured_status=forged,
            public_status=forged,
            observed_image_digest=NEW.image_digest,
            observed_config_digest=NEW_CONFIG,
        )
    assert store.transaction_path.exists()


def test_legacy_import_can_seed_separate_v2_without_mutating_v1(tmp_path: Path) -> None:
    legacy_path = tmp_path / "controller-release-v1.json"
    legacy_bytes = (
        json.dumps(
            {
                "schema": LEGACY_STATUS_SCHEMA,
                "state": "active",
                "revision": OLD.source_sha,
                "release_digest": OLD.policy_bundle_digest,
                "activated_at": "2026-09-05T00:00:00Z",
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()
    legacy_path.write_bytes(legacy_bytes)
    v2_path = tmp_path / "controller-release-v2.json"
    store = ActivationStateStore(v2_path)
    envelope = _envelope(
        expected_generation=0,
        expected_status_digest=hashlib.sha256(legacy_bytes).hexdigest(),
    )

    with pytest.raises(ControllerActivationError, match="config"):
        store.reserve(
            envelope,
            allow_legacy_import=True,
            legacy_status_path=legacy_path,
            observed_image_digest=OLD.image_digest,
            observed_config_digest="f" * 64,
        )
    assert not v2_path.exists()
    assert legacy_path.read_bytes() == legacy_bytes

    assert (
        store.reserve(
            envelope,
            allow_legacy_import=True,
            legacy_status_path=legacy_path,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )
        == "new"
    )
    assert store.read_status().generation == 0
    assert store.read_status().current == OLD
    assert legacy_path.read_bytes() == legacy_bytes


def test_status_rejects_unknown_fields_and_invalid_previous_generation() -> None:
    value = _status().mapping()
    with pytest.raises(ControllerActivationError, match="shape"):
        ControllerReleaseStatus.parse({**value, "unexpected": True})

    invalid = dict(value)
    invalid["previous"] = {"generation": 7, **OLD.mapping()}
    with pytest.raises(ControllerActivationError, match="previous generation"):
        ControllerReleaseStatus.parse(invalid)


def test_state_store_rejects_group_writable_status_and_transaction(tmp_path: Path) -> None:
    store = _store(tmp_path)
    envelope = _envelope()
    store.status_path.chmod(0o664)
    with pytest.raises(ControllerActivationError, match="state is unsafe"):
        store.reserve(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )

    store.status_path.chmod(0o644)
    store.reserve(
        envelope,
        observed_image_digest=OLD.image_digest,
        observed_config_digest=OLD_CONFIG,
    )
    store.transaction_path.chmod(0o660)
    with pytest.raises(ControllerActivationError, match="state is unsafe"):
        store.assert_current(
            envelope,
            observed_image_digest=OLD.image_digest,
            observed_config_digest=OLD_CONFIG,
        )
