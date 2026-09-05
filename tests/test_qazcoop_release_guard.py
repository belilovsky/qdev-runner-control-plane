from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType

import pytest

from qdev_runner import controller_admission
from qdev_runner.controller_admission import initialize_keypair, sign_payload
from qdev_runner.qazcoop_release_guard import (
    CONTROLLER_PATH,
    PAYLOAD_PATH,
    QazCoopReleaseGuardError,
    verify_qazcoop_admission,
)

CONTROLLER_REVISION = "c" * 40
BRANCH = "refs/heads/codex/qazcoop-mvp"


def _hook_module() -> ModuleType:
    path = Path(__file__).parents[1] / "scripts/qazcoop_update_hook.py"
    spec = importlib.util.spec_from_file_location("qazcoop_update_hook_test", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603
        ["/usr/bin/git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _trust_bundle(tmp_path: Path, public_key: Path) -> tuple[Path, Path, Path]:
    trust = tmp_path / "trust"
    trust.mkdir()
    public = trust / "public.pem"
    public.write_bytes(public_key.read_bytes())
    schema = trust / "admission.schema.json"
    schema.write_text("{}\n", encoding="utf-8")
    launcher = tmp_path / "qdev-controller-verify-admission"
    launcher.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    hook = tmp_path / "qazcoop-update"
    hook.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    launcher.chmod(0o755)
    hook.chmod(0o755)
    files = {
        "public.pem": _digest(public),
        "admission.schema.json": _digest(schema),
        "controller_admission.py": _digest(Path(controller_admission.__file__)),
        "qazcoop_release_guard.py": _digest(
            Path(__file__).parents[1] / "src/qdev_runner/qazcoop_release_guard.py"
        ),
        "qdev-controller-verify-admission": _digest(launcher),
        "qazcoop-update": _digest(hook),
    }
    _write_json(
        trust / "bundle.json",
        {
            "contract": "qazcoop-release-guard-trust-bundle/v1",
            "controller_revision": CONTROLLER_REVISION,
            "repository": {
                "id": 1_357_887_516,
                "full_name": "belilovsky/qazcoop",
                "protected_ref": BRANCH,
            },
            "files": files,
        },
    )
    return trust, launcher, hook


def _release_payload(functional_sha: str, manifest: dict[str, object]) -> dict[str, object]:
    files = manifest["files"]
    assert isinstance(files, dict)
    return {
        "contract": "qazcoop-release-receipt-payload/v3",
        "status": "release_ready",
        "scope": "private_technical_contour",
        "functional_source_sha": functional_sha,
        "artifact_identity": {
            "application_image_digest": "sha256:" + "1" * 64,
            "retention_image_digest": "sha256:" + "2" * 64,
            "migration_head": "0008_security",
            "edge_config_sha256": "sha256:" + "3" * 64,
        },
        "browser_acceptance": {
            "observed_source_sha": functional_sha,
            "status": "verified",
            "artifact": "browser.jsonl",
            "artifact_sha256": "sha256:" + "4" * 64,
            "routes_total": 24,
            "batch_checked": 24,
            "browser_cases": 960,
            "passed": 944,
            "failed": 0,
            "auth_blocked": 0,
            "not_applicable": 16,
            "acceptance_rule": "all mandatory private cells must pass",
        },
        "restore": {
            "observed_source_sha": functional_sha,
            "status": "verified",
            "backup_id": "backup-20260905",
            "backup_sha256": "sha256:" + "5" * 64,
            "receipt_sha256": "sha256:" + "6" * 64,
            "control_document_sha256": "sha256:" + "7" * 64,
            "measured_rpo_seconds": 3600,
            "measured_rto_seconds": 600,
            "evidence_gap": None,
        },
        "previous_release": {
            "functional_source_sha": "a" * 40,
            "application_image_digest": "sha256:" + "8" * 64,
            "evidence_status": "unsafe_for_authz_rollback",
        },
        "rollback": {
            "status": "verified",
            "application_image_digest": "sha256:" + "9" * 64,
            "retention_image_digest": "sha256:" + "a" * 64,
            "historical_tags": ["qazcoop-app:rollback-safe"],
            "reason": "first image after tenant isolation closure",
        },
        "controller_admission": {
            "status": "external_required",
            "contract_path": CONTROLLER_PATH,
            "admission_id": "admission-qazcoop-20260905",
        },
        "supply_chain": {
            "sbom_sha256": "sha256:" + "b" * 64,
            "provenance_sha256": "sha256:" + "c" * 64,
            "status": "verified",
        },
    }


def _controller(functional_sha: str, manifest: dict[str, object]) -> dict[str, object]:
    files = manifest["files"]
    assert isinstance(files, dict)
    return {
        "contract": "qdev-ci-controller-admission/v1",
        "project_id": "qazcoop",
        "repository": "belilovsky/qazcoop",
        "protected_branch": "codex/qazcoop-mvp",
        "requested_functional_source_sha": functional_sha,
        "required_profiles": [
            "reuse-first",
            "postgres-migrations",
            "container-supply-chain",
        ],
        "registration_status": "confirmed",
        "admission_status": "external_required",
        "admission_id": "admission-qazcoop-20260905",
        "external_verifier": {
            "delivery": "root_owned_controller_bundle",
            "protected_environment": "qazcoop-release-admission",
            "controller_repository": "belilovsky/qdev-runner-control-plane",
            "controller_revision": CONTROLLER_REVISION,
            "bundle_contract": "qazcoop-release-guard-trust-bundle/v1",
        },
        "trust": {
            "signature_algorithm": "ed25519",
            "trust_root_id": "qdev-ci-controller-production-v1",
            "verifier_sha256": files["qazcoop_release_guard.py"],
            "schema_sha256": files["admission.schema.json"],
            "public_key_sha256": files["public.pem"],
            "public_key_mirror_path": "app/contracts/trust/qdev-ci-controller-ed25519.pub",
        },
        "evidence_gap": None,
        "claim_boundary": "external signed controller admission is authoritative",
    }


def _repository(tmp_path: Path, trust: Path) -> tuple[Path, str, str]:
    repository = tmp_path / "repository"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.email", "controller@example.invalid")
    _git(repository, "config", "user.name", "Controller Test")
    (repository / "functional.txt").write_text("functional\n", encoding="utf-8")
    public_mirror = repository / "app/contracts/trust/qdev-ci-controller-ed25519.pub"
    public_mirror.parent.mkdir(parents=True, exist_ok=True)
    public_mirror.write_bytes((trust / "public.pem").read_bytes())
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "functional")
    functional_sha = _git(repository, "rev-parse", "HEAD")
    manifest = json.loads((trust / "bundle.json").read_text(encoding="utf-8"))
    _write_json(repository / PAYLOAD_PATH, _release_payload(functional_sha, manifest))
    _write_json(repository / CONTROLLER_PATH, _controller(functional_sha, manifest))
    _git(repository, "add", PAYLOAD_PATH, CONTROLLER_PATH)
    _git(repository, "commit", "-m", "evidence")
    return repository, functional_sha, _git(repository, "rev-parse", "HEAD")


def _signed_receipt(functional_sha: str, private_key: Path) -> dict[str, object]:
    now = datetime.now(UTC)
    return sign_payload(
        {
            "repository": {"id": 1_357_887_516, "full_name": "belilovsky/qazcoop"},
            "protected_ref": BRANCH,
            "functional_source_sha": functional_sha,
            "workflow": {"run_id": 1001, "run_attempt": 1},
            "required_jobs": [
                {
                    "name": "reuse-first",
                    "controller_profile": "qdev-ci",
                    "job_id": 2001,
                    "conclusion": "success",
                },
                {
                    "name": "postgres-migrations",
                    "controller_profile": "qdev-ci-docker",
                    "job_id": 2002,
                    "conclusion": "success",
                },
                {
                    "name": "container-supply-chain",
                    "controller_profile": "qdev-ci-docker",
                    "job_id": 2003,
                    "conclusion": "success",
                },
            ],
            "controller_revision": CONTROLLER_REVISION,
            "admission": {
                "id": "admission-qazcoop-20260905",
                "claim_id": "claim-qazcoop-20260905",
            },
            "issued_at": (now - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "expires_at": (now + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        private_key,
    )


def test_guard_verifies_and_consumes_exact_signed_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    initialize_keypair(private, public)
    trust, launcher, hook = _trust_bundle(tmp_path, public)
    repository, functional_sha, evidence_sha = _repository(tmp_path, trust)
    receipt_dir = tmp_path / "receipts"
    receipt_dir.mkdir()
    _write_json(
        receipt_dir / "admission-qazcoop-20260905.json",
        _signed_receipt(functional_sha, private),
    )
    monkeypatch.setenv("QAZCOOP_GUARD_LAUNCHER", str(launcher))
    monkeypatch.setenv("QAZCOOP_GUARD_HOOK", str(hook))

    result = verify_qazcoop_admission(
        repository=repository,
        protected_ref=BRANCH,
        evidence_commit_sha=evidence_sha,
        require_authoritative=True,
        trust_dir=trust,
        receipt_dir=receipt_dir,
        replay_store=tmp_path / "consumed.sqlite3",
    )
    assert result["state"] == "admission_consumed"
    with pytest.raises(
        controller_admission.ControllerAdmissionError, match="already been consumed"
    ):
        verify_qazcoop_admission(
            repository=repository,
            protected_ref=BRANCH,
            evidence_commit_sha=evidence_sha,
            require_authoritative=True,
            trust_dir=trust,
            receipt_dir=receipt_dir,
            replay_store=tmp_path / "consumed.sqlite3",
        )


def test_guard_rejects_tampered_installed_hook(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    initialize_keypair(private, public)
    trust, launcher, hook = _trust_bundle(tmp_path, public)
    repository, _functional_sha, evidence_sha = _repository(tmp_path, trust)
    hook.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    monkeypatch.setenv("QAZCOOP_GUARD_LAUNCHER", str(launcher))
    monkeypatch.setenv("QAZCOOP_GUARD_HOOK", str(hook))

    with pytest.raises(QazCoopReleaseGuardError, match="trusted file digest mismatch"):
        verify_qazcoop_admission(
            repository=repository,
            protected_ref=BRANCH,
            evidence_commit_sha=evidence_sha,
            require_authoritative=False,
            trust_dir=trust,
            receipt_dir=tmp_path / "unused",
            replay_store=tmp_path / "unused.sqlite3",
        )


def test_guard_rejects_evidence_commit_with_extra_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    initialize_keypair(private, public)
    trust, launcher, hook = _trust_bundle(tmp_path, public)
    repository, _functional_sha, _evidence_sha = _repository(tmp_path, trust)
    (repository / "extra.txt").write_text("untrusted\n", encoding="utf-8")
    _git(repository, "add", "extra.txt")
    _git(repository, "commit", "--amend", "--no-edit")
    monkeypatch.setenv("QAZCOOP_GUARD_LAUNCHER", str(launcher))
    monkeypatch.setenv("QAZCOOP_GUARD_HOOK", str(hook))

    with pytest.raises(QazCoopReleaseGuardError, match="outside the exact allowlist"):
        verify_qazcoop_admission(
            repository=repository,
            protected_ref=BRANCH,
            evidence_commit_sha=_git(repository, "rev-parse", "HEAD"),
            require_authoritative=False,
            trust_dir=trust,
            receipt_dir=tmp_path / "unused",
            replay_store=tmp_path / "unused.sqlite3",
        )


def test_update_hook_rejects_lock_receipt_mismatch_before_verifier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repository = tmp_path / "bare.git"
    worktree = tmp_path / "worktree"
    _git(tmp_path, "init", "--bare", str(repository))
    _git(tmp_path, "init", str(worktree))
    _git(worktree, "config", "user.email", "controller@example.invalid")
    _git(worktree, "config", "user.name", "Controller Test")
    old_source = "a" * 40
    _write_json(
        worktree / "app/contracts/release_lock.v1.json",
        {
            "contract": "qazcoop-release-lock/v1",
            "status": "active",
            "functional_source_sha": old_source,
            "public_marker": f"qazcoop-{old_source[:7]}",
        },
    )
    _git(worktree, "add", ".")
    _git(worktree, "commit", "-m", "old")
    old = _git(worktree, "rev-parse", "HEAD")
    new_source = "b" * 40
    _write_json(
        worktree / "app/contracts/release_lock.v1.json",
        {
            "contract": "qazcoop-release-lock/v1",
            "status": "active",
            "functional_source_sha": new_source,
            "public_marker": f"qazcoop-{new_source[:7]}",
        },
    )
    _write_json(
        worktree / PAYLOAD_PATH,
        {"functional_source_sha": "c" * 40, "status": "release_ready"},
    )
    _git(worktree, "add", ".")
    _git(worktree, "commit", "-m", "candidate")
    new = _git(worktree, "rev-parse", "HEAD")
    _git(worktree, "push", str(repository), f"{new}:{BRANCH}")

    hook = _hook_module()
    verifier_called = False

    original_run = subprocess.run

    def observed_run(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        nonlocal verifier_called
        command = args[0]
        if isinstance(command, list) and command and str(command[0]).endswith(
            "qdev-controller-verify-admission"
        ):
            verifier_called = True
            return subprocess.CompletedProcess(command, 0, "", "")
        return original_run(*args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(hook.subprocess, "run", observed_run)
    with pytest.raises(hook.GuardError, match="release lock and evidence source differ"):
        hook.validate_update(repository, BRANCH, old, new)
    assert verifier_called is False
