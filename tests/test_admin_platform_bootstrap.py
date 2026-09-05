from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from qdev_runner.admin_platform import AdminPlatformLedger

ROOT = Path(__file__).resolve().parents[1]
GIT = shutil.which("git")
assert GIT is not None
RECEIPT_KEY = "bootstrap-test-receipt-key"


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603
        [GIT, *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _release(tmp_path: Path) -> tuple[Path, str]:
    release = tmp_path / "release"
    (release / "config").mkdir(parents=True)
    shutil.copyfile(
        ROOT / "config" / "admin-platform-ledger-v2.yml",
        release / "config" / "admin-platform-ledger-v2.yml",
    )
    _git(release, "init", "-b", "main")
    _git(release, "config", "user.name", "Test")
    _git(release, "config", "user.email", "test@example.com")
    _git(release, "add", "config/admin-platform-ledger-v2.yml")
    _git(release, "commit", "-m", "controller release")
    return release, _git(release, "rev-parse", "HEAD")


def _invoke(
    release: Path,
    tmp_path: Path,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    environment["QDEV_OPERATOR_RECEIPT_KEY"] = RECEIPT_KEY
    environment["PYTHONPATH"] = str(ROOT / "src")
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(ROOT / "scripts" / "bootstrap_admin_platform_ledger_v3.py"),
            str(release),
            "--reference",
            "refs/heads/main",
            "--ledger",
            str(tmp_path / "durable" / "admin-platform-ledger.yml"),
            "--receipt-root",
            str(tmp_path / "durable" / "receipts"),
            "--migration-archive-root",
            str(tmp_path / "durable" / "migration-archive"),
            "--signer-state-root",
            str(tmp_path / "durable" / "signer"),
        ],
        cwd=ROOT,
        env=environment,
        check=False,
        capture_output=True,
        text=True,
    )


def test_bootstrap_binds_only_the_measured_clean_release(tmp_path: Path) -> None:
    release, source_sha = _release(tmp_path)

    result = _invoke(release, tmp_path)

    assert result.returncode == 0, result.stderr
    update = json.loads(result.stdout)
    assert update["active_stage"] == "controller"
    assert update["active_status"] == "candidate"
    assert update["migration_archive_uri"] is None
    ledger = AdminPlatformLedger(
        tmp_path / "durable" / "admin-platform-ledger.yml",
        receipt_key=RECEIPT_KEY,
        receipt_root=tmp_path / "durable" / "receipts",
    )
    assert ledger.active_candidate is not None
    assert ledger.active_candidate.source_sha == source_sha
    assert ledger.active_candidate.release_id == f"controller-v3-{source_sha[:12]}"
    ledger.validate_admission("controller", source_sha)

    idempotent = _invoke(release, tmp_path)
    assert idempotent.returncode == 0, idempotent.stderr
    assert json.loads(idempotent.stdout)["receipt_uris"] == []


def test_bootstrap_rejects_a_dirty_release_before_writing_state(tmp_path: Path) -> None:
    release, _ = _release(tmp_path)
    (release / "untracked.txt").write_text("not part of the release\n", encoding="utf-8")

    result = _invoke(release, tmp_path)

    assert result.returncode == 1
    assert "controller release contains uncommitted files" in result.stderr
    assert not (tmp_path / "durable" / "admin-platform-ledger.yml").exists()
