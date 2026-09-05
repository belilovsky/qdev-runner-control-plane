from __future__ import annotations

import hashlib
import os
import shutil
import stat
from pathlib import Path

import pytest

from qdev_runner.admin_platform import AdminPlatformCandidate, AdminPlatformLedger
from qdev_runner.admin_platform_state import (
    AdminPlatformStateError,
    AdminPlatformStateStore,
)
from qdev_runner.operations import OperationStore

RECEIPT_KEY = "admin-platform-state-test-key"
CONTROLLER_SHA = "21b23e25ed45a547ad460e4bc412a4949a909c3f"
CONTROLLER_RELEASE = "controller-v3-21b23e25"


def _seed_path() -> Path:
    return Path(__file__).parents[1] / "config" / "admin-platform-ledger-v2.yml"


def _state(tmp_path: Path) -> tuple[AdminPlatformStateStore, OperationStore]:
    ledger_path = tmp_path / "state" / "admin-platform-ledger.yml"
    ledger_path.parent.mkdir()
    shutil.copyfile(_seed_path(), ledger_path)
    state = AdminPlatformStateStore(
        ledger_path,
        receipt_key=RECEIPT_KEY,
        receipt_root=ledger_path.parent / "receipts",
    )
    signer = OperationStore(
        tmp_path / "operations",
        worker_signing_key="unused-worker-key",
        receipt_signing_key=RECEIPT_KEY,
    )
    return state, signer


def _uninitialized_state(
    tmp_path: Path,
) -> tuple[AdminPlatformStateStore, OperationStore, Path]:
    ledger_path = tmp_path / "state" / "admin-platform-ledger.yml"
    ledger_path.parent.mkdir()
    state = AdminPlatformStateStore(
        ledger_path,
        receipt_key=RECEIPT_KEY,
        receipt_root=ledger_path.parent / "receipts",
    )
    signer = OperationStore(
        tmp_path / "operations",
        worker_signing_key="unused-worker-key",
        receipt_signing_key=RECEIPT_KEY,
    )
    return state, signer, ledger_path


def _receipt(
    signer: OperationStore,
    *,
    observed_at: str,
    lane: str | None,
    outcome: str,
    stage: str = "controller",
    release_id: str = CONTROLLER_RELEASE,
    source_sha: str = CONTROLLER_SHA,
    evidence_type: str = "lane_result",
) -> dict[str, object]:
    return signer.receipt(
        {
            "kind": "admin-platform-evidence",
            "observed_at": observed_at,
            "program_id": "qdev-admin-platform-wave-1",
            "stage": stage,
            "release_id": release_id,
            "source_sha": source_sha,
            "evidence_type": evidence_type,
            "lane": lane,
            "outcome": outcome,
        }
    )


def _record(
    state: AdminPlatformStateStore,
    signer: OperationStore,
    digest: str,
    *,
    observed_at: str,
    lane: str,
    outcome: str,
) -> str:
    return state.record_result(
        expected_sha256=digest,
        receipt=_receipt(
            signer,
            observed_at=observed_at,
            lane=lane,
            outcome=outcome,
        ),
    ).ledger_sha256


def _controller_candidate(
    *,
    release_id: str = CONTROLLER_RELEASE,
    source_sha: str = CONTROLLER_SHA,
) -> AdminPlatformCandidate:
    return AdminPlatformCandidate(
        release_id=release_id,
        repository="belilovsky/qdev-runner-control-plane",
        source_sha=source_sha,
        reference="refs/heads/codex/admin-platform-controller-v3-20260905",
    )


def test_state_store_initializes_missing_v3_state_from_exact_source_receipt(
    tmp_path: Path,
) -> None:
    state, signer, ledger_path = _uninitialized_state(tmp_path)
    candidate = _controller_candidate()
    source_receipt = _receipt(
        signer,
        observed_at="2026-09-05T00:01:00Z",
        lane="source",
        outcome="passed",
    )

    initialized = state.initialize_from_template(
        template_path=_seed_path(),
        candidate=candidate,
        source_receipt=source_receipt,
    )

    assert initialized.previous_sha256 == hashlib.sha256(b"").hexdigest()
    assert initialized.active_stage == "controller"
    assert initialized.active_status == "candidate"
    assert initialized.migration_archive_uri is None
    assert len(initialized.receipt_uris) == 1
    ledger = AdminPlatformLedger(
        ledger_path,
        receipt_key=RECEIPT_KEY,
        receipt_root=ledger_path.parent / "receipts",
    )
    ledger.validate_admission(
        "controller",
        CONTROLLER_SHA,
    )

    unchanged = state.initialize_from_template(
        template_path=_seed_path(),
        candidate=candidate,
        source_receipt=source_receipt,
    )
    assert unchanged.previous_sha256 == initialized.ledger_sha256
    assert unchanged.ledger_sha256 == initialized.ledger_sha256
    assert unchanged.receipt_uris == ()


def test_state_store_refuses_to_replace_a_different_initialized_v3_candidate(
    tmp_path: Path,
) -> None:
    state, signer, _ = _uninitialized_state(tmp_path)
    state.initialize_from_template(
        template_path=_seed_path(),
        candidate=_controller_candidate(),
        source_receipt=_receipt(
            signer,
            observed_at="2026-09-05T00:01:00Z",
            lane="source",
            outcome="passed",
        ),
    )
    replacement_sha = "d" * 40
    replacement_release = "controller-v3-replacement"

    with pytest.raises(
        AdminPlatformStateError,
        match="initialized admin platform candidate does not match",
    ):
        state.initialize_from_template(
            template_path=_seed_path(),
            candidate=_controller_candidate(
                release_id=replacement_release,
                source_sha=replacement_sha,
            ),
            source_receipt=_receipt(
                signer,
                observed_at="2026-09-05T00:02:00Z",
                lane="source",
                outcome="passed",
                release_id=replacement_release,
                source_sha=replacement_sha,
            ),
        )


def test_state_store_requires_explicit_legacy_migration_and_archives_exact_bytes(
    tmp_path: Path,
) -> None:
    state, signer, ledger_path = _uninitialized_state(tmp_path)
    legacy_path = Path(__file__).parents[1] / "config" / "admin-platform-ledger.yml"
    legacy_raw = legacy_path.read_bytes()
    ledger_path.write_bytes(legacy_raw)
    source_receipt = _receipt(
        signer,
        observed_at="2026-09-05T00:01:00Z",
        lane="source",
        outcome="passed",
    )

    with pytest.raises(
        AdminPlatformStateError,
        match="legacy admin platform ledger migration was not authorized",
    ):
        state.initialize_from_template(
            template_path=_seed_path(),
            candidate=_controller_candidate(),
            source_receipt=source_receipt,
        )

    archive_root = tmp_path / "migration-archive"
    initialized = state.initialize_from_template(
        template_path=_seed_path(),
        candidate=_controller_candidate(),
        source_receipt=source_receipt,
        allow_legacy_migration=True,
        migration_archive_root=archive_root,
    )

    assert initialized.migration_archive_uri is not None
    archive_path = Path(initialized.migration_archive_uri)
    assert archive_path.parent == archive_root
    assert archive_path.read_bytes() == legacy_raw
    assert hashlib.sha256(archive_path.read_bytes()).hexdigest() in archive_path.name
    AdminPlatformLedger(
        ledger_path,
        receipt_key=RECEIPT_KEY,
        receipt_root=ledger_path.parent / "receipts",
    )


def test_state_store_refuses_a_symlink_durable_ledger(tmp_path: Path) -> None:
    state, signer, ledger_path = _uninitialized_state(tmp_path)
    target = tmp_path / "outside.yml"
    target.write_bytes(_seed_path().read_bytes())
    ledger_path.symlink_to(target)

    with pytest.raises(AdminPlatformStateError, match="durable admin platform ledger is unsafe"):
        state.initialize_from_template(
            template_path=_seed_path(),
            candidate=_controller_candidate(),
            source_receipt=_receipt(
                signer,
                observed_at="2026-09-05T00:01:00Z",
                lane="source",
                outcome="passed",
            ),
        )


def test_state_store_applies_exact_runtime_owner_and_private_modes(
    tmp_path: Path,
) -> None:
    state, signer, ledger_path = _uninitialized_state(tmp_path)
    state = AdminPlatformStateStore(
        ledger_path,
        receipt_key=RECEIPT_KEY,
        receipt_root=ledger_path.parent / "receipts",
        file_uid=os.getuid(),
        file_gid=os.getgid(),
    )

    initialized = state.initialize_from_template(
        template_path=_seed_path(),
        candidate=_controller_candidate(),
        source_receipt=_receipt(
            signer,
            observed_at="2026-09-05T00:01:00Z",
            lane="source",
            outcome="passed",
        ),
    )

    assert stat.S_IMODE(ledger_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(state.lock_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(state.receipt_root.stat().st_mode) == 0o700
    receipt_path = ledger_path.parent / initialized.receipt_uris[0]
    assert stat.S_IMODE(receipt_path.stat().st_mode) == 0o600


def test_state_store_atomically_accepts_and_advances_one_stage(tmp_path: Path) -> None:
    state, signer = _state(tmp_path)
    digest, _ = state.current()

    digest = _record(
        state,
        signer,
        digest,
        observed_at="2026-09-05T00:01:00Z",
        lane="source",
        outcome="passed",
    )
    stale_digest = hashlib.sha256(_seed_path().read_bytes()).hexdigest()
    with pytest.raises(AdminPlatformStateError, match="compare-and-swap conflict"):
        _record(
            state,
            signer,
            stale_digest,
            observed_at="2026-09-05T00:02:00Z",
            lane="ci",
            outcome="queued",
        )

    for observed_at, lane, outcome in (
        ("2026-09-05T00:02:00Z", "ci", "queued"),
        ("2026-09-05T00:03:00Z", "ci", "passed"),
        ("2026-09-05T00:04:00Z", "publication", "passed"),
        ("2026-09-05T00:05:00Z", "deploy", "queued"),
        ("2026-09-05T00:06:00Z", "deploy", "passed"),
        ("2026-09-05T00:07:00Z", "browser", "passed"),
        ("2026-09-05T00:08:00Z", "rollback", "passed"),
        ("2026-09-05T00:09:00Z", "observation", "passed"),
    ):
        digest = _record(
            state,
            signer,
            digest,
            observed_at=observed_at,
            lane=lane,
            outcome=outcome,
        )

    avds_sha = "b" * 40
    avds_release = "avds-admin-shell-0.2.2-test"
    update = state.accept_and_advance(
        expected_sha256=digest,
        terminal_receipt=_receipt(
            signer,
            observed_at="2026-09-05T00:10:00Z",
            lane=None,
            outcome="live_accepted",
            evidence_type="attempt_terminal",
        ),
        next_candidate=AdminPlatformCandidate(
            release_id=avds_release,
            repository="belilovsky/av-platform-core",
            source_sha=avds_sha,
            reference="refs/heads/codex/avds-admin-shell-0.2.2-test",
        ),
        next_source_receipt=_receipt(
            signer,
            observed_at="2026-09-05T00:11:00Z",
            lane="source",
            outcome="passed",
            stage="avds-admin-shell",
            release_id=avds_release,
            source_sha=avds_sha,
        ),
    )

    assert update.active_stage == "avds-admin-shell"
    assert update.active_status == "candidate"
    assert len(update.receipt_uris) == 2
    current_digest, snapshot = state.current()
    assert current_digest == update.ledger_sha256
    assert snapshot["active_stage"] == "avds-admin-shell"
    entries = {entry["entry_id"]: entry for entry in snapshot["entries"]}
    assert entries["controller"]["status"] == "live_accepted"
    assert entries["avds-admin-shell"]["status"] == "candidate"
    AdminPlatformLedger(
        tmp_path / "state" / "admin-platform-ledger.yml",
        receipt_key=RECEIPT_KEY,
        receipt_root=tmp_path / "state" / "receipts",
    )


def test_state_store_finishes_and_restarts_without_erasing_attempt_history(
    tmp_path: Path,
) -> None:
    state, signer = _state(tmp_path)
    digest, _ = state.current()
    digest = _record(
        state,
        signer,
        digest,
        observed_at="2026-09-05T00:01:00Z",
        lane="source",
        outcome="passed",
    )
    digest = _record(
        state,
        signer,
        digest,
        observed_at="2026-09-05T00:02:00Z",
        lane="ci",
        outcome="queued",
    )
    finished = state.finish_attempt(
        expected_sha256=digest,
        result_receipt=_receipt(
            signer,
            observed_at="2026-09-05T00:03:00Z",
            lane="ci",
            outcome="failed",
        ),
        terminal_receipt=_receipt(
            signer,
            observed_at="2026-09-05T00:04:00Z",
            lane=None,
            outcome="blocked",
            evidence_type="attempt_terminal",
        ),
    )
    assert finished.active_status == "blocked"

    retry_sha = "c" * 40
    retry = AdminPlatformCandidate(
        release_id="controller-v3-retry-2",
        repository="belilovsky/qdev-runner-control-plane",
        source_sha=retry_sha,
        reference="refs/heads/codex/admin-platform-controller-v3-retry-2",
    )
    restarted = state.restart_attempt(
        expected_sha256=finished.ledger_sha256,
        candidate=retry,
        source_receipt=_receipt(
            signer,
            observed_at="2026-09-05T00:05:00Z",
            lane="source",
            outcome="passed",
            release_id=retry.release_id,
            source_sha=retry.source_sha,
        ),
    )

    assert restarted.active_status == "candidate"
    _, snapshot = state.current()
    controller = snapshot["entries"][0]
    assert [attempt["release_id"] for attempt in controller["attempts"]] == [
        CONTROLLER_RELEASE,
        retry.release_id,
    ]
    assert controller["attempts"][0]["terminal_state"] == "blocked"
    assert controller["attempts"][1]["terminal_state"] is None


def test_state_store_rejects_tampered_receipt_and_symlink_receipt_root(
    tmp_path: Path,
) -> None:
    state, signer = _state(tmp_path)
    digest, _ = state.current()
    receipt = _receipt(
        signer,
        observed_at="2026-09-05T00:01:00Z",
        lane="source",
        outcome="passed",
    )
    receipt["signature"] = "0" * 64
    with pytest.raises(AdminPlatformStateError, match="evidence receipt is invalid"):
        state.record_result(expected_sha256=digest, receipt=receipt)

    unsafe_root = tmp_path / "unsafe-receipts"
    unsafe_root.symlink_to(tmp_path / "operations", target_is_directory=True)
    unsafe_state = AdminPlatformStateStore(
        tmp_path / "state" / "admin-platform-ledger.yml",
        receipt_key=RECEIPT_KEY,
        receipt_root=unsafe_root,
    )
    with pytest.raises(AdminPlatformStateError, match="receipt root is unavailable"):
        unsafe_state.record_result(
            expected_sha256=digest,
            receipt=_receipt(
                signer,
                observed_at="2026-09-05T00:01:00Z",
                lane="source",
                outcome="passed",
            ),
        )


def test_state_store_rejects_a_lane_result_after_terminal_time(tmp_path: Path) -> None:
    state, signer = _state(tmp_path)
    digest, _ = state.current()
    with pytest.raises(AdminPlatformStateError, match="follows its terminal receipt"):
        state.finish_attempt(
            expected_sha256=digest,
            result_receipt=_receipt(
                signer,
                observed_at="2026-09-05T00:03:00.100000Z",
                lane="source",
                outcome="blocked",
            ),
            terminal_receipt=_receipt(
                signer,
                observed_at="2026-09-05T00:03:00Z",
                lane=None,
                outcome="blocked",
                evidence_type="attempt_terminal",
            ),
        )
