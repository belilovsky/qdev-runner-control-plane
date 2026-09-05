from __future__ import annotations

import errno
import hashlib
import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from qdev_runner.admin_platform import (
    AdminPlatformCandidate,
    AdminPlatformLedger,
    AdminPlatformLedgerError,
)
from qdev_runner.admin_platform_state import (
    AdminPlatformStateError,
    AdminPlatformStateStore,
)
from qdev_runner.controller_candidate import (
    REFERENCE,
    REPOSITORY,
    ControllerCandidateError,
    prepare_controller_candidate,
)
from qdev_runner.operations import OperationStore, parse_utc
from qdev_runner.operator import verify_controller_receipt

RECEIPT_KEY = "controller-candidate-test-receipt-key"
CURRENT_SHA = "8" * 40
INTERMEDIATE_SHA = "a" * 40
NEXT_SHA = "9" * 40
LATER_SHA = "b" * 40


def _template() -> Path:
    return Path(__file__).parents[1] / "config" / "admin-platform-ledger-v2.yml"


def _paths(tmp_path: Path) -> tuple[Path, Path, Path]:
    return (
        tmp_path / "state" / "admin-platform-ledger.yml",
        tmp_path / "state" / "receipts",
        tmp_path / "signer",
    )


def _signer(root: Path) -> OperationStore:
    return OperationStore(
        root,
        worker_signing_key=RECEIPT_KEY,
        receipt_signing_key=RECEIPT_KEY,
    )


def _evidence(
    signer: OperationStore,
    *,
    candidate: AdminPlatformCandidate,
    observed_at: str,
    evidence_type: str = "lane_result",
    lane: str | None = "source",
    outcome: str = "passed",
) -> dict[str, Any]:
    return signer.receipt(
        {
            "kind": "admin-platform-evidence",
            "observed_at": observed_at,
            "program_id": "qdev-admin-platform-wave-1",
            "stage": "controller",
            "release_id": candidate.release_id,
            "source_sha": candidate.source_sha,
            "evidence_type": evidence_type,
            "lane": lane,
            "outcome": outcome,
        }
    )


def _initialize(
    tmp_path: Path,
    *,
    observed_at: str = "2026-09-05T00:00:00Z",
) -> tuple[AdminPlatformStateStore, OperationStore, Path, Path, Path]:
    ledger, receipts, signer_root = _paths(tmp_path)
    state = AdminPlatformStateStore(
        ledger,
        receipt_key=RECEIPT_KEY,
        receipt_root=receipts,
    )
    signer = _signer(signer_root)
    current = AdminPlatformCandidate(
        release_id=f"controller-v3-{CURRENT_SHA}",
        repository=REPOSITORY,
        source_sha=CURRENT_SHA,
        reference="refs/heads/codex/previous-controller",
    )
    state.initialize_from_template(
        template_path=_template(),
        candidate=current,
        source_receipt=_evidence(
            signer,
            candidate=current,
            observed_at=observed_at,
        ),
    )
    return state, signer, ledger, receipts, signer_root


def _prepare(tmp_path: Path) -> dict[str, Any]:
    ledger, receipts, signer_root = _paths(tmp_path)
    return prepare_controller_candidate(
        source_sha=NEXT_SHA,
        expected_current_source_sha=CURRENT_SHA,
        receipt_key=RECEIPT_KEY,
        ledger_path=ledger,
        receipt_root=receipts,
        signer_state_root=signer_root,
    )


def test_prepare_controller_candidate_is_transactional_and_idempotent(
    tmp_path: Path,
) -> None:
    state, _, _, receipts, _ = _initialize(tmp_path)

    result = _prepare(tmp_path)

    assert result["status"] == "completed"
    assert result["candidate"] == {
        "release_id": f"controller-v3-{NEXT_SHA}",
        "repository": REPOSITORY,
        "source_sha": NEXT_SHA,
        "reference": REFERENCE,
    }
    assert result["previous_candidate"]["source_sha"] == CURRENT_SHA
    assert len(result["receipt_uris"]) == 3
    digest, snapshot = state.current()
    assert result["ledger_sha256"] == digest
    assert snapshot["active_candidate"] == result["candidate"]
    assert snapshot["program"]["status"] == "active"
    entry = snapshot["entries"][0]
    assert entry["status"] == "candidate"
    assert [attempt["source_sha"] for attempt in entry["attempts"]] == [
        CURRENT_SHA,
        NEXT_SHA,
    ]
    assert entry["attempts"][0]["terminal_state"] == "blocked"
    assert entry["attempts"][1]["terminal_state"] is None
    receipt_count = len(list(receipts.rglob("*.json")))

    replay = _prepare(tmp_path)

    assert replay["status"] == "already_completed"
    assert replay["receipt_uris"] == []
    assert replay["ledger_sha256"] == digest
    assert len(list(receipts.rglob("*.json"))) == receipt_count


def test_prepare_controller_candidate_resumes_after_terminal_transition(
    tmp_path: Path,
) -> None:
    state, signer, _, _, _ = _initialize(tmp_path)
    digest, snapshot = state.current()
    current = AdminPlatformCandidate(**snapshot["active_candidate"])
    finished = state.finish_attempt(
        expected_sha256=digest,
        result_receipt=_evidence(
            signer,
            candidate=current,
            observed_at="2026-09-05T00:00:01Z",
            lane="ci",
            outcome="blocked",
        ),
        terminal_receipt=_evidence(
            signer,
            candidate=current,
            observed_at="2026-09-05T00:00:01Z",
            evidence_type="attempt_terminal",
            lane=None,
            outcome="blocked",
        ),
    )

    result = _prepare(tmp_path)

    assert result["status"] == "completed"
    assert len(result["receipt_uris"]) == 1
    assert result["ledger_sha256"] != finished.ledger_sha256
    _, current_snapshot = state.current()
    assert current_snapshot["active_candidate"]["source_sha"] == NEXT_SHA


def test_restart_survives_commit_failure_without_enforced_orphan(
    tmp_path: Path,
) -> None:
    state, signer, ledger, receipts, _ = _initialize(tmp_path)
    digest, snapshot = state.current()
    current = AdminPlatformCandidate(**snapshot["active_candidate"])
    state.finish_attempt(
        expected_sha256=digest,
        result_receipt=_evidence(
            signer,
            candidate=current,
            observed_at="2026-09-05T00:00:01Z",
            lane="ci",
            outcome="blocked",
        ),
        terminal_receipt=_evidence(
            signer,
            candidate=current,
            observed_at="2026-09-05T00:00:01Z",
            evidence_type="attempt_terminal",
            lane=None,
            outcome="blocked",
        ),
    )
    before = ledger.read_bytes()
    root_receipts_before = sorted(receipts.glob("*.json"))

    with patch.object(
        AdminPlatformStateStore,
        "_commit_locked",
        side_effect=RuntimeError("simulated restart commit failure"),
    ), pytest.raises(RuntimeError, match="simulated restart commit failure"):
        _prepare(tmp_path)

    assert ledger.read_bytes() == before
    assert sorted(receipts.glob("*.json")) == root_receipts_before
    interrupted_transactions = sorted((receipts / "transactions").iterdir())
    assert len(interrupted_transactions) == 1
    orphan = json.loads(
        next(
            path
            for path in interrupted_transactions[0].glob("*.json")
            if path.name != "ledger-binding.json"
        ).read_text()
    )
    with pytest.raises(ValueError, match="requires committed ledger context"):
        verify_controller_receipt(orphan, receipt_key=RECEIPT_KEY)

    result = _prepare(tmp_path)

    assert result["status"] == "completed"
    assert len(result["receipt_uris"]) == 1
    assert len(list((receipts / "transactions").iterdir())) == 1
    _, recovered = state.current()
    assert recovered["active_candidate"]["source_sha"] == NEXT_SHA
    AdminPlatformLedger(
        ledger,
        receipt_key=RECEIPT_KEY,
        receipt_root=receipts,
    )


def test_prepare_controller_candidate_survives_commit_failure_without_split_state(
    tmp_path: Path,
) -> None:
    state, _, ledger, receipts, _ = _initialize(tmp_path)
    before = ledger.read_bytes()
    before_digest = hashlib.sha256(before).hexdigest()

    with patch.object(
        AdminPlatformStateStore,
        "_commit_locked",
        side_effect=RuntimeError("simulated commit failure"),
    ), pytest.raises(RuntimeError, match="simulated commit failure"):
        _prepare(tmp_path)

    with patch.object(
        AdminPlatformStateStore,
        "_commit_locked",
        side_effect=RuntimeError("simulated commit failure"),
    ), pytest.raises(RuntimeError, match="simulated commit failure"):
        _prepare(tmp_path)

    assert ledger.read_bytes() == before
    _, interrupted = state.current()
    assert interrupted["program"]["status"] == "active"
    assert interrupted["active_candidate"]["source_sha"] == CURRENT_SHA
    assert len(interrupted["entries"][0]["attempts"]) == 1
    interrupted_transactions = sorted((receipts / "transactions").iterdir())
    assert len(interrupted_transactions) == 1
    interrupted_binding = json.loads(
        (interrupted_transactions[0] / "ledger-binding.json").read_text()
    )["payload"]
    assert interrupted_binding["previous_ledger_sha256"] == before_digest
    assert interrupted_binding["target_ledger_sha256"] != before_digest
    assert all(
        receipt["receipt_uri"].encode() not in before
        for receipt in interrupted_binding["receipts"]
    )
    orphan = json.loads(
        next(
            path
            for path in interrupted_transactions[0].glob("*.json")
            if path.name != "ledger-binding.json"
        ).read_text()
    )
    with pytest.raises(ValueError, match="requires committed ledger context"):
        verify_controller_receipt(orphan, receipt_key=RECEIPT_KEY)
    orphan_binding = json.loads(
        (interrupted_transactions[0] / "ledger-binding.json").read_text()
    )
    with pytest.raises(ValueError, match="requires committed ledger context"):
        verify_controller_receipt(orphan_binding, receipt_key=RECEIPT_KEY)

    result = _prepare(tmp_path)

    assert result["status"] == "completed"
    assert len(list((receipts / "transactions").iterdir())) == 1
    _, recovered = state.current()
    assert recovered["program"]["status"] == "active"
    assert recovered["active_candidate"]["source_sha"] == NEXT_SHA
    assert [attempt["terminal_state"] for attempt in recovered["entries"][0]["attempts"]] == [
        "blocked",
        None,
    ]
    committed_bindings = [
        json.loads((transaction / "ledger-binding.json").read_text())["payload"]
        for transaction in (receipts / "transactions").iterdir()
    ]
    assert any(
        binding["target_ledger_sha256"] == result["ledger_sha256"]
        for binding in committed_bindings
    )
    AdminPlatformLedger(
        ledger,
        receipt_key=RECEIPT_KEY,
        receipt_root=receipts,
    )


def test_transaction_receipts_fail_closed_when_ledger_lineage_is_missing(
    tmp_path: Path,
) -> None:
    state, signer, ledger, receipts, signer_root = _initialize(tmp_path)
    prepare_controller_candidate(
        source_sha=INTERMEDIATE_SHA,
        expected_current_source_sha=CURRENT_SHA,
        receipt_key=RECEIPT_KEY,
        ledger_path=ledger,
        receipt_root=receipts,
        signer_state_root=signer_root,
    )
    digest, snapshot = state.current()
    intermediate = AdminPlatformCandidate(**snapshot["active_candidate"])
    advanced = state.record_result(
        expected_sha256=digest,
        receipt=_evidence(
            signer,
            candidate=intermediate,
            observed_at=snapshot["program"]["updated_at"],
            lane="ci",
            outcome="passed",
        ),
    )
    (receipts / "ledger-links" / f"{advanced.ledger_sha256}.json").unlink()

    with pytest.raises(
        AdminPlatformLedgerError,
        match="admin platform receipt is unavailable",
    ):
        AdminPlatformLedger(
            ledger,
            receipt_key=RECEIPT_KEY,
            receipt_root=receipts,
        )


def test_child_receipt_directory_creation_fsyncs_every_new_parent(tmp_path: Path) -> None:
    receipt_parent = tmp_path / "separate-state"
    receipts = receipt_parent / "receipts"
    state = AdminPlatformStateStore(
        tmp_path / "ledger.yml",
        receipt_key=RECEIPT_KEY,
        receipt_root=receipts,
    )
    synced_inodes: list[int] = []
    real_fsync = os.fsync

    def record_fsync(descriptor: int) -> None:
        synced_inodes.append(os.fstat(descriptor).st_ino)
        real_fsync(descriptor)

    with patch(
        "qdev_runner.admin_platform_state.os.fsync",
        side_effect=record_fsync,
    ):
        receipt_root_fd, child_fd = state._open_durable_child_directory(
            "transactions",
            unavailable="unavailable",
            unsafe="unsafe",
        )
        os.close(child_fd)
        os.close(receipt_root_fd)

    assert tmp_path.stat().st_ino in synced_inodes
    assert receipt_parent.stat().st_ino in synced_inodes
    assert receipts.stat().st_ino in synced_inodes


def test_child_receipt_directory_retry_fsyncs_interrupted_existing_edge(
    tmp_path: Path,
) -> None:
    receipts = tmp_path / "separate-state" / "receipts"
    state = AdminPlatformStateStore(
        tmp_path / "ledger.yml",
        receipt_key=RECEIPT_KEY,
        receipt_root=receipts,
    )
    real_fsync = os.fsync

    def interrupt_after_child_mkdir(descriptor: int) -> None:
        if receipts.exists() and os.fstat(descriptor).st_ino == receipts.stat().st_ino:
            raise OSError(errno.EIO, "simulated crash before receipt-root fsync")
        real_fsync(descriptor)

    with (
        patch(
            "qdev_runner.admin_platform_state.os.fsync",
            side_effect=interrupt_after_child_mkdir,
        ),
        pytest.raises(OSError, match="simulated crash before receipt-root fsync"),
    ):
        state._open_durable_child_directory(
            "transactions",
            unavailable="unavailable",
            unsafe="unsafe",
        )

    assert (receipts / "transactions").is_dir()
    synced_inodes: list[int] = []

    def record_fsync(descriptor: int) -> None:
        synced_inodes.append(os.fstat(descriptor).st_ino)
        real_fsync(descriptor)

    with patch(
        "qdev_runner.admin_platform_state.os.fsync",
        side_effect=record_fsync,
    ):
        receipt_root_fd, child_fd = state._open_durable_child_directory(
            "transactions",
            unavailable="unavailable",
            unsafe="unsafe",
        )
        os.close(child_fd)
        os.close(receipt_root_fd)

    assert receipts.stat().st_ino in synced_inodes


def test_durable_directory_open_closes_child_when_parent_fsync_fails(
    tmp_path: Path,
) -> None:
    state = AdminPlatformStateStore(
        tmp_path / "ledger.yml",
        receipt_key=RECEIPT_KEY,
        receipt_root=tmp_path / "receipts",
    )
    opened: list[int] = []
    real_open = os.open

    def record_open(*args: object, **kwargs: object) -> int:
        descriptor = real_open(*args, **kwargs)  # type: ignore[arg-type]
        opened.append(descriptor)
        return descriptor

    with (
        patch(
            "qdev_runner.admin_platform_state.os.open",
            side_effect=record_open,
        ),
        patch(
            "qdev_runner.admin_platform_state.os.fsync",
            side_effect=OSError(errno.EIO, "simulated parent fsync failure"),
        ),
        pytest.raises(
            AdminPlatformStateError,
            match="unavailable",
        ),
    ):
        state._open_durable_directory_path(
            state.receipt_root,
            unavailable="unavailable",
            unsafe="unsafe",
        )

    assert len(opened) >= 2
    for descriptor in opened:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)


def test_stale_transaction_directory_is_safely_reaped(tmp_path: Path) -> None:
    state = AdminPlatformStateStore(
        tmp_path / "ledger.yml",
        receipt_key=RECEIPT_KEY,
        receipt_root=tmp_path / "receipts",
    )
    transaction_id = "a" * 64
    transactions = tmp_path / "receipts" / "transactions"
    stale = transactions / f".{transaction_id}.0123456789abcdef.tmp"
    unrelated = transactions / ".unrelated.0123456789abcdef.tmp"
    stale.mkdir(parents=True)
    unrelated.mkdir()
    (stale / "receipt.json").write_text("partial", encoding="utf-8")
    root_fd = os.open(transactions, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        state._remove_stale_transaction_directories(
            root_fd,
            transaction_id,
            ("receipt.json",),
        )
    finally:
        os.close(root_fd)

    assert not stale.exists()
    assert unrelated.is_dir()


def test_stale_transaction_cleanup_failure_closes_parent_descriptors(
    tmp_path: Path,
) -> None:
    state, _, _, receipts, _ = _initialize(tmp_path)
    _, document = state.current()
    transaction_id = "a" * 64
    transactions = receipts / "transactions"
    stale = transactions / f".{transaction_id}.0123456789abcdef.tmp"
    stale.mkdir(parents=True)
    (stale / "unexpected.json").write_text("{}", encoding="utf-8")
    opened: list[int] = []
    original_open = state._open_durable_child_directory

    def record_open(*args: Any, **kwargs: Any) -> tuple[int, int]:
        descriptors = original_open(*args, **kwargs)
        opened.extend(descriptors)
        return descriptors

    with (
        patch.object(
            state,
            "_open_durable_child_directory",
            side_effect=record_open,
        ),
        pytest.raises(AdminPlatformStateError, match="unexpected files"),
    ):
        state._persist_receipt_transaction(
            transaction_id=transaction_id,
            receipts=(
                (
                    f"receipts/transactions/{transaction_id}/{'b' * 64}.json",
                    "c" * 64,
                    b"{}\n",
                ),
            ),
            previous_raw=state.path.read_bytes(),
            document=document,
            observed_at="2026-09-05T00:00:01Z",
        )

    assert len(opened) == 2
    for descriptor in opened:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)


def test_torn_ledger_link_does_not_poison_retry(tmp_path: Path) -> None:
    state, _, _, receipts, _ = _initialize(tmp_path)
    target = "f" * 64

    def torn_write(directory_fd: int, filename: str, raw: bytes) -> None:
        descriptor = os.open(
            filename,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=directory_fd,
        )
        try:
            os.write(descriptor, raw[:16])
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        raise OSError(errno.ENOSPC, "simulated torn lineage write")

    with (
        patch.object(state, "_write_transaction_file", side_effect=torn_write),
        pytest.raises(OSError, match="simulated torn lineage write"),
    ):
        state._persist_ledger_link(
            previous_ledger_sha256="e" * 64,
            target_ledger_sha256=target,
            observed_at="2026-09-05T00:00:00Z",
        )

    link_root = receipts / "ledger-links"
    assert not (link_root / f"{target}.json").exists()
    assert not list(link_root.glob(f".{target}.json.*.tmp"))

    state._persist_ledger_link(
        previous_ledger_sha256="e" * 64,
        target_ledger_sha256=target,
        observed_at="2026-09-05T00:00:00Z",
    )

    assert (link_root / f"{target}.json").read_bytes()
    assert not list(link_root.glob(f".{target}.json.*.tmp"))


def test_ledger_link_cleanup_fsync_failure_closes_parent_descriptors(
    tmp_path: Path,
) -> None:
    state, _, _, _, _ = _initialize(tmp_path)
    opened: list[int] = []
    directory_fd: int | None = None
    original_open = state._open_durable_child_directory
    original_fsync = os.fsync

    def record_open(*args: Any, **kwargs: Any) -> tuple[int, int]:
        nonlocal directory_fd
        descriptors = original_open(*args, **kwargs)
        opened.extend(descriptors)
        directory_fd = descriptors[1]
        return descriptors

    def fail_cleanup_fsync(descriptor: int) -> None:
        if descriptor == directory_fd:
            raise OSError(errno.EIO, "simulated cleanup fsync failure")
        original_fsync(descriptor)

    with (
        patch.object(
            state,
            "_open_durable_child_directory",
            side_effect=record_open,
        ),
        patch(
            "qdev_runner.admin_platform_state.os.link",
            side_effect=OSError(errno.EIO, "simulated link failure"),
        ),
        patch(
            "qdev_runner.admin_platform_state.os.fsync",
            side_effect=fail_cleanup_fsync,
        ),
        pytest.raises(OSError, match="simulated cleanup fsync failure"),
    ):
        state._persist_ledger_link(
            previous_ledger_sha256="e" * 64,
            target_ledger_sha256="f" * 64,
            observed_at="2026-09-05T00:00:00Z",
        )

    assert len(opened) == 2
    for descriptor in opened:
        with pytest.raises(OSError, match="Bad file descriptor"):
            os.fstat(descriptor)


def test_prepare_controller_candidate_uses_monotonic_durable_timestamps(
    tmp_path: Path,
) -> None:
    state, _, _, _, _ = _initialize(
        tmp_path,
        observed_at="2099-09-05T00:00:00Z",
    )

    _prepare(tmp_path)

    _, snapshot = state.current()
    entry = snapshot["entries"][0]
    finished_at = entry["attempts"][0]["finished_at"]
    restarted_at = entry["attempts"][1]["started_at"]
    assert parse_utc(finished_at) > parse_utc("2099-09-05T00:00:00Z")
    assert parse_utc(restarted_at) > parse_utc(finished_at)


def test_prepare_controller_candidate_fails_closed_without_mutation(
    tmp_path: Path,
) -> None:
    state, _, ledger, receipts, signer_root = _initialize(tmp_path)
    before_raw = ledger.read_bytes()
    before_receipts = sorted(path.name for path in receipts.rglob("*.json"))
    before_digest, _ = state.current()

    with pytest.raises(
        ControllerCandidateError,
        match="active runtime is not an unambiguous terminal controller attempt",
    ):
        prepare_controller_candidate(
            source_sha=NEXT_SHA,
            expected_current_source_sha="7" * 40,
            receipt_key=RECEIPT_KEY,
            ledger_path=ledger,
            receipt_root=receipts,
            signer_state_root=signer_root,
        )

    after_digest, _ = state.current()
    assert ledger.read_bytes() == before_raw
    assert before_digest == after_digest == hashlib.sha256(before_raw).hexdigest()
    assert sorted(path.name for path in receipts.rglob("*.json")) == before_receipts


def test_prepare_controller_candidate_supersedes_non_deployed_durable_candidate(
    tmp_path: Path,
) -> None:
    state, signer, ledger, receipts, signer_root = _initialize(tmp_path)
    first = prepare_controller_candidate(
        source_sha=INTERMEDIATE_SHA,
        expected_current_source_sha=CURRENT_SHA,
        receipt_key=RECEIPT_KEY,
        ledger_path=ledger,
        receipt_root=receipts,
        signer_state_root=signer_root,
    )
    digest, snapshot = state.current()
    intermediate = AdminPlatformCandidate(**snapshot["active_candidate"])
    observed_at = snapshot["program"]["updated_at"]
    ci_passed = state.record_result(
        expected_sha256=digest,
        receipt=_evidence(
            signer,
            candidate=intermediate,
            observed_at=observed_at,
            lane="ci",
            outcome="passed",
        ),
    )

    result = prepare_controller_candidate(
        source_sha=NEXT_SHA,
        expected_current_source_sha=CURRENT_SHA,
        receipt_key=RECEIPT_KEY,
        ledger_path=ledger,
        receipt_root=receipts,
        signer_state_root=signer_root,
    )

    assert first["candidate"]["source_sha"] == INTERMEDIATE_SHA
    assert ci_passed.active_status == "ci_passed"
    assert result["status"] == "completed"
    assert result["previous_candidate"]["source_sha"] == INTERMEDIATE_SHA
    _, current = state.current()
    assert current["active_candidate"]["source_sha"] == NEXT_SHA
    assert [attempt["terminal_state"] for attempt in current["entries"][0]["attempts"]] == [
        "blocked",
        "blocked",
        None,
    ]


def test_prepare_controller_candidate_ignores_historical_lane_outcomes(
    tmp_path: Path,
) -> None:
    state, signer, ledger, receipts, signer_root = _initialize(tmp_path)
    prepare_controller_candidate(
        source_sha=INTERMEDIATE_SHA,
        expected_current_source_sha=CURRENT_SHA,
        receipt_key=RECEIPT_KEY,
        ledger_path=ledger,
        receipt_root=receipts,
        signer_state_root=signer_root,
    )
    digest, snapshot = state.current()
    intermediate = AdminPlatformCandidate(**snapshot["active_candidate"])
    ci_passed = state.record_result(
        expected_sha256=digest,
        receipt=_evidence(
            signer,
            candidate=intermediate,
            observed_at=snapshot["program"]["updated_at"],
            lane="ci",
            outcome="passed",
        ),
    )
    prepare_controller_candidate(
        source_sha=NEXT_SHA,
        expected_current_source_sha=CURRENT_SHA,
        receipt_key=RECEIPT_KEY,
        ledger_path=ledger,
        receipt_root=receipts,
        signer_state_root=signer_root,
    )

    result = prepare_controller_candidate(
        source_sha=LATER_SHA,
        expected_current_source_sha=CURRENT_SHA,
        receipt_key=RECEIPT_KEY,
        ledger_path=ledger,
        receipt_root=receipts,
        signer_state_root=signer_root,
    )

    assert ci_passed.active_status == "ci_passed"
    assert result["status"] == "completed"
    _, current = state.current()
    entry = current["entries"][0]
    assert entry["attempts"][-2]["source_sha"] == NEXT_SHA
    assert entry["attempts"][-2]["terminal_state"] == "blocked"
    assert entry["results"][-2]["release_id"] == f"controller-v3-{NEXT_SHA}"
    assert entry["results"][-2]["lane"] == "ci"
    assert entry["results"][-2]["outcome"] == "blocked"
    assert current["active_candidate"]["source_sha"] == LATER_SHA


def test_prepare_controller_candidate_rejects_durable_candidate_with_deploy_evidence(
    tmp_path: Path,
) -> None:
    state, signer, ledger, receipts, signer_root = _initialize(tmp_path)
    prepare_controller_candidate(
        source_sha=INTERMEDIATE_SHA,
        expected_current_source_sha=CURRENT_SHA,
        receipt_key=RECEIPT_KEY,
        ledger_path=ledger,
        receipt_root=receipts,
        signer_state_root=signer_root,
    )
    digest, snapshot = state.current()
    intermediate = AdminPlatformCandidate(**snapshot["active_candidate"])
    observed_at = snapshot["program"]["updated_at"]
    for lane in ("ci", "publication", "deploy"):
        update = state.record_result(
            expected_sha256=digest,
            receipt=_evidence(
                signer,
                candidate=intermediate,
                observed_at=observed_at,
                lane=lane,
                outcome="passed",
            ),
        )
        digest = update.ledger_sha256

    before_raw = ledger.read_bytes()
    with pytest.raises(
        ControllerCandidateError,
        match="durable controller candidate has entered deployment",
    ):
        prepare_controller_candidate(
            source_sha=NEXT_SHA,
            expected_current_source_sha=CURRENT_SHA,
            receipt_key=RECEIPT_KEY,
            ledger_path=ledger,
            receipt_root=receipts,
            signer_state_root=signer_root,
        )
    assert ledger.read_bytes() == before_raw
