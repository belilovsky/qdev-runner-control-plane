from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest

from qdev_runner.admin_platform import AdminPlatformCandidate
from qdev_runner.admin_platform_state import AdminPlatformStateStore
from qdev_runner.controller_candidate import (
    REFERENCE,
    REPOSITORY,
    ControllerCandidateError,
    prepare_controller_candidate,
)
from qdev_runner.operations import OperationStore, parse_utc

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


def test_prepare_controller_candidate_survives_commit_failure_without_split_state(
    tmp_path: Path,
) -> None:
    state, _, ledger, _, _ = _initialize(tmp_path)
    before = ledger.read_bytes()

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

    result = _prepare(tmp_path)

    assert result["status"] == "completed"
    _, recovered = state.current()
    assert recovered["program"]["status"] == "active"
    assert recovered["active_candidate"]["source_sha"] == NEXT_SHA
    assert [attempt["terminal_state"] for attempt in recovered["entries"][0]["attempts"]] == [
        "blocked",
        None,
    ]


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
