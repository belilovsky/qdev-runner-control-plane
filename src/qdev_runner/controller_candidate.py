"""Prepare one exact controller release as the durable active candidate."""

from __future__ import annotations

from dataclasses import asdict
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, cast

from .admin_platform import AdminPlatformCandidate
from .admin_platform_state import AdminPlatformStateStore
from .operations import OperationStore, format_utc, parse_utc, utc_now

PROGRAM_ID = "qdev-admin-platform-wave-1"
REPOSITORY = "belilovsky/qdev-runner-control-plane"
REFERENCE = "refs/heads/main"


class ControllerCandidateError(ValueError):
    """Raised when a controller candidate rollover is not admissible."""


def _evidence(
    signer: OperationStore,
    *,
    candidate: AdminPlatformCandidate,
    observed_at: str,
    evidence_type: str,
    lane: str | None,
    outcome: str,
) -> dict[str, Any]:
    return signer.receipt(
        {
            "kind": "admin-platform-evidence",
            "observed_at": observed_at,
            "program_id": PROGRAM_ID,
            "stage": "controller",
            "release_id": candidate.release_id,
            "source_sha": candidate.source_sha,
            "evidence_type": evidence_type,
            "lane": lane,
            "outcome": outcome,
        }
    )


def _active_entry(snapshot: dict[str, Any]) -> dict[str, Any]:
    for value in cast(list[dict[str, Any]], snapshot.get("entries", [])):
        if value.get("entry_id") == "controller":
            return value
    raise ControllerCandidateError("controller ledger entry is unavailable")


def _candidate(value: object) -> AdminPlatformCandidate:
    if not isinstance(value, dict) or set(value) != {
        "release_id",
        "repository",
        "source_sha",
        "reference",
    }:
        raise ControllerCandidateError("controller active candidate is invalid")
    fields = ("release_id", "repository", "source_sha", "reference")
    if any(not isinstance(value[field], str) for field in fields):
        raise ControllerCandidateError("controller active candidate is invalid")
    return AdminPlatformCandidate(
        release_id=cast(str, value["release_id"]),
        repository=cast(str, value["repository"]),
        source_sha=cast(str, value["source_sha"]),
        reference=cast(str, value["reference"]),
    )


def _next_observed_at(snapshot: dict[str, Any]) -> datetime:
    program = snapshot.get("program")
    updated_at = program.get("updated_at") if isinstance(program, dict) else None
    if not isinstance(updated_at, str):
        raise ControllerCandidateError("controller program timestamp is unavailable")
    try:
        latest = parse_utc(updated_at)
    except ValueError as error:
        raise ControllerCandidateError("controller program timestamp is invalid") from error
    return max(utc_now(), latest + timedelta(microseconds=1))


def _blocking_lane(entry: dict[str, Any], *, release_id: str) -> str:
    """Select the first unfinished lane whose prerequisites already passed."""

    results = cast(list[dict[str, Any]], entry.get("results", []))
    latest = {
        cast(str, result["lane"]): cast(str, result["outcome"])
        for result in results
        if isinstance(result, dict)
        and result.get("release_id") == release_id
        and isinstance(result.get("lane"), str)
        and isinstance(result.get("outcome"), str)
    }
    candidates = (
        ("ci", ("source",)),
        ("publication", ("source", "ci")),
        ("deploy", ("source", "ci", "publication")),
        ("browser", ("source", "ci", "deploy")),
        ("rollback", ("source", "ci", "publication", "deploy")),
        (
            "observation",
            ("source", "ci", "publication", "deploy", "rollback"),
        ),
    )
    for lane, prerequisites in candidates:
        if all(latest.get(required) == "passed" for required in prerequisites) and latest.get(
            lane
        ) in {None, "pending", "queued", "auth_blocked"}:
            return lane
    raise ControllerCandidateError("active controller attempt has no admissible blocking lane")


def _require_active_runtime_lineage(
    entry: dict[str, Any],
    *,
    active_candidate: AdminPlatformCandidate,
    active_runtime_source_sha: str,
) -> None:
    """Verify that a non-deployed durable candidate may be superseded safely."""

    if active_candidate.source_sha == active_runtime_source_sha:
        return
    if entry.get("status") not in {"candidate", "ci_queued", "ci_passed"}:
        raise ControllerCandidateError(
            "durable controller candidate has entered deployment"
        )

    results = cast(list[dict[str, Any]], entry.get("results", []))
    if any(
        result.get("release_id") == active_candidate.release_id
        and result.get("lane") == "deploy"
        for result in results
        if isinstance(result, dict)
    ):
        raise ControllerCandidateError(
            "durable controller candidate has deploy evidence"
        )

    attempts = cast(list[dict[str, Any]], entry.get("attempts", []))
    runtime_attempts = [
        attempt
        for attempt in attempts
        if isinstance(attempt, dict)
        and attempt.get("source_sha") == active_runtime_source_sha
        and attempt.get("terminal_state") in {"blocked", "rolled_back"}
        and isinstance(attempt.get("finished_at"), str)
    ]
    if len(runtime_attempts) != 1:
        raise ControllerCandidateError(
            "active runtime is not an unambiguous terminal controller attempt"
        )
    runtime_release_id = runtime_attempts[0].get("release_id")
    if not isinstance(runtime_release_id, str) or not any(
        result.get("release_id") == runtime_release_id
        and result.get("lane") == "source"
        and result.get("outcome") == "passed"
        for result in results
        if isinstance(result, dict)
    ):
        raise ControllerCandidateError(
            "active runtime controller attempt has no passing source evidence"
        )


def prepare_controller_candidate(
    *,
    source_sha: str,
    expected_current_source_sha: str,
    receipt_key: str,
    ledger_path: Path,
    receipt_root: Path,
    signer_state_root: Path,
    runtime_uid: int | None = None,
    runtime_gid: int | None = None,
) -> dict[str, Any]:
    """Supersede an unfinished controller attempt and admit one exact SHA.

    The two durable transitions are intentionally restartable. If execution
    stops after the old attempt is terminally blocked, a replay continues with
    the exact new candidate. If it stops after restart, replay is read-only.
    """

    if not receipt_key:
        raise ControllerCandidateError("controller receipt key is required")
    for label, value in (
        ("controller source SHA", source_sha),
        ("current controller source SHA", expected_current_source_sha),
    ):
        if len(value) != 40 or any(char not in "0123456789abcdef" for char in value):
            raise ControllerCandidateError(f"{label} is invalid")
    candidate = AdminPlatformCandidate(
        release_id=f"controller-v3-{source_sha}",
        repository=REPOSITORY,
        source_sha=source_sha,
        reference=REFERENCE,
    )
    state = AdminPlatformStateStore(
        ledger_path,
        receipt_key=receipt_key,
        receipt_root=receipt_root,
        file_uid=runtime_uid,
        file_gid=runtime_gid,
    )
    signer = OperationStore(
        signer_state_root,
        worker_signing_key=receipt_key,
        receipt_signing_key=receipt_key,
    )

    digest, snapshot = state.current()
    if snapshot.get("active_stage") != "controller":
        raise ControllerCandidateError("controller is not the active admin platform stage")
    active = snapshot.get("active_candidate")
    active_candidate = _candidate(active)
    entry = _active_entry(snapshot)
    program = snapshot.get("program")
    program_status = program.get("status") if isinstance(program, dict) else None

    if active_candidate == candidate:
        if program_status != "active" or entry.get("status") not in {
            "candidate",
            "ci_queued",
            "ci_passed",
            "deploying",
        }:
            raise ControllerCandidateError("matching controller candidate is not active")
        return {
            "schema": "qdev-controller-candidate-preparation-v1",
            "status": "already_completed",
            "candidate": asdict(candidate),
            "previous_candidate": asdict(active_candidate),
            "ledger_sha256": digest,
            "receipt_uris": [],
        }

    previous = active_candidate
    if previous.repository != REPOSITORY:
        raise ControllerCandidateError("active controller repository is invalid")
    _require_active_runtime_lineage(
        entry,
        active_candidate=previous,
        active_runtime_source_sha=expected_current_source_sha,
    )

    receipts: list[str] = []
    if program_status == "active":
        if entry.get("status") not in {"candidate", "ci_queued", "ci_passed", "deploying"}:
            raise ControllerCandidateError("active controller attempt cannot be superseded")
        terminal_time = _next_observed_at(snapshot)
        blocking_lane = _blocking_lane(entry, release_id=previous.release_id)
        terminal = state.finish_attempt(
            expected_sha256=digest,
            result_receipt=_evidence(
                signer,
                candidate=previous,
                observed_at=format_utc(terminal_time),
                evidence_type="lane_result",
                lane=blocking_lane,
                outcome="blocked",
            ),
            terminal_receipt=_evidence(
                signer,
                candidate=previous,
                observed_at=format_utc(terminal_time),
                evidence_type="attempt_terminal",
                lane=None,
                outcome="blocked",
            ),
        )
        digest = terminal.ledger_sha256
        receipts.extend(terminal.receipt_uris)
        source_time = terminal_time + timedelta(microseconds=1)
    elif program_status == "blocked" and entry.get("status") in {"blocked", "rolled_back"}:
        source_time = _next_observed_at(snapshot)
    else:
        raise ControllerCandidateError("controller program is not restartable")

    restarted = state.restart_attempt(
        expected_sha256=digest,
        candidate=candidate,
        source_receipt=_evidence(
            signer,
            candidate=candidate,
            observed_at=format_utc(source_time),
            evidence_type="lane_result",
            lane="source",
            outcome="passed",
        ),
    )
    receipts.extend(restarted.receipt_uris)
    return {
        "schema": "qdev-controller-candidate-preparation-v1",
        "status": "completed",
        "candidate": asdict(candidate),
        "previous_candidate": asdict(previous),
        "ledger_sha256": restarted.ledger_sha256,
        "receipt_uris": receipts,
    }
