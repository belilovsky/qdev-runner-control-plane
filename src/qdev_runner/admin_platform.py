"""Canonical Admin Platform ledger and measured controller runtime identity.

The v3 ledger is deliberately read-only in the broker.  Advancing a stage is
an operator/controller operation that replaces the source document with a new
validated receipt; broker admission only consumes the exact active tuple.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any, Literal, cast

import yaml

from .admin_platform_ledger import AdminPlatformLedgerEntry
from .admin_platform_ledger import AdminPlatformLedgerError as AdminPlatformLedgerError
from .operator import verify_controller_receipt

SCHEMA_V3 = "qdev-admin-platform-ledger-v3"
COMPATIBILITY_SCHEMA_V1 = "qdev-admin-platform-ledger-compatibility-v1"
RUNTIME_HEALTH_SCHEMA_V1: Literal["qdev-controller-runtime-health-v1"] = (
    "qdev-controller-runtime-health-v1"
)
CONTROLLER_RELEASE_SCHEMA_V1 = "qdev-controller-release-status-v1"
CONTROLLER_RELEASE_SCHEMA_V2 = "qdev-controller-release-status-v2"

ORDER_V3 = (
    "controller",
    "avds-admin-shell",
    "qaz-admin-kit",
    "ortcom",
    "cmnt",
    "total",
    "qazposter",
    "platform-registry-qak-1",
)
STATUSES_V3 = frozenset(
    {
        "candidate",
        "ci_queued",
        "ci_passed",
        "deploying",
        "live_accepted",
        "rolled_back",
        "blocked",
    }
)
ACTIVE_STATUSES_V3 = frozenset({"candidate", "ci_queued", "ci_passed", "deploying"})
TERMINAL_STATUSES_V3 = frozenset({"live_accepted", "rolled_back", "blocked"})
RESULT_LANES_V3 = (
    "source",
    "ci",
    "publication",
    "deploy",
    "browser",
    "rollback",
    "observation",
)
RESULT_OUTCOMES_V3 = frozenset(
    {
        "pending",
        "queued",
        "passed",
        "failed",
        "blocked",
        "auth_blocked",
        "not_applicable",
    }
)
NOT_APPLICABLE_LANES_V3: dict[str, frozenset[str]] = {
    "controller": frozenset({"browser", "observation"}),
    "avds-admin-shell": frozenset({"deploy", "rollback", "observation"}),
    "qaz-admin-kit": frozenset({"deploy", "browser", "rollback", "observation"}),
    "ortcom": frozenset(),
    "cmnt": frozenset(),
    "total": frozenset(),
    "qazposter": frozenset(),
    "platform-registry-qak-1": frozenset(),
}
_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_RELEASE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_REFERENCE = re.compile(r"^refs/(?:heads|tags)/[A-Za-z0-9._/-]+$")
_RECEIPT_URI = re.compile(
    r"^receipts/(?:[A-Za-z0-9][A-Za-z0-9._-]{0,190}\.json|"
    r"transactions/[0-9a-f]{64}/[0-9a-f]{64}\.json)$"
)
_RECEIPT_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_MAX_RECEIPT_BYTES = 1024 * 1024
_MAX_LEDGER_BYTES = 4 * 1024 * 1024


def _json_safe(value: Any) -> Any:
    """Convert YAML-native dates into deterministic JSON values."""

    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


def _require_aware_timestamp(value: Any, label: str) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError as error:
            raise AdminPlatformLedgerError(f"{label} timestamp is invalid") from error
    else:
        raise AdminPlatformLedgerError(f"{label} timestamp is invalid")
    if parsed.tzinfo is None:
        raise AdminPlatformLedgerError(f"{label} timestamp is not timezone-aware")
    return parsed.astimezone(UTC)


@dataclass(frozen=True)
class AdminPlatformCandidate:
    """The exact release tuple currently admitted by the program."""

    release_id: str
    repository: str
    source_sha: str
    reference: str


@dataclass(frozen=True)
class ControllerRuntimeHealth:
    """Typed, non-secret projection of the activated controller runtime."""

    schema: Literal["qdev-controller-runtime-health-v1"]
    state: Literal["active", "legacy", "unavailable"]
    revision: str | None
    digest: str | None
    activated: str | None
    runtime_identity: dict[str, str] | None
    dependency_identity: dict[str, str] | None
    receipt: dict[str, Any] | None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class AdminPlatformLedger:
    """Validate the canonical, ordered v3 program ledger.

    Legacy ledgers are intentionally not accepted for admission.  Consumers
    that still need the old shape receive a generated, explicitly read-only
    projection from :meth:`compatibility_snapshot_v1`.
    """

    def __init__(
        self,
        path: Path,
        *,
        receipt_key: str | None = None,
        receipt_root: Path | None = None,
    ) -> None:
        self._raw_v3: dict[str, Any] | None = None
        self.schema_version: str
        self.active_stage: str | None
        self.active_candidate: AdminPlatformCandidate | None
        self.entries: tuple[AdminPlatformLedgerEntry, ...]
        self.program: dict[str, Any]
        self.prerequisites: dict[str, Any]
        self.history: list[Any]
        self.attempts: list[Any]
        self._by_entry_id: dict[str, AdminPlatformLedgerEntry]
        self._receipt_key = receipt_key
        self._receipt_root = receipt_root or path.parent / "receipts"
        self._pending_receipts: list[dict[str, Any]] = []
        self._transaction_bindings: dict[str, dict[str, Any]] = {}

        document, self._ledger_sha256 = self._load(path)
        schema_version = document.get("schema_version")
        if schema_version != SCHEMA_V3:
            raise AdminPlatformLedgerError("canonical admin platform ledger must use schema v3")
        self._load_v3(document)
        self._verify_pending_receipts()

    @staticmethod
    def _load(path: Path) -> tuple[dict[str, Any], str]:
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            ledger_fd = os.open(path, os.O_RDONLY | nofollow)
            try:
                metadata = os.fstat(ledger_fd)
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_LEDGER_BYTES:
                    raise AdminPlatformLedgerError("admin platform ledger file is unsafe")
                chunks: list[bytes] = []
                remaining = _MAX_LEDGER_BYTES + 1
                while remaining:
                    chunk = os.read(ledger_fd, min(65536, remaining))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    remaining -= len(chunk)
                raw = b"".join(chunks)
                if len(raw) > _MAX_LEDGER_BYTES:
                    raise AdminPlatformLedgerError("admin platform ledger file is too large")
            finally:
                os.close(ledger_fd)
            document = yaml.safe_load(raw.decode("utf-8"))
        except AdminPlatformLedgerError:
            raise
        except (OSError, UnicodeDecodeError, yaml.YAMLError) as error:
            raise AdminPlatformLedgerError("admin platform ledger is unavailable") from error
        if not isinstance(document, dict):
            raise AdminPlatformLedgerError("admin platform ledger shape is invalid")
        return cast(dict[str, Any], document), hashlib.sha256(raw).hexdigest()

    def _load_v3(self, document: dict[str, Any]) -> None:
        if set(document) != {
            "schema_version",
            "program",
            "active_stage",
            "active_candidate",
            "entries",
        }:
            raise AdminPlatformLedgerError("admin platform ledger v3 shape is invalid")
        program = document["program"]
        if not isinstance(program, dict) or set(program) != {
            "id",
            "owner",
            "status",
            "updated_at",
        }:
            raise AdminPlatformLedgerError("admin platform program metadata is invalid")
        if not isinstance(program["id"], str) or not _RELEASE_ID.fullmatch(program["id"]):
            raise AdminPlatformLedgerError("admin platform program id is invalid")
        if not isinstance(program["owner"], str) or not program["owner"]:
            raise AdminPlatformLedgerError("admin platform program owner is invalid")
        if program["status"] not in {"active", "blocked", "complete"}:
            raise AdminPlatformLedgerError("admin platform program status is invalid")
        program_updated_at = _require_aware_timestamp(
            program["updated_at"], "program updated_at"
        )

        active_stage = document["active_stage"]
        if active_stage is not None and (
            not isinstance(active_stage, str) or active_stage not in ORDER_V3
        ):
            raise AdminPlatformLedgerError("admin platform active stage is invalid")
        candidate = self._candidate(document["active_candidate"])

        raw_entries = document["entries"]
        if not isinstance(raw_entries, dict) or tuple(raw_entries) != ORDER_V3:
            raise AdminPlatformLedgerError("admin platform ledger order is invalid")

        entries: list[AdminPlatformLedgerEntry] = []
        for index, entry_id in enumerate(ORDER_V3):
            raw = raw_entries[entry_id]
            entry = self._validate_v3_entry(program["id"], entry_id, index, raw)
            entries.append(entry)

        event_times = [
            _require_aware_timestamp(value, "admin platform event")
            for raw_entry in raw_entries.values()
            for value in (
                [attempt["started_at"] for attempt in raw_entry["attempts"]]
                + [
                    attempt["finished_at"]
                    for attempt in raw_entry["attempts"]
                    if attempt["finished_at"] is not None
                ]
                + [result["recorded_at"] for result in raw_entry["results"]]
            )
        ]
        if event_times and program_updated_at != max(event_times):
            raise AdminPlatformLedgerError(
                "admin platform program updated_at does not match the latest event"
            )

        if program["status"] == "complete":
            if active_stage is not None or candidate is not None:
                raise AdminPlatformLedgerError("complete admin platform ledger has an active tuple")
            if any(entry.status != "live_accepted" for entry in entries):
                raise AdminPlatformLedgerError(
                    "complete admin platform ledger has unfinished stages"
                )
        else:
            if active_stage is None or candidate is None:
                raise AdminPlatformLedgerError(
                    "active candidate may be null only when the program is complete"
                )
            active_index = ORDER_V3.index(active_stage)
            active_status = entries[active_index].status
            if program["status"] == "active" and active_status not in ACTIVE_STATUSES_V3:
                raise AdminPlatformLedgerError(
                    "active program does not identify an advancing stage"
                )
            for index, entry in enumerate(entries):
                if index < active_index and entry.status != "live_accepted":
                    raise AdminPlatformLedgerError(
                        "prior stage must be live_accepted; rolled_back cannot advance"
                    )
                if index == active_index and entry.status not in (
                    ACTIVE_STATUSES_V3 | {"blocked", "rolled_back"}
                ):
                    raise AdminPlatformLedgerError("active stage status is invalid")
                if index > active_index and entry.status != "blocked":
                    raise AdminPlatformLedgerError("later admin platform stage is not blocked")
            if program["status"] == "blocked" and entries[active_index].status not in {
                "blocked",
                "rolled_back",
            }:
                raise AdminPlatformLedgerError("blocked program does not identify a blocked stage")
            self._validate_active_candidate(
                active_stage,
                candidate,
                cast(dict[str, Any], raw_entries[active_stage]),
            )

        self.schema_version = SCHEMA_V3
        self.active_stage = active_stage
        self.active_candidate = candidate
        self.entries = tuple(entries)
        self._by_entry_id = {entry.entry_id: entry for entry in entries}
        self.program = cast(dict[str, Any], _json_safe(dict(program)))
        self.prerequisites = {
            entry_id: list(cast(dict[str, Any], raw_entries[entry_id])["prerequisites"])
            for entry_id in ORDER_V3
        }
        self.history = []
        self.attempts = [
            cast(dict[str, Any], _json_safe(dict(attempt)))
            for entry_id in ORDER_V3
            for attempt in cast(dict[str, Any], raw_entries[entry_id])["attempts"]
        ]
        self._raw_v3 = cast(dict[str, Any], _json_safe(document))

    @staticmethod
    def _candidate(value: Any) -> AdminPlatformCandidate | None:
        if value is None:
            return None
        if not isinstance(value, dict) or set(value) != {
            "release_id",
            "repository",
            "source_sha",
            "reference",
        }:
            raise AdminPlatformLedgerError("admin platform active candidate shape is invalid")
        release_id = value["release_id"]
        repository = value["repository"]
        source_sha = value["source_sha"]
        reference = value["reference"]
        if not isinstance(release_id, str) or not _RELEASE_ID.fullmatch(release_id):
            raise AdminPlatformLedgerError("admin platform release id is invalid")
        if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
            raise AdminPlatformLedgerError("admin platform candidate repository is invalid")
        if not isinstance(source_sha, str) or not _SHA.fullmatch(source_sha):
            raise AdminPlatformLedgerError("admin platform candidate source SHA is invalid")
        if not isinstance(reference, str) or not _REFERENCE.fullmatch(reference):
            raise AdminPlatformLedgerError("admin platform candidate reference is invalid")
        return AdminPlatformCandidate(release_id, repository, source_sha, reference)

    def _validate_v3_entry(
        self, program_id: str, entry_id: str, index: int, value: Any
    ) -> AdminPlatformLedgerEntry:
        if not isinstance(value, dict) or set(value) != {
            "project_id",
            "repository",
            "source_sha",
            "reference",
            "status",
            "prerequisites",
            "attempts",
            "results",
        }:
            raise AdminPlatformLedgerError(f"{entry_id} ledger entry shape is invalid")
        project_id = value["project_id"]
        repository = value["repository"]
        source_sha = value["source_sha"]
        reference = value["reference"]
        status = value["status"]
        if not isinstance(project_id, str) or not project_id:
            raise AdminPlatformLedgerError(f"{entry_id} project id is invalid")
        if not isinstance(repository, str) or not _REPOSITORY.fullmatch(repository):
            raise AdminPlatformLedgerError(f"{entry_id} repository is invalid")
        if (source_sha is None) != (reference is None):
            raise AdminPlatformLedgerError(f"{entry_id} source and reference must be paired")
        if source_sha is not None and (
            not isinstance(source_sha, str) or not _SHA.fullmatch(source_sha)
        ):
            raise AdminPlatformLedgerError(f"{entry_id} source SHA is invalid")
        if reference is not None and (
            not isinstance(reference, str) or not _REFERENCE.fullmatch(reference)
        ):
            raise AdminPlatformLedgerError(f"{entry_id} reference is invalid")
        if not isinstance(status, str) or status not in STATUSES_V3:
            raise AdminPlatformLedgerError(f"{entry_id} status is invalid")

        expected_prerequisites = [] if index == 0 else [ORDER_V3[index - 1]]
        if value["prerequisites"] != expected_prerequisites:
            raise AdminPlatformLedgerError(f"{entry_id} prerequisites are invalid")
        attempts = value["attempts"]
        results = value["results"]
        if not isinstance(attempts, list) or not isinstance(results, list):
            raise AdminPlatformLedgerError(f"{entry_id} attempts/results must be lists")

        attempt_ids: list[str] = []
        attempt_sources: dict[str, str] = {}
        attempt_terminal_states: list[str | None] = []
        attempt_times: dict[str, tuple[datetime, datetime | None]] = {}
        previous_finished_at: datetime | None = None
        for attempt in attempts:
            if not isinstance(attempt, dict) or set(attempt) != {
                "release_id",
                "source_sha",
                "reference",
                "started_at",
                "finished_at",
                "terminal_state",
                "receipt_uri",
                "receipt_sha256",
            }:
                raise AdminPlatformLedgerError(f"{entry_id} attempt shape is invalid")
            release_id = attempt["release_id"]
            attempt_sha = attempt["source_sha"]
            attempt_reference = attempt["reference"]
            if not isinstance(release_id, str) or not _RELEASE_ID.fullmatch(release_id):
                raise AdminPlatformLedgerError(f"{entry_id} attempt release id is invalid")
            if release_id in attempt_ids:
                raise AdminPlatformLedgerError(f"{entry_id} attempt release id is duplicated")
            if not isinstance(attempt_sha, str) or not _SHA.fullmatch(attempt_sha):
                raise AdminPlatformLedgerError(f"{entry_id} attempt source SHA is invalid")
            if not isinstance(attempt_reference, str) or not _REFERENCE.fullmatch(
                attempt_reference
            ):
                raise AdminPlatformLedgerError(f"{entry_id} attempt reference is invalid")
            started_at = _require_aware_timestamp(
                attempt["started_at"], f"{entry_id} attempt started_at"
            )
            if previous_finished_at is not None and started_at < previous_finished_at:
                raise AdminPlatformLedgerError(f"{entry_id} attempt history is not chronological")
            terminal_state = attempt["terminal_state"]
            finished_at = attempt["finished_at"]
            attempt_receipt = attempt["receipt_uri"]
            attempt_receipt_sha256 = attempt["receipt_sha256"]
            terminal_values = (
                terminal_state,
                finished_at,
                attempt_receipt,
                attempt_receipt_sha256,
            )
            if all(item is None for item in terminal_values):
                normalized_finished_at = None
            elif any(item is None for item in terminal_values):
                raise AdminPlatformLedgerError(
                    f"{entry_id} attempt terminal fields must be recorded together"
                )
            else:
                if terminal_state not in TERMINAL_STATUSES_V3:
                    raise AdminPlatformLedgerError(f"{entry_id} attempt terminal state is invalid")
                normalized_finished_at = _require_aware_timestamp(
                    finished_at, f"{entry_id} attempt finished_at"
                )
                if normalized_finished_at < started_at:
                    raise AdminPlatformLedgerError(f"{entry_id} attempt finishes before it starts")
                if not isinstance(attempt_receipt, str) or not _RECEIPT_URI.fullmatch(
                    attempt_receipt
                ):
                    raise AdminPlatformLedgerError(
                        f"{entry_id} attempt terminal receipt is invalid"
                    )
                if not isinstance(attempt_receipt_sha256, str) or not _RECEIPT_SHA256.fullmatch(
                    attempt_receipt_sha256
                ):
                    raise AdminPlatformLedgerError(
                        f"{entry_id} attempt terminal receipt checksum is invalid"
                    )
                self._pending_receipts.append(
                    {
                        "program_id": program_id,
                        "stage": entry_id,
                        "release_id": release_id,
                        "source_sha": attempt_sha,
                        "evidence_type": "attempt_terminal",
                        "lane": None,
                        "outcome": terminal_state,
                        "recorded_at": finished_at,
                        "receipt_uri": attempt_receipt,
                        "receipt_sha256": attempt_receipt_sha256,
                    }
                )
            attempt_ids.append(release_id)
            attempt_sources[release_id] = attempt_sha
            attempt_terminal_states.append(terminal_state)
            attempt_times[release_id] = (started_at, normalized_finished_at)
            previous_finished_at = normalized_finished_at

        if any(state is None for state in attempt_terminal_states[:-1]):
            raise AdminPlatformLedgerError(
                f"{entry_id} has an unresolved attempt before the latest attempt"
            )

        results_by_attempt: dict[str, dict[str, str]] = {
            release_id: {} for release_id in attempt_ids
        }
        latest_result_time: dict[str, datetime] = {}
        for result in results:
            if not isinstance(result, dict) or set(result) != {
                "release_id",
                "lane",
                "outcome",
                "recorded_at",
                "receipt_uri",
                "receipt_sha256",
            }:
                raise AdminPlatformLedgerError(f"{entry_id} result shape is invalid")
            release_id = result["release_id"]
            lane = result["lane"]
            outcome = result["outcome"]
            receipt_uri = result["receipt_uri"]
            receipt_sha256 = result["receipt_sha256"]
            if not isinstance(release_id, str) or release_id not in attempt_ids:
                raise AdminPlatformLedgerError(f"{entry_id} result references an unknown attempt")
            if not isinstance(lane, str) or lane not in RESULT_LANES_V3:
                raise AdminPlatformLedgerError(f"{entry_id} result lane is invalid")
            if not isinstance(outcome, str) or outcome not in RESULT_OUTCOMES_V3:
                raise AdminPlatformLedgerError(f"{entry_id} result outcome is invalid")
            if outcome == "queued" and lane not in {"ci", "deploy"}:
                raise AdminPlatformLedgerError(
                    f"{entry_id} result lane {lane} cannot be queued"
                )
            if outcome == "auth_blocked" and lane != "browser":
                raise AdminPlatformLedgerError(
                    f"{entry_id} result lane {lane} cannot be auth_blocked"
                )
            if (
                outcome == "not_applicable"
                and lane not in NOT_APPLICABLE_LANES_V3[entry_id]
            ):
                raise AdminPlatformLedgerError(
                    f"{entry_id} result lane {lane} cannot be not_applicable"
                )
            recorded_at = _require_aware_timestamp(
                result["recorded_at"], f"{entry_id} result recorded_at"
            )
            started_at, finished_at = attempt_times[release_id]
            if recorded_at < started_at or (finished_at is not None and recorded_at > finished_at):
                raise AdminPlatformLedgerError(
                    f"{entry_id} result timestamp is outside its attempt"
                )
            previous_result_time = latest_result_time.get(release_id)
            if previous_result_time is not None and recorded_at < previous_result_time:
                raise AdminPlatformLedgerError(
                    f"{entry_id} result history is not chronological"
                )
            previous_outcome = results_by_attempt[release_id].get(lane)
            self._validate_result_transition(entry_id, lane, previous_outcome, outcome)
            self._validate_lane_prerequisites(
                entry_id,
                lane,
                outcome,
                results_by_attempt[release_id],
            )
            if outcome == "pending":
                if receipt_uri is not None or receipt_sha256 is not None:
                    raise AdminPlatformLedgerError(
                        f"{entry_id} pending lane result has receipt evidence"
                    )
            else:
                if not isinstance(receipt_uri, str) or not _RECEIPT_URI.fullmatch(receipt_uri):
                    raise AdminPlatformLedgerError(
                        f"{entry_id} non-pending lane result has no valid receipt"
                    )
                if not isinstance(receipt_sha256, str) or not _RECEIPT_SHA256.fullmatch(
                    receipt_sha256
                ):
                    raise AdminPlatformLedgerError(
                        f"{entry_id} non-pending lane result has no valid receipt checksum"
                    )
                self._pending_receipts.append(
                    {
                        "program_id": program_id,
                        "stage": entry_id,
                        "release_id": release_id,
                        "source_sha": attempt_sources[release_id],
                        "evidence_type": "lane_result",
                        "lane": lane,
                        "outcome": outcome,
                        "recorded_at": result["recorded_at"],
                        "receipt_uri": receipt_uri,
                        "receipt_sha256": receipt_sha256,
                    }
                )
            results_by_attempt[release_id][lane] = outcome
            latest_result_time[release_id] = recorded_at

        if not attempts:
            if results or source_sha is not None or reference is not None or status != "blocked":
                raise AdminPlatformLedgerError(f"{entry_id} empty attempt history is inconsistent")
        else:
            latest_attempt = attempts[-1]
            if (
                source_sha != latest_attempt["source_sha"]
                or reference != latest_attempt["reference"]
            ):
                raise AdminPlatformLedgerError(f"{entry_id} source does not match latest attempt")
            latest_terminal_state = attempt_terminal_states[-1]
            if status in ACTIVE_STATUSES_V3 and latest_terminal_state is not None:
                raise AdminPlatformLedgerError(
                    f"{entry_id} active status has a terminal latest attempt"
                )
            if status in TERMINAL_STATUSES_V3 and latest_terminal_state != status:
                raise AdminPlatformLedgerError(
                    f"{entry_id} status does not match latest attempt terminal state"
                )

            latest_release_id = attempt_ids[-1]
            latest_results = results_by_attempt[latest_release_id]
            if status == "ci_queued" and latest_results.get("ci") != "queued":
                raise AdminPlatformLedgerError(f"{entry_id} CI queue result is missing")
            if (
                status in {"ci_passed", "deploying", "live_accepted"}
                and latest_results.get("ci") != "passed"
            ):
                raise AdminPlatformLedgerError(f"{entry_id} passing CI result is missing")
            if status == "deploying" and latest_results.get("deploy") not in {
                "queued",
                "passed",
            }:
                raise AdminPlatformLedgerError(f"{entry_id} deploy result is not active")
            if status == "rolled_back" and latest_results.get("rollback") != "passed":
                raise AdminPlatformLedgerError(f"{entry_id} rollback result is missing")
            if status == "blocked" and not any(
                outcome in {"failed", "blocked", "auth_blocked"}
                for outcome in latest_results.values()
            ):
                complete_replaced_attempt = (
                    entry_id == "controller"
                    and set(latest_results) == set(RESULT_LANES_V3)
                    and all(
                        outcome in {"passed", "not_applicable"}
                        for outcome in latest_results.values()
                    )
                )
                if not complete_replaced_attempt:
                    raise AdminPlatformLedgerError(
                        f"{entry_id} blocked result is missing"
                    )
            if status == "live_accepted":
                missing_lanes = set(RESULT_LANES_V3) - set(latest_results)
                invalid_lanes = {
                    lane
                    for lane, outcome in latest_results.items()
                    if outcome not in {"passed", "not_applicable"}
                }
                if missing_lanes or invalid_lanes:
                    raise AdminPlatformLedgerError(
                        f"{entry_id} live acceptance does not have complete lane receipts"
                    )
                if latest_results.get("source") != "passed" or latest_results.get(
                    "ci"
                ) != "passed":
                    raise AdminPlatformLedgerError(
                        f"{entry_id} live acceptance requires passing source and CI"
                    )
        return AdminPlatformLedgerEntry(entry_id, project_id, source_sha, status)

    @staticmethod
    def _validate_result_transition(
        entry_id: str,
        lane: str,
        previous: str | None,
        current: str,
    ) -> None:
        """Enforce append-only lane progress without erasing historical evidence."""

        if previous is None:
            return
        allowed: dict[str, frozenset[str]] = {
            "pending": frozenset(
                {
                    "queued",
                    "passed",
                    "failed",
                    "blocked",
                    "auth_blocked",
                    "not_applicable",
                }
            ),
            "queued": frozenset({"passed", "failed", "blocked", "auth_blocked"}),
            "auth_blocked": frozenset({"passed", "failed", "blocked"}),
            "passed": frozenset(),
            "failed": frozenset(),
            "blocked": frozenset(),
            "not_applicable": frozenset(),
        }
        if current not in allowed[previous]:
            raise AdminPlatformLedgerError(
                f"{entry_id} result lane {lane} transition {previous} -> {current} is invalid"
            )

    @staticmethod
    def _validate_lane_prerequisites(
        entry_id: str,
        lane: str,
        outcome: str,
        latest: dict[str, str],
    ) -> None:
        """Keep evidence lanes ordered without conflating their outcomes."""

        if outcome == "pending" or lane == "source":
            return
        if latest.get("source") != "passed":
            raise AdminPlatformLedgerError(
                f"{entry_id} result lane {lane} requires passing source evidence"
            )
        if lane == "ci":
            return
        if latest.get("ci") != "passed":
            raise AdminPlatformLedgerError(
                f"{entry_id} result lane {lane} requires passing CI evidence"
            )
        if lane in {"deploy", "rollback", "observation"} and latest.get(
            "publication"
        ) != "passed":
            raise AdminPlatformLedgerError(
                f"{entry_id} result lane {lane} requires passing publication evidence"
            )
        runtime_stage = entry_id not in {"avds-admin-shell", "qaz-admin-kit"}
        if (
            runtime_stage
            and lane in {"browser", "rollback", "observation"}
            and latest.get("deploy") != "passed"
        ):
            raise AdminPlatformLedgerError(
                f"{entry_id} result lane {lane} requires passing deploy evidence"
            )
        if runtime_stage and lane == "observation" and latest.get("rollback") != "passed":
            raise AdminPlatformLedgerError(
                f"{entry_id} observation requires passing rollback evidence"
            )

    @staticmethod
    def _normalized_timestamp(value: Any) -> str:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        else:  # pragma: no cover - structural validation rejects this first
            raise ValueError("timestamp is invalid")
        return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")

    def _read_receipt(self, receipt_uri: str, receipt_sha256: str) -> dict[str, Any]:
        if self._receipt_key is None:
            raise AdminPlatformLedgerError("admin platform receipt verification key is unavailable")
        relative = receipt_uri.removeprefix("receipts/")
        parts = relative.split("/")
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            root_fd = os.open(self._receipt_root, directory_flags | nofollow)
        except OSError as error:
            raise AdminPlatformLedgerError("admin platform receipt root is unavailable") from error
        try:
            if len(parts) == 1:
                raw = self._read_receipt_file(root_fd, parts[0], nofollow)
            elif len(parts) == 3 and parts[0] == "transactions":
                transaction_id, filename = parts[1], parts[2]
                try:
                    transactions_fd = os.open(
                        "transactions",
                        directory_flags | nofollow,
                        dir_fd=root_fd,
                    )
                except OSError as error:
                    raise AdminPlatformLedgerError(
                        "admin platform receipt transaction is unavailable"
                    ) from error
                try:
                    transactions_metadata = os.fstat(transactions_fd)
                    if not stat.S_ISDIR(transactions_metadata.st_mode):
                        raise AdminPlatformLedgerError(
                            "admin platform receipt transaction root is unsafe"
                        )
                    try:
                        transaction_fd = os.open(
                            transaction_id,
                            directory_flags | nofollow,
                            dir_fd=transactions_fd,
                        )
                    except OSError as error:
                        raise AdminPlatformLedgerError(
                            "admin platform receipt transaction is unavailable"
                        ) from error
                finally:
                    os.close(transactions_fd)
                try:
                    transaction_metadata = os.fstat(transaction_fd)
                    if not stat.S_ISDIR(transaction_metadata.st_mode):
                        raise AdminPlatformLedgerError(
                            "admin platform receipt transaction is unsafe"
                        )
                    raw = self._read_receipt_file(transaction_fd, filename, nofollow)
                    binding_raw = self._read_receipt_file(
                        transaction_fd, "ledger-binding.json", nofollow
                    )
                finally:
                    os.close(transaction_fd)
                self._verify_transaction_binding(
                    binding_raw,
                    receipt_root_fd=root_fd,
                    transaction_id=transaction_id,
                    receipt_uri=receipt_uri,
                    receipt_sha256=receipt_sha256,
                )
            else:  # pragma: no cover - URI validation rejects this first
                raise AdminPlatformLedgerError("admin platform receipt URI is invalid")
        finally:
            os.close(root_fd)
        if hashlib.sha256(raw).hexdigest() != receipt_sha256:
            raise AdminPlatformLedgerError("admin platform receipt checksum does not match")
        try:
            document = json.loads(raw)
            if not isinstance(document, dict):
                raise ValueError("receipt is not an object")
            return verify_controller_receipt(
                document,
                receipt_key=self._receipt_key,
                allow_ledger_bound=len(parts) == 3,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise AdminPlatformLedgerError(
                "admin platform controller receipt is invalid"
            ) from error

    @staticmethod
    def _read_receipt_file(directory_fd: int, filename: str, nofollow: int) -> bytes:
        try:
            receipt_fd = os.open(filename, os.O_RDONLY | nofollow, dir_fd=directory_fd)
        except OSError as error:
            raise AdminPlatformLedgerError("admin platform receipt is unavailable") from error
        try:
            metadata = os.fstat(receipt_fd)
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > _MAX_RECEIPT_BYTES:
                raise AdminPlatformLedgerError("admin platform receipt file is unsafe")
            chunks: list[bytes] = []
            remaining = _MAX_RECEIPT_BYTES + 1
            while remaining:
                chunk = os.read(receipt_fd, min(65536, remaining))
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            raw = b"".join(chunks)
            if len(raw) > _MAX_RECEIPT_BYTES:
                raise AdminPlatformLedgerError("admin platform receipt file is too large")
            return raw
        finally:
            os.close(receipt_fd)

    def _verify_transaction_binding(
        self,
        raw: bytes,
        *,
        receipt_root_fd: int,
        transaction_id: str,
        receipt_uri: str,
        receipt_sha256: str,
    ) -> None:
        try:
            document = json.loads(raw)
            if not isinstance(document, dict):
                raise ValueError("transaction binding is not an object")
            verified = verify_controller_receipt(
                document,
                receipt_key=cast(str, self._receipt_key),
                allow_ledger_bound=True,
            )
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
            raise AdminPlatformLedgerError(
                "admin platform receipt transaction binding is invalid"
            ) from error
        payload = verified["payload"]
        expected_receipt = {
            "receipt_uri": receipt_uri,
            "receipt_sha256": receipt_sha256,
        }
        if (
            payload.get("kind") != "admin-platform-state-transaction"
            or payload.get("transaction_id") != transaction_id
            or expected_receipt not in payload.get("receipts", [])
        ):
            raise AdminPlatformLedgerError(
                "admin platform receipt transaction is not bound to this ledger"
            )
        target_ledger_sha256 = cast(str, payload["target_ledger_sha256"])
        if target_ledger_sha256 != self._ledger_sha256:
            self._require_ledger_descendant(
                receipt_root_fd,
                ancestor_sha256=target_ledger_sha256,
            )
        existing = self._transaction_bindings.setdefault(transaction_id, payload)
        if existing != payload:
            raise AdminPlatformLedgerError(
                "admin platform receipt transaction binding is inconsistent"
            )

    def _require_ledger_descendant(
        self,
        receipt_root_fd: int,
        *,
        ancestor_sha256: str,
    ) -> None:
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        nofollow = getattr(os, "O_NOFOLLOW", 0)
        try:
            links_fd = os.open(
                "ledger-links",
                directory_flags | nofollow,
                dir_fd=receipt_root_fd,
            )
        except OSError as error:
            raise AdminPlatformLedgerError(
                "admin platform ledger lineage is unavailable"
            ) from error
        cursor = self._ledger_sha256
        visited: set[str] = set()
        try:
            for _ in range(4096):
                if cursor == ancestor_sha256:
                    return
                if cursor in visited:
                    break
                visited.add(cursor)
                raw = self._read_receipt_file(links_fd, f"{cursor}.json", nofollow)
                try:
                    document = json.loads(raw)
                    if not isinstance(document, dict):
                        raise ValueError("ledger link is not an object")
                    verified = verify_controller_receipt(
                        document,
                        receipt_key=cast(str, self._receipt_key),
                        allow_ledger_bound=True,
                    )
                except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
                    raise AdminPlatformLedgerError(
                        "admin platform ledger lineage is invalid"
                    ) from error
                link = verified["payload"]
                if (
                    link.get("kind") != "admin-platform-ledger-link"
                    or link.get("target_ledger_sha256") != cursor
                ):
                    raise AdminPlatformLedgerError(
                        "admin platform ledger lineage is inconsistent"
                    )
                cursor = cast(str, link["previous_ledger_sha256"])
        finally:
            os.close(links_fd)
        raise AdminPlatformLedgerError(
            "admin platform receipt transaction is not in the ledger lineage"
        )

    def _verify_pending_receipts(self) -> None:
        for expected in self._pending_receipts:
            document = self._read_receipt(
                cast(str, expected["receipt_uri"]),
                cast(str, expected["receipt_sha256"]),
            )
            expected_payload = {
                "kind": "admin-platform-evidence",
                "observed_at": self._normalized_timestamp(expected["recorded_at"]),
                "program_id": expected["program_id"],
                "stage": expected["stage"],
                "release_id": expected["release_id"],
                "source_sha": expected["source_sha"],
                "evidence_type": expected["evidence_type"],
                "lane": expected["lane"],
                "outcome": expected["outcome"],
            }
            if document["payload"] != expected_payload:
                raise AdminPlatformLedgerError(
                    "admin platform receipt does not match the ledger evidence tuple"
                )
        referenced = {
            (
                cast(str, expected["receipt_uri"]),
                cast(str, expected["receipt_sha256"]),
            )
            for expected in self._pending_receipts
        }
        for binding in self._transaction_bindings.values():
            committed_group = {
                (cast(str, receipt["receipt_uri"]), cast(str, receipt["receipt_sha256"]))
                for receipt in cast(list[dict[str, Any]], binding["receipts"])
            }
            if not committed_group.issubset(referenced):
                raise AdminPlatformLedgerError(
                    "admin platform receipt transaction is only partially committed"
                )

    @staticmethod
    def _validate_active_candidate(
        active_stage: str,
        candidate: AdminPlatformCandidate,
        raw_entry: dict[str, Any],
    ) -> None:
        attempts = cast(list[dict[str, Any]], raw_entry["attempts"])
        if not attempts or candidate.release_id != attempts[-1]["release_id"]:
            raise AdminPlatformLedgerError("active candidate does not reference the latest attempt")
        if (
            candidate.repository != raw_entry["repository"]
            or candidate.source_sha != raw_entry["source_sha"]
            or candidate.reference != raw_entry["reference"]
        ):
            raise AdminPlatformLedgerError(
                f"active candidate tuple does not match the {active_stage} entry"
            )

    def snapshot(self) -> dict[str, Any]:
        """Return a deterministic, read-only audit projection."""

        assert self._raw_v3 is not None
        raw_entries = cast(dict[str, dict[str, Any]], self._raw_v3["entries"])
        return {
            "schema": SCHEMA_V3,
            "program": dict(self.program),
            "active_stage": self.active_stage,
            "active_candidate": (
                asdict(self.active_candidate)
                if isinstance(self.active_candidate, AdminPlatformCandidate)
                else None
            ),
            "entries": [
                {"entry_id": entry_id, **cast(dict[str, Any], _json_safe(raw_entries[entry_id]))}
                for entry_id in ORDER_V3
            ],
        }

    def document(self) -> dict[str, Any]:
        """Return a detached canonical document for a controller-owned transition."""

        assert self._raw_v3 is not None
        return deepcopy(self._raw_v3)

    def compatibility_snapshot_v1(self) -> dict[str, Any]:
        """Generate a non-admitting v1-shaped observer projection.

        The explicit compatibility schema and ``read_only`` marker prevent the
        projection from being mistaken for a mutable legacy admission ledger.
        """

        candidate = self.active_candidate
        return {
            "schema": COMPATIBILITY_SCHEMA_V1,
            "read_only": True,
            "admission": "disabled",
            "source_schema": self.schema_version,
            "active_candidate": self.active_stage,
            "candidate": (
                asdict(candidate) if isinstance(candidate, AdminPlatformCandidate) else None
            ),
            "entries": [
                {
                    "entry_id": entry.entry_id,
                    "project_id": entry.project_id,
                    "source_sha": entry.source_sha,
                    "status": entry.status,
                }
                for entry in self.entries
            ],
        }

    def validate_admission(self, entry_id: str, exact_sha: str) -> AdminPlatformLedgerEntry:
        """Require the exact active stage and source identity."""

        entry = self._by_entry_id.get(entry_id)
        if entry is None or self.active_stage != entry_id:
            raise AdminPlatformLedgerError("admin platform candidate is not active")
        candidate = self.active_candidate
        if (
            entry.status not in ACTIVE_STATUSES_V3
            or entry.source_sha != exact_sha
            or not isinstance(candidate, AdminPlatformCandidate)
            or candidate.source_sha != exact_sha
            or not self._active_source_is_verified()
        ):
            raise AdminPlatformLedgerError("admin platform candidate tuple is not admitted")
        return entry

    def classify_admission(self, entry_id: str, exact_sha: str) -> tuple[bool, str | None]:
        """Observe whether one queued tuple is currently admitted."""

        entry = self._by_entry_id.get(entry_id)
        if entry is None or self.active_stage != entry_id or entry.status not in ACTIVE_STATUSES_V3:
            return False, "admin-platform-candidate-not-active"
        candidate = self.active_candidate
        if (
            entry.source_sha != exact_sha
            or not isinstance(candidate, AdminPlatformCandidate)
            or candidate.source_sha != exact_sha
            or not self._active_source_is_verified()
        ):
            return False, "admin-platform-candidate-tuple-not-admitted"
        return True, None

    def _active_source_is_verified(self) -> bool:
        """Require immutable passing source evidence before queue admission."""

        if self.active_stage is None or not isinstance(
            self.active_candidate, AdminPlatformCandidate
        ):
            return False
        assert self._raw_v3 is not None
        entry = cast(dict[str, dict[str, Any]], self._raw_v3["entries"])[
            self.active_stage
        ]
        latest: str | None = None
        for result in cast(list[dict[str, Any]], entry["results"]):
            if (
                result["release_id"] == self.active_candidate.release_id
                and result["lane"] == "source"
            ):
                latest = cast(str, result["outcome"])
        return latest == "passed"


def controller_runtime_health(path: Path) -> ControllerRuntimeHealth:
    """Measure runtime identity from the activation status written on the host."""

    unavailable = ControllerRuntimeHealth(
        schema=RUNTIME_HEALTH_SCHEMA_V1,
        state="unavailable",
        revision=None,
        digest=None,
        activated=None,
        runtime_identity=None,
        dependency_identity=None,
        receipt=None,
    )
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return unavailable
    if not isinstance(value, dict):
        return unavailable
    schema = value.get("schema")
    if schema not in {CONTROLLER_RELEASE_SCHEMA_V1, CONTROLLER_RELEASE_SCHEMA_V2}:
        return unavailable
    if value.get("state") != "active":
        return unavailable
    legacy_keys = {
        "schema",
        "state",
        "revision",
        "release_digest",
        "activated_at",
    }
    measured_keys = legacy_keys | {"runtime_identity", "dependency_identity"}
    if set(value) != (legacy_keys if schema == CONTROLLER_RELEASE_SCHEMA_V1 else measured_keys):
        return unavailable
    revision = value.get("revision")
    release_digest = value.get("release_digest")
    activated_at = value.get("activated_at")
    if not isinstance(revision, str) or not _SHA.fullmatch(revision):
        return unavailable
    if not isinstance(release_digest, str) or not _SHA256.fullmatch(release_digest):
        return unavailable
    if schema == CONTROLLER_RELEASE_SCHEMA_V2 and not release_digest.startswith("sha256:"):
        return unavailable
    if not isinstance(activated_at, str):
        return unavailable
    try:
        parsed = datetime.fromisoformat(activated_at.replace("Z", "+00:00"))
    except ValueError:
        return unavailable
    if parsed.tzinfo is None:
        return unavailable
    normalized_digest = (
        release_digest if release_digest.startswith("sha256:") else f"sha256:{release_digest}"
    )
    receipt = cast(dict[str, Any], _json_safe(value))
    if schema == CONTROLLER_RELEASE_SCHEMA_V1:
        # Existing installations remain observable during the bounded bootstrap,
        # but a legacy activation is never represented as measured evidence.
        return ControllerRuntimeHealth(
            schema=RUNTIME_HEALTH_SCHEMA_V1,
            state="legacy",
            revision=revision,
            digest=normalized_digest,
            activated=activated_at,
            runtime_identity=None,
            dependency_identity=None,
            receipt=receipt,
        )

    runtime_identity = value.get("runtime_identity")
    dependency_identity = value.get("dependency_identity")
    if not isinstance(runtime_identity, dict) or set(runtime_identity) != {
        "source_revision",
        "source_digest",
        "public_image_id",
        "internal_image_id",
    }:
        return unavailable
    if not isinstance(dependency_identity, dict) or set(dependency_identity) != {
        "requirements_digest",
        "public_installed_digest",
        "internal_installed_digest",
    }:
        return unavailable
    source_revision = runtime_identity.get("source_revision")
    measured_digests = [
        runtime_identity.get("source_digest"),
        runtime_identity.get("public_image_id"),
        runtime_identity.get("internal_image_id"),
        dependency_identity.get("requirements_digest"),
        dependency_identity.get("public_installed_digest"),
        dependency_identity.get("internal_installed_digest"),
    ]
    if source_revision != revision or any(
        not isinstance(item, str) or not item.startswith("sha256:") or not _SHA256.fullmatch(item)
        for item in measured_digests
    ):
        return unavailable
    if (
        dependency_identity["public_installed_digest"]
        != dependency_identity["internal_installed_digest"]
    ):
        return unavailable
    return ControllerRuntimeHealth(
        schema=RUNTIME_HEALTH_SCHEMA_V1,
        state="active",
        revision=revision,
        digest=normalized_digest,
        activated=activated_at,
        runtime_identity=cast(dict[str, str], _json_safe(runtime_identity)),
        dependency_identity=cast(dict[str, str], _json_safe(dependency_identity)),
        receipt=receipt,
    )
