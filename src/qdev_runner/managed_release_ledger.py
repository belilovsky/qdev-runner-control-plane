"""Strict, independent admission ledger for controller-managed production releases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "qdev-managed-release-ledger-v2"
STATUSES = frozenset(
    {"candidate", "ci_queued", "ci_passed", "deploying", "live_accepted", "rolled_back", "blocked"}
)
ACTIVE_STATUSES = frozenset({"candidate", "ci_queued", "ci_passed", "deploying"})
_ENTRY_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


class ManagedReleaseLedgerError(ValueError):
    """Raised when a managed production ledger cannot safely admit a claim."""


@dataclass(frozen=True)
class ManagedReleaseLedgerEntry:
    entry_id: str
    project_id: str
    source_sha: str
    status: str
    ci_runs: tuple[dict[str, str], ...]


class ManagedReleaseLedger:
    """Read-only validator for isolated managed-production candidates."""

    def __init__(self, path: Path) -> None:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ManagedReleaseLedgerError("managed release ledger is unavailable") from exc
        if not isinstance(document, dict) or set(document) != {"schema_version", "entries"}:
            raise ManagedReleaseLedgerError("managed release ledger shape is invalid")
        if document["schema_version"] != SCHEMA:
            raise ManagedReleaseLedgerError("managed release ledger schema is invalid")
        raw_entries = document["entries"]
        if not isinstance(raw_entries, dict) or not raw_entries:
            raise ManagedReleaseLedgerError("managed release ledger has no entries")

        expected = {
            "project_id",
            "source_sha",
            "status",
            "ci_runs",
            "artifact",
            "ci",
            "deploy",
            "live_acceptance",
            "rollback",
        }
        entries: dict[str, ManagedReleaseLedgerEntry] = {}
        raw_snapshots: dict[str, dict[str, Any]] = {}
        for entry_id, raw in raw_entries.items():
            if (
                not isinstance(entry_id, str)
                or not _ENTRY_ID.fullmatch(entry_id)
                or not isinstance(raw, dict)
                or set(raw) != expected
            ):
                raise ManagedReleaseLedgerError("managed release ledger entry is invalid")
            project_id = raw["project_id"]
            source_sha = raw["source_sha"]
            status = raw["status"]
            if not isinstance(project_id, str) or not project_id:
                raise ManagedReleaseLedgerError("managed release ledger project is invalid")
            if not isinstance(source_sha, str) or not _SHA.fullmatch(source_sha):
                raise ManagedReleaseLedgerError("managed release ledger source SHA is invalid")
            if not isinstance(status, str) or status not in STATUSES:
                raise ManagedReleaseLedgerError("managed release ledger status is invalid")
            ci_runs = self._validate_ci_runs(raw["ci_runs"])
            for stage in ("artifact", "ci", "deploy", "live_acceptance", "rollback"):
                self._validate_stage(raw[stage])
            entries[entry_id] = ManagedReleaseLedgerEntry(
                entry_id=entry_id,
                project_id=project_id,
                source_sha=source_sha,
                status=status,
                ci_runs=ci_runs,
            )
            raw_snapshots[entry_id] = {
                stage: dict(raw[stage])
                for stage in ("artifact", "ci", "deploy", "live_acceptance", "rollback")
            }

        self.entries = tuple(entries.values())
        self._by_entry_id = entries
        self._raw_snapshots = raw_snapshots

    def snapshot(self) -> dict[str, Any]:
        return {
            "schema": SCHEMA,
            "entries": [
                {
                    "entry_id": entry.entry_id,
                    "project_id": entry.project_id,
                    "source_sha": entry.source_sha,
                    "status": entry.status,
                    "ci_runs": [dict(item) for item in entry.ci_runs],
                    **self._raw_snapshots[entry.entry_id],
                }
                for entry in self.entries
            ],
        }

    def validate_admission(
        self, entry_id: str, exact_sha: str, *, run_id: int, run_attempt: int
    ) -> ManagedReleaseLedgerEntry:
        entry = self._by_entry_id.get(entry_id)
        if entry is None:
            raise ManagedReleaseLedgerError("managed production candidate is not registered")
        if entry.status not in ACTIVE_STATUSES or entry.source_sha != exact_sha:
            raise ManagedReleaseLedgerError("managed production candidate tuple is not admitted")
        if not any(
            item["run_id"] == str(run_id)
            and item["run_attempt"] == str(run_attempt)
            and item["state"] in {"queued", "in_progress"}
            for item in entry.ci_runs
        ):
            raise ManagedReleaseLedgerError("managed production CI run is not admitted")
        return entry

    def classify_admission(
        self, entry_id: str, exact_sha: str, *, run_id: int, run_attempt: int
    ) -> tuple[bool, str | None]:
        """Observe whether a queued managed-production tuple remains admissible.

        Direct claims continue to use :meth:`validate_admission` and fail
        closed. This observational form exists only for FIFO scans, where a
        retired or superseded production candidate must remain recorded but
        must not indefinitely hold an unrelated profile queue.
        """

        entry = self._by_entry_id.get(entry_id)
        if entry is None or entry.status not in ACTIVE_STATUSES:
            return False, "managed-production-candidate-not-active"
        if entry.source_sha != exact_sha:
            return False, "managed-production-candidate-tuple-not-admitted"
        if not any(
            item["run_id"] == str(run_id)
            and item["run_attempt"] == str(run_attempt)
            and item["state"] in {"queued", "in_progress"}
            for item in entry.ci_runs
        ):
            return False, "managed-production-candidate-tuple-not-admitted"
        return True, None

    @staticmethod
    def _validate_stage(value: Any) -> None:
        if not isinstance(value, dict) or set(value) != {"state", "receipt_uri"}:
            raise ManagedReleaseLedgerError("managed release ledger evidence is invalid")
        if value["state"] not in STATUSES or (
            value["receipt_uri"] is not None and not isinstance(value["receipt_uri"], str)
        ):
            raise ManagedReleaseLedgerError("managed release ledger evidence state is invalid")

    @staticmethod
    def _validate_ci_runs(value: Any) -> tuple[dict[str, str], ...]:
        if not isinstance(value, list) or not value:
            raise ManagedReleaseLedgerError("managed release CI runs are invalid")
        result: list[dict[str, str]] = []
        run_tuples: set[tuple[str, str]] = set()
        for item in value:
            if (
                not isinstance(item, dict)
                or set(item) != {"run_id", "run_attempt", "state"}
                or not isinstance(item["run_id"], str)
                or not item["run_id"].isdigit()
                or not isinstance(item["run_attempt"], str)
                or not item["run_attempt"].isdigit()
                or int(item["run_attempt"]) < 1
                or item["state"] not in {"queued", "in_progress", "terminal"}
                or (item["run_id"], item["run_attempt"]) in run_tuples
            ):
                raise ManagedReleaseLedgerError("managed release CI run state is invalid")
            run_tuples.add((item["run_id"], item["run_attempt"]))
            result.append(
                {
                    "run_id": item["run_id"],
                    "run_attempt": item["run_attempt"],
                    "state": item["state"],
                }
            )
        return tuple(result)
