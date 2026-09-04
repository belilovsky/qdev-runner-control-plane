"""Strict, source-versioned progress ledger for the Admin Platform release wave."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import date, datetime
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "qdev-admin-platform-ledger-v1"
SCHEMA_V1 = SCHEMA
SCHEMA_V2 = "qdev-admin-platform-ledger-v2"
ORDER = ("avds-admin-shell", "ortcom", "cmnt", "total", "qazposter")
STATUSES = frozenset(
    {"candidate", "ci_queued", "ci_passed", "deploying", "live_accepted", "rolled_back", "blocked"}
)
ACTIVE_STATUSES = frozenset({"candidate", "ci_queued", "ci_passed", "deploying"})
TERMINAL_STATUSES = frozenset({"live_accepted", "rolled_back"})
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _json_safe(value: Any) -> Any:
    """Convert YAML-native timestamp values to deterministic JSON scalars.

    ``yaml.safe_load`` intentionally resolves unquoted ISO timestamps to
    ``datetime``/``date`` instances.  Ledger snapshots are signed controller
    receipts, so they must have exactly the same JSON representation whether
    they came from YAML or an already materialized document.
    """
    if isinstance(value, datetime):
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, date):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    return value


class AdminPlatformLedgerError(ValueError):
    """Raised when the release ledger cannot provide a safe program state."""


@dataclass(frozen=True)
class AdminPlatformLedgerEntry:
    entry_id: str
    project_id: str
    source_sha: str | None
    status: str


class AdminPlatformLedger:
    """Read-only ledger validator; only controller receipts may advance it."""

    def __init__(self, path: Path) -> None:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise AdminPlatformLedgerError("admin platform ledger is unavailable") from exc
        if not isinstance(document, dict):
            raise AdminPlatformLedgerError("admin platform ledger shape is invalid")
        schema_version = document.get("schema_version")
        if schema_version not in {SCHEMA_V1, SCHEMA_V2}:
            raise AdminPlatformLedgerError("admin platform ledger schema is invalid")
        if schema_version == SCHEMA_V1 and set(document) != {
            "schema_version",
            "active_candidate",
            "entries",
        }:
            raise AdminPlatformLedgerError("admin platform ledger shape is invalid")
        if schema_version == SCHEMA_V2:
            # v2 adds durable prerequisites and append-only attempt history.
            # ``program`` is optional so a v1 document can be promoted without
            # fabricating an owner or release target.
            required_v2 = {
                "schema_version",
                "active_candidate",
                "prerequisites",
                "history",
                "attempts",
                "entries",
            }
            if not required_v2.issubset(document) or set(document) - (
                required_v2 | {"program"}
            ):
                raise AdminPlatformLedgerError("admin platform ledger v2 shape is invalid")
            self._validate_v2_program(document)
        self.schema_version = str(schema_version)
        active_candidate = document["active_candidate"]
        raw_entries = document["entries"]
        if active_candidate is not None and not isinstance(active_candidate, str):
            raise AdminPlatformLedgerError("admin platform ledger identity is invalid")
        if not isinstance(raw_entries, dict):
            raise AdminPlatformLedgerError("admin platform ledger identity is invalid")
        if tuple(raw_entries) != ORDER or (
            active_candidate is not None and active_candidate not in raw_entries
        ):
            raise AdminPlatformLedgerError("admin platform ledger order is invalid")

        entries: list[AdminPlatformLedgerEntry] = []
        # Normalize optional v2 evidence into a separate mapping.  Never mutate
        # the YAML object that was loaded from disk: callers may retain it for
        # diagnostics and a snapshot must describe the source faithfully.
        normalized_entries: dict[str, Any] = {
            entry_id: dict(raw) if isinstance(raw, dict) else raw
            for entry_id, raw in raw_entries.items()
        }
        required = {
            "project_id",
            "source_sha",
            "status",
            "artifact",
            "ci",
            "deploy",
            "live_acceptance",
            "rollback",
        }
        for entry_id, raw in raw_entries.items():
            raw = normalized_entries[entry_id]
            if not isinstance(raw, dict):
                raise AdminPlatformLedgerError("admin platform ledger entry is invalid")
            allowed = required | ({"observed_external_ci"} if entry_id == "qazposter" else set())
            if schema_version == SCHEMA_V2:
                allowed |= {"browser", "observation", "prerequisites", "attempts"}
            if not set(raw).issubset(allowed) or not required.issubset(raw):
                raise AdminPlatformLedgerError("admin platform ledger fields are invalid")
            project_id = raw["project_id"]
            source_sha = raw["source_sha"]
            status = raw["status"]
            if not isinstance(project_id, str) or not project_id:
                raise AdminPlatformLedgerError("admin platform ledger project is invalid")
            if source_sha is not None and (
                not isinstance(source_sha, str) or not _SHA.fullmatch(source_sha)
            ):
                raise AdminPlatformLedgerError("admin platform ledger source SHA is invalid")
            if not isinstance(status, str) or status not in STATUSES:
                raise AdminPlatformLedgerError("admin platform ledger status is invalid")
            stages: tuple[str, ...] = (
                "artifact",
                "ci",
                "deploy",
                "live_acceptance",
                "rollback",
            )
            if schema_version == SCHEMA_V2:
                stages += ("browser", "observation")
            for stage in stages:
                if stage not in raw:
                    # A v2 entry may be introduced while a stage has not yet
                    # been recorded.  It must still carry an explicit blocked
                    # result instead of relying on an implicit fallback.
                    if schema_version == SCHEMA_V2:
                        raw[stage] = {"state": "blocked", "receipt_uri": None}
                    else:
                        raise AdminPlatformLedgerError("admin platform ledger evidence is invalid")
                self._validate_stage(raw[stage])
            if schema_version == SCHEMA_V2:
                self._validate_entry_prerequisites(raw.get("prerequisites", {}), entry_id)
                self._validate_history_list(raw.get("attempts", []), "entry attempts")
            if entry_id == "qazposter":
                self._validate_external_ci(raw["observed_external_ci"])
            entries.append(AdminPlatformLedgerEntry(entry_id, project_id, source_sha, status))

        active_index = ORDER.index(active_candidate) if active_candidate is not None else len(ORDER)
        for index, entry in enumerate(entries):
            if index < active_index and entry.status not in TERMINAL_STATUSES:
                raise AdminPlatformLedgerError("prior release is not terminal")
            if index == active_index and entry.status not in ACTIVE_STATUSES:
                raise AdminPlatformLedgerError("active release status is invalid")
            if index > active_index and entry.status != "blocked":
                raise AdminPlatformLedgerError("later release is not blocked")
        if active_candidate is None and any(
            entry.status not in TERMINAL_STATUSES for entry in entries
        ):
            raise AdminPlatformLedgerError("closed admin platform ledger has nonterminal entries")
        self.active_candidate = active_candidate
        self.entries = tuple(entries)
        self._by_entry_id = {entry.entry_id: entry for entry in entries}
        self.program = dict(document.get("program", {})) if schema_version == SCHEMA_V2 else {}
        self.prerequisites = (
            dict(document.get("prerequisites", {})) if schema_version == SCHEMA_V2 else {}
        )
        self.history = list(document.get("history", [])) if schema_version == SCHEMA_V2 else []
        self.attempts = list(document.get("attempts", [])) if schema_version == SCHEMA_V2 else []
        self._raw_entries = {
            entry_id: {
                stage: dict(normalized_entries[entry_id][stage])
                for stage in (
                    "artifact",
                    "ci",
                    "deploy",
                    "browser",
                    "observation",
                    "live_acceptance",
                    "rollback",
                )
                if stage in raw_entries[entry_id]
            }
            | (
                {"observed_external_ci": dict(normalized_entries[entry_id]["observed_external_ci"])}
                if entry_id == "qazposter"
                else {}
            )
            for entry_id in ORDER
        }

    def snapshot(self) -> dict[str, Any]:
        """Return a non-mutating, source-bound projection for controller audits."""
        document: dict[str, Any] = {
            "schema": self.schema_version,
            "active_candidate": self.active_candidate,
            "entries": [],
        }
        if self.schema_version == SCHEMA_V2:
            document.update(
                {
                    "program": self.program,
                    "prerequisites": self.prerequisites,
                    "history": self.history,
                    "attempts": self.attempts,
                }
            )
        for entry in self.entries:
            item: dict[str, Any] = {
                "entry_id": entry.entry_id,
                "project_id": entry.project_id,
                "source_sha": entry.source_sha,
                "status": entry.status,
            }
            source = self._raw_entries[entry.entry_id]
            for stage in (
                "artifact",
                "ci",
                "deploy",
                "browser",
                "observation",
                "live_acceptance",
                "rollback",
            ):
                if stage in source:
                    item[stage] = dict(source[stage])
            if entry.entry_id == "qazposter":
                item["observed_external_ci"] = dict(source["observed_external_ci"])
            document["entries"].append(item)
        return _json_safe(document)

    def validate_admission(self, entry_id: str, exact_sha: str) -> AdminPlatformLedgerEntry:
        """Require the next controller claim to match the one active candidate."""
        entry = self._by_entry_id.get(entry_id)
        if entry is None or self.active_candidate != entry_id:
            raise AdminPlatformLedgerError("admin platform candidate is not active")
        if entry.status not in ACTIVE_STATUSES or entry.source_sha != exact_sha:
            raise AdminPlatformLedgerError("admin platform candidate tuple is not admitted")
        return entry

    @staticmethod
    def _validate_stage(value: Any) -> None:
        if not isinstance(value, dict) or set(value) != {"state", "receipt_uri"}:
            raise AdminPlatformLedgerError("admin platform ledger evidence is invalid")
        if value["state"] not in STATUSES or (
            value["receipt_uri"] is not None and not isinstance(value["receipt_uri"], str)
        ):
            raise AdminPlatformLedgerError("admin platform ledger evidence state is invalid")

    @staticmethod
    def _validate_external_ci(value: Any) -> None:
        if not isinstance(value, dict) or set(value) != {"run_id", "state"}:
            raise AdminPlatformLedgerError("external CI observation is invalid")
        if not isinstance(value["run_id"], str) or value["state"] not in {
            "queued",
            "in_progress",
            "terminal",
        }:
            raise AdminPlatformLedgerError("external CI observation state is invalid")

    @staticmethod
    def _validate_history_list(value: Any, label: str) -> None:
        if not isinstance(value, list):
            raise AdminPlatformLedgerError(f"{label} must be a list")
        for item in value:
            if not isinstance(item, dict):
                raise AdminPlatformLedgerError(f"{label} contains an invalid record")
            # History is deliberately non-secret and receipt-oriented.  Do
            # not accept arbitrary blobs that could later be treated as proof.
            if set(item) - {
                "attempt_id",
                "release_id",
                "state",
                "started_at",
                "finished_at",
                "receipt_uri",
                "reason",
            }:
                raise AdminPlatformLedgerError(f"{label} fields are invalid")
            if "state" in item and item["state"] not in STATUSES:
                raise AdminPlatformLedgerError(f"{label} state is invalid")

    @classmethod
    def _validate_entry_prerequisites(cls, value: Any, entry_id: str) -> None:
        if not isinstance(value, dict):
            raise AdminPlatformLedgerError(f"{entry_id} prerequisites are invalid")
        for prerequisite, state in value.items():
            if not isinstance(prerequisite, str) or not prerequisite:
                raise AdminPlatformLedgerError(f"{entry_id} prerequisite identity is invalid")
            if not (
                (isinstance(state, str) and state in STATUSES)
                or (isinstance(state, dict) and set(state) == {"state", "receipt_uri"})
            ):
                raise AdminPlatformLedgerError(f"{entry_id} prerequisite state is invalid")
            if isinstance(state, dict):
                cls._validate_stage(state)

    @classmethod
    def _validate_v2_program(cls, document: dict[str, Any]) -> None:
        prerequisites = document.get("prerequisites")
        history = document.get("history")
        attempts = document.get("attempts")
        if not isinstance(prerequisites, dict):
            raise AdminPlatformLedgerError("admin platform prerequisites are invalid")
        expected_prerequisites = {
            "controller",
            "qaz_admin_kit",
            "avds_admin_shell",
            "compatibility_matrix",
        }
        if set(prerequisites) != expected_prerequisites:
            raise AdminPlatformLedgerError("admin platform prerequisites fields are invalid")
        for prerequisite in expected_prerequisites:
            cls._validate_stage(prerequisites[prerequisite])
        cls._validate_history_list(history, "admin platform history")
        cls._validate_history_list(attempts, "admin platform attempts")
        program = document.get("program", {})
        if not isinstance(program, dict) or set(program) - {
            "id",
            "owner",
            "status",
            "updated_at",
        }:
            raise AdminPlatformLedgerError("admin platform program metadata is invalid")
        if program.get("status") is not None and program.get("status") not in {
            "active",
            "complete",
            "blocked",
        }:
            raise AdminPlatformLedgerError("admin platform program status is invalid")
