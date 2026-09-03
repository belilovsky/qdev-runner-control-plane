"""Strict, source-versioned progress ledger for the Admin Platform release wave."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "qdev-admin-platform-ledger-v1"
ORDER = ("avds-admin-shell", "ortcom", "cmnt", "total", "qazposter")
STATUSES = frozenset(
    {"candidate", "ci_queued", "ci_passed", "deploying", "live_accepted", "rolled_back", "blocked"}
)
ACTIVE_STATUSES = frozenset({"candidate", "ci_queued", "ci_passed", "deploying"})
TERMINAL_STATUSES = frozenset({"live_accepted", "rolled_back"})
_SHA = re.compile(r"^[0-9a-f]{40}$")


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
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "active_candidate",
            "entries",
        }:
            raise AdminPlatformLedgerError("admin platform ledger shape is invalid")
        if document["schema_version"] != SCHEMA:
            raise AdminPlatformLedgerError("admin platform ledger schema is invalid")
        active_candidate = document["active_candidate"]
        raw_entries = document["entries"]
        if not isinstance(active_candidate, str) or not isinstance(raw_entries, dict):
            raise AdminPlatformLedgerError("admin platform ledger identity is invalid")
        if tuple(raw_entries) != ORDER or active_candidate not in raw_entries:
            raise AdminPlatformLedgerError("admin platform ledger order is invalid")

        entries: list[AdminPlatformLedgerEntry] = []
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
            if not isinstance(raw, dict):
                raise AdminPlatformLedgerError("admin platform ledger entry is invalid")
            allowed = required | ({"observed_external_ci"} if entry_id == "qazposter" else set())
            if set(raw) != allowed:
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
            for stage in ("artifact", "ci", "deploy", "live_acceptance", "rollback"):
                self._validate_stage(raw[stage])
            if entry_id == "qazposter":
                self._validate_external_ci(raw["observed_external_ci"])
            entries.append(AdminPlatformLedgerEntry(entry_id, project_id, source_sha, status))

        active_index = ORDER.index(active_candidate)
        for index, entry in enumerate(entries):
            if index < active_index and entry.status not in TERMINAL_STATUSES:
                raise AdminPlatformLedgerError("prior release is not terminal")
            if index == active_index and entry.status not in ACTIVE_STATUSES:
                raise AdminPlatformLedgerError("active release status is invalid")
            if index > active_index and entry.status != "blocked":
                raise AdminPlatformLedgerError("later release is not blocked")
        self.active_candidate = active_candidate
        self.entries = tuple(entries)
        self._by_entry_id = {entry.entry_id: entry for entry in entries}
        self._raw_entries = {
            entry_id: {
                stage: dict(raw_entries[entry_id][stage])
                for stage in ("artifact", "ci", "deploy", "live_acceptance", "rollback")
            }
            | (
                {"observed_external_ci": dict(raw_entries[entry_id]["observed_external_ci"])}
                if entry_id == "qazposter"
                else {}
            )
            for entry_id in ORDER
        }

    def snapshot(self) -> dict[str, Any]:
        """Return a non-mutating, source-bound projection for controller audits."""
        document: dict[str, Any] = {
            "schema": SCHEMA,
            "active_candidate": self.active_candidate,
            "entries": [],
        }
        for entry in self.entries:
            item: dict[str, Any] = {
                "entry_id": entry.entry_id,
                "project_id": entry.project_id,
                "source_sha": entry.source_sha,
                "status": entry.status,
            }
            source = self._raw_entries[entry.entry_id]
            for stage in ("artifact", "ci", "deploy", "live_acceptance", "rollback"):
                item[stage] = dict(source[stage])
            if entry.entry_id == "qazposter":
                item["observed_external_ci"] = dict(source["observed_external_ci"])
            document["entries"].append(item)
        return document

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
