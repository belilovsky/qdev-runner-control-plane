"""Strict, independent admission ledger for controller-managed production releases."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "qdev-managed-release-ledger-v1"
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
            ci_runs = self._validate_ci_runs(raw["ci_runs"], project_id=project_id)
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
        self,
        entry_id: str,
        exact_sha: str,
        *,
        repository: str | None = None,
        run_id: str | None = None,
        attempt: str | None = None,
        job_id: str | None = None,
    ) -> ManagedReleaseLedgerEntry:
        entry = self._by_entry_id.get(entry_id)
        if entry is None:
            raise ManagedReleaseLedgerError("managed production candidate is not registered")
        if entry.status not in ACTIVE_STATUSES or entry.source_sha != exact_sha:
            raise ManagedReleaseLedgerError("managed production candidate tuple is not admitted")
        # Provider bindings are part of the durable admission record for lanes
        # that are waiting on already-created workflow runs.  A caller cannot
        # turn a same-SHA run, a different attempt, or a different repository
        # into an admissible claim by merely presenting ``status: passed``.
        bound_runs = [item for item in entry.ci_runs if "repository" in item or "job_id" in item]
        if bound_runs:
            if None in {repository, run_id, attempt, job_id}:
                raise ManagedReleaseLedgerError("managed production provider binding is incomplete")
            if not any(
                item.get("repository") == repository
                and item.get("run_id") == run_id
                and item.get("attempt") == attempt
                and item.get("job_id") == job_id
                for item in bound_runs
            ):
                raise ManagedReleaseLedgerError(
                    "managed production provider binding is not admitted"
                )
        return entry

    def validate_candidate_ci_runs(
        self, entry_id: str, exact_sha: str, run_ids: list[str]
    ) -> ManagedReleaseLedgerEntry:
        """Admit only the complete, terminal CI set recorded by the controller.

        The provider bindings in ``ci_runs`` are the controller's allowlist for
        the candidate.  A release receipt may not introduce an unregistered
        run, omit one of the bound runs, or turn a queued/in-progress run into
        evidence merely by reporting ``status: passed``.
        """

        entry = self._by_entry_id.get(entry_id)
        if entry is None:
            raise ManagedReleaseLedgerError("managed production candidate is not registered")
        if entry.source_sha != exact_sha:
            raise ManagedReleaseLedgerError("managed production candidate tuple is not admitted")
        if not isinstance(run_ids, list) or not run_ids:
            raise ManagedReleaseLedgerError("managed release CI evidence has no run IDs")
        if any(not isinstance(run_id, str) or not run_id.isdigit() for run_id in run_ids) or len(
            run_ids
        ) != len(set(run_ids)):
            raise ManagedReleaseLedgerError("managed release CI evidence run IDs are invalid")
        expected = {item["run_id"] for item in entry.ci_runs}
        if set(run_ids) != expected:
            raise ManagedReleaseLedgerError(
                "managed release CI evidence does not match the admitted run set"
            )
        if entry.status != "ci_passed" or any(
            item["state"] != "terminal" for item in entry.ci_runs
        ):
            raise ManagedReleaseLedgerError("managed release CI evidence is not terminal")
        return entry

    @staticmethod
    def _validate_stage(value: Any) -> None:
        if not isinstance(value, dict) or set(value) != {"state", "receipt_uri"}:
            raise ManagedReleaseLedgerError("managed release ledger evidence is invalid")
        if value["state"] not in STATUSES or (
            value["receipt_uri"] is not None and not isinstance(value["receipt_uri"], str)
        ):
            raise ManagedReleaseLedgerError("managed release ledger evidence state is invalid")

    @staticmethod
    def _validate_ci_runs(value: Any, *, project_id: str) -> tuple[dict[str, str], ...]:
        if not isinstance(value, list) or not value:
            raise ManagedReleaseLedgerError("managed release CI runs are invalid")
        result: list[dict[str, str]] = []
        run_ids: set[str] = set()
        provider_bindings: set[tuple[str, str, str, str]] = set()
        provider_jobs: set[tuple[str, str, str]] = set()
        for item in value:
            if not isinstance(item, dict):
                raise ManagedReleaseLedgerError("managed release CI run state is invalid")
            basic = {"run_id", "state"}
            extended = basic | {"repository", "job_id", "attempt"}
            allowed = extended if project_id == "qazgeo" else basic
            if (
                set(item) != allowed
                or not isinstance(item["run_id"], str)
                or not item["run_id"].isdigit()
                or item["state"] not in {"queued", "in_progress", "terminal"}
            ):
                raise ManagedReleaseLedgerError("managed release CI run state is invalid")
            if project_id == "qazgeo" and (
                not isinstance(item["repository"], str)
                or item["repository"] != "belilovsky/qazgeo"
                or not isinstance(item["job_id"], str)
                or not item["job_id"].isdigit()
                or not isinstance(item["attempt"], str)
                or not item["attempt"].isdigit()
                or int(item["attempt"]) < 1
            ):
                raise ManagedReleaseLedgerError("managed release CI provider binding is invalid")
            if project_id == "qazgeo":
                binding = (
                    item["repository"],
                    item["run_id"],
                    item["attempt"],
                    item["job_id"],
                )
                job = (item["repository"], item["run_id"], item["job_id"])
                # A workflow run may legitimately contain several jobs.  Keep
                # each concrete provider job/attempt binding unique, while
                # refusing a second record for the same job that could make
                # admission ambiguous.
                if binding in provider_bindings or job in provider_jobs:
                    raise ManagedReleaseLedgerError("managed release CI run state is invalid")
                provider_bindings.add(binding)
                provider_jobs.add(job)
            elif item["run_id"] in run_ids:
                raise ManagedReleaseLedgerError("managed release CI run state is invalid")
            run_ids.add(item["run_id"])
            result.append({str(key): str(value) for key, value in item.items()})
        return tuple(result)
