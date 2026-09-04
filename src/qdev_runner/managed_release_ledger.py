"""Strict, independent admission ledger for controller-managed production releases."""

from __future__ import annotations

import fcntl
import os
import re
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
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
    """Validator and controller-owned mutator for managed-production candidates.

    The ledger is normally consumed as configuration, but a controller must
    also be able to register provider jobs created by a verified ``push``
    event.  Those writes are deliberately tiny, locked and atomic: callers
    cannot replace the candidate, alter its repository, or turn an arbitrary
    client-supplied status into CI evidence.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
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

    def register_qgeo_ci_binding(
        self,
        *,
        repository: str,
        source_sha: str,
        run_id: str,
        attempt: str,
        job_id: str,
        state: str = "queued",
    ) -> dict[str, Any]:
        """Register one provider job for the exact QGeo candidate.

        Registration is an internal controller operation, not a general
        ledger editor.  It is idempotent for the exact tuple and refuses a
        conflicting reuse of a provider job or a different candidate.
        """

        if repository != "belilovsky/qazgeo":
            raise ManagedReleaseLedgerError("managed release repository is not QGeo")
        if not _SHA.fullmatch(source_sha):
            raise ManagedReleaseLedgerError("managed release source SHA is invalid")
        if not all(
            isinstance(value, str) and value.isdigit() for value in (run_id, attempt, job_id)
        ):
            raise ManagedReleaseLedgerError("managed release provider binding is invalid")
        if int(attempt) < 1 or int(run_id) < 1 or int(job_id) < 1:
            raise ManagedReleaseLedgerError("managed release provider binding is invalid")
        if state not in {"queued", "in_progress", "terminal"}:
            raise ManagedReleaseLedgerError("managed release provider state is invalid")
        entry = self._by_entry_id.get("qazgeo")
        if entry is None or entry.source_sha != source_sha:
            raise ManagedReleaseLedgerError("managed production candidate tuple is not admitted")

        binding = {
            "run_id": run_id,
            "state": state,
            "repository": repository,
            "job_id": job_id,
            "attempt": attempt,
        }
        for item in entry.ci_runs:
            same_job = item.get("repository") == repository and item.get("job_id") == job_id
            same_tuple = (
                same_job and item.get("run_id") == run_id and item.get("attempt") == attempt
            )
            if same_tuple:
                return {
                    "entry": entry,
                    "binding": dict(item),
                    "idempotent": True,
                    "backup_path": None,
                }
            if same_job:
                raise ManagedReleaseLedgerError("managed release provider job is already bound")

        def mutate(document: dict[str, Any]) -> None:
            raw_entry = document.get("entries", {}).get("qazgeo")
            if not isinstance(raw_entry, dict) or raw_entry.get("source_sha") != source_sha:
                raise ManagedReleaseLedgerError(
                    "managed production candidate tuple is not admitted"
                )
            raw_runs = raw_entry.get("ci_runs")
            if not isinstance(raw_runs, list):
                raise ManagedReleaseLedgerError("managed release CI runs are invalid")
            for raw_item in raw_runs:
                if not isinstance(raw_item, dict):
                    raise ManagedReleaseLedgerError("managed release CI run state is invalid")
                if raw_item.get("repository") == repository and raw_item.get("job_id") == job_id:
                    if raw_item.get("run_id") == run_id and raw_item.get("attempt") == attempt:
                        return
                    raise ManagedReleaseLedgerError("managed release provider job is already bound")
            raw_runs.append(binding)

        backup_path = self._atomic_update(mutate)
        refreshed = ManagedReleaseLedger(self.path)
        refreshed_entry = refreshed._by_entry_id["qazgeo"]
        return {
            "entry": refreshed_entry,
            "binding": dict(binding),
            "idempotent": False,
            "backup_path": str(backup_path) if backup_path is not None else None,
        }

    def reconcile_qgeo_ci_terminal(
        self,
        *,
        source_sha: str,
        verified_bindings: Sequence[Mapping[str, str]],
    ) -> dict[str, Any]:
        """Mark all provider bindings terminal after provider verification.

        The broker supplies only bindings it has independently fetched from
        GitHub and checked.  The method still compares the complete set under
        the file lock, so a stale or partial verification cannot promote CI.
        """

        entry = self._by_entry_id.get("qazgeo")
        if entry is None or entry.source_sha != source_sha:
            raise ManagedReleaseLedgerError("managed production candidate tuple is not admitted")
        expected = {
            (
                item.get("repository", ""),
                item.get("run_id", ""),
                item.get("attempt", ""),
                item.get("job_id", ""),
            )
            for item in entry.ci_runs
        }
        supplied: set[tuple[str, str, str, str]] = set()
        for item in verified_bindings:
            if not isinstance(item, Mapping):
                raise ManagedReleaseLedgerError("managed release CI verification is invalid")
            binding = (
                str(item.get("repository", "")),
                str(item.get("run_id", "")),
                str(item.get("attempt", "")),
                str(item.get("job_id", "")),
            )
            if binding in supplied:
                raise ManagedReleaseLedgerError("managed release CI verification is duplicated")
            supplied.add(binding)
        if supplied != expected:
            raise ManagedReleaseLedgerError("managed release CI verification is incomplete")

        already_terminal = entry.status == "ci_passed" and all(
            item["state"] == "terminal" for item in entry.ci_runs
        )

        def mutate(document: dict[str, Any]) -> None:
            raw_entry = document.get("entries", {}).get("qazgeo")
            if not isinstance(raw_entry, dict) or raw_entry.get("source_sha") != source_sha:
                raise ManagedReleaseLedgerError(
                    "managed production candidate tuple is not admitted"
                )
            raw_runs = raw_entry.get("ci_runs")
            if not isinstance(raw_runs, list):
                raise ManagedReleaseLedgerError("managed release CI runs are invalid")
            for raw_item in raw_runs:
                if not isinstance(raw_item, dict):
                    raise ManagedReleaseLedgerError("managed release CI run state is invalid")
                raw_item["state"] = "terminal"
            raw_entry["status"] = "ci_passed"
            raw_ci = raw_entry.get("ci")
            if not isinstance(raw_ci, dict):
                raise ManagedReleaseLedgerError("managed release CI evidence is invalid")
            raw_ci["state"] = "ci_passed"

        backup_path = None if already_terminal else self._atomic_update(mutate)
        refreshed = ManagedReleaseLedger(self.path)
        return {
            "entry": refreshed._by_entry_id["qazgeo"],
            "idempotent": already_terminal,
            "backup_path": str(backup_path) if backup_path is not None else None,
        }

    def _atomic_update(self, mutate: Any) -> Path | None:
        """Apply a controller mutation while preserving a rollback copy."""

        lock_path = self.path.with_name(f".{self.path.name}.lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            with os.fdopen(descriptor, "r+") as lock_stream:
                fcntl.flock(lock_stream.fileno(), fcntl.LOCK_EX)
                try:
                    document = yaml.safe_load(self.path.read_text(encoding="utf-8"))
                except (OSError, yaml.YAMLError) as exc:
                    raise ManagedReleaseLedgerError(
                        "managed release ledger is unavailable"
                    ) from exc
                if not isinstance(document, dict):
                    raise ManagedReleaseLedgerError("managed release ledger shape is invalid")
                before = yaml.safe_dump(document, sort_keys=False, allow_unicode=False)
                mutate(document)
                after = yaml.safe_dump(document, sort_keys=False, allow_unicode=False)
                if after == before:
                    return None
                stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%S.%fZ")
                backup = self.path.with_name(f"{self.path.name}.pre-qgeo-ledger-{stamp}.bak")
                try:
                    shutil.copy2(self.path, backup)
                except OSError as exc:
                    raise ManagedReleaseLedgerError("managed release ledger backup failed") from exc
                temporary_fd, temporary_name = tempfile.mkstemp(
                    prefix=f".{self.path.name}.", suffix=".tmp", dir=self.path.parent
                )
                os.close(temporary_fd)
                temporary = Path(temporary_name)
                try:
                    temporary.write_text(after, encoding="utf-8")
                    with temporary.open("rb") as stream:
                        os.fsync(stream.fileno())
                    os.chmod(temporary, self.path.stat().st_mode & 0o777)
                    os.replace(temporary, self.path)
                    directory_fd = os.open(self.path.parent, os.O_RDONLY)
                    try:
                        os.fsync(directory_fd)
                    finally:
                        os.close(directory_fd)
                except OSError as exc:
                    raise ManagedReleaseLedgerError("managed release ledger write failed") from exc
                finally:
                    if temporary.exists():
                        temporary.unlink()
                return backup
        finally:
            # The descriptor is closed by fdopen above.  Keep this defensive
            # branch for failures before fdopen takes ownership.
            with suppress(OSError):
                os.close(descriptor)

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

    def validate_candidate(self, entry_id: str, exact_sha: str) -> ManagedReleaseLedgerEntry:
        """Validate only the immutable candidate tuple.

        Provider bindings are intentionally not required here: this is the
        narrow prerequisite used while the controller registers a newly
        observed workflow job.  Full release admission still goes through
        ``validate_candidate_ci_runs`` after every bound job is terminal.
        """

        entry = self._by_entry_id.get(entry_id)
        if entry is None:
            raise ManagedReleaseLedgerError("managed production candidate is not registered")
        if entry.status not in ACTIVE_STATUSES or entry.source_sha != exact_sha:
            raise ManagedReleaseLedgerError("managed production candidate tuple is not admitted")
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
