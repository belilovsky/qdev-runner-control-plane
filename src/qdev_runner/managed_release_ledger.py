"""Strict, independent admission ledger for controller-managed releases."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import shutil
import tempfile
from collections.abc import Callable, Mapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import yaml

SCHEMA = "qdev-managed-release-ledger-v2"
STATUSES = frozenset(
    {
        "registration",
        "ci_queued",
        "ci_passed",
        "deploying",
        "live_accepted",
        "rolled_back",
        "blocked",
    }
)
ACTIVE_STATUSES = frozenset({"ci_queued", "ci_passed", "deploying"})
REGISTRATION_STATES = frozenset({"closed", "open", "sealed"})
REGISTRATION_PHASES = frozenset({"pull_request", "push"})
QGEO_REPOSITORY = "belilovsky/qazgeo"
QGEO_PROFILES = frozenset({"qdev-ci", "qdev-ci-docker"})
QGEO_REQUIRED_JOB_PROFILES: dict[str, dict[str, dict[str, str]]] = {
    "pull_request": {
        ".github/workflows/ci.yml": {
            "lint": "qdev-ci",
            "security-source": "qdev-ci",
            "test": "qdev-ci-docker",
        },
        ".github/workflows/qdev-runner-contract.yml": {"contract": "qdev-ci"},
    },
    "push": {
        ".github/workflows/ci.yml": {
            "lint": "qdev-ci",
            "security-source": "qdev-ci",
            "test": "qdev-ci-docker",
            "docker-build": "qdev-ci-docker",
        },
        ".github/workflows/qdev-runner-contract.yml": {"contract": "qdev-ci"},
    },
}

_ENTRY_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9][A-Za-z0-9._/-]*\.ya?ml$")
_PR_REF = re.compile(r"^refs/pull/[1-9][0-9]*/merge$")
_JOB_NAME = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,126}[a-z0-9])?$")

_BINDING_KEYS = {
    "repository",
    "candidate_sha",
    "checkout_sha",
    "run_id",
    "attempt",
    "job_id",
    "workflow_path",
    "event",
    "ref",
    "head_branch",
    "profile",
    "labels",
    "job_name",
    "state",
    "conclusion",
}
_BINDING_IDENTITY_KEYS = _BINDING_KEYS - {"state", "conclusion"}


class ManagedReleaseLedgerError(ValueError):
    """Raised when a managed production ledger cannot safely admit a claim."""


@dataclass(frozen=True)
class ManagedReleaseLedgerEntry:
    entry_id: str
    project_id: str
    source_sha: str | None
    status: str
    registration_state: str
    registration_phase: str | None
    pr_verified: bool
    required_workflows: tuple[str, ...]
    job_set_digest: str | None
    ci_runs: tuple[dict[str, Any], ...]


def _canonical_binding(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _job_set_digest(bindings: Sequence[Mapping[str, Any]]) -> str:
    identities = [
        {key: binding[key] for key in sorted(_BINDING_IDENTITY_KEYS)} for binding in bindings
    ]
    identities.sort(key=_canonical_binding)
    encoded = json.dumps(
        identities,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _binding_key(value: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(value["repository"]),
        str(value["run_id"]),
        str(value["attempt"]),
        str(value["job_id"]),
    )


def _binding_identity(value: Mapping[str, Any]) -> dict[str, Any]:
    return {key: value[key] for key in _BINDING_IDENTITY_KEYS}


def qgeo_dynamic_job_label(run_id: str, attempt: str, job_name: str) -> str:
    """Derive the one exact per-job runner label bound by QGeo CI."""

    if (
        not run_id.isdigit()
        or int(run_id) < 1
        or not attempt.isdigit()
        or int(attempt) < 1
        or _JOB_NAME.fullmatch(job_name) is None
    ):
        raise ManagedReleaseLedgerError("managed release CI job label identity is invalid")
    return f"qdev-job-{run_id}-{attempt}-{job_name}"


def _validate_required_workflows(value: object) -> tuple[str, ...]:
    if (
        not isinstance(value, list)
        or not value
        or any(
            not isinstance(item, str) or _WORKFLOW_PATH.fullmatch(item) is None for item in value
        )
        or len(value) != len(set(value))
        or value != sorted(value)
    ):
        raise ManagedReleaseLedgerError("managed release required workflows are invalid")
    return tuple(value)


def _validate_binding(
    value: object,
    *,
    source_sha: str,
    phase: str,
    required_workflows: tuple[str, ...],
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _BINDING_KEYS:
        raise ManagedReleaseLedgerError("managed release CI provider binding is invalid")
    binding = dict(value)
    string_fields = _BINDING_KEYS - {"labels", "conclusion"}
    if any(not isinstance(binding[field], str) for field in string_fields):
        raise ManagedReleaseLedgerError("managed release CI provider binding is invalid")
    if binding["repository"] != QGEO_REPOSITORY or binding["candidate_sha"] != source_sha:
        raise ManagedReleaseLedgerError("managed release CI provider binding is foreign")
    if _SHA.fullmatch(binding["checkout_sha"]) is None:
        raise ManagedReleaseLedgerError("managed release checkout SHA is invalid")
    if any(
        not binding[field].isdigit() or int(binding[field]) < 1
        for field in ("run_id", "attempt", "job_id")
    ):
        raise ManagedReleaseLedgerError("managed release CI provider binding is invalid")
    if binding["workflow_path"] not in required_workflows:
        raise ManagedReleaseLedgerError("managed release workflow is not required")
    if binding["event"] != phase:
        raise ManagedReleaseLedgerError("managed release CI event is invalid")
    if not binding["head_branch"] or _JOB_NAME.fullmatch(binding["job_name"]) is None:
        raise ManagedReleaseLedgerError("managed release CI provider binding is invalid")
    if binding["profile"] not in QGEO_PROFILES:
        raise ManagedReleaseLedgerError("managed release CI profile is invalid")
    required_profile = (
        QGEO_REQUIRED_JOB_PROFILES.get(phase, {})
        .get(binding["workflow_path"], {})
        .get(binding["job_name"])
    )
    if required_profile != binding["profile"]:
        raise ManagedReleaseLedgerError("managed release CI job selector is not required")
    labels = binding["labels"]
    expected_labels = sorted(
        (
            "self-hosted",
            "Linux",
            "X64",
            binding["profile"],
            qgeo_dynamic_job_label(binding["run_id"], binding["attempt"], binding["job_name"]),
        )
    )
    if not isinstance(labels, list) or labels != expected_labels:
        raise ManagedReleaseLedgerError("managed release CI labels are invalid")
    if phase == "pull_request":
        if _PR_REF.fullmatch(binding["ref"]) is None or binding["checkout_sha"] == source_sha:
            raise ManagedReleaseLedgerError("managed release pull request identity is invalid")
    elif phase == "push":
        if (
            binding["ref"] != "refs/heads/main"
            or binding["head_branch"] != "main"
            or binding["checkout_sha"] != source_sha
        ):
            raise ManagedReleaseLedgerError("managed release main push identity is invalid")
    else:  # pragma: no cover - caller validates this first
        raise ManagedReleaseLedgerError("managed release registration phase is invalid")
    state = binding["state"]
    conclusion = binding["conclusion"]
    if state not in {"queued", "in_progress", "terminal"}:
        raise ManagedReleaseLedgerError("managed release CI state is invalid")
    if state == "terminal":
        if conclusion != "success":
            raise ManagedReleaseLedgerError("managed release CI conclusion is invalid")
    elif conclusion is not None:
        raise ManagedReleaseLedgerError("managed release CI conclusion is premature")
    return binding


def _validate_ci_runs(
    value: object,
    *,
    source_sha: str,
    phase: str,
    required_workflows: tuple[str, ...],
) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or not value:
        raise ManagedReleaseLedgerError("managed release CI runs are invalid")
    result: list[dict[str, Any]] = []
    provider_bindings: set[tuple[str, str, str, str]] = set()
    provider_jobs: set[tuple[str, str]] = set()
    run_identity: dict[str, tuple[str, str, str, str, str, str]] = {}
    workflow_runs: dict[str, str] = {}
    for raw in value:
        item = _validate_binding(
            raw,
            source_sha=source_sha,
            phase=phase,
            required_workflows=required_workflows,
        )
        binding = _binding_key(item)
        job = (item["repository"], item["job_id"])
        if binding in provider_bindings or job in provider_jobs:
            raise ManagedReleaseLedgerError("managed release CI run state is duplicated")
        provider_bindings.add(binding)
        provider_jobs.add(job)
        common = (
            item["attempt"],
            item["workflow_path"],
            item["event"],
            item["ref"],
            item["head_branch"],
            item["checkout_sha"],
        )
        previous = run_identity.setdefault(item["run_id"], common)
        if previous != common:
            raise ManagedReleaseLedgerError("managed release workflow run identity is ambiguous")
        prior_run = workflow_runs.setdefault(item["workflow_path"], item["run_id"])
        if prior_run != item["run_id"]:
            raise ManagedReleaseLedgerError("managed release workflow has multiple runs")
        result.append(item)
    return tuple(result)


class ManagedReleaseLedger:
    """Controller-owned QGeo candidate and exact provider-job state machine."""

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

        entries: dict[str, ManagedReleaseLedgerEntry] = {}
        raw_snapshots: dict[str, dict[str, Any]] = {}
        for entry_id, raw in raw_entries.items():
            entry = self._parse_entry(entry_id, raw)
            entries[entry_id] = entry
            assert isinstance(raw, dict)
            raw_snapshots[entry_id] = {
                stage: dict(raw[stage])
                for stage in ("artifact", "ci", "deploy", "live_acceptance", "rollback")
            }
        self.entries = tuple(entries.values())
        self._by_entry_id = entries
        self._raw_snapshots = raw_snapshots

    @classmethod
    def _parse_entry(cls, entry_id: object, raw: object) -> ManagedReleaseLedgerEntry:
        expected = {
            "project_id",
            "source_sha",
            "status",
            "registration",
            "ci_runs",
            "artifact",
            "ci",
            "deploy",
            "live_acceptance",
            "rollback",
        }
        if (
            not isinstance(entry_id, str)
            or _ENTRY_ID.fullmatch(entry_id) is None
            or not isinstance(raw, dict)
            or set(raw) != expected
        ):
            raise ManagedReleaseLedgerError("managed release ledger entry is invalid")
        project_id = raw["project_id"]
        status = raw["status"]
        if entry_id != "qazgeo" or project_id != "qazgeo":
            raise ManagedReleaseLedgerError("managed release ledger project is invalid")
        if not isinstance(status, str) or status not in STATUSES:
            raise ManagedReleaseLedgerError("managed release ledger status is invalid")
        registration = raw["registration"]
        registration_keys = {
            "state",
            "phase",
            "pr_verified",
            "required_workflows",
            "job_set_digest",
        }
        if not isinstance(registration, dict) or set(registration) != registration_keys:
            raise ManagedReleaseLedgerError("managed release registration is invalid")
        state = registration["state"]
        phase = registration["phase"]
        pr_verified = registration["pr_verified"]
        job_set_digest = registration["job_set_digest"]
        if state not in REGISTRATION_STATES or not isinstance(pr_verified, bool):
            raise ManagedReleaseLedgerError("managed release registration is invalid")
        required_workflows = _validate_required_workflows(registration["required_workflows"])
        source_sha = raw["source_sha"]

        if state == "closed":
            if (
                source_sha is not None
                or phase is not None
                or pr_verified
                or job_set_digest is not None
                or raw["ci_runs"] != []
                or status != "registration"
            ):
                raise ManagedReleaseLedgerError("closed managed release registration is invalid")
            ci_runs: tuple[dict[str, Any], ...] = ()
        else:
            if (
                not isinstance(source_sha, str)
                or _SHA.fullmatch(source_sha) is None
                or phase not in REGISTRATION_PHASES
            ):
                raise ManagedReleaseLedgerError("managed release candidate identity is invalid")
            ci_runs = _validate_ci_runs(
                raw["ci_runs"],
                source_sha=source_sha,
                phase=phase,
                required_workflows=required_workflows,
            )
            if phase == "pull_request" and state == "open" and pr_verified:
                raise ManagedReleaseLedgerError("open pull request cannot be pre-verified")
            if phase == "push" and not pr_verified:
                raise ManagedReleaseLedgerError("main push requires verified pull request CI")
            if state == "open":
                if job_set_digest is not None or status != "ci_queued":
                    raise ManagedReleaseLedgerError("open managed release registration is invalid")
            else:
                if (
                    status != "ci_passed"
                    or not pr_verified
                    or any(
                        item["state"] != "terminal" or item["conclusion"] != "success"
                        for item in ci_runs
                    )
                    or not isinstance(job_set_digest, str)
                    or _DIGEST.fullmatch(job_set_digest) is None
                    or job_set_digest != _job_set_digest(ci_runs)
                ):
                    raise ManagedReleaseLedgerError(
                        "sealed managed release registration is invalid"
                    )
        for stage in ("artifact", "ci", "deploy", "live_acceptance", "rollback"):
            cls._validate_stage(raw[stage])
        expected_ci_state = {
            "closed": "registration",
            "open": "ci_queued",
            "sealed": "ci_passed",
        }[state]
        if raw["ci"]["state"] != expected_ci_state:
            raise ManagedReleaseLedgerError("managed release CI evidence state is invalid")
        return ManagedReleaseLedgerEntry(
            entry_id=entry_id,
            project_id=project_id,
            source_sha=source_sha,
            status=status,
            registration_state=state,
            registration_phase=phase,
            pr_verified=pr_verified,
            required_workflows=required_workflows,
            job_set_digest=job_set_digest,
            ci_runs=ci_runs,
        )

    def register_qgeo_ci_binding(
        self,
        *,
        repository: str,
        source_sha: str,
        checkout_sha: str,
        run_id: str,
        attempt: str,
        job_id: str,
        workflow_path: str,
        event: str,
        ref: str,
        head_branch: str,
        profile: str,
        labels: Sequence[str],
        job_name: str,
        state: str,
        conclusion: str | None,
    ) -> dict[str, Any]:
        """Open/advance one controller-observed QGeo CI registration."""

        if repository != QGEO_REPOSITORY or _SHA.fullmatch(source_sha) is None:
            raise ManagedReleaseLedgerError("managed release candidate identity is invalid")
        entry = self._by_entry_id.get("qazgeo")
        if entry is None:
            raise ManagedReleaseLedgerError("managed production candidate is not registered")
        binding = _validate_binding(
            {
                "repository": repository,
                "candidate_sha": source_sha,
                "checkout_sha": checkout_sha,
                "run_id": run_id,
                "attempt": attempt,
                "job_id": job_id,
                "workflow_path": workflow_path,
                "event": event,
                "ref": ref,
                "head_branch": head_branch,
                "profile": profile,
                "labels": sorted(labels),
                "job_name": job_name,
                "state": state,
                "conclusion": conclusion,
            },
            source_sha=source_sha,
            phase=event,
            required_workflows=entry.required_workflows,
        )
        binding_result: dict[str, Any] = dict(binding)

        def mutate(document: dict[str, Any]) -> None:
            nonlocal binding_result
            raw_entry = document.get("entries", {}).get("qazgeo")
            if not isinstance(raw_entry, dict):
                raise ManagedReleaseLedgerError("managed production candidate is not registered")
            registration = raw_entry.get("registration")
            raw_runs = raw_entry.get("ci_runs")
            raw_ci = raw_entry.get("ci")
            if (
                not isinstance(registration, dict)
                or not isinstance(raw_runs, list)
                or not isinstance(raw_ci, dict)
            ):
                raise ManagedReleaseLedgerError("managed release ledger state is invalid")
            current_state = registration.get("state")
            current_phase = registration.get("phase")
            current_sha = raw_entry.get("source_sha")
            if current_state == "closed":
                if event != "pull_request":
                    raise ManagedReleaseLedgerError(
                        "managed release registration must begin with pull request CI"
                    )
                raw_entry["source_sha"] = source_sha
                registration["state"] = "open"
                registration["phase"] = event
                registration["pr_verified"] = False
                registration["job_set_digest"] = None
                raw_entry["status"] = "ci_queued"
                raw_ci["state"] = "ci_queued"
                raw_ci["receipt_uri"] = None
            elif current_sha != source_sha:
                raise ManagedReleaseLedgerError(
                    "managed production candidate tuple is not admitted"
                )
            elif current_state == "sealed" and current_phase == "pull_request" and event == "push":
                if registration.get("pr_verified") is not True:
                    raise ManagedReleaseLedgerError("pull request CI is not verified")
                raw_runs.clear()
                registration["state"] = "open"
                registration["phase"] = "push"
                registration["job_set_digest"] = None
                raw_entry["status"] = "ci_queued"
                raw_ci["state"] = "ci_queued"
                raw_ci["receipt_uri"] = None
            elif current_phase != event:
                raise ManagedReleaseLedgerError("managed release CI phase is not admitted")

            matching: dict[str, Any] | None = None
            for raw_item in raw_runs:
                if not isinstance(raw_item, dict):
                    raise ManagedReleaseLedgerError("managed release CI run state is invalid")
                if raw_item.get("repository") == repository and raw_item.get("job_id") == job_id:
                    if _binding_identity(raw_item) != _binding_identity(binding):
                        raise ManagedReleaseLedgerError(
                            "managed release provider job is already bound"
                        )
                    matching = raw_item
                    break
            if current_state == "sealed" and not (
                current_phase == "pull_request" and event == "push"
            ):
                if matching == binding:
                    binding_result = dict(matching)
                    return
                raise ManagedReleaseLedgerError("managed release exact job set is sealed")
            if matching is None:
                raw_runs.append(dict(binding))
                return
            ranks = {"queued": 0, "in_progress": 1, "terminal": 2}
            if ranks[binding["state"]] < ranks.get(str(matching.get("state")), 99):
                raise ManagedReleaseLedgerError("managed release CI observation is stale")
            if matching == binding:
                binding_result = dict(matching)
                return
            matching["state"] = binding["state"]
            matching["conclusion"] = binding["conclusion"]
            binding_result = dict(matching)

        backup_path = self._atomic_update(mutate)
        refreshed = ManagedReleaseLedger(self.path)
        refreshed_entry = refreshed._by_entry_id["qazgeo"]
        refreshed_binding = next(
            (
                item
                for item in refreshed_entry.ci_runs
                if item["repository"] == repository and item["job_id"] == job_id
            ),
            binding_result,
        )
        return {
            "entry": refreshed_entry,
            "binding": dict(refreshed_binding),
            "idempotent": backup_path is None,
            "backup_path": str(backup_path) if backup_path is not None else None,
        }

    def reconcile_qgeo_ci_terminal(
        self,
        *,
        source_sha: str,
        verified_bindings: Sequence[Mapping[str, Any]],
    ) -> dict[str, Any]:
        """Seal the provider's complete, exact, successful job set."""

        entry = self.validate_candidate("qazgeo", source_sha)
        if entry.registration_phase is None:
            raise ManagedReleaseLedgerError("managed release CI phase is unavailable")
        supplied = _validate_ci_runs(
            [dict(item) for item in verified_bindings],
            source_sha=source_sha,
            phase=entry.registration_phase,
            required_workflows=entry.required_workflows,
        )
        if any(item["state"] != "terminal" or item["conclusion"] != "success" for item in supplied):
            raise ManagedReleaseLedgerError("managed release CI verification is not terminal")
        if {item["workflow_path"] for item in supplied} != set(entry.required_workflows):
            raise ManagedReleaseLedgerError("managed release required workflow set is incomplete")
        required_selectors = {
            (workflow_path, job_name, profile)
            for workflow_path, jobs in QGEO_REQUIRED_JOB_PROFILES[entry.registration_phase].items()
            for job_name, profile in jobs.items()
        }
        supplied_selectors = {
            (item["workflow_path"], item["job_name"], item["profile"]) for item in supplied
        }
        if supplied_selectors != required_selectors or len(supplied) != len(required_selectors):
            raise ManagedReleaseLedgerError("managed release required job set is incomplete")
        expected_by_key = {_binding_key(item): item for item in entry.ci_runs}
        supplied_by_key = {_binding_key(item): item for item in supplied}
        if set(expected_by_key) != set(supplied_by_key) or any(
            _binding_identity(expected_by_key[key]) != _binding_identity(supplied_by_key[key])
            for key in expected_by_key
        ):
            raise ManagedReleaseLedgerError("managed release exact job set does not match")
        supplied_list = [dict(item) for item in supplied]
        supplied_list.sort(key=_canonical_binding)
        digest = _job_set_digest(supplied_list)

        def mutate(document: dict[str, Any]) -> None:
            raw_entry = document.get("entries", {}).get("qazgeo")
            if not isinstance(raw_entry, dict) or raw_entry.get("source_sha") != source_sha:
                raise ManagedReleaseLedgerError(
                    "managed production candidate tuple is not admitted"
                )
            registration = raw_entry.get("registration")
            raw_runs = raw_entry.get("ci_runs")
            raw_ci = raw_entry.get("ci")
            if (
                not isinstance(registration, dict)
                or registration.get("phase") != entry.registration_phase
                or registration.get("state") not in {"open", "sealed"}
                or not isinstance(raw_runs, list)
                or not isinstance(raw_ci, dict)
            ):
                raise ManagedReleaseLedgerError("managed release registration changed")
            current_by_key = {
                _binding_key(item): item for item in raw_runs if isinstance(item, dict)
            }
            if len(current_by_key) != len(raw_runs) or set(current_by_key) != set(supplied_by_key):
                raise ManagedReleaseLedgerError("managed release exact job set changed")
            if any(
                _binding_identity(current_by_key[key]) != _binding_identity(supplied_by_key[key])
                for key in current_by_key
            ):
                raise ManagedReleaseLedgerError("managed release exact job set changed")
            raw_entry["ci_runs"] = supplied_list
            registration["state"] = "sealed"
            registration["pr_verified"] = True
            registration["job_set_digest"] = digest
            raw_entry["status"] = "ci_passed"
            raw_ci["state"] = "ci_passed"

        backup_path = self._atomic_update(mutate)
        refreshed = ManagedReleaseLedger(self.path)
        return {
            "entry": refreshed._by_entry_id["qazgeo"],
            "idempotent": backup_path is None,
            "backup_path": str(backup_path) if backup_path is not None else None,
        }

    def _atomic_update(self, mutate: Callable[[dict[str, Any]], None]) -> Path | None:
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
                    "registration": {
                        "state": entry.registration_state,
                        "phase": entry.registration_phase,
                        "pr_verified": entry.pr_verified,
                        "required_workflows": list(entry.required_workflows),
                        "job_set_digest": entry.job_set_digest,
                    },
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
        """Admit a claim only for one open, exact provider checkout tuple."""

        entry = self._by_entry_id.get(entry_id)
        if entry is None or entry.registration_state != "open":
            raise ManagedReleaseLedgerError("managed production candidate is not open")
        if None in {repository, run_id, attempt, job_id}:
            raise ManagedReleaseLedgerError("managed production provider binding is incomplete")
        binding = next(
            (
                item
                for item in entry.ci_runs
                if item["repository"] == repository
                and item["run_id"] == run_id
                and item["attempt"] == attempt
                and item["job_id"] == job_id
            ),
            None,
        )
        if binding is None or binding["checkout_sha"] != exact_sha:
            raise ManagedReleaseLedgerError("managed production provider binding is not admitted")
        if binding["state"] == "terminal":
            raise ManagedReleaseLedgerError("managed production provider binding is terminal")
        return entry

    def validate_candidate(self, entry_id: str, exact_sha: str) -> ManagedReleaseLedgerEntry:
        entry = self._by_entry_id.get(entry_id)
        if entry is None or entry.registration_state == "closed":
            raise ManagedReleaseLedgerError("managed production candidate is not registered")
        if entry.status not in ACTIVE_STATUSES or entry.source_sha != exact_sha:
            raise ManagedReleaseLedgerError("managed production candidate tuple is not admitted")
        return entry

    def classify_admission(self, entry_id: str, exact_sha: str) -> tuple[bool, str | None]:
        """Observe whether a queued managed-production tuple remains admissible.

        Direct claims continue to use :meth:`validate_admission` and fail
        closed. This observational form exists only for FIFO scans, where a
        retired or superseded production candidate must remain recorded but
        must not indefinitely hold an unrelated profile queue.
        """

        entry = self._by_entry_id.get(entry_id)
        if entry is None or entry.status not in ACTIVE_STATUSES:
            return False, "managed-production-candidate-not-active"
        admitted_checkout = any(
            binding["checkout_sha"] == exact_sha and binding["state"] in {"queued", "in_progress"}
            for binding in entry.ci_runs
        )
        if not admitted_checkout:
            return False, "managed-production-candidate-tuple-not-admitted"
        return True, None

    def validate_candidate_ci_runs(
        self,
        entry_id: str,
        exact_sha: str,
        run_ids: list[str],
        *,
        receipt_scope: Mapping[str, object] | None = None,
    ) -> ManagedReleaseLedgerEntry:
        """Admit release only for sealed exact main-push CI of the candidate."""

        entry = self._by_entry_id.get(entry_id)
        if entry is None or entry.source_sha != exact_sha:
            raise ManagedReleaseLedgerError("managed production candidate tuple is not admitted")
        if (
            entry.registration_state != "sealed"
            or entry.registration_phase != "push"
            or not entry.pr_verified
            or entry.status != "ci_passed"
        ):
            raise ManagedReleaseLedgerError("managed release main CI is not sealed")
        if (
            not isinstance(run_ids, list)
            or not run_ids
            or any(not isinstance(run_id, str) or not run_id.isdigit() for run_id in run_ids)
            or len(run_ids) != len(set(run_ids))
        ):
            raise ManagedReleaseLedgerError("managed release CI evidence run IDs are invalid")
        expected = {item["run_id"] for item in entry.ci_runs}
        if set(run_ids) != expected:
            raise ManagedReleaseLedgerError(
                "managed release CI evidence does not match the admitted run set"
            )
        if any(
            item["state"] != "terminal" or item["conclusion"] != "success" for item in entry.ci_runs
        ):
            raise ManagedReleaseLedgerError("managed release CI evidence is not terminal")
        if {item["workflow_path"] for item in entry.ci_runs} != set(entry.required_workflows):
            raise ManagedReleaseLedgerError("managed release required workflow set is incomplete")
        if entry.job_set_digest != _job_set_digest(entry.ci_runs):
            raise ManagedReleaseLedgerError("managed release exact job set digest is invalid")
        if receipt_scope is not None:
            repository = receipt_scope.get("repository")
            workflow = receipt_scope.get("workflow")
            job = receipt_scope.get("job")
            profile = receipt_scope.get("runner_profile")
            run_id = receipt_scope.get("run_id")
            job_id = receipt_scope.get("job_id")
            attempt = receipt_scope.get("attempt")
            if (
                repository != QGEO_REPOSITORY
                or not isinstance(workflow, str)
                or not isinstance(job, str)
                or not isinstance(profile, str)
                or isinstance(run_id, bool)
                or not isinstance(run_id, int)
                or run_id < 1
                or isinstance(job_id, bool)
                or not isinstance(job_id, int)
                or job_id < 1
                or isinstance(attempt, bool)
                or not isinstance(attempt, int)
                or attempt < 1
            ):
                raise ManagedReleaseLedgerError(
                    "managed release candidate receipt scope is invalid"
                )
            matched_binding = next(
                (
                    item
                    for item in entry.ci_runs
                    if item["repository"] == repository
                    and item["workflow_path"] == workflow
                    and item["job_name"] == job
                    and item["profile"] == profile
                    and item["run_id"] == str(run_id)
                    and item["job_id"] == str(job_id)
                    and item["attempt"] == str(attempt)
                    and item["candidate_sha"] == exact_sha
                    and item["checkout_sha"] == exact_sha
                    and item["state"] == "terminal"
                    and item["conclusion"] == "success"
                ),
                None,
            )
            if matched_binding is None:
                raise ManagedReleaseLedgerError(
                    "managed release candidate receipt is not bound to the provider ledger"
                )
        return entry

    @staticmethod
    def _validate_stage(value: object) -> None:
        if not isinstance(value, dict) or set(value) != {"state", "receipt_uri"}:
            raise ManagedReleaseLedgerError("managed release ledger evidence is invalid")
        if value["state"] not in STATUSES or (
            value["receipt_uri"] is not None and not isinstance(value["receipt_uri"], str)
        ):
            raise ManagedReleaseLedgerError("managed release ledger evidence state is invalid")
