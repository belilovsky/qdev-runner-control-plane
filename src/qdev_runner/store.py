from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from .claim_scope import SCHEMA_V2, ClaimScope
from .models import QueuedJob

MINIMUM_QUEUE_TIMESTAMP = datetime(2020, 1, 1, tzinfo=UTC).timestamp()
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
_RECOVERY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_INTERFACE_VERSION = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_CANARY_WORKFLOW = re.compile(r"^[A-Za-z0-9_.@/ -]{1,255}$")
_CANARY_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_RUNNER_LABEL = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_RECOVERY_ACTIONS = frozenset({"restore_saved_configuration", "replace_existing_registration"})
_WORKER_RECOVERY_BINDINGS = {
    "qdev-platform-ci-187": {
        "repository": "belilovsky/platform-portal",
        "labels": ("self-hosted", "Linux", "X64", "qdev-platform-ci"),
        "recovery_action": "restore_saved_configuration",
    },
    "qdev-qazstack-01": {
        "repository": "belilovsky/qazstack",
        "labels": ("self-hosted", "Linux", "X64", "qdev-ci"),
        "recovery_action": "replace_existing_registration",
    },
}
_WORKER_RECOVERY_CANARY_WORKFLOWS = {
    "qdev-platform-ci-187": ".github/workflows/runner-smoke.yml",
    "qdev-qazstack-01": ".github/workflows/self-hosted-recovery.yml",
}
_WORKER_RECOVERY_CANARY_PHASES = frozenset(
    {
        "dispatch_intent",
        "dispatching",
        "dispatched",
        "run_observed",
        "labels_pending",
        "labels_applied",
        "job_observed",
        "completed",
        "cleanup_pending",
        "cleaned",
        "accepted",
        "ambiguous",
    }
)
_WORKER_RECOVERY_CANARY_TRANSITIONS = {
    "dispatch_intent": frozenset({"dispatching", "ambiguous"}),
    "dispatching": frozenset({"dispatched", "ambiguous"}),
    "dispatched": frozenset({"run_observed", "ambiguous"}),
    "run_observed": frozenset({"labels_pending", "ambiguous"}),
    "labels_pending": frozenset({"labels_applied", "ambiguous"}),
    "labels_applied": frozenset({"job_observed", "ambiguous"}),
    "job_observed": frozenset({"completed", "ambiguous"}),
    "completed": frozenset({"cleanup_pending", "ambiguous"}),
    "cleanup_pending": frozenset({"cleaned", "ambiguous"}),
    "cleaned": frozenset({"accepted", "ambiguous"}),
    "accepted": frozenset(),
    "ambiguous": frozenset(),
}
_WORKER_RECOVERY_CANARY_STATUSES = frozenset(
    {"queued", "in_progress", "waiting", "pending", "requested", "completed"}
)
_WORKER_RECOVERY_CANARY_CONCLUSIONS = frozenset(
    {
        "success",
        "failure",
        "neutral",
        "cancelled",
        "skipped",
        "timed_out",
        "action_required",
        "stale",
        "startup_failure",
    }
)


def _finite_recovery_number(value: object, *, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError(f"{field} is invalid")
    result = float(value)
    if not math.isfinite(result):
        raise ValueError(f"{field} is invalid")
    return result


def _recovery_proof_window(value: object) -> float:
    result = _finite_recovery_number(value, field="recovery proof age")
    if result < 0:
        raise ValueError("recovery proof age is invalid")
    return result


def _valid_canary_ref(value: object) -> bool:
    return (
        isinstance(value, str)
        and _CANARY_REF.fullmatch(value) is not None
        and ".." not in value
        and "//" not in value
        and "@{" not in value
        and not value.endswith(("/", "."))
    )


def _canonical_provider_observation(value: object) -> tuple[dict[str, Any], str, str]:
    """Return a JSON-native provider observation and its content digest."""

    if not isinstance(value, dict):
        raise ValueError("provider observation is invalid")
    try:
        canonical = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        )
        normalized = json.loads(canonical)
    except (TypeError, ValueError, json.JSONDecodeError) as error:
        raise ValueError("provider observation is invalid") from error
    if normalized != value:
        raise ValueError("provider observation is invalid")
    digest = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    return normalized, canonical, digest


def _provider_observation_collection(
    observation: dict[str, Any], name: str
) -> list[dict[str, Any]]:
    collection = observation.get(name)
    if not isinstance(collection, dict) or set(collection) != {"total_count", "items"}:
        raise ValueError("provider observation is invalid")
    total_count = collection["total_count"]
    items = collection["items"]
    if (
        isinstance(total_count, bool)
        or not isinstance(total_count, int)
        or total_count < 0
        or not isinstance(items, list)
        or total_count != len(items)
        or any(not isinstance(item, dict) for item in items)
    ):
        raise ValueError("provider observation is invalid")
    return items


def _provider_runner_observations(observation: dict[str, Any]) -> list[dict[str, Any]]:
    runners = _provider_observation_collection(observation, "runners")
    for runner in runners:
        if set(runner) != {"id", "name", "status", "busy", "labels"}:
            raise ValueError("provider observation is invalid")
        runner_id = runner["id"]
        runner_labels = runner["labels"]
        if (
            isinstance(runner_id, bool)
            or not isinstance(runner_id, int)
            or runner_id <= 0
            or not isinstance(runner["name"], str)
            or not runner["name"]
            or runner["status"] not in {"online", "offline"}
            or not isinstance(runner["busy"], bool)
            or not isinstance(runner_labels, list)
            or not runner_labels
            or any(
                not isinstance(label, str) or _RUNNER_LABEL.fullmatch(label) is None
                for label in runner_labels
            )
            or len({label.lower() for label in runner_labels}) != len(runner_labels)
        ):
            raise ValueError("provider observation is invalid")
    return runners


def _worker_recovery_temporary_label(operation_id: str) -> str:
    if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(operation_id):
        raise ValueError("worker recovery canary operation identity is invalid")
    return f"qdev-job-recovery-{operation_id}"


def _worker_recovery_dispatch_correlation(operation_id: str) -> str:
    if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(operation_id):
        raise ValueError("worker recovery canary operation identity is invalid")
    return f"qdev-recovery-{operation_id}"


def _validate_provider_observation(
    value: object,
    *,
    schema: str,
    repository: str,
    worker_name: str,
    provider_runner_id: int,
    provider_status: str,
    provider_busy: bool,
    labels: tuple[str, ...],
    canary: dict[str, Any] | None = None,
) -> tuple[dict[str, Any], str, str]:
    observation, canonical, digest = _canonical_provider_observation(value)
    required = {"schema", "repository", "runners", "active_target_jobs"}
    if canary is not None:
        required.add("canary")
    try:
        runners = _provider_runner_observations(observation)
        active_target_jobs = _provider_observation_collection(observation, "active_target_jobs")
    except ValueError as error:
        raise ValueError("provider observation is invalid") from error
    matching = [runner for runner in runners if runner["name"] == worker_name]
    expected_runner = {
        "id": provider_runner_id,
        "name": worker_name,
        "status": provider_status,
        "busy": provider_busy,
        "labels": list(labels),
    }
    if (
        set(observation) != required
        or observation["schema"] != schema
        or observation["repository"] != repository
        or matching != [expected_runner]
        or active_target_jobs
        or observation["active_target_jobs"]["total_count"] != 0
        or (canary is not None and observation["canary"] != canary)
    ):
        raise ValueError("provider observation is invalid")
    return observation, canonical, digest


def worker_recovery_provider_status(
    value: object,
    *,
    worker_name: str,
    provider_runner_id: int,
    recovery_action: str,
) -> str:
    """Recover the exact admitted status from the immutable provider snapshot."""

    observation, _, _ = _canonical_provider_observation(value)
    try:
        runners = _provider_runner_observations(observation)
    except ValueError as error:
        raise ValueError("provider observation is invalid") from error
    matching = [runner for runner in runners if runner["name"] == worker_name]
    if (
        len(matching) != 1
        or matching[0]["id"] != provider_runner_id
        or matching[0]["status"] not in {"online", "offline"}
    ):
        raise ValueError("provider observation is invalid")
    status = str(matching[0]["status"])
    if status == "online" and recovery_action != "restore_saved_configuration":
        raise ValueError("provider observation is invalid")
    return status


def _validate_provider_absence_observation(
    value: object,
    *,
    repository: str,
    worker_name: str,
) -> tuple[dict[str, Any], str, str]:
    observation, canonical, digest = _canonical_provider_observation(value)
    try:
        runners = _provider_runner_observations(observation)
        active_target_jobs = _provider_observation_collection(observation, "active_target_jobs")
    except ValueError as error:
        raise ValueError("provider absence observation is invalid") from error
    if (
        set(observation)
        != {"schema", "repository", "worker_name", "runners", "active_target_jobs"}
        or observation["schema"] != "qdev-worker-provider-absence-observation-v1"
        or observation["repository"] != repository
        or observation["worker_name"] != worker_name
        or any(runner["name"] == worker_name for runner in runners)
        or active_target_jobs
        or observation["active_target_jobs"]["total_count"] != 0
    ):
        raise ValueError("provider absence observation is invalid")
    return observation, canonical, digest


SCHEMA = """
CREATE TABLE IF NOT EXISTS jobs (
    job_id INTEGER PRIMARY KEY,
    delivery_id TEXT NOT NULL UNIQUE,
    run_id INTEGER NOT NULL,
    repository TEXT NOT NULL,
    repository_id INTEGER NOT NULL,
    installation_id INTEGER NOT NULL,
    labels_json TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    head_branch TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    status TEXT NOT NULL CHECK(
        status IN ('pending','claimed','running','completed','rejected','failed')
    ),
    worker_name TEXT,
    claim_scope_id TEXT,
    profile TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    claimed_at REAL,
    completed_at REAL,
    result TEXT,
    attempts INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS jobs_status_created_idx ON jobs(status, created_at);

CREATE TABLE IF NOT EXISTS workers (
    name TEXT PRIMARY KEY,
    profiles_json TEXT NOT NULL,
    active_jobs INTEGER NOT NULL,
    last_seen REAL NOT NULL,
    detail_json TEXT NOT NULL
);

-- A recovery fence is durable and never expires into admission after a crash.
-- Old runtimes ignore this additive table: rollback must be performed only
-- after native reconciliation of all unreleased fences.
CREATE TABLE IF NOT EXISTS worker_recoveries (
    idempotency_key TEXT PRIMARY KEY,
    worker_name TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    operation_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('prepared','invoking','completed','released')),
    created_at REAL NOT NULL,
    invoked_at REAL,
    updated_at REAL NOT NULL,
    native_outcome TEXT,
    native_outcome_digest TEXT,
    agent_identity TEXT,
    reconciled_at REAL,
    repository TEXT,
    labels_json TEXT,
    provider_runner_id INTEGER,
    provider_idle_proof_digest TEXT,
    provider_reconciliation_digest TEXT,
    provider_observation_json TEXT,
    provider_observed_at REAL,
    recovery_action TEXT,
    operator_certificate_sha256 TEXT,
    expected_agent_certificate_sha256 TEXT,
    interface_version TEXT,
    interface_digest TEXT,
    controller_revision TEXT,
    controller_release_digest TEXT,
    policy_digest TEXT,
    agent_release_digest TEXT,
    controller_receipt_id TEXT,
    controller_observed_at REAL,
    request_digest TEXT,
    request_nonce TEXT,
    requested_at REAL,
    consumed_at REAL,
    native_outcome_signature TEXT,
    agent_certificate_sha256 TEXT,
    native_outcome_observed_at REAL,
    native_finalized_at REAL,
    accepted_provider_runner_id INTEGER,
    acceptance_proof_digest TEXT,
    acceptance_proof_signature TEXT,
    acceptance_reconciliation_digest TEXT,
    acceptance_observed_at REAL,
    canary_repository TEXT,
    canary_workflow TEXT,
    canary_ref TEXT,
    canary_run_id INTEGER,
    canary_job_id INTEGER,
    canary_attempt INTEGER,
    canary_head_sha TEXT,
    canary_runner_id INTEGER,
    canary_status TEXT,
    canary_conclusion TEXT,
    canary_completed_at REAL,
    released_at REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS worker_recovery_active_idx
    ON worker_recoveries(worker_name) WHERE state!='released';

-- A prepared recovery may be abandoned only through a fresh controller-owned
-- provider observation.  The signed receipt is append-only so releasing the
-- fence cannot erase which release and operator made that decision.
CREATE TABLE IF NOT EXISTS worker_recovery_aborts (
    receipt_digest TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    worker_name TEXT NOT NULL,
    repository TEXT NOT NULL,
    request_fingerprint TEXT NOT NULL,
    operator_certificate_sha256 TEXT NOT NULL,
    original_controller_revision TEXT NOT NULL,
    original_controller_release_digest TEXT NOT NULL,
    abort_controller_revision TEXT NOT NULL,
    abort_controller_release_digest TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    agent_release_digest TEXT NOT NULL,
    provider_idle_proof_digest TEXT NOT NULL,
    provider_reconciliation_digest TEXT NOT NULL,
    provider_observation_json TEXT NOT NULL,
    reason TEXT NOT NULL,
    signature TEXT NOT NULL,
    provider_observed_at REAL NOT NULL,
    aborted_at REAL NOT NULL,
    FOREIGN KEY(operation_id) REFERENCES worker_recoveries(operation_id)
);
CREATE INDEX IF NOT EXISTS worker_recovery_aborts_operation_idx
    ON worker_recovery_aborts(operation_id, aborted_at);

CREATE TRIGGER IF NOT EXISTS worker_recovery_aborts_no_update
BEFORE UPDATE ON worker_recovery_aborts
BEGIN
    SELECT RAISE(ABORT, 'worker recovery aborts are append-only');
END;

CREATE TRIGGER IF NOT EXISTS worker_recovery_aborts_no_delete
BEFORE DELETE ON worker_recovery_aborts
BEGIN
    SELECT RAISE(ABORT, 'worker recovery aborts are append-only');
END;

-- Native observations are append-only.  An ambiguous or failed observation
-- keeps the worker fenced, but a later terminal observation for the exact same
-- adapter operation can safely complete reconciliation without editing history.
CREATE TABLE IF NOT EXISTS worker_recovery_outcomes (
    receipt_digest TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    worker_name TEXT NOT NULL,
    request_digest TEXT NOT NULL,
    agent_certificate_sha256 TEXT NOT NULL,
    provider_reconciliation_digest TEXT NOT NULL,
    recovery_action TEXT NOT NULL,
    request_nonce TEXT NOT NULL,
    policy_digest TEXT NOT NULL,
    agent_release_digest TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK(
        outcome IN ('completed','not_applied','failed','ambiguous')
    ),
    outcome_digest TEXT NOT NULL,
    signature TEXT NOT NULL,
    observed_at REAL NOT NULL,
    reconciled_at REAL NOT NULL,
    FOREIGN KEY(operation_id) REFERENCES worker_recoveries(operation_id),
    UNIQUE(operation_id, outcome_digest)
);
CREATE INDEX IF NOT EXISTS worker_recovery_outcomes_operation_idx
    ON worker_recovery_outcomes(operation_id, reconciled_at);

-- Acceptance is a second, append-only controller observation.  A successful
-- native mutation is deliberately still fenced until the provider proves the
-- same registered runner is online/idle with its permanent labels and a
-- controller-orchestrated canary has completed on that runner.
CREATE TABLE IF NOT EXISTS worker_recovery_acceptances (
    proof_digest TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL UNIQUE,
    worker_name TEXT NOT NULL,
    repository TEXT NOT NULL,
    labels_json TEXT NOT NULL,
    prior_provider_runner_id INTEGER,
    prior_provider_runner_disposition TEXT NOT NULL CHECK(
        prior_provider_runner_disposition IN ('same','absent')
    ),
    provider_runner_id INTEGER NOT NULL,
    matching_runner_count INTEGER NOT NULL CHECK(matching_runner_count=1),
    provider_reconciliation_digest TEXT NOT NULL,
    provider_observation_json TEXT NOT NULL,
    provider_observed_at REAL NOT NULL,
    canary_repository TEXT NOT NULL,
    canary_workflow TEXT NOT NULL,
    canary_ref TEXT NOT NULL,
    canary_head_sha TEXT NOT NULL,
    canary_run_id INTEGER NOT NULL,
    canary_run_attempt INTEGER NOT NULL,
    canary_job_id INTEGER NOT NULL,
    canary_runner_id INTEGER NOT NULL,
    canary_status TEXT NOT NULL CHECK(canary_status='completed'),
    canary_conclusion TEXT NOT NULL CHECK(canary_conclusion='success'),
    canary_completed_at REAL NOT NULL,
    signature TEXT NOT NULL,
    accepted_at REAL NOT NULL,
    FOREIGN KEY(operation_id) REFERENCES worker_recoveries(operation_id)
);
CREATE INDEX IF NOT EXISTS worker_recovery_acceptances_operation_idx
    ON worker_recovery_acceptances(operation_id, accepted_at);

-- Canary dispatch and label cleanup contain provider-side ambiguity windows.
-- The projection is updated only through compare-and-swap transitions while
-- the event ledger below preserves every committed state.  It intentionally
-- has no provider-response, credential, registration-token or free-form
-- payload column: only the minimum identity needed for safe reconciliation is
-- durable.
CREATE TABLE IF NOT EXISTS worker_recovery_canaries (
    operation_id TEXT PRIMARY KEY,
    worker_name TEXT NOT NULL,
    repository TEXT NOT NULL,
    workflow TEXT NOT NULL,
    ref TEXT NOT NULL,
    head_sha TEXT NOT NULL,
    baseline_run_id INTEGER NOT NULL CHECK(baseline_run_id>=0),
    provider_runner_id INTEGER NOT NULL CHECK(provider_runner_id>0),
    provider_runner_name TEXT NOT NULL,
    dispatch_correlation TEXT NOT NULL UNIQUE,
    temporary_label TEXT NOT NULL,
    temporary_labels_json TEXT NOT NULL,
    intent_digest TEXT NOT NULL UNIQUE,
    phase TEXT NOT NULL CHECK(phase IN (
        'dispatch_intent','dispatching','dispatched','run_observed',
        'labels_pending','labels_applied','job_observed','completed',
        'cleanup_pending','cleaned','accepted','ambiguous'
    )),
    revision INTEGER NOT NULL CHECK(revision>=1),
    run_id INTEGER,
    run_attempt INTEGER,
    job_id INTEGER,
    run_status TEXT,
    conclusion TEXT,
    dispatch_observed_label TEXT,
    run_observed_label TEXT,
    job_labels_json TEXT,
    job_runner_id INTEGER,
    job_runner_name TEXT,
    dispatched_at REAL,
    completed_at REAL,
    cleaned_at REAL,
    accepted_at REAL,
    last_event_digest TEXT NOT NULL,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    FOREIGN KEY(operation_id) REFERENCES worker_recoveries(operation_id)
);
CREATE INDEX IF NOT EXISTS worker_recovery_canaries_phase_idx
    ON worker_recovery_canaries(phase, updated_at);

CREATE TABLE IF NOT EXISTS worker_recovery_canary_events (
    event_digest TEXT PRIMARY KEY,
    operation_id TEXT NOT NULL,
    revision INTEGER NOT NULL CHECK(revision>=1),
    from_phase TEXT,
    phase TEXT NOT NULL,
    event_json TEXT NOT NULL,
    recorded_at REAL NOT NULL,
    FOREIGN KEY(operation_id) REFERENCES worker_recoveries(operation_id),
    UNIQUE(operation_id, revision)
);
CREATE INDEX IF NOT EXISTS worker_recovery_canary_events_operation_idx
    ON worker_recovery_canary_events(operation_id, revision);

CREATE TRIGGER IF NOT EXISTS worker_recovery_canary_events_no_update
BEFORE UPDATE ON worker_recovery_canary_events
BEGIN
    SELECT RAISE(ABORT, 'worker recovery canary events are append-only');
END;

CREATE TRIGGER IF NOT EXISTS worker_recovery_canary_events_no_delete
BEFORE DELETE ON worker_recovery_canary_events
BEGIN
    SELECT RAISE(ABORT, 'worker recovery canary events are append-only');
END;

"""


def _worker_concurrency(detail: dict[str, Any]) -> int:
    try:
        return max(1, int(detail.get("concurrency", 1)))
    except (TypeError, ValueError):
        return 1


def _disk_headroom_allowed(detail: dict[str, Any], profile_disk_mb: int | None) -> bool:
    if profile_disk_mb is None:
        return True
    try:
        disk_free_gib = float(detail["disk_free_gib"])
        min_disk_free_gib = float(detail.get("min_disk_free_gib", 30))
    except (KeyError, TypeError, ValueError):
        return False
    return disk_free_gib >= min_disk_free_gib + profile_disk_mb / 1024


def _is_valid_queue_timestamp(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
        and value >= MINIMUM_QUEUE_TIMESTAMP
    )


def _workflow_job_created_at(payload_json: str) -> float | None:
    try:
        payload = json.loads(payload_json)
        value = payload.get("workflow_job", {}).get("created_at")
        if not isinstance(value, str):
            return None
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC).timestamp()
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return timestamp if _is_valid_queue_timestamp(timestamp) else None


def _workflow_job_attempt(payload_json: str) -> int | None:
    """Read the provider's immutable run attempt without inventing a default.

    A v2 scope binds a concrete provider attempt.  Treating a missing value as
    attempt one would let an old scope claim a later provider retry, so callers
    fail closed when GitHub did not send the field.
    """
    try:
        payload = json.loads(payload_json)
        value = payload.get("workflow_job", {}).get("run_attempt")
        attempt = int(value)
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return attempt if attempt > 0 else None


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            connection.execute("BEGIN IMMEDIATE")
            try:
                columns = {
                    str(row["name"])
                    for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
                }
                if "claim_scope_id" not in columns:
                    connection.execute("ALTER TABLE jobs ADD COLUMN claim_scope_id TEXT")
                self._migrate_schema(connection)
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            self._repair_invalid_queue_timestamps(connection)

    def _repair_invalid_queue_timestamps(self, connection: sqlite3.Connection) -> None:
        """Restore FIFO ordering for legacy rows written with invalid timestamps.

        A workflow job's immutable GitHub creation time is the preferred repair
        source. If an older webhook lacks that field, its already-recorded
        update time is the least surprising monotonic fallback.
        """
        rows = connection.execute(
            """
            SELECT job_id, payload_json, created_at, updated_at
            FROM jobs
            WHERE status IN ('pending', 'claimed', 'running')
              AND (created_at IS NULL OR created_at <= ? OR created_at != created_at)
            """,
            (MINIMUM_QUEUE_TIMESTAMP,),
        ).fetchall()
        for row in rows:
            repaired = _workflow_job_created_at(str(row["payload_json"]))
            if repaired is None and _is_valid_queue_timestamp(row["updated_at"]):
                repaired = float(row["updated_at"])
            if repaired is None:
                repaired = time.time()
            connection.execute(
                "UPDATE jobs SET created_at=? WHERE job_id=? "
                "AND (created_at IS NULL OR created_at=? OR created_at != created_at)",
                (repaired, row["job_id"], row["created_at"]),
            )

    @staticmethod
    def _migrate_schema(connection: sqlite3.Connection) -> None:
        """Apply additive migrations to databases created by older brokers."""

        recovery_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(worker_recoveries)").fetchall()
        }
        recovery_additions = {
            "operation_id": "TEXT",
            "native_outcome": "TEXT",
            "native_outcome_digest": "TEXT",
            "agent_identity": "TEXT",
            "reconciled_at": "REAL",
            "repository": "TEXT",
            "labels_json": "TEXT",
            "provider_runner_id": "INTEGER",
            "provider_idle_proof_digest": "TEXT",
            "provider_reconciliation_digest": "TEXT",
            "provider_observation_json": "TEXT",
            "provider_observed_at": "REAL",
            "recovery_action": "TEXT",
            "operator_certificate_sha256": "TEXT",
            "expected_agent_certificate_sha256": "TEXT",
            "interface_version": "TEXT",
            "interface_digest": "TEXT",
            "controller_revision": "TEXT",
            "controller_release_digest": "TEXT",
            "policy_digest": "TEXT",
            "agent_release_digest": "TEXT",
            "controller_receipt_id": "TEXT",
            "controller_observed_at": "REAL",
            "request_digest": "TEXT",
            "request_nonce": "TEXT",
            "requested_at": "REAL",
            "consumed_at": "REAL",
            "native_outcome_signature": "TEXT",
            "agent_certificate_sha256": "TEXT",
            "native_outcome_observed_at": "REAL",
            "native_finalized_at": "REAL",
            "accepted_provider_runner_id": "INTEGER",
            "acceptance_proof_digest": "TEXT",
            "acceptance_proof_signature": "TEXT",
            "acceptance_reconciliation_digest": "TEXT",
            "acceptance_observed_at": "REAL",
            "canary_repository": "TEXT",
            "canary_workflow": "TEXT",
            "canary_ref": "TEXT",
            "canary_run_id": "INTEGER",
            "canary_job_id": "INTEGER",
            "canary_attempt": "INTEGER",
            "canary_head_sha": "TEXT",
            "canary_runner_id": "INTEGER",
            "canary_status": "TEXT",
            "canary_conclusion": "TEXT",
            "canary_completed_at": "REAL",
            "released_at": "REAL",
        }
        for name, sql_type in recovery_additions.items():
            if name not in recovery_columns:
                connection.execute(f"ALTER TABLE worker_recoveries ADD COLUMN {name} {sql_type}")
        outcome_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(worker_recovery_outcomes)").fetchall()
        }
        outcome_additions = {
            "provider_reconciliation_digest": "TEXT",
            "recovery_action": "TEXT",
            "request_nonce": "TEXT",
            "policy_digest": "TEXT",
            "agent_release_digest": "TEXT",
        }
        for name, sql_type in outcome_additions.items():
            if name not in outcome_columns:
                connection.execute(
                    f"ALTER TABLE worker_recovery_outcomes ADD COLUMN {name} {sql_type}"
                )
        acceptance_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(worker_recovery_acceptances)"
            ).fetchall()
        }
        if "provider_observation_json" not in acceptance_columns:
            connection.execute(
                "ALTER TABLE worker_recovery_acceptances ADD COLUMN provider_observation_json TEXT"
            )
        acceptance_info = connection.execute(
            "PRAGMA table_info(worker_recovery_acceptances)"
        ).fetchall()
        prior_provider_column = next(
            (row for row in acceptance_info if row["name"] == "prior_provider_runner_id"),
            None,
        )
        if prior_provider_column is not None and int(prior_provider_column["notnull"]) == 1:
            connection.execute(
                "ALTER TABLE worker_recovery_acceptances "
                "RENAME TO worker_recovery_acceptances_legacy"
            )
            connection.execute(
                """
                CREATE TABLE worker_recovery_acceptances (
                    proof_digest TEXT PRIMARY KEY,
                    operation_id TEXT NOT NULL UNIQUE,
                    worker_name TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    labels_json TEXT NOT NULL,
                    prior_provider_runner_id INTEGER,
                    prior_provider_runner_disposition TEXT NOT NULL CHECK(
                        prior_provider_runner_disposition IN ('same','absent')
                    ),
                    provider_runner_id INTEGER NOT NULL,
                    matching_runner_count INTEGER NOT NULL CHECK(matching_runner_count=1),
                    provider_reconciliation_digest TEXT NOT NULL,
                    provider_observation_json TEXT,
                    provider_observed_at REAL NOT NULL,
                    canary_repository TEXT NOT NULL,
                    canary_workflow TEXT NOT NULL,
                    canary_ref TEXT NOT NULL,
                    canary_head_sha TEXT NOT NULL,
                    canary_run_id INTEGER NOT NULL,
                    canary_run_attempt INTEGER NOT NULL,
                    canary_job_id INTEGER NOT NULL,
                    canary_runner_id INTEGER NOT NULL,
                    canary_status TEXT NOT NULL CHECK(canary_status='completed'),
                    canary_conclusion TEXT NOT NULL CHECK(canary_conclusion='success'),
                    canary_completed_at REAL NOT NULL,
                    signature TEXT NOT NULL,
                    accepted_at REAL NOT NULL,
                    FOREIGN KEY(operation_id) REFERENCES worker_recoveries(operation_id)
                )
                """
            )
            connection.execute(
                """
                INSERT INTO worker_recovery_acceptances (
                    proof_digest, operation_id, worker_name, repository, labels_json,
                    prior_provider_runner_id, prior_provider_runner_disposition,
                    provider_runner_id, matching_runner_count,
                    provider_reconciliation_digest, provider_observation_json,
                    provider_observed_at, canary_repository, canary_workflow,
                    canary_ref, canary_head_sha, canary_run_id, canary_run_attempt,
                    canary_job_id, canary_runner_id, canary_status, canary_conclusion,
                    canary_completed_at, signature, accepted_at
                ) SELECT
                    proof_digest, operation_id, worker_name, repository, labels_json,
                    prior_provider_runner_id, prior_provider_runner_disposition,
                    provider_runner_id, matching_runner_count,
                    provider_reconciliation_digest, provider_observation_json,
                    provider_observed_at, canary_repository, canary_workflow,
                    canary_ref, canary_head_sha, canary_run_id, canary_run_attempt,
                    canary_job_id, canary_runner_id, canary_status, canary_conclusion,
                    canary_completed_at, signature, accepted_at
                FROM worker_recovery_acceptances_legacy
                """
            )
            connection.execute("DROP TABLE worker_recovery_acceptances_legacy")
            connection.execute(
                "CREATE INDEX IF NOT EXISTS worker_recovery_acceptances_operation_idx "
                "ON worker_recovery_acceptances(operation_id, accepted_at)"
            )
        canary_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(worker_recovery_canaries)").fetchall()
        }
        canary_additions = {
            "dispatch_correlation": "TEXT",
            "temporary_label": "TEXT",
            "dispatch_observed_label": "TEXT",
            "run_observed_label": "TEXT",
            "job_labels_json": "TEXT",
            "job_runner_id": "INTEGER",
            "job_runner_name": "TEXT",
            "dispatched_at": "REAL",
        }
        for name, sql_type in canary_additions.items():
            if name not in canary_columns:
                connection.execute(
                    f"ALTER TABLE worker_recovery_canaries ADD COLUMN {name} {sql_type}"
                )
        # Legacy rows predate native-operation identity.  Derive it from their
        # immutable request binding; no recovery may be replayed to populate it.
        rows = connection.execute(
            "SELECT idempotency_key,worker_name,request_fingerprint "
            "FROM worker_recoveries WHERE operation_id IS NULL"
        ).fetchall()
        for row in rows:
            operation_id = hashlib.sha256(
                (
                    f"{row['idempotency_key']}\0{row['worker_name']}\0{row['request_fingerprint']}"
                ).encode()
            ).hexdigest()
            connection.execute(
                "UPDATE worker_recoveries SET operation_id=? WHERE idempotency_key=?",
                (operation_id, row["idempotency_key"]),
            )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS worker_recovery_operation_idx "
            "ON worker_recoveries(operation_id)"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS worker_recovery_controller_receipt_idx "
            "ON worker_recoveries(controller_receipt_id) "
            "WHERE controller_receipt_id IS NOT NULL"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS worker_recovery_request_nonce_idx "
            "ON worker_recoveries(request_nonce) WHERE request_nonce IS NOT NULL"
        )
        connection.execute(
            "CREATE UNIQUE INDEX IF NOT EXISTS worker_recovery_canary_correlation_idx "
            "ON worker_recovery_canaries(dispatch_correlation) "
            "WHERE dispatch_correlation IS NOT NULL"
        )

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.path, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        try:
            yield connection
        finally:
            connection.close()

    def enqueue(self, job: QueuedJob) -> bool:
        now = time.time()
        with self.connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO jobs(
                    job_id, delivery_id, run_id, repository, repository_id,
                    installation_id, labels_json, head_sha, head_branch,
                    payload_json, status, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?, 'pending', ?,?)
                """,
                (
                    job.job_id,
                    job.delivery_id,
                    job.run_id,
                    job.repository,
                    job.repository_id,
                    job.installation_id,
                    json.dumps(job.labels),
                    job.head_sha,
                    job.head_branch,
                    json.dumps(job.payload, separators=(",", ":")),
                    now,
                    now,
                ),
            )
            return cursor.rowcount == 1

    def _has_available_tier_slot(
        self,
        connection: sqlite3.Connection,
        tier: str,
        cutoff: float,
        *,
        profile: str | None = None,
        profile_disk_mb: int | None = None,
    ) -> bool:
        rows = connection.execute(
            """
            SELECT name, profiles_json, active_jobs, last_seen, detail_json
            FROM workers WHERE last_seen>=?
            """,
            (cutoff,),
        ).fetchall()
        for row in rows:
            if self._worker_fenced(connection, str(row["name"])):
                continue
            detail = json.loads(row["detail_json"])
            worker_profiles = {str(item).lower() for item in json.loads(row["profiles_json"])}
            if profile is not None and profile.lower() not in worker_profiles:
                continue
            if (
                detail.get("tier") == tier
                and detail.get("allowed", True) is True
                and int(row["active_jobs"]) < _worker_concurrency(detail)
                and _disk_headroom_allowed(detail, profile_disk_mb)
            ):
                return True
        return False

    def claim(
        self,
        worker_name: str,
        profiles: tuple[str, ...],
        *,
        tier: str = "primary",
        disk_free_gib: float | None = None,
        min_disk_free_gib: float | None = None,
        profile_disk_mb: dict[str, int] | None = None,
        repository_profile_disk_mb: dict[tuple[str, str], int] | None = None,
        repository: str | None = None,
        head_sha: str | None = None,
        primary_max_age_seconds: int = 90,
        claim_scope: ClaimScope | None = None,
        fifo_skip_job_ids: frozenset[int] = frozenset(),
        fifo_skip_guard: Callable[[frozenset[int]], frozenset[int]] | None = None,
    ) -> dict[str, Any] | None:
        if fifo_skip_job_ids and (
            claim_scope is None or claim_scope.schema != SCHEMA_V2
        ):
            raise ValueError("FIFO skips require an exact v2 claim scope")
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            # Revalidate externally governed FIFO exceptions only after the
            # durable queue transaction has begun. This read is the claim's
            # linearization point: a head reactivated before it blocks the
            # later row, while a later ledger mutation is ordered after claim.
            if fifo_skip_guard is not None:
                fifo_skip_job_ids = fifo_skip_guard(fifo_skip_job_ids)
            if self._worker_fenced(connection, worker_name):
                connection.execute("COMMIT")
                return None
            self._repair_invalid_queue_timestamps(connection)
            selected = None
            selected_profile = None
            # Do not cap this scan: a long backlog of jobs for unavailable profiles
            # must not starve a later job that this worker can actually run.  The
            # status/created_at index preserves FIFO ordering for each eligible job.
            pending_rows = list(
                connection.execute(
                    "SELECT * FROM jobs WHERE status='pending' ORDER BY created_at, job_id"
                )
            )
            if claim_scope is not None and claim_scope.schema != SCHEMA_V2:
                # A temporary scope is an explicit execution sequence.  Keep the
                # normal queue FIFO untouched, while ensuring a scoped worker can
                # never let queue arrival order override the signed allowlist.
                scope_order = {item.job_id: index for index, item in enumerate(claim_scope.jobs)}
                pending_rows.sort(
                    key=lambda row: scope_order.get(int(row["job_id"]), len(scope_order))
                )
            profile_heads: dict[str, int] = {}
            enforce_profile_fifo = bool(
                (claim_scope is not None and claim_scope.schema == SCHEMA_V2)
                or repository is not None
                or head_sha is not None
            )
            if enforce_profile_fifo:
                # v2 scopes may authorize independent profiles concurrently, but
                # may never skip the oldest pending job within any one profile.
                # Keep this guard in the durable claim path as well as the
                # controller endpoint: a worker must not be able to bypass FIFO
                # by invoking the store directly.
                for row in pending_rows:
                    # A capacity directive is already bound by the controller to
                    # one validated repository/SHA tuple.  Compute FIFO within
                    # that bounded candidate set; otherwise an older row that the
                    # controller deliberately deemed inadmissible can deadlock the
                    # exact signed scope forever.
                    if (
                        claim_scope is not None
                        and claim_scope.schema == SCHEMA_V2
                        and repository is not None
                        and str(row["repository"]).lower() != repository.lower()
                    ):
                        continue
                    if (
                        claim_scope is not None
                        and claim_scope.schema == SCHEMA_V2
                        and head_sha is not None
                        and str(row["head_sha"]).lower() != head_sha.lower()
                    ):
                        continue
                    labels = {label.lower() for label in json.loads(row["labels_json"])}
                    matching_profile = next(
                        (profile for profile in profiles if profile.lower() in labels), None
                    )
                    if matching_profile is not None:
                        if (
                            claim_scope is not None
                            and int(row["job_id"]) in fifo_skip_job_ids
                            and claim_scope.skips(
                                int(row["job_id"]),
                                str(row["repository"]),
                                str(row["head_sha"]),
                                matching_profile,
                                run_id=int(row["run_id"]),
                                attempt=_workflow_job_attempt(str(row["payload_json"])),
                            )
                        ):
                            continue
                        profile_heads.setdefault(matching_profile.lower(), int(row["job_id"]))
            for row in pending_rows:
                if repository is not None and str(row["repository"]).lower() != repository.lower():
                    continue
                if head_sha is not None and str(row["head_sha"]).lower() != head_sha.lower():
                    continue
                labels = {label.lower() for label in json.loads(row["labels_json"])}
                matching_profile = next(
                    (profile for profile in profiles if profile.lower() in labels), None
                )
                if matching_profile is None:
                    continue
                if enforce_profile_fifo and profile_heads.get(matching_profile.lower()) != int(
                    row["job_id"]
                ):
                    continue
                if claim_scope is not None and not claim_scope.permits(
                    int(row["job_id"]),
                    str(row["repository"]),
                    str(row["head_sha"]),
                    matching_profile,
                    run_id=int(row["run_id"]),
                    attempt=_workflow_job_attempt(str(row["payload_json"])),
                ):
                    continue
                required_disk_mb = None
                if profile_disk_mb is not None:
                    required_disk_mb = profile_disk_mb.get(matching_profile)
                    if repository_profile_disk_mb is not None:
                        required_disk_mb = repository_profile_disk_mb.get(
                            (str(row["repository"]).lower(), matching_profile.lower()),
                            required_disk_mb,
                        )
                if profile_disk_mb is not None and required_disk_mb is None:
                    continue
                if (
                    disk_free_gib is not None
                    and min_disk_free_gib is not None
                    and not _disk_headroom_allowed(
                        {
                            "disk_free_gib": disk_free_gib,
                            "min_disk_free_gib": min_disk_free_gib,
                        },
                        required_disk_mb,
                    )
                ):
                    continue
                if tier == "reserve" and self._has_available_tier_slot(
                    connection,
                    "primary",
                    now - primary_max_age_seconds,
                    profile=matching_profile,
                    profile_disk_mb=required_disk_mb,
                ):
                    connection.execute("COMMIT")
                    return None
                selected = row
                selected_profile = matching_profile
                break
            if selected is None:
                connection.execute("COMMIT")
                return None
            assert selected_profile is not None
            updated = connection.execute(
                """
                UPDATE jobs SET status='claimed', worker_name=?, claim_scope_id=?, profile=?,
                    claimed_at=?, updated_at=?, attempts=attempts+1
                WHERE job_id=? AND status='pending'
                """,
                (
                    worker_name,
                    claim_scope.scope_id if claim_scope is not None else None,
                    selected_profile,
                    now,
                    now,
                    selected["job_id"],
                ),
            )
            connection.execute("COMMIT")
            if updated.rowcount != 1:
                return None
            return dict(selected) | {
                "worker_name": worker_name,
                "profile": selected_profile,
            }

    def set_status(self, job_id: int, status: str, result: str = "") -> None:
        now = time.time()
        completed_at = now if status in {"completed", "failed", "rejected"} else None
        with self.connect() as connection:
            connection.execute(
                "UPDATE jobs SET status=?, result=?, updated_at=?, "
                "completed_at=COALESCE(?, completed_at) WHERE job_id=?",
                (status, result[:4000], now, completed_at, job_id),
            )

    def job_status(self, job_id: int) -> str | None:
        with self.connect() as connection:
            row = connection.execute("SELECT status FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return str(row["status"]) if row is not None else None

    def job(self, job_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM jobs WHERE job_id=?", (job_id,)).fetchone()
        return dict(row) if row is not None else None

    def pending_jobs(self) -> list[dict[str, Any]]:
        """Return the durable FIFO projection without changing a job state."""
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM jobs WHERE status='pending' ORDER BY created_at, job_id"
            ).fetchall()
        return [dict(row) for row in rows]

    def fail_if_active(self, job_id: int, result: str) -> bool:
        now = time.time()
        with self.connect() as connection:
            updated = connection.execute(
                """
                UPDATE jobs SET status='failed', result=?, updated_at=?, completed_at=?
                WHERE job_id=? AND status IN ('claimed','running')
                """,
                (result[:4000], now, now, job_id),
            )
        return updated.rowcount == 1

    def requeue_active(self, job_id: int, reason: str) -> bool:
        now = time.time()
        with self.connect() as connection:
            updated = connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL,
                    claim_scope_id=NULL, profile=NULL,
                    claimed_at=NULL, updated_at=?, result=?
                WHERE job_id=? AND status IN ('claimed','running')
                """,
                (now, reason[:4000], job_id),
            )
        return updated.rowcount == 1

    def requeue(self, job_id: int, reason: str) -> None:
        now = time.time()
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL,
                    claim_scope_id=NULL, profile=NULL,
                    claimed_at=NULL, updated_at=?, result=?
                WHERE job_id=? AND status='claimed'
                """,
                (now, reason[:4000], job_id),
            )

    def complete_from_webhook(self, job_id: int, conclusion: str) -> None:
        self.set_status(job_id, "completed", conclusion)

    def heartbeat(
        self,
        name: str,
        profiles: tuple[str, ...],
        active_jobs: int,
        active_job_ids: tuple[int, ...],
        detail: dict[str, Any],
    ) -> None:
        now = time.time()
        worker_detail = detail | {"active_job_ids": list(active_job_ids)}
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                """
                INSERT INTO workers(name, profiles_json, active_jobs, last_seen, detail_json)
                VALUES(?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET profiles_json=excluded.profiles_json,
                    active_jobs=excluded.active_jobs, last_seen=excluded.last_seen,
                    detail_json=excluded.detail_json
                """,
                (name, json.dumps(profiles), active_jobs, now, json.dumps(worker_detail)),
            )
            if active_job_ids:
                connection.execute(
                    """
                    UPDATE jobs SET updated_at=? WHERE worker_name=?
                    AND status IN ('claimed','running')
                    AND job_id IN (SELECT value FROM json_each(?))
                    """,
                    (now, name, json.dumps(active_job_ids)),
                )
            connection.execute("COMMIT")

    @staticmethod
    def _worker_fenced(connection: sqlite3.Connection, worker_name: str) -> bool:
        return (
            connection.execute(
                "SELECT 1 FROM worker_recoveries WHERE worker_name=? AND state!='released'",
                (worker_name,),
            ).fetchone()
            is not None
        )

    @staticmethod
    def _require_worker_idle(
        connection: sqlite3.Connection, worker_name: str, *, after: float = 0
    ) -> None:
        worker = connection.execute("SELECT * FROM workers WHERE name=?", (worker_name,)).fetchone()
        if worker is None or not 0 <= time.time() - float(worker["last_seen"]) < 90:
            raise ValueError("worker heartbeat is missing or stale")
        if float(worker["last_seen"]) <= after:
            raise ValueError("post-recovery heartbeat has not arrived")
        detail = json.loads(worker["detail_json"])
        if (
            int(worker["active_jobs"]) != 0
            or detail.get("active_job_ids") != []
            or connection.execute(
                "SELECT 1 FROM jobs WHERE worker_name=? AND status IN ('claimed','running')",
                (worker_name,),
            ).fetchone()
            is not None
        ):
            raise ValueError("worker has active or unverified work")

    @staticmethod
    def _require_no_durable_worker_work(connection: sqlite3.Connection, worker_name: str) -> None:
        """Prove the controller has no durable claim for an offline worker.

        A stale or missing heartbeat is expected during recovery and therefore
        cannot prove either idle or busy.  Provider reconciliation is supplied
        by the authenticated controller-owned provider integration; this check
        independently proves that the controller database has no
        claimed/running work for the target.
        """

        if (
            connection.execute(
                "SELECT 1 FROM jobs WHERE worker_name=? AND status IN ('claimed','running')",
                (worker_name,),
            ).fetchone()
            is not None
        ):
            raise ValueError("worker has durable active work")

    @contextmanager
    def worker_admission_guard(self, worker_name: str) -> Iterator[None]:
        """Serialize scope publication against durable claims and recovery fencing."""
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                if self._worker_fenced(connection, worker_name):
                    raise ValueError("worker recovery fence is active")
                self._require_worker_idle(connection, worker_name)
                yield
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def begin_worker_recovery(
        self,
        worker_name: str,
        idempotency_key: str,
        fingerprint: str,
        *,
        repository: str,
        labels: tuple[str, ...],
        provider_idle_proof: dict[str, Any],
        provider_proof_key: str,
        recovery_action: str,
        operator_certificate_sha256: str,
        expected_agent_certificate_sha256: str,
        interface_version: str,
        interface_digest: str,
        controller_revision: str,
        controller_release_digest: str,
        policy_digest: str,
        agent_release_digest: str,
        controller_receipt_id: str,
        controller_observed_at: float,
        request_nonce: str,
        requested_at: float,
        proof_max_age_seconds: float = 120.0,
    ) -> dict[str, Any]:
        controller_observed_at = _finite_recovery_number(
            controller_observed_at, field="worker recovery request timestamp"
        )
        requested_at = _finite_recovery_number(
            requested_at, field="worker recovery request timestamp"
        )
        proof_max_age_seconds = _recovery_proof_window(proof_max_age_seconds)
        if (
            not isinstance(idempotency_key, str)
            or not _RECOVERY_KEY.fullmatch(idempotency_key)
            or not isinstance(fingerprint, str)
            or not _SHA256_HEX.fullmatch(fingerprint)
            or not isinstance(repository, str)
            or not _REPOSITORY.fullmatch(repository)
            or not isinstance(labels, tuple)
            or not labels
            or any(not isinstance(label, str) or not label for label in labels)
            or len(set(labels)) != len(labels)
            or recovery_action not in _RECOVERY_ACTIONS
            or not isinstance(operator_certificate_sha256, str)
            or not _SHA256_HEX.fullmatch(operator_certificate_sha256)
            or not isinstance(expected_agent_certificate_sha256, str)
            or not _SHA256_HEX.fullmatch(expected_agent_certificate_sha256)
            or not isinstance(interface_version, str)
            or not _INTERFACE_VERSION.fullmatch(interface_version)
            or not isinstance(interface_digest, str)
            or not _SHA256_HEX.fullmatch(interface_digest)
            or not isinstance(controller_revision, str)
            or not _GIT_REVISION.fullmatch(controller_revision)
            or not isinstance(controller_release_digest, str)
            or not _SHA256_HEX.fullmatch(controller_release_digest)
            or not isinstance(policy_digest, str)
            or not _SHA256_DIGEST.fullmatch(policy_digest)
            or not isinstance(agent_release_digest, str)
            or not _SHA256_DIGEST.fullmatch(agent_release_digest)
            or not isinstance(controller_receipt_id, str)
            or not _SHA256_HEX.fullmatch(controller_receipt_id)
            or not isinstance(request_nonce, str)
            or not _RECOVERY_KEY.fullmatch(request_nonce)
        ):
            raise ValueError("worker recovery binding is invalid")
        target = _WORKER_RECOVERY_BINDINGS.get(worker_name)
        if target != {
            "repository": repository,
            "labels": labels,
            "recovery_action": recovery_action,
        }:
            raise ValueError("worker recovery target is not registered")
        now = time.time()
        provider = self.verify_worker_provider_idle_proof(
            provider_idle_proof,
            key=provider_proof_key,
            worker_name=worker_name,
            repository=repository,
            labels=labels,
            # Verify the immutable signature before looking up an idempotent
            # replay.  Freshness is enforced below only for first admission.
            max_age_seconds=None,
        )
        _, provider_observation_json, _ = _canonical_provider_observation(
            provider["provider_observation"]
        )
        operation_binding = {
            "schema": "qdev-worker-recovery-operation-v2",
            "idempotency_key": idempotency_key,
            "worker_name": worker_name,
            "request_digest": fingerprint,
            "repository": repository,
            "labels": list(labels),
            "recovery_action": recovery_action,
            "operator_certificate_sha256": operator_certificate_sha256,
            "expected_agent_certificate_sha256": expected_agent_certificate_sha256,
            "interface_version": interface_version,
            "interface_digest": interface_digest,
            "controller_revision": controller_revision,
            "controller_release_digest": controller_release_digest,
            "policy_digest": policy_digest,
            "agent_release_digest": agent_release_digest,
            "controller_receipt_id": controller_receipt_id,
            "controller_observed_at": controller_observed_at,
            "request_nonce": request_nonce,
            "requested_at": requested_at,
            "provider_idle_proof_digest": provider["digest"],
            "provider_reconciliation_digest": provider["provider_reconciliation_digest"],
        }
        operation_id = hashlib.sha256(
            json.dumps(
                operation_binding,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT * FROM worker_recoveries WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()
                if existing is not None:
                    existing_binding = (
                        existing["worker_name"],
                        existing["request_fingerprint"],
                        existing["repository"],
                        existing["labels_json"],
                        existing["recovery_action"],
                        existing["operator_certificate_sha256"],
                        existing["expected_agent_certificate_sha256"],
                        existing["interface_version"],
                        existing["interface_digest"],
                        existing["controller_revision"],
                        existing["controller_release_digest"],
                        existing["policy_digest"],
                        existing["agent_release_digest"],
                        existing["controller_receipt_id"],
                        existing["controller_observed_at"],
                        existing["request_nonce"],
                        existing["requested_at"],
                        existing["provider_idle_proof_digest"],
                        existing["provider_reconciliation_digest"],
                        existing["provider_observation_json"],
                        existing["operation_id"],
                    )
                    supplied_binding = (
                        worker_name,
                        fingerprint,
                        repository,
                        json.dumps(list(labels), separators=(",", ":")),
                        recovery_action,
                        operator_certificate_sha256,
                        expected_agent_certificate_sha256,
                        interface_version,
                        interface_digest,
                        controller_revision,
                        controller_release_digest,
                        policy_digest,
                        agent_release_digest,
                        controller_receipt_id,
                        controller_observed_at,
                        request_nonce,
                        requested_at,
                        provider["digest"],
                        provider["provider_reconciliation_digest"],
                        provider_observation_json,
                        operation_id,
                    )
                    if existing_binding != supplied_binding:
                        raise ValueError("recovery idempotency key is bound to another request")
                    connection.execute("COMMIT")
                    return dict(existing)
                if self._worker_fenced(connection, worker_name):
                    raise ValueError("worker has another recovery transaction")
                if (
                    not 0 <= now - controller_observed_at <= proof_max_age_seconds
                    or not 0 <= now - requested_at <= proof_max_age_seconds
                    or requested_at + 5 < controller_observed_at
                ):
                    raise ValueError("worker recovery request is not fresh")
                if not 0 <= now - float(provider["observed_at"]) <= proof_max_age_seconds:
                    raise ValueError("provider idle proof is stale")
                self._require_no_durable_worker_work(connection, worker_name)
                connection.execute(
                    "INSERT INTO worker_recoveries("
                    "idempotency_key,worker_name,request_fingerprint,operation_id,"
                    "state,created_at,invoked_at,updated_at,repository,labels_json,"
                    "provider_runner_id,provider_idle_proof_digest,provider_observed_at,"
                    "provider_reconciliation_digest,provider_observation_json,"
                    "recovery_action,operator_certificate_sha256,"
                    "expected_agent_certificate_sha256,interface_version,interface_digest,"
                    "controller_revision,controller_release_digest,policy_digest,"
                    "agent_release_digest,controller_receipt_id,"
                    "controller_observed_at,request_digest,request_nonce,requested_at,consumed_at"
                    ") VALUES(?,?,?,?,'prepared',?,NULL,"
                    "?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        idempotency_key,
                        worker_name,
                        fingerprint,
                        operation_id,
                        now,
                        now,
                        repository,
                        json.dumps(list(labels), separators=(",", ":")),
                        provider["provider_runner_id"],
                        provider["digest"],
                        provider["observed_at"],
                        provider["provider_reconciliation_digest"],
                        provider_observation_json,
                        recovery_action,
                        operator_certificate_sha256,
                        expected_agent_certificate_sha256,
                        interface_version,
                        interface_digest,
                        controller_revision,
                        controller_release_digest,
                        policy_digest,
                        agent_release_digest,
                        controller_receipt_id,
                        controller_observed_at,
                        fingerprint,
                        request_nonce,
                        requested_at,
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM worker_recoveries WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()
                connection.execute("COMMIT")
                assert row is not None
                return dict(row)
            except sqlite3.IntegrityError as error:
                connection.execute("ROLLBACK")
                raise ValueError("worker recovery authority was already consumed") from error
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def issue_worker_provider_idle_proof(
        *,
        key: str,
        worker_name: str,
        repository: str,
        labels: tuple[str, ...],
        provider_runner_id: int | None,
        provider_status: str | None,
        provider_busy: bool | None,
        active_jobs: int,
        provider_observation: dict[str, Any],
        observed_at: float | None = None,
    ) -> dict[str, Any]:
        """Create the controller-internal provider observation used by admission.

        This is not an HTTP request shape.  Only the controller process holding
        the receipt key can create a proof which ``begin_worker_recovery`` will
        accept, so an operator cannot turn a caller-supplied boolean into idle
        evidence.
        """

        target = _WORKER_RECOVERY_BINDINGS.get(worker_name)
        common_invalid = (
            not isinstance(key, str)
            or not key
            or target is None
            or target["repository"] != repository
            or target["labels"] != labels
            or isinstance(active_jobs, bool)
            or not isinstance(active_jobs, int)
            or active_jobs != 0
        )
        provider_is_absent = provider_runner_id is None
        provider_status_is_allowed = provider_status == "offline" or (
            target is not None
            and target["recovery_action"] == "restore_saved_configuration"
            and provider_status == "online"
        )
        present_invalid = not provider_is_absent and (
            isinstance(provider_runner_id, bool)
            or not isinstance(provider_runner_id, int)
            or provider_runner_id <= 0
            or not provider_status_is_allowed
            or provider_busy is not False
        )
        absent_invalid = provider_is_absent and (
            target is None
            or target["recovery_action"] != "replace_existing_registration"
            or provider_status is not None
            or provider_busy is not None
        )
        if common_invalid or present_invalid or absent_invalid:
            raise ValueError("provider idle proof is invalid")
        try:
            if provider_is_absent:
                canonical_observation, _, provider_reconciliation_digest = (
                    _validate_provider_absence_observation(
                        provider_observation,
                        repository=repository,
                        worker_name=worker_name,
                    )
                )
                proof_schema = "qdev-worker-provider-idle-proof-v2"
            else:
                assert isinstance(provider_runner_id, int)
                assert isinstance(provider_status, str)
                assert isinstance(provider_busy, bool)
                canonical_observation, _, provider_reconciliation_digest = (
                    _validate_provider_observation(
                        provider_observation,
                        schema="qdev-worker-provider-observation-v1",
                        repository=repository,
                        worker_name=worker_name,
                        provider_runner_id=provider_runner_id,
                        provider_status=provider_status,
                        provider_busy=provider_busy,
                        labels=labels,
                    )
                )
                proof_schema = "qdev-worker-provider-idle-proof-v1"
        except ValueError as error:
            raise ValueError("provider idle proof is invalid") from error
        timestamp = (
            time.time()
            if observed_at is None
            else _finite_recovery_number(observed_at, field="provider idle proof timestamp")
        )
        payload = {
            "schema": proof_schema,
            "worker_name": worker_name,
            "repository": repository,
            "labels": list(labels),
            "provider_runner_id": provider_runner_id,
            "provider_status": provider_status,
            "provider_busy": provider_busy,
            "active_jobs": active_jobs,
            "provider_observation": canonical_observation,
            "provider_reconciliation_digest": provider_reconciliation_digest,
            "observed_at": timestamp,
        }
        canonical = json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
        signature = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        return payload | {"digest": digest, "signature": signature}

    @staticmethod
    def verify_worker_provider_idle_proof(
        proof: dict[str, Any],
        *,
        key: str,
        worker_name: str,
        repository: str,
        labels: tuple[str, ...],
        max_age_seconds: float | None,
    ) -> dict[str, Any]:
        required = {
            "schema",
            "worker_name",
            "repository",
            "labels",
            "provider_runner_id",
            "provider_status",
            "provider_busy",
            "active_jobs",
            "provider_observation",
            "provider_reconciliation_digest",
            "observed_at",
            "digest",
            "signature",
        }
        if (
            not isinstance(key, str)
            or not key
            or not isinstance(proof, dict)
            or set(proof) != required
            or not isinstance(max_age_seconds, (int, float, type(None)))
            or isinstance(max_age_seconds, bool)
        ):
            raise ValueError("provider idle proof is invalid")
        if max_age_seconds is not None:
            try:
                max_age_seconds = _recovery_proof_window(max_age_seconds)
            except ValueError as error:
                raise ValueError("provider idle proof is invalid") from error
        payload = {name: proof[name] for name in required - {"digest", "signature"}}
        try:
            canonical = json.dumps(
                payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise ValueError("provider idle proof is invalid") from error
        expected_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
        expected_signature = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        now = time.time()
        try:
            observed_at = _finite_recovery_number(
                proof["observed_at"], field="provider idle proof timestamp"
            )
        except ValueError as error:
            raise ValueError("provider idle proof is invalid") from error
        proof_age = now - observed_at
        target = _WORKER_RECOVERY_BINDINGS.get(worker_name)
        provider_is_absent = proof.get("schema") == "qdev-worker-provider-idle-proof-v2"
        try:
            if provider_is_absent:
                _, _, provider_reconciliation_digest = _validate_provider_absence_observation(
                    proof["provider_observation"],
                    repository=repository,
                    worker_name=worker_name,
                )
            else:
                _, _, provider_reconciliation_digest = _validate_provider_observation(
                    proof["provider_observation"],
                    schema="qdev-worker-provider-observation-v1",
                    repository=repository,
                    worker_name=worker_name,
                    provider_runner_id=proof["provider_runner_id"],
                    provider_status=proof["provider_status"],
                    provider_busy=proof["provider_busy"],
                    labels=labels,
                )
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError("provider idle proof is invalid") from error
        provider_identity_is_valid = (
            provider_is_absent
            and target is not None
            and target["recovery_action"] == "replace_existing_registration"
            and proof["provider_runner_id"] is None
            and proof["provider_status"] is None
            and proof["provider_busy"] is None
        ) or (
            not provider_is_absent
            and proof["schema"] == "qdev-worker-provider-idle-proof-v1"
            and not isinstance(proof["provider_runner_id"], bool)
            and isinstance(proof["provider_runner_id"], int)
            and proof["provider_runner_id"] > 0
            and (
                proof["provider_status"] == "offline"
                or (
                    target is not None
                    and target["recovery_action"] == "restore_saved_configuration"
                    and proof["provider_status"] == "online"
                )
            )
            and proof["provider_busy"] is False
        )
        if (
            proof["worker_name"] != worker_name
            or proof["repository"] != repository
            or proof["labels"] != list(labels)
            or not provider_identity_is_valid
            or isinstance(proof["active_jobs"], bool)
            or not isinstance(proof["active_jobs"], int)
            or proof["active_jobs"] != 0
            or not isinstance(proof["provider_reconciliation_digest"], str)
            or not _SHA256_DIGEST.fullmatch(proof["provider_reconciliation_digest"])
            or proof["provider_reconciliation_digest"] != provider_reconciliation_digest
            or proof_age < 0
            or (max_age_seconds is not None and proof_age > max_age_seconds)
            or not isinstance(proof["digest"], str)
            or not _SHA256_DIGEST.fullmatch(proof["digest"])
            or proof["digest"] != expected_digest
            or not isinstance(proof["signature"], str)
            or not hmac.compare_digest(proof["signature"], expected_signature)
        ):
            raise ValueError("provider idle proof is invalid")
        return dict(proof)

    @staticmethod
    def issue_worker_recovery_acceptance_proof(
        *,
        key: str,
        operation_id: str,
        worker_name: str,
        repository: str,
        labels: tuple[str, ...],
        prior_provider_runner_id: int | None,
        prior_provider_runner_disposition: str,
        provider_runner_id: int,
        matching_runner_count: int,
        provider_status: str,
        provider_busy: bool,
        active_jobs: int,
        provider_observation: dict[str, Any],
        canary_repository: str,
        canary_workflow: str,
        canary_ref: str,
        canary_head_sha: str,
        canary_dispatch_correlation: str,
        canary_temporary_label: str,
        canary_dispatch_observed_label: str,
        canary_run_observed_label: str,
        canary_baseline_run_id: int,
        canary_run_id: int,
        canary_run_attempt: int,
        canary_job_id: int,
        canary_job_labels: tuple[str, ...],
        canary_job_runner_id: int,
        canary_job_runner_name: str,
        canary_runner_id: int,
        canary_runner_name: str,
        canary_status: str,
        canary_conclusion: str,
        canary_completed_at: float,
        observed_at: float | None = None,
    ) -> dict[str, Any]:
        """Sign the controller's provider/canary observation for fence release.

        The provider integration must first resolve the complete repository
        runner/job/run sets.  This helper accepts only the two fixed targets,
        an exact single same-name runner, final permanent labels and a green
        canary tied to that runner.  The full observation remains bound by the
        reconciliation digest rather than being reduced to caller booleans.
        """

        target = _WORKER_RECOVERY_BINDINGS.get(worker_name)
        integer_values = (
            provider_runner_id,
            matching_runner_count,
            canary_run_id,
            canary_run_attempt,
            canary_job_id,
            canary_job_runner_id,
            canary_runner_id,
        )
        valid_runner_transition = (
            prior_provider_runner_id is not None
            and prior_provider_runner_disposition == "same"
            and provider_runner_id == prior_provider_runner_id
        ) or (
            target is not None
            and target["recovery_action"] == "replace_existing_registration"
            and prior_provider_runner_disposition == "absent"
            and (prior_provider_runner_id is None or provider_runner_id != prior_provider_runner_id)
        )
        if (
            not isinstance(key, str)
            or not key
            or not isinstance(operation_id, str)
            or not _SHA256_HEX.fullmatch(operation_id)
            or target is None
            or target["repository"] != repository
            or target["labels"] != labels
            or (
                prior_provider_runner_id is not None
                and (
                    isinstance(prior_provider_runner_id, bool)
                    or not isinstance(prior_provider_runner_id, int)
                    or prior_provider_runner_id <= 0
                )
            )
            or any(
                isinstance(value, bool) or not isinstance(value, int) for value in integer_values
            )
            or isinstance(canary_baseline_run_id, bool)
            or not isinstance(canary_baseline_run_id, int)
            or canary_baseline_run_id < 0
            or any(value <= 0 for value in integer_values)
            or matching_runner_count != 1
            or not valid_runner_transition
            or provider_status != "online"
            or provider_busy is not False
            or isinstance(active_jobs, bool)
            or not isinstance(active_jobs, int)
            or active_jobs != 0
            or canary_repository != repository
            or not isinstance(canary_workflow, str)
            or not _CANARY_WORKFLOW.fullmatch(canary_workflow)
            or canary_workflow != _WORKER_RECOVERY_CANARY_WORKFLOWS.get(worker_name)
            or not _valid_canary_ref(canary_ref)
            or not isinstance(canary_head_sha, str)
            or not _GIT_REVISION.fullmatch(canary_head_sha)
            or canary_dispatch_correlation != _worker_recovery_dispatch_correlation(operation_id)
            or canary_temporary_label != _worker_recovery_temporary_label(operation_id)
            or canary_dispatch_observed_label != canary_temporary_label
            or canary_run_observed_label != canary_temporary_label
            or canary_run_id <= canary_baseline_run_id
            or not isinstance(canary_job_labels, tuple)
            or len({label.lower() for label in canary_job_labels}) != len(canary_job_labels)
            or canary_job_labels != labels + (canary_temporary_label,)
            or canary_job_runner_id != provider_runner_id
            or canary_job_runner_name != worker_name
            or canary_runner_id != provider_runner_id
            or canary_runner_name != worker_name
            or canary_status != "completed"
            or canary_conclusion != "success"
        ):
            raise ValueError("worker recovery acceptance proof is invalid")
        completed_at = _finite_recovery_number(
            canary_completed_at, field="worker recovery canary completion timestamp"
        )
        timestamp = (
            time.time()
            if observed_at is None
            else _finite_recovery_number(observed_at, field="worker recovery acceptance timestamp")
        )
        if timestamp < completed_at:
            raise ValueError("worker recovery acceptance proof is invalid")
        canary_observation = {
            "repository": canary_repository,
            "workflow": canary_workflow,
            "ref": canary_ref,
            "head_sha": canary_head_sha,
            "dispatch_correlation": canary_dispatch_correlation,
            "temporary_label": canary_temporary_label,
            "dispatch_observed_label": canary_dispatch_observed_label,
            "run_observed_label": canary_run_observed_label,
            "baseline_run_id": canary_baseline_run_id,
            "run_id": canary_run_id,
            "run_attempt": canary_run_attempt,
            "job_id": canary_job_id,
            "job_labels": list(canary_job_labels),
            "job_runner_id": canary_job_runner_id,
            "job_runner_name": canary_job_runner_name,
            "status": canary_status,
            "conclusion": canary_conclusion,
            "completed_at": completed_at,
        }
        try:
            canonical_observation, _, provider_reconciliation_digest = (
                _validate_provider_observation(
                    provider_observation,
                    schema="qdev-worker-recovery-provider-observation-v1",
                    repository=repository,
                    worker_name=worker_name,
                    provider_runner_id=provider_runner_id,
                    provider_status=provider_status,
                    provider_busy=provider_busy,
                    labels=labels,
                    canary=canary_observation,
                )
            )
            observed_runners = _provider_runner_observations(canonical_observation)
        except ValueError as error:
            raise ValueError("worker recovery acceptance proof is invalid") from error
        if (
            prior_provider_runner_id is not None
            and prior_provider_runner_disposition == "absent"
            and any(runner["id"] == prior_provider_runner_id for runner in observed_runners)
        ):
            raise ValueError("worker recovery acceptance proof is invalid")
        payload = {
            "schema": (
                "qdev-worker-recovery-acceptance-proof-v2"
                if prior_provider_runner_id is None
                else "qdev-worker-recovery-acceptance-proof-v1"
            ),
            "operation_id": operation_id,
            "worker_name": worker_name,
            "repository": repository,
            "labels": list(labels),
            "prior_provider_runner_id": prior_provider_runner_id,
            "prior_provider_runner_disposition": prior_provider_runner_disposition,
            "provider_runner_id": provider_runner_id,
            "matching_runner_count": matching_runner_count,
            "provider_status": provider_status,
            "provider_busy": provider_busy,
            "active_jobs": active_jobs,
            "provider_observation": canonical_observation,
            "provider_reconciliation_digest": provider_reconciliation_digest,
            "canary_repository": canary_repository,
            "canary_workflow": canary_workflow,
            "canary_ref": canary_ref,
            "canary_head_sha": canary_head_sha,
            "canary_dispatch_correlation": canary_dispatch_correlation,
            "canary_temporary_label": canary_temporary_label,
            "canary_dispatch_observed_label": canary_dispatch_observed_label,
            "canary_run_observed_label": canary_run_observed_label,
            "canary_baseline_run_id": canary_baseline_run_id,
            "canary_run_id": canary_run_id,
            "canary_run_attempt": canary_run_attempt,
            "canary_job_id": canary_job_id,
            "canary_job_labels": list(canary_job_labels),
            "canary_job_runner_id": canary_job_runner_id,
            "canary_job_runner_name": canary_job_runner_name,
            "canary_runner_id": canary_runner_id,
            "canary_runner_name": canary_runner_name,
            "canary_status": canary_status,
            "canary_conclusion": canary_conclusion,
            "canary_completed_at": completed_at,
            "observed_at": timestamp,
        }
        canonical = json.dumps(
            payload,
            allow_nan=False,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
        signature = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        return payload | {"digest": digest, "signature": signature}

    @staticmethod
    def verify_worker_recovery_acceptance_proof(
        proof: dict[str, Any],
        *,
        key: str,
        operation_id: str,
        worker_name: str,
        repository: str,
        labels: tuple[str, ...],
        prior_provider_runner_id: int | None,
        recovery_action: str,
        native_finalized_at: float,
        max_age_seconds: float | None,
    ) -> dict[str, Any]:
        required = {
            "schema",
            "operation_id",
            "worker_name",
            "repository",
            "labels",
            "prior_provider_runner_id",
            "prior_provider_runner_disposition",
            "provider_runner_id",
            "matching_runner_count",
            "provider_status",
            "provider_busy",
            "active_jobs",
            "provider_observation",
            "provider_reconciliation_digest",
            "canary_repository",
            "canary_workflow",
            "canary_ref",
            "canary_head_sha",
            "canary_dispatch_correlation",
            "canary_temporary_label",
            "canary_dispatch_observed_label",
            "canary_run_observed_label",
            "canary_baseline_run_id",
            "canary_run_id",
            "canary_run_attempt",
            "canary_job_id",
            "canary_job_labels",
            "canary_job_runner_id",
            "canary_job_runner_name",
            "canary_runner_id",
            "canary_runner_name",
            "canary_status",
            "canary_conclusion",
            "canary_completed_at",
            "observed_at",
            "digest",
            "signature",
        }
        if (
            not isinstance(key, str)
            or not key
            or not isinstance(proof, dict)
            or set(proof) != required
            or not isinstance(max_age_seconds, (int, float, type(None)))
            or isinstance(max_age_seconds, bool)
        ):
            raise ValueError("worker recovery acceptance proof is invalid")
        if max_age_seconds is not None:
            try:
                max_age_seconds = _recovery_proof_window(max_age_seconds)
            except ValueError as error:
                raise ValueError("worker recovery acceptance proof is invalid") from error
        try:
            finalized_at = _finite_recovery_number(
                native_finalized_at, field="native recovery finalization timestamp"
            )
            completed_at = _finite_recovery_number(
                proof["canary_completed_at"],
                field="worker recovery canary completion timestamp",
            )
            observed_at = _finite_recovery_number(
                proof["observed_at"], field="worker recovery acceptance timestamp"
            )
            payload = {name: proof[name] for name in required - {"digest", "signature"}}
            canonical = json.dumps(
                payload,
                allow_nan=False,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise ValueError("worker recovery acceptance proof is invalid") from error
        expected_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
        expected_signature = hmac.new(key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
        integer_fields = (
            "provider_runner_id",
            "matching_runner_count",
            "canary_run_id",
            "canary_run_attempt",
            "canary_job_id",
            "canary_job_runner_id",
            "canary_runner_id",
        )
        integers_are_valid = all(
            not isinstance(proof[name], bool) and isinstance(proof[name], int) and proof[name] > 0
            for name in integer_fields
        )
        prior_provider_identity_is_valid = (
            prior_provider_runner_id is None
            and proof["schema"] == "qdev-worker-recovery-acceptance-proof-v2"
            and proof["prior_provider_runner_id"] is None
        ) or (
            prior_provider_runner_id is not None
            and proof["schema"] == "qdev-worker-recovery-acceptance-proof-v1"
            and not isinstance(prior_provider_runner_id, bool)
            and isinstance(prior_provider_runner_id, int)
            and prior_provider_runner_id > 0
            and proof["prior_provider_runner_id"] == prior_provider_runner_id
        )
        runner_transition_is_valid = (
            prior_provider_runner_id is not None
            and proof["prior_provider_runner_disposition"] == "same"
            and proof["provider_runner_id"] == prior_provider_runner_id
        ) or (
            recovery_action == "replace_existing_registration"
            and proof["prior_provider_runner_disposition"] == "absent"
            and (
                prior_provider_runner_id is None
                or proof["provider_runner_id"] != prior_provider_runner_id
            )
        )
        expected_temporary_label = _worker_recovery_temporary_label(operation_id)
        expected_dispatch_correlation = _worker_recovery_dispatch_correlation(operation_id)
        canary_observation = {
            "repository": proof["canary_repository"],
            "workflow": proof["canary_workflow"],
            "ref": proof["canary_ref"],
            "head_sha": proof["canary_head_sha"],
            "dispatch_correlation": proof["canary_dispatch_correlation"],
            "temporary_label": proof["canary_temporary_label"],
            "dispatch_observed_label": proof["canary_dispatch_observed_label"],
            "run_observed_label": proof["canary_run_observed_label"],
            "baseline_run_id": proof["canary_baseline_run_id"],
            "run_id": proof["canary_run_id"],
            "run_attempt": proof["canary_run_attempt"],
            "job_id": proof["canary_job_id"],
            "job_labels": proof["canary_job_labels"],
            "job_runner_id": proof["canary_job_runner_id"],
            "job_runner_name": proof["canary_job_runner_name"],
            "status": proof["canary_status"],
            "conclusion": proof["canary_conclusion"],
            "completed_at": completed_at,
        }
        try:
            provider_observation, _, recomputed_provider_digest = _validate_provider_observation(
                proof["provider_observation"],
                schema="qdev-worker-recovery-provider-observation-v1",
                repository=repository,
                worker_name=worker_name,
                provider_runner_id=proof["provider_runner_id"],
                provider_status=proof["provider_status"],
                provider_busy=proof["provider_busy"],
                labels=labels,
                canary=canary_observation,
            )
            observed_runners = _provider_runner_observations(provider_observation)
        except (TypeError, ValueError) as error:
            raise ValueError("worker recovery acceptance proof is invalid") from error
        now = time.time()
        age = now - observed_at
        if (
            proof["operation_id"] != operation_id
            or proof["worker_name"] != worker_name
            or proof["repository"] != repository
            or proof["labels"] != list(labels)
            or not integers_are_valid
            or not prior_provider_identity_is_valid
            or proof["matching_runner_count"] != 1
            or not runner_transition_is_valid
            or proof["provider_status"] != "online"
            or proof["provider_busy"] is not False
            or isinstance(proof["active_jobs"], bool)
            or not isinstance(proof["active_jobs"], int)
            or proof["active_jobs"] != 0
            or not isinstance(proof["provider_reconciliation_digest"], str)
            or not _SHA256_DIGEST.fullmatch(proof["provider_reconciliation_digest"])
            or proof["provider_reconciliation_digest"] != recomputed_provider_digest
            or proof["canary_repository"] != repository
            or not isinstance(proof["canary_workflow"], str)
            or not _CANARY_WORKFLOW.fullmatch(proof["canary_workflow"])
            or proof["canary_workflow"] != _WORKER_RECOVERY_CANARY_WORKFLOWS.get(worker_name)
            or not _valid_canary_ref(proof["canary_ref"])
            or not isinstance(proof["canary_head_sha"], str)
            or not _GIT_REVISION.fullmatch(proof["canary_head_sha"])
            or proof["canary_dispatch_correlation"] != expected_dispatch_correlation
            or proof["canary_temporary_label"] != expected_temporary_label
            or proof["canary_dispatch_observed_label"] != expected_temporary_label
            or proof["canary_run_observed_label"] != expected_temporary_label
            or isinstance(proof["canary_baseline_run_id"], bool)
            or not isinstance(proof["canary_baseline_run_id"], int)
            or proof["canary_baseline_run_id"] < 0
            or proof["canary_run_id"] <= proof["canary_baseline_run_id"]
            or proof["canary_job_labels"] != list(labels) + [expected_temporary_label]
            or proof["canary_job_runner_id"] != proof["provider_runner_id"]
            or proof["canary_job_runner_name"] != worker_name
            or proof["canary_runner_id"] != proof["provider_runner_id"]
            or proof["canary_runner_name"] != worker_name
            or proof["canary_status"] != "completed"
            or proof["canary_conclusion"] != "success"
            or completed_at < finalized_at
            or observed_at < completed_at
            or age < 0
            or (max_age_seconds is not None and age > max_age_seconds)
            or not isinstance(proof["digest"], str)
            or not _SHA256_DIGEST.fullmatch(proof["digest"])
            or proof["digest"] != expected_digest
            or not isinstance(proof["signature"], str)
            or not _SHA256_HEX.fullmatch(proof["signature"])
            or not hmac.compare_digest(proof["signature"], expected_signature)
            or (
                prior_provider_runner_id is not None
                and proof["prior_provider_runner_disposition"] == "absent"
                and any(runner["id"] == prior_provider_runner_id for runner in observed_runners)
            )
        ):
            raise ValueError("worker recovery acceptance proof is invalid")
        return dict(proof)

    @staticmethod
    def _worker_recovery_canary_row(
        row: sqlite3.Row | dict[str, Any],
    ) -> dict[str, Any]:
        value = dict(row)
        try:
            labels = json.loads(str(value.pop("temporary_labels_json")))
            raw_job_labels = value.pop("job_labels_json")
            job_labels = None if raw_job_labels is None else json.loads(str(raw_job_labels))
        except (KeyError, TypeError, json.JSONDecodeError) as error:
            raise ValueError("worker recovery canary durable binding is invalid") from error
        operation_id = value.get("operation_id")
        if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(operation_id):
            raise ValueError("worker recovery canary durable binding is invalid")
        expected_temporary_label = _worker_recovery_temporary_label(operation_id)
        if (
            not isinstance(labels, list)
            or labels != [expected_temporary_label]
            or any(not isinstance(label, str) for label in labels)
            or value.get("temporary_label") != expected_temporary_label
            or value.get("dispatch_correlation")
            != _worker_recovery_dispatch_correlation(operation_id)
            or (
                job_labels is not None
                and (
                    not isinstance(job_labels, list)
                    or any(not isinstance(label, str) for label in job_labels)
                )
            )
        ):
            raise ValueError("worker recovery canary durable binding is invalid")
        value["temporary_labels"] = tuple(labels)
        value["job_labels"] = None if job_labels is None else tuple(job_labels)
        return value

    @staticmethod
    def _worker_recovery_canary_event_payload(
        canary: dict[str, Any],
        *,
        from_phase: str | None,
        recorded_at: float,
    ) -> dict[str, Any]:
        """Build the complete allowlisted event body without caller payloads."""

        return {
            "schema": "qdev-worker-recovery-canary-event-v1",
            "operation_id": canary["operation_id"],
            "revision": canary["revision"],
            "from_phase": from_phase,
            "phase": canary["phase"],
            "intent_digest": canary["intent_digest"],
            "worker_name": canary["worker_name"],
            "repository": canary["repository"],
            "workflow": canary["workflow"],
            "ref": canary["ref"],
            "head_sha": canary["head_sha"],
            "baseline_run_id": canary["baseline_run_id"],
            "provider_runner_id": canary["provider_runner_id"],
            "provider_runner_name": canary["provider_runner_name"],
            "dispatch_correlation": canary["dispatch_correlation"],
            "temporary_label": canary["temporary_label"],
            "temporary_labels": list(canary["temporary_labels"]),
            "dispatch_observed_label": canary["dispatch_observed_label"],
            "run_observed_label": canary["run_observed_label"],
            "run_id": canary["run_id"],
            "run_attempt": canary["run_attempt"],
            "job_id": canary["job_id"],
            "job_labels": (None if canary["job_labels"] is None else list(canary["job_labels"])),
            "job_runner_id": canary["job_runner_id"],
            "job_runner_name": canary["job_runner_name"],
            "run_status": canary["run_status"],
            "conclusion": canary["conclusion"],
            "dispatched_at": canary["dispatched_at"],
            "completed_at": canary["completed_at"],
            "cleaned_at": canary["cleaned_at"],
            "accepted_at": canary["accepted_at"],
            "recorded_at": recorded_at,
        }

    @staticmethod
    def _worker_recovery_canary_event_digest(payload: dict[str, Any]) -> str:
        canonical = json.dumps(
            payload,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return "sha256:" + hashlib.sha256(canonical).hexdigest()

    @staticmethod
    def _require_worker_recovery_canary_event(
        connection: sqlite3.Connection,
        canary: dict[str, Any],
        *,
        from_phase: str | None,
        require_current_tip: bool = True,
    ) -> None:
        event = connection.execute(
            "SELECT * FROM worker_recovery_canary_events WHERE operation_id=? AND revision=?",
            (canary["operation_id"], canary["revision"]),
        ).fetchone()
        if event is None:
            raise ValueError("worker recovery canary event history is incomplete")
        try:
            payload = json.loads(str(event["event_json"]))
            expected = Store._worker_recovery_canary_event_payload(
                canary,
                from_phase=from_phase,
                recorded_at=_finite_recovery_number(
                    event["recorded_at"], field="worker recovery canary event timestamp"
                ),
            )
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("worker recovery canary event history is invalid") from error
        digest = Store._worker_recovery_canary_event_digest(expected)
        if (
            payload != expected
            or event["event_digest"] != digest
            or (require_current_tip and canary["last_event_digest"] != digest)
            or event["from_phase"] != from_phase
            or event["phase"] != canary["phase"]
        ):
            raise ValueError("worker recovery canary event history is invalid")

    @staticmethod
    def _validate_worker_recovery_canary_identity(
        *,
        operation_id: str,
        worker_name: str,
        repository: str,
        workflow: str,
        ref: str,
        head_sha: str,
        baseline_run_id: int,
        provider_runner_id: int,
        provider_runner_name: str,
        permanent_labels: tuple[str, ...],
        dispatch_correlation: str,
        temporary_label: str,
    ) -> None:
        target = _WORKER_RECOVERY_BINDINGS.get(worker_name)
        if (
            target is None
            or target["repository"] != repository
            or target["labels"] != permanent_labels
            or workflow != _WORKER_RECOVERY_CANARY_WORKFLOWS.get(worker_name)
            or not _CANARY_WORKFLOW.fullmatch(workflow)
            or not _valid_canary_ref(ref)
            or not _GIT_REVISION.fullmatch(head_sha)
            or isinstance(baseline_run_id, bool)
            or not isinstance(baseline_run_id, int)
            or baseline_run_id < 0
            or isinstance(provider_runner_id, bool)
            or not isinstance(provider_runner_id, int)
            or provider_runner_id <= 0
            or provider_runner_name != worker_name
            or dispatch_correlation != _worker_recovery_dispatch_correlation(operation_id)
            or temporary_label != _worker_recovery_temporary_label(operation_id)
            or _RUNNER_LABEL.fullmatch(temporary_label) is None
            or temporary_label.lower() in {label.lower() for label in permanent_labels}
        ):
            raise ValueError("worker recovery canary binding is invalid")

    def create_worker_recovery_canary_intent(
        self,
        *,
        operation_id: str,
        repository: str,
        workflow: str,
        ref: str,
        head_sha: str,
        baseline_run_id: int,
        provider_runner_id: int,
        provider_runner_name: str,
    ) -> tuple[dict[str, Any], bool]:
        """Commit an exact canary dispatch intent before any provider action.

        Only allowlisted identity fields are accepted, so registration tokens,
        credentials and raw provider responses cannot enter this ledger.  The
        boolean result is ``True`` only for an exact idempotent replay.
        """

        if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(operation_id):
            raise ValueError("worker recovery canary operation identity is invalid")
        dispatch_correlation = _worker_recovery_dispatch_correlation(operation_id)
        temporary_label = _worker_recovery_temporary_label(operation_id)
        temporary_labels = (temporary_label,)
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                recovery = connection.execute(
                    "SELECT * FROM worker_recoveries WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
                if (
                    recovery is None
                    or recovery["state"] != "completed"
                    or recovery["native_outcome"] != "completed"
                ):
                    raise ValueError("worker recovery is not ready for canary dispatch")
                try:
                    permanent_labels = tuple(json.loads(str(recovery["labels_json"])))
                except (TypeError, json.JSONDecodeError) as error:
                    raise ValueError("worker recovery durable binding is invalid") from error
                self._validate_worker_recovery_canary_identity(
                    operation_id=operation_id,
                    worker_name=str(recovery["worker_name"]),
                    repository=repository,
                    workflow=workflow,
                    ref=ref,
                    head_sha=head_sha,
                    baseline_run_id=baseline_run_id,
                    provider_runner_id=provider_runner_id,
                    provider_runner_name=provider_runner_name,
                    permanent_labels=permanent_labels,
                    dispatch_correlation=dispatch_correlation,
                    temporary_label=temporary_label,
                )
                intent = {
                    "schema": "qdev-worker-recovery-canary-intent-v2",
                    "operation_id": operation_id,
                    "worker_name": recovery["worker_name"],
                    "repository": repository,
                    "workflow": workflow,
                    "ref": ref,
                    "head_sha": head_sha,
                    "baseline_run_id": baseline_run_id,
                    "provider_runner_id": provider_runner_id,
                    "provider_runner_name": provider_runner_name,
                    "dispatch_correlation": dispatch_correlation,
                    "temporary_label": temporary_label,
                    "temporary_labels": list(temporary_labels),
                }
                intent_digest = self._worker_recovery_canary_event_digest(intent)
                existing = connection.execute(
                    "SELECT * FROM worker_recovery_canaries WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
                if existing is not None:
                    canary = self._worker_recovery_canary_row(existing)
                    if canary["intent_digest"] != intent_digest:
                        raise ValueError(
                            "worker recovery canary operation is bound to another intent"
                        )
                    initial = dict(canary)
                    initial.update(
                        {
                            "phase": "dispatch_intent",
                            "revision": 1,
                            "run_id": None,
                            "run_attempt": None,
                            "job_id": None,
                            "dispatch_observed_label": None,
                            "run_observed_label": None,
                            "job_labels": None,
                            "job_runner_id": None,
                            "job_runner_name": None,
                            "run_status": None,
                            "conclusion": None,
                            "dispatched_at": None,
                            "completed_at": None,
                            "cleaned_at": None,
                            "accepted_at": None,
                        }
                    )
                    self._require_worker_recovery_canary_event(
                        connection,
                        initial,
                        from_phase=None,
                        require_current_tip=canary["revision"] == 1,
                    )
                    connection.execute("COMMIT")
                    return canary, True
                canary = {
                    "operation_id": operation_id,
                    "worker_name": recovery["worker_name"],
                    "repository": repository,
                    "workflow": workflow,
                    "ref": ref,
                    "head_sha": head_sha,
                    "baseline_run_id": baseline_run_id,
                    "provider_runner_id": provider_runner_id,
                    "provider_runner_name": provider_runner_name,
                    "dispatch_correlation": dispatch_correlation,
                    "temporary_label": temporary_label,
                    "temporary_labels": temporary_labels,
                    "intent_digest": intent_digest,
                    "phase": "dispatch_intent",
                    "revision": 1,
                    "run_id": None,
                    "run_attempt": None,
                    "job_id": None,
                    "dispatch_observed_label": None,
                    "run_observed_label": None,
                    "job_labels": None,
                    "job_runner_id": None,
                    "job_runner_name": None,
                    "run_status": None,
                    "conclusion": None,
                    "dispatched_at": None,
                    "completed_at": None,
                    "cleaned_at": None,
                    "accepted_at": None,
                    "created_at": now,
                    "updated_at": now,
                }
                event_payload = self._worker_recovery_canary_event_payload(
                    canary, from_phase=None, recorded_at=now
                )
                event_digest = self._worker_recovery_canary_event_digest(event_payload)
                canary["last_event_digest"] = event_digest
                connection.execute(
                    "INSERT INTO worker_recovery_canaries("
                    "operation_id,worker_name,repository,workflow,ref,head_sha,"
                    "baseline_run_id,provider_runner_id,provider_runner_name,"
                    "dispatch_correlation,temporary_label,temporary_labels_json,"
                    "intent_digest,phase,revision,run_id,run_attempt,job_id,"
                    "dispatch_observed_label,run_observed_label,job_labels_json,"
                    "job_runner_id,job_runner_name,run_status,conclusion,dispatched_at,"
                    "completed_at,cleaned_at,"
                    "accepted_at,last_event_digest,created_at,updated_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        operation_id,
                        recovery["worker_name"],
                        repository,
                        workflow,
                        ref,
                        head_sha,
                        baseline_run_id,
                        provider_runner_id,
                        provider_runner_name,
                        dispatch_correlation,
                        temporary_label,
                        json.dumps(list(temporary_labels), separators=(",", ":")),
                        intent_digest,
                        "dispatch_intent",
                        1,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        event_digest,
                        now,
                        now,
                    ),
                )
                connection.execute(
                    "INSERT INTO worker_recovery_canary_events("
                    "event_digest,operation_id,revision,from_phase,phase,event_json,"
                    "recorded_at) VALUES(?,?,?,?,?,?,?)",
                    (
                        event_digest,
                        operation_id,
                        1,
                        None,
                        "dispatch_intent",
                        json.dumps(
                            event_payload,
                            ensure_ascii=True,
                            sort_keys=True,
                            separators=(",", ":"),
                        ),
                        now,
                    ),
                )
                connection.execute("COMMIT")
                return canary, False
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _worker_recovery_canary_transition_matches(
        canary: dict[str, Any],
        *,
        phase: str,
        dispatch_correlation: str | None,
        observed_temporary_label: str | None,
        run_id: int | None,
        run_attempt: int | None,
        job_id: int | None,
        job_labels: tuple[str, ...] | None,
        job_runner_id: int | None,
        job_runner_name: str | None,
        run_status: str | None,
        conclusion: str | None,
        completed_at: float | None,
    ) -> bool:
        if phase in {"dispatched", "run_observed", "job_observed"} and (
            dispatch_correlation is None or observed_temporary_label is None
        ):
            return False
        if phase == "run_observed" and (run_id is None or run_attempt is None):
            return False
        if phase == "job_observed" and (
            job_id is None
            or job_labels is None
            or job_runner_id is None
            or job_runner_name is None
            or run_status is None
        ):
            return False
        if phase == "completed" and (
            run_status is None or conclusion is None or completed_at is None
        ):
            return False
        supplied = {
            "run_id": run_id,
            "run_attempt": run_attempt,
            "job_id": job_id,
            "job_labels": job_labels,
            "job_runner_id": job_runner_id,
            "job_runner_name": job_runner_name,
            "run_status": run_status,
            "conclusion": conclusion,
            "completed_at": completed_at,
        }
        observed_field = {
            "dispatched": "dispatch_observed_label",
            "run_observed": "run_observed_label",
        }.get(phase)
        return (
            (dispatch_correlation is None or canary["dispatch_correlation"] == dispatch_correlation)
            and (
                observed_temporary_label is None
                or (
                    observed_field is None and canary["temporary_label"] == observed_temporary_label
                )
                or (
                    observed_field is not None
                    and canary[observed_field] == observed_temporary_label
                )
            )
            and all(value is None or canary[name] == value for name, value in supplied.items())
        )

    @staticmethod
    def _validate_worker_recovery_canary_observation(
        canary: dict[str, Any],
        *,
        phase: str,
        permanent_labels: tuple[str, ...],
        native_finalized_at: float,
    ) -> None:
        if phase == "ambiguous":
            return
        expected_temporary_label = _worker_recovery_temporary_label(canary["operation_id"])
        expected_correlation = _worker_recovery_dispatch_correlation(canary["operation_id"])
        dispatched_phases = {
            "dispatched",
            "run_observed",
            "labels_pending",
            "labels_applied",
            "job_observed",
            "completed",
            "cleanup_pending",
            "cleaned",
            "accepted",
        }
        run_phases = {
            "run_observed",
            "labels_pending",
            "labels_applied",
            "job_observed",
            "completed",
            "cleanup_pending",
            "cleaned",
            "accepted",
        }
        job_phases = {
            "job_observed",
            "completed",
            "cleanup_pending",
            "cleaned",
            "accepted",
        }
        completed_phases = {"completed", "cleanup_pending", "cleaned", "accepted"}
        if (
            canary["dispatch_correlation"] != expected_correlation
            or canary["temporary_label"] != expected_temporary_label
            or canary["temporary_labels"] != (expected_temporary_label,)
        ):
            raise ValueError("worker recovery canary durable binding is invalid")
        if phase in dispatched_phases:
            try:
                dispatched_at = _finite_recovery_number(
                    canary["dispatched_at"],
                    field="worker recovery canary dispatch timestamp",
                )
            except ValueError as error:
                raise ValueError(
                    "worker recovery canary dispatch observation is invalid"
                ) from error
            if canary["dispatch_observed_label"] != expected_temporary_label:
                raise ValueError("worker recovery canary dispatch observation is invalid")
        else:
            dispatched_at = 0.0
        if phase in run_phases and (
            canary["run_observed_label"] != expected_temporary_label
            or not isinstance(canary["run_id"], int)
            or isinstance(canary["run_id"], bool)
            or canary["run_id"] <= canary["baseline_run_id"]
            or not isinstance(canary["run_attempt"], int)
            or isinstance(canary["run_attempt"], bool)
            or canary["run_attempt"] <= 0
        ):
            raise ValueError("worker recovery canary run observation is invalid")
        if phase in job_phases and (
            not isinstance(canary["job_id"], int)
            or isinstance(canary["job_id"], bool)
            or canary["job_id"] <= 0
            or canary["job_labels"] != permanent_labels + (expected_temporary_label,)
            or canary["job_runner_id"] != canary["provider_runner_id"]
            or canary["job_runner_name"] != canary["provider_runner_name"]
            or canary["run_status"] not in _WORKER_RECOVERY_CANARY_STATUSES
        ):
            raise ValueError("worker recovery canary job observation is invalid")
        if phase in completed_phases:
            try:
                completed_at = _finite_recovery_number(
                    canary["completed_at"],
                    field="worker recovery canary completion timestamp",
                )
            except ValueError as error:
                raise ValueError("worker recovery canary completion is invalid") from error
            if (
                canary["run_status"] != "completed"
                or canary["conclusion"] not in _WORKER_RECOVERY_CANARY_CONCLUSIONS
                or completed_at < dispatched_at
                or completed_at < native_finalized_at
                or completed_at > time.time()
            ):
                raise ValueError("worker recovery canary completion is invalid")
        if phase in {"cleaned", "accepted"} and canary["cleaned_at"] is None:
            raise ValueError("worker recovery canary cleanup is invalid")
        if phase == "accepted" and (
            canary["conclusion"] != "success" or canary["accepted_at"] is None
        ):
            raise ValueError("worker recovery canary acceptance is invalid")

    def _transition_worker_recovery_canary(
        self,
        connection: sqlite3.Connection,
        *,
        operation_id: str,
        expected_revision: int,
        expected_phase: str,
        phase: str,
        dispatch_correlation: str | None,
        observed_temporary_label: str | None,
        run_id: int | None,
        run_attempt: int | None,
        job_id: int | None,
        job_labels: tuple[str, ...] | None,
        job_runner_id: int | None,
        job_runner_name: str | None,
        run_status: str | None,
        conclusion: str | None,
        completed_at: float | None,
        allow_accepted: bool,
    ) -> tuple[dict[str, Any], bool]:
        row = connection.execute(
            "SELECT * FROM worker_recovery_canaries WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        if row is None:
            raise ValueError("worker recovery canary intent is missing")
        current = self._worker_recovery_canary_row(row)
        current_revision = int(current["revision"])
        if current_revision == expected_revision + 1:
            if current["phase"] != phase or not self._worker_recovery_canary_transition_matches(
                current,
                phase=phase,
                dispatch_correlation=dispatch_correlation,
                observed_temporary_label=observed_temporary_label,
                run_id=run_id,
                run_attempt=run_attempt,
                job_id=job_id,
                job_labels=job_labels,
                job_runner_id=job_runner_id,
                job_runner_name=job_runner_name,
                run_status=run_status,
                conclusion=conclusion,
                completed_at=completed_at,
            ):
                raise ValueError("worker recovery canary transition is ambiguous")
            self._require_worker_recovery_canary_event(
                connection, current, from_phase=expected_phase
            )
            return current, True
        if current_revision != expected_revision or current["phase"] != expected_phase:
            raise ValueError("worker recovery canary transition is ambiguous")
        if phase not in _WORKER_RECOVERY_CANARY_TRANSITIONS.get(expected_phase, frozenset()):
            raise ValueError("invalid worker recovery canary transition")
        if phase == "accepted" and not allow_accepted:
            raise ValueError("worker recovery canary acceptance is controller-owned")

        recovery = connection.execute(
            "SELECT labels_json,native_finalized_at FROM worker_recoveries WHERE operation_id=?",
            (operation_id,),
        ).fetchone()
        try:
            if recovery is None:
                raise ValueError
            permanent_labels_value = json.loads(str(recovery["labels_json"]))
            permanent_labels = tuple(permanent_labels_value)
            native_finalized_at = _finite_recovery_number(
                recovery["native_finalized_at"],
                field="native recovery finalization timestamp",
            )
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("worker recovery durable binding is invalid") from error

        if phase in {"dispatched", "run_observed", "job_observed"} and (
            dispatch_correlation != current["dispatch_correlation"]
            or observed_temporary_label != current["temporary_label"]
        ):
            raise ValueError("worker recovery canary provider binding is invalid")
        unexpected_evidence = {
            "dispatching": (
                dispatch_correlation,
                observed_temporary_label,
                run_id,
                run_attempt,
                job_id,
                job_labels,
                job_runner_id,
                job_runner_name,
                run_status,
                conclusion,
                completed_at,
            ),
            "labels_pending": (
                dispatch_correlation,
                observed_temporary_label,
                run_id,
                run_attempt,
                job_id,
                job_labels,
                job_runner_id,
                job_runner_name,
                run_status,
                conclusion,
                completed_at,
            ),
            "labels_applied": (
                dispatch_correlation,
                observed_temporary_label,
                run_id,
                run_attempt,
                job_id,
                job_labels,
                job_runner_id,
                job_runner_name,
                run_status,
                conclusion,
                completed_at,
            ),
            "cleanup_pending": (
                dispatch_correlation,
                observed_temporary_label,
                run_id,
                run_attempt,
                job_id,
                job_labels,
                job_runner_id,
                job_runner_name,
                run_status,
                conclusion,
                completed_at,
            ),
            "cleaned": (
                dispatch_correlation,
                observed_temporary_label,
                run_id,
                run_attempt,
                job_id,
                job_labels,
                job_runner_id,
                job_runner_name,
                run_status,
                conclusion,
                completed_at,
            ),
            "accepted": (
                dispatch_correlation,
                observed_temporary_label,
                run_id,
                run_attempt,
                job_id,
                job_labels,
                job_runner_id,
                job_runner_name,
                run_status,
                conclusion,
                completed_at,
            ),
            "ambiguous": (
                dispatch_correlation,
                observed_temporary_label,
                run_id,
                run_attempt,
                job_id,
                job_labels,
                job_runner_id,
                job_runner_name,
                run_status,
                conclusion,
                completed_at,
            ),
        }.get(phase)
        if unexpected_evidence is not None and any(
            value is not None for value in unexpected_evidence
        ):
            raise ValueError("worker recovery canary transition has unexpected evidence")

        if phase == "dispatched":
            current["dispatch_observed_label"] = observed_temporary_label
        elif phase == "run_observed":
            current["run_observed_label"] = observed_temporary_label
        elif phase == "job_observed":
            current["job_labels"] = job_labels
            current["job_runner_id"] = job_runner_id
            current["job_runner_name"] = job_runner_name

        for name, supplied in (
            ("run_id", run_id),
            ("run_attempt", run_attempt),
            ("job_id", job_id),
            ("conclusion", conclusion),
        ):
            if supplied is not None and current[name] not in {None, supplied}:
                raise ValueError("worker recovery canary observation changed")
            if supplied is not None:
                current[name] = supplied
        if run_status is not None:
            if run_status not in _WORKER_RECOVERY_CANARY_STATUSES or (
                current["run_status"] == "completed" and run_status != "completed"
            ):
                raise ValueError("worker recovery canary status changed")
            current["run_status"] = run_status
        if conclusion is not None and conclusion not in _WORKER_RECOVERY_CANARY_CONCLUSIONS:
            raise ValueError("worker recovery canary conclusion is invalid")
        now = time.time()
        current["phase"] = phase
        current["revision"] = current_revision + 1
        current["updated_at"] = now
        if phase == "dispatched" and current["dispatched_at"] is None:
            current["dispatched_at"] = now
        if phase == "completed":
            if completed_at is None:
                raise ValueError("provider canary completion timestamp is required")
            current["completed_at"] = completed_at
        if phase == "cleaned" and current["cleaned_at"] is None:
            current["cleaned_at"] = now
        if phase == "accepted" and current["accepted_at"] is None:
            current["accepted_at"] = now
        self._validate_worker_recovery_canary_observation(
            current,
            phase=phase,
            permanent_labels=permanent_labels,
            native_finalized_at=native_finalized_at,
        )
        event_payload = self._worker_recovery_canary_event_payload(
            current, from_phase=expected_phase, recorded_at=now
        )
        event_digest = self._worker_recovery_canary_event_digest(event_payload)
        updated = connection.execute(
            "UPDATE worker_recovery_canaries SET phase=?,revision=?,run_id=?,"
            "run_attempt=?,job_id=?,dispatch_observed_label=?,run_observed_label=?,"
            "job_labels_json=?,job_runner_id=?,job_runner_name=?,run_status=?,"
            "conclusion=?,dispatched_at=?,completed_at=?,"
            "cleaned_at=?,accepted_at=?,last_event_digest=?,updated_at=? "
            "WHERE operation_id=? AND revision=? AND phase=?",
            (
                phase,
                current["revision"],
                current["run_id"],
                current["run_attempt"],
                current["job_id"],
                current["dispatch_observed_label"],
                current["run_observed_label"],
                None
                if current["job_labels"] is None
                else json.dumps(list(current["job_labels"]), separators=(",", ":")),
                current["job_runner_id"],
                current["job_runner_name"],
                current["run_status"],
                current["conclusion"],
                current["dispatched_at"],
                current["completed_at"],
                current["cleaned_at"],
                current["accepted_at"],
                event_digest,
                now,
                operation_id,
                expected_revision,
                expected_phase,
            ),
        )
        if updated.rowcount != 1:
            raise ValueError("worker recovery canary transition is ambiguous")
        connection.execute(
            "INSERT INTO worker_recovery_canary_events("
            "event_digest,operation_id,revision,from_phase,phase,event_json,recorded_at) "
            "VALUES(?,?,?,?,?,?,?)",
            (
                event_digest,
                operation_id,
                current["revision"],
                expected_phase,
                phase,
                json.dumps(
                    event_payload,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                now,
            ),
        )
        current["last_event_digest"] = event_digest
        return current, False

    def transition_worker_recovery_canary(
        self,
        *,
        operation_id: str,
        expected_revision: int,
        expected_phase: str,
        phase: str,
        dispatch_correlation: str | None = None,
        observed_temporary_label: str | None = None,
        run_id: int | None = None,
        run_attempt: int | None = None,
        job_id: int | None = None,
        job_labels: tuple[str, ...] | None = None,
        job_runner_id: int | None = None,
        job_runner_name: str | None = None,
        run_status: str | None = None,
        conclusion: str | None = None,
        completed_at: float | None = None,
    ) -> tuple[dict[str, Any], bool]:
        """CAS one durable canary phase; exact replay is explicitly reported."""

        if (
            not isinstance(operation_id, str)
            or not _SHA256_HEX.fullmatch(operation_id)
            or isinstance(expected_revision, bool)
            or not isinstance(expected_revision, int)
            or expected_revision <= 0
            or expected_phase not in _WORKER_RECOVERY_CANARY_PHASES
            or phase not in _WORKER_RECOVERY_CANARY_PHASES
        ):
            raise ValueError("worker recovery canary transition binding is invalid")
        for value in (run_id, run_attempt, job_id, job_runner_id):
            if value is not None and (
                isinstance(value, bool) or not isinstance(value, int) or value <= 0
            ):
                raise ValueError("worker recovery canary observation is invalid")
        if run_status is not None and run_status not in _WORKER_RECOVERY_CANARY_STATUSES:
            raise ValueError("worker recovery canary status is invalid")
        if conclusion is not None and conclusion not in _WORKER_RECOVERY_CANARY_CONCLUSIONS:
            raise ValueError("worker recovery canary conclusion is invalid")
        if dispatch_correlation is not None and (
            not isinstance(dispatch_correlation, str)
            or not _RECOVERY_KEY.fullmatch(dispatch_correlation)
        ):
            raise ValueError("worker recovery canary correlation is invalid")
        if observed_temporary_label is not None and (
            not isinstance(observed_temporary_label, str)
            or _RUNNER_LABEL.fullmatch(observed_temporary_label) is None
        ):
            raise ValueError("worker recovery canary label is invalid")
        if job_labels is not None and (
            not isinstance(job_labels, tuple)
            or not job_labels
            or any(
                not isinstance(label, str) or _RUNNER_LABEL.fullmatch(label) is None
                for label in job_labels
            )
            or len({label.lower() for label in job_labels}) != len(job_labels)
        ):
            raise ValueError("worker recovery canary job labels are invalid")
        if job_runner_name is not None and (
            not isinstance(job_runner_name, str) or job_runner_name not in _WORKER_RECOVERY_BINDINGS
        ):
            raise ValueError("worker recovery canary job runner is invalid")
        if completed_at is not None:
            completed_at = _finite_recovery_number(
                completed_at, field="worker recovery canary completion timestamp"
            )
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                result = self._transition_worker_recovery_canary(
                    connection,
                    operation_id=operation_id,
                    expected_revision=expected_revision,
                    expected_phase=expected_phase,
                    phase=phase,
                    dispatch_correlation=dispatch_correlation,
                    observed_temporary_label=observed_temporary_label,
                    run_id=run_id,
                    run_attempt=run_attempt,
                    job_id=job_id,
                    job_labels=job_labels,
                    job_runner_id=job_runner_id,
                    job_runner_name=job_runner_name,
                    run_status=run_status,
                    conclusion=conclusion,
                    completed_at=completed_at,
                    allow_accepted=False,
                )
                connection.execute("COMMIT")
                return result
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def claim_worker_recovery_canary_dispatch(
        self, *, operation_id: str, expected_revision: int
    ) -> tuple[dict[str, Any], bool]:
        """Fence the dispatch ambiguity window before calling the provider.

        The boolean is ``True`` only for the process that acquired permission
        to make the provider call.  Exact replays return ``False`` and must
        reconcile the in-flight dispatch instead of dispatching again.
        """

        canary, idempotent = self.transition_worker_recovery_canary(
            operation_id=operation_id,
            expected_revision=expected_revision,
            expected_phase="dispatch_intent",
            phase="dispatching",
        )
        return canary, not idempotent

    def worker_recovery_canary(self, operation_id: str) -> dict[str, Any] | None:
        if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(operation_id):
            raise ValueError("worker recovery canary operation identity is invalid")
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM worker_recovery_canaries WHERE operation_id=?",
                (operation_id,),
            ).fetchone()
        return self._worker_recovery_canary_row(row) if row is not None else None

    def worker_recovery_canary_events(self, operation_id: str) -> list[dict[str, Any]]:
        if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(operation_id):
            raise ValueError("worker recovery canary operation identity is invalid")
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM worker_recovery_canary_events WHERE operation_id=? "
                "ORDER BY revision",
                (operation_id,),
            ).fetchall()
        events: list[dict[str, Any]] = []
        for row in rows:
            value = dict(row)
            try:
                value["event"] = json.loads(str(value.pop("event_json")))
            except (TypeError, json.JSONDecodeError) as error:
                raise ValueError("worker recovery canary event history is invalid") from error
            events.append(value)
        return events

    @staticmethod
    def _require_worker_recovery_canary_acceptance(
        connection: sqlite3.Connection,
        recovery: sqlite3.Row,
        accepted: dict[str, Any],
        *,
        phase: str,
    ) -> dict[str, Any]:
        row = connection.execute(
            "SELECT * FROM worker_recovery_canaries WHERE operation_id=?",
            (recovery["operation_id"],),
        ).fetchone()
        if row is None:
            raise ValueError("worker recovery canary durable proof is missing")
        canary = Store._worker_recovery_canary_row(row)
        try:
            permanent_labels_value = json.loads(str(recovery["labels_json"]))
            permanent_labels = tuple(permanent_labels_value)
            native_finalized_at = _finite_recovery_number(
                recovery["native_finalized_at"],
                field="native recovery finalization timestamp",
            )
            dispatched_at = _finite_recovery_number(
                canary["dispatched_at"],
                field="worker recovery canary dispatch timestamp",
            )
            completed_at = _finite_recovery_number(
                canary["completed_at"],
                field="worker recovery canary completion timestamp",
            )
            cleaned_at = _finite_recovery_number(
                canary["cleaned_at"],
                field="worker recovery canary cleanup timestamp",
            )
            observed_at = _finite_recovery_number(
                accepted["observed_at"],
                field="worker recovery acceptance timestamp",
            )
            canary_observation = {
                "repository": accepted["canary_repository"],
                "workflow": accepted["canary_workflow"],
                "ref": accepted["canary_ref"],
                "head_sha": accepted["canary_head_sha"],
                "dispatch_correlation": accepted["canary_dispatch_correlation"],
                "temporary_label": accepted["canary_temporary_label"],
                "dispatch_observed_label": accepted["canary_dispatch_observed_label"],
                "run_observed_label": accepted["canary_run_observed_label"],
                "baseline_run_id": accepted["canary_baseline_run_id"],
                "run_id": accepted["canary_run_id"],
                "run_attempt": accepted["canary_run_attempt"],
                "job_id": accepted["canary_job_id"],
                "job_labels": accepted["canary_job_labels"],
                "job_runner_id": accepted["canary_job_runner_id"],
                "job_runner_name": accepted["canary_job_runner_name"],
                "status": accepted["canary_status"],
                "conclusion": accepted["canary_conclusion"],
                "completed_at": completed_at,
            }
            provider_observation, _, provider_reconciliation_digest = (
                _validate_provider_observation(
                    accepted["provider_observation"],
                    schema="qdev-worker-recovery-provider-observation-v1",
                    repository=str(recovery["repository"]),
                    worker_name=str(recovery["worker_name"]),
                    provider_runner_id=int(accepted["provider_runner_id"]),
                    provider_status="online",
                    provider_busy=False,
                    labels=permanent_labels,
                    canary=canary_observation,
                )
            )
            observed_runners = _provider_runner_observations(provider_observation)
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as error:
            raise ValueError("worker recovery canary durable proof is invalid") from error
        if (
            not permanent_labels
            or any(not isinstance(label, str) or not label for label in permanent_labels)
            or len(set(permanent_labels)) != len(permanent_labels)
            or canary["phase"] != phase
            or canary["worker_name"] != recovery["worker_name"]
            or canary["repository"] != recovery["repository"]
            or canary["workflow"] != accepted["canary_workflow"]
            or canary["ref"] != accepted["canary_ref"]
            or canary["head_sha"] != accepted["canary_head_sha"]
            or canary["provider_runner_id"] != accepted["provider_runner_id"]
            or canary["provider_runner_name"] != accepted["canary_runner_name"]
            or canary["dispatch_correlation"] != accepted["canary_dispatch_correlation"]
            or canary["temporary_label"] != accepted["canary_temporary_label"]
            or canary["dispatch_observed_label"] != accepted["canary_dispatch_observed_label"]
            or canary["run_observed_label"] != accepted["canary_run_observed_label"]
            or canary["baseline_run_id"] != accepted["canary_baseline_run_id"]
            or canary["run_id"] != accepted["canary_run_id"]
            or canary["run_attempt"] != accepted["canary_run_attempt"]
            or canary["job_id"] != accepted["canary_job_id"]
            or list(canary["job_labels"] or ()) != accepted["canary_job_labels"]
            or canary["job_runner_id"] != accepted["canary_job_runner_id"]
            or canary["job_runner_name"] != accepted["canary_job_runner_name"]
            or canary["run_status"] != accepted["canary_status"]
            or canary["conclusion"] != accepted["canary_conclusion"]
            or completed_at != accepted["canary_completed_at"]
            or accepted["provider_reconciliation_digest"] != provider_reconciliation_digest
            or (
                accepted["prior_provider_runner_disposition"] == "absent"
                and any(
                    runner["id"] == recovery["provider_runner_id"] for runner in observed_runners
                )
            )
            or dispatched_at > completed_at
            or native_finalized_at > completed_at
            or completed_at > cleaned_at
            or cleaned_at > observed_at
        ):
            raise ValueError("worker recovery acceptance is not bound to the durable canary")
        Store._validate_worker_recovery_canary_observation(
            canary,
            phase=phase,
            permanent_labels=permanent_labels,
            native_finalized_at=native_finalized_at,
        )
        Store._require_worker_recovery_canary_event(
            connection,
            canary,
            from_phase="cleanup_pending" if phase == "cleaned" else "cleaned",
        )
        return canary

    @staticmethod
    def _worker_recovery_projection(
        connection: sqlite3.Connection, *, column: str, value: str
    ) -> sqlite3.Row | None:
        if column == "operation_id":
            predicate = "WHERE wr.operation_id=?"
        elif column == "idempotency_key":
            predicate = "WHERE wr.idempotency_key=?"
        else:
            raise ValueError("native recovery lookup is invalid")
        query = (
            """
            SELECT
                wr.*,
                wa.receipt_digest AS abort_receipt_digest,
                wa.signature AS abort_signature,
                wa.reason AS abort_reason,
                wa.abort_controller_revision,
                wa.abort_controller_release_digest,
                wa.provider_idle_proof_digest AS abort_provider_idle_proof_digest,
                wa.provider_reconciliation_digest AS abort_provider_reconciliation_digest,
                wa.provider_observation_json AS abort_provider_observation_json,
                wa.provider_observed_at AS abort_provider_observed_at,
                wa.aborted_at
            FROM worker_recoveries AS wr
            LEFT JOIN worker_recovery_aborts AS wa ON wa.operation_id=wr.operation_id
            """
            + predicate
        )
        return cast(sqlite3.Row | None, connection.execute(query, (value,)).fetchone())

    def worker_recovery(self, operation_id: str) -> dict[str, Any] | None:
        if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(operation_id):
            raise ValueError("native recovery operation identity is invalid")
        with self.connect() as connection:
            row = self._worker_recovery_projection(
                connection, column="operation_id", value=operation_id
            )
        return dict(row) if row is not None else None

    def worker_recovery_by_idempotency_key(self, idempotency_key: str) -> dict[str, Any] | None:
        """Return the exact durable operation after a lost prepare response."""

        if not isinstance(idempotency_key, str) or not _RECOVERY_KEY.fullmatch(idempotency_key):
            raise ValueError("worker recovery idempotency key is invalid")
        with self.connect() as connection:
            row = self._worker_recovery_projection(
                connection, column="idempotency_key", value=idempotency_key
            )
        return dict(row) if row is not None else None

    def abort_worker_recovery(
        self,
        *,
        operation_id: str,
        request_fingerprint: str,
        operator_certificate_sha256: str,
        abort_controller_revision: str,
        abort_controller_release_digest: str,
        policy_digest: str,
        agent_release_digest: str,
        provider_idle_proof: dict[str, Any],
        provider_proof_key: str,
        reason: str,
        proof_max_age_seconds: float = 120.0,
    ) -> dict[str, Any]:
        """Atomically release one never-invoked fence with an append-only receipt."""

        normalized_reason = reason.strip() if isinstance(reason, str) else ""
        if (
            not isinstance(operation_id, str)
            or not _SHA256_HEX.fullmatch(operation_id)
            or not isinstance(request_fingerprint, str)
            or not _SHA256_HEX.fullmatch(request_fingerprint)
            or not isinstance(operator_certificate_sha256, str)
            or not _SHA256_HEX.fullmatch(operator_certificate_sha256)
            or not isinstance(abort_controller_revision, str)
            or not _GIT_REVISION.fullmatch(abort_controller_revision)
            or not isinstance(abort_controller_release_digest, str)
            or not _SHA256_HEX.fullmatch(abort_controller_release_digest)
            or not isinstance(policy_digest, str)
            or not _SHA256_DIGEST.fullmatch(policy_digest)
            or not isinstance(agent_release_digest, str)
            or not _SHA256_DIGEST.fullmatch(agent_release_digest)
            or normalized_reason != reason
            or not 8 <= len(normalized_reason) <= 500
            or not isinstance(provider_proof_key, str)
            or not provider_proof_key
        ):
            raise ValueError("worker recovery abort binding is invalid")
        proof_max_age_seconds = _recovery_proof_window(proof_max_age_seconds)

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                recovery = connection.execute(
                    "SELECT * FROM worker_recoveries WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
                if recovery is None:
                    raise ValueError("worker recovery transaction changed")
                labels = tuple(json.loads(str(recovery["labels_json"])))
                target = _WORKER_RECOVERY_BINDINGS.get(str(recovery["worker_name"]))
                if (
                    target is None
                    or target["repository"] != recovery["repository"]
                    or target["labels"] != labels
                    or target["recovery_action"] != recovery["recovery_action"]
                    or recovery["request_fingerprint"] != request_fingerprint
                    or recovery["operator_certificate_sha256"]
                    != operator_certificate_sha256
                ):
                    raise ValueError("worker recovery abort binding changed")

                existing = connection.execute(
                    "SELECT * FROM worker_recovery_aborts WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
                if existing is not None:
                    if (
                        recovery["state"] != "released"
                        or existing["request_fingerprint"] != request_fingerprint
                        or existing["operator_certificate_sha256"]
                        != operator_certificate_sha256
                        or existing["abort_controller_revision"]
                        != abort_controller_revision
                        or existing["abort_controller_release_digest"]
                        != abort_controller_release_digest
                        or existing["policy_digest"] != policy_digest
                        or existing["agent_release_digest"] != agent_release_digest
                        or existing["reason"] != normalized_reason
                    ):
                        raise ValueError("worker recovery abort replay changed")
                    replay = self._worker_recovery_projection(
                        connection, column="operation_id", value=operation_id
                    )
                    if replay is None:
                        raise ValueError("worker recovery transaction changed")
                    connection.execute("COMMIT")
                    row = dict(replay)
                    row["abort_idempotent_replay"] = True
                    return row

                provider = self.verify_worker_provider_idle_proof(
                    provider_idle_proof,
                    key=provider_proof_key,
                    worker_name=str(recovery["worker_name"]),
                    repository=str(recovery["repository"]),
                    labels=labels,
                    max_age_seconds=proof_max_age_seconds,
                )
                _, provider_observation_json, _ = _canonical_provider_observation(
                    provider["provider_observation"]
                )
                if (
                    recovery["state"] != "prepared"
                    or recovery["invoked_at"] is not None
                    or recovery["native_outcome"] is not None
                    or recovery["native_outcome_digest"] is not None
                    or recovery["native_outcome_signature"] is not None
                    or recovery["agent_identity"] is not None
                    or recovery["agent_certificate_sha256"] is not None
                    or recovery["reconciled_at"] is not None
                    or recovery["native_finalized_at"] is not None
                    or recovery["acceptance_proof_digest"] is not None
                    or recovery["canary_run_id"] is not None
                    or connection.execute(
                        "SELECT 1 FROM worker_recovery_outcomes WHERE operation_id=?",
                        (operation_id,),
                    ).fetchone()
                    is not None
                    or connection.execute(
                        "SELECT 1 FROM worker_recovery_acceptances WHERE operation_id=?",
                        (operation_id,),
                    ).fetchone()
                    is not None
                    or connection.execute(
                        "SELECT 1 FROM worker_recovery_canaries WHERE operation_id=?",
                        (operation_id,),
                    ).fetchone()
                    is not None
                ):
                    raise ValueError("worker recovery operation cannot be aborted")
                self._require_no_durable_worker_work(
                    connection, str(recovery["worker_name"])
                )
                aborted_at = time.time()
                payload = {
                    "schema": "qdev-worker-recovery-abort-receipt-v1",
                    "operation_id": operation_id,
                    "worker_name": recovery["worker_name"],
                    "repository": recovery["repository"],
                    "request_fingerprint": request_fingerprint,
                    "operator_certificate_sha256": operator_certificate_sha256,
                    "original_controller_revision": recovery["controller_revision"],
                    "original_controller_release_digest": recovery[
                        "controller_release_digest"
                    ],
                    "abort_controller_revision": abort_controller_revision,
                    "abort_controller_release_digest": abort_controller_release_digest,
                    "policy_digest": policy_digest,
                    "agent_release_digest": agent_release_digest,
                    "provider_idle_proof_digest": provider["digest"],
                    "provider_reconciliation_digest": provider[
                        "provider_reconciliation_digest"
                    ],
                    "provider_observation": provider["provider_observation"],
                    "reason": normalized_reason,
                    "provider_observed_at": provider["observed_at"],
                    "aborted_at": aborted_at,
                }
                canonical = json.dumps(
                    payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                ).encode("utf-8")
                receipt_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
                signature = hmac.new(
                    provider_proof_key.encode("utf-8"), canonical, hashlib.sha256
                ).hexdigest()
                connection.execute(
                    """
                    INSERT INTO worker_recovery_aborts(
                        receipt_digest,operation_id,worker_name,repository,
                        request_fingerprint,operator_certificate_sha256,
                        original_controller_revision,original_controller_release_digest,
                        abort_controller_revision,abort_controller_release_digest,
                        policy_digest,agent_release_digest,provider_idle_proof_digest,
                        provider_reconciliation_digest,provider_observation_json,reason,
                        signature,provider_observed_at,aborted_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        receipt_digest,
                        operation_id,
                        recovery["worker_name"],
                        recovery["repository"],
                        request_fingerprint,
                        operator_certificate_sha256,
                        recovery["controller_revision"],
                        recovery["controller_release_digest"],
                        abort_controller_revision,
                        abort_controller_release_digest,
                        policy_digest,
                        agent_release_digest,
                        provider["digest"],
                        provider["provider_reconciliation_digest"],
                        provider_observation_json,
                        normalized_reason,
                        signature,
                        provider["observed_at"],
                        aborted_at,
                    ),
                )
                updated = connection.execute(
                    """
                    UPDATE worker_recoveries
                    SET state='released', updated_at=?, released_at=?
                    WHERE operation_id=? AND state='prepared' AND invoked_at IS NULL
                    """,
                    (aborted_at, aborted_at, operation_id),
                )
                if updated.rowcount != 1:
                    raise ValueError("worker recovery transaction changed")
                connection.execute("COMMIT")
            except BaseException:
                connection.execute("ROLLBACK")
                raise
        result = self.worker_recovery(operation_id)
        assert result is not None
        result["abort_idempotent_replay"] = False
        return result

    def prepared_worker_recovery(self, worker_name: str) -> dict[str, Any] | None:
        if not isinstance(worker_name, str) or worker_name not in _WORKER_RECOVERY_BINDINGS:
            raise ValueError("worker recovery target is not registered")
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM worker_recoveries WHERE worker_name=? AND state='prepared'",
                (worker_name,),
            ).fetchone()
        return dict(row) if row is not None else None

    def advance_worker_recovery(
        self,
        idempotency_key: str,
        *,
        expected: str,
        state: str,
        acceptance_proof: dict[str, Any] | None = None,
        acceptance_proof_key: str | None = None,
        proof_max_age_seconds: float = 120.0,
    ) -> dict[str, Any]:
        if not isinstance(idempotency_key, str) or not _RECOVERY_KEY.fullmatch(idempotency_key):
            raise ValueError("worker recovery idempotency key is invalid")
        if (expected, state) not in {
            ("prepared", "invoking"),
            ("prepared", "released"),
            ("completed", "released"),
        }:
            raise ValueError("invalid worker recovery transition")
        proof_max_age_seconds = _recovery_proof_window(proof_max_age_seconds)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM worker_recoveries WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()
                if row is None:
                    raise ValueError("worker recovery transaction changed")
                labels = tuple(json.loads(str(row["labels_json"])))
                if (
                    not labels
                    or any(not isinstance(label, str) or not label for label in labels)
                    or len(set(labels)) != len(labels)
                ):
                    raise ValueError("worker recovery durable binding is invalid")
                # A lost accept response may be replayed long after the proof's
                # freshness window.  Verify the exact signed proof and compare
                # it with the already-persisted acceptance without re-running
                # provider observation or agent mutation.
                if row["state"] == "released" and (expected, state) == ("completed", "released"):
                    if (
                        row["native_outcome"] != "completed"
                        or acceptance_proof is None
                        or not isinstance(acceptance_proof_key, str)
                        or not acceptance_proof_key
                    ):
                        raise ValueError("worker recovery transaction changed")
                    accepted = self.verify_worker_recovery_acceptance_proof(
                        acceptance_proof,
                        key=acceptance_proof_key,
                        operation_id=str(row["operation_id"]),
                        worker_name=str(row["worker_name"]),
                        repository=str(row["repository"]),
                        labels=labels,
                        prior_provider_runner_id=(
                            None
                            if row["provider_runner_id"] is None
                            else int(row["provider_runner_id"])
                        ),
                        recovery_action=str(row["recovery_action"]),
                        native_finalized_at=float(row["native_finalized_at"]),
                        max_age_seconds=None,
                    )
                    acceptance_row = connection.execute(
                        "SELECT * FROM worker_recovery_acceptances WHERE operation_id=?",
                        (row["operation_id"],),
                    ).fetchone()
                    _, provider_observation_json, _ = _canonical_provider_observation(
                        accepted["provider_observation"]
                    )
                    if (
                        acceptance_row is None
                        or row["acceptance_proof_digest"] != accepted["digest"]
                        or row["acceptance_proof_signature"] != accepted["signature"]
                        or row["accepted_provider_runner_id"] != accepted["provider_runner_id"]
                        or acceptance_row["proof_digest"] != accepted["digest"]
                        or acceptance_row["signature"] != accepted["signature"]
                        or acceptance_row["provider_reconciliation_digest"]
                        != accepted["provider_reconciliation_digest"]
                        or acceptance_row["provider_observation_json"] != provider_observation_json
                        or acceptance_row["canary_run_id"] != accepted["canary_run_id"]
                        or acceptance_row["canary_run_attempt"] != accepted["canary_run_attempt"]
                        or acceptance_row["canary_job_id"] != accepted["canary_job_id"]
                        or acceptance_row["canary_runner_id"] != accepted["canary_runner_id"]
                        or acceptance_row["canary_completed_at"] != accepted["canary_completed_at"]
                    ):
                        raise ValueError("worker recovery acceptance is bound to another proof")
                    self._require_worker_recovery_canary_acceptance(
                        connection, row, accepted, phase="accepted"
                    )
                    connection.execute("COMMIT")
                    return dict(row)
                if row["state"] != expected:
                    raise ValueError("worker recovery transaction changed")
                now = time.time()
                if state == "invoking":
                    try:
                        controller_observed_at = _finite_recovery_number(
                            row["controller_observed_at"],
                            field="worker recovery controller timestamp",
                        )
                        requested_at = _finite_recovery_number(
                            row["requested_at"],
                            field="worker recovery request timestamp",
                        )
                        provider_observed_at = _finite_recovery_number(
                            row["provider_observed_at"],
                            field="worker recovery provider timestamp",
                        )
                    except ValueError as error:
                        raise ValueError("worker recovery durable binding is invalid") from error
                    if any(
                        not 0 <= now - timestamp <= proof_max_age_seconds
                        for timestamp in (
                            controller_observed_at,
                            requested_at,
                            provider_observed_at,
                        )
                    ):
                        raise ValueError("worker recovery evidence expired before invocation")
                    self._require_no_durable_worker_work(connection, str(row["worker_name"]))
                elif (expected, state) == ("completed", "released"):
                    if (
                        row["native_outcome"] != "completed"
                        or not isinstance(row["native_outcome_digest"], str)
                        or not _SHA256_DIGEST.fullmatch(row["native_outcome_digest"])
                        or not isinstance(row["agent_certificate_sha256"], str)
                        or not _SHA256_HEX.fullmatch(row["agent_certificate_sha256"])
                        or not isinstance(row["native_outcome_signature"], str)
                        or not _SHA256_HEX.fullmatch(row["native_outcome_signature"])
                        or row["reconciled_at"] is None
                        or row["native_finalized_at"] is None
                    ):
                        raise ValueError("worker recovery has no signed completed native outcome")
                    if (
                        acceptance_proof is None
                        or not isinstance(acceptance_proof_key, str)
                        or not acceptance_proof_key
                    ):
                        raise ValueError("worker recovery acceptance proof is required")
                    accepted = self.verify_worker_recovery_acceptance_proof(
                        acceptance_proof,
                        key=acceptance_proof_key,
                        operation_id=str(row["operation_id"]),
                        worker_name=str(row["worker_name"]),
                        repository=str(row["repository"]),
                        labels=labels,
                        prior_provider_runner_id=(
                            None
                            if row["provider_runner_id"] is None
                            else int(row["provider_runner_id"])
                        ),
                        recovery_action=str(row["recovery_action"]),
                        native_finalized_at=float(row["native_finalized_at"]),
                        max_age_seconds=proof_max_age_seconds,
                    )
                    self._require_no_durable_worker_work(connection, str(row["worker_name"]))
                    canary = self._require_worker_recovery_canary_acceptance(
                        connection, row, accepted, phase="cleaned"
                    )
                    self._transition_worker_recovery_canary(
                        connection,
                        operation_id=str(row["operation_id"]),
                        expected_revision=int(canary["revision"]),
                        expected_phase="cleaned",
                        phase="accepted",
                        dispatch_correlation=None,
                        observed_temporary_label=None,
                        run_id=None,
                        run_attempt=None,
                        job_id=None,
                        job_labels=None,
                        job_runner_id=None,
                        job_runner_name=None,
                        run_status=None,
                        conclusion=None,
                        completed_at=None,
                        allow_accepted=True,
                    )
                    _, provider_observation_json, _ = _canonical_provider_observation(
                        accepted["provider_observation"]
                    )
                    connection.execute(
                        "INSERT INTO worker_recovery_acceptances("
                        "proof_digest,operation_id,worker_name,repository,labels_json,"
                        "prior_provider_runner_id,prior_provider_runner_disposition,"
                        "provider_runner_id,matching_runner_count,"
                        "provider_reconciliation_digest,provider_observation_json,"
                        "provider_observed_at,"
                        "canary_repository,canary_workflow,canary_ref,canary_head_sha,"
                        "canary_run_id,canary_run_attempt,canary_job_id,canary_runner_id,"
                        "canary_status,canary_conclusion,canary_completed_at,signature,"
                        "accepted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                        (
                            accepted["digest"],
                            row["operation_id"],
                            row["worker_name"],
                            row["repository"],
                            row["labels_json"],
                            accepted["prior_provider_runner_id"],
                            accepted["prior_provider_runner_disposition"],
                            accepted["provider_runner_id"],
                            accepted["matching_runner_count"],
                            accepted["provider_reconciliation_digest"],
                            provider_observation_json,
                            accepted["observed_at"],
                            accepted["canary_repository"],
                            accepted["canary_workflow"],
                            accepted["canary_ref"],
                            accepted["canary_head_sha"],
                            accepted["canary_run_id"],
                            accepted["canary_run_attempt"],
                            accepted["canary_job_id"],
                            accepted["canary_runner_id"],
                            accepted["canary_status"],
                            accepted["canary_conclusion"],
                            accepted["canary_completed_at"],
                            accepted["signature"],
                            now,
                        ),
                    )
                invoked_at = now if state == "invoking" else row["invoked_at"]
                if (expected, state) == ("completed", "released"):
                    connection.execute(
                        "UPDATE worker_recoveries SET state=?,invoked_at=?,updated_at=?,"
                        "accepted_provider_runner_id=?,acceptance_proof_digest=?,"
                        "acceptance_proof_signature=?,acceptance_reconciliation_digest=?,"
                        "acceptance_observed_at=?,canary_repository=?,canary_workflow=?,"
                        "canary_ref=?,canary_run_id=?,canary_job_id=?,canary_attempt=?,"
                        "canary_head_sha=?,canary_runner_id=?,canary_status=?,"
                        "canary_conclusion=?,canary_completed_at=?,released_at=? "
                        "WHERE idempotency_key=?",
                        (
                            state,
                            invoked_at,
                            now,
                            accepted["provider_runner_id"],
                            accepted["digest"],
                            accepted["signature"],
                            accepted["provider_reconciliation_digest"],
                            accepted["observed_at"],
                            accepted["canary_repository"],
                            accepted["canary_workflow"],
                            accepted["canary_ref"],
                            accepted["canary_run_id"],
                            accepted["canary_job_id"],
                            accepted["canary_run_attempt"],
                            accepted["canary_head_sha"],
                            accepted["canary_runner_id"],
                            accepted["canary_status"],
                            accepted["canary_conclusion"],
                            accepted["canary_completed_at"],
                            now,
                            idempotency_key,
                        ),
                    )
                else:
                    connection.execute(
                        "UPDATE worker_recoveries SET state=?,invoked_at=?,updated_at=?,"
                        "released_at=? WHERE idempotency_key=?",
                        (
                            state,
                            invoked_at,
                            now,
                            now if state == "released" else row["released_at"],
                            idempotency_key,
                        ),
                    )
                updated = connection.execute(
                    "SELECT * FROM worker_recoveries WHERE idempotency_key=?",
                    (idempotency_key,),
                ).fetchone()
                connection.execute("COMMIT")
                assert updated is not None
                return dict(updated)
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def reconcile_worker_recovery(
        self,
        *,
        operation_id: str,
        worker_name: str,
        request_fingerprint: str,
        recovery_action: str,
        request_nonce: str,
        provider_reconciliation_digest: str,
        agent_certificate_sha256: str,
        outcome: str,
        outcome_digest: str,
        agent_release_digest: str,
        reconciliation_key: str,
        observed_at: float | None = None,
        proof_max_age_seconds: float = 120.0,
    ) -> dict[str, Any]:
        """Append one signed native observation and perform its safe transition.

        ``not_applied`` is the sole failure outcome that can release a fence:
        the authenticated host agent has proved that no native mutation began.
        Failed or ambiguous observations stay fenced without preventing a later
        terminal observation for this exact operation.  Every observation is
        signed by the controller and immutable after insertion.
        """

        proof_max_age_seconds = _recovery_proof_window(proof_max_age_seconds)
        if outcome not in {"completed", "not_applied", "failed", "ambiguous"}:
            raise ValueError("native recovery outcome is invalid")
        if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(operation_id):
            raise ValueError("native recovery operation identity is invalid")
        if not isinstance(worker_name, str) or worker_name not in _WORKER_RECOVERY_BINDINGS:
            raise ValueError("native recovery worker identity is invalid")
        if not isinstance(request_fingerprint, str) or not _SHA256_HEX.fullmatch(
            request_fingerprint
        ):
            raise ValueError("native recovery request digest is invalid")
        if recovery_action not in _RECOVERY_ACTIONS:
            raise ValueError("native recovery action is invalid")
        if not isinstance(request_nonce, str) or not _RECOVERY_KEY.fullmatch(request_nonce):
            raise ValueError("native recovery request nonce is invalid")
        if not isinstance(provider_reconciliation_digest, str) or not _SHA256_DIGEST.fullmatch(
            provider_reconciliation_digest
        ):
            raise ValueError("native recovery provider reconciliation binding is invalid")
        if not isinstance(outcome_digest, str) or not _SHA256_DIGEST.fullmatch(outcome_digest):
            raise ValueError("native recovery outcome digest is invalid")
        if not isinstance(agent_release_digest, str) or not _SHA256_DIGEST.fullmatch(
            agent_release_digest
        ):
            raise ValueError("native recovery agent release is invalid")
        if not isinstance(agent_certificate_sha256, str) or not _SHA256_HEX.fullmatch(
            agent_certificate_sha256
        ):
            raise ValueError("native recovery agent certificate is invalid")
        if not isinstance(reconciliation_key, str) or not reconciliation_key:
            raise ValueError("native recovery reconciliation key is unavailable")
        native_observed_at = (
            time.time()
            if observed_at is None
            else _finite_recovery_number(observed_at, field="native recovery outcome timestamp")
        )
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                row = connection.execute(
                    "SELECT * FROM worker_recoveries WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
                if row is None or (
                    row["worker_name"],
                    row["request_digest"],
                    row["recovery_action"],
                    row["request_nonce"],
                    row["provider_reconciliation_digest"],
                    row["agent_release_digest"],
                    row["expected_agent_certificate_sha256"],
                ) != (
                    worker_name,
                    request_fingerprint,
                    recovery_action,
                    request_nonce,
                    provider_reconciliation_digest,
                    agent_release_digest,
                    agent_certificate_sha256,
                ):
                    raise ValueError("native outcome does not match recovery operation")
                try:
                    permanent_labels = tuple(json.loads(str(row["labels_json"])))
                    stored_observation = json.loads(str(row["provider_observation_json"]))
                    if row["provider_runner_id"] is None:
                        _, canonical_observation, recomputed_provider_digest = (
                            _validate_provider_absence_observation(
                                stored_observation,
                                repository=str(row["repository"]),
                                worker_name=worker_name,
                            )
                        )
                    else:
                        provider_status = worker_recovery_provider_status(
                            stored_observation,
                            worker_name=worker_name,
                            provider_runner_id=int(row["provider_runner_id"]),
                            recovery_action=recovery_action,
                        )
                        _, canonical_observation, recomputed_provider_digest = (
                            _validate_provider_observation(
                                stored_observation,
                                schema="qdev-worker-provider-observation-v1",
                                repository=str(row["repository"]),
                                worker_name=worker_name,
                                provider_runner_id=int(row["provider_runner_id"]),
                                provider_status=provider_status,
                                provider_busy=False,
                                labels=permanent_labels,
                            )
                        )
                except (TypeError, ValueError, json.JSONDecodeError) as error:
                    raise ValueError(
                        "native recovery provider reconciliation binding is invalid"
                    ) from error
                if (
                    row["provider_observation_json"] != canonical_observation
                    or provider_reconciliation_digest != recomputed_provider_digest
                ):
                    raise ValueError("native recovery provider reconciliation binding is invalid")
                policy_digest = row["policy_digest"]
                if not isinstance(policy_digest, str) or not _SHA256_DIGEST.fullmatch(
                    policy_digest
                ):
                    raise ValueError("native recovery policy binding is invalid")
                prior_outcome = connection.execute(
                    "SELECT * FROM worker_recovery_outcomes "
                    "WHERE operation_id=? AND outcome_digest=?",
                    (operation_id, outcome_digest),
                ).fetchone()
                if prior_outcome is not None:
                    if (
                        prior_outcome["worker_name"],
                        prior_outcome["request_digest"],
                        prior_outcome["agent_certificate_sha256"],
                        prior_outcome["provider_reconciliation_digest"],
                        prior_outcome["recovery_action"],
                        prior_outcome["request_nonce"],
                        prior_outcome["policy_digest"],
                        prior_outcome["agent_release_digest"],
                        prior_outcome["outcome"],
                    ) != (
                        worker_name,
                        request_fingerprint,
                        agent_certificate_sha256,
                        provider_reconciliation_digest,
                        recovery_action,
                        request_nonce,
                        policy_digest,
                        agent_release_digest,
                        outcome,
                    ):
                        raise ValueError("native outcome digest is bound to another result")
                    connection.execute("COMMIT")
                    return dict(row) | {
                        "reconciliation_receipt_digest": prior_outcome["receipt_digest"],
                        "reconciliation_signature": prior_outcome["signature"],
                    }
                if not 0 <= now - native_observed_at <= proof_max_age_seconds:
                    raise ValueError("native recovery outcome is not fresh")
                invoked_at = _finite_recovery_number(
                    row["invoked_at"], field="native recovery invocation timestamp"
                )
                if native_observed_at < invoked_at:
                    raise ValueError("native recovery outcome predates adapter invocation")
                if row["state"] != "invoking":
                    raise ValueError("native recovery operation is not awaiting outcome")
                if row["native_outcome"] in {"completed", "not_applied"}:
                    raise ValueError("native recovery terminal outcome cannot be changed")
                receipt_payload = {
                    "schema": "qdev-worker-recovery-native-outcome-v1",
                    "operation_id": operation_id,
                    "worker_name": worker_name,
                    "request_digest": request_fingerprint,
                    "agent_certificate_sha256": agent_certificate_sha256,
                    "provider_reconciliation_digest": provider_reconciliation_digest,
                    "recovery_action": recovery_action,
                    "request_nonce": request_nonce,
                    "policy_digest": policy_digest,
                    "agent_release_digest": agent_release_digest,
                    "outcome": outcome,
                    "outcome_digest": outcome_digest,
                    "observed_at": native_observed_at,
                }
                canonical = json.dumps(
                    receipt_payload,
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
                receipt_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
                signature = hmac.new(
                    reconciliation_key.encode("utf-8"), canonical, hashlib.sha256
                ).hexdigest()
                connection.execute(
                    "INSERT INTO worker_recovery_outcomes("
                    "receipt_digest,operation_id,worker_name,request_digest,"
                    "agent_certificate_sha256,provider_reconciliation_digest,"
                    "recovery_action,request_nonce,policy_digest,agent_release_digest,"
                    "outcome,outcome_digest,signature,observed_at,reconciled_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        receipt_digest,
                        operation_id,
                        worker_name,
                        request_fingerprint,
                        agent_certificate_sha256,
                        provider_reconciliation_digest,
                        recovery_action,
                        request_nonce,
                        policy_digest,
                        agent_release_digest,
                        outcome,
                        outcome_digest,
                        signature,
                        native_observed_at,
                        now,
                    ),
                )
                state = (
                    "completed"
                    if outcome == "completed"
                    else "released"
                    if outcome == "not_applied"
                    else "invoking"
                )
                finalized_at = now if outcome in {"completed", "not_applied"} else None
                released_at = now if outcome == "not_applied" else None
                connection.execute(
                    "UPDATE worker_recoveries SET state=?,native_outcome=?,"
                    "native_outcome_digest=?,agent_identity=?,agent_certificate_sha256=?,"
                    "native_outcome_signature=?,"
                    "native_outcome_observed_at=?,reconciled_at=?,native_finalized_at=?,"
                    "updated_at=?,released_at=? "
                    "WHERE operation_id=?",
                    (
                        state,
                        outcome,
                        outcome_digest,
                        agent_certificate_sha256,
                        agent_certificate_sha256,
                        signature,
                        native_observed_at,
                        now,
                        finalized_at,
                        now,
                        released_at,
                        operation_id,
                    ),
                )
                updated = connection.execute(
                    "SELECT * FROM worker_recoveries WHERE operation_id=?",
                    (operation_id,),
                ).fetchone()
                connection.execute("COMMIT")
                assert updated is not None
                return dict(updated) | {
                    "reconciliation_receipt_digest": receipt_digest,
                    "reconciliation_signature": signature,
                }
            except BaseException:
                connection.execute("ROLLBACK")
                raise

    def worker_recovery_outcomes(self, operation_id: str) -> list[dict[str, Any]]:
        if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(operation_id):
            raise ValueError("native recovery operation identity is invalid")
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM worker_recovery_outcomes WHERE operation_id=? "
                "ORDER BY reconciled_at,receipt_digest",
                (operation_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def has_available_tier_slot(self, tier: str, max_age_seconds: int) -> bool:
        cutoff = time.time() - max_age_seconds
        with self.connect() as connection:
            return self._has_available_tier_slot(connection, tier, cutoff)

    def stale_jobs(self, worker_timeout_seconds: int) -> list[dict[str, Any]]:
        cutoff = time.time() - worker_timeout_seconds
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT jobs.*, workers.last_seen AS worker_last_seen
                FROM jobs LEFT JOIN workers ON workers.name=jobs.worker_name
                WHERE jobs.status IN ('claimed','running') AND jobs.updated_at<?
                  AND (jobs.worker_name IS NULL OR workers.name IS NULL
                       OR workers.last_seen<? OR workers.active_jobs=0)
                ORDER BY jobs.created_at ASC, jobs.job_id ASC
                """,
                (cutoff, cutoff),
            ).fetchall()
        return [dict(row) for row in rows]

    def release_stale_job(self, job_id: int, reason: str, worker_timeout_seconds: int) -> bool:
        cutoff = time.time() - worker_timeout_seconds
        now = time.time()
        with self.connect() as connection:
            updated = connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL,
                    claim_scope_id=NULL, profile=NULL,
                    claimed_at=NULL, updated_at=?, result=?
                WHERE job_id=? AND status IN ('claimed','running') AND updated_at<?
                  AND (worker_name IS NULL OR worker_name NOT IN (
                    SELECT name FROM workers WHERE last_seen>=? AND active_jobs>0
                  ))
                """,
                (now, reason[:4000], job_id, cutoff, cutoff),
            )
        return updated.rowcount == 1

    def failed_worker_jobs(self) -> list[dict[str, Any]]:
        """Return terminal local worker failures still queued by the provider."""
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT jobs.*, workers.last_seen AS worker_last_seen
                FROM jobs LEFT JOIN workers ON workers.name=jobs.worker_name
                WHERE jobs.status='failed' AND jobs.worker_name IS NOT NULL
                  AND jobs.claimed_at IS NOT NULL
                  AND jobs.result LIKE 'worker=% exit=%'
                ORDER BY jobs.created_at ASC, jobs.job_id ASC
                """
            ).fetchall()
        return [dict(row) for row in rows]

    def release_failed_job(
        self,
        job_id: int,
        reason: str,
        *,
        expected_updated_at: float,
    ) -> bool:
        """Atomically release one provider-confirmed queued worker failure."""
        now = time.time()
        with self.connect() as connection:
            updated = connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL,
                    claim_scope_id=NULL, profile=NULL, claimed_at=NULL,
                    completed_at=NULL, updated_at=?, result=?
                WHERE job_id=? AND status='failed' AND updated_at=?
                  AND worker_name IS NOT NULL AND claimed_at IS NOT NULL
                  AND result LIKE 'worker=% exit=%'
                """,
                (now, reason[:4000], job_id, expected_updated_at),
            )
        return updated.rowcount == 1

    def health(self) -> dict[str, Any]:
        with self.connect() as connection:
            counts = {
                row["status"]: row["count"]
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM jobs GROUP BY status"
                ).fetchall()
            }
            workers = []
            for row in connection.execute(
                "SELECT name, profiles_json, active_jobs, last_seen, detail_json FROM workers"
            ).fetchall():
                detail = json.loads(row["detail_json"])
                concurrency = _worker_concurrency(detail)
                active_jobs = int(row["active_jobs"])
                slots_available = max(0, concurrency - active_jobs)
                recovery_fenced = self._worker_fenced(connection, str(row["name"]))
                capacity_allowed = detail.get("allowed", True) is True and not recovery_fenced
                if recovery_fenced:
                    slots_available = 0
                workers.append(
                    dict(row)
                    | {
                        "tier": detail.get("tier", "unknown"),
                        "capacity_allowed": capacity_allowed,
                        "concurrency": concurrency,
                        "slots_available": slots_available,
                        "available": capacity_allowed and slots_available > 0,
                        "recovery_fenced": recovery_fenced,
                    }
                )
        return {"jobs": counts, "workers": workers, "now": time.time()}
