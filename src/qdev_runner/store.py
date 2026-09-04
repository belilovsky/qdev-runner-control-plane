from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

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
_RECOVERY_ACTIONS = frozenset(
    {"restore_saved_configuration", "replace_existing_registration"}
)
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
    provider_observed_at REAL,
    recovery_action TEXT,
    operator_certificate_sha256 TEXT,
    expected_agent_certificate_sha256 TEXT,
    interface_version TEXT,
    interface_digest TEXT,
    controller_revision TEXT,
    controller_release_digest TEXT,
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
    prior_provider_runner_id INTEGER NOT NULL,
    prior_provider_runner_disposition TEXT NOT NULL CHECK(
        prior_provider_runner_disposition IN ('same','absent')
    ),
    provider_runner_id INTEGER NOT NULL,
    matching_runner_count INTEGER NOT NULL CHECK(matching_runner_count=1),
    provider_reconciliation_digest TEXT NOT NULL,
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
            "provider_observed_at": "REAL",
            "recovery_action": "TEXT",
            "operator_certificate_sha256": "TEXT",
            "expected_agent_certificate_sha256": "TEXT",
            "interface_version": "TEXT",
            "interface_digest": "TEXT",
            "controller_revision": "TEXT",
            "controller_release_digest": "TEXT",
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
                connection.execute(
                    f"ALTER TABLE worker_recoveries ADD COLUMN {name} {sql_type}"
                )
        outcome_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(worker_recovery_outcomes)"
            ).fetchall()
        }
        if "provider_reconciliation_digest" not in outcome_columns:
            connection.execute(
                "ALTER TABLE worker_recovery_outcomes ADD COLUMN "
                "provider_reconciliation_digest TEXT"
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
                    f"{row['idempotency_key']}\0{row['worker_name']}\0"
                    f"{row['request_fingerprint']}"
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
    ) -> dict[str, Any] | None:
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
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
                    labels = {label.lower() for label in json.loads(row["labels_json"])}
                    matching_profile = next(
                        (profile for profile in profiles if profile.lower() in labels), None
                    )
                    if matching_profile is not None:
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
                if (
                    enforce_profile_fifo
                    and profile_heads.get(matching_profile.lower()) != int(row["job_id"])
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
    def _require_no_durable_worker_work(
        connection: sqlite3.Connection, worker_name: str
    ) -> None:
        """Prove the controller has no durable claim for an offline worker.

        A stale or missing heartbeat is expected during recovery and therefore
        cannot prove either idle or busy.  Provider reconciliation is supplied
        by the authenticated controller-owned provider integration; this check
        independently proves that the controller database has no
        claimed/running work for the target.
        """

        if (
            connection.execute(
                "SELECT 1 FROM jobs WHERE worker_name=? "
                "AND status IN ('claimed','running')",
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
            "controller_receipt_id": controller_receipt_id,
            "controller_observed_at": controller_observed_at,
            "request_nonce": request_nonce,
            "requested_at": requested_at,
            "provider_idle_proof_digest": provider["digest"],
            "provider_reconciliation_digest": provider[
                "provider_reconciliation_digest"
            ],
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
                        existing["controller_receipt_id"],
                        existing["controller_observed_at"],
                        existing["request_nonce"],
                        existing["requested_at"],
                        existing["provider_idle_proof_digest"],
                        existing["provider_reconciliation_digest"],
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
                        controller_receipt_id,
                        controller_observed_at,
                        request_nonce,
                        requested_at,
                        provider["digest"],
                        provider["provider_reconciliation_digest"],
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
                    "provider_reconciliation_digest,"
                    "recovery_action,operator_certificate_sha256,"
                    "expected_agent_certificate_sha256,interface_version,interface_digest,"
                    "controller_revision,controller_release_digest,controller_receipt_id,"
                    "controller_observed_at,request_digest,request_nonce,requested_at,consumed_at"
                    ") VALUES(?,?,?,?,'prepared',?,NULL,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
                        recovery_action,
                        operator_certificate_sha256,
                        expected_agent_certificate_sha256,
                        interface_version,
                        interface_digest,
                        controller_revision,
                        controller_release_digest,
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
        provider_runner_id: int,
        provider_status: str,
        provider_busy: bool,
        active_jobs: int,
        provider_reconciliation_digest: str,
        observed_at: float | None = None,
    ) -> dict[str, Any]:
        """Create the controller-internal provider observation used by admission.

        This is not an HTTP request shape.  Only the controller process holding
        the receipt key can create a proof which ``begin_worker_recovery`` will
        accept, so an operator cannot turn a caller-supplied boolean into idle
        evidence.
        """

        target = _WORKER_RECOVERY_BINDINGS.get(worker_name)
        if (
            not isinstance(key, str)
            or not key
            or target is None
            or target["repository"] != repository
            or target["labels"] != labels
            or isinstance(provider_runner_id, bool)
            or not isinstance(provider_runner_id, int)
            or provider_runner_id <= 0
            or provider_status != "offline"
            or provider_busy is not False
            or isinstance(active_jobs, bool)
            or not isinstance(active_jobs, int)
            or active_jobs != 0
            or not isinstance(provider_reconciliation_digest, str)
            or not _SHA256_DIGEST.fullmatch(provider_reconciliation_digest)
        ):
            raise ValueError("provider idle proof is invalid")
        timestamp = (
            time.time()
            if observed_at is None
            else _finite_recovery_number(
                observed_at, field="provider idle proof timestamp"
            )
        )
        payload = {
            "schema": "qdev-worker-provider-idle-proof-v1",
            "worker_name": worker_name,
            "repository": repository,
            "labels": list(labels),
            "provider_runner_id": provider_runner_id,
            "provider_status": provider_status,
            "provider_busy": provider_busy,
            "active_jobs": active_jobs,
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
        expected_signature = hmac.new(
            key.encode("utf-8"), canonical, hashlib.sha256
        ).hexdigest()
        now = time.time()
        try:
            observed_at = _finite_recovery_number(
                proof["observed_at"], field="provider idle proof timestamp"
            )
        except ValueError as error:
            raise ValueError("provider idle proof is invalid") from error
        proof_age = now - observed_at
        if (
            proof["schema"] != "qdev-worker-provider-idle-proof-v1"
            or proof["worker_name"] != worker_name
            or proof["repository"] != repository
            or proof["labels"] != list(labels)
            or isinstance(proof["provider_runner_id"], bool)
            or not isinstance(proof["provider_runner_id"], int)
            or proof["provider_runner_id"] <= 0
            or proof["provider_status"] != "offline"
            or proof["provider_busy"] is not False
            or isinstance(proof["active_jobs"], bool)
            or not isinstance(proof["active_jobs"], int)
            or proof["active_jobs"] != 0
            or not isinstance(proof["provider_reconciliation_digest"], str)
            or not _SHA256_DIGEST.fullmatch(proof["provider_reconciliation_digest"])
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
        prior_provider_runner_id: int,
        prior_provider_runner_disposition: str,
        provider_runner_id: int,
        matching_runner_count: int,
        provider_status: str,
        provider_busy: bool,
        active_jobs: int,
        provider_reconciliation_digest: str,
        canary_repository: str,
        canary_workflow: str,
        canary_ref: str,
        canary_head_sha: str,
        canary_run_id: int,
        canary_run_attempt: int,
        canary_job_id: int,
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
            prior_provider_runner_id,
            provider_runner_id,
            matching_runner_count,
            canary_run_id,
            canary_run_attempt,
            canary_job_id,
            canary_runner_id,
        )
        valid_runner_transition = (
            prior_provider_runner_disposition == "same"
            and provider_runner_id == prior_provider_runner_id
        ) or (
            target is not None
            and target["recovery_action"] == "replace_existing_registration"
            and prior_provider_runner_disposition == "absent"
            and provider_runner_id != prior_provider_runner_id
        )
        if (
            not isinstance(key, str)
            or not key
            or not isinstance(operation_id, str)
            or not _SHA256_HEX.fullmatch(operation_id)
            or target is None
            or target["repository"] != repository
            or target["labels"] != labels
            or any(
                isinstance(value, bool) or not isinstance(value, int)
                for value in integer_values
            )
            or any(value <= 0 for value in integer_values)
            or matching_runner_count != 1
            or not valid_runner_transition
            or provider_status != "online"
            or provider_busy is not False
            or isinstance(active_jobs, bool)
            or not isinstance(active_jobs, int)
            or active_jobs != 0
            or not isinstance(provider_reconciliation_digest, str)
            or not _SHA256_DIGEST.fullmatch(provider_reconciliation_digest)
            or canary_repository != repository
            or not isinstance(canary_workflow, str)
            or not _CANARY_WORKFLOW.fullmatch(canary_workflow)
            or canary_workflow
            != _WORKER_RECOVERY_CANARY_WORKFLOWS.get(worker_name)
            or not _valid_canary_ref(canary_ref)
            or not isinstance(canary_head_sha, str)
            or not _GIT_REVISION.fullmatch(canary_head_sha)
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
            else _finite_recovery_number(
                observed_at, field="worker recovery acceptance timestamp"
            )
        )
        if timestamp < completed_at:
            raise ValueError("worker recovery acceptance proof is invalid")
        payload = {
            "schema": "qdev-worker-recovery-acceptance-proof-v1",
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
            "provider_reconciliation_digest": provider_reconciliation_digest,
            "canary_repository": canary_repository,
            "canary_workflow": canary_workflow,
            "canary_ref": canary_ref,
            "canary_head_sha": canary_head_sha,
            "canary_run_id": canary_run_id,
            "canary_run_attempt": canary_run_attempt,
            "canary_job_id": canary_job_id,
            "canary_runner_id": canary_runner_id,
            "canary_runner_name": canary_runner_name,
            "canary_status": canary_status,
            "canary_conclusion": canary_conclusion,
            "canary_completed_at": completed_at,
            "observed_at": timestamp,
        }
        canonical = json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
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
        prior_provider_runner_id: int,
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
            "provider_reconciliation_digest",
            "canary_repository",
            "canary_workflow",
            "canary_ref",
            "canary_head_sha",
            "canary_run_id",
            "canary_run_attempt",
            "canary_job_id",
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
                payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
            ).encode("utf-8")
        except (TypeError, ValueError) as error:
            raise ValueError("worker recovery acceptance proof is invalid") from error
        expected_digest = "sha256:" + hashlib.sha256(canonical).hexdigest()
        expected_signature = hmac.new(
            key.encode("utf-8"), canonical, hashlib.sha256
        ).hexdigest()
        integer_fields = (
            "prior_provider_runner_id",
            "provider_runner_id",
            "matching_runner_count",
            "canary_run_id",
            "canary_run_attempt",
            "canary_job_id",
            "canary_runner_id",
        )
        integers_are_valid = all(
            not isinstance(proof[name], bool)
            and isinstance(proof[name], int)
            and proof[name] > 0
            for name in integer_fields
        )
        runner_transition_is_valid = (
            proof["prior_provider_runner_disposition"] == "same"
            and proof["provider_runner_id"] == prior_provider_runner_id
        ) or (
            recovery_action == "replace_existing_registration"
            and proof["prior_provider_runner_disposition"] == "absent"
            and proof["provider_runner_id"] != prior_provider_runner_id
        )
        now = time.time()
        age = now - observed_at
        if (
            proof["schema"] != "qdev-worker-recovery-acceptance-proof-v1"
            or proof["operation_id"] != operation_id
            or proof["worker_name"] != worker_name
            or proof["repository"] != repository
            or proof["labels"] != list(labels)
            or not integers_are_valid
            or proof["prior_provider_runner_id"] != prior_provider_runner_id
            or proof["matching_runner_count"] != 1
            or not runner_transition_is_valid
            or proof["provider_status"] != "online"
            or proof["provider_busy"] is not False
            or isinstance(proof["active_jobs"], bool)
            or not isinstance(proof["active_jobs"], int)
            or proof["active_jobs"] != 0
            or not isinstance(proof["provider_reconciliation_digest"], str)
            or not _SHA256_DIGEST.fullmatch(proof["provider_reconciliation_digest"])
            or proof["canary_repository"] != repository
            or not isinstance(proof["canary_workflow"], str)
            or not _CANARY_WORKFLOW.fullmatch(proof["canary_workflow"])
            or proof["canary_workflow"]
            != _WORKER_RECOVERY_CANARY_WORKFLOWS.get(worker_name)
            or not _valid_canary_ref(proof["canary_ref"])
            or not isinstance(proof["canary_head_sha"], str)
            or not _GIT_REVISION.fullmatch(proof["canary_head_sha"])
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
        ):
            raise ValueError("worker recovery acceptance proof is invalid")
        return dict(proof)

    def worker_recovery(self, operation_id: str) -> dict[str, Any] | None:
        if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(
            operation_id
        ):
            raise ValueError("native recovery operation identity is invalid")
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM worker_recoveries WHERE operation_id=?", (operation_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def worker_recovery_by_idempotency_key(
        self, idempotency_key: str
    ) -> dict[str, Any] | None:
        """Return the exact durable operation after a lost prepare response."""

        if not isinstance(idempotency_key, str) or not _RECOVERY_KEY.fullmatch(
            idempotency_key
        ):
            raise ValueError("worker recovery idempotency key is invalid")
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM worker_recoveries WHERE idempotency_key=?",
                (idempotency_key,),
            ).fetchone()
        return dict(row) if row is not None else None

    def prepared_worker_recovery(self, worker_name: str) -> dict[str, Any] | None:
        if (
            not isinstance(worker_name, str)
            or worker_name not in _WORKER_RECOVERY_BINDINGS
        ):
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
        if not isinstance(idempotency_key, str) or not _RECOVERY_KEY.fullmatch(
            idempotency_key
        ):
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
                if (
                    row["state"] == "released"
                    and (expected, state) == ("completed", "released")
                ):
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
                        prior_provider_runner_id=int(row["provider_runner_id"]),
                        recovery_action=str(row["recovery_action"]),
                        native_finalized_at=float(row["native_finalized_at"]),
                        max_age_seconds=None,
                    )
                    acceptance_row = connection.execute(
                        "SELECT * FROM worker_recovery_acceptances "
                        "WHERE operation_id=?",
                        (row["operation_id"],),
                    ).fetchone()
                    if (
                        acceptance_row is None
                        or row["acceptance_proof_digest"] != accepted["digest"]
                        or row["acceptance_proof_signature"] != accepted["signature"]
                        or row["accepted_provider_runner_id"]
                        != accepted["provider_runner_id"]
                        or acceptance_row["proof_digest"] != accepted["digest"]
                        or acceptance_row["signature"] != accepted["signature"]
                    ):
                        raise ValueError(
                            "worker recovery acceptance is bound to another proof"
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
                        raise ValueError(
                            "worker recovery durable binding is invalid"
                        ) from error
                    if any(
                        not 0 <= now - timestamp <= proof_max_age_seconds
                        for timestamp in (
                            controller_observed_at,
                            requested_at,
                            provider_observed_at,
                        )
                    ):
                        raise ValueError(
                            "worker recovery evidence expired before invocation"
                        )
                    self._require_no_durable_worker_work(
                        connection, str(row["worker_name"])
                    )
                elif (expected, state) == ("completed", "released"):
                    if (
                        row["native_outcome"] != "completed"
                        or not isinstance(row["native_outcome_digest"], str)
                        or not _SHA256_DIGEST.fullmatch(row["native_outcome_digest"])
                        or not isinstance(row["agent_certificate_sha256"], str)
                        or not _SHA256_HEX.fullmatch(
                            row["agent_certificate_sha256"]
                        )
                        or not isinstance(row["native_outcome_signature"], str)
                        or not _SHA256_HEX.fullmatch(row["native_outcome_signature"])
                        or row["reconciled_at"] is None
                        or row["native_finalized_at"] is None
                    ):
                        raise ValueError(
                            "worker recovery has no signed completed native outcome"
                        )
                    if (
                        acceptance_proof is None
                        or not isinstance(acceptance_proof_key, str)
                        or not acceptance_proof_key
                    ):
                        raise ValueError(
                            "worker recovery acceptance proof is required"
                        )
                    accepted = self.verify_worker_recovery_acceptance_proof(
                        acceptance_proof,
                        key=acceptance_proof_key,
                        operation_id=str(row["operation_id"]),
                        worker_name=str(row["worker_name"]),
                        repository=str(row["repository"]),
                        labels=labels,
                        prior_provider_runner_id=int(row["provider_runner_id"]),
                        recovery_action=str(row["recovery_action"]),
                        native_finalized_at=float(row["native_finalized_at"]),
                        max_age_seconds=proof_max_age_seconds,
                    )
                    self._require_no_durable_worker_work(
                        connection, str(row["worker_name"])
                    )
                    connection.execute(
                        "INSERT INTO worker_recovery_acceptances("
                        "proof_digest,operation_id,worker_name,repository,labels_json,"
                        "prior_provider_runner_id,prior_provider_runner_disposition,"
                        "provider_runner_id,matching_runner_count,"
                        "provider_reconciliation_digest,provider_observed_at,"
                        "canary_repository,canary_workflow,canary_ref,canary_head_sha,"
                        "canary_run_id,canary_run_attempt,canary_job_id,canary_runner_id,"
                        "canary_status,canary_conclusion,canary_completed_at,signature,"
                        "accepted_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
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
        agent_certificate_sha256: str,
        outcome: str,
        outcome_digest: str,
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
        if (
            not isinstance(request_fingerprint, str)
            or not _SHA256_HEX.fullmatch(request_fingerprint)
        ):
            raise ValueError("native recovery request digest is invalid")
        if not isinstance(outcome_digest, str) or not _SHA256_DIGEST.fullmatch(
            outcome_digest
        ):
            raise ValueError("native recovery outcome digest is invalid")
        if (
            not isinstance(agent_certificate_sha256, str)
            or not _SHA256_HEX.fullmatch(agent_certificate_sha256)
        ):
            raise ValueError("native recovery agent certificate is invalid")
        if not isinstance(reconciliation_key, str) or not reconciliation_key:
            raise ValueError("native recovery reconciliation key is unavailable")
        native_observed_at = (
            time.time()
            if observed_at is None
            else _finite_recovery_number(
                observed_at, field="native recovery outcome timestamp"
            )
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
                    row["expected_agent_certificate_sha256"],
                ) != (
                    worker_name,
                    request_fingerprint,
                    agent_certificate_sha256,
                ):
                    raise ValueError("native outcome does not match recovery operation")
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
                        prior_outcome["outcome"],
                    ) != (
                        worker_name,
                        request_fingerprint,
                        agent_certificate_sha256,
                        row["provider_reconciliation_digest"],
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
                    raise ValueError(
                        "native recovery outcome predates adapter invocation"
                    )
                if row["state"] != "invoking":
                    raise ValueError("native recovery operation is not awaiting outcome")
                if row["native_outcome"] in {"completed", "not_applied"}:
                    raise ValueError("native recovery terminal outcome cannot be changed")
                provider_reconciliation_digest = row[
                    "provider_reconciliation_digest"
                ]
                if (
                    not isinstance(provider_reconciliation_digest, str)
                    or not _SHA256_DIGEST.fullmatch(
                        provider_reconciliation_digest
                    )
                ):
                    raise ValueError(
                        "native recovery provider reconciliation binding is invalid"
                    )
                receipt_payload = {
                    "schema": "qdev-worker-recovery-native-outcome-v1",
                    "operation_id": operation_id,
                    "worker_name": worker_name,
                    "request_digest": request_fingerprint,
                    "agent_certificate_sha256": agent_certificate_sha256,
                    "provider_reconciliation_digest": provider_reconciliation_digest,
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
                    "outcome,outcome_digest,signature,observed_at,reconciled_at) "
                    "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        receipt_digest,
                        operation_id,
                        worker_name,
                        request_fingerprint,
                        agent_certificate_sha256,
                        provider_reconciliation_digest,
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
        if not isinstance(operation_id, str) or not _SHA256_HEX.fullmatch(
            operation_id
        ):
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
