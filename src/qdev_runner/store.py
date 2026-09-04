from __future__ import annotations

import hashlib
import json
import math
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
MAX_INFRASTRUCTURE_RETRIES = 1

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
    attempts INTEGER NOT NULL DEFAULT 0,
    infra_retries INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS jobs_status_created_idx ON jobs(status, created_at);

CREATE TABLE IF NOT EXISTS workers (
    name TEXT PRIMARY KEY,
    profiles_json TEXT NOT NULL,
    active_jobs INTEGER NOT NULL,
    last_seen REAL NOT NULL,
    detail_json TEXT NOT NULL
);

-- Test receipts are intentionally additive to the runner queue.  The queue
-- remains the source of execution state while this table is the immutable
-- result ledger keyed by job, suite and GitHub attempt.
CREATE TABLE IF NOT EXISTS test_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    repository TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    suite TEXT NOT NULL,
    workflow TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    contract TEXT NOT NULL,
    execution_status TEXT NOT NULL,
    test_status TEXT NOT NULL,
    total INTEGER NOT NULL,
    executed INTEGER NOT NULL,
    failed INTEGER NOT NULL,
    skipped INTEGER NOT NULL,
    coverage_json TEXT NOT NULL,
    critical_scenarios_json TEXT NOT NULL,
    reports_json TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    digest TEXT NOT NULL,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    created_at REAL NOT NULL,
    UNIQUE(job_id, suite, attempt)
);
CREATE INDEX IF NOT EXISTS test_runs_repository_created_idx
    ON test_runs(repository, created_at DESC);
CREATE INDEX IF NOT EXISTS test_runs_job_idx ON test_runs(job_id);

-- Source reports are retained separately from the normalized receipt.  A
-- receipt is not confirmed until every referenced source file has been
-- persisted and its size/digest is recorded here.
CREATE TABLE IF NOT EXISTS test_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_id INTEGER NOT NULL,
    run_id INTEGER NOT NULL,
    repository TEXT NOT NULL,
    commit_sha TEXT NOT NULL,
    suite TEXT NOT NULL,
    workflow TEXT NOT NULL,
    attempt INTEGER NOT NULL,
    path TEXT NOT NULL,
    format TEXT NOT NULL,
    size INTEGER NOT NULL CHECK(size >= 0),
    sha256 TEXT NOT NULL,
    storage_path TEXT NOT NULL,
    created_at REAL NOT NULL,
    UNIQUE(job_id, suite, attempt, path)
);
CREATE INDEX IF NOT EXISTS test_reports_job_idx ON test_reports(job_id, created_at DESC);

-- A dispatch intent is an outbox entry in the same durable store as the
-- schedule.  It makes the gap between the SQLite commit and GitHub dispatch
-- visible after a restart instead of losing a due run or blindly duplicating
-- it.
CREATE TABLE IF NOT EXISTS test_dispatch_intents (
    id TEXT PRIMARY KEY,
    repository TEXT NOT NULL,
    workflow TEXT NOT NULL,
    suite TEXT NOT NULL,
    ref TEXT NOT NULL,
    installation_id INTEGER NOT NULL DEFAULT 0,
    slot REAL NOT NULL,
    expected_sha TEXT,
    correlation_id TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK(state IN ('pending','dispatched','ambiguous','error')),
    provider_run_id INTEGER,
    provider_job_id INTEGER,
    provider_response_json TEXT NOT NULL DEFAULT '{}',
    last_error TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS test_dispatch_intents_state_idx
    ON test_dispatch_intents(state, updated_at);

-- Retry requests have a stable client/request id and a separate attempt row;
-- the original job remains immutable history while a provider retry receives
-- its own run/job identity.
CREATE TABLE IF NOT EXISTS test_retry_attempts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id TEXT NOT NULL UNIQUE,
    source_job_id INTEGER NOT NULL,
    repository TEXT NOT NULL,
    source_run_id INTEGER NOT NULL,
    source_job_attempt INTEGER NOT NULL,
    expected_sha TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('requested','dispatched','ambiguous','completed','error')),
    provider_response_json TEXT NOT NULL DEFAULT '{}',
    provider_run_id INTEGER,
    provider_job_id INTEGER,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS test_retry_attempts_source_idx
    ON test_retry_attempts(source_job_id, created_at DESC);

CREATE TABLE IF NOT EXISTS test_retry_requests (
    job_id INTEGER PRIMARY KEY,
    requested_at REAL NOT NULL,
    requested_by TEXT NOT NULL
);

-- Recurring main-branch test dispatches live in the same controller database.
-- The primary key makes registration idempotent and the transactional claim
-- advances next_run_at before dispatch so a controller restart cannot enqueue
-- the same schedule twice.
CREATE TABLE IF NOT EXISTS test_schedules (
    repository TEXT NOT NULL,
    workflow TEXT NOT NULL,
    suite TEXT NOT NULL,
    installation_id INTEGER NOT NULL,
    ref TEXT NOT NULL,
    interval_seconds INTEGER NOT NULL CHECK(interval_seconds BETWEEN 60 AND 604800),
    next_run_at REAL NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1 CHECK(enabled IN (0, 1)),
    last_dispatch_at REAL,
    last_error TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    PRIMARY KEY(repository, workflow, suite, ref)
);
CREATE INDEX IF NOT EXISTS test_schedules_due_idx
    ON test_schedules(enabled, next_run_at);
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
            # Both broker containers open the shared database during startup.
            # Serialize additive ALTER TABLE migrations after the idempotent
            # CREATE statements so concurrent starts cannot both observe a
            # missing column and make the second ALTER fail with a duplicate
            # column error.
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

        columns = {
            str(row["name"]) for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
        }
        if "infra_retries" not in columns:
            connection.execute(
                "ALTER TABLE jobs ADD COLUMN infra_retries INTEGER NOT NULL DEFAULT 0"
            )
        dispatch_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(test_dispatch_intents)").fetchall()
        }
        if "installation_id" not in dispatch_columns:
            connection.execute(
                "ALTER TABLE test_dispatch_intents ADD COLUMN installation_id INTEGER "
                "NOT NULL DEFAULT 0"
            )
        if "expected_sha" not in dispatch_columns:
            connection.execute("ALTER TABLE test_dispatch_intents ADD COLUMN expected_sha TEXT")

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
            SELECT profiles_json, active_jobs, last_seen, detail_json
            FROM workers WHERE last_seen>=?
            """,
            (cutoff,),
        ).fetchall()
        for row in rows:
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
        primary_max_age_seconds: int = 90,
        claim_scope: ClaimScope | None = None,
    ) -> dict[str, Any] | None:
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
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
            if claim_scope is not None and claim_scope.schema == SCHEMA_V2:
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
                labels = {label.lower() for label in json.loads(row["labels_json"])}
                matching_profile = next(
                    (profile for profile in profiles if profile.lower() in labels), None
                )
                if matching_profile is None:
                    continue
                if (
                    claim_scope is not None
                    and claim_scope.schema == SCHEMA_V2
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

    def record_test_run(self, payload: dict[str, Any], digest: str) -> tuple[dict[str, Any], bool]:
        """Store one normalized receipt, returning ``(row, idempotent)``.

        A second delivery of byte-for-byte equivalent data is harmless.  A
        different receipt for the same job/suite/attempt is a conflict and is
        rejected instead of silently replacing evidence.
        """

        execution = payload["execution"]
        result = payload["result"]
        now = time.time()
        with self.connect() as connection:
            # Serialize the check-then-insert pair so duplicate deliveries from
            # concurrent final workflow steps resolve to one receipt rather
            # than leaking a UNIQUE constraint error to either caller.
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT * FROM test_runs WHERE job_id=? AND suite=? AND attempt=?",
                    (payload["job_id"], payload["suite"], payload["attempt"]),
                ).fetchone()
                if existing is not None:
                    if str(existing["digest"]) != digest:
                        raise ValueError("conflicting test result for job/suite/attempt")
                    connection.execute("COMMIT")
                    return self._json_row(existing), True
                cursor = connection.execute(
                    """
                    INSERT INTO test_runs(
                        job_id, repository, commit_sha, suite, workflow, attempt,
                        contract, execution_status, test_status, total, executed,
                        failed, skipped, coverage_json, critical_scenarios_json,
                        reports_json, payload_json, digest, started_at, finished_at, created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        int(payload["job_id"]),
                        payload["repository"],
                        payload["commit_sha"],
                        payload["suite"],
                        payload["workflow"],
                        int(payload["attempt"]),
                        payload["schema"],
                        execution["status"],
                        result["status"],
                        int(result["total"]),
                        int(result["executed"]),
                        int(result["failed"]),
                        int(result["skipped"]),
                        json.dumps(payload["coverage"], separators=(",", ":")),
                        json.dumps(payload["critical_scenarios"], separators=(",", ":")),
                        json.dumps(payload["reports"], separators=(",", ":")),
                        json.dumps(
                            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
                        ),
                        digest,
                        execution["started_at"],
                        execution.get("finished_at"),
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM test_runs WHERE id=?", (cursor.lastrowid,)
                ).fetchone()
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        if row is None:  # pragma: no cover - sqlite guarantees the inserted row
            raise RuntimeError("test result insert did not return a row")
        return self._json_row(row), False

    def record_test_report(
        self,
        payload: dict[str, Any],
        *,
        report: dict[str, Any],
        storage_path: str,
        size: int,
        sha256: str,
    ) -> tuple[dict[str, Any], bool]:
        """Record one persisted source report with conflict-safe delivery.

        The caller must write the file first and pass the measured byte count
        and digest.  A duplicate delivery with the same digest is harmless;
        different bytes for the same attempt/path are rejected.
        """

        now = time.time()
        path = str(report["path"])
        # A database receipt is only evidence after the immutable source file
        # has been durably written and re-measured.  Keep this invariant in the
        # store as well as in the HTTP handler so alternate callers cannot
        # create a green receipt for a missing or truncated file.
        source = Path(storage_path)
        if not source.is_file():
            raise ValueError("source report is not persisted")
        measured_size = source.stat().st_size
        if measured_size != int(size):
            raise ValueError("source report size does not match persisted file")
        measured_sha256 = hashlib.sha256(source.read_bytes()).hexdigest()
        if measured_sha256 != str(sha256).lower():
            raise ValueError("source report checksum does not match persisted file")
        if len(str(sha256)) != 64 or any(
            char not in "0123456789abcdefABCDEF" for char in str(sha256)
        ):
            raise ValueError("source report checksum is invalid")
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    """
                    SELECT * FROM test_reports
                    WHERE job_id=? AND suite=? AND attempt=? AND path=?
                    """,
                    (int(payload["job_id"]), str(payload["suite"]), int(payload["attempt"]), path),
                ).fetchone()
                if existing is not None:
                    if str(existing["sha256"]) != sha256 or int(existing["size"]) != int(size):
                        raise ValueError("conflicting source report for job/suite/attempt/path")
                    connection.execute("COMMIT")
                    return dict(existing), True
                cursor = connection.execute(
                    """
                    INSERT INTO test_reports(
                        job_id, run_id, repository, commit_sha, suite, workflow,
                        attempt, path, format, size, sha256, storage_path, created_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        int(payload["job_id"]),
                        int(payload.get("run_id") or 0),
                        str(payload["repository"]),
                        str(payload["commit_sha"]),
                        str(payload["suite"]),
                        str(payload["workflow"]),
                        int(payload["attempt"]),
                        path,
                        str(report.get("format") or "unknown"),
                        int(size),
                        sha256,
                        storage_path,
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM test_reports WHERE id=?", (cursor.lastrowid,)
                ).fetchone()
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        if row is None:  # pragma: no cover - sqlite guarantees the inserted row
            raise RuntimeError("source report insert did not return a row")
        return dict(row), False

    def test_reports_for_job(self, job_id: int) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM test_reports WHERE job_id=? ORDER BY created_at ASC, id ASC",
                (job_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _test_run_row(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        for key in ("coverage_json", "critical_scenarios_json", "reports_json"):
            raw = value.pop(key, "")
            value[key.removesuffix("_json")] = json.loads(raw) if raw else []
        payload_raw = value.pop("payload_json", "")
        payload = json.loads(payload_raw) if payload_raw else {}
        value["payload"] = payload if isinstance(payload, dict) else {}
        flags = value["payload"].get("flags", {})
        value["flags"] = flags if isinstance(flags, dict) else {}
        return value

    @staticmethod
    def _json_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        """Decode provider JSON while retaining the stable database fields."""

        value = dict(row)
        raw = value.pop("provider_response_json", "")
        try:
            provider_response = json.loads(raw) if raw else {}
        except (TypeError, json.JSONDecodeError):
            provider_response = {"raw": str(raw)}
        value["provider_response"] = (
            provider_response
            if isinstance(provider_response, dict)
            else {"value": provider_response}
        )
        return value

    @staticmethod
    def _quarantine_expired(flags: Any, *, now: datetime | None = None) -> bool:
        if not isinstance(flags, dict) or flags.get("quarantined") is not True:
            return False
        expiry = flags.get("quarantine_until")
        if not isinstance(expiry, str) or not expiry:
            return True
        try:
            parsed = datetime.fromisoformat(expiry.replace("Z", "+00:00"))
        except ValueError:
            return True
        if parsed.tzinfo is None:
            return True
        return parsed <= (now or datetime.now(UTC))

    @staticmethod
    def _quality_metadata(run: dict[str, Any]) -> dict[str, Any]:
        flags = run.get("flags") if isinstance(run.get("flags"), dict) else {}
        critical = run.get("critical_scenarios")
        critical_blocked = isinstance(critical, list) and any(
            not isinstance(scenario, dict) or scenario.get("status") != "passed"
            for scenario in critical
        )
        quarantine_expired = Store._quarantine_expired(flags)
        return {
            "flags": flags,
            "quarantine_expired": quarantine_expired,
            "quality_status": (
                "blocked"
                if critical_blocked or quarantine_expired
                else str(run.get("test_status", "unknown"))
            ),
        }

    @staticmethod
    def _summary_run(run: dict[str, Any]) -> dict[str, Any]:
        """Return a bounded operator-facing history item.

        The immutable payload remains available from the detail endpoint.  The
        summary is polled by the Platform screen, so omit the duplicated raw
        envelope while retaining counts, coverage, critical scenarios and
        report locators needed to explain a result.
        """

        return {
            key: run[key]
            for key in (
                "id",
                "job_id",
                "repository",
                "commit_sha",
                "suite",
                "workflow",
                "attempt",
                "contract",
                "execution_status",
                "test_status",
                "total",
                "executed",
                "failed",
                "skipped",
                "coverage",
                "critical_scenarios",
                "reports",
                "digest",
                "started_at",
                "finished_at",
                "created_at",
            )
            if key in run
        } | Store._quality_metadata(run)

    def test_run(self, run_id: int) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute("SELECT * FROM test_runs WHERE id=?", (run_id,)).fetchone()
        return self._test_run_row(row) if row is not None else None

    def test_runs_for_job(self, job_id: int) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM test_runs WHERE job_id=? ORDER BY created_at ASC, id ASC", (job_id,)
            ).fetchall()
        return [self._test_run_row(row) for row in rows]

    def list_test_runs(
        self,
        *,
        repository: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> tuple[list[dict[str, Any]], int]:
        clauses: list[str] = []
        values: list[Any] = []
        if repository:
            clauses.append("repository=?")
            values.append(repository)
        if status:
            clauses.append("test_status=?")
            values.append(status)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as connection:
            count_query = f"SELECT COUNT(*) FROM test_runs{where}"  # noqa: S608 - clauses are fixed predicates built above.
            total = int(connection.execute(count_query, values).fetchone()[0])
            list_query = (
                f"SELECT * FROM test_runs{where} "  # noqa: S608 - clauses are fixed predicates built above.
                "ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?"
            )
            rows = connection.execute(
                list_query,
                [*values, max(1, min(limit, 200)), max(0, offset)],
            ).fetchall()
        return [self._test_run_row(row) for row in rows], total

    def test_summary(self, catalog: list[dict[str, Any]] | None = None) -> dict[str, Any]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM test_runs ORDER BY created_at DESC, id DESC"
            ).fetchall()
            job_counts = {
                str(row["status"]): int(row["count"])
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM jobs GROUP BY status"
                ).fetchall()
            }
            schedule_rows = connection.execute(
                """
                SELECT repository, workflow, suite, ref, interval_seconds,
                       next_run_at, enabled, last_dispatch_at, last_error
                FROM test_schedules
                ORDER BY repository, workflow, suite, ref
                """
            ).fetchall()
        runs = [self._test_run_row(row) for row in rows]
        counts = {status: 0 for status in ("passed", "failed", "not_run")}
        blocked = sum(
            1 for run in runs if self._quality_metadata(run)["quality_status"] == "blocked"
        )
        projects: dict[str, dict[str, Any]] = {}
        for run in runs:
            status = str(run["test_status"])
            if status in counts:
                counts[status] += 1
            project = projects.setdefault(
                str(run["repository"]), {"repository": run["repository"], "runs": []}
            )
            project["runs"].append(run)
        for row in schedule_rows:
            repository = str(row["repository"])
            project = projects.setdefault(repository, {"repository": repository, "runs": []})
            project.setdefault("schedules", []).append(self._schedule_row(row))
        # When the controller has a server-owned project catalog, seed every
        # active project before folding in receipts.  A missing receipt is an
        # explicit unknown/not-configured state, never an implicit green.
        for entry in catalog or []:
            repository = str(entry.get("repository") or "")
            if not repository:
                continue
            project = projects.setdefault(repository, {"repository": repository, "runs": []})
            required_suites = [
                str(value) for value in entry.get("required_suites", []) if str(value).strip()
            ]
            project["required_suites"] = sorted(set(required_suites))
            project["configured"] = bool(entry.get("configured", bool(required_suites)))
            if entry.get("current_sha"):
                project["current_sha"] = str(entry["current_sha"]).lower()
            if "coverage_required" in entry:
                project["coverage_required"] = bool(entry["coverage_required"])
            if entry.get("coverage_minimum") is not None:
                project["coverage_minimum"] = float(entry["coverage_minimum"])
            critical_required = entry.get("critical_scenarios_required", [])
            if isinstance(critical_required, str):
                critical_required = [critical_required]
            if isinstance(critical_required, (list, tuple)):
                project["critical_scenarios_required"] = sorted(
                    {str(value).strip() for value in critical_required if str(value).strip()}
                )
        for project in projects.values():
            latest: dict[str, dict[str, Any]] = {}
            for run in project["runs"]:
                latest.setdefault(str(run["suite"]), run)
            project["latest"] = [run | self._quality_metadata(run) for run in latest.values()]
            required = set(project.get("required_suites", []))
            latest_by_suite = {str(run["suite"]): run for run in project["latest"]}
            missing = sorted(required.difference(latest_by_suite))
            stale = bool(
                project.get("current_sha")
                and any(
                    str(run.get("commit_sha", "")).lower() != project["current_sha"]
                    for run in latest_by_suite.values()
                )
            )
            project["missing_suites"] = missing
            project["stale"] = stale
            required_runs = [
                latest_by_suite[suite] for suite in required if suite in latest_by_suite
            ]
            execution_blocked = any(
                str(run.get("execution_status"))
                in {"queued", "running", "error", "timeout", "cancelled"}
                for run in required_runs
            )
            failed_result = any(
                str(run.get("test_status")) == "failed"
                or str(run.get("quality_status")) == "blocked"
                or int(run.get("executed") or 0) <= 0
                for run in required_runs
            )
            not_run = any(str(run.get("test_status")) == "not_run" for run in required_runs)
            coverage_unknown = False
            coverage_below_minimum = False
            if project.get("coverage_required"):
                for run in required_runs:
                    coverage = run.get("coverage")
                    entries = coverage if isinstance(coverage, list) else []
                    measured: list[float] = []
                    for coverage_item in entries:
                        if not isinstance(coverage_item, dict):
                            continue
                        percentage = coverage_item.get("percentage")
                        if (
                            coverage_item.get("status") == "measured"
                            and isinstance(percentage, (int, float))
                        ):
                            measured.append(float(percentage))
                    if not measured:
                        coverage_unknown = True
                    minimum = project.get("coverage_minimum")
                    if minimum is not None and measured and min(measured) < float(minimum):
                        coverage_below_minimum = True
            critical_required = set(project.get("critical_scenarios_required", []))
            critical_unknown = False
            if critical_required:
                for run in required_runs:
                    scenarios = {
                        str(item.get("id")): str(item.get("status"))
                        for item in (run.get("critical_scenarios") or [])
                        if isinstance(item, dict) and item.get("id")
                    }
                    if any(
                        scenarios.get(identifier) != "passed" for identifier in critical_required
                    ):
                        critical_unknown = True
            project["readiness_reasons"] = {
                "missing_suites": missing,
                "stale_sha": stale,
                "execution_blocked": execution_blocked,
                "failed_result": failed_result,
                "not_run": not_run,
                "coverage_unknown": coverage_unknown,
                "coverage_below_minimum": coverage_below_minimum,
                "critical_scenarios_blocked": critical_unknown,
            }
            if project.get("configured") is False:
                readiness = "not_configured"
            elif missing or stale or not latest_by_suite or not project.get("current_sha"):
                readiness = "unknown"
            elif execution_blocked:
                readiness = "runner_blocked"
            elif (
                failed_result
                or not_run
                or coverage_unknown
                or coverage_below_minimum
                or critical_unknown
            ):
                readiness = "failed" if (failed_result or coverage_below_minimum) else "unknown"
            else:
                readiness = "ready"
            project["readiness"] = readiness
            project["history"] = [self._summary_run(run) for run in project["runs"][:20]]
            project.setdefault("schedules", [])
            enabled_schedules = [
                schedule
                for schedule in project["schedules"]
                if schedule.get("enabled") is True
                and isinstance(schedule.get("next_run_at"), (int, float))
            ]
            project["next_run_at"] = (
                min(float(schedule["next_run_at"]) for schedule in enabled_schedules)
                if enabled_schedules
                else None
            )
            project.pop("runs", None)
        return {
            "schema": "qdev-test-summary-v1",
            "generated_at": time.time(),
            "runs_total": len(runs),
            "passed": counts["passed"],
            "failed": counts["failed"],
            "not_run": counts["not_run"],
            "blocked": blocked,
            "jobs": job_counts,
            "projects": sorted(projects.values(), key=lambda item: str(item["repository"])),
        }

    def request_test_retry(self, job_id: int, requested_by: str) -> bool:
        with self.connect() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO test_retry_requests(job_id, requested_at, requested_by) "
                "VALUES(?,?,?)",
                (job_id, time.time(), requested_by[:256]),
            )
        return cursor.rowcount == 1

    def retry_attempt(
        self,
        *,
        request_id: str,
        source_job_id: int,
        repository: str,
        source_run_id: int,
        source_job_attempt: int,
        expected_sha: str,
        requested_by: str,
        reason: str,
    ) -> tuple[dict[str, Any], bool]:
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT * FROM test_retry_attempts WHERE request_id=?", (request_id,)
                ).fetchone()
                if existing is not None:
                    connection.execute("COMMIT")
                    return self._json_row(existing), True
                cursor = connection.execute(
                    """
                    INSERT INTO test_retry_attempts(
                        request_id, source_job_id, repository, source_run_id,
                        source_job_attempt, expected_sha, requested_by, reason,
                        state, created_at, updated_at
                    ) VALUES(?,?,?,?,?,?,?,?, 'requested', ?, ?)
                    """,
                    (
                        request_id,
                        int(source_job_id),
                        repository,
                        int(source_run_id),
                        int(source_job_attempt),
                        expected_sha,
                        requested_by[:256],
                        reason[:512],
                        now,
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM test_retry_attempts WHERE id=?", (cursor.lastrowid,)
                ).fetchone()
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        if row is None:  # pragma: no cover
            raise RuntimeError("retry attempt insert did not return a row")
        return self._json_row(row), False

    def update_retry_attempt(
        self,
        request_id: str,
        *,
        state: str,
        provider_response: dict[str, Any] | None = None,
        provider_run_id: int | None = None,
        provider_job_id: int | None = None,
    ) -> dict[str, Any] | None:
        if state not in {"requested", "dispatched", "ambiguous", "completed", "error"}:
            raise ValueError("invalid retry attempt state")
        now = time.time()
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT provider_response_json FROM test_retry_attempts WHERE request_id=?",
                (request_id,),
            ).fetchone()
            provider_payload = provider_response
            if provider_payload is None and existing is not None:
                try:
                    decoded = json.loads(str(existing["provider_response_json"] or "{}"))
                    provider_payload = decoded if isinstance(decoded, dict) else {}
                except json.JSONDecodeError:
                    provider_payload = {}
            connection.execute(
                """
                UPDATE test_retry_attempts
                SET state=?, provider_response_json=?, provider_run_id=?,
                    provider_job_id=?, updated_at=?
                WHERE request_id=?
                """,
                (
                    state,
                    json.dumps(provider_payload or {}, separators=(",", ":")),
                    provider_run_id,
                    provider_job_id,
                    now,
                    request_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM test_retry_attempts WHERE request_id=?", (request_id,)
            ).fetchone()
        return self._json_row(row) if row is not None else None

    def complete_retry_for_provider_job(
        self, provider_job_id: int, conclusion: str
    ) -> dict[str, Any] | None:
        """Close the durable retry attempt when its new provider job completes."""

        if provider_job_id < 1:
            return None
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM test_retry_attempts WHERE provider_job_id=?",
                (provider_job_id,),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            try:
                provider_payload = json.loads(str(row["provider_response_json"] or "{}"))
            except json.JSONDecodeError:
                provider_payload = {}
            if not isinstance(provider_payload, dict):
                provider_payload = {}
            provider_payload["conclusion"] = str(conclusion)[:128]
            connection.execute(
                "UPDATE test_retry_attempts SET state='completed', provider_response_json=?, "
                "updated_at=? WHERE provider_job_id=? AND state IN "
                "('requested','dispatched','ambiguous')",
                (json.dumps(provider_payload, separators=(",", ":")), now, provider_job_id),
            )
            updated = connection.execute(
                "SELECT * FROM test_retry_attempts WHERE provider_job_id=?",
                (provider_job_id,),
            ).fetchone()
            connection.execute("COMMIT")
        return self._json_row(updated) if updated is not None else None

    def retry_attempts_for_job(self, job_id: int) -> list[dict[str, Any]]:
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT * FROM test_retry_attempts WHERE source_job_id=? "
                "ORDER BY created_at ASC, id ASC",
                (job_id,),
            ).fetchall()
        return [self._json_row(row) for row in rows]

    def list_retry_attempts(self, *, states: tuple[str, ...] | None = None) -> list[dict[str, Any]]:
        values: list[Any] = []
        query = "SELECT * FROM test_retry_attempts"
        if states:
            values.extend(states)
            query += f" WHERE state IN ({','.join('?' for _ in states)})"
        query += " ORDER BY created_at ASC, id ASC"
        with self.connect() as connection:
            rows = connection.execute(query, values).fetchall()  # noqa: S608 - predicates are parameterized.
        return [self._json_row(row) for row in rows]

    def link_retry_provider_job(
        self,
        *,
        repository: str,
        expected_sha: str,
        provider_run_id: int,
        provider_job_id: int,
    ) -> dict[str, Any] | None:
        """Bind a newly delivered provider job to one outstanding retry.

        GitHub gives a rerun a new run/job identity, so it cannot be matched by
        the source job id.  The expected SHA is immutable; only a single
        outstanding retry for that repository/SHA may be linked implicitly.
        Ambiguous rows remain visible for an operator to reconcile explicitly.
        """

        if provider_run_id < 1 or provider_job_id < 1:
            return None
        normalized_sha = expected_sha.lower()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT * FROM test_retry_attempts WHERE provider_run_id=? "
                    "AND provider_job_id=?",
                    (provider_run_id, provider_job_id),
                ).fetchone()
                if existing is not None:
                    connection.execute("COMMIT")
                    return self._json_row(existing)
                candidates = connection.execute(
                    "SELECT * FROM test_retry_attempts WHERE repository=? "
                    "AND lower(expected_sha)=? AND state IN ('requested','dispatched','ambiguous') "
                    "ORDER BY created_at DESC, id DESC",
                    (repository, normalized_sha),
                ).fetchall()
                if len(candidates) != 1:
                    connection.execute("COMMIT")
                    return None
                request_id = str(candidates[0]["request_id"])
                now = time.time()
                connection.execute(
                    "UPDATE test_retry_attempts SET state='dispatched', "
                    "provider_run_id=?, provider_job_id=?, updated_at=? WHERE request_id=?",
                    (provider_run_id, provider_job_id, now, request_id),
                )
                row = connection.execute(
                    "SELECT * FROM test_retry_attempts WHERE request_id=?", (request_id,)
                ).fetchone()
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        return self._json_row(row) if row is not None else None

    def create_dispatch_intent(
        self,
        *,
        intent_id: str,
        repository: str,
        workflow: str,
        suite: str,
        ref: str,
        installation_id: int = 0,
        slot: float,
        expected_sha: str | None,
        correlation_id: str,
    ) -> tuple[dict[str, Any], bool]:
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                existing = connection.execute(
                    "SELECT * FROM test_dispatch_intents WHERE correlation_id=?",
                    (correlation_id,),
                ).fetchone()
                if existing is not None:
                    connection.execute("COMMIT")
                    return dict(existing), True
                connection.execute(
                    """
                    INSERT INTO test_dispatch_intents(
                        id, repository, workflow, suite, ref, installation_id, slot, expected_sha,
                        correlation_id, state, created_at, updated_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,'pending',?,?)
                    """,
                    (
                        intent_id,
                        repository,
                        workflow,
                        suite,
                        ref,
                        int(installation_id),
                        float(slot),
                        expected_sha,
                        correlation_id,
                        now,
                        now,
                    ),
                )
                row = connection.execute(
                    "SELECT * FROM test_dispatch_intents WHERE id=?", (intent_id,)
                ).fetchone()
                connection.execute("COMMIT")
            except Exception:
                connection.execute("ROLLBACK")
                raise
        if row is None:  # pragma: no cover
            raise RuntimeError("dispatch intent insert did not return a row")
        return dict(row), False

    def update_dispatch_intent(
        self,
        intent_id: str,
        *,
        state: str,
        provider_response: dict[str, Any] | None = None,
        provider_run_id: int | None = None,
        provider_job_id: int | None = None,
        error: str | None = None,
    ) -> dict[str, Any] | None:
        if state not in {"pending", "dispatched", "ambiguous", "error"}:
            raise ValueError("invalid dispatch intent state")
        now = time.time()
        with self.connect() as connection:
            existing = connection.execute(
                "SELECT provider_response_json FROM test_dispatch_intents WHERE id=?",
                (intent_id,),
            ).fetchone()
            provider_payload = provider_response
            if provider_payload is None and existing is not None:
                try:
                    decoded = json.loads(str(existing["provider_response_json"] or "{}"))
                    provider_payload = decoded if isinstance(decoded, dict) else {}
                except json.JSONDecodeError:
                    provider_payload = {}
            connection.execute(
                """
                UPDATE test_dispatch_intents
                SET state=?, provider_response_json=?, provider_run_id=?,
                    provider_job_id=?, last_error=?, updated_at=?
                WHERE id=?
                """,
                (
                    state,
                    json.dumps(provider_payload or {}, separators=(",", ":")),
                    provider_run_id,
                    provider_job_id,
                    (error or "")[:4000] or None,
                    now,
                    intent_id,
                ),
            )
            row = connection.execute(
                "SELECT * FROM test_dispatch_intents WHERE id=?", (intent_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def begin_dispatch_intent(self, intent_id: str) -> dict[str, Any] | None:
        """Atomically reserve a pending intent for one provider call.

        ``ambiguous`` is deliberate: the provider request may have succeeded
        immediately before a controller crash.  A restarted scheduler can
        reconcile that state, but it must never issue a blind second dispatch.
        """

        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                """
                UPDATE test_dispatch_intents
                SET state='ambiguous', last_error='provider request in flight', updated_at=?
                WHERE id=? AND state='pending'
                """,
                (now, intent_id),
            )
            row = connection.execute(
                "SELECT * FROM test_dispatch_intents WHERE id=?", (intent_id,)
            ).fetchone()
            connection.execute("COMMIT")
        if updated.rowcount != 1 or row is None:
            return None
        return dict(row)

    def dispatch_intent(self, correlation_id: str) -> dict[str, Any] | None:
        with self.connect() as connection:
            row = connection.execute(
                "SELECT * FROM test_dispatch_intents WHERE correlation_id=?", (correlation_id,)
            ).fetchone()
        return dict(row) if row is not None else None

    def list_dispatch_intents(
        self, *, states: tuple[str, ...] | None = None
    ) -> list[dict[str, Any]]:
        values: list[Any] = []
        if states:
            values.extend(states)
        with self.connect() as connection:
            query = "SELECT * FROM test_dispatch_intents"
            if states:
                query += f" WHERE state IN ({','.join('?' for _ in states)})"
            query += " ORDER BY created_at ASC, id ASC"
            rows = connection.execute(query, values).fetchall()  # noqa: S608 - predicates are parameterized.
        return [self._json_row(row) for row in rows]

    def active_test_job_count(self) -> int:
        with self.connect() as connection:
            row = connection.execute(
                """
                SELECT COUNT(*) FROM jobs
                WHERE status IN ('pending','claimed','running')
                  AND json_extract(payload_json, '$.workflow_job') IS NOT NULL
                """
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def clear_test_retry(self, job_id: int) -> None:
        with self.connect() as connection:
            connection.execute("DELETE FROM test_retry_requests WHERE job_id=?", (job_id,))

    def upsert_test_schedule(
        self,
        *,
        repository: str,
        workflow: str,
        suite: str,
        installation_id: int,
        ref: str,
        interval_seconds: int,
        next_run_at: float | None = None,
        enabled: bool = True,
    ) -> dict[str, Any]:
        """Create or update one recurring test dispatch registration."""

        now = time.time()
        scheduled_at = now if next_run_at is None else float(next_run_at)
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO test_schedules(
                    repository, workflow, suite, installation_id, ref,
                    interval_seconds, next_run_at, enabled, created_at, updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(repository, workflow, suite, ref) DO UPDATE SET
                    installation_id=excluded.installation_id,
                    interval_seconds=excluded.interval_seconds,
                    next_run_at=excluded.next_run_at,
                    enabled=excluded.enabled,
                    last_error=NULL,
                    updated_at=excluded.updated_at
                """,
                (
                    repository,
                    workflow,
                    suite,
                    int(installation_id),
                    ref,
                    int(interval_seconds),
                    scheduled_at,
                    1 if enabled else 0,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                """
                SELECT * FROM test_schedules
                WHERE repository=? AND workflow=? AND suite=? AND ref=?
                """,
                (repository, workflow, suite, ref),
            ).fetchone()
        if row is None:  # pragma: no cover - sqlite guarantees the row
            raise RuntimeError("test schedule upsert did not return a row")
        return self._schedule_row(row)

    @staticmethod
    def _schedule_row(row: sqlite3.Row | dict[str, Any]) -> dict[str, Any]:
        value = dict(row)
        value["enabled"] = bool(value.get("enabled"))
        return value

    def list_test_schedules(self, *, enabled: bool | None = None) -> list[dict[str, Any]]:
        clauses: list[str] = []
        values: list[Any] = []
        if enabled is not None:
            clauses.append("enabled=?")
            values.append(1 if enabled else 0)
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self.connect() as connection:
            query = f"SELECT * FROM test_schedules{where} ORDER BY repository, workflow, suite, ref"  # noqa: S608 - predicates are fixed above.
            rows = connection.execute(query, values).fetchall()
        return [self._schedule_row(row) for row in rows]

    def due_test_schedules(
        self, *, now: float | None = None, limit: int = 20
    ) -> list[dict[str, Any]]:
        current = time.time() if now is None else float(now)
        bounded_limit = max(1, min(int(limit), 100))
        with self.connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM test_schedules
                WHERE enabled=1 AND next_run_at<=?
                ORDER BY next_run_at, repository, workflow, suite, ref
                LIMIT ?
                """,
                (current, bounded_limit),
            ).fetchall()
        return [self._schedule_row(row) for row in rows]

    def claim_test_schedule(
        self,
        *,
        repository: str,
        workflow: str,
        suite: str,
        ref: str,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        """Atomically reserve a due schedule and advance its next run."""

        current = time.time() if now is None else float(now)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM test_schedules
                WHERE repository=? AND workflow=? AND suite=? AND ref=?
                  AND enabled=1 AND next_run_at<=?
                """,
                (repository, workflow, suite, ref, current),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            next_run_at = max(current, float(row["next_run_at"])) + int(row["interval_seconds"])
            updated = connection.execute(
                """
                UPDATE test_schedules
                SET next_run_at=?, last_dispatch_at=?, last_error=NULL, updated_at=?
                WHERE repository=? AND workflow=? AND suite=? AND ref=?
                  AND enabled=1 AND next_run_at<=?
                """,
                (
                    next_run_at,
                    current,
                    current,
                    repository,
                    workflow,
                    suite,
                    ref,
                    current,
                ),
            )
            connection.execute("COMMIT")
            if updated.rowcount != 1:
                return None
        claimed = dict(row)
        claimed["next_run_at"] = next_run_at
        claimed["last_dispatch_at"] = current
        claimed["last_error"] = None
        return self._schedule_row(claimed)

    def advance_test_schedule(
        self,
        *,
        repository: str,
        workflow: str,
        suite: str,
        ref: str,
        due_at: float,
        now: float | None = None,
    ) -> dict[str, Any] | None:
        """Advance a schedule only after the provider dispatch is confirmed."""

        current = time.time() if now is None else float(now)
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                """
                SELECT * FROM test_schedules
                WHERE repository=? AND workflow=? AND suite=? AND ref=?
                """,
                (repository, workflow, suite, ref),
            ).fetchone()
            if row is None:
                connection.execute("COMMIT")
                return None
            # Do not move a schedule backwards if an operator edited it while
            # a provider request was in flight.  The due slot is the stable
            # correlation key; only an unchanged/older slot is advanced.
            next_run_at = float(row["next_run_at"])
            if next_run_at <= float(due_at) + 1e-6:
                next_run_at = max(current, float(due_at)) + int(row["interval_seconds"])
            updated = connection.execute(
                """
                UPDATE test_schedules
                SET next_run_at=?, last_dispatch_at=?, last_error=NULL, updated_at=?
                WHERE repository=? AND workflow=? AND suite=? AND ref=?
                """,
                (
                    next_run_at,
                    current,
                    current,
                    repository,
                    workflow,
                    suite,
                    ref,
                ),
            )
            connection.execute("COMMIT")
            if updated.rowcount != 1:
                return None
        value = dict(row)
        value["next_run_at"] = next_run_at
        value["last_dispatch_at"] = current
        value["last_error"] = None
        return self._schedule_row(value)

    def record_test_schedule_error(
        self, *, repository: str, workflow: str, suite: str, ref: str, error: str
    ) -> None:
        now = time.time()
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE test_schedules SET last_error=?, updated_at=?
                WHERE repository=? AND workflow=? AND suite=? AND ref=?
                """,
                (error[:4000], now, repository, workflow, suite, ref),
            )

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

    @staticmethod
    def _transition_infrastructure(
        connection: sqlite3.Connection, job_id: int, reason: str, now: float
    ) -> bool:
        """Retry one infrastructure failure once, then make it terminal.

        This helper is called while the caller owns an IMMEDIATE transaction so
        a worker heartbeat, lease recovery and broker error cannot race into
        duplicate retries.  Assertion/test failures use ``fail_if_active``
        and never enter this path.
        """

        row = connection.execute(
            "SELECT status, infra_retries FROM jobs WHERE job_id=?", (job_id,)
        ).fetchone()
        if row is None or str(row["status"]) not in {"claimed", "running"}:
            return False
        retries = int(row["infra_retries"] or 0)
        if retries < MAX_INFRASTRUCTURE_RETRIES:
            connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL,
                    claim_scope_id=NULL, profile=NULL,
                    claimed_at=NULL, completed_at=NULL, updated_at=?,
                    infra_retries=?, result=?
                WHERE job_id=? AND status IN ('claimed','running')
                """,
                (
                    now,
                    retries + 1,
                    f"infrastructure retry {retries + 1}/{MAX_INFRASTRUCTURE_RETRIES}: {reason}"[
                        :4000
                    ],
                    job_id,
                ),
            )
        else:
            connection.execute(
                """
                UPDATE jobs SET status='failed', worker_name=NULL, profile=NULL,
                    claimed_at=NULL, completed_at=?, updated_at=?,
                    result=?
                WHERE job_id=? AND status IN ('claimed','running')
                """,
                (
                    now,
                    now,
                    f"infrastructure retry exhausted ({MAX_INFRASTRUCTURE_RETRIES}): {reason}"[
                        :4000
                    ],
                    job_id,
                ),
            )
        return True

    def requeue_infrastructure(self, job_id: int, reason: str) -> bool:
        """Bound infrastructure recovery to one automatic retry per job."""

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            changed = self._transition_infrastructure(connection, job_id, reason, time.time())
            connection.execute("COMMIT")
        return changed

    def requeue_active(self, job_id: int, reason: str) -> bool:
        return self.requeue_infrastructure(job_id, reason)

    def requeue(self, job_id: int, reason: str) -> None:
        self.requeue_infrastructure(job_id, reason)

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
                capacity_allowed = detail.get("allowed", True) is True
                workers.append(
                    dict(row)
                    | {
                        "tier": detail.get("tier", "unknown"),
                        "capacity_allowed": capacity_allowed,
                        "concurrency": concurrency,
                        "slots_available": slots_available,
                        "available": capacity_allowed and slots_available > 0,
                    }
                )
        return {"jobs": counts, "workers": workers, "now": time.time()}
