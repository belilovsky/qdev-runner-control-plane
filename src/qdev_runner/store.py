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
CREATE TABLE IF NOT EXISTS worker_recovery_holds (
    worker_name TEXT PRIMARY KEY REFERENCES workers(name),
    operation_fence TEXT NOT NULL UNIQUE,
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS controller_operation_hold (
    singleton INTEGER PRIMARY KEY CHECK(singleton=1),
    operation_fence TEXT NOT NULL UNIQUE,
    target_id TEXT NOT NULL,
    state_revision TEXT NOT NULL,
    created_at REAL NOT NULL
);
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
            columns = {
                str(row["name"]) for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
            }
            if "claim_scope_id" not in columns:
                connection.execute("ALTER TABLE jobs ADD COLUMN claim_scope_id TEXT")
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
        payload_json = json.dumps(job.payload, separators=(",", ":"))
        created_at = _workflow_job_created_at(payload_json) or now
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
                    payload_json,
                    created_at,
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
            AND NOT EXISTS (
                SELECT 1 FROM worker_recovery_holds WHERE worker_name=workers.name
            )
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
        head_sha: str | None = None,
        primary_max_age_seconds: int = 90,
        claim_scope: ClaimScope | None = None,
    ) -> dict[str, Any] | None:
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute(
                "SELECT 1 FROM controller_operation_hold WHERE singleton=1"
            ).fetchone():
                connection.execute("COMMIT")
                return None
            if connection.execute(
                "SELECT 1 FROM worker_recovery_holds WHERE worker_name=?", (worker_name,)
            ).fetchone():
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

    def acquire_recovery_hold_state(
        self, worker_name: str, operation_fence: str
    ) -> tuple[int, str]:
        """Fence an existing worker and atomically observe all controller-owned work.

        No queue rows are modified. A hold survives a broker crash; only the
        same operation may resume or release it. The host must independently
        verify that no runner/job process is active before a service restart.
        """
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            worker = connection.execute(
                "SELECT active_jobs FROM workers WHERE name=?", (worker_name,)
            ).fetchone()
            if worker is None:
                raise ValueError("recovery worker is not registered")
            hold = connection.execute(
                "SELECT operation_fence FROM worker_recovery_holds WHERE worker_name=?",
                (worker_name,),
            ).fetchone()
            if hold is not None and hold["operation_fence"] != operation_fence:
                raise ValueError("worker recovery is already fenced")
            running = connection.execute(
                "SELECT COUNT(*) FROM jobs WHERE worker_name=? AND status IN ('claimed','running')",
                (worker_name,),
            ).fetchone()[0]
            active = max(int(worker["active_jobs"]), int(running))
            revision = hashlib.sha256(
                json.dumps(
                    {
                        "worker_name": worker_name,
                        "operation_fence": operation_fence,
                        "heartbeat_active_jobs": int(worker["active_jobs"]),
                        "controller_active_jobs": int(running),
                    },
                    ensure_ascii=True,
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode()
            ).hexdigest()
            if active == 0:
                connection.execute(
                    "INSERT OR IGNORE INTO worker_recovery_holds VALUES(?,?,?)",
                    (worker_name, operation_fence, time.time()),
                )
            connection.execute("COMMIT")
            return active, revision

    def acquire_recovery_hold(self, worker_name: str, operation_fence: str) -> int:
        active, _revision = self.acquire_recovery_hold_state(worker_name, operation_fence)
        return active

    def worker_recovery_observation(self, worker_name: str, operation_fence: str) -> dict[str, Any]:
        """Return controller-owned worker state while an exact recovery hold exists.

        The recovery executor uses this snapshot before invoking the privileged
        adapter and again afterwards.  Adapter output is deliberately excluded:
        only a later broker heartbeat can prove that the recovered worker has
        rejoined with usable capacity.
        """

        with self.connect() as connection:
            connection.execute("BEGIN")
            worker = connection.execute(
                "SELECT profiles_json, active_jobs, last_seen, detail_json "
                "FROM workers WHERE name=?",
                (worker_name,),
            ).fetchone()
            hold = connection.execute(
                "SELECT operation_fence FROM worker_recovery_holds WHERE worker_name=?",
                (worker_name,),
            ).fetchone()
            connection.execute("COMMIT")
        if worker is None:
            raise ValueError("recovery worker is not registered")
        if hold is None or hold["operation_fence"] != operation_fence:
            raise ValueError("worker recovery hold is unavailable")
        profiles = json.loads(worker["profiles_json"])
        detail = json.loads(worker["detail_json"])
        if (
            not isinstance(profiles, list)
            or not profiles
            or not all(isinstance(profile, str) and profile for profile in profiles)
            or not isinstance(detail, dict)
        ):
            raise ValueError("worker recovery observation is invalid")
        concurrency = _worker_concurrency(detail)
        active_jobs = int(worker["active_jobs"])
        return {
            "worker_name": worker_name,
            "profiles": tuple(profiles),
            "active_jobs": active_jobs,
            "last_seen": float(worker["last_seen"]),
            "allowed": detail.get("allowed", True) is True,
            "concurrency": concurrency,
            "slots_available": max(0, concurrency - active_jobs),
            "authenticated_certificate_sha256": detail.get("authenticated_certificate_sha256"),
        }

    def acquire_controller_hold(
        self, operation_fence: str, target_id: str, *, exclude_job_id: int
    ) -> tuple[int, str]:
        """Atomically stop new claims and attest the quiescent scheduler state.

        The hold is controller-owned and survives process failure.  A retry of
        the same operation receives the same revision; a different operation
        cannot replace it.  The caller signs the returned revision before it
        crosses the privileged boundary.
        """

        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT operation_fence, target_id, state_revision "
                "FROM controller_operation_hold WHERE singleton=1"
            ).fetchone()
            if existing is not None:
                if (
                    existing["operation_fence"] != operation_fence
                    or existing["target_id"] != target_id
                ):
                    connection.execute("ROLLBACK")
                    raise ValueError("controller scheduler is already fenced")
                connection.execute("COMMIT")
                return 0, str(existing["state_revision"])
            rows = connection.execute(
                "SELECT job_id, status, COALESCE(worker_name, '') AS worker_name, updated_at "
                "FROM jobs WHERE status IN ('claimed','running') AND job_id<>? "
                "ORDER BY job_id",
                (exclude_job_id,),
            ).fetchall()
            active = len(rows)
            snapshot = {
                "operation_fence": operation_fence,
                "target_id": target_id,
                "exclude_job_id": exclude_job_id,
                "active": [
                    [
                        int(row["job_id"]),
                        str(row["status"]),
                        str(row["worker_name"]),
                        row["updated_at"],
                    ]
                    for row in rows
                ],
            }
            revision = hashlib.sha256(
                json.dumps(
                    snapshot, ensure_ascii=True, sort_keys=True, separators=(",", ":")
                ).encode()
            ).hexdigest()
            if active == 0:
                connection.execute(
                    "INSERT INTO controller_operation_hold VALUES(1,?,?,?,?)",
                    (operation_fence, target_id, revision, time.time()),
                )
            connection.execute("COMMIT")
            return active, revision

    def release_controller_hold(self, operation_fence: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM controller_operation_hold WHERE singleton=1 AND operation_fence=?",
                (operation_fence,),
            )

    def release_recovery_hold(self, worker_name: str, operation_fence: str) -> None:
        with self.connect() as connection:
            connection.execute(
                "DELETE FROM worker_recovery_holds WHERE worker_name=? AND operation_fence=?",
                (worker_name, operation_fence),
            )

    def active_job_count(self, *, exclude_job_id: int | None = None) -> int:
        """Return controller-owned claimed/running work, optionally excluding itself."""

        with self.connect() as connection:
            if exclude_job_id is None:
                row = connection.execute(
                    "SELECT COUNT(*) FROM jobs WHERE status IN ('claimed','running')"
                ).fetchone()
            else:
                row = connection.execute(
                    "SELECT COUNT(*) FROM jobs WHERE status IN ('claimed','running') AND job_id<>?",
                    (exclude_job_id,),
                ).fetchone()
        return int(row[0])

    def health(self) -> dict[str, Any]:
        with self.connect() as connection:
            counts = {
                row["status"]: row["count"]
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM jobs GROUP BY status"
                ).fetchall()
            }
            held_workers = {
                row[0]
                for row in connection.execute("SELECT worker_name FROM worker_recovery_holds")
            }
            workers = []
            for row in connection.execute(
                "SELECT name, profiles_json, active_jobs, last_seen, detail_json FROM workers"
            ).fetchall():
                detail = json.loads(row["detail_json"])
                concurrency = _worker_concurrency(detail)
                active_jobs = int(row["active_jobs"])
                slots_available = max(0, concurrency - active_jobs)
                recovery_held = row["name"] in held_workers
                capacity_allowed = detail.get("allowed", True) is True and not recovery_held
                workers.append(
                    dict(row)
                    | {
                        "tier": detail.get("tier", "unknown"),
                        "capacity_allowed": capacity_allowed,
                        "concurrency": concurrency,
                        "slots_available": slots_available,
                        "available": capacity_allowed and slots_available > 0,
                        "recovery_held": recovery_held,
                    }
                )
        return {"jobs": counts, "workers": workers, "now": time.time()}
