from __future__ import annotations

import json
import math
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from .claim_scope import ClaimScope
from .models import QueuedJob

MINIMUM_QUEUE_TIMESTAMP = datetime(2020, 1, 1, tzinfo=UTC).timestamp()
QUEUE_RETRY_BASE_SECONDS = 30
QUEUE_RETRY_MAX_SECONDS = 300
KNOWN_PROFILES = frozenset({"qdev-ci", "qdev-ci-browser", "qdev-ci-docker"})
IMMUTABLE_QUEUE_MIGRATION = "20260827_immutable_github_fifo_v1"

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
    profile TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    claimed_at REAL,
    completed_at REAL,
    result TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    github_queued_at REAL,
    queue_sequence INTEGER,
    queue_time_source TEXT,
    required_profile TEXT,
    retry_not_before REAL NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS jobs_status_created_idx ON jobs(status, created_at);

CREATE TABLE IF NOT EXISTS workers (
    name TEXT PRIMARY KEY,
    profiles_json TEXT NOT NULL,
    active_jobs INTEGER NOT NULL,
    last_seen REAL NOT NULL,
    detail_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS schema_migrations (
    name TEXT PRIMARY KEY,
    applied_at REAL NOT NULL
);
"""


def _worker_concurrency(detail: dict[str, Any]) -> int:
    try:
        return max(1, int(detail.get("concurrency", 1)))
    except (TypeError, ValueError):
        return 1


def _disk_headroom_allowed(
    detail: dict[str, Any], profile_disk_mb: int | None
) -> bool:
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
        timestamp = datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(
            UTC
        ).timestamp()
    except (AttributeError, TypeError, ValueError, json.JSONDecodeError):
        return None
    return timestamp if _is_valid_queue_timestamp(timestamp) else None


def _profile_from_labels(labels_json: str) -> str | None:
    try:
        labels = {str(label).lower() for label in json.loads(labels_json)}
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    profiles = KNOWN_PROFILES.intersection(labels)
    return next(iter(profiles)) if len(profiles) == 1 else None


def _retry_delay(attempts: int) -> int:
    exponent = max(0, attempts - 1)
    return int(min(QUEUE_RETRY_BASE_SECONDS * (2**exponent), QUEUE_RETRY_MAX_SECONDS))


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")
            self._migrate_immutable_queue(connection)

    def _migrate_immutable_queue(self, connection: sqlite3.Connection) -> None:
        """Backfill immutable ordering keys from accepted webhook payloads.

        ``created_at`` deliberately remains the broker receive time.  Legacy
        rows without GitHub's signed timestamp get a labelled fallback rather
        than a silent timestamp repair.
        """
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(jobs)").fetchall()
        }
        additions = {
            "github_queued_at": "REAL",
            "queue_sequence": "INTEGER",
            "queue_time_source": "TEXT",
            "required_profile": "TEXT",
            "retry_not_before": "REAL NOT NULL DEFAULT 0",
        }
        connection.execute("BEGIN IMMEDIATE")
        try:
            for name, definition in additions.items():
                if name not in columns:
                    connection.execute(f"ALTER TABLE jobs ADD COLUMN {name} {definition}")

            rows = connection.execute(
                """
                SELECT job_id, payload_json, labels_json, profile, created_at, updated_at,
                    github_queued_at, queue_sequence, queue_time_source, required_profile
                FROM jobs
                WHERE github_queued_at IS NULL OR queue_sequence IS NULL
                   OR queue_time_source IS NULL OR required_profile IS NULL
                """
            ).fetchall()
            recovered: list[tuple[float, sqlite3.Row, str, str]] = []
            for row in rows:
                github_queued_at = _workflow_job_created_at(str(row["payload_json"]))
                if github_queued_at is not None:
                    source = "github_workflow_job_created_at"
                elif _is_valid_queue_timestamp(row["created_at"]):
                    github_queued_at = float(row["created_at"])
                    source = "legacy_received_at"
                elif _is_valid_queue_timestamp(row["updated_at"]):
                    github_queued_at = float(row["updated_at"])
                    source = "legacy_updated_at"
                else:
                    github_queued_at = time.time()
                    source = "migration_now"
                profile = str(row["profile"] or "").lower()
                if profile not in KNOWN_PROFILES:
                    profile = _profile_from_labels(str(row["labels_json"])) or "legacy-unclassified"
                recovered.append((github_queued_at, row, source, profile))

            next_sequence_row = connection.execute(
                "SELECT COALESCE(MAX(queue_sequence), 0) AS value FROM jobs"
            ).fetchone()
            next_sequence = int(next_sequence_row["value"])
            for github_queued_at, row, source, profile in sorted(
                recovered, key=lambda item: (item[0], int(item[1]["job_id"]))
            ):
                next_sequence += 1
                connection.execute(
                    """
                    UPDATE jobs SET github_queued_at=?, queue_sequence=?, queue_time_source=?,
                        required_profile=?, retry_not_before=COALESCE(retry_not_before, 0)
                    WHERE job_id=?
                    """,
                    (github_queued_at, next_sequence, source, profile, row["job_id"]),
                )

            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS jobs_queue_sequence_idx ON jobs(queue_sequence)"
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS jobs_claim_fifo_idx ON jobs(
                    status, required_profile, retry_not_before, github_queued_at, queue_sequence
                )
                """
            )
            connection.execute(
                """
                CREATE TRIGGER IF NOT EXISTS jobs_queue_key_immutable
                BEFORE UPDATE OF github_queued_at, queue_sequence, queue_time_source,
                    required_profile ON jobs
                FOR EACH ROW
                WHEN NEW.github_queued_at IS NOT OLD.github_queued_at
                   OR NEW.queue_sequence IS NOT OLD.queue_sequence
                   OR NEW.queue_time_source IS NOT OLD.queue_time_source
                   OR NEW.required_profile IS NOT OLD.required_profile
                BEGIN
                    SELECT RAISE(ABORT, 'immutable queue key');
                END
                """
            )
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations(name, applied_at) VALUES(?, ?)",
                (IMMUTABLE_QUEUE_MIGRATION, time.time()),
            )
            connection.execute("COMMIT")
        except Exception:
            connection.execute("ROLLBACK")
            raise

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
        required_profile = job.required_profile.lower() or _profile_from_labels(
            json.dumps(job.labels)
        )
        if required_profile not in KNOWN_PROFILES:
            raise ValueError("queued job requires exactly one supported profile")
        payload_json = json.dumps(job.payload, separators=(",", ":"))
        github_queued_at = _workflow_job_created_at(payload_json)
        queue_time_source = "github_workflow_job_created_at"
        if github_queued_at is None:
            github_queued_at = now
            queue_time_source = "received_at_fallback"
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            sequence_row = connection.execute(
                "SELECT COALESCE(MAX(queue_sequence), 0) AS value FROM jobs"
            ).fetchone()
            queue_sequence = int(sequence_row["value"]) + 1
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO jobs(
                    job_id, delivery_id, run_id, repository, repository_id,
                    installation_id, labels_json, head_sha, head_branch,
                    payload_json, status, created_at, updated_at, github_queued_at,
                    queue_sequence, queue_time_source, required_profile, retry_not_before
                ) VALUES(?,?,?,?,?,?,?,?,?,?, 'pending', ?,?,?,?,?,?,?)
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
                    now,
                    now,
                    github_queued_at,
                    queue_sequence,
                    queue_time_source,
                    required_profile,
                    now,
                ),
            )
            connection.execute("COMMIT")
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
        primary_max_age_seconds: int = 90,
        claim_scope: ClaimScope | None = None,
    ) -> dict[str, Any] | None:
        now = time.time()
        normalized_profiles = tuple(profile.lower() for profile in profiles)
        if not normalized_profiles:
            return None
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            selected = None
            selected_profile = None
            placeholders = ",".join("?" for _ in normalized_profiles)
            # A profile has its own immutable FIFO.  This lets a dedicated light
            # worker progress even while browser or Docker capacity is unavailable.
            query = """
                SELECT * FROM jobs
                WHERE status='pending' AND retry_not_before<=?
                  AND required_profile IN (PROFILE_BINDINGS)
                ORDER BY github_queued_at, queue_sequence
            """.replace("PROFILE_BINDINGS", placeholders)
            for row in connection.execute(query, (now, *normalized_profiles)):
                matching_profile = str(row["required_profile"])
                if claim_scope is not None and not claim_scope.permits(
                    int(row["job_id"]),
                    str(row["repository"]),
                    str(row["head_sha"]),
                    matching_profile,
                ):
                    continue
                required_disk_mb = (
                    profile_disk_mb.get(matching_profile) if profile_disk_mb is not None else None
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
                UPDATE jobs SET status='claimed', worker_name=?, profile=?, claimed_at=?,
                    updated_at=?, attempts=attempts+1
                WHERE job_id=? AND status='pending'
                """,
                (worker_name, selected_profile, now, now, selected["job_id"]),
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
            row = connection.execute(
                "SELECT attempts FROM jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            retry_not_before = now + _retry_delay(int(row["attempts"])) if row else now
            updated = connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL, profile=NULL,
                    claimed_at=NULL, retry_not_before=?, updated_at=?, result=?
                WHERE job_id=? AND status IN ('claimed','running')
                """,
                (retry_not_before, now, reason[:4000], job_id),
            )
        return updated.rowcount == 1

    def requeue(self, job_id: int, reason: str) -> None:
        now = time.time()
        with self.connect() as connection:
            row = connection.execute(
                "SELECT attempts FROM jobs WHERE job_id=?", (job_id,)
            ).fetchone()
            retry_not_before = now + _retry_delay(int(row["attempts"])) if row else now
            connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL, profile=NULL,
                    claimed_at=NULL, retry_not_before=?, updated_at=?, result=?
                WHERE job_id=? AND status='claimed'
                """,
                (retry_not_before, now, reason[:4000], job_id),
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
                connection.execute(
                    """
                    UPDATE jobs SET status='pending', worker_name=NULL, profile=NULL,
                        claimed_at=NULL, retry_not_before=?, updated_at=?,
                        result='worker no longer reports job'
                    WHERE worker_name=? AND status IN ('claimed','running')
                      AND updated_at<?
                      AND job_id NOT IN (SELECT value FROM json_each(?))
                    """,
                    (
                        now + QUEUE_RETRY_BASE_SECONDS,
                        now,
                        name,
                        now - 30,
                        json.dumps(active_job_ids),
                    ),
                )
            else:
                connection.execute(
                    """
                    UPDATE jobs SET status='pending', worker_name=NULL, profile=NULL,
                        claimed_at=NULL, retry_not_before=?, updated_at=?,
                        result='worker no longer reports job'
                    WHERE worker_name=? AND status IN ('claimed','running') AND updated_at<?
                    """,
                    (now + QUEUE_RETRY_BASE_SECONDS, now, name, now - 30),
                )
            connection.execute("COMMIT")

    def has_available_tier_slot(self, tier: str, max_age_seconds: int) -> bool:
        cutoff = time.time() - max_age_seconds
        with self.connect() as connection:
            return self._has_available_tier_slot(connection, tier, cutoff)

    def recover_stale_jobs(self, worker_timeout_seconds: int) -> int:
        cutoff = time.time() - worker_timeout_seconds
        now = time.time()
        with self.connect() as connection:
            updated = connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL, profile=NULL,
                    claimed_at=NULL, retry_not_before=?, updated_at=?, result='worker lease expired'
                WHERE status IN ('claimed','running') AND updated_at<?
                  AND (worker_name IS NULL OR worker_name NOT IN (
                    SELECT name FROM workers WHERE last_seen>=?
                  ))
                """,
                (now + QUEUE_RETRY_BASE_SECONDS, now, cutoff, cutoff),
            )
        return updated.rowcount

    def health(self) -> dict[str, Any]:
        now = time.time()
        with self.connect() as connection:
            counts = {
                row["status"]: row["count"]
                for row in connection.execute(
                    "SELECT status, COUNT(*) AS count FROM jobs GROUP BY status"
                ).fetchall()
            }
            pending_rows = connection.execute(
                """
                SELECT required_profile, COUNT(*) AS count, MIN(github_queued_at) AS oldest
                FROM jobs WHERE status='pending'
                GROUP BY required_profile
                """
            ).fetchall()
            pending_by_profile = {
                str(row["required_profile"]): int(row["count"])
                for row in pending_rows
            }
            oldest_timestamp = min(
                (float(row["oldest"]) for row in pending_rows if row["oldest"] is not None),
                default=None,
            )
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
        fresh_workers = [worker for worker in workers if now - worker["last_seen"] < 90]
        available_slots_by_profile: dict[str, int] = {}
        blocked_profiles: dict[str, str] = {}
        for profile, pending in pending_by_profile.items():
            compatible = [
                worker
                for worker in fresh_workers
                if profile in {str(item).lower() for item in json.loads(worker["profiles_json"])}
            ]
            slots = sum(
                int(worker["slots_available"])
                for worker in compatible
                if worker["capacity_allowed"]
            )
            available_slots_by_profile[profile] = slots
            if pending and slots == 0:
                if not compatible:
                    blocked_profiles[profile] = "no_fresh_compatible_worker"
                elif not any(worker["capacity_allowed"] for worker in compatible):
                    blocked_profiles[profile] = "capacity_blocked"
                else:
                    blocked_profiles[profile] = "no_free_slot"
        return {
            "jobs": counts,
            "workers": workers,
            "now": now,
            "oldest_pending_age_seconds": (
                max(0.0, now - oldest_timestamp) if oldest_timestamp is not None else None
            ),
            "pending_by_profile": pending_by_profile,
            "available_slots_by_profile": available_slots_by_profile,
            "blocked_profiles": blocked_profiles,
            "queue_schema_migration": IMMUTABLE_QUEUE_MIGRATION,
        }
