from __future__ import annotations

import json
import sqlite3
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .models import QueuedJob

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


class Store:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        with self.connect() as connection:
            connection.executescript(SCHEMA)
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("PRAGMA synchronous=FULL")

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
        primary_max_age_seconds: int = 90,
    ) -> dict[str, Any] | None:
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM jobs WHERE status='pending' ORDER BY created_at LIMIT 100"
            ).fetchall()
            selected = None
            selected_profile = None
            for row in rows:
                labels = {label.lower() for label in json.loads(row["labels_json"])}
                matching_profile = next(
                    (profile for profile in profiles if profile.lower() in labels), None
                )
                if matching_profile is None:
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
            updated = connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL, profile=NULL,
                    claimed_at=NULL, created_at=?, updated_at=?, result=?
                WHERE job_id=? AND status IN ('claimed','running')
                """,
                (now, now, reason[:4000], job_id),
            )
        return updated.rowcount == 1

    def requeue(self, job_id: int, reason: str) -> None:
        now = time.time()
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL, profile=NULL,
                    claimed_at=NULL, created_at=?, updated_at=?, result=?
                WHERE job_id=? AND status='claimed'
                """,
                (now, now, reason[:4000], job_id),
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
                        claimed_at=NULL, updated_at=?, result='worker no longer reports job'
                    WHERE worker_name=? AND status IN ('claimed','running')
                      AND updated_at<?
                      AND job_id NOT IN (SELECT value FROM json_each(?))
                    """,
                    (now, name, now - 30, json.dumps(active_job_ids)),
                )
            else:
                connection.execute(
                    """
                    UPDATE jobs SET status='pending', worker_name=NULL, profile=NULL,
                        claimed_at=NULL, updated_at=?, result='worker no longer reports job'
                    WHERE worker_name=? AND status IN ('claimed','running') AND updated_at<?
                    """,
                    (now, name, now - 30),
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
                    claimed_at=NULL, updated_at=?, result='worker lease expired'
                WHERE status IN ('claimed','running') AND updated_at<?
                  AND (worker_name IS NULL OR worker_name NOT IN (
                    SELECT name FROM workers WHERE last_seen>=?
                  ))
                """,
                (now, cutoff, cutoff),
            )
        return updated.rowcount

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
