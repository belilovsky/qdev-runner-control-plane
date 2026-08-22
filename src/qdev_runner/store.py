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

    def claim(self, worker_name: str, profiles: tuple[str, ...]) -> dict[str, Any] | None:
        now = time.time()
        with self.connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM jobs WHERE status='pending' ORDER BY created_at LIMIT 100"
            ).fetchall()
            selected = None
            for row in rows:
                labels = {label.lower() for label in json.loads(row["labels_json"])}
                if any(profile.lower() in labels for profile in profiles):
                    selected = row
                    break
            if selected is None:
                connection.execute("COMMIT")
                return None
            profile = next(
                profile
                for profile in profiles
                if profile.lower()
                in {label.lower() for label in json.loads(selected["labels_json"])}
            )
            updated = connection.execute(
                """
                UPDATE jobs SET status='claimed', worker_name=?, profile=?, claimed_at=?,
                    updated_at=?, attempts=attempts+1
                WHERE job_id=? AND status='pending'
                """,
                (worker_name, profile, now, now, selected["job_id"]),
            )
            connection.execute("COMMIT")
            if updated.rowcount != 1:
                return None
            return dict(selected) | {"worker_name": worker_name, "profile": profile}

    def set_status(self, job_id: int, status: str, result: str = "") -> None:
        now = time.time()
        completed_at = now if status in {"completed", "failed", "rejected"} else None
        with self.connect() as connection:
            connection.execute(
                "UPDATE jobs SET status=?, result=?, updated_at=?, "
                "completed_at=COALESCE(?, completed_at) WHERE job_id=?",
                (status, result[:4000], now, completed_at, job_id),
            )

    def requeue(self, job_id: int, reason: str) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                UPDATE jobs SET status='pending', worker_name=NULL, profile=NULL,
                    claimed_at=NULL, updated_at=?, result=? WHERE job_id=? AND status='claimed'
                """,
                (time.time(), reason[:4000], job_id),
            )

    def complete_from_webhook(self, job_id: int, conclusion: str) -> None:
        self.set_status(job_id, "completed", conclusion)

    def heartbeat(
        self, name: str, profiles: tuple[str, ...], active_jobs: int, detail: dict[str, Any]
    ) -> None:
        with self.connect() as connection:
            connection.execute(
                """
                INSERT INTO workers(name, profiles_json, active_jobs, last_seen, detail_json)
                VALUES(?,?,?,?,?)
                ON CONFLICT(name) DO UPDATE SET profiles_json=excluded.profiles_json,
                    active_jobs=excluded.active_jobs, last_seen=excluded.last_seen,
                    detail_json=excluded.detail_json
                """,
                (name, json.dumps(profiles), active_jobs, time.time(), json.dumps(detail)),
            )
            connection.execute(
                "UPDATE jobs SET updated_at=? WHERE worker_name=? "
                "AND status IN ('claimed','running')",
                (time.time(), name),
            )

    def has_fresh_tier(self, tier: str, max_age_seconds: int) -> bool:
        cutoff = time.time() - max_age_seconds
        with self.connect() as connection:
            rows = connection.execute(
                "SELECT last_seen, detail_json FROM workers WHERE last_seen>=?", (cutoff,)
            ).fetchall()
        return any(
            detail.get("tier") == tier and detail.get("allowed", True) is True
            for row in rows
            for detail in (json.loads(row["detail_json"]),)
        )

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
                workers.append(
                    dict(row)
                    | {
                        "tier": detail.get("tier", "unknown"),
                        "available": detail.get("allowed", True) is True,
                    }
                )
        return {"jobs": counts, "workers": workers, "now": time.time()}
