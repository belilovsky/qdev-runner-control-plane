#!/usr/bin/env python3
"""Export a sealed, aggregate seven-day capacity history from the controller store.

The collector uses SQLite read-only mode. It neither alters the broker store
nor exposes a repository, job, runner, host or claim identity.
"""

from __future__ import annotations

import argparse
import json
import os
import sqlite3
import stat
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

HISTORY_SCHEMA = "qdev-ci-profile-history-v1"
REQUIRED_PROFILES = ("qdev-ci", "qdev-ci-browser", "qdev-ci-docker")
HISTORY_WINDOW_HOURS = 7 * 24


class CapacityHistoryError(ValueError):
    """The controller store cannot safely produce an aggregate history."""


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _regular_private(path: Path) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise CapacityHistoryError("controller database is unavailable") from exc
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise CapacityHistoryError("controller database must be a regular file")
    if metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise CapacityHistoryError("controller database must not be group/world writable")


def _hour_floor(value: datetime) -> datetime:
    return value.astimezone(UTC).replace(minute=0, second=0, microsecond=0)


def _empty_profiles() -> dict[str, dict[str, list[float] | list[int]]]:
    return {
        profile: {
            "hourly_arrivals": [0] * HISTORY_WINDOW_HOURS,
            "durations_minutes": [],
        }
        for profile in REQUIRED_PROFILES
    }


def _connect_read_only(path: Path) -> sqlite3.Connection:
    try:
        return sqlite3.connect(f"file:{path.resolve()}?mode=ro", uri=True)
    except sqlite3.Error as exc:
        raise CapacityHistoryError("controller database cannot be opened read-only") from exc


def build_history(database: Path, *, now: datetime | None = None) -> dict[str, Any]:
    """Return only profile aggregates for the preceding 168 complete hours."""

    _regular_private(database)
    now = now or _utc_now()
    end = _hour_floor(now)
    start = end - timedelta(hours=HISTORY_WINDOW_HOURS)
    start_epoch = start.timestamp()
    end_epoch = end.timestamp()
    profile_data = _empty_profiles()

    try:
        with _connect_read_only(database) as connection:
            rows = connection.execute(
                """
                SELECT profile, created_at, claimed_at, completed_at
                FROM jobs
                WHERE profile IN (?, ?, ?)
                  AND ((created_at >= ? AND created_at < ?)
                    OR (completed_at >= ? AND completed_at < ?))
                """,
                (*REQUIRED_PROFILES, start_epoch, end_epoch, start_epoch, end_epoch),
            )
            for profile, created_at, claimed_at, completed_at in rows:
                if profile not in profile_data:
                    continue
                if isinstance(created_at, int | float) and start_epoch <= created_at < end_epoch:
                    bucket = int((float(created_at) - start_epoch) // 3600)
                    profile_data[profile]["hourly_arrivals"][bucket] += 1  # type: ignore[index]
                if (
                    isinstance(claimed_at, int | float)
                    and isinstance(completed_at, int | float)
                    and start_epoch <= completed_at < end_epoch
                    and completed_at >= claimed_at
                ):
                    minutes = (float(completed_at) - float(claimed_at)) / 60
                    if minutes > 0:
                        profile_data[profile]["durations_minutes"].append(minutes)  # type: ignore[union-attr]
    except sqlite3.Error as exc:
        raise CapacityHistoryError("controller database history query failed") from exc

    return {
        "schema": HISTORY_SCHEMA,
        "observed_at": _iso(now),
        "window_start": _iso(start),
        "window_end": _iso(end),
        "profiles": [
            {"profile": profile, **profile_data[profile]} for profile in REQUIRED_PROFILES
        ],
    }


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        with temporary.open("x", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        os.chmod(temporary, stat.S_IRUSR | stat.S_IWUSR)
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args(argv)
    try:
        _atomic_write(arguments.output, build_history(arguments.database))
    except (CapacityHistoryError, OSError) as exc:
        print(f"capacity history error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
