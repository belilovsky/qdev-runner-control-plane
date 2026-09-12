"""The capacity history export stays aggregate-only and read-only."""

from __future__ import annotations

import importlib.util
import sqlite3
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COLLECTOR = ROOT / "scripts" / "qdev_capacity_history_collector.py"


def _load():
    spec = importlib.util.spec_from_file_location("qdev_capacity_history_collector", COLLECTOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["qdev_capacity_history_collector"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def collector():
    return _load()


def _database(tmp_path: Path) -> Path:
    path = tmp_path / "controller.db"
    with sqlite3.connect(path) as connection:
        connection.execute(
            "CREATE TABLE jobs (profile TEXT, created_at REAL, claimed_at REAL, completed_at REAL)"
        )
    path.chmod(0o600)
    return path


def test_history_is_profile_scoped_aggregate_and_has_168_hour_buckets(collector, tmp_path):
    database = _database(tmp_path)
    now = datetime(2026, 9, 12, 12, 30, tzinfo=UTC)
    start = datetime(2026, 9, 5, 12, tzinfo=UTC).timestamp()
    with sqlite3.connect(database) as connection:
        connection.executemany(
            "INSERT INTO jobs VALUES (?, ?, ?, ?)",
            [
                ("qdev-ci", start + 3600, start + 3660, start + 4260),
                ("qdev-ci-docker", start + 2 * 3600, start + 2 * 3660, start + 2 * 4260),
                ("unsealed", start + 3600, start + 3660, start + 4260),
            ],
        )

    history = collector.build_history(database, now=now)

    assert history["schema"] == "qdev-ci-profile-history-v1"
    assert history["window_start"] == "2026-09-05T12:00:00Z"
    profiles = {item["profile"]: item for item in history["profiles"]}
    assert set(profiles) == {"qdev-ci", "qdev-ci-browser", "qdev-ci-docker"}
    assert all(len(item["hourly_arrivals"]) == 168 for item in profiles.values())
    assert profiles["qdev-ci"]["hourly_arrivals"][1] == 1
    assert profiles["qdev-ci"]["durations_minutes"] == [10.0]
    assert profiles["qdev-ci-docker"]["hourly_arrivals"][2] == 1
    assert profiles["qdev-ci-browser"]["durations_minutes"] == []
    assert "repository" not in repr(history)


def test_history_rejects_unsafe_database_path(collector, tmp_path):
    database = _database(tmp_path)
    database.chmod(0o660)
    with pytest.raises(collector.CapacityHistoryError, match="group/world writable"):
        collector.build_history(database)


def test_history_does_not_count_incomplete_or_negative_duration(collector, tmp_path):
    database = _database(tmp_path)
    now = datetime(2026, 9, 12, 12, 30, tzinfo=UTC)
    start = datetime(2026, 9, 5, 12, tzinfo=UTC).timestamp()
    with sqlite3.connect(database) as connection:
        connection.executemany(
            "INSERT INTO jobs VALUES (?, ?, ?, ?)",
            [
                ("qdev-ci", start + 3600, None, None),
                ("qdev-ci", start + 7200, start + 8000, start + 7900),
            ],
        )

    history = collector.build_history(database, now=now)
    ci = next(item for item in history["profiles"] if item["profile"] == "qdev-ci")
    assert sum(ci["hourly_arrivals"]) == 2
    assert ci["durations_minutes"] == []


def test_weekly_systemd_plan_is_local_and_has_no_admission_surface():
    service = (ROOT / "deploy" / "qdev-capacity-plan.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy" / "qdev-capacity-plan.timer").read_text(encoding="utf-8")

    assert "User=root" in service
    assert "ConditionPathIsRegular=/var/lib/qdev-runner/broker-state/broker.db" in service
    assert "qdev_capacity_history_collector.py" in service
    assert "qdev_capacity_planner.py" in service
    assert (
        "ReadOnlyPaths=/opt/qdev-runner-control-plane /var/lib/qdev-runner/broker-state" in service
    )
    assert "ReadWritePaths=/var/lib/qdev-runner/capacity" in service
    assert "ProtectSystem=full" in service
    assert "claim" not in service.lower()
    assert "runner" not in service.lower().replace("qdev-runner", "")
    assert "ExecStart=" not in timer
    assert "OnCalendar=Sun *-*-* 03:17:00 UTC" in timer
