#!/usr/bin/env python3
"""Create a deterministic, review-only four-VPS capacity recommendation.

The planner deliberately has no provider, controller or runner-client code.
It turns seven-day, profile-scoped aggregate history into a signed-off input
for the sealed host-admission path; it cannot create a worker, alter FIFO, or
change a capacity threshold.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

HISTORY_SCHEMA = "qdev-ci-profile-history-v1"
PLAN_SCHEMA = "qdev-ci-capacity-plan-v1"
REQUIRED_PROFILES = ("qdev-ci", "qdev-ci-browser", "qdev-ci-docker")
ACTIVE_BASELINE_SLOTS = 6
N_PLUS_ONE_HOST_SLOTS = 2
TARGET_UTILIZATION = 0.7
HISTORY_WINDOW_HOURS = 7 * 24


class CapacityPlanError(ValueError):
    """The supplied aggregate history cannot support a safe recommendation."""


def _utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _require_sequence(value: object, *, field: str) -> Sequence[object]:
    if not isinstance(value, list):
        raise CapacityPlanError(f"{field} must be a list")
    return value


def _numbers(value: object, *, field: str, minimum: float) -> tuple[float, ...]:
    values = _require_sequence(value, field=field)
    parsed: list[float] = []
    for item in values:
        if not isinstance(item, int | float) or isinstance(item, bool):
            raise CapacityPlanError(f"{field} must contain numbers")
        number = float(item)
        if not math.isfinite(number) or number < minimum:
            raise CapacityPlanError(f"{field} contains an invalid value")
        parsed.append(number)
    if not parsed:
        raise CapacityPlanError(f"{field} must not be empty")
    return tuple(parsed)


def percentile_95(values: Sequence[float]) -> float:
    """Nearest-rank p95 with no interpolation that could hide peak demand."""

    if not values:
        raise CapacityPlanError("p95 requires at least one measurement")
    ordered = sorted(values)
    return ordered[math.ceil(0.95 * len(ordered)) - 1]


def profile_slots(hourly_arrivals: Sequence[float], durations_minutes: Sequence[float]) -> int:
    """Compute the published p95/profile capacity formula."""

    arrivals = percentile_95(hourly_arrivals)
    duration = percentile_95(durations_minutes)
    return math.ceil(arrivals * duration / 60 / TARGET_UTILIZATION)


def _profile_history(document: Mapping[str, Any]) -> Mapping[str, Mapping[str, Any]]:
    if document.get("schema") != HISTORY_SCHEMA:
        raise CapacityPlanError(f"history schema must be {HISTORY_SCHEMA}")
    raw_profiles = document.get("profiles")
    if not isinstance(raw_profiles, list):
        raise CapacityPlanError("profiles must be a list")

    profiles: dict[str, Mapping[str, Any]] = {}
    for item in raw_profiles:
        if not isinstance(item, Mapping):
            raise CapacityPlanError("profiles must contain objects")
        profile = item.get("profile")
        if not isinstance(profile, str) or profile not in REQUIRED_PROFILES:
            raise CapacityPlanError("history contains an unsealed profile")
        if profile in profiles:
            raise CapacityPlanError(f"history contains duplicate profile {profile}")
        profiles[profile] = item
    return profiles


def build_plan(document: Mapping[str, Any], *, observed_at: str | None = None) -> dict[str, Any]:
    """Return a capacity recommendation without changing runtime state."""

    profiles = _profile_history(document)
    plan_profiles: list[dict[str, Any]] = []
    history_complete = True
    formula_slots = 0

    for profile in REQUIRED_PROFILES:
        item = profiles.get(profile)
        if item is None:
            history_complete = False
            plan_profiles.append(
                {
                    "profile": profile,
                    "history_complete": False,
                    "recommended_slots": None,
                    "reason": "missing-profile-history",
                }
            )
            continue
        arrivals = _numbers(
            item.get("hourly_arrivals"), field=f"{profile}.hourly_arrivals", minimum=0
        )
        durations = _numbers(
            item.get("durations_minutes"), field=f"{profile}.durations_minutes", minimum=0.001
        )
        if len(arrivals) < HISTORY_WINDOW_HOURS or not durations:
            history_complete = False
            plan_profiles.append(
                {
                    "profile": profile,
                    "history_complete": False,
                    "recommended_slots": None,
                    "reason": "insufficient-seven-day-history",
                    "hourly_samples": len(arrivals),
                    "duration_samples": len(durations),
                }
            )
            continue
        recommended = profile_slots(arrivals, durations)
        formula_slots += recommended
        plan_profiles.append(
            {
                "profile": profile,
                "history_complete": True,
                "hourly_samples": len(arrivals),
                "duration_samples": len(durations),
                "p95_hourly_arrivals": percentile_95(arrivals),
                "p95_duration_minutes": percentile_95(durations),
                "recommended_slots": recommended,
                "reason": "p95-arrivals-times-p95-duration-over-70-percent-utilization",
            }
        )

    active_slots = (
        ACTIVE_BASELINE_SLOTS
        if not history_complete
        else max(ACTIVE_BASELINE_SLOTS, formula_slots)
    )
    registered_slots = active_slots + N_PLUS_ONE_HOST_SLOTS
    four_vps_limit = ACTIVE_BASELINE_SLOTS + N_PLUS_ONE_HOST_SLOTS
    return {
        "schema": PLAN_SCHEMA,
        "observed_at": observed_at or str(document.get("observed_at") or _utc_now()),
        "history_schema": HISTORY_SCHEMA,
        "history_window_hours_required": HISTORY_WINDOW_HOURS,
        "target_utilization": TARGET_UTILIZATION,
        "profiles": plan_profiles,
        "active_slots_required": active_slots,
        "n_plus_one_reserve_slots_required": N_PLUS_ONE_HOST_SLOTS,
        "registered_slots_required": registered_slots,
        "four_vps_registered_slot_limit": four_vps_limit,
        "capacity_review_required": registered_slots > four_vps_limit,
        "automatic_action": "none",
        "next_step": (
            "review sealed host audit and controller admission"
            if registered_slots <= four_vps_limit
            else "capacity review required; do not alter host registry automatically"
        ),
    }


def _load_json(path: Path) -> Mapping[str, Any]:
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CapacityPlanError(f"cannot read history: {exc}") from exc
    if not isinstance(document, Mapping):
        raise CapacityPlanError("history must be a JSON object")
    return document


def _atomic_write(path: Path, payload: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
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
    parser.add_argument("--history", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        plan = build_plan(_load_json(arguments.history))
        if arguments.output is None:
            json.dump(plan, sys.stdout, indent=2, sort_keys=True)
            sys.stdout.write("\n")
        else:
            _atomic_write(arguments.output, plan)
    except CapacityPlanError as exc:
        parser.error(str(exc))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
