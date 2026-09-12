"""The capacity planner is a review input, never a host-admission bypass."""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
PLANNER = ROOT / "scripts" / "qdev_capacity_planner.py"


def _load():
    spec = importlib.util.spec_from_file_location("qdev_capacity_planner", PLANNER)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules["qdev_capacity_planner"] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def planner():
    return _load()


def _profile(
    profile: str,
    *,
    arrivals: list[int] | None = None,
    durations: list[int] | None = None,
):
    return {
        "profile": profile,
        "hourly_arrivals": arrivals if arrivals is not None else [1] * 168,
        "durations_minutes": durations if durations is not None else [10] * 30,
    }


def _history(*profiles):
    return {"schema": "qdev-ci-profile-history-v1", "profiles": list(profiles)}


def test_p95_formula_is_deterministic_and_conservative(planner):
    arrivals = [1] * 159 + [10] * 9
    durations = [10] * 28 + [30, 30]
    assert planner.percentile_95(arrivals) == 10
    assert planner.percentile_95(durations) == 30
    assert planner.profile_slots(arrivals, durations) == 8


def test_missing_or_short_history_keeps_the_sealed_six_plus_two_baseline(planner):
    plan = planner.build_plan(_history(_profile("qdev-ci")))
    assert plan["active_slots_required"] == 6
    assert plan["n_plus_one_reserve_slots_required"] == 2
    assert plan["registered_slots_required"] == 8
    assert plan["capacity_review_required"] is False
    assert plan["automatic_action"] == "none"
    assert {item["profile"] for item in plan["profiles"] if not item["history_complete"]} == {
        "qdev-ci-browser",
        "qdev-ci-docker",
    }


def test_complete_history_calculates_per_profile_and_requires_review_above_four_vps(planner):
    plan = planner.build_plan(
        _history(
            _profile("qdev-ci", arrivals=[10] * 168, durations=[30] * 30),
            _profile("qdev-ci-browser", arrivals=[1] * 168, durations=[10] * 30),
            _profile("qdev-ci-docker", arrivals=[1] * 168, durations=[10] * 30),
        )
    )
    assert [item["recommended_slots"] for item in plan["profiles"]] == [8, 1, 1]
    assert plan["active_slots_required"] == 10
    assert plan["registered_slots_required"] == 12
    assert plan["capacity_review_required"] is True
    assert plan["automatic_action"] == "none"


@pytest.mark.parametrize(
    "history",
    [
        {"schema": "wrong", "profiles": []},
        _history(_profile("unsealed-profile")),
        _history(_profile("qdev-ci", arrivals=[-1] * 168)),
        _history(_profile("qdev-ci", durations=[])),
    ],
)
def test_invalid_or_unsealed_history_fails_closed(planner, history):
    with pytest.raises(planner.CapacityPlanError):
        planner.build_plan(history)
