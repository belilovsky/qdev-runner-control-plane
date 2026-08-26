from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def load_module() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts/audit_runtime.py"
    spec = importlib.util.spec_from_file_location("audit_runtime", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def health() -> dict[str, object]:
    return {
        "ok": True,
        "schema": "qdev-runner-health-v1",
        "primary_present": True,
        "reserve_present": True,
        "primary_capacity_allowed": True,
        "reserve_capacity_allowed": True,
        "primary_slots_available": 0,
        "reserve_slots_available": 1,
    }


def test_busy_primary_is_healthy_when_reserve_is_ready() -> None:
    module = load_module()
    assert module.evaluate(health(), require_primary_slot=False, require_reserve_slot=False) == []


def test_slot_requirement_is_explicit() -> None:
    module = load_module()
    assert module.evaluate(health(), require_primary_slot=True, require_reserve_slot=False) == [
        "primary_slot_unavailable"
    ]


def test_missing_reserve_is_a_failure() -> None:
    module = load_module()
    document = health()
    document["reserve_present"] = False
    assert "reserve_not_present" in module.evaluate(
        document, require_primary_slot=False, require_reserve_slot=False
    )
