from __future__ import annotations

import importlib.util
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "manage_worker_gate", ROOT / "scripts/manage_worker_gate.py"
)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)


def paths(tmp_path: Path):  # type: ignore[no-untyped-def]
    return MODULE.GatePaths(
        permit=tmp_path / "worker.enabled",
        marker=tmp_path / "worker.paused",
        state=tmp_path / "worker-gate.json",
        lock=tmp_path / "worker-gate.lock",
        receipts=tmp_path / "receipts",
    )


def passing_runtime_receipt(tmp_path: Path) -> Path:
    receipt = tmp_path / "runtime.json"
    receipt.write_text(
        json.dumps(
            {
                "schema": "qdev-runner-worker-runtime-audit-v1",
                "status": "passed",
                "errors": [],
                "observed_at": datetime.now(UTC).isoformat(),
                "worker_name": "mail-qdev-reserve",
                "tier": "reserve",
            }
        ),
        encoding="utf-8",
    )
    return receipt


def test_gate_is_owner_bound_and_runtime_audit_gated(tmp_path: Path) -> None:
    gate_paths = paths(tmp_path)
    commands: list[list[str]] = []
    runner = commands.append

    MODULE.acquire(gate_paths, owner="INC-1", reason="maintenance", runner=runner)

    assert gate_paths.marker.exists()
    assert not gate_paths.permit.exists()
    assert MODULE.read_json(gate_paths.state)["owner"] == "INC-1"
    with pytest.raises(RuntimeError, match="owned by"):
        MODULE.release(
            gate_paths,
            owner="INC-2",
            reason="wrong owner",
            runtime_receipt=passing_runtime_receipt(tmp_path),
            runner=runner,
        )

    MODULE.release(
        gate_paths,
        owner="INC-1",
        reason="verified",
        runtime_receipt=passing_runtime_receipt(tmp_path),
        runner=runner,
    )

    assert gate_paths.permit.exists()
    assert not gate_paths.marker.exists()
    assert MODULE.read_json(gate_paths.state)["status"] == "enabled"
    assert commands[-1] == ["systemctl", "start", "qdev-runner-worker.service"]


def test_gate_refuses_implicit_owner_takeover(tmp_path: Path) -> None:
    gate_paths = paths(tmp_path)
    MODULE.acquire(gate_paths, owner="INC-1", reason="maintenance", runner=lambda _: None)

    with pytest.raises(RuntimeError, match="owned by"):
        MODULE.acquire(
            gate_paths,
            owner="INC-2",
            reason="collision",
            runner=lambda _: None,
        )


def test_worker_service_is_default_deny_and_drains_without_timeout() -> None:
    service = (ROOT / "deploy/qdev-runner-worker.service").read_text(encoding="utf-8")

    assert "ConditionPathExists=/etc/qdev/qdev-runner-worker.enabled" in service
    assert "TimeoutStopSec=infinity" in service
