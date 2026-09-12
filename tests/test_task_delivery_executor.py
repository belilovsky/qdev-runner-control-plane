"""Sealed task-delivery executor behaviour."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
EXECUTOR = ROOT / "scripts" / "qdev_fixed_task_delivery_executor.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def executor():
    return _load(EXECUTOR, "qdev_fixed_task_delivery_executor")


def _write_private(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def _delivery(executor, *, status: str = "in_progress"):
    base = {
        "schema": "qdev-ci-incident-watchdog-v1-job-status",
        "incident_id": executor.INCIDENT_ID,
        "repository": "belilovsky/qazlake",
        "run_id": 11,
        "job_id": 22,
        "status": status,
        "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }
    base["delivery_id"] = hashlib.sha256(
        f"{executor.INCIDENT_ID}:job-status:{base['repository']}:{base['run_id']}:{base['job_id']}:{status}".encode()
    ).hexdigest()
    return base


def _outbox(executor, deliveries):
    return {
        "schema": executor.OUTBOX_SCHEMA,
        "incident_id": executor.INCIDENT_ID,
        "deliveries": deliveries,
    }


def _registry(executor):
    return {"schema": executor.REGISTRY_SCHEMA, "adapter_path": str(executor.FIXED_ADAPTER)}


def _receipt(executor, delivery, *, timestamp: datetime | None = None):
    return {
        "schema": executor.RECEIPT_SCHEMA,
        "delivery_id": delivery["delivery_id"],
        "repository": delivery["repository"],
        "run_id": delivery["run_id"],
        "job_id": delivery["job_id"],
        "status": delivery["status"],
        "delivered_at": (timestamp or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
    }


def _response(executor, delivery, outcome: str, *, receipt=None):
    return {
        "schema": executor.ADAPTER_RESPONSE_SCHEMA,
        "delivery_id": delivery["delivery_id"],
        "outcome": outcome,
        "receipt": receipt,
    }


def _fixed_adapter(executor, monkeypatch, tmp_path: Path) -> Path:
    adapter = tmp_path / "fixed-adapter"
    adapter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    adapter.chmod(0o700)
    monkeypatch.setattr(executor, "FIXED_ADAPTER", adapter)
    return adapter


def test_rejects_arbitrary_delivery_tuple(executor, tmp_path: Path):
    outbox = tmp_path / "outbox.json"
    delivery = _delivery(executor)
    delivery["job_id"] = 999
    _write_private(outbox, _outbox(executor, [delivery]))
    with pytest.raises(executor.ExecutorError, match="delivery_identity_invalid"):
        executor.load_outbox(outbox, owner_uid=None)


def test_private_binding_permits_only_fixed_adapter(executor, monkeypatch, tmp_path: Path):
    adapter = _fixed_adapter(executor, monkeypatch, tmp_path)
    registry = tmp_path / "registry.json"
    _write_private(registry, _registry(executor))
    assert executor.resolve_adapter(registry, owner_uid=None) == adapter
    _write_private(
        registry, {"schema": executor.REGISTRY_SCHEMA, "adapter_path": "/operator-command"}
    )
    with pytest.raises(executor.ExecutorError, match="delivery_registry_identity_invalid"):
        executor.resolve_adapter(registry, owner_uid=None)


def test_exact_delivery_receipt_is_written_once(executor, monkeypatch, tmp_path: Path):
    _fixed_adapter(executor, monkeypatch, tmp_path)
    delivery = _delivery(executor)
    outbox, registry, receipts, state = (
        tmp_path / name for name in ("outbox.json", "registry.json", "receipts.jsonl", "state.json")
    )
    _write_private(outbox, _outbox(executor, [delivery]))
    _write_private(registry, _registry(executor))
    calls = []

    def adapter_run(_adapter, received):
        calls.append(received)
        return "delivered", _receipt(executor, received)

    monkeypatch.setattr(executor, "run_adapter", adapter_run)
    first = executor.execute(
        outbox=outbox, receipts=receipts, registry=registry, state_path=state, owner_uid=None
    )
    second = executor.execute(
        outbox=outbox, receipts=receipts, registry=registry, state_path=state, owner_uid=None
    )
    assert first["delivered"] == 1
    assert second["already_receipted"] == 1
    assert len(calls) == 1
    assert len(receipts.read_text(encoding="utf-8").splitlines()) == 1
    assert stat.S_IMODE(receipts.stat().st_mode) == 0o600


def test_explicit_transient_failure_retries_then_delivers(executor, monkeypatch, tmp_path: Path):
    _fixed_adapter(executor, monkeypatch, tmp_path)
    delivery = _delivery(executor)
    outbox, registry, receipts, state = (
        tmp_path / name for name in ("outbox.json", "registry.json", "receipts.jsonl", "state.json")
    )
    _write_private(outbox, _outbox(executor, [delivery]))
    _write_private(registry, _registry(executor))
    responses = [("retryable_failure", None), ("delivered", _receipt(executor, delivery))]
    monkeypatch.setattr(executor, "run_adapter", lambda _adapter, _delivery: responses.pop(0))
    now = datetime.now(UTC)
    pending = executor.execute(
        outbox=outbox,
        receipts=receipts,
        registry=registry,
        state_path=state,
        owner_uid=None,
        now=now,
    )
    not_due = executor.execute(
        outbox=outbox,
        receipts=receipts,
        registry=registry,
        state_path=state,
        owner_uid=None,
        now=now + timedelta(seconds=1),
    )
    done = executor.execute(
        outbox=outbox,
        receipts=receipts,
        registry=registry,
        state_path=state,
        owner_uid=None,
        now=now + timedelta(seconds=executor.RETRY_DELAYS_SECONDS[0] + 1),
    )
    assert pending["retry_scheduled"] == 1
    assert not_due["idle"] == 1
    assert done["delivered"] == 1


def test_ambiguous_or_exhausted_delivery_goes_to_dlq_without_resend(
    executor, monkeypatch, tmp_path: Path
):
    _fixed_adapter(executor, monkeypatch, tmp_path)
    delivery = _delivery(executor)
    outbox, registry, receipts, state = (
        tmp_path / name for name in ("outbox.json", "registry.json", "receipts.jsonl", "state.json")
    )
    _write_private(outbox, _outbox(executor, [delivery]))
    _write_private(registry, _registry(executor))
    calls = []

    def ambiguous(_adapter, received):
        calls.append(received)
        raise executor.ExecutorError("delivery_adapter_ambiguous")

    monkeypatch.setattr(executor, "run_adapter", ambiguous)
    first = executor.execute(
        outbox=outbox, receipts=receipts, registry=registry, state_path=state, owner_uid=None
    )
    second = executor.execute(
        outbox=outbox, receipts=receipts, registry=registry, state_path=state, owner_uid=None
    )
    assert first["dead_letter"] == 1
    assert second["dead_letter"] == 1
    assert len(calls) == 1
    stored = json.loads(state.read_text(encoding="utf-8"))
    assert stored["deliveries"][delivery["delivery_id"]]["state"] == "dead_letter"


def test_invalid_receipt_is_never_acknowledged(executor, monkeypatch, tmp_path: Path):
    _fixed_adapter(executor, monkeypatch, tmp_path)
    delivery = _delivery(executor)
    outbox, registry, receipts, state = (
        tmp_path / name for name in ("outbox.json", "registry.json", "receipts.jsonl", "state.json")
    )
    _write_private(outbox, _outbox(executor, [delivery]))
    _write_private(registry, _registry(executor))
    invalid = _receipt(executor, delivery)
    invalid["job_id"] = 999
    monkeypatch.setattr(executor, "run_adapter", lambda _adapter, _delivery: ("delivered", invalid))
    result = executor.execute(
        outbox=outbox, receipts=receipts, registry=registry, state_path=state, owner_uid=None
    )
    assert result["dead_letter"] == 1
    assert not receipts.exists()


def test_systemd_timer_has_no_operator_input_surface(executor):
    del executor
    service = (ROOT / "deploy" / "qdev-task-delivery-executor.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy" / "qdev-task-delivery-executor.timer").read_text(encoding="utf-8")
    assert "User=root" in service
    assert "NoNewPrivileges=true" in service
    assert "ConditionPathIsRegular=/etc/qdev-runner/task-delivery-targets.json" in service
    assert "OnUnitActiveSec=2min" in timer
    assert "ExecStart=" not in timer
