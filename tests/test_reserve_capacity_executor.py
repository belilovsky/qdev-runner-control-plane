"""Sealed reserve-capacity executor behaviour."""

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
EXECUTOR = ROOT / "scripts" / "qdev_fixed_reserve_capacity_executor.py"


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def executor():
    return _load(EXECUTOR, "qdev_fixed_reserve_capacity_executor")


def _write_private(path: Path, value: object) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def _request(executor):
    return {
        "request_id": hashlib.sha256(
            f"{executor.INCIDENT_ID}:reserve:{executor.HOST_ID}:{executor.ACTION}".encode()
        ).hexdigest(),
        "host_id": executor.HOST_ID,
        "action": executor.ACTION,
        "follow_up": ["host-audit", "capacity-calculation"],
    }


def _receipt(executor, request, *, audited_at: datetime | None = None):
    return {
        "schema": executor.RECEIPT_SCHEMA,
        "request_id": request["request_id"],
        "host_id": request["host_id"],
        "action": request["action"],
        "status": "admitted",
        "slots": 2,
        "profiles": ["qdev-ci", "qdev-ci-browser"],
        "max_docker_jobs": 0,
        "audited_at": (audited_at or datetime.now(UTC)).isoformat().replace("+00:00", "Z"),
        "audit_digest": "a" * 64,
    }


def _outbox(executor, requests):
    return {
        "schema": executor.OUTBOX_SCHEMA,
        "incident_id": executor.INCIDENT_ID,
        "requests": requests,
    }


def _registry(executor):
    return {
        "schema": executor.REGISTRY_SCHEMA,
        "targets": {
            executor.HOST_ID: {
                "host_id": executor.HOST_ID,
                "adapter_path": str(executor.FIXED_ADAPTER),
            }
        },
    }


def test_rejects_anything_except_the_single_sealed_reserve_request(executor, tmp_path: Path):
    outbox = tmp_path / "outbox.json"
    request = _request(executor)
    request["host_id"] = "not-a-reserve"
    _write_private(outbox, _outbox(executor, [request]))

    with pytest.raises(executor.ExecutorError, match="reserve_request_identity_invalid"):
        executor.load_request(outbox, owner_uid=None)


def test_private_registry_resolves_only_fixed_adapter(executor, monkeypatch, tmp_path: Path):
    adapter = tmp_path / "fixed-adapter"
    adapter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    adapter.chmod(0o700)
    monkeypatch.setattr(executor, "FIXED_ADAPTER", adapter)
    registry = tmp_path / "registry.json"
    _write_private(registry, _registry(executor))

    assert executor.resolve_adapter(registry, owner_uid=None) == adapter

    invalid = _registry(executor)
    invalid["targets"][executor.HOST_ID]["adapter_path"] = "/operator-command"
    _write_private(registry, invalid)
    with pytest.raises(executor.ExecutorError, match="reserve_registry_identity_invalid"):
        executor.resolve_adapter(registry, owner_uid=None)


def test_rejects_stale_host_audit(executor):
    request = _request(executor)
    now = datetime.now(UTC)
    stale = _receipt(
        executor,
        request,
        audited_at=now - timedelta(seconds=executor.MAX_AUDIT_AGE_SECONDS + 1),
    )

    with pytest.raises(executor.ExecutorError, match="reserve_adapter_audit_not_fresh"):
        executor._validate_receipt(stale, request, now=now)


def test_exact_receipt_is_appended_once_without_second_adapter_run(
    executor, monkeypatch, tmp_path: Path
):
    adapter = tmp_path / "fixed-adapter"
    adapter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    adapter.chmod(0o700)
    monkeypatch.setattr(executor, "FIXED_ADAPTER", adapter)
    request = _request(executor)
    outbox = tmp_path / "outbox.json"
    registry = tmp_path / "registry.json"
    receipts = tmp_path / "receipts.jsonl"
    _write_private(outbox, _outbox(executor, [request]))
    _write_private(registry, _registry(executor))
    calls = []

    def adapter_run(path, received_request, *, now):
        calls.append((path, received_request))
        return _receipt(executor, received_request, audited_at=now)

    monkeypatch.setattr(executor, "run_adapter", adapter_run)
    first = executor.execute(
        outbox=outbox,
        receipts=receipts,
        registry=registry,
        owner_uid=None,
        now=datetime.now(UTC),
    )
    second = executor.execute(
        outbox=outbox,
        receipts=receipts,
        registry=registry,
        owner_uid=None,
        now=datetime.now(UTC),
    )

    assert first == {
        "schema": executor.RECEIPT_SCHEMA,
        "status": "admitted",
        "receipt_written": True,
    }
    assert second == {
        "schema": executor.RECEIPT_SCHEMA,
        "status": "already_receipted",
        "receipt_written": False,
    }
    assert len(calls) == 1
    assert stat.S_IMODE(receipts.stat().st_mode) == 0o600
    assert len(receipts.read_text(encoding="utf-8").splitlines()) == 1


def test_service_watches_only_the_sealed_outbox(executor):
    del executor
    service = (ROOT / "deploy" / "qdev-reserve-capacity-executor.service").read_text(
        encoding="utf-8"
    )
    path_unit = (ROOT / "deploy" / "qdev-reserve-capacity-executor.path").read_text(
        encoding="utf-8"
    )
    assert "User=root" in service
    assert "NoNewPrivileges=true" in service
    assert (
        "PathChanged=/var/lib/qdev-runner/incident-watchdog/reserve-capacity-outbox.json"
        in path_unit
    )
    assert "mail-general-reserve" not in service + path_unit
