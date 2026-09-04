from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from bootstrap_support import KEY, operation, policy, register, request

from qdev_runner import fleet_bootstrap_executor as executor
from qdev_runner.fleet_bootstrap import BootstrapOperationStore, FleetBootstrapError
from qdev_runner.store import Store


def _context(tmp_path: Path, active_jobs: int = 0) -> dict:
    controller = Store(tmp_path / "controller.db")
    req = request()
    register(controller, active_jobs=active_jobs)
    return {
        "policy": policy(), "store": BootstrapOperationStore(tmp_path / "operation.json"),
        "operation": operation(controller, req), "signing_key": KEY, "controller_store": controller,
        "adapter": tmp_path / "adapter", "receipt_path": tmp_path / "receipt.json",
    }


def _allow_adapter(monkeypatch: pytest.MonkeyPatch, context: dict, reply=None) -> list:
    # Only this unit seam bypasses filesystem ownership; separate tests exercise
    # the real rejection path. Subprocess input/output remain production-shaped.
    monkeypatch.setattr(executor, "_adapter_path", lambda path: path)
    calls = []

    def run(args, **kwargs):
        envelope = json.loads(kwargs["input"])
        calls.append(envelope)
        target = envelope["target"]
        result = {
            "schema": executor.RECOVERY_RESULT_SCHEMA, "status": "completed",
            "worker_name": target["worker_name"], "target_id": target["target_id"],
            "service_unit": target["service_unit"], "active_jobs": 0, "result": {"native": "ok"},
            "operation_fence": envelope["operation"]["payload"]["fence"],
        }
        if reply:
            result.update(reply)
        return subprocess.CompletedProcess(args, 0, json.dumps(result), "")

    monkeypatch.setattr(executor.subprocess, "run", run)
    return calls


def test_missing_adapter_is_pending_without_poisoning_terminal_receipt(tmp_path: Path) -> None:
    context = _context(tmp_path)
    result = executor.execute_existing_worker_recovery(**context)
    assert result.status == "access_blocked"
    assert result.operation_status == "pending"
    assert result.active_jobs is None
    assert json.loads((tmp_path / "operation.json").read_text())["status"] == "pending"
    assert not (tmp_path / "receipt.json").exists()


def test_active_work_comes_from_controller_and_is_never_restarted(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path, active_jobs=1)
    calls = _allow_adapter(monkeypatch, context)
    result = executor.execute_existing_worker_recovery(**context)
    assert (result.status, result.active_jobs) == ("active_work", 1)
    assert not calls


def test_success_is_durable_and_retry_does_not_execute_adapter(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    calls = _allow_adapter(monkeypatch, context)
    first = executor.execute_existing_worker_recovery(**context)
    second = executor.execute_existing_worker_recovery(**context)
    assert first == second
    assert second.status == "completed"
    assert len(calls) == 1
    assert json.loads((tmp_path / "receipt.json").read_text())["status"] == "completed"
    assert not context["controller_store"].health()["workers"][0]["recovery_held"]


@pytest.mark.parametrize("reply", [
    {"worker_name": "other"}, {"operation_fence": "b" * 64}, {"active_jobs": 1},
])
def test_adapter_identity_mismatch_keeps_hold_and_pending(tmp_path, monkeypatch, reply) -> None:
    context = _context(tmp_path)
    _allow_adapter(monkeypatch, context, reply)
    result = executor.execute_existing_worker_recovery(**context)
    assert result.status == "failed"
    assert result.error_code == "adapter_identity_mismatch"
    assert context["controller_store"].health()["workers"][0]["recovery_held"]
    assert not (tmp_path / "receipt.json").exists()


def test_failed_adapter_resumes_without_false_receipt(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    _allow_adapter(monkeypatch, context, {"operation_fence": "b" * 64})
    assert executor.execute_existing_worker_recovery(**context).status == "failed"
    calls = _allow_adapter(monkeypatch, context)
    assert executor.execute_existing_worker_recovery(**context).status == "completed"
    assert len(calls) == 1


def test_raw_unsigned_directive_is_rejected_before_adapter(tmp_path, monkeypatch) -> None:
    context = _context(tmp_path)
    calls = _allow_adapter(monkeypatch, context)
    context["operation"].directive["payload"]["request"]["source_sha"] = "b" * 40
    with pytest.raises(FleetBootstrapError, match="signature"):
        executor.execute_existing_worker_recovery(**context)
    assert not calls


def test_real_adapter_path_rejects_relative_user_owned_and_symlink(tmp_path: Path) -> None:
    path = tmp_path / "adapter"
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(0o777)
    link = tmp_path / "link"
    link.symlink_to(path)
    assert executor._adapter_path(Path("adapter")) is None
    assert executor._adapter_path(path) is None
    assert executor._adapter_path(link) is None


def test_expiration_while_waiting_for_execution_lock_prevents_side_effect(tmp_path, monkeypatch):
    from contextlib import contextmanager

    from qdev_runner import bootstrap_authority

    context = _context(tmp_path)
    calls = _allow_adapter(monkeypatch, context)
    original = context["store"].execution_lock
    expired = context["operation"].directive["payload"]["expires_at"] + 1

    @contextmanager
    def lock():
        with original():
            monkeypatch.setattr(bootstrap_authority.time, "time", lambda: expired)
            yield

    monkeypatch.setattr(context["store"], "execution_lock", lock)
    with pytest.raises(FleetBootstrapError, match="expired"):
        executor.execute_existing_worker_recovery(**context)
    assert not calls


def test_adapter_appearing_mid_request_cannot_bypass_hold(tmp_path, monkeypatch):
    context = _context(tmp_path, active_jobs=1)
    calls = _allow_adapter(monkeypatch, context)
    resolutions = iter([None, context["adapter"]])
    monkeypatch.setattr(executor, "_adapter_path", lambda _: next(resolutions))
    result = executor.execute_existing_worker_recovery(**context)
    assert result.status == "access_blocked"
    assert result.active_jobs is None
    assert not calls


def test_expiration_during_hold_acquisition_prevents_adapter(tmp_path, monkeypatch):
    from qdev_runner import bootstrap_authority

    context = _context(tmp_path)
    calls = _allow_adapter(monkeypatch, context)
    acquire = context["controller_store"].acquire_recovery_hold
    expired = context["operation"].directive["payload"]["expires_at"] + 1

    def delayed_acquire(*args):
        result = acquire(*args)
        monkeypatch.setattr(bootstrap_authority.time, "time", lambda: expired)
        return result

    monkeypatch.setattr(context["controller_store"], "acquire_recovery_hold", delayed_acquire)
    with pytest.raises(FleetBootstrapError, match="expired"):
        executor.execute_existing_worker_recovery(**context)
    assert not calls


def _fresh_attempt(context, monkeypatch, **changes):
    """Synthetic signed fresh admission; RSA + GitHub admission is tested separately."""
    import hashlib

    from qdev_runner import bootstrap_authority
    from qdev_runner.fleet_bootstrap import bootstrap_request_fingerprint

    previous = context["operation"]
    now = previous.directive["payload"]["expires_at"] + 10
    monkeypatch.setattr(bootstrap_authority.time, "time", lambda: now)
    req = previous.request.model_copy(update={"run_id": 124, "job_id": 457, **changes})
    payload = {
        **previous.directive["payload"], "issued_at": now, "expires_at": now + 300,
        "request": req.model_dump(mode="json", by_alias=True),
        "fence": hashlib.sha256(
            f"{previous.idempotency_key}:{bootstrap_request_fingerprint(req)}".encode(),
        ).hexdigest(),
    }
    directive = {"payload": payload, "signature": bootstrap_authority._signature(payload, KEY)}
    context["operation"] = bootstrap_authority.verify_directive(
        directive, policy=context["policy"], signing_key=KEY,
    )


def test_completed_crash_reconciles_hold_after_old_authorization_expires(tmp_path, monkeypatch):
    context = _context(tmp_path)
    calls = _allow_adapter(monkeypatch, context)
    controller = context["controller_store"]
    release = controller.release_recovery_hold
    monkeypatch.setattr(controller, "release_recovery_hold", lambda *args: None)
    first = executor.execute_existing_worker_recovery(**context)
    assert first.status == "completed"
    assert controller.health()["workers"][0]["recovery_held"]
    monkeypatch.setattr(controller, "release_recovery_hold", release)
    _fresh_attempt(context, monkeypatch)
    assert executor.execute_existing_worker_recovery(**context) == first
    assert not controller.health()["workers"][0]["recovery_held"]
    assert len(calls) == 1


def test_pending_reconciles_on_fresh_attempt_with_original_fence(tmp_path, monkeypatch):
    context = _context(tmp_path)
    _allow_adapter(monkeypatch, context, {"operation_fence": "b" * 64})
    fence = context["operation"].fence
    assert executor.execute_existing_worker_recovery(**context).status == "failed"
    _fresh_attempt(context, monkeypatch)
    calls = _allow_adapter(monkeypatch, context)
    assert executor.execute_existing_worker_recovery(**context).status == "completed"
    assert calls[0]["operation"]["payload"]["fence"] == fence


@pytest.mark.parametrize("change", [
    {"worker_name": "qdev-qazstack-01"}, {"source_sha": "b" * 40},
])
def test_reconciliation_rejects_changed_target_or_source(tmp_path, monkeypatch, change):
    context = _context(tmp_path)
    _allow_adapter(monkeypatch, context, {"operation_fence": "b" * 64})
    assert executor.execute_existing_worker_recovery(**context).status == "failed"
    _fresh_attempt(context, monkeypatch, **change)
    calls = _allow_adapter(monkeypatch, context)
    with pytest.raises(FleetBootstrapError, match="intent changed"):
        executor.execute_existing_worker_recovery(**context)
    assert not calls
    assert context["controller_store"].health()["workers"][0]["recovery_held"]
