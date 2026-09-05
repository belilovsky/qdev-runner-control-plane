from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from bootstrap_support import KEY, candidate_receipt, operation, policy, register, request

from qdev_runner import fleet_bootstrap_operation_executor as executor
from qdev_runner.fleet_bootstrap import BootstrapOperationStore, FleetBootstrapRequest
from qdev_runner.models import QueuedJob
from qdev_runner.store import Store


def _request(action: str):
    payload = request().model_dump(mode="json")
    payload.update({"action": action, "worker_name": None})
    if action == "enrol-host-agent":
        payload["release_lane"] = "qdev-release-qmt"
        payload["controller_candidate_receipt"] = None
    else:
        payload["release_lane"] = None
        payload["controller_candidate_receipt"] = candidate_receipt()
    return FleetBootstrapRequest.model_validate(payload)


def _context(tmp_path: Path, action: str = "activate-controller") -> dict:
    controller = Store(tmp_path / "controller.db")
    req = _request(action)
    register(controller)
    return {
        "policy": policy(),
        "store": BootstrapOperationStore(tmp_path / "operation.json"),
        "operation": operation(controller, req),
        "signing_key": KEY,
        "controller_store": controller,
        "activation_adapter": tmp_path / "activation-adapter",
        "enrolment_adapter": tmp_path / "enrolment-adapter",
        "receipt_path": tmp_path / "receipt.json",
    }


def _allow_adapter(
    monkeypatch: pytest.MonkeyPatch, context: dict, reply: dict | None = None
) -> list[dict]:
    monkeypatch.setattr(executor, "_adapter_path", lambda value: value)
    calls: list[dict] = []

    def run(args, **kwargs):
        envelope = json.loads(kwargs["input"])
        calls.append(envelope)
        response = {
            "schema": executor.RESULT_SCHEMA,
            "status": "completed",
            "action": envelope["request"]["action"],
            "target_id": envelope["target"]["target_id"],
            "result": {"native": "verified"},
            "operation_fence": envelope["operation"]["payload"]["fence"],
        }
        if reply:
            response.update(reply)
        return subprocess.CompletedProcess(args, 0, json.dumps(response), "")

    monkeypatch.setattr(executor.subprocess, "run", run)
    return calls


@pytest.mark.parametrize("action", ["activate-controller", "enrol-host-agent"])
def test_policy_derives_target_and_success_is_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    context = _context(tmp_path, action)
    calls = _allow_adapter(monkeypatch, context)

    first = executor.execute_bootstrap_operation(**context)
    second = executor.execute_bootstrap_operation(**context)

    assert first == second
    assert first.status == "completed"
    assert len(calls) == 1
    assert calls[0]["target"]["target_id"] == first.target_id
    if action == "activate-controller":
        assert calls[0]["target"]["artifact_ref"].endswith("@sha256:" + "b" * 64)
        assert calls[0]["active_jobs"] == 0
    else:
        assert calls[0]["target"]["release_lane"] == "qdev-release-qmt"
        assert calls[0]["target"]["placement"] == "srv138jump"
        assert calls[0]["active_jobs"] is None
    assert json.loads((tmp_path / "receipt.json").read_text())["status"] == "completed"


def test_completed_activation_replay_releases_its_hold_and_restores_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(tmp_path)
    calls = _allow_adapter(monkeypatch, context)
    controller: Store = context["controller_store"]
    release = controller.release_controller_hold
    monkeypatch.setattr(controller, "release_controller_hold", lambda _fence: None)

    first = executor.execute_bootstrap_operation(**context)

    assert first.status == "completed"
    assert controller.claim("other-executor", ("qdev-ci",)) is None
    context["receipt_path"].unlink()
    monkeypatch.setattr(controller, "release_controller_hold", release)

    replay = executor.execute_bootstrap_operation(**context)

    assert replay == first
    assert len(calls) == 1
    assert json.loads(context["receipt_path"].read_text())["status"] == "completed"


def test_completed_activation_replay_restores_receipt_after_persist_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(tmp_path)
    calls = _allow_adapter(monkeypatch, context)
    persist = executor._persist_receipt
    failures = 0

    def fail_once(path: Path, payload: dict) -> None:
        nonlocal failures
        failures += 1
        if failures == 1:
            raise OSError("simulated receipt persistence failure")
        persist(path, payload)

    monkeypatch.setattr(executor, "_persist_receipt", fail_once)
    with pytest.raises(OSError, match="simulated receipt"):
        executor.execute_bootstrap_operation(**context)

    replay = executor.execute_bootstrap_operation(**context)

    assert replay.status == "completed"
    assert len(calls) == 1
    assert json.loads(context["receipt_path"].read_text())["status"] == "completed"


def test_activation_refuses_other_active_controller_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    context = _context(tmp_path)
    controller: Store = context["controller_store"]
    controller.enqueue(
        QueuedJob(
            "other",
            999,
            999,
            "belilovsky/qdev-runner-control-plane",
            1,
            300,
            ("self-hosted", "qdev-ci"),
            "c" * 40,
            "main",
            {},
        )
    )
    assert controller.claim("other-executor", ("qdev-ci",)) is not None
    calls = _allow_adapter(monkeypatch, context)

    result = executor.execute_bootstrap_operation(**context)

    assert result.status == "active_work"
    assert result.active_jobs == 1
    assert not calls
    assert not (tmp_path / "receipt.json").exists()


@pytest.mark.parametrize(
    "reply",
    [
        {"action": "enrol-host-agent"},
        {"target_id": "release-lane:other"},
        {"operation_fence": "f" * 64},
        {"result": {"token": "must-not-be-recorded"}},
    ],
)
def test_adapter_mismatch_or_sensitive_result_never_completes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reply: dict
) -> None:
    context = _context(tmp_path)
    _allow_adapter(monkeypatch, context, reply)

    result = executor.execute_bootstrap_operation(**context)

    assert result.status == "failed"
    assert result.operation_status == "pending"
    assert not (tmp_path / "receipt.json").exists()


def test_missing_root_owned_adapter_is_access_blocked(tmp_path: Path) -> None:
    result = executor.execute_bootstrap_operation(**_context(tmp_path))
    assert result.status == "access_blocked"
    assert result.operation_status == "pending"
