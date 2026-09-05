from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest
from bootstrap_support import operation, policy, register, request

from qdev_runner import worker_recovery_native as recovery
from qdev_runner.store import Store


def _envelope(tmp_path: Any, worker: str = "srv1879763-primary") -> dict[str, Any]:
    controller = Store(tmp_path / "controller.db")
    register(controller, worker=worker)
    intent = request(worker)
    authority = operation(controller, intent)
    target = policy().worker_target(worker)
    assert target is not None
    return {
        "schema": "qdev-fleet-worker-recovery-request-v2",
        "operation": authority.directive,
        "request": intent.model_dump(mode="json", by_alias=True),
        "target": {
            "worker_name": target.worker_name,
            "target_id": target.target_id,
            "service_unit": target.service_unit,
            "host_binding": target.host_binding,
            "labels": list(target.labels),
            "certificate_fingerprint_sha256": target.certificate_fingerprint_sha256,
        },
        "active_jobs": 0,
    }


def _completed(returncode: int, stdout: str = "") -> Any:
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr="")


def test_active_registered_worker_is_idempotent(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        recovery,
        "_run_systemctl",
        lambda *args: calls.append(args) or _completed(0, "active\n"),
    )

    result = recovery.execute(envelope, policy=policy())

    assert result["status"] == "already_completed"
    assert result["result"] == {"service_active": True}
    assert calls == [("is-active", envelope["target"]["service_unit"])]


def test_inactive_registered_worker_is_restarted_and_verified(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    results = iter([_completed(3), _completed(0), _completed(0, "active\n")])
    calls: list[tuple[str, ...]] = []
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        recovery,
        "_run_systemctl",
        lambda *args: calls.append(args) or next(results),
    )

    result = recovery.execute(envelope, policy=policy())

    assert result["status"] == "completed"
    assert result["result"] == {"service_active": True}
    assert calls == [
        ("is-active", envelope["target"]["service_unit"]),
        ("restart", envelope["target"]["service_unit"]),
        ("is-active", envelope["target"]["service_unit"]),
    ]


def test_failed_restart_is_not_reported_as_recovered(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    results = iter([_completed(3), _completed(1), _completed(3, "inactive\n")])
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 0)
    monkeypatch.setattr(recovery, "_run_systemctl", lambda *args: next(results))

    result = recovery.execute(envelope, policy=policy())

    assert result["status"] == "failed"
    assert result["result"] == {
        "service_active": False,
        "error_code": "service_restart_failed",
    }


def test_caller_cannot_change_registered_target(
    tmp_path: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    envelope["target"]["service_unit"] = "attacker.service"
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 0)

    with pytest.raises(recovery.WorkerRecoveryError, match="differs from policy"):
        recovery.execute(envelope, policy=policy())


def test_worker_recovery_requires_root(tmp_path: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    envelope = _envelope(tmp_path)
    monkeypatch.setattr(recovery.os, "geteuid", lambda: 1000)

    with pytest.raises(recovery.WorkerRecoveryError, match="requires root"):
        recovery.execute(envelope, policy=policy())
