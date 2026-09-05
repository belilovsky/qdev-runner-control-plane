from __future__ import annotations

import json
import stat
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from bootstrap_support import KEY, candidate_receipt, operation, policy, register, request

from qdev_runner import privileged_bootstrap_executor as executor
from qdev_runner.bootstrap_authority import create_quiescence_receipt
from qdev_runner.fleet_bootstrap import FleetBootstrapRequest
from qdev_runner.host_enrolment_challenge import (
    HostEnrolmentChallenge,
    create_host_enrolment_ack,
)
from qdev_runner.store import Store


def test_signing_key_is_read_only_from_root_owned_private_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "directive.key"
    key_path.write_text("k" * 64, encoding="utf-8")
    original_stat = Path.stat

    def trusted_stat(path: Path, *args: object, **kwargs: object) -> object:
        if path == key_path:
            return SimpleNamespace(
                st_mode=stat.S_IFREG | 0o600,
                st_uid=0,
                st_size=64,
            )
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", trusted_stat)

    assert executor._read_signing_key(key_path) == "k" * 64


def test_signing_key_rejects_symlink(tmp_path: Path) -> None:
    target = tmp_path / "target.key"
    target.write_text("k" * 64, encoding="utf-8")
    link = tmp_path / "directive.key"
    link.symlink_to(target)

    with pytest.raises(executor.PrivilegedExecutorError, match="path is unsafe"):
        executor._read_signing_key(link)


def test_signing_key_rejects_permissive_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_path = tmp_path / "directive.key"
    key_path.write_text("k" * 64, encoding="utf-8")
    original_stat = Path.stat

    def permissive_stat(path: Path, *args: object, **kwargs: object) -> object:
        if path == key_path:
            return SimpleNamespace(
                st_mode=stat.S_IFREG | 0o640,
                st_uid=0,
                st_size=64,
            )
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "stat", permissive_stat)

    with pytest.raises(executor.PrivilegedExecutorError, match="file is unsafe"):
        executor._read_signing_key(key_path)


def _runtime_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> tuple[Path, Path, Path, Path]:
    release = tmp_path / "release"
    package = release / "venv/lib/python3.12/site-packages/qdev_runner/executor.py"
    package.parent.mkdir(parents=True)
    package.write_text("# installed package\n", encoding="utf-8")
    (release / "source-revision").write_text("a" * 40 + "\n", encoding="utf-8")
    (release / "bundle-digest").write_text("b" * 64 + "\n", encoding="utf-8")
    boot_id = tmp_path / "boot-id"
    boot_id.write_text("01234567-89ab-cdef-0123-456789abcdef\n", encoding="ascii")
    process_stat = tmp_path / "process-stat"
    process_stat.write_text(
        "123 (bootstrap executor) S " + " ".join(["0"] * 18 + ["987654"]) + "\n",
        encoding="utf-8",
    )
    original_lstat = Path.lstat

    def trusted_lstat(path: Path, *args: object, **kwargs: object) -> object:
        if path == release:
            return SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0)
        return original_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", trusted_lstat)
    monkeypatch.setattr(
        executor,
        "_trusted_identity_file",
        lambda path: path.read_text(encoding="utf-8").strip(),
    )
    return release, package, boot_id, process_stat


def test_runtime_identity_binds_loaded_package_and_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release, package, boot_id, process_stat = _runtime_fixture(tmp_path, monkeypatch)

    identity = executor._runtime_identity(
        release,
        package_path=package,
        process_id=123,
        boot_id_path=boot_id,
        process_stat_path=process_stat,
    )

    assert identity == {
        "schema": "qdev-bootstrap-executor-runtime-identity-v1",
        "source_revision": "a" * 40,
        "bundle_digest": "b" * 64,
        "pid": 123,
        "boot_id": "01234567-89ab-cdef-0123-456789abcdef",
        "process_start_ticks": 987654,
        "release_root": str(release),
        "package_path": str(package),
    }


def test_runtime_identity_rejects_package_outside_release(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release, _package, boot_id, process_stat = _runtime_fixture(tmp_path, monkeypatch)
    outside = tmp_path / "outside.py"
    outside.write_text("# wrong package\n", encoding="utf-8")

    with pytest.raises(executor.PrivilegedExecutorError, match="outside its release"):
        executor._runtime_identity(
            release,
            package_path=outside,
            process_id=123,
            boot_id_path=boot_id,
            process_stat_path=process_stat,
        )


def _request(action: str = "activate-controller") -> FleetBootstrapRequest:
    payload = request().model_dump(mode="json")
    payload.update({"action": action, "worker_name": None, "release_lane": None})
    if action == "enrol-host-agent":
        payload["release_lane"] = "qdev-release-qmt"
        payload["controller_candidate_receipt"] = None
    else:
        payload["controller_candidate_receipt"] = candidate_receipt()
    return FleetBootstrapRequest.model_validate(payload)


def _envelope(tmp_path: Path, action: str = "activate-controller") -> dict[str, Any]:
    controller = Store(tmp_path / "controller.db")
    register(controller)
    req = _request(action)
    authorized = operation(controller, req)
    target = executor._target(policy(), req)
    quiescence = (
        create_quiescence_receipt(
            authorized,
            target_id=target["target_id"],
            state_revision="d" * 64,
            active_jobs=0,
            signing_key=KEY,
        )
        if action == "activate-controller"
        else None
    )
    return {
        "schema": "qdev-fleet-bootstrap-adapter-request-v1",
        "operation": authorized.directive,
        "request": req.model_dump(mode="json", by_alias=True),
        "target": target,
        "active_jobs": 0 if action == "activate-controller" else None,
        "quiescence": quiescence,
    }


def _helpers(tmp_path: Path) -> dict[str, Path]:
    return {
        action: tmp_path / action
        for action in (
            "activate-controller",
            "enrol-host-agent",
            "restore-existing-worker",
        )
    }


def _native_result(envelope: dict[str, Any]) -> dict[str, Any]:
    request_value = envelope["request"]
    result: dict[str, Any] = {"native": "verified"}
    if request_value["action"] == "enrol-host-agent":
        challenge = HostEnrolmentChallenge.model_validate(
            {
                "schema": "qdev-host-enrolment-challenge-v1",
                "release_lane": envelope["target"]["release_lane"],
                "project_id": envelope["target"]["project_id"],
                "placement": envelope["target"]["placement"],
                "controller_revision": request_value["controller_revision"],
                "operation_fence": envelope["operation"]["payload"]["fence"],
                "certificate_fingerprint_sha256": "c" * 64,
                "nonce": "d" * 64,
            }
        )
        result = {
            "release_lane": envelope["target"]["release_lane"],
            "host_agent_identity": envelope["target"]["host_agent_mtls_identity"],
            "certificate_fingerprint_sha256": "c" * 64,
            "service_status": "active",
            "enrolment_ack": create_host_enrolment_ack(
                challenge,
                mtls_identity=envelope["target"]["host_agent_mtls_identity"],
                signing_key=KEY,
            ),
        }
    return {
        "schema": executor.RESULT_SCHEMA,
        "status": "completed",
        "action": request_value["action"],
        "target_id": envelope["target"]["target_id"],
        "result": result,
        "operation_fence": envelope["operation"]["payload"]["fence"],
    }


def _allow_state(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        executor,
        "_private_root",
        lambda path: path.mkdir(parents=True, exist_ok=True),
    )


def test_exact_completed_request_is_replayed_without_native_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    helpers = _helpers(tmp_path)
    _allow_state(monkeypatch)
    monkeypatch.setattr(executor, "_adapter_path", lambda path: path)
    calls = 0

    def invoke(helper: Path, value: dict[str, Any], **kwargs: object) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return _native_result(value)

    monkeypatch.setattr(executor, "_invoke_native", invoke)
    first = executor.execute_envelope(
        envelope,
        policy=policy(),
        signing_key=KEY,
        state_root=tmp_path / "state",
        helper_paths=helpers,
    )
    second = executor.execute_envelope(
        envelope,
        policy=policy(),
        signing_key=KEY,
        state_root=tmp_path / "state",
        helper_paths=helpers,
    )

    assert first == second
    assert first["status"] == "completed"
    assert calls == 1
    fence = envelope["operation"]["payload"]["fence"]
    journal = json.loads((tmp_path / "state" / f"{fence}.json").read_text())
    assert journal["phase"] == "completed"


def test_access_blocked_request_remains_retryable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    helpers = _helpers(tmp_path)
    _allow_state(monkeypatch)
    available = False

    def adapter(path: Path) -> Path | None:
        return path if available else None

    monkeypatch.setattr(executor, "_adapter_path", adapter)
    monkeypatch.setattr(
        executor,
        "_invoke_native",
        lambda helper, value, **kwargs: _native_result(value),
    )
    blocked = executor.execute_envelope(
        envelope,
        policy=policy(),
        signing_key=KEY,
        state_root=tmp_path / "state",
        helper_paths=helpers,
    )
    available = True
    completed = executor.execute_envelope(
        envelope,
        policy=policy(),
        signing_key=KEY,
        state_root=tmp_path / "state",
        helper_paths=helpers,
    )

    assert blocked["status"] == "access_blocked"
    assert completed["status"] == "completed"


def test_changed_journal_identity_cannot_reuse_fence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    helpers = _helpers(tmp_path)
    _allow_state(monkeypatch)
    monkeypatch.setattr(executor, "_adapter_path", lambda path: path)
    monkeypatch.setattr(
        executor,
        "_invoke_native",
        lambda helper, value, **kwargs: _native_result(value),
    )
    executor.execute_envelope(
        envelope,
        policy=policy(),
        signing_key=KEY,
        state_root=tmp_path / "state",
        helper_paths=helpers,
    )
    fence = envelope["operation"]["payload"]["fence"]
    journal_path = tmp_path / "state" / f"{fence}.json"
    journal = json.loads(journal_path.read_text())
    journal["identity_digest"] = "0" * 64
    journal_path.write_text(json.dumps(journal))

    with pytest.raises(executor.PrivilegedExecutorError, match="changed intent"):
        executor.execute_envelope(
            envelope,
            policy=policy(),
            signing_key=KEY,
            state_root=tmp_path / "state",
            helper_paths=helpers,
        )


def test_native_identity_mismatch_is_not_committed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    helpers = _helpers(tmp_path)
    _allow_state(monkeypatch)
    monkeypatch.setattr(executor, "_adapter_path", lambda path: path)

    def invoke(helper: Path, value: dict[str, Any], **kwargs: object) -> dict[str, Any]:
        result = _native_result(value)
        result["target_id"] = "controller:wrong"
        return executor._validate_native_result(
            result,
            request=FleetBootstrapRequest.model_validate(value["request"]),
            target=value["target"],
            active_jobs=value["active_jobs"],
            fence=value["operation"]["payload"]["fence"],
            signing_key=KEY,
        )

    monkeypatch.setattr(executor, "_invoke_native", invoke)
    with pytest.raises(executor.PrivilegedExecutorError, match="identity mismatch"):
        executor.execute_envelope(
            envelope,
            policy=policy(),
            signing_key=KEY,
            state_root=tmp_path / "state",
            helper_paths=helpers,
        )

    fence = envelope["operation"]["payload"]["fence"]
    journal = json.loads((tmp_path / "state" / f"{fence}.json").read_text())
    assert journal["phase"] == "applying"
    assert journal["result"] is None


def test_host_enrolment_requires_controller_signed_mtls_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path, "enrol-host-agent")
    result = _native_result(envelope)
    result["result"]["enrolment_ack"]["signature"] = "0" * 64

    with pytest.raises(
        executor.PrivilegedExecutorError,
        match="host enrolment acknowledgement is invalid",
    ):
        executor._validate_native_result(
            result,
            request=FleetBootstrapRequest.model_validate(envelope["request"]),
            target=envelope["target"],
            active_jobs=None,
            fence=envelope["operation"]["payload"]["fence"],
            signing_key=KEY,
        )


def test_tampered_quiescence_receipt_is_rejected(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path)
    envelope["quiescence"]["payload"]["active_jobs"] = 1

    with pytest.raises(
        executor.PrivilegedExecutorError,
        match="bootstrap quiescence authority is invalid",
    ):
        executor.execute_envelope(
            envelope,
            policy=policy(),
            signing_key=KEY,
            state_root=tmp_path / "state",
            helper_paths=_helpers(tmp_path),
        )
