from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

import qdev_runner.fleet_host_dispatch as dispatch_module
from qdev_runner.fleet_bootstrap import (
    BootstrapOperationStore,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
)
from qdev_runner.fleet_host_dispatch import (
    DISPATCH_REQUEST_SCHEMA,
    FleetHostDispatcher,
    FleetHostDispatchError,
    FleetHostDispatchSpool,
)

ROOT = Path(__file__).resolve().parents[1]


def _roots(tmp_path: Path) -> tuple[Path, Path, Path]:
    incoming = tmp_path / "spool" / "incoming"
    processing = tmp_path / "spool" / "processing"
    results = tmp_path / "spool" / "results"
    incoming.mkdir(parents=True)
    processing.mkdir()
    results.mkdir()
    incoming.chmod(0o700)
    processing.chmod(0o700)
    results.chmod(0o750)
    return incoming, processing, results


def _policy_files(tmp_path: Path) -> tuple[Path, Path, FleetBootstrapPolicy]:
    policy_root = tmp_path / "policy"
    policy_root.mkdir(mode=0o700)
    policy_path = policy_root / "fleet-bootstrap.yml"
    lanes_path = policy_root / "release-lanes.yml"
    policy_path.write_bytes((ROOT / "config/fleet-bootstrap.yml").read_bytes())
    lanes_path.write_bytes((ROOT / "config/release-lanes.yml").read_bytes())
    policy_path.chmod(0o600)
    lanes_path.chmod(0o600)
    return policy_path, lanes_path, FleetBootstrapPolicy(policy_path, lanes_path)


def _request(
    policy: FleetBootstrapPolicy,
    *,
    run_id: int = 101,
    action: str = "activate-controller",
) -> FleetBootstrapRequest:
    raw: dict[str, Any] = {
        "schema": "qdev-fleet-bootstrap-request-v1",
        "action": action,
        "source_sha": "a" * 40,
        "run_id": run_id,
        "job_id": 202,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": "a" * 40,
        "controller_release_digest": "sha256:" + "b" * 64,
        "release_lane": None,
        "worker_name": None,
    }
    if action == "enrol-host-agent":
        raw["release_lane"] = "qdev-release-qmt"
    elif action == "restore-existing-worker":
        raw["worker_name"] = "qdev-platform-ci-187"
    return FleetBootstrapRequest.model_validate(raw)


def _bridge(
    tmp_path: Path,
) -> tuple[
    FleetHostDispatchSpool,
    FleetHostDispatcher,
    FleetBootstrapPolicy,
    Path,
    Path,
    Path,
]:
    incoming, processing, results = _roots(tmp_path)
    policy_path, lanes_path, policy = _policy_files(tmp_path)
    adapter = tmp_path / "fixed-root-adapter"
    adapter.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    adapter.chmod(0o700)
    uid = os.geteuid()
    gid = os.getegid()
    spool = FleetHostDispatchSpool(
        incoming,
        results,
        runtime_uid=uid,
        runtime_gid=gid,
        result_uid=uid,
    )
    dispatcher = FleetHostDispatcher(
        request_root=incoming,
        processing_root=processing,
        result_root=results,
        policy_path=policy_path,
        release_lanes_path=lanes_path,
        activation_adapter=adapter,
        enrolment_adapter=adapter,
        recovery_adapter=adapter,
        runtime_uid=uid,
        runtime_gid=gid,
        root_uid=uid,
        root_gid=gid,
    )
    return spool, dispatcher, policy, incoming, processing, results


def _store(tmp_path: Path, key: str) -> BootstrapOperationStore:
    return BootstrapOperationStore(tmp_path / "operations" / f"{key}.json")


def test_missing_bridge_is_access_blocked_then_available_bridge_queues(
    tmp_path: Path,
) -> None:
    policy_path, lanes_path, policy = _policy_files(tmp_path)
    del policy_path, lanes_path
    uid = os.geteuid()
    gid = os.getegid()
    incoming = tmp_path / "spool" / "incoming"
    results = tmp_path / "spool" / "results"
    spool = FleetHostDispatchSpool(
        incoming,
        results,
        runtime_uid=uid,
        runtime_gid=gid,
        result_uid=uid,
    )
    request = _request(policy)

    blocked = spool.submit(
        policy=policy,
        store=_store(tmp_path, "bridge-offline-001"),
        request=request,
        idempotency_key="bridge-offline-001",
    )
    assert blocked.status == "access_blocked"
    assert blocked.error_code == "host_dispatch_unavailable"

    incoming.mkdir(parents=True)
    results.mkdir()
    incoming.chmod(0o700)
    results.chmod(0o750)
    queued = spool.submit(
        policy=policy,
        store=_store(tmp_path, "bridge-online-001"),
        request=request,
        idempotency_key="bridge-online-001",
    )
    assert queued.status == "queued"
    envelope = json.loads(
        (incoming / "bridge-online-001.json").read_text(encoding="utf-8")
    )
    assert envelope["schema"] == DISPATCH_REQUEST_SCHEMA
    assert set(envelope) == {
        "schema",
        "idempotency_key",
        "request_fingerprint",
        "request",
        "active_jobs",
    }
    assert {"command", "path", "url", "host"}.isdisjoint(envelope["request"])


def test_completed_result_is_durable_and_reused_without_reexecution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool, dispatcher, policy, incoming, _processing, results = _bridge(tmp_path)
    request = _request(policy)
    key = "completion-reuse-001"
    store = _store(tmp_path, key)
    calls = 0

    def complete_adapter(*args: Any, **kwargs: Any) -> tuple[str, dict[str, Any]]:
        nonlocal calls
        del args, kwargs
        calls += 1
        return "completed", {"rollback_revision": "b" * 40}

    monkeypatch.setattr(dispatch_module, "_invoke_bootstrap_adapter", complete_adapter)
    assert spool.submit(
        policy=policy,
        store=store,
        request=request,
        idempotency_key=key,
    ).status == "queued"
    dispatched = dispatcher.drain()
    assert len(dispatched) == 1
    assert dispatched[0].status == "completed"
    assert calls == 1
    assert not (incoming / f"{key}.json").exists()
    assert (results / f"{key}.json").exists()

    observed = spool.submit(
        policy=policy,
        store=store,
        request=request,
        idempotency_key=key,
    )
    reused = spool.submit(
        policy=policy,
        store=store,
        request=request,
        idempotency_key=key,
    )
    assert observed.status == reused.status == "completed"
    assert observed.result == reused.result
    assert calls == 1


def test_started_without_result_becomes_unknown_and_never_repeats_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    spool, dispatcher, policy, _incoming, processing, results = _bridge(tmp_path)
    request = _request(policy)
    key = "unknown-outcome-001"
    store = _store(tmp_path, key)
    calls = 0

    def crash_after_start(*args: Any, **kwargs: Any) -> tuple[str, dict[str, Any]]:
        nonlocal calls
        del args, kwargs
        calls += 1
        raise RuntimeError("simulated process loss after mutation boundary")

    monkeypatch.setattr(
        dispatch_module, "_invoke_bootstrap_adapter", crash_after_start
    )
    spool.submit(
        policy=policy,
        store=store,
        request=request,
        idempotency_key=key,
    )
    with pytest.raises(RuntimeError, match="simulated process loss"):
        dispatcher.drain()
    assert calls == 1
    assert (processing / f"{key}.request.json").exists()
    assert (processing / f"{key}.started.json").exists()
    assert not (results / f"{key}.json").exists()

    reconciled = dispatcher.drain()
    assert len(reconciled) == 1
    assert reconciled[0].status == "unknown"
    assert reconciled[0].error_code == (
        "operation_outcome_unknown_reconciliation_required"
    )
    assert calls == 1
    observation = spool.submit(
        policy=policy,
        store=store,
        request=request,
        idempotency_key=key,
    )
    assert observation.status == "unknown"
    assert observation.operation_status == "unknown"
    assert observation.result is None


def test_dispatch_rejects_tampering_symlinks_and_path_traversal(
    tmp_path: Path,
) -> None:
    spool, dispatcher, policy, incoming, _processing, _results = _bridge(tmp_path)
    request = _request(policy)
    key = "tampered-request-001"
    spool.submit(
        policy=policy,
        store=_store(tmp_path, key),
        request=request,
        idempotency_key=key,
    )
    request_path = incoming / f"{key}.json"
    envelope = json.loads(request_path.read_text(encoding="utf-8"))
    envelope["command"] = ["/bin/sh", "-c", "id"]
    request_path.write_text(json.dumps(envelope), encoding="utf-8")
    request_path.chmod(0o600)
    with pytest.raises(FleetHostDispatchError, match="request shape"):
        dispatcher.drain()

    request_path.unlink()
    target = tmp_path / "attacker-controlled.json"
    target.write_text("{}", encoding="utf-8")
    (incoming / "symlink-request-001.json").symlink_to(target)
    with pytest.raises(FleetHostDispatchError, match="unreadable"):
        dispatcher.drain()

    with pytest.raises(FleetHostDispatchError, match="idempotency key"):
        spool.submit(
            policy=policy,
            store=_store(tmp_path, "escape-attempt-001"),
            request=request,
            idempotency_key="../escape-attempt-001",
        )


def test_dispatch_rejects_duplicate_fingerprint_drift(tmp_path: Path) -> None:
    spool, _dispatcher, policy, _incoming, _processing, _results = _bridge(tmp_path)
    key = "fingerprint-drift-001"
    store = _store(tmp_path, key)
    spool.submit(
        policy=policy,
        store=store,
        request=_request(policy),
        idempotency_key=key,
    )
    with pytest.raises(RuntimeError, match="different parameters"):
        spool.submit(
            policy=policy,
            store=store,
            request=_request(policy, run_id=303),
            idempotency_key=key,
        )


def test_root_dispatch_reloads_and_rejects_writable_policy(tmp_path: Path) -> None:
    spool, dispatcher, policy, _incoming, _processing, _results = _bridge(tmp_path)
    key = "unsafe-policy-001"
    spool.submit(
        policy=policy,
        store=_store(tmp_path, key),
        request=_request(policy),
        idempotency_key=key,
    )
    dispatcher.policy_path.chmod(0o660)
    with pytest.raises(FleetHostDispatchError, match="permissions"):
        dispatcher.drain()


def test_deployment_exposes_only_spools_and_declares_root_path_unit() -> None:
    compose = (ROOT / "deploy/compose.yml").read_text(encoding="utf-8")
    service = (ROOT / "deploy/qdev-fleet-host-dispatch.service").read_text(
        encoding="utf-8"
    )
    path_unit = (ROOT / "deploy/qdev-fleet-host-dispatch.path").read_text(
        encoding="utf-8"
    )
    provision = (ROOT / "scripts/provision_controller.sh").read_text(
        encoding="utf-8"
    )

    assert "/usr/local/sbin:/usr/local/sbin" not in compose
    assert "/var/run/docker.sock" not in compose
    assert "/run/docker.sock" not in compose
    assert "fleet-host-dispatch/incoming" in compose
    assert "fleet-host-dispatch/results" in compose
    assert "fleet-host-dispatch/results:ro" in compose
    assert "User=root" in service
    assert "ExecStart=/usr/bin/python3 -I /usr/local/libexec/qdev-fleet-host-dispatch" in service
    assert "PathExistsGlob=/var/lib/qdev-runner/fleet-host-dispatch/incoming/*.json" in path_unit
    assert "Unit=qdev-fleet-host-dispatch.service" in path_unit
    assert "qdev-fleet-host-dispatch.service" in provision
    assert "qdev-fleet-host-dispatch.path" in provision
    assert "-m 0700" in provision
    assert "-m 0750" in provision
