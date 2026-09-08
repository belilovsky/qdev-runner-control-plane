import hashlib
import hmac
import importlib.util
import json
import os
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
import yaml

import qdev_runner.release_lane as RELEASE_LANE
from qdev_runner.release_lane import (
    HostHeartbeatRequest,
    ReleaseAdmissionRequest,
    ReleaseLanePolicy,
    ReleaseStore,
)

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qdev_admin_platform_release_host_agent.py"
SPEC = importlib.util.spec_from_file_location("qdev_admin_platform_release_host_agent", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AGENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AGENT
SPEC.loader.exec_module(AGENT)

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
SECRET = b"managed-host-dispatch-test-secret"
RELEASE_ID = "release-operation-0001"
LEASE_ID = "lease-operation-0001"
FENCE = "f" * 24
NONCE = "n" * 32


def _release(profile: object) -> dict[str, str]:
    return {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"{profile.artifact_prefix}@{DIGEST}",
    }


def _variant(profile: object, marker: str) -> dict[str, str]:
    digest = "sha256:" + marker * 64
    return {
        "source_sha": marker * 40,
        "artifact_digest": digest,
        "artifact_ref": f"{profile.artifact_prefix}@{digest}",
    }


def _native_receipt(profile: object, release: dict[str, str]) -> dict[str, Any]:
    if profile.name == "qmt":
        dependencies = {"qmt_version": "4.4.2"}
        provenance = {
            "candidate_receipt_sha256": "4" * 64,
            "migration_receipt_digest": "sha256:" + "5" * 64,
            "contract_digest": "6" * 64,
        }
    else:
        dependencies = {"qaz_admin_kit": "0.4.9", "avds": "0.2.2"}
        provenance = {
            "qak_wheel_sha256": "1" * 64,
            "avds_artifact_sha256": "2" * 64,
            "avds_source_sha": "3" * 40,
        }
    return {
        "schema": AGENT.NATIVE_RECEIPT_SCHEMA,
        "project_id": profile.project_id,
        "native_host_adapter": profile.adapter,
        **release,
        "readiness": profile.readiness,
        "runtime_identity": {**release, "measured": True},
        "dependency_identity": dependencies,
        "artifact_provenance": provenance,
    }


def _candidate_evidence(profile: object) -> dict[str, str]:
    if profile.name == "qmt":
        return {
            "schema": "qdev-qmt-candidate-evidence-v1",
            "candidate_receipt_sha256": "4" * 64,
            "release_version": "4.4.2",
            "migration_receipt_digest": "sha256:" + "5" * 64,
            "contract_digest": "6" * 64,
        }
    return {
        "schema": "qdev-release-candidate-evidence-v1",
        "candidate_receipt_sha256": "4" * 64,
    }


def _config(profile: object) -> object:
    return AGENT.Config(
        controller_url="https://worker.ci.qdev.run",
        client_cert=Path("/fixed/client.crt"),
        client_key=Path("/fixed/client.key"),
        controller_ca=Path("/fixed/controller-ca.crt"),
        host_identity=f"qdev-host-agent:{profile.placement}",
        dispatch_secret=SECRET,
    )


def _signed_job(
    profile: object,
    config: object,
    candidate: dict[str, str],
    *,
    now: int | None = None,
    nonce: str = NONCE,
    workflow: str = "ci.yml",
    job_name: str = "release",
    lease_expires_at: int | None = None,
    rollback_anchor: dict[str, str] | None = None,
) -> dict[str, Any]:
    issued_at = int(time.time()) if now is None else now
    if lease_expires_at is None:
        lease_expires_at = issued_at + 3600
    if rollback_anchor is None:
        rollback_anchor = _variant(profile, "b")
    candidate_evidence = _candidate_evidence(profile)
    claim = {
        "schema": AGENT.HOST_DISPATCH_CLAIM_SCHEMA,
        "repository": profile.repository,
        "workflow": workflow,
        "job": job_name,
        "exact_sha": candidate["source_sha"],
        "run_id": 101,
        "job_id": 202,
        "attempt": 1,
        "runner_profile": "qdev-ci-docker",
        "host_identity": config.host_identity,
        "release_id": RELEASE_ID,
        "release_lane": profile.lane,
        "project_id": profile.project_id,
        "placement": profile.placement,
        "artifact_digest": candidate["artifact_digest"],
        "artifact_ref": candidate["artifact_ref"],
        "lease_id": LEASE_ID,
        "fence": FENCE,
        "lease_expires_at": lease_expires_at,
        "rollback_anchor": rollback_anchor,
        "candidate_evidence": candidate_evidence,
        "issued_at": issued_at,
        "expires_at": min(issued_at + 120, lease_expires_at),
        "nonce": nonce,
    }
    return {
        "schema": "qdev-release-host-agent-job-v1",
        "release_id": RELEASE_ID,
        "release_lane": profile.lane,
        "project_id": profile.project_id,
        "placement": profile.placement,
        **candidate,
        "lease_id": LEASE_ID,
        "fence": FENCE,
        "lease_expires_at": lease_expires_at,
        "rollback_anchor": rollback_anchor,
        "candidate_evidence": candidate_evidence,
        "dispatch_claim": claim,
        "dispatch_claim_signature": hmac.new(
            SECRET, AGENT._canonical_bytes(claim), hashlib.sha256
        ).hexdigest(),
    }


def _test_profile(tmp_path: Path, name: str = "total") -> object:
    root = tmp_path / "agent"
    root.mkdir()
    base = AGENT.PROFILES[name]
    return replace(
        base,
        minimum_free_gib=0,
        state_path=root / "state.json",
        lock_path=root / "agent.lock",
        release_dispatcher=root / "release",
        rollback_dispatcher=root / "rollback",
        receipt_dispatcher=root / "receipt",
    )


def _provision_agent_state(
    profile: object,
    active: dict[str, str],
    rollback: dict[str, str],
) -> None:
    """Create a state backed by an already completed measured bootstrap."""
    AGENT._write_journal(
        profile,
        "bootstrap_anchor_measured",
        active_release=rollback,
        rollback=rollback,
    )
    AGENT._write_journal(
        profile,
        "bootstrap_anchor_persisted",
        active_release=rollback,
        rollback=rollback,
    )
    AGENT.write_state(profile.state_path, active, rollback)


def _controller_status(
    profile: object,
    candidate: dict[str, str],
    status: str = "accepted",
    *,
    runtime_receipt: dict[str, Any] | None = None,
    rollback_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "schema": "qdev-controller-release-status-v1",
        "release_id": RELEASE_ID,
        "status": status,
        "release_lane": profile.lane,
        "project_id": profile.project_id,
        "placement": profile.placement,
        **candidate,
        "runtime_receipt": runtime_receipt,
        "rollback_receipt": rollback_receipt,
    }


def _lane_release(lane: object, marker: str) -> dict[str, str]:
    digest = "sha256:" + marker * 64
    return {
        "source_sha": marker * 40,
        "artifact_digest": digest,
        "artifact_ref": f"{lane.artifact_ref_prefix}@{digest}",
    }


def _managed_request(
    lane: object,
    candidate: dict[str, str],
    *,
    now: int,
    nonce: str = NONCE,
    workflow: str = "ci.yml",
    job_name: str = "release",
) -> ReleaseAdmissionRequest:
    receipt = {
        "schema": "qdev-release-candidate-receipt-v1",
        "status": "passed",
        **candidate,
        "repository": lane.canonical_repository,
        "workflow": workflow,
        "job": job_name,
        "run_id": 101,
        "job_id": 202,
        "attempt": 1,
        "runner_profile": "qdev-ci-docker",
    }
    request = ReleaseAdmissionRequest.model_validate(
        {
            "schema": RELEASE_LANE.REQUEST_SCHEMA,
            "release_lane": lane.name,
            "project_id": lane.project_id,
            "placement": lane.placement,
            **candidate,
            "candidate_receipt": receipt,
        }
    )
    claim = RELEASE_LANE.controller_claim_payload(
        request,
        lane,
        issued_at=now,
        expires_at=now + 120,
        nonce=nonce,
    )
    return request.model_copy(
        update={
            "controller_claim": claim,
            "controller_claim_signature": hmac.new(
                SECRET,
                RELEASE_LANE._canonical_bytes(claim),
                hashlib.sha256,
            ).hexdigest(),
        }
    )


def _host_heartbeat(
    lane: object,
    active: dict[str, str],
    rollback: dict[str, str],
    *,
    bootstrap: bool,
) -> HostHeartbeatRequest:
    return HostHeartbeatRequest.model_validate(
        {
            "schema": RELEASE_LANE.HOST_HEARTBEAT_SCHEMA,
            "release_lane": lane.name,
            "project_id": lane.project_id,
            "placement": lane.placement,
            "state": "ready",
            "release_lock": "available",
            "capacity_free_gib": lane.minimum_free_gib + 10,
            "active_release": active,
            "rollback": {"verified": True, **rollback},
            "bootstrap": bootstrap,
        }
    )


def _native_lane_receipt(lane: object, release: dict[str, str]) -> dict[str, Any]:
    return {
        "schema": "qdev-admin-platform-native-receipt-v1",
        "project_id": lane.project_id,
        "native_host_adapter": lane.native_host_adapter,
        **release,
        "readiness": {name: "ok" for name in lane.required_readiness},
        "runtime_identity": {**release, "measured": True},
        "dependency_identity": {"qaz_admin_kit": "0.4.9", "avds": "0.2.2"},
        "artifact_provenance": {
            "qak_wheel_sha256": "1" * 64,
            "avds_artifact_sha256": "2" * 64,
            "avds_source_sha": "3" * 40,
        },
    }


def _controller_rollback_receipt(
    lane: object,
    job: dict[str, Any],
    restored: dict[str, str],
) -> dict[str, Any]:
    failed = {key: job[key] for key in ("source_sha", "artifact_digest", "artifact_ref")}
    return {
        "schema": RELEASE_LANE.ROLLBACK_RECEIPT_SCHEMA,
        "status": "rolled_back",
        "project_id": lane.project_id,
        "release_lane": lane.name,
        "placement": lane.placement,
        "release_id": job["release_id"],
        "failed_release": failed,
        "restored_release": restored,
        "native_receipt": _native_lane_receipt(lane, restored),
    }


def _patch_local_security(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(AGENT, "_root_directory", lambda _: None)
    monkeypatch.setattr(AGENT, "_private", lambda *_, **__: None)


def test_admin_platform_lanes_are_exact_and_total_has_no_total_kz_endpoint() -> None:
    policy = ReleaseLanePolicy(ROOT / "config/release-lanes.yml")
    expected = {
        "qdev-release-ortcom": ("belilovsky/ortcom-kz", "ortcom-root-deploy-v1"),
        "qdev-release-cmnt": ("belilovsky/cmnt-web", "cmnt-root-rolling-launcher-v1"),
        "qdev-release-total": ("belilovsky/total-kz", "total-qdev-native-release-v1"),
        "qdev-release-qazposter": ("belilovsky/qazposter", "qazposter-native-release-v1"),
    }
    for lane_name, (repository, adapter) in expected.items():
        lane = policy.lane(lane_name)
        assert lane.canonical_repository == repository
        assert lane.native_host_adapter == adapter
        assert lane.runtime_endpoints
        assert lane.required_readiness == ("native", "public", "identity")
    total_lane = policy.lane("qdev-release-total")
    assert all("total.kz" not in endpoint for endpoint in total_lane.runtime_endpoints)


def test_product_lanes_cannot_drift_from_the_managed_registry() -> None:
    policy = ReleaseLanePolicy(ROOT / "config/release-lanes.yml")
    registry = yaml.safe_load((ROOT / "config/managed-registry.yml").read_text(encoding="utf-8"))
    entries = registry["entries"]
    names = {
        "qdev-release-ortcom": "ortcom",
        "qdev-release-cmnt": "cmnt",
        "qdev-release-total": "total",
        "qdev-release-qazposter": "qazposter",
        "qdev-release-qazagents-static": "qazagents",
    }
    for lane_name, registry_name in names.items():
        lane = policy.lane(lane_name)
        entry = entries[registry_name]
        assert lane.project_id == entry["project_id"]
        assert lane.canonical_repository == entry["repository"]
        assert list(lane.runtime_endpoints) == entry["runtime_endpoints"]
        assert lane.rollback_reference == entry["rollback_reference"]


def test_qazagents_static_lane_is_separate_from_qgeo_container_contract() -> None:
    policy = ReleaseLanePolicy(ROOT / "config/release-lanes.yml")
    lane = policy.lane("qdev-release-qazagents-static")
    assert lane.project_id == "qazagents"
    assert lane.artifact_repository == "qazagents-static"
    assert lane.native_host_adapter == "qazagents-static-release-v1"
    assert "qgeo" not in lane.native_host_adapter
    assert lane.required_readiness == ("native", "public", "identity")
    assert all(
        endpoint.startswith("https://qazagents.qdev.run/") for endpoint in lane.runtime_endpoints
    )


def test_controller_managed_claim_dispatch_and_nonce_are_bound_and_expiring(
    tmp_path: Path,
) -> None:
    lane = ReleaseLanePolicy(ROOT / "config/release-lanes.yml").lane("qdev-release-total")
    store = ReleaseStore(tmp_path / "store")
    now = 2_000_000_000
    anchor = _lane_release(lane, "b")
    candidate = _lane_release(lane, "a")
    store.record_heartbeat(
        lane,
        _host_heartbeat(lane, anchor, anchor, bootstrap=True),
        identity=lane.host_agent_mtls_identity,
        now=now,
    )
    request = _managed_request(lane, candidate, now=now)
    RELEASE_LANE.validate_controller_claim(request, lane, signing_key=SECRET, now=now)

    changed_receipt = {
        **request.candidate_receipt,
        "workflow": "other.yml",
    }
    rebound = request.model_copy(update={"candidate_receipt": changed_receipt})
    with pytest.raises(RELEASE_LANE.ReleaseLaneError, match="does not bind"):
        RELEASE_LANE.validate_controller_claim(rebound, lane, signing_key=SECRET, now=now)
    with pytest.raises(RELEASE_LANE.ReleaseLaneError, match="expired"):
        RELEASE_LANE.validate_controller_claim(request, lane, signing_key=SECRET, now=now + 120)

    job, duplicate = store.admit(request, lane, now=now, lease_ttl_seconds=600)
    assert duplicate is False
    assert job["lease_expires_at"] == now + 600
    assert job["rollback_anchor"] == anchor
    dispatched = store.next_job(
        lane,
        host_identity=lane.host_agent_mtls_identity,
        dispatch_signing_key=SECRET,
        now=now + 1,
    )
    assert dispatched is not None
    assert dispatched["dispatch_claim"]["workflow"] == "ci.yml"
    assert dispatched["dispatch_claim"]["job"] == "release"
    assert dispatched["dispatch_claim"]["lease_expires_at"] == now + 600
    assert dispatched["dispatch_claim"]["rollback_anchor"] == anchor
    assert dispatched["dispatch_claim"]["expires_at"] <= now + 600

    rolled_back = store.rollback(
        lane,
        job["release_id"],
        _controller_rollback_receipt(lane, job, anchor),
        lease_id=job["lease_id"],
        fence=job["fence"],
        now=now + 2,
    )
    assert rolled_back["status"] == "rolled_back"

    replay = _managed_request(
        lane,
        _lane_release(lane, "c"),
        now=now + 3,
        nonce=NONCE,
    )
    RELEASE_LANE.validate_controller_claim(replay, lane, signing_key=SECRET, now=now + 3)
    with pytest.raises(RELEASE_LANE.ReleaseLaneError, match="already consumed"):
        store.admit(replay, lane, now=now + 3, lease_ttl_seconds=600)


def test_controller_lease_fence_and_frozen_rollback_anchor_are_fail_closed(
    tmp_path: Path,
) -> None:
    lane = ReleaseLanePolicy(ROOT / "config/release-lanes.yml").lane("qdev-release-total")
    store = ReleaseStore(tmp_path / "store")
    now = 2_000_000_000
    anchor = _lane_release(lane, "b")
    candidate = _lane_release(lane, "a")
    store.record_heartbeat(
        lane,
        _host_heartbeat(lane, anchor, anchor, bootstrap=True),
        identity=lane.host_agent_mtls_identity,
        now=now,
    )
    request = _managed_request(lane, candidate, now=now)
    RELEASE_LANE.validate_controller_claim(request, lane, signing_key=SECRET, now=now)
    job, _ = store.admit(request, lane, now=now, lease_ttl_seconds=60)
    store.next_job(
        lane,
        host_identity=lane.host_agent_mtls_identity,
        dispatch_signing_key=SECRET,
        now=now + 1,
    )
    receipt = _controller_rollback_receipt(lane, job, anchor)
    with pytest.raises(RELEASE_LANE.ReleaseLaneError, match="fence"):
        store.rollback(
            lane,
            job["release_id"],
            receipt,
            lease_id=job["lease_id"],
            fence="0" * 24,
            now=now + 2,
        )
    wrong_anchor = _lane_release(lane, "c")
    with pytest.raises(RELEASE_LANE.ReleaseLaneError, match="frozen"):
        store.rollback(
            lane,
            job["release_id"],
            _controller_rollback_receipt(lane, job, wrong_anchor),
            lease_id=job["lease_id"],
            fence=job["fence"],
            now=now + 2,
        )
    # Expiry closes new admission/dispatch, but an exact durably dispatched
    # operation may still report its single terminal rollback during the
    # bounded recovery window. This prevents an already-mutated host from
    # becoming permanently stranded when the lease expires mid-operation.
    recovered = store.rollback(
        lane,
        job["release_id"],
        receipt,
        lease_id=job["lease_id"],
        fence=job["fence"],
        now=now + 60,
    )
    assert recovered["status"] == "rolled_back"


def test_controller_journal_is_authoritative_after_snapshot_crash(
    tmp_path: Path,
) -> None:
    lane = ReleaseLanePolicy(ROOT / "config/release-lanes.yml").lane("qdev-release-total")
    store = ReleaseStore(tmp_path / "store")
    now = 2_000_000_000
    anchor = _lane_release(lane, "b")
    candidate = _lane_release(lane, "a")
    store.record_heartbeat(
        lane,
        _host_heartbeat(lane, anchor, anchor, bootstrap=True),
        identity=lane.host_agent_mtls_identity,
        now=now,
    )
    request = _managed_request(lane, candidate, now=now)
    RELEASE_LANE.validate_controller_claim(request, lane, signing_key=SECRET, now=now)
    accepted, _ = store.admit(request, lane, now=now, lease_ttl_seconds=600)
    accepted_snapshot = json.loads(json.dumps(accepted))
    dispatched = store.next_job(
        lane,
        host_identity=lane.host_agent_mtls_identity,
        dispatch_signing_key=SECRET,
        now=now + 1,
    )
    assert dispatched is not None

    snapshot_path = store._job_path(lane.name)
    store._write(snapshot_path, accepted_snapshot)
    reconciled = store.job(lane, dispatched["release_id"])
    assert reconciled == dispatched
    assert store._read(snapshot_path) == dispatched

    snapshot_path.unlink()
    assert store.job(lane, dispatched["release_id"]) == dispatched
    forged = json.loads(json.dumps(dispatched))
    forged["operation_phase"] = "forged"
    store._write(snapshot_path, forged)
    with pytest.raises(RELEASE_LANE.ReleaseLaneError, match="diverges"):
        store.job(lane, dispatched["release_id"])


def test_controller_initial_heartbeat_establishes_one_measured_anchor(
    tmp_path: Path,
) -> None:
    lane = ReleaseLanePolicy(ROOT / "config/release-lanes.yml").lane("qdev-release-total")
    store = ReleaseStore(tmp_path / "store")
    now = 2_000_000_000
    anchor = _lane_release(lane, "b")
    other = _lane_release(lane, "c")
    with pytest.raises(RELEASE_LANE.ReleaseLaneError, match="first managed"):
        store.record_heartbeat(
            lane,
            _host_heartbeat(lane, other, anchor, bootstrap=False),
            identity=lane.host_agent_mtls_identity,
            now=now,
        )
    store.record_heartbeat(
        lane,
        _host_heartbeat(lane, anchor, anchor, bootstrap=True),
        identity=lane.host_agent_mtls_identity,
        now=now,
    )
    with pytest.raises(RELEASE_LANE.ReleaseLaneError, match="cannot change"):
        store.record_heartbeat(
            lane,
            _host_heartbeat(lane, other, other, bootstrap=True),
            identity=lane.host_agent_mtls_identity,
            now=now + 1,
        )
    store.record_heartbeat(
        lane,
        _host_heartbeat(lane, other, anchor, bootstrap=False),
        identity=lane.host_agent_mtls_identity,
        now=now + 1,
    )
    with pytest.raises(RELEASE_LANE.ReleaseLaneError, match="return to bootstrap"):
        store.record_heartbeat(
            lane,
            _host_heartbeat(lane, other, other, bootstrap=True),
            identity=lane.host_agent_mtls_identity,
            now=now + 2,
        )


def test_agent_profiles_bind_each_release_to_a_compiled_native_adapter() -> None:
    assert set(AGENT.PROFILES) == {"ortcom", "cmnt", "total", "qazposter", "qmt"}
    for profile in AGENT.PROFILES.values():
        release = _release(profile)
        assert AGENT._release(release, profile) == release
        assert profile.release_dispatcher.is_absolute()
        assert profile.rollback_dispatcher.is_absolute()
        assert profile.receipt_dispatcher.is_absolute()
        assert profile.readiness == {"identity": "ok", "native": "ok", "public": "ok"}
        invalid = {**release, "artifact_ref": "registry.example.invalid/unsafe@" + DIGEST}
        try:
            AGENT._release(invalid, profile)
        except AGENT.AgentError:
            pass
        else:  # pragma: no cover - protects the fail-closed boundary
            raise AssertionError("untrusted artifact reference was accepted")


def test_qmt_candidate_evidence_is_exact_and_version_bound() -> None:
    profile = AGENT.PROFILES["qmt"]
    evidence = _candidate_evidence(profile)
    assert AGENT._candidate_evidence(evidence, profile) == evidence
    for field, invalid in (
        ("release_version", "4.4.1"),
        ("migration_receipt_digest", "sha256:" + "z" * 64),
        ("contract_digest", "0" * 63),
    ):
        with pytest.raises(AGENT.AgentError, match="QMT candidate evidence"):
            AGENT._candidate_evidence({**evidence, field: invalid}, profile)
    with pytest.raises(AGENT.AgentError, match="shape"):
        AGENT._candidate_evidence({**evidence, "image_digest": DIGEST}, profile)


def test_qmt_native_release_receives_only_signed_candidate_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = AGENT.PROFILES["qmt"]
    release = _release(profile)
    evidence = _candidate_evidence(profile)
    commands: list[list[str]] = []
    monkeypatch.setattr(AGENT, "_ensure_dispatcher", lambda _: None)
    monkeypatch.setattr(
        AGENT,
        "_run",
        lambda command, **_: commands.append(command) or b"",
    )
    with pytest.raises(AGENT.AgentError, match="signed candidate evidence"):
        AGENT.invoke_native(profile, "release", release)
    AGENT.invoke_native(profile, "release", release, evidence)
    command = commands[-1]
    assert command[0] == str(profile.release_dispatcher)
    assert command[1:3] == ["--action", "release"]
    for flag, value in (
        ("--candidate-receipt-sha256", evidence["candidate_receipt_sha256"]),
        ("--release-version", "4.4.2"),
        ("--migration-receipt-digest", evidence["migration_receipt_digest"]),
        ("--contract-digest", evidence["contract_digest"]),
    ):
        assert command[command.index(flag) + 1] == value


def test_qmt_runtime_receipt_must_match_signed_candidate_evidence() -> None:
    profile = AGENT.PROFILES["qmt"]
    release = _release(profile)
    receipt = _native_receipt(profile, release)
    assert AGENT._validate_native_runtime(receipt, profile, release)
    wrong_version = {
        **receipt,
        "dependency_identity": {"qmt_version": "4.4.1"},
    }
    with pytest.raises(AGENT.AgentError, match="QMT dependency identity"):
        AGENT._validate_native_runtime(wrong_version, profile, release)
    wrong_migration = {
        **receipt,
        "artifact_provenance": {
            **receipt["artifact_provenance"],
            "migration_receipt_digest": "sha256:" + "9" * 64,
        },
    }
    assert AGENT._validate_native_runtime(wrong_migration, profile, release)
    assert wrong_migration["artifact_provenance"] != {
        key: _candidate_evidence(profile)[key]
        for key in (
            "candidate_receipt_sha256",
            "migration_receipt_digest",
            "contract_digest",
        )
    }


def test_agent_rejects_unsigned_expired_or_foreign_dispatch_claims() -> None:
    profile = AGENT.PROFILES["total"]
    config = _config(profile)
    release = _variant(profile, "a")
    now = 2_000_000_000
    job = _signed_job(profile, config, release, now=now)
    assert AGENT._validated_job(job, profile, config, now=now) == (
        RELEASE_ID,
        release,
        LEASE_ID,
        FENCE,
        NONCE,
        now + 3600,
        _variant(profile, "b"),
        _candidate_evidence(profile),
    )
    with pytest.raises(AGENT.AgentError):
        AGENT._validated_job({**job, "placement": "arbitrary-host"}, profile, config, now=now)
    with pytest.raises(AGENT.AgentError):
        AGENT._validated_job(
            {**job, "dispatch_claim_signature": "0" * 64}, profile, config, now=now
        )
    with pytest.raises(AGENT.AgentError):
        AGENT._validated_job(job, profile, config, now=now + 121)
    rebound = _signed_job(
        profile,
        config,
        release,
        now=now,
        workflow="release.yml",
        job_name="publish",
    )
    rebound["dispatch_claim"]["workflow"] = "ci.yml"
    with pytest.raises(AGENT.AgentError, match="signature"):
        AGENT._validated_job(rebound, profile, config, now=now)


def test_agent_rejects_a_consumed_dispatch_nonce(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _test_profile(tmp_path)
    config = _config(profile)
    candidate = _variant(profile, "a")
    previous = _variant(profile, "b")
    previous_rollback = _variant(profile, "c")
    lease_expires_at = int(time.time()) + 3600
    _patch_local_security(monkeypatch)
    AGENT._write_operation(
        profile,
        "dispatch_accepted",
        RELEASE_ID,
        LEASE_ID,
        FENCE,
        AGENT._operation_context(
            profile,
            candidate,
            previous,
            previous_rollback,
            NONCE,
            lease_expires_at,
            previous,
        ),
    )
    with pytest.raises(AGENT.AgentError, match="already consumed"):
        AGENT.validate_job(
            _signed_job(
                profile,
                config,
                candidate,
                lease_expires_at=lease_expires_at,
                rollback_anchor=previous,
            ),
            profile,
            config,
        )


def test_agent_requires_native_runtime_evidence_for_release_and_rollback(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = AGENT.PROFILES["cmnt"]
    release = _variant(profile, "a")
    rollback = _variant(profile, "b")
    document = _native_receipt(profile, release)
    monkeypatch.setattr(AGENT, "_ensure_dispatcher", lambda _: None)
    monkeypatch.setattr(AGENT, "_run", lambda _: json.dumps(document).encode())
    assert AGENT.native_receipt(profile, release) == document
    runtime = AGENT._completion_receipt(profile, release, rollback, document)
    AGENT._validate_completion_receipt(runtime, profile, release, rollback)
    rollback_native = _native_receipt(profile, rollback)
    rolled_back = AGENT._rollback_receipt(profile, RELEASE_ID, release, rollback, rollback_native)
    AGENT._validate_rollback_receipt(rolled_back, profile, RELEASE_ID, release, rollback)

    incomplete = {key: value for key, value in document.items() if key != "artifact_provenance"}
    with pytest.raises(AGENT.AgentError, match="runtime receipt"):
        AGENT._completion_receipt(profile, release, rollback, incomplete)
    incomplete_rollback = {
        key: value for key, value in rollback_native.items() if key != "artifact_provenance"
    }
    with pytest.raises(AGENT.AgentError, match="runtime receipt"):
        AGENT._rollback_receipt(profile, RELEASE_ID, release, rollback, incomplete_rollback)


def test_agent_journal_is_append_only_durable_and_tamper_evident(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _test_profile(tmp_path)
    _patch_local_security(monkeypatch)
    first = AGENT._write_journal(profile, "anchor_missing")
    second = AGENT._write_journal(profile, "heartbeat")
    path = AGENT._journal_path(profile)
    assert first["journal_seq"] == 1
    assert second["journal_seq"] == 2
    assert second["previous_event_sha256"] == first["event_sha256"]
    assert os.stat(path).st_mode & 0o777 == 0o600

    lines = path.read_bytes().splitlines()
    tampered = json.loads(lines[0])
    tampered["phase"] = "forged"
    path.write_bytes(AGENT._canonical_bytes(tampered) + b"\n" + lines[1] + b"\n")
    with pytest.raises(AGENT.AgentError, match="journal hash"):
        AGENT._journal_events(profile)


def test_agent_bootstraps_first_heartbeat_from_measured_runtime_and_retries_safely(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _test_profile(tmp_path)
    config = _config(profile)
    measured = _variant(profile, "b")
    _patch_local_security(monkeypatch)
    monkeypatch.setattr(
        AGENT, "native_receipt", lambda *_, **__: _native_receipt(profile, measured)
    )
    attempts = 0

    def fake_request(
        _config: object,
        _method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        **_: Any,
    ) -> tuple[int, bytes]:
        nonlocal attempts
        assert path.endswith("/heartbeat")
        assert payload is not None
        assert payload["bootstrap"] is True
        assert payload["active_release"] == measured
        assert payload["rollback"] == {"verified": True, **measured}
        attempts += 1
        if attempts == 1:
            raise AGENT.ControllerTransportError("lost bootstrap acknowledgement")
        return 200, b""

    monkeypatch.setattr(AGENT, "request", fake_request)
    with pytest.raises(AGENT.ControllerTransportError):
        AGENT.run_once(config, profile)
    assert not profile.state_path.exists()
    result = AGENT.run_once(config, profile)
    assert result["status"] == "bootstrapped"
    assert AGENT.read_state(profile.state_path, profile, allow_bootstrap=True) == (
        measured,
        measured,
    )
    assert [event["phase"] for event in AGENT._journal_events(profile)][-3:] == [
        "bootstrap_anchor_measured",
        "bootstrap_anchor_measured",
        "bootstrap_anchor_persisted",
    ]


def test_agent_run_once_completes_signed_managed_release_without_name_or_type_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _test_profile(tmp_path)
    config = _config(profile)
    candidate = _variant(profile, "a")
    active = _variant(profile, "b")
    rollback = _variant(profile, "c")
    job = _signed_job(profile, config, candidate, rollback_anchor=active)
    _patch_local_security(monkeypatch)
    _provision_agent_state(profile, active, rollback)
    native_invocations: list[tuple[str, dict[str, str]]] = []
    running = {"release": active}

    def measured_receipt(
        _profile: object,
        release: dict[str, str] | None = None,
        *,
        current: bool = False,
    ) -> dict[str, Any]:
        assert current is True
        assert release is None
        return _native_receipt(profile, running["release"])

    def invoke(_profile: object, action: str, release: dict[str, str]) -> None:
        native_invocations.append((action, release))
        running["release"] = release

    monkeypatch.setattr(AGENT, "native_receipt", measured_receipt)
    monkeypatch.setattr(AGENT, "invoke_native", invoke)

    def fake_request(
        _config: object,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        if path.endswith("/heartbeat"):
            return 200, b""
        if path.endswith("/jobs/next"):
            return 200, json.dumps(job).encode()
        if method == "GET" and path.endswith(f"/jobs/{RELEASE_ID}"):
            return 200, json.dumps(_controller_status(profile, candidate)).encode()
        if method == "POST" and path.endswith(f"/jobs/{RELEASE_ID}/complete"):
            assert headers == AGENT._controller_headers(LEASE_ID, FENCE)
            assert payload is not None
            return 200, AGENT._canonical_bytes(payload)
        raise AssertionError(f"unexpected controller request: {method} {path}")

    monkeypatch.setattr(AGENT, "request", fake_request)
    result = AGENT.run_once(config, profile)
    assert result["status"] == "verified"
    assert native_invocations == [("release", candidate)]
    assert AGENT.read_state(profile.state_path, profile) == (candidate, active)
    assert [event["phase"] for event in AGENT._journal_events(profile)][-4:] == [
        "release_started",
        "release_ready",
        "verified",
        "completed",
    ]


def test_agent_release_failure_passes_full_safe_rollback_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _test_profile(tmp_path)
    config = _config(profile)
    candidate = _variant(profile, "a")
    active = _variant(profile, "b")
    rollback = _variant(profile, "c")
    job = _signed_job(profile, config, candidate, rollback_anchor=active)
    _patch_local_security(monkeypatch)
    _provision_agent_state(profile, active, rollback)
    monkeypatch.setattr(
        AGENT,
        "native_receipt",
        lambda _profile, release=None, *, current=False: _native_receipt(profile, active),
    )

    def fail_release(*_: object, **__: object) -> None:
        raise AGENT.AgentError("native release failed")

    monkeypatch.setattr(AGENT, "invoke_native", fail_release)
    captured: dict[str, Any] = {}

    def fake_rollback(
        _config: object,
        _profile: object,
        release_id: str,
        failed: dict[str, str],
        restored: dict[str, str],
        **kwargs: Any,
    ) -> dict[str, Any]:
        captured.update(release_id=release_id, failed=failed, restored=restored, **kwargs)
        return {}

    monkeypatch.setattr(AGENT, "rollback_remote", fake_rollback)

    def fake_request(
        _config: object,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        del method, payload, headers
        if path.endswith("/heartbeat"):
            return 200, b""
        if path.endswith("/jobs/next"):
            return 200, json.dumps(job).encode()
        raise AssertionError(f"unexpected controller request: {path}")

    monkeypatch.setattr(AGENT, "request", fake_request)
    with pytest.raises(AGENT.AgentError, match="native release failed"):
        AGENT.run_once(config, profile)
    assert captured == {
        "release_id": RELEASE_ID,
        "failed": candidate,
        "restored": active,
        "lease_id": LEASE_ID,
        "fence": FENCE,
        "dispatch_nonce": NONCE,
        "previous_rollback": rollback,
        "lease_expires_at": job["lease_expires_at"],
        "rollback_anchor": active,
    }


def test_agent_unknown_completion_is_reconciled_without_blind_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _test_profile(tmp_path)
    config = _config(profile)
    candidate = _variant(profile, "a")
    active = _variant(profile, "b")
    rollback = _variant(profile, "c")
    job = _signed_job(profile, config, candidate, rollback_anchor=active)
    _patch_local_security(monkeypatch)
    _provision_agent_state(profile, active, rollback)
    native_invocations: list[tuple[str, dict[str, str]]] = []
    running = {"release": active}

    def measured_receipt(
        _profile: object,
        release: dict[str, str] | None = None,
        *,
        current: bool = False,
    ) -> dict[str, Any]:
        assert current is True
        assert release is None
        return _native_receipt(profile, running["release"])

    def invoke(_profile: object, action: str, release: dict[str, str]) -> None:
        native_invocations.append((action, release))
        running["release"] = release

    monkeypatch.setattr(AGENT, "native_receipt", measured_receipt)
    monkeypatch.setattr(AGENT, "invoke_native", invoke)
    monkeypatch.setattr(
        AGENT,
        "rollback_remote",
        lambda *_, **__: pytest.fail("unknown completion triggered rollback"),
    )
    status_reads = 0

    def fake_request(
        _config: object,
        method: str,
        path: str,
        payload: dict[str, Any] | None = None,
        *,
        headers: dict[str, str] | None = None,
    ) -> tuple[int, bytes]:
        nonlocal status_reads
        del payload, headers
        if path.endswith("/heartbeat"):
            return 200, b""
        if path.endswith("/jobs/next"):
            return 200, json.dumps(job).encode()
        if method == "GET" and path.endswith(f"/jobs/{RELEASE_ID}"):
            status_reads += 1
            return 200, json.dumps(_controller_status(profile, candidate)).encode()
        if method == "POST" and path.endswith(f"/jobs/{RELEASE_ID}/complete"):
            raise AGENT.ControllerTransportError("unknown write outcome")
        raise AssertionError(f"unexpected controller request: {method} {path}")

    monkeypatch.setattr(AGENT, "request", fake_request)
    with pytest.raises(AGENT.ControllerOutcomeUnresolved):
        AGENT.run_once(config, profile)
    assert native_invocations == [("release", candidate)]
    assert status_reads == 3
    assert AGENT.read_state(profile.state_path, profile) == (active, rollback)
    assert AGENT._journal_events(profile)[-1]["phase"] == "completion_unresolved"


def test_agent_reconciles_pending_operation_before_heartbeat_or_native_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _test_profile(tmp_path)
    config = _config(profile)
    candidate = _variant(profile, "a")
    active = _variant(profile, "b")
    rollback = _variant(profile, "c")
    _patch_local_security(monkeypatch)
    _provision_agent_state(profile, active, rollback)
    lease_expires_at = int(time.time()) + 3600
    AGENT._write_operation(
        profile,
        "release_started",
        RELEASE_ID,
        LEASE_ID,
        FENCE,
        AGENT._operation_context(
            profile,
            candidate,
            active,
            rollback,
            NONCE,
            lease_expires_at,
            active,
        ),
    )
    monkeypatch.setattr(
        AGENT,
        "native_receipt",
        lambda _profile, release=None, *, current=False: (
            _native_receipt(profile, candidate)
            if current
            else pytest.fail("unexpected target-specific native receipt")
        ),
    )

    def unavailable(*_: object, **__: object) -> dict[str, Any]:
        raise AGENT.ControllerTransportError("controller unavailable")

    monkeypatch.setattr(AGENT, "_controller_status", unavailable)
    monkeypatch.setattr(
        AGENT, "invoke_native", lambda *_, **__: pytest.fail("native mutation was repeated")
    )
    monkeypatch.setattr(
        AGENT, "request", lambda *_, **__: pytest.fail("heartbeat or poll was attempted")
    )
    with pytest.raises(AGENT.ControllerOutcomeUnresolved):
        AGENT.run_once(config, profile)
    assert AGENT._journal_events(profile)[-1]["phase"] == "recovery_unresolved"


def test_agent_rollback_reconciles_controller_before_native_action(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _test_profile(tmp_path)
    config = _config(profile)
    candidate = _variant(profile, "a")
    restored = _variant(profile, "b")
    previous_rollback = _variant(profile, "c")

    def unavailable(*_: object, **__: object) -> dict[str, Any]:
        raise AGENT.ControllerTransportError("controller unavailable")

    monkeypatch.setattr(AGENT, "_controller_status", unavailable)
    monkeypatch.setattr(
        AGENT, "native_receipt", lambda *_, **__: pytest.fail("native state was inspected")
    )
    monkeypatch.setattr(
        AGENT, "invoke_native", lambda *_, **__: pytest.fail("native rollback was attempted")
    )
    with pytest.raises(AGENT.ControllerOutcomeUnresolved, match="unknown before rollback"):
        AGENT.rollback_remote(
            config,
            profile,
            RELEASE_ID,
            candidate,
            restored,
            lease_id=LEASE_ID,
            fence=FENCE,
            dispatch_nonce=NONCE,
            previous_rollback=previous_rollback,
            lease_expires_at=int(time.time()) + 3600,
            rollback_anchor=restored,
        )


def test_agent_cannot_be_reconfigured_with_host_paths() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "QDEV_RELEASE_STATE_PATH" not in source
    assert "QDEV_RELEASE_LOCK_PATH" not in source
    assert "QDEV_RELEASE_NATIVE" not in source
    assert "total.kz" not in source
    assert "ssh" not in source.lower()
