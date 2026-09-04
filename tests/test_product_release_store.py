"""Real controller store writes and fault recovery, without product/network calls."""

import json
from pathlib import Path

import pytest

from qdev_runner.release_lane import (
    HostHeartbeatRequest,
    ReleaseAdmissionRequest,
    ReleaseLaneError,
    ReleaseLanePolicy,
    ReleaseStore,
)


@pytest.fixture
def store(tmp_path):
    lane = ReleaseLanePolicy(Path(__file__).parents[1] / "config/release-lanes.yml").lane(
        "qdev-release-qmt"
    )
    return ReleaseStore(tmp_path), lane


def release(lane, char):
    digest = "sha256:" + char * 64
    return {
        "source_sha": char * 40,
        "artifact_digest": digest,
        "artifact_ref": lane.artifact_ref_prefix + "@" + digest,
    }


def heartbeat(store, lane, active, previous):
    store.record_heartbeat(
        lane,
        HostHeartbeatRequest(
            schema="qdev-release-host-agent-heartbeat-v1",
            release_lane=lane.name,
            project_id=lane.project_id,
            placement=lane.placement,
            state="ready",
            release_lock="available",
            capacity_free_gib=100,
            active_release=active,
            rollback={"verified": True, **previous},
        ),
        identity=lane.host_agent_mtls_identity,
    )


def admit(store, lane, value):
    return store.admit(
        ReleaseAdmissionRequest(
            schema="qdev-controller-release-request-v1",
            release_lane=lane.name,
            project_id=lane.project_id,
            placement=lane.placement,
            candidate_receipt={},
            **value,
        ),
        lane,
    )[0]


def receipt(lane, value, previous):
    image_id, config_digest = "sha256:" + "f" * 64, "e" * 64
    return {
        "schema": "qdev-controller-release-runtime-receipt-v1",
        "status": "verified",
        "project": lane.project_id,
        "release_lane": lane.name,
        "placement": lane.placement,
        **value,
        "health": "ok",
        "readiness": {key: "ok" for key in lane.required_readiness},
        "rollback": {"verified": True, **previous},
        "runtime_identity": {
            **value,
            "measured": True,
            "image_id": image_id,
            "services": {"kaztilshi": image_id},
        },
        "dependency_identity": {"compose_config_sha256": config_digest},
        "artifact_provenance": {
            "schema": "qdev-product-oci-provenance-v1",
            **value,
            "image_id": image_id,
            "config_sha256": config_digest,
        },
    }


def complete(store, lane, job, proof):
    return store.complete(
        lane, job["release_id"], proof, lease_id=job["lease_id"], fence=job["fence"]
    )


def test_next_release_requires_reconciled_heartbeat_and_keeps_ack_history(store):
    s, lane = store
    prior, old, a, b = (release(lane, c) for c in "dcab")
    heartbeat(s, lane, old, prior)
    job_a = admit(s, lane, a)
    proof = receipt(lane, a, old)
    complete(s, lane, job_a, proof)
    with pytest.raises(ReleaseLaneError, match="not reconciled"):
        admit(s, lane, b)
    # Even a fresh but stale-valued heartbeat cannot carry the old anchor.
    heartbeat(s, lane, old, prior)
    with pytest.raises(ReleaseLaneError, match="not reconciled"):
        admit(s, lane, b)
    heartbeat(s, lane, a, old)
    job_b = admit(s, lane, b)
    assert job_b["previous_release"] == a
    before = s._operation_path(lane.name).read_bytes()
    assert complete(s, lane, job_a, proof)["status"] == "verified"
    assert s._operation_path(lane.name).read_bytes() == before
    assert s.active_job(lane)["release_id"] == job_b["release_id"]
    with pytest.raises(ReleaseLaneError, match="lease"):
        s.complete(lane, job_a["release_id"], proof, lease_id="wrong", fence=job_a["fence"])
    with pytest.raises(ReleaseLaneError, match="another receipt"):
        complete(s, lane, job_a, {**proof, "health": "failed"})
    assert complete(s, lane, job_b, receipt(lane, b, a))["status"] == "verified"


def test_lost_second_write_is_repaired_by_identical_ack(store, monkeypatch):
    s, lane = store
    prior, old, a = (release(lane, c) for c in "cba")
    heartbeat(s, lane, old, prior)
    job = admit(s, lane, a)
    proof = receipt(lane, a, old)
    original = s._write

    def write(path, value):
        if path == s._operation_path(lane.name) and value.get("phase") == "verified":
            raise OSError("simulated second write failure")
        original(path, value)

    monkeypatch.setattr(s, "_write", write)
    with pytest.raises(OSError):
        complete(s, lane, job, proof)
    assert json.loads(s._job_path(lane.name).read_text())["status"] == "verified"
    monkeypatch.setattr(s, "_write", original)
    complete(s, lane, job, proof)
    assert json.loads(s._operation_path(lane.name).read_text())["phase"] == "verified"


@pytest.mark.parametrize("fault", ["io", "json", "shape"])
def test_unreadable_job_never_allows_replacement(store, monkeypatch, fault):
    s, lane = store
    prior, old, a, b = (release(lane, c) for c in "dcab")
    heartbeat(s, lane, old, prior)
    job = admit(s, lane, a)
    path = s._job_path(lane.name)
    before = path.read_bytes()
    original = Path.read_text

    def read(candidate, *args, **kwargs):
        if candidate == path:
            if fault == "io":
                raise OSError("simulated I/O failure")
            return "invalid JSON" if fault == "json" else "[]"
        return original(candidate, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", read)
    with pytest.raises(ReleaseLaneError, match="state"):
        admit(s, lane, b)
    assert path.read_bytes() == before
    monkeypatch.setattr(Path, "read_text", original)
    assert s.active_job(lane)["release_id"] == job["release_id"]
