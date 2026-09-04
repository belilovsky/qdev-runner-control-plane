from pathlib import Path

import pytest
import yaml

from qdev_runner.release_lane import (
    HOST_HEARTBEAT_SCHEMA,
    REQUEST_SCHEMA,
    RUNTIME_RECEIPT_SCHEMA,
    HostHeartbeatRequest,
    ReleaseAdmissionRequest,
    ReleaseLaneError,
    ReleaseLanePolicy,
    ReleaseStore,
    validate_candidate,
    validate_host_heartbeat,
    validate_runtime_receipt,
)

ROOT = Path(__file__).parents[1]
LANES_PATH = ROOT / "config" / "release-lanes.yml"
QGEO_SHA = "8bfd4e5bb7da5c7c99fd12865fb56d88fc5c9d7d"
QGEO_DIGEST = "sha256:" + "a" * 64
QGEO_REF = f"registry.ci.qdev.run/belilovsky/qazgeo@{QGEO_DIGEST}"
ROLLBACK_SHA = "d65cd62a4c96786d9d5c35ebea8af872dcc3cb69"
ROLLBACK_DIGEST = "sha256:96d4399d5f5345f956abbffbd185552da4406a7a26017164f2ca6313688ef5cb"
ROLLBACK_REF = f"registry.ci.qdev.run/belilovsky/qazgeo@{ROLLBACK_DIGEST}"


def _qgeo_lane():
    return ReleaseLanePolicy(LANES_PATH).lane("qdev-release-qazgeo")


def _candidate_request(*, evidence: dict | None = None) -> ReleaseAdmissionRequest:
    if evidence is None:
        evidence = {
            "ci": {
                "status": "passed",
                "source_sha": QGEO_SHA,
                "run_ids": ["33838251934", "33838251867"],
            },
            "artifact": {
                "status": "passed",
                "source_sha": QGEO_SHA,
                "artifact_digest": QGEO_DIGEST,
                "artifact_ref": QGEO_REF,
            },
            "static": {"status": "passed", "source_sha": QGEO_SHA, "digest": "sha256:" + "b" * 64},
            "provenance": {
                "status": "passed",
                "source_sha": QGEO_SHA,
                "artifact_digest": QGEO_DIGEST,
            },
            "preflight": {"status": "passed", "source_sha": QGEO_SHA},
        }
    return ReleaseAdmissionRequest.model_validate(
        {
            "schema": REQUEST_SCHEMA,
            "release_lane": "qdev-release-qazgeo",
            "project_id": "qazgeo",
            "placement": "qazgeo-primary-187",
            "source_sha": QGEO_SHA,
            "artifact_digest": QGEO_DIGEST,
            "artifact_ref": QGEO_REF,
            "candidate_receipt": {
                "schema": "qdev-release-candidate-receipt-v1",
                "status": "passed",
                "source_sha": QGEO_SHA,
                "artifact_digest": QGEO_DIGEST,
                "artifact_ref": QGEO_REF,
                "evidence": evidence,
            },
        }
    )


def test_qgeo_candidate_requires_complete_bound_evidence() -> None:
    lane = _qgeo_lane()
    validate_candidate(_candidate_request(), lane)

    request = _candidate_request()
    request.candidate_receipt["evidence"].pop("preflight")
    with pytest.raises(ReleaseLaneError, match="evidence is incomplete"):
        validate_candidate(request, lane)

    request = _candidate_request()
    request.candidate_receipt["evidence"]["artifact"]["artifact_digest"] = "sha256:" + "c" * 64
    with pytest.raises(ReleaseLaneError, match="artifact evidence"):
        validate_candidate(request, lane)


@pytest.mark.parametrize(
    "artifact_repository",
    [
        "belilovsky/../qazgeo",
        "belilovsky//qazgeo",
        "Belilovsky/qazgeo",
        "registry.ci.qdev.run/belilovsky/qazgeo",
        "../qazgeo",
    ],
)
def test_release_policy_rejects_unsafe_nested_oci_repositories(
    tmp_path: Path, artifact_repository: str
) -> None:
    document = yaml.safe_load(LANES_PATH.read_text(encoding="utf-8"))
    document["lanes"]["qdev-release-qazgeo"]["artifact_repository"] = artifact_repository
    path = tmp_path / "release-lanes.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ReleaseLaneError, match="release lane values"):
        ReleaseLanePolicy(path)


def test_qgeo_bootstrap_accepts_old_runtime_as_active_and_rollback() -> None:
    lane = _qgeo_lane()
    old = {
        "source_sha": ROLLBACK_SHA,
        "artifact_digest": ROLLBACK_DIGEST,
        "artifact_ref": ROLLBACK_REF,
    }
    request = HostHeartbeatRequest.model_validate(
        {
            "schema": HOST_HEARTBEAT_SCHEMA,
            "release_lane": lane.name,
            "project_id": lane.project_id,
            "placement": lane.placement,
            "state": "ready",
            "release_lock": "available",
            "capacity_free_gib": 62.3,
            "active_release": old,
            "rollback": {"verified": True, **old},
        }
    )
    validate_host_heartbeat(request, lane)


def test_qgeo_runtime_receipt_requires_all_dependencies() -> None:
    lane = _qgeo_lane()
    receipt = {
        "schema": RUNTIME_RECEIPT_SCHEMA,
        "status": "verified",
        "project": lane.project_id,
        "release_lane": lane.name,
        "placement": lane.placement,
        "source_sha": QGEO_SHA,
        "artifact_digest": QGEO_DIGEST,
        "artifact_ref": QGEO_REF,
        "health": "ok",
        "readiness": {
            "local": "ok",
            "public": "ok",
            "db": "ok",
            "postgis": "ok",
            "martin": "ok",
            "photon": "ok",
            "redis": "ok",
        },
        "rollback": {
            "verified": True,
            "source_sha": ROLLBACK_SHA,
            "artifact_digest": ROLLBACK_DIGEST,
            "artifact_ref": ROLLBACK_REF,
        },
    }
    validate_runtime_receipt(
        receipt,
        lane=lane,
        source_sha=QGEO_SHA,
        artifact_digest=QGEO_DIGEST,
        artifact_ref=QGEO_REF,
    )
    receipt["readiness"].pop("redis")
    with pytest.raises(ReleaseLaneError, match="readiness or rollback"):
        validate_runtime_receipt(
            receipt,
            lane=lane,
            source_sha=QGEO_SHA,
            artifact_digest=QGEO_DIGEST,
            artifact_ref=QGEO_REF,
        )


def test_release_admission_is_idempotent_after_verified_result(tmp_path: Path) -> None:
    lane = _qgeo_lane()
    store = ReleaseStore(tmp_path / "release-state")
    request = _candidate_request()
    first, idempotent = store.admit(request, lane)
    assert idempotent is False
    dispatched = store.next_job(lane)
    assert dispatched is not None
    runtime_receipt = {
        "schema": RUNTIME_RECEIPT_SCHEMA,
        "status": "verified",
        "project": lane.project_id,
        "release_lane": lane.name,
        "placement": lane.placement,
        "source_sha": QGEO_SHA,
        "artifact_digest": QGEO_DIGEST,
        "artifact_ref": QGEO_REF,
        "health": "ok",
        "readiness": {
            "local": "ok",
            "public": "ok",
            "db": "ok",
            "postgis": "ok",
            "martin": "ok",
            "photon": "ok",
            "redis": "ok",
        },
        "rollback": {
            "verified": True,
            "source_sha": ROLLBACK_SHA,
            "artifact_digest": ROLLBACK_DIGEST,
            "artifact_ref": ROLLBACK_REF,
        },
    }
    completed = store.complete(lane, str(first["release_id"]), runtime_receipt)
    repeated, idempotent = store.admit(request, lane)
    assert idempotent is True
    assert repeated["release_id"] == completed["release_id"]


def test_release_admission_rejects_changed_evidence_for_same_tuple(tmp_path: Path) -> None:
    lane = _qgeo_lane()
    store = ReleaseStore(tmp_path / "release-state")
    request = _candidate_request()
    store.admit(request, lane)
    changed = _candidate_request()
    changed.candidate_receipt["evidence"]["static"]["digest"] = "sha256:" + "c" * 64
    with pytest.raises(ReleaseLaneError, match="different candidate evidence"):
        store.admit(changed, lane)
