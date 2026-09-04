import json
from pathlib import Path

import pytest

from qdev_runner.release_lane import (
    REQUEST_SCHEMA,
    ReleaseAdmissionRequest,
    ReleaseLaneError,
    ReleaseLanePolicy,
    ReleaseStore,
    validate_candidate,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ReleaseLanePolicy(ROOT / "config/release-lanes.yml")


def _release(lane: object, marker: str) -> dict[str, str]:
    # The lane object is deliberately typed at runtime so the fixture stays
    # independent of a product-specific adapter implementation.
    artifact_prefix = lane.artifact_ref_prefix  # type: ignore[attr-defined]
    digest = "sha256:" + marker * 64
    return {
        "source_sha": marker * 40,
        "artifact_digest": digest,
        "artifact_ref": f"{artifact_prefix}@{digest}",
    }


def _request(lane: object, marker: str) -> ReleaseAdmissionRequest:
    release = _release(lane, marker)
    receipt = {
        "schema": "qdev-release-candidate-receipt-v1",
        "status": "passed",
        **release,
        "repository": lane.canonical_repository,  # type: ignore[attr-defined]
        "workflow": "release.yml",
        "job": "native-release",
        "attempt": 1,
        "runner_profile": "qdev-ci-docker",
    }
    request = ReleaseAdmissionRequest(
        schema=REQUEST_SCHEMA,
        release_lane=lane.name,  # type: ignore[attr-defined]
        project_id=lane.project_id,  # type: ignore[attr-defined]
        placement=lane.placement,  # type: ignore[attr-defined]
        **release,
        candidate_receipt=receipt,
    )
    validate_candidate(request, lane)  # type: ignore[arg-type]
    return request


def _runtime_receipt(lane: object, release: dict[str, str], rollback: dict[str, str]) -> dict:
    return {
        "schema": "qdev-controller-release-runtime-receipt-v1",
        "status": "verified",
        "project": lane.project_id,  # type: ignore[attr-defined]
        "release_lane": lane.name,  # type: ignore[attr-defined]
        "placement": lane.placement,  # type: ignore[attr-defined]
        **release,
        "health": "ok",
        "readiness": {name: "ok" for name in lane.required_readiness},  # type: ignore[attr-defined]
        "rollback": {"verified": True, **rollback},
        "runtime_identity": {**release, "measured": True},
        "dependency_identity": {"qazstack": "1.31.1", "qak": "0.4.8"},
        "artifact_provenance": {
            "qak_wheel_sha256": "d" * 64,
            "avds_artifact_sha256": "e" * 64,
            "avds_source_sha": "f" * 40,
        },
    }


def _native_receipt(lane: object, release: dict[str, str], *, evidence: bool = True) -> dict:
    document = {
        "schema": "qdev-admin-platform-native-receipt-v1",
        "project_id": lane.project_id,  # type: ignore[attr-defined]
        "native_host_adapter": lane.native_host_adapter,  # type: ignore[attr-defined]
        **release,
        "readiness": {name: "ok" for name in lane.required_readiness},  # type: ignore[attr-defined]
    }
    if evidence:
        document.update(
            {
                "runtime_identity": {**release, "measured": True},
                "dependency_identity": {"qazstack": "1.31.1", "qak": "0.4.8"},
                "artifact_provenance": {
                    "qak_wheel_sha256": "d" * 64,
                    "avds_artifact_sha256": "e" * 64,
                    "avds_source_sha": "f" * 40,
                },
            }
        )
    return document


def test_managed_release_must_be_dispatched_before_completion(tmp_path: Path) -> None:
    lane = POLICY.lane("qdev-release-cmnt")
    store = ReleaseStore(tmp_path)
    request = _request(lane, "a")
    job, duplicate = store.admit(request, lane)
    assert duplicate is False
    receipt = _runtime_receipt(lane, _release(lane, "a"), _release(lane, "b"))

    with pytest.raises(ReleaseLaneError, match="was not dispatched"):
        store.complete(
            lane,
            job["release_id"],
            receipt,
            lease_id=job["lease_id"],
            fence=job["fence"],
        )

    dispatched = store.next_job(lane)
    assert dispatched is not None and dispatched["status"] == "dispatched"
    verified = store.complete(
        lane,
        job["release_id"],
        receipt,
        lease_id=job["lease_id"],
        fence=job["fence"],
    )
    assert verified["status"] == "verified"

    history_path = tmp_path / "operations" / f"{lane.name}.jsonl"
    history = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()]
    assert [event["phase"] for event in history] == ["accepted", "dispatched", "verified"]
    assert all(event["release_id"] == job["release_id"] for event in history)
    assert all(event["lease_id"] == job["lease_id"] for event in history)
    assert all(event["fence"] == job["fence"] for event in history)


def test_runtime_evidence_rejects_empty_dependency_identity() -> None:
    lane = POLICY.lane("qdev-release-cmnt")
    release = _release(lane, "a")
    receipt = _runtime_receipt(lane, release, _release(lane, "b"))
    receipt["dependency_identity"] = {}
    from qdev_runner.release_lane import validate_runtime_receipt

    with pytest.raises(ReleaseLaneError, match="dependency identity is invalid"):
        validate_runtime_receipt(
            receipt,
            lane=lane,
            source_sha=release["source_sha"],
            artifact_digest=release["artifact_digest"],
            artifact_ref=release["artifact_ref"],
        )


def test_managed_native_receipt_requires_healthy_readiness() -> None:
    lane = POLICY.lane("qdev-release-cmnt")
    release = _release(lane, "a")
    receipt = _native_receipt(lane, release)
    receipt["readiness"][lane.required_readiness[0]] = "degraded"

    from qdev_runner.release_lane import validate_native_receipt

    with pytest.raises(ReleaseLaneError, match="readiness is invalid"):
        validate_native_receipt(
            receipt,
            lane=lane,
            source_sha=release["source_sha"],
            artifact_digest=release["artifact_digest"],
            artifact_ref=release["artifact_ref"],
        )


def test_managed_rollback_requires_measured_native_evidence(tmp_path: Path) -> None:
    lane = POLICY.lane("qdev-release-cmnt")
    store = ReleaseStore(tmp_path)
    first = _request(lane, "a")
    first_job, _ = store.admit(first, lane)
    store.next_job(lane)
    first_receipt = _runtime_receipt(lane, _release(lane, "a"), _release(lane, "b"))
    store.complete(
        lane,
        first_job["release_id"],
        first_receipt,
        lease_id=first_job["lease_id"],
        fence=first_job["fence"],
    )

    second = _request(lane, "c")
    second_job, _ = store.admit(second, lane)
    store.next_job(lane)
    failed = _release(lane, "c")
    restored = _release(lane, "a")
    rollback = {
        "schema": "qdev-controller-release-rollback-receipt-v1",
        "status": "rolled_back",
        "project_id": lane.project_id,
        "release_lane": lane.name,
        "placement": lane.placement,
        "release_id": second_job["release_id"],
        "failed_release": failed,
        "restored_release": restored,
        "native_receipt": _native_receipt(lane, restored, evidence=False),
    }
    with pytest.raises(ReleaseLaneError, match="native receipt lacks runtime evidence"):
        store.rollback(
            lane,
            second_job["release_id"],
            rollback,
            lease_id=second_job["lease_id"],
            fence=second_job["fence"],
        )

    rollback["native_receipt"] = _native_receipt(lane, restored)
    rolled_back = store.rollback(
        lane,
        second_job["release_id"],
        rollback,
        lease_id=second_job["lease_id"],
        fence=second_job["fence"],
    )
    assert rolled_back["status"] == "rolled_back"
    history_path = tmp_path / "operations" / f"{lane.name}.jsonl"
    history = [json.loads(line) for line in history_path.read_text(encoding="utf-8").splitlines()]
    assert history[-1]["phase"] == "rolled_back"
