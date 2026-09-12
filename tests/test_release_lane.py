import copy
import hashlib
import hmac
import json
from pathlib import Path

import pytest
import yaml

from qdev_runner.release_lane import (
    CONTROLLER_CLAIM_SCHEMA,
    HOST_HEARTBEAT_SCHEMA,
    REQUEST_SCHEMA,
    RUNTIME_RECEIPT_SCHEMA,
    HostHeartbeatRequest,
    ReleaseAdmissionRequest,
    ReleaseLaneError,
    ReleaseLanePolicy,
    ReleaseStore,
    candidate_artifact_delivery,
    controller_claim_payload,
    host_dispatch_claim_payload,
    qazagents_artifact_provenance_from_evidence,
    qazagents_candidate_evidence_digest,
    qgeo_candidate_evidence_digest,
    validate_candidate,
    validate_controller_claim,
    validate_host_heartbeat,
    validate_native_runtime_receipt,
    validate_runtime_receipt,
)

ROOT = Path(__file__).parents[1]
LANES_PATH = ROOT / "config" / "release-lanes.yml"
QGEO_SHA = "9" * 40
QGEO_DIGEST = "sha256:" + "a" * 64
QGEO_REF = f"registry.ci.qdev.run/belilovsky/qazgeo@{QGEO_DIGEST}"
ROLLBACK_SHA = "d65cd62a4c96786d9d5c35ebea8af872dcc3cb69"
ROLLBACK_DIGEST = "sha256:96d4399d5f5345f956abbffbd185552da4406a7a26017164f2ca6313688ef5cb"
ROLLBACK_REF = f"registry.ci.qdev.run/belilovsky/qazgeo@{ROLLBACK_DIGEST}"
SIGNING_KEY = "controller-claim-test-key-32-bytes!!"
TEST_NOW = 2_000_000_000
QAZAGENTS_SHA = "1" * 40
QAZAGENTS_DIGEST = "sha256:" + "2" * 64
QAZAGENTS_REF = f"registry.ci.qdev.run/qazagents-static@{QAZAGENTS_DIGEST}"
QAZAGENTS_ARCHIVE_SHA256 = "3" * 64
QAZAGENTS_PAYLOAD_SHA256 = "4" * 64
QAZAGENTS_ROLLBACK_SHA = "5" * 40
QAZAGENTS_ROLLBACK_DIGEST = "sha256:" + "6" * 64
QAZAGENTS_ROLLBACK_REF = f"registry.ci.qdev.run/qazagents-static@{QAZAGENTS_ROLLBACK_DIGEST}"


def _qgeo_lane():
    return ReleaseLanePolicy(LANES_PATH).lane("qdev-release-qazgeo")


def _qazagents_lane():
    return ReleaseLanePolicy(LANES_PATH).lane("qdev-release-qazagents-static")


def _qazagents_evidence() -> dict:
    return {
        "ci": {
            "status": "passed",
            "source_sha": QAZAGENTS_SHA,
            "run_ids": ["33838251934", "33838251867"],
            "job_set_digest": "7" * 64,
            "release_evidence_sha256": "8" * 64,
        },
        "artifact": {
            "status": "passed",
            "source_sha": QAZAGENTS_SHA,
            "artifact_digest": QAZAGENTS_DIGEST,
            "artifact_ref": QAZAGENTS_REF,
            "archive_sha256": QAZAGENTS_ARCHIVE_SHA256,
            "payload_sha256": QAZAGENTS_PAYLOAD_SHA256,
        },
        "static": {
            "status": "passed",
            "source_sha": QAZAGENTS_SHA,
            "digest": "sha256:" + "9" * 64,
            "manifest": "release-manifest.json",
            "skills_manifest_sha256": "sha256:" + "a" * 64,
            "release_manifest_sha256": "sha256:" + "b" * 64,
        },
        "sbom": {
            "status": "passed",
            "source_sha": QAZAGENTS_SHA,
            "digest": "sha256:" + "c" * 64,
            "format": "SPDX-2.3",
            "artifact_digest": QAZAGENTS_DIGEST,
        },
        "provenance": {
            "status": "passed",
            "source_sha": QAZAGENTS_SHA,
            "artifact_digest": QAZAGENTS_DIGEST,
            "archive_sha256": QAZAGENTS_ARCHIVE_SHA256,
            "payload_sha256": QAZAGENTS_PAYLOAD_SHA256,
            "skills_manifest_sha256": "sha256:" + "a" * 64,
            "release_manifest_sha256": "sha256:" + "b" * 64,
        },
        "security": {
            "status": "passed",
            "source_sha": QAZAGENTS_SHA,
            "source_scan_digest": "sha256:" + "d" * 64,
            "archive_scan_digest": "sha256:" + "e" * 64,
            "artifact_digest": QAZAGENTS_DIGEST,
        },
        "preflight": {
            "status": "passed",
            "source_sha": QAZAGENTS_SHA,
            "release_lane": "qdev-release-qazagents-static",
            "placement": "qazagents-static-runtime",
            "heartbeat_digest": "sha256:" + "f" * 64,
            "heartbeat_received_at": 1.0,
        },
    }


def _qazagents_candidate_request(*, evidence: dict | None = None) -> ReleaseAdmissionRequest:
    return ReleaseAdmissionRequest.model_validate(
        {
            "schema": REQUEST_SCHEMA,
            "release_lane": "qdev-release-qazagents-static",
            "project_id": "qazagents",
            "placement": "qazagents-static-runtime",
            "source_sha": QAZAGENTS_SHA,
            "artifact_digest": QAZAGENTS_DIGEST,
            "artifact_ref": QAZAGENTS_REF,
            "candidate_receipt": {
                "schema": "qdev-release-candidate-receipt-v1",
                "status": "passed",
                "source_sha": QAZAGENTS_SHA,
                "artifact_digest": QAZAGENTS_DIGEST,
                "artifact_ref": QAZAGENTS_REF,
                "artifact_type": "http-archive",
                "artifact_uri": "https://ci.qdev.run/artifacts/qazagents-static/release.tar.gz",
                "archive_sha256": QAZAGENTS_ARCHIVE_SHA256,
                "payload_sha256": QAZAGENTS_PAYLOAD_SHA256,
                "repository": "belilovsky/qazagents",
                "workflow": "QazAgents static release",
                "job": "source-bound archive",
                "run_id": 33838251934,
                "job_id": 101039384205,
                "attempt": 1,
                "runner_profile": "qdev-ci",
                "evidence": _qazagents_evidence() if evidence is None else evidence,
            },
        }
    )


def _qazagents_runtime_receipt(lane) -> dict:
    evidence = _qazagents_evidence()
    return {
        "schema": RUNTIME_RECEIPT_SCHEMA,
        "status": "verified",
        "project": lane.project_id,
        "release_lane": lane.name,
        "placement": lane.placement,
        "source_sha": QAZAGENTS_SHA,
        "artifact_digest": QAZAGENTS_DIGEST,
        "artifact_ref": QAZAGENTS_REF,
        "health": "ok",
        "readiness": {"native": "ok", "public": "ok", "identity": "ok"},
        "runtime_identity": {
            "source_sha": QAZAGENTS_SHA,
            "artifact_digest": QAZAGENTS_DIGEST,
            "artifact_ref": QAZAGENTS_REF,
            "measured": True,
        },
        "dependency_identity": {"static_host_adapter": lane.native_host_adapter},
        "artifact_provenance": qazagents_artifact_provenance_from_evidence(evidence),
        "static_bundle": {
            "digest": "sha256:" + "9" * 64,
            "manifest": "release-manifest.json",
            "skills_manifest_sha256": "sha256:" + "a" * 64,
            "release_manifest_sha256": "sha256:" + "b" * 64,
        },
        "rollback": {
            "verified": True,
            "source_sha": QAZAGENTS_ROLLBACK_SHA,
            "artifact_digest": QAZAGENTS_ROLLBACK_DIGEST,
            "artifact_ref": QAZAGENTS_ROLLBACK_REF,
        },
    }


def _qgeo_dependency_identity() -> dict[str, dict[str, object]]:
    result: dict[str, dict[str, object]] = {}
    for index, service in enumerate(("db", "martin", "photon", "redis"), start=1):
        reference = f"registry.example.test/qgeo/{service}@sha256:{index:064x}"
        result[service] = {
            "artifact_ref": reference,
            "source_revision": None,
            "container_id": f"container-{service}",
            "config_image": reference,
            "image_id": f"sha256:{index + 10:064x}",
            "image_repo_digests": [reference],
        }
    result["postgis"] = dict(result["db"])
    result["postgis"]["image_repo_digests"] = list(result["db"]["image_repo_digests"])
    result["app"] = {
        "artifact_ref": QGEO_REF,
        "source_revision": QGEO_SHA,
        "container_id": "container-qgeo",
        "config_image": QGEO_REF,
        "image_id": "sha256:" + "8" * 64,
        "image_repo_digests": [QGEO_REF],
    }
    return result


def _candidate_request(*, evidence: dict | None = None) -> ReleaseAdmissionRequest:
    if evidence is None:
        evidence = {
            "ci": {
                "status": "passed",
                "source_sha": QGEO_SHA,
                "run_ids": ["33838251934", "33838251867"],
                "job_set_digest": "1" * 64,
                "release_evidence_sha256": "2" * 64,
            },
            "artifact": {
                "status": "passed",
                "source_sha": QGEO_SHA,
                "artifact_digest": QGEO_DIGEST,
                "artifact_ref": QGEO_REF,
            },
            "static": {"status": "passed", "source_sha": QGEO_SHA, "digest": "sha256:" + "b" * 64},
            "sbom": {
                "status": "passed",
                "source_sha": QGEO_SHA,
                "digest": "sha256:" + "3" * 64,
                "format": "SPDX-2.3",
                "artifact_digest": QGEO_DIGEST,
            },
            "provenance": {
                "status": "passed",
                "source_sha": QGEO_SHA,
                "artifact_digest": QGEO_DIGEST,
                "qazstack_source_sha": "f" * 40,
                "qazstack_version": "candidate-bound",
                "qazstack_source_manifest_sha256": "sha256:" + "c" * 64,
                "avds_source_sha": "e" * 40,
                "avds_artifact_sha256": "d" * 64,
            },
            "security": {
                "status": "passed",
                "source_sha": QGEO_SHA,
                "source_scan_digest": "sha256:" + "4" * 64,
                "image_scan_digest": "sha256:" + "5" * 64,
                "artifact_digest": QGEO_DIGEST,
            },
            "preflight": {
                "status": "passed",
                "source_sha": QGEO_SHA,
                "release_lane": "qdev-release-qazgeo",
                "placement": "qazgeo-app-runtime",
                "heartbeat_digest": "sha256:" + "6" * 64,
                "heartbeat_received_at": 1.0,
            },
        }
    return ReleaseAdmissionRequest.model_validate(
        {
            "schema": REQUEST_SCHEMA,
            "release_lane": "qdev-release-qazgeo",
            "project_id": "qazgeo",
            "placement": "qazgeo-app-runtime",
            "source_sha": QGEO_SHA,
            "artifact_digest": QGEO_DIGEST,
            "artifact_ref": QGEO_REF,
            "candidate_receipt": {
                "schema": "qdev-release-candidate-receipt-v1",
                "status": "passed",
                "source_sha": QGEO_SHA,
                "artifact_digest": QGEO_DIGEST,
                "artifact_ref": QGEO_REF,
                "repository": "belilovsky/qazgeo",
                "workflow": "CI – QazGeo",
                "job": "docker-build",
                "run_id": 33838251934,
                "job_id": 101039384205,
                "attempt": 1,
                "runner_profile": "qdev-ci-docker",
                "evidence": evidence,
            },
        }
    )


def _sign_request(
    request: ReleaseAdmissionRequest,
    lane,
    *,
    nonce: str = "candidate-release-nonce-000000000001",
) -> None:
    claim = controller_claim_payload(
        request,
        lane,
        issued_at=TEST_NOW,
        expires_at=TEST_NOW + 120,
        nonce=nonce,
    )
    request.controller_claim = claim
    request.controller_claim_signature = hmac.new(
        SIGNING_KEY.encode("utf-8"),
        json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _record_bootstrap_heartbeat(store: ReleaseStore, lane) -> None:
    anchor = (
        {
            "source_sha": QAZAGENTS_ROLLBACK_SHA,
            "artifact_digest": QAZAGENTS_ROLLBACK_DIGEST,
            "artifact_ref": QAZAGENTS_ROLLBACK_REF,
        }
        if lane.project_id == "qazagents"
        else {
            "source_sha": ROLLBACK_SHA,
            "artifact_digest": ROLLBACK_DIGEST,
            "artifact_ref": ROLLBACK_REF,
        }
    )
    heartbeat = HostHeartbeatRequest.model_validate(
        {
            "schema": HOST_HEARTBEAT_SCHEMA,
            "release_lane": lane.name,
            "project_id": lane.project_id,
            "placement": lane.placement,
            "state": "ready",
            "release_lock": "available",
            "capacity_free_gib": 62.3,
            "active_release": anchor,
            "rollback": {"verified": True, **anchor},
            "bootstrap": True,
        }
    )
    store.record_heartbeat(
        lane,
        heartbeat,
        identity=lane.host_agent_mtls_identity,
        now=TEST_NOW,
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


def test_qazagents_static_candidate_requires_archive_and_manifest_provenance() -> None:
    lane = _qazagents_lane()
    validate_candidate(_qazagents_candidate_request(), lane)

    evidence = _qazagents_evidence()
    evidence["provenance"]["archive_sha256"] = "0" * 64
    with pytest.raises(ReleaseLaneError, match="provenance evidence"):
        validate_candidate(_qazagents_candidate_request(evidence=evidence), lane)

    request = _qazagents_candidate_request()
    request.candidate_receipt["artifact_type"] = "oci"
    request.candidate_receipt.pop("archive_sha256")
    request.candidate_receipt.pop("payload_sha256")
    with pytest.raises(ReleaseLaneError, match="QazAgents candidate must"):
        validate_candidate(request, lane)


def test_qazagents_controller_claim_binds_full_static_evidence() -> None:
    lane = _qazagents_lane()
    request = _qazagents_candidate_request()
    claim = controller_claim_payload(
        request,
        lane,
        issued_at=TEST_NOW,
        expires_at=TEST_NOW + 120,
        nonce="qazagents-static-nonce-000000000001",
    )
    assert claim["candidate_evidence_digest"] == qazagents_candidate_evidence_digest(
        request.candidate_receipt["evidence"]
    )
    request.controller_claim = claim
    request.controller_claim_signature = hmac.new(
        SIGNING_KEY.encode("utf-8"),
        json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    validate_controller_claim(request, lane, signing_key=SIGNING_KEY, now=TEST_NOW)

    request.candidate_receipt["evidence"]["static"]["skills_manifest_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(ReleaseLaneError, match="does not bind release tuple"):
        validate_controller_claim(request, lane, signing_key=SIGNING_KEY, now=TEST_NOW)


def test_http_archive_dispatch_claim_binds_verified_delivery_coordinates(tmp_path: Path) -> None:
    lane = _qazagents_lane()
    store = ReleaseStore(tmp_path / "release-state")
    request = _qazagents_candidate_request()
    _record_bootstrap_heartbeat(store, lane)
    _sign_request(request, lane, nonce="qazagents-static-nonce-000000000003")
    admitted, _ = store.admit(request, lane, now=TEST_NOW)
    dispatched = store.next_job(
        lane,
        host_identity=lane.host_agent_mtls_identity,
        dispatch_signing_key=SIGNING_KEY,
        now=TEST_NOW + 1,
    )
    assert dispatched is not None
    claim = dispatched["dispatch_claim"]
    assert claim["artifact_delivery"] == {
        "schema": "qdev-release-http-archive-delivery-v1",
        "artifact_uri": "https://ci.qdev.run/artifacts/qazagents-static/release.tar.gz",
        "archive_sha256": QAZAGENTS_ARCHIVE_SHA256,
        "payload_sha256": QAZAGENTS_PAYLOAD_SHA256,
    }
    assert (
        dispatched["dispatch_claim_signature"]
        == hmac.new(
            SIGNING_KEY.encode("utf-8"),
            json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
                "utf-8"
            ),
            hashlib.sha256,
        ).hexdigest()
    )

    corrupted = copy.deepcopy(dispatched)
    corrupted["candidate_receipt"]["artifact_uri"] = "http://invalid.example/archive.tar.gz"
    with pytest.raises(ReleaseLaneError, match="HTTP archive delivery coordinates"):
        candidate_artifact_delivery(corrupted)
    with pytest.raises(ReleaseLaneError, match="HTTP archive delivery coordinates"):
        host_dispatch_claim_payload(
            corrupted,
            lane,
            host_identity=lane.host_agent_mtls_identity,
            issued_at=TEST_NOW + 1,
            expires_at=TEST_NOW + 121,
            nonce="qazagents-static-nonce-000000000004",
        )


def test_qazagents_runtime_receipts_require_the_static_host_adapter_and_bundle() -> None:
    lane = _qazagents_lane()
    receipt = _qazagents_runtime_receipt(lane)
    validate_runtime_receipt(
        receipt,
        lane=lane,
        source_sha=QAZAGENTS_SHA,
        artifact_digest=QAZAGENTS_DIGEST,
        artifact_ref=QAZAGENTS_REF,
    )
    native = {
        "schema": "qdev-admin-platform-native-receipt-v1",
        "project_id": lane.project_id,
        "native_host_adapter": lane.native_host_adapter,
        "source_sha": QAZAGENTS_SHA,
        "artifact_digest": QAZAGENTS_DIGEST,
        "artifact_ref": QAZAGENTS_REF,
        "readiness": {"native": "ok", "public": "ok", "identity": "ok"},
        "runtime_identity": receipt["runtime_identity"],
        "dependency_identity": receipt["dependency_identity"],
        "artifact_provenance": receipt["artifact_provenance"],
        "static_bundle": receipt["static_bundle"],
    }
    validate_native_runtime_receipt(
        native,
        lane=lane,
        source_sha=QAZAGENTS_SHA,
        artifact_digest=QAZAGENTS_DIGEST,
        artifact_ref=QAZAGENTS_REF,
    )

    without_bundle = copy.deepcopy(receipt)
    without_bundle.pop("static_bundle")
    with pytest.raises(ReleaseLaneError, match="static bundle evidence is required"):
        validate_runtime_receipt(
            without_bundle,
            lane=lane,
            source_sha=QAZAGENTS_SHA,
            artifact_digest=QAZAGENTS_DIGEST,
            artifact_ref=QAZAGENTS_REF,
        )

    forged_adapter = copy.deepcopy(native)
    forged_adapter["dependency_identity"] = {
        "static_host_adapter": "qgeo-native-immutable-release-v1"
    }
    with pytest.raises(ReleaseLaneError, match="static host adapter identity"):
        validate_native_runtime_receipt(
            forged_adapter,
            lane=lane,
            source_sha=QAZAGENTS_SHA,
            artifact_digest=QAZAGENTS_DIGEST,
            artifact_ref=QAZAGENTS_REF,
        )

    absolute_manifest = copy.deepcopy(native)
    absolute_manifest["static_bundle"]["manifest"] = "/release-manifest.json"
    with pytest.raises(ReleaseLaneError, match="static bundle evidence"):
        validate_native_runtime_receipt(
            absolute_manifest,
            lane=lane,
            source_sha=QAZAGENTS_SHA,
            artifact_digest=QAZAGENTS_DIGEST,
            artifact_ref=QAZAGENTS_REF,
        )


def test_qazagents_complete_rejects_static_provenance_drift(tmp_path: Path) -> None:
    lane = _qazagents_lane()
    store = ReleaseStore(tmp_path / "release-state")
    request = _qazagents_candidate_request()
    _record_bootstrap_heartbeat(store, lane)
    _sign_request(request, lane, nonce="qazagents-static-nonce-000000000002")
    admitted, _ = store.admit(request, lane, now=TEST_NOW)
    dispatched = store.next_job(
        lane,
        host_identity=lane.host_agent_mtls_identity,
        dispatch_signing_key=SIGNING_KEY,
        now=TEST_NOW + 1,
    )
    assert dispatched is not None

    forged = _qazagents_runtime_receipt(lane)
    forged["static_bundle"]["skills_manifest_sha256"] = "sha256:" + "0" * 64
    with pytest.raises(ReleaseLaneError, match="static bundle does not match"):
        store.complete(
            lane,
            str(admitted["release_id"]),
            forged,
            lease_id=str(admitted["lease_id"]),
            fence=str(admitted["fence"]),
            now=TEST_NOW + 2,
        )

    completed = store.complete(
        lane,
        str(admitted["release_id"]),
        _qazagents_runtime_receipt(lane),
        lease_id=str(admitted["lease_id"]),
        fence=str(admitted["fence"]),
        now=TEST_NOW + 2,
    )
    assert completed["status"] == "verified"


def test_qgeo_controller_claim_binds_complete_candidate_evidence() -> None:
    lane = _qgeo_lane()
    request = _candidate_request()
    claim = controller_claim_payload(request, lane)
    assert claim["schema"] == CONTROLLER_CLAIM_SCHEMA
    assert claim["candidate_evidence_digest"] == qgeo_candidate_evidence_digest(
        request.candidate_receipt["evidence"]
    )
    signing_key = SIGNING_KEY
    encoded = json.dumps(
        claim,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    request.controller_claim = claim
    request.controller_claim_signature = hmac.new(
        signing_key.encode("utf-8"), encoded, hashlib.sha256
    ).hexdigest()
    validate_controller_claim(request, lane, signing_key=signing_key)

    request.candidate_receipt["evidence"]["security"]["image_scan_digest"] = "sha256:" + "7" * 64
    with pytest.raises(ReleaseLaneError, match="does not bind release tuple"):
        validate_controller_claim(request, lane, signing_key=signing_key)


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


def test_release_policy_parses_and_validates_certificate_bindings(tmp_path: Path) -> None:
    document = yaml.safe_load(LANES_PATH.read_text(encoding="utf-8"))
    document["lanes"]["qdev-release-qazgeo"]["client_certificate_sha256"] = "a" * 64
    document["lanes"]["qdev-release-qazgeo"]["host_agent_certificate_sha256"] = "b" * 64
    path = tmp_path / "release-lanes.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    lane = ReleaseLanePolicy(path).lane("qdev-release-qazgeo")
    assert lane.client_certificate_sha256 == "a" * 64
    assert lane.host_agent_certificate_sha256 == "b" * 64

    document["lanes"]["qdev-release-qazgeo"]["client_certificate_sha256"] = "not-a-fingerprint"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ReleaseLaneError, match="certificate binding"):
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
            "app": "ok",
        },
        "runtime_identity": {
            "source_sha": QGEO_SHA,
            "artifact_digest": QGEO_DIGEST,
            "artifact_ref": QGEO_REF,
            "measured": True,
            "container_id": "container-qgeo",
            "config_image": QGEO_REF,
            "image_id": "sha256:" + "8" * 64,
            "image_repo_digests": [QGEO_REF],
        },
        "dependency_identity": _qgeo_dependency_identity(),
        "artifact_provenance": {
            "qazstack_source_sha": "f" * 40,
            "qazstack_version": "candidate-bound",
            "qazstack_source_manifest_sha256": "sha256:" + "c" * 64,
            "avds_artifact_sha256": "d" * 64,
            "avds_source_sha": "e" * 40,
        },
        "static_bundle": {
            "digest": "sha256:" + "b" * 64,
            "manifest": "/opt/qazgeo/manifests/test.json",
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

    receipt["readiness"]["redis"] = "ok"
    receipt["dependency_identity"]["redis"]["artifact_ref"] = "redis:7"
    with pytest.raises(ReleaseLaneError, match="dependency identity"):
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
    _record_bootstrap_heartbeat(store, lane)
    _sign_request(request, lane)
    first, idempotent = store.admit(request, lane, now=TEST_NOW)
    assert idempotent is False
    dispatched = store.next_job(
        lane,
        host_identity=lane.host_agent_mtls_identity,
        dispatch_signing_key=SIGNING_KEY,
        now=TEST_NOW + 1,
    )
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
            "app": "ok",
        },
        "runtime_identity": {
            "source_sha": QGEO_SHA,
            "artifact_digest": QGEO_DIGEST,
            "artifact_ref": QGEO_REF,
            "measured": True,
            "container_id": "container-qgeo",
            "config_image": QGEO_REF,
            "image_id": "sha256:" + "8" * 64,
            "image_repo_digests": [QGEO_REF],
        },
        "dependency_identity": _qgeo_dependency_identity(),
        "artifact_provenance": {
            "qazstack_source_sha": "f" * 40,
            "qazstack_version": "candidate-bound",
            "qazstack_source_manifest_sha256": "sha256:" + "c" * 64,
            "avds_artifact_sha256": "d" * 64,
            "avds_source_sha": "e" * 40,
        },
        "static_bundle": {
            "digest": "sha256:" + "b" * 64,
            "manifest": "/opt/qazgeo/manifests/test.json",
        },
        "rollback": {
            "verified": True,
            "source_sha": ROLLBACK_SHA,
            "artifact_digest": ROLLBACK_DIGEST,
            "artifact_ref": ROLLBACK_REF,
        },
    }
    completed = store.complete(
        lane,
        str(first["release_id"]),
        runtime_receipt,
        lease_id=str(first["lease_id"]),
        fence=str(first["fence"]),
    )
    repeated, idempotent = store.admit(request, lane, now=TEST_NOW + 2)
    assert idempotent is True
    assert repeated["release_id"] == completed["release_id"]


def test_expired_dispatched_qgeo_lease_allows_only_exact_bounded_terminal_recovery(
    tmp_path: Path,
) -> None:
    lane = _qgeo_lane()
    store = ReleaseStore(tmp_path / "release-state")
    request = _candidate_request()
    _record_bootstrap_heartbeat(store, lane)
    _sign_request(request, lane)
    job, _ = store.admit(request, lane, now=TEST_NOW, lease_ttl_seconds=60)
    dispatched = store.next_job(
        lane,
        host_identity=lane.host_agent_mtls_identity,
        dispatch_signing_key=SIGNING_KEY,
        now=TEST_NOW + 1,
        claim_ttl_seconds=30,
    )
    assert dispatched is not None

    ReleaseStore._ensure_terminal_lease(dispatched, lane, now=TEST_NOW + 61)

    forged = json.loads(json.dumps(dispatched))
    forged["dispatch_claim"]["exact_sha"] = "e" * 40
    with pytest.raises(ReleaseLaneError, match="dispatch proof is not exact"):
        ReleaseStore._ensure_terminal_lease(forged, lane, now=TEST_NOW + 61)

    never_dispatched = {**job, "status": "accepted", "operation_phase": "accepted"}
    with pytest.raises(ReleaseLaneError, match="was not durably dispatched"):
        ReleaseStore._ensure_terminal_lease(never_dispatched, lane, now=TEST_NOW + 61)

    with pytest.raises(ReleaseLaneError, match="grace has expired"):
        ReleaseStore._ensure_terminal_lease(dispatched, lane, now=TEST_NOW + 86_461)


def test_release_admission_rejects_changed_evidence_for_same_tuple(tmp_path: Path) -> None:
    lane = _qgeo_lane()
    store = ReleaseStore(tmp_path / "release-state")
    request = _candidate_request()
    _record_bootstrap_heartbeat(store, lane)
    _sign_request(request, lane)
    store.admit(request, lane, now=TEST_NOW)
    changed = _candidate_request()
    changed.candidate_receipt["evidence"]["static"]["digest"] = "sha256:" + "c" * 64
    _sign_request(changed, lane, nonce="candidate-release-nonce-000000000002")
    with pytest.raises(ReleaseLaneError, match="different candidate evidence"):
        store.admit(changed, lane, now=TEST_NOW + 1)
