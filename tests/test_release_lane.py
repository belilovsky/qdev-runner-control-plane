import hashlib
import hmac
import json
from dataclasses import replace
from pathlib import Path

import pytest
import yaml

from qdev_runner.release_lane import (
    CONTROLLER_CLAIM_SCHEMA,
    HOST_HEARTBEAT_SCHEMA,
    REQUEST_SCHEMA,
    RUNTIME_RECEIPT_SCHEMA,
    SCOPED_CONTROLLER_CLAIM_SCHEMA,
    HostHeartbeatRequest,
    ReleaseAdmissionRequest,
    ReleaseLaneError,
    ReleaseLanePolicy,
    ReleaseStore,
    controller_claim_payload,
    qgeo_candidate_evidence_digest,
    validate_candidate,
    validate_controller_claim,
    validate_host_heartbeat,
    validate_runtime_receipt,
)

ROOT = Path(__file__).parents[1]
LANES_PATH = ROOT / "config" / "release-lanes.yml"
QGEO_SHA = "9" * 40
QGEO_DIGEST = "sha256:" + "a" * 64
QGEO_REF = f"registry.ci.qdev.run/belilovsky/qazgeo@{QGEO_DIGEST}"
RP_SHA = "8" * 40
RP_DIGEST = "sha256:" + "e" * 64
RP_REF = f"registry.ci.qdev.run/belilovsky/ipos@{RP_DIGEST}"
RP_SOURCE_PATHS = (
    "qdev-reports-private.json",
    "qdev-rp-platform.json",
    "Dockerfile.reports",
    "docker-compose.reports.yml",
    "deploy/build-reports.sh",
    "deploy/publish-reports-image.sh",
)
ROLLBACK_SHA = "d65cd62a4c96786d9d5c35ebea8af872dcc3cb69"
ROLLBACK_DIGEST = "sha256:96d4399d5f5345f956abbffbd185552da4406a7a26017164f2ca6313688ef5cb"
ROLLBACK_REF = f"registry.ci.qdev.run/belilovsky/qazgeo@{ROLLBACK_DIGEST}"
SIGNING_KEY = "controller-claim-test-key-32-bytes!!"
TEST_NOW = 2_000_000_000


def _qgeo_lane():
    return ReleaseLanePolicy(LANES_PATH).lane("qdev-release-qazgeo")


def _rp_lane():
    return ReleaseLanePolicy(LANES_PATH).lane("qdev-release-rp")


def _reviewed_rp_lane():
    """Test the future signed binding without changing the pending config."""
    return replace(
        _rp_lane(),
        activation_state="active",
        client_mtls_identity="qdev-release-client:rp-test",
        host_agent_mtls_identity="qdev-host-agent:rp-test",
        minimum_free_gib=20,
        heartbeat_ttl_seconds=90,
        rollback_reference="test-rollback-anchor",
        required_readiness=("private",),
    )


def _rp_candidate_request(
    *, source_paths: tuple[str, ...] = RP_SOURCE_PATHS
) -> ReleaseAdmissionRequest:
    return ReleaseAdmissionRequest.model_validate(
        {
            "schema": REQUEST_SCHEMA,
            "release_lane": "qdev-release-rp",
            "project_id": "rp",
            "placement": "vps-apps-148",
            "source_sha": RP_SHA,
            "artifact_digest": RP_DIGEST,
            "artifact_ref": RP_REF,
            "candidate_receipt": {
                "schema": "qdev-release-candidate-receipt-v1",
                "status": "passed",
                "source_sha": RP_SHA,
                "artifact_digest": RP_DIGEST,
                "artifact_ref": RP_REF,
                "repository": "belilovsky/ipos",
                "workflow": "Reports private release",
                "job": "build-reports",
                "run_id": 123,
                "job_id": 456,
                "attempt": 1,
                "runner_profile": "qdev-ci-docker",
                "managed_registry_entry": "rp-reports-private",
                "source_scope": "reports-private",
                "source_paths": list(source_paths),
            },
        }
    )


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
    anchor = {
        "source_sha": ROLLBACK_SHA,
        "artifact_digest": ROLLBACK_DIGEST,
        "artifact_ref": ROLLBACK_REF,
    }
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


def test_reports_private_pending_lane_cannot_touch_state_or_active_shared_host(
    tmp_path: Path,
) -> None:
    lane = _rp_lane()
    assert lane.is_scoped
    assert lane.activation_state == "pending_external_enrolment"
    assert lane.client_mtls_identity == ""
    assert lane.host_agent_mtls_identity == ""
    assert lane.rollback_reference == ""

    with pytest.raises(ReleaseLaneError, match="pending external enrolment"):
        validate_candidate(_rp_candidate_request(), lane)

    store = ReleaseStore(tmp_path / "release-state")
    with pytest.raises(ReleaseLaneError, match="pending external enrolment"):
        store.admit(_rp_candidate_request(), lane, now=TEST_NOW)
    assert not (store.jobs_root / "qdev-release-rp.json").exists()
    assert not (store.operations_root / "qdev-release-rp.jsonl").exists()

    policy = ReleaseLanePolicy(LANES_PATH)
    # RP's pending record shares the declared placement without changing the
    # single active lane already used by the enrolled host agent.
    assert policy.lane_for_placement("vps-apps-148").name == "qdev-release-qaz-fund"
    with pytest.raises(ReleaseLaneError, match="pending external enrolment"):
        policy.lane_for_host("vps-apps-148", "qdev-release-rp")


def test_reports_private_controller_claim_binds_exact_source_scope_after_review() -> None:
    """A test-only reviewed lane proves the future contract without activation."""
    lane = _reviewed_rp_lane()
    request = _rp_candidate_request()
    validate_candidate(request, lane)
    _sign_request(request, lane)
    assert request.controller_claim is not None
    assert request.controller_claim["schema"] == SCOPED_CONTROLLER_CLAIM_SCHEMA
    assert request.controller_claim["scope"]["source_scope"] == "reports-private"
    assert request.controller_claim["scope"]["source_paths"] == list(RP_SOURCE_PATHS)
    validate_controller_claim(request, lane, signing_key=SIGNING_KEY, now=TEST_NOW)

    changed_paths = RP_SOURCE_PATHS[:-1]
    with pytest.raises(ReleaseLaneError, match="source scope"):
        validate_candidate(_rp_candidate_request(source_paths=changed_paths), lane)


def test_reports_private_lane_rejects_fabricated_active_config(tmp_path: Path) -> None:
    document = yaml.safe_load(LANES_PATH.read_text(encoding="utf-8"))
    document["lanes"]["qdev-release-rp"]["activation"]["state"] = "active"
    path = tmp_path / "release-lanes.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ReleaseLaneError, match="pending admission"):
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
