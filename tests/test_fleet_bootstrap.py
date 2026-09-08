from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from qdev_runner.fleet_bootstrap import (
    REQUEST_SCHEMA,
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    bootstrap_request_fingerprint,
    bootstrap_request_fingerprints,
)

ROOT = Path(__file__).resolve().parents[1]
POLICY = ROOT / "config" / "fleet-bootstrap.yml"
RELEASE_LANES = ROOT / "config" / "release-lanes.yml"
SOURCE_SHA = "a" * 40


def _request(**overrides: object) -> FleetBootstrapRequest:
    body: dict[str, object] = {
        "schema": REQUEST_SCHEMA,
        "action": "activate-controller",
        "source_sha": SOURCE_SHA,
        "run_id": 123,
        "job_id": 456,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": SOURCE_SHA,
        "controller_release_digest": "sha256:" + "b" * 64,
        "controller_image_digest": "sha256:" + "c" * 64,
        "activation_envelope_digest": "sha256:" + "d" * 64,
        "release_lane": None,
        "worker_name": None,
    }
    body.update(overrides)
    return FleetBootstrapRequest.model_validate(body)


def _claims(**overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "repository": "belilovsky/qdev-runner-control-plane",
        "ref": "refs/heads/main",
        "sha": SOURCE_SHA,
        "run_id": 123,
        "run_attempt": "1",
        "workflow_ref": (
            "belilovsky/qdev-runner-control-plane/.github/workflows/"
            "fleet-bootstrap.yml@refs/heads/main"
        ),
        "job_workflow_ref": (
            "belilovsky/qdev-runner-control-plane/.github/workflows/"
            "fleet-bootstrap.yml@refs/heads/main"
        ),
    }
    values.update(overrides)
    return values


def test_bootstrap_policy_accepts_dynamic_source_bound_signed_transition() -> None:
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    policy.validate(_request())
    policy.validate_oidc_claims(_claims(), _request())


def test_bootstrap_policy_accepts_standard_workflow_without_job_workflow_ref() -> None:
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    claims = _claims()
    claims.pop("job_workflow_ref")
    policy.validate_oidc_claims(claims, _request())


def test_bootstrap_policy_maps_only_existing_runner_identities() -> None:
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    request = _request(
        action="restore-existing-worker",
        release_lane=None,
        worker_name="qdev-platform-ci-187",
        controller_revision=None,
        controller_release_digest=None,
        controller_image_digest=None,
        activation_envelope_digest=None,
    )
    policy.validate(request)
    target = policy.worker_target("qdev-platform-ci-187")
    assert target is not None
    assert target.target_id == ("actions.runner.belilovsky-platform-portal.qdev-platform-ci-187")
    assert target.service_unit.endswith(".service")
    assert target.host_binding == "controller-registry"


def test_pending_reports_private_lane_cannot_become_bootstrap_target(tmp_path: Path) -> None:
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    with pytest.raises(FleetBootstrapError, match="allowlisted"):
        policy.release_lane("qdev-release-rp")

    # Even an accidental future allowlist edit cannot turn the pending source
    # contract into a host-enrolment target before external evidence exists.
    document = yaml.safe_load(POLICY.read_text(encoding="utf-8"))
    document["enrolment"]["lanes"].append("qdev-release-rp")
    scoped_policy_path = tmp_path / "fleet-bootstrap.yml"
    scoped_policy_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    policy = FleetBootstrapPolicy(scoped_policy_path, RELEASE_LANES)
    with pytest.raises(FleetBootstrapError, match="unavailable"):
        policy.release_lane("qdev-release-rp")


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"controller_revision": "b" * 40}, "workflow source"),
        ({"controller_release_digest": "sha256:bad"}, "signed envelope"),
        ({"controller_image_digest": "sha256:bad"}, "signed envelope"),
        ({"activation_envelope_digest": "sha256:bad"}, "signed envelope"),
        ({"claim_ttl_seconds": 901}, "TTL"),
        (
            {
                "action": "enrol-host-agent",
                "release_lane": "qdev-release-qaz-fund",
                "worker_name": None,
            },
            "lane",
        ),
        (
            {
                "action": "restore-existing-worker",
                "release_lane": None,
                "worker_name": "temporary-runner",
                "controller_revision": None,
                "controller_release_digest": None,
                "controller_image_digest": None,
                "activation_envelope_digest": None,
            },
            "worker",
        ),
    ],
)
def test_bootstrap_policy_rejects_any_unapproved_target(
    overrides: dict[str, object], message: str
) -> None:
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    with pytest.raises(FleetBootstrapError, match=message):
        policy.validate(_request(**overrides))


@pytest.mark.parametrize(
    "claims",
    [
        _claims(ref="refs/heads/release"),
        _claims(sha="b" * 40),
        _claims(run_attempt="2"),
        _claims(workflow_ref="belilovsky/other/.github/workflows/x.yml@refs/heads/main"),
        _claims(job_workflow_ref="belilovsky/other/.github/workflows/x.yml@refs/heads/main"),
    ],
)
def test_bootstrap_policy_rejects_oidc_claim_drift(claims: dict[str, object]) -> None:
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    with pytest.raises(FleetBootstrapError, match="OIDC"):
        policy.validate_oidc_claims(claims, _request())


def test_bootstrap_policy_has_no_pinned_controller_or_rollback_tuple() -> None:
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    assert policy.activation.mode == "signed-external-envelope"
    assert policy.activation.envelope_schema == "qdev-controller-activation-envelope-v1"
    assert policy.activation.public_key_binding == "controller-registry"
    policy.validate(
        _request(
            source_sha="d" * 40,
            controller_revision="d" * 40,
            controller_image_digest="sha256:" + "e" * 64,
            activation_envelope_digest="sha256:" + "f" * 64,
        )
    )


def test_bootstrap_operation_store_is_idempotent_and_rejects_drift(tmp_path: Path) -> None:
    request = _request()
    store = BootstrapOperationStore(tmp_path / "operations.json")
    key = "bootstrap-operation-001"

    first = store.begin(key, request)
    assert first.status == "pending"
    assert first.request_fingerprint == bootstrap_request_fingerprint(request)
    assert store.begin(key, request) == first

    with pytest.raises(FleetBootstrapError, match="reused"):
        store.begin(key, _request(run_id=124))

    completed = store.complete(key, request, {"action": "validated", "attempt": 1})
    assert completed.status == "completed"
    assert store.begin(key, request) == completed
    assert store.complete(key, request, {"action": "validated", "attempt": 1}) == completed

    with pytest.raises(FleetBootstrapError, match="cannot be changed"):
        store.complete(key, request, {"action": "different"})


def test_bootstrap_operation_store_never_persists_sensitive_result_keys(tmp_path: Path) -> None:
    store = BootstrapOperationStore(tmp_path / "operations.json")
    request = _request()
    store.begin("bootstrap-operation-002", request)
    with pytest.raises(FleetBootstrapError, match="safe"):
        store.complete("bootstrap-operation-002", request, {"oidc_token": "redacted"})


def test_bootstrap_operation_store_preserves_legacy_single_image_fingerprint(
    tmp_path: Path,
) -> None:
    request = _request()
    current = bootstrap_request_fingerprint(request)
    legacy = next(value for value in bootstrap_request_fingerprints(request) if value != current)
    path = tmp_path / "operations.json"
    path.write_text(
        (
            '{"idempotency_key":"legacy-operation-001","request_fingerprint":"'
            + legacy
            + '","result":null,"schema":"qdev-fleet-bootstrap-operation-v1",'
            '"status":"pending"}\n'
        ),
        encoding="utf-8",
    )
    store = BootstrapOperationStore(path)

    pending = store.begin("legacy-operation-001", request)
    assert pending.request_fingerprint == legacy
    completed = store.complete(
        "legacy-operation-001", request, {"action": "validated", "attempt": 1}
    )
    assert completed.request_fingerprint == legacy
    assert store.begin("legacy-operation-001", request) == completed
