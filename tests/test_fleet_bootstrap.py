from __future__ import annotations

from pathlib import Path

import pytest
from bootstrap_support import candidate_receipt

from qdev_runner.fleet_bootstrap import (
    REQUEST_SCHEMA,
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    bootstrap_request_fingerprint,
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
        "controller_release_digest": (
            "sha256:93d3c8208ed40ed7702ac79a69dbf4e712192f3a929b0c632ea1a13263c61cf3"
        ),
        "controller_candidate_receipt": candidate_receipt(
            image_digest=("sha256:93d3c8208ed40ed7702ac79a69dbf4e712192f3a929b0c632ea1a13263c61cf3")
        ),
        "release_lane": None,
        "worker_name": None,
    }
    body.update(overrides)
    if body["action"] != "activate-controller" and "controller_candidate_receipt" not in overrides:
        body["controller_candidate_receipt"] = None
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


def test_bootstrap_policy_accepts_only_the_fixed_transition() -> None:
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
        worker_name="srv1879763-primary",
    )
    policy.validate(request)
    target = policy.worker_target("srv1879763-primary")
    assert target is not None
    assert target.target_id == "controller.worker.srv1879763-primary"
    assert target.service_unit == "qdev-runner-worker.service"
    assert target.host_binding == "controller-registry"
    assert target.certificate_fingerprint_sha256 == (
        "ed0a503d98a2c163c42b3244f5b4f83c88b7b3ab4a7e028482c890ab814650f3"
    )
    assert target.labels == (
        "self-hosted",
        "Linux",
        "X64",
        "qdev-ci",
        "qdev-ci-browser",
        "qdev-ci-docker",
    )


def test_bootstrap_policy_rejects_worker_profile_coverage_drift(tmp_path: Path) -> None:
    altered = (POLICY.read_text(encoding="utf-8")).replace(
        ", qdev-ci-browser, qdev-ci-docker]", ", qdev-ci-browser]"
    )
    policy_path = tmp_path / "fleet-bootstrap.yml"
    policy_path.write_text(altered, encoding="utf-8")
    with pytest.raises(FleetBootstrapError, match="cover exactly"):
        FleetBootstrapPolicy(policy_path, RELEASE_LANES)


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"controller_revision": "b" * 40}, "workflow source"),
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
