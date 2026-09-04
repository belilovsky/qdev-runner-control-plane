from __future__ import annotations

from pathlib import Path

import pytest

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
        "controller_revision": "bfabddddcd4c6aa1679b7a45dd4d63054feee4cd",
        "controller_release_digest": (
            "sha256:a879c69590c1a8586565302746ef6f53b57be0325f2197b209299ccdffc2abc1"
        ),
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


def test_bootstrap_policy_accepts_only_the_fixed_transition() -> None:
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    policy.validate(_request())
    policy.validate_oidc_claims(_claims(), _request())


def test_bootstrap_policy_accepts_standard_workflow_without_job_workflow_ref() -> None:
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    claims = _claims()
    claims.pop("job_workflow_ref")
    policy.validate_oidc_claims(claims, _request())


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"controller_revision": "b" * 40}, "tuple"),
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
