from __future__ import annotations

from pathlib import Path

import pytest

from qdev_runner.fleet_bootstrap import (
    REQUEST_SCHEMA,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
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
        "controller_revision": "6973178af5a462a1fda71ed65ce52f3f9a2abfa2",
        "controller_release_digest": (
            "sha256:900e07564b7c29efafa9638ca337f38f19daad651921db5321adbd25230e4fab"
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
    ],
)
def test_bootstrap_policy_rejects_oidc_claim_drift(claims: dict[str, object]) -> None:
    policy = FleetBootstrapPolicy(POLICY, RELEASE_LANES)
    with pytest.raises(FleetBootstrapError, match="OIDC"):
        policy.validate_oidc_claims(claims, _request())
