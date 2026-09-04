"""Real RSA signature admission, with synthetic GitHub and controller state."""
from __future__ import annotations

import copy
import time
from pathlib import Path

import pytest
from bootstrap_support import KEY, GitHub, claims, policy, register, request
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError
from test_github_oidc import _jwk, _token

from qdev_runner.bootstrap_authority import authorize_bootstrap, verify_directive
from qdev_runner.fleet_bootstrap import FleetBootstrapError, FleetBootstrapRequest
from qdev_runner.github_oidc import GitHubActionsArtifactOIDCVerifier, GitHubActionsOIDCError
from qdev_runner.store import Store


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def admit(tmp_path, rsa_key, *, changes=None, job_changes=None, run_changes=None, registered=True):
    controller = Store(tmp_path / "broker.db")
    if registered:
        register(controller)
    identity = policy()
    verifier = GitHubActionsArtifactOIDCVerifier(
        audience=identity.identity.audience, fetch_jwks=lambda: {"keys": [_jwk(rsa_key)]},
    )
    github = GitHub()
    github.job.update(job_changes or {})
    github.run.update(run_changes or {})
    return authorize_bootstrap(
        token=_token(rsa_key, claims() | (changes or {})), request=request(),
        idempotency_key="worker-recovery-001", policy=identity, verifier=verifier,
        github=github, controller_store=controller, signing_key=KEY,
    )


def test_real_oidc_signature_produces_bounded_verified_operation(tmp_path: Path, rsa_key):
    operation = admit(tmp_path, rsa_key)
    assert verify_directive(operation.directive, policy=policy(), signing_key=KEY) == operation
    payload = operation.directive["payload"]
    assert 0 < payload["expires_at"] - payload["issued_at"] <= 300
    assert set(payload) == {
        "schema", "request", "idempotency_key", "fence", "issued_at", "expires_at",
    }


@pytest.mark.parametrize("changes", [
    {"iss": "https://untrusted.invalid"}, {"aud": "qdev-artifact-v1"},
    {"repository": "belilovsky/other"}, {"ref": "refs/heads/other"},
    {"sha": "b" * 40}, {"run_id": "124"}, {"run_attempt": "2"},
    {"workflow_ref": "belilovsky/other/.github/workflows/fleet-bootstrap.yml@refs/heads/main"},
    {"job_workflow_ref": "belilovsky/other/.github/workflows/reusable.yml@refs/heads/main"},
    {"event_name": "pull_request"}, {"event_name": "push"},
    {"iat": False}, {"iat": float("nan")}, {"exp": float("inf")},
    {"iat": int(time.time()) + 30}, {"exp": int(time.time()) - 1},
    {"iat": int(time.time()) - 500, "exp": int(time.time()) + 500},
])
def test_rejects_oidc_binding_changes(tmp_path, rsa_key, changes):
    with pytest.raises((FleetBootstrapError, GitHubActionsOIDCError)):
        admit(tmp_path, rsa_key, changes=changes)


@pytest.mark.parametrize("job_changes,run_changes", [
    ({"id": 457}, {}), ({"run_id": 124}, {}), ({"run_attempt": 2}, {}),
    ({"head_sha": "b" * 40}, {}), ({"status": "completed"}, {}),
    ({"name": "fleet-bootstrap-validate"}, {}), ({}, {"id": 124}),
    ({}, {"run_attempt": 2}), ({}, {"head_sha": "b" * 40}),
    ({}, {"head_branch": "other"}), ({}, {"event": "push"}),
    ({}, {"path": ".github/workflows/other.yml"}), ({}, {"status": "completed"}),
])
def test_rejects_github_attempt_mismatch(tmp_path, rsa_key, job_changes, run_changes):
    with pytest.raises(FleetBootstrapError, match="GitHub job attempt"):
        admit(tmp_path, rsa_key, job_changes=job_changes, run_changes=run_changes)


def test_requires_controller_webhook_and_claim_record(tmp_path, rsa_key):
    with pytest.raises(FleetBootstrapError, match="controller job identity"):
        admit(tmp_path, rsa_key, registered=False)


def test_rejects_wrong_directive_signer_and_tampering(tmp_path, rsa_key):
    operation = admit(tmp_path, rsa_key)
    with pytest.raises(FleetBootstrapError, match="signature"):
        verify_directive(operation.directive, policy=policy(), signing_key="other-test-key")
    forged = copy.deepcopy(operation.directive)
    forged["payload"]["request"]["worker_name"] = "qdev-qazstack-01"
    with pytest.raises(FleetBootstrapError, match="signature"):
        verify_directive(forged, policy=policy(), signing_key=KEY)


@pytest.mark.parametrize("field", ["run_id", "job_id", "attempt", "claim_ttl_seconds"])
@pytest.mark.parametrize("value", [True, "1", 1.0, 0, -1])
def test_rejects_non_exact_positive_integer_request_fields(field, value):
    raw = request().model_dump(by_alias=True)
    raw[field] = value
    with pytest.raises(ValidationError):
        FleetBootstrapRequest.model_validate(raw)
