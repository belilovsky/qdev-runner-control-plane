"""Real private handler and verifier; synthetic provider/store, never admission."""

import hashlib
import hmac
import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest
import yaml
from fastapi.testclient import TestClient
from test_broker_surface import _settings
from test_idp_file_evidence import Provider, observation_fixture  # noqa: F401

from qdev_runner.broker import create_app
from qdev_runner.file_apply_authorization import canonical_bytes
from qdev_runner.policy import Policy
from qdev_runner.store import Store

SIGNER = "synthetic-test-key-not-runtime-material"
URL = "/internal/v1/releases/qdev-release-idp/idp-ci-observation"
IDENTITY = {"X-QDev-mTLS-Identity": "operator"}


@pytest.fixture
def api_fixture(tmp_path, policy_files, observation_fixture):  # noqa: F811
    binding, _, root, _ = observation_fixture
    now = datetime.now(UTC)
    binding["ci_observation"]["observed_at"] = now.isoformat()
    for name in ("quality", "runner_contract"):
        binding["ci_observation"][name]["started_at"] = (now - timedelta(seconds=120)).isoformat()
        binding["ci_observation"][name]["completed_at"] = (now - timedelta(seconds=60)).isoformat()
    provider = Provider(binding)
    inventory, profiles = policy_files
    policy_path = tmp_path / "release-lanes.yml"
    lane = {
        "project_id": "id-qdev-run",
        "placement": "idp-host",
        "client_mtls_identity": "operator",
        "host_agent_mtls_identity": "qdev-host-agent:idp-host",
        "minimum_free_gib": 1,
        "heartbeat_ttl_seconds": 60,
        "artifact_repository": "idp-release",
        "canonical_repository": "belilovsky/id-qdev-run",
        "artifact_ref_prefix": "qdev/idp-release",
        "native_host_adapter": "idp-file-v1",
        "runtime_endpoints": ["https://id.qdev.run/.well-known/qdev-release.json"],
        "rollback_reference": "retained",
        "required_readiness": ["native", "identity"],
    }
    policy_path.write_text(
        yaml.safe_dump(
            {"schema_version": "qdev-release-lanes-v2", "lanes": {"qdev-release-idp": lane}}
        )
    )
    settings = replace(
        _settings(tmp_path, inventory, profiles, surface="internal"),
        artifact_root=root,
        controller_claim_key=SIGNER,
        release_lanes_path=policy_path,
        release_jobs_root=tmp_path / "release-jobs",
    )

    def app(**overrides):
        current = replace(settings, **overrides)
        return create_app(
            current,
            store=Store(current.database_path),
            policy=Policy(inventory, profiles),
            github=provider,
        )

    return binding, provider, settings, lane, app


def test_private_api_signs_measured_ci_only_without_creating_lease(api_fixture):
    binding, provider, settings, _, factory = api_fixture
    with TestClient(factory()) as client:
        response = client.post(URL, content=canonical_bytes(binding), headers=IDENTITY)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["schema"] == "qdev-controller-idp-ci-signed-observation-v1"
    measured = result["observation"]
    assert measured["status"] == "provider_ci_archive_verified"
    assert measured["release_lane"] == "qdev-release-idp"
    assert (
        result["signature"]
        == hmac.new(SIGNER.encode(), canonical_bytes(measured), hashlib.sha256).hexdigest()
    )
    assert measured["controller_admission"] == "not_verified"
    assert measured["native_runtime"] == "not_verified"
    assert measured["acceptance"] == "not_run"
    assert "lease_id" not in json.dumps(result)
    assert "log" in provider.calls
    assert not settings.release_jobs_root.exists()


@pytest.mark.parametrize("headers", [{}, {"X-QDev-mTLS-Identity": "wrong"}])
def test_private_api_requires_exact_identity_before_parsing(api_fixture, headers):
    _, provider, settings, _, factory = api_fixture
    with TestClient(factory()) as client:
        response = client.post(URL, content=b"not JSON", headers=headers)
    assert response.status_code == 403
    assert not provider.calls
    assert not settings.release_jobs_root.exists()


def test_public_surface_hides_ci_observation_even_with_identity(api_fixture):
    binding, provider, _, _, factory = api_fixture
    with TestClient(factory(surface="public")) as client:
        response = client.post(URL, content=canonical_bytes(binding), headers=IDENTITY)
    assert response.status_code == 404
    assert not response.content
    assert not provider.calls


@pytest.mark.parametrize(
    "field,value",
    [
        ("project_id", "other-project"),
        ("canonical_repository", "belilovsky/other-project"),
        ("native_host_adapter", "other-v1"),
    ],
)
def test_different_lane_is_not_an_idp_issuer(api_fixture, field, value):
    binding, provider, settings, lane, factory = api_fixture
    lane[field] = value
    settings.release_lanes_path.write_text(
        yaml.safe_dump(
            {"schema_version": "qdev-release-lanes-v2", "lanes": {"qdev-release-idp": lane}}
        )
    )
    with TestClient(factory()) as client:
        response = client.post(URL, content=canonical_bytes(binding), headers=IDENTITY)
    assert response.status_code == 422
    assert not provider.calls
    assert not settings.release_jobs_root.exists()


def test_missing_signer_does_not_read_provider_or_create_state(api_fixture):
    binding, provider, settings, _, factory = api_fixture
    with TestClient(factory(controller_claim_key=None)) as client:
        response = client.post(URL, content=canonical_bytes(binding), headers=IDENTITY)
    assert response.status_code == 503
    assert not provider.calls
    assert not settings.release_jobs_root.exists()


def test_queued_ci_cannot_be_signed_by_private_handler(api_fixture):
    binding, provider, settings, _, factory = api_fixture
    provider.runs[1]["status"] = "queued"
    with TestClient(factory()) as client:
        response = client.post(URL, content=canonical_bytes(binding), headers=IDENTITY)
    assert response.status_code == 422
    assert response.json() == {"detail": "IdP provider evidence was not verified"}
    assert not settings.release_jobs_root.exists()


@pytest.mark.parametrize(
    "body",
    [
        b'{"client_secret":"fixture-sensitive-value"}',
        b"fixture-sensitive-value",
        b"[1,2,3]",
        b"\xff",
    ],
)
def test_validation_never_echoes_supplied_values(api_fixture, body):
    _, provider, _, _, factory = api_fixture
    with TestClient(factory()) as client:
        response = client.post(URL, content=body, headers=IDENTITY)
    assert response.status_code == 422
    assert "fixture-sensitive-value" not in response.text
    assert not provider.calls


def test_body_limit_precedes_provider_lookup(api_fixture):
    _, provider, _, _, factory = api_fixture
    with TestClient(factory()) as client:
        response = client.post(URL, content=(b"x" * 32769), headers=IDENTITY)
    assert response.status_code == 413
    assert not provider.calls


def test_unknown_lane_is_not_created_on_request(api_fixture):
    binding, provider, settings, _, factory = api_fixture
    with TestClient(factory()) as client:
        response = client.post(
            URL.replace("qdev-release-idp", "unknown"),
            content=canonical_bytes(binding),
            headers=IDENTITY,
        )
    assert response.status_code == 404
    assert not provider.calls
    assert not settings.release_jobs_root.exists()
