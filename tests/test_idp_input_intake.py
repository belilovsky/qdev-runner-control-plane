"""Host intake with real archive verification and private retention; no helpers."""

import json
from dataclasses import replace

import pytest
import test_idp_retained_dispatch as retained
from fastapi.testclient import TestClient
from test_broker_idp_authorization import api as api_fixture
from test_file_apply_authorization import NOW
from test_idp_file_issuer import mutate_job
from test_idp_native_invocation import AGENT, make_invocation

from qdev_runner import idp_retained_dispatch as storage
from qdev_runner.idp_native_bundle import VerifiedNativeBundle

api = api_fixture


@pytest.fixture
def inputs(tmp_path, monkeypatch):
    generator = retained.store.__wrapped__(monkeypatch)
    next(generator)
    value = make_invocation(tmp_path, monkeypatch)
    value.response = {
        "schema": "qdev-controller-idp-dispatch-inputs-v1",
        "status": "authenticated_inputs", "acceptance": "not_run",
        "job": json.loads(json.dumps(value.job)), "candidate_receipt": value.candidate,
    }
    value.calls = []

    def request(config, method, path, payload=None, *, headers):
        value.calls.append(path)
        assert config == value.config and method == "GET" and payload is None
        assert path == (
            f"/internal/v1/release-hosts/{value.profile.placement}/jobs/"
            f"{value.job['release_id']}/idp-inputs?release_lane={value.lane.name}"
        )
        assert headers == {
            "X-QDev-Release-Lease": value.job["lease_id"],
            "X-QDev-Release-Fence": value.job["fence"],
        }
        return 200, json.dumps(value.response).encode()

    monkeypatch.setattr(AGENT, "request", request)
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: pytest.fail("helper execution"))
    yield value
    with pytest.raises(StopIteration):
        next(generator)


def intake(value):
    return AGENT.retain_controller_idp_inputs(
        value.config, value.profile, value.lane, value.job, value.archive,
        transaction=retained.TRANSACTION,
    )


def test_full_response_verifies_and_retains_once_without_loading(inputs):
    first = intake(inputs)
    assert first["status"] == "retained"
    assert len(inputs.calls) == 1
    metadata, archive = storage.read(retained.TRANSACTION)
    assert metadata["candidate"] == inputs.candidate
    assert metadata["job"] == inputs.job and archive == inputs.archive
    assert intake(inputs) == first
    assert len(inputs.calls) == 2


@pytest.mark.parametrize("fault", ["signature", "expiry", "lane", "identity"])
def test_invalid_job_never_contacts_controller(inputs, monkeypatch, fault):
    if fault == "signature":
        inputs.job["dispatch_claim_signature"] = "0" * 64
    elif fault == "expiry":
        monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    elif fault == "lane":
        inputs.lane = replace(inputs.lane, project_id="other")
    else:
        inputs.config = replace(inputs.config, host_identity="qdev-host-agent:other")
    with pytest.raises(AGENT.AgentError):
        intake(inputs)
    assert not inputs.calls and not storage.ROOT.exists()


@pytest.mark.parametrize("fault", [
    "job", "candidate", "attempt", "schema", "status", "acceptance", "extra", "archive",
])
def test_drift_cannot_publish_any_inputs(inputs, fault):
    if fault == "job":
        inputs.response["job"]["source_sha"] = "f" * 40
    elif fault == "candidate":
        inputs.response["candidate_receipt"]["artifact_uri"] = "https://private-fixture.invalid/"
    elif fault == "attempt":
        inputs.response["candidate_receipt"]["attempt"] += 1
    elif fault == "extra":
        inputs.response["helper"] = "private-fixture"
    elif fault == "archive":
        inputs.archive += b"private-fixture"
    else:
        inputs.response[fault] = "private-fixture"
    with pytest.raises(AGENT.AgentError) as caught:
        intake(inputs)
    assert "private-fixture" not in str(caught.value)
    assert len(inputs.calls) == 1 and not storage.ROOT.exists()


@pytest.mark.parametrize("body", [
    b"private-fixture", b"\xff", b"{}", b'{"job":{},"job":{}}',
    b"[" * 2000, b"x" * (1024 * 1024 + 1),
])
def test_malformed_bounded_transport_never_publishes(inputs, monkeypatch, body):
    monkeypatch.setattr(AGENT, "request", lambda *a, **k: (200, body))
    with pytest.raises(AGENT.AgentError) as caught:
        intake(inputs)
    assert "private-fixture" not in str(caught.value)
    assert not storage.ROOT.exists()


@pytest.mark.parametrize("outcome", [204, 401, 409, 503, "lost"])
def test_network_failure_is_not_retried(inputs, monkeypatch, outcome):
    calls = []

    def request(*args, **kwargs):
        calls.append(1)
        if outcome == "lost":
            raise AGENT.ControllerTransportError("private-fixture")
        return outcome, b"private-fixture"

    monkeypatch.setattr(AGENT, "request", request)
    with pytest.raises(AGENT.AgentError) as caught:
        intake(inputs)
    assert "private-fixture" not in str(caught.value)
    assert calls == [1] and not storage.ROOT.exists()


def test_expiry_during_read_does_not_publish(inputs, monkeypatch):
    def request(*a, **k):
        monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
        return 200, json.dumps(inputs.response).encode()

    monkeypatch.setattr(AGENT, "request", request)
    with pytest.raises(AGENT.AgentError):
        intake(inputs)
    assert not storage.ROOT.exists()


def test_actual_private_broker_response_to_verified_host_retention(api, inputs, monkeypatch):
    # Real controller journal, private key map, endpoint, signature verification,
    # nested archive/component validation and durable host retention. The archive
    # and authority are synthetic test fixtures, not live release evidence.
    assert api.lane.name == inputs.lane.name
    mutate_job(api, lambda job: job.update(
        **inputs.job, candidate_receipt=inputs.candidate,
    ))
    before = api.store.operation_events(api.lane)
    calls = []
    with TestClient(api.factory()) as client:
        def request(config, method, path, payload=None, *, headers):
            calls.append(path)
            response = client.get(path, headers={
                **headers, "X-QDev-mTLS-Identity": config.host_identity,
            })
            return response.status_code, response.content

        monkeypatch.setattr(AGENT, "request", request)
        assert intake(inputs)["status"] == "retained"
    assert len(calls) == 1
    assert api.store.operation_events(api.lane) == before
    assert not api.provider.calls
    metadata, archive = storage.read(retained.TRANSACTION)
    assert archive == inputs.archive and metadata["candidate"] == inputs.candidate
