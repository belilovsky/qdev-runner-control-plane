"""Real local issuer/journal/host bridge; synthetic CI and native runtime only."""

import fcntl
import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
from test_file_apply_authorization import KEY, NOW
from test_idp_file_issuer import make_issuer, mutate_job
from test_idp_file_runtime import AGENT, make_idp_host, rehash

from qdev_runner.file_apply_authorization import canonical_bytes
from qdev_runner.release_lane import ReleaseLaneError

TRANSPORT = AGENT.request


def make_host(tmp_path, monkeypatch, *, associated=False):
    controller_root = tmp_path / "controller"
    controller_root.mkdir(mode=0o700)
    data = make_issuer(controller_root, associated=associated)
    host_root = tmp_path / "host"
    host_root.mkdir(mode=0o700)
    old, reader, binding, state, profile, lane, _, _ = make_idp_host(
        data.pair, host_root, monkeypatch, previous=data.previous
    )
    job = json.loads(old._job)
    mutate_job(
        data,
        lambda current: current.update(
            release_id=job["release_id"],
            lease_id=job["lease_id"],
            dispatch_claim=job["dispatch_claim"],
            dispatch_claim_signature=job["dispatch_claim_signature"],
        ),
    )
    adapter = AGENT.ControllerIssuedIdPFileApplyAdapter(old._config, profile, lane, job)
    base_request = AGENT.request
    result = SimpleNamespace(
        data=data,
        reader=reader,
        binding=binding,
        state=state,
        profile=profile,
        lane=lane,
        job=job,
        config=old._config,
        adapter=adapter,
        requests=[],
        change_response=lambda response: response,
        after_issue=lambda: None,
    )

    def request(config, method, path, payload=None, *, headers=None):
        if path.endswith("/idp-file-authorization"):
            # Native still holds its own global lock; host lock is deliberately
            # free during bounded controller/provider IO (no second CLI).
            with AGENT._acquire_lock(profile.lock_path) as unlocked:
                fcntl.flock(unlocked.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            assert method == "POST"
            assert headers == AGENT._controller_headers(job["lease_id"], job["fence"])
            assert payload == canonical_bytes(data.native)
            assert not AGENT._pending_operation(profile)
            result.requests.append(payload)
            receipt = data.store.authorize_idp_file_apply(
                lane,
                job["release_id"],
                payload,
                lease_id=job["lease_id"],
                fence=job["fence"],
                signing_key=KEY,
                github=data.provider,
                artifact_root=data.artifact_root,
                clock=lambda: NOW,
            )
            result.after_issue()
            return result.change_response((200, canonical_bytes(receipt)))
        return base_request(config, method, path, payload, headers=headers)

    monkeypatch.setattr(AGENT, "request", request)
    return result


@pytest.fixture
def host(tmp_path, monkeypatch):
    return make_host(tmp_path, monkeypatch)


@pytest.mark.parametrize("associated", [False, True])
def test_real_issuer_exact_bytes_native_reads_and_durable_completion(
    tmp_path, monkeypatch, associated
):
    host = make_host(tmp_path, monkeypatch, associated=associated)
    with host.adapter(host.reader)(host.binding) as guard:
        guard.assert_current()
        assert host.state["reads"] == ["prepared", "prepared"]
        host.state["installed"] = True
    assert host.state["reads"] == ["prepared", "prepared", "installed", "installed"]
    assert host.state["controller"] == "verified"
    assert host.state["completion"] is not None
    assert len(host.requests) == 1
    assert not AGENT._pending_operation(host.profile)
    assert host.data.store.operation_events(host.lane)[-1]["phase"] == "idp_file_authorized"
    with pytest.raises(AGENT.AgentError, match="consumed"), host.adapter(host.reader)(host.binding):
        pytest.fail("dispatch replay")
    assert len(host.requests) == 1


def test_unknown_apply_requires_reconciliation_before_new_issuance(host):
    with (
        pytest.raises(RuntimeError, match="synthetic process loss"),
        host.adapter(host.reader)(host.binding),
    ):
        raise RuntimeError("synthetic process loss")
    assert AGENT._pending_operation(host.profile)
    with (
        pytest.raises(AGENT.ControllerOutcomeUnresolved, match="reconciliation"),
        host.adapter(host.reader)(host.binding),
    ):
        pytest.fail("unreconciled apply")
    assert len(host.requests) == 1


@pytest.mark.parametrize("status", [0, 201, 403, 409, 500])
def test_unconfirmed_issuer_response_does_not_consume_dispatch(host, status):
    host.change_response = lambda response: (status, b"secret-provider-response")
    with (
        pytest.raises(AGENT.ControllerTransportError) as error,
        host.adapter(host.reader)(host.binding),
    ):
        pytest.fail("unconfirmed apply")
    assert "secret" not in str(error.value)
    assert not AGENT._pending_operation(host.profile)
    assert host.state["reads"] == ["prepared"]
    assert len(host.requests) == 1  # never retries automatically
    host.change_response = lambda response: response
    with host.adapter(host.reader)(host.binding):
        host.state["installed"] = True
    assert len(host.requests) == 2  # fresh authorization, unchanged lease/nonce


@pytest.mark.parametrize(
    "mutation",
    [
        lambda x: x.update(schema="untrusted"),
        lambda x: x.update(acceptance="accepted"),
        lambda x: x.update(extra="secret"),
        lambda x: x.update(journal_seq=True),
        lambda x: x.update(journal_seq=0),
        lambda x: x.update(journal_event_sha256="unknown"),
        lambda x: x.update(dispatch_claim_signature="replaced"),
        lambda x: x["dispatch_claim"].update(fence="e" * 24),
        lambda x: x.update(authorization=[]),
        lambda x: x.update(candidate_receipt=None),
    ],
)
def test_strict_response_rejects_unbound_envelope_before_host_journal(host, mutation):
    def changed(response):
        value = json.loads(response[1])
        mutation(value)
        return 200, canonical_bytes(value)

    host.change_response = changed
    with (
        pytest.raises(AGENT.AgentError, match="invalid controller"),
        host.adapter(host.reader)(host.binding),
    ):
        pytest.fail("bad envelope")
    assert not AGENT._pending_operation(host.profile)


@pytest.mark.parametrize(
    "body",
    [
        b"secret-response",
        b"[]",
        b"{}",
        b'{"secret":1,"secret":2}',
        b"x" * (2 * 1024 * 1024 + 1),
        b"[" * 2000,
    ],
    ids=["non-json", "array", "empty", "duplicate", "oversize", "too-deep"],
)
def test_malformed_response_is_bounded_duplicate_safe_and_redacted(host, body):
    host.change_response = lambda response: (200, body)
    with (
        pytest.raises(AGENT.AgentError, match="invalid controller") as error,
        host.adapter(host.reader)(host.binding),
    ):
        pytest.fail("bad response")
    assert "secret" not in str(error.value)
    assert not AGENT._pending_operation(host.profile)


@pytest.mark.parametrize("field", ["authorization_signature", "authorization", "candidate_receipt"])
def test_valid_transport_does_not_replace_signature_and_candidate_verification(host, field):
    def changed(response):
        value = json.loads(response[1])
        if field == "authorization_signature":
            value[field] = "0" * 64
        elif field == "authorization":
            value[field]["binding_sha256"] = "0" * 64
        else:
            value[field]["source_sha"] = "b" * 40
        return 200, canonical_bytes(value)

    host.change_response = changed
    with (
        pytest.raises((ReleaseLaneError, AGENT.AgentError)),
        host.adapter(host.reader)(host.binding),
    ):
        pytest.fail("unverified signature/candidate")
    assert not AGENT._pending_operation(host.profile)


@pytest.mark.parametrize("phase", ["lease", "controller", "native", "host-state"])
def test_network_gap_rechecks_every_mutable_boundary(host, monkeypatch, phase):
    def changed():
        if phase == "lease":
            monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
        elif phase == "controller":
            host.state["controller"] = "rolled_back"
        elif phase == "native":
            original = host.reader.observe_prepared

            def drift():
                value = original()
                value["binding"]["expected_previous_sha"] = "a" * 40
                return value

            host.reader.observe_prepared = drift
        else:
            active, rollback = AGENT.read_state(host.profile.state_path, host.profile)
            active["source_sha"] = "a" * 40
            AGENT.write_state(host.profile.state_path, active, rollback)

    host.after_issue = changed
    with (
        pytest.raises((ReleaseLaneError, AGENT.AgentError, ValueError)),
        host.adapter(host.reader)(host.binding),
    ):
        pytest.fail("changed authority/runtime")
    assert not AGENT._pending_operation(host.profile)


def test_legacy_prepared_observation_denied_before_issuance(host):
    original = host.reader.observe_prepared

    def legacy():
        value = original()
        value["schema_version"] = "qdev-idp-prepared-observation-v1"
        value.pop("rollback_snapshot")
        rehash(value)
        return value

    host.reader.observe_prepared = legacy
    with pytest.raises(ReleaseLaneError), host.adapter(host.reader)(host.binding):
        pytest.fail("legacy rollback proof")
    assert not host.requests


def test_changed_fence_denied_before_issuer_or_journal(host, monkeypatch):
    original = AGENT.request

    def lost(config, method, path, payload=None, *, headers=None):
        if method == "GET":
            return 409, b"secret-fence-detail"
        return original(config, method, path, payload, headers=headers)

    monkeypatch.setattr(AGENT, "request", lost)
    with pytest.raises(AGENT.AgentError), host.adapter(host.reader)(host.binding):
        pytest.fail("lost lease")
    assert not host.requests
    assert not AGENT._pending_operation(host.profile)


def test_fence_taken_after_issuance_denies_even_a_valid_signed_envelope(host, monkeypatch):
    original = AGENT.request

    def lost(config, method, path, payload=None, *, headers=None):
        if method == "GET" and host.requests:
            return 409, b"secret-current-lease"
        return original(config, method, path, payload, headers=headers)

    monkeypatch.setattr(AGENT, "request", lost)
    with pytest.raises(AGENT.AgentError), host.adapter(host.reader)(host.binding):
        pytest.fail("stale signed authorization")
    assert len(host.requests) == 1
    assert not AGENT._pending_operation(host.profile)


def test_lost_response_after_durable_issue_does_not_start_local_apply(host):
    def lost(response):
        raise AGENT.ControllerTransportError("controller request outcome is unknown")

    host.change_response = lost
    with pytest.raises(AGENT.ControllerTransportError), host.adapter(host.reader)(host.binding):
        pytest.fail("lost issuer response")
    assert len(host.requests) == 1
    assert host.data.store.operation_events(host.lane)[-1]["phase"] == "idp_file_authorized"
    assert not AGENT._pending_operation(host.profile)
    host.change_response = lambda response: response
    with host.adapter(host.reader)(host.binding):
        host.state["installed"] = True
    assert len(host.requests) == 2


def test_new_pending_operation_during_issuance_requires_reconciliation(host):
    def pending():
        active, rollback = AGENT.read_state(host.profile.state_path, host.profile)
        context = AGENT._operation_context(
            host.profile,
            {key: host.job[key] for key in ("source_sha", "artifact_digest", "artifact_ref")},
            active,
            rollback,
            host.job["dispatch_claim"]["nonce"],
            host.job["lease_expires_at"],
            host.job["rollback_anchor"],
        )
        with AGENT._acquire_lock(host.profile.lock_path) as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            AGENT._write_operation(
                host.profile,
                "dispatch_accepted",
                host.job["release_id"],
                host.job["lease_id"],
                host.job["fence"],
                context,
            )

    host.after_issue = pending
    with pytest.raises(AGENT.ControllerOutcomeUnresolved), host.adapter(host.reader)(host.binding):
        pytest.fail("concurrent unknown apply")
    assert len(host.requests) == 1
    assert host.state["reads"] == ["prepared"]
    assert AGENT._pending_operation(host.profile)


def test_native_host_lock_conflict_never_reaches_issuer(host):
    with AGENT._acquire_lock(host.profile.lock_path) as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        with (
            pytest.raises(AGENT.AgentError, match="lock is already held"),
            host.adapter(host.reader)(host.binding),
        ):
            pytest.fail("concurrent host operation")
    assert not host.requests


def test_fixed_scope_and_reader_are_not_caller_selected(host):
    with pytest.raises(AGENT.AgentError, match="fixed native lane"):
        AGENT.ControllerIssuedIdPFileApplyAdapter(
            host.config, replace(host.profile, project_id="other"), host.lane, host.job
        )
    with pytest.raises(AGENT.AgentError, match="locked native"):
        host.adapter({"observe_prepared": "pass", "observe_installed": "pass"})


def test_transport_preserves_exact_canonical_native_bytes_and_redacts_failure(host, monkeypatch):
    calls = []

    def run(command, *, payload=None):
        calls.append((command, payload))
        return b"{}\n200"

    monkeypatch.setattr(AGENT, "_run", run)
    path = (
        f"/internal/v1/release-hosts/{host.profile.placement}/jobs/"
        f"{host.job['release_id']}/idp-file-authorization"
    )
    headers = AGENT._controller_headers(host.job["lease_id"], host.job["fence"])
    body = canonical_bytes(host.data.native)
    assert TRANSPORT(host.config, "POST", path, body, headers=headers) == (200, b"{}")
    assert calls[0][1] == body
    assert calls[0][1].endswith(b"\n")
    assert "--data-binary" in calls[0][0] and "@-" in calls[0][0]
    for method, bad_path, bad_body, bad_headers in (
        ("GET", path, body, headers),
        ("POST", path + "/extra", body, headers),
        ("POST", path, body[:-1], headers),
        ("POST", path, body, None),
        ("POST", path, b"x" * (2 * 1024 * 1024) + b"\n", headers),
    ):
        with pytest.raises(AGENT.AgentError, match="fixed IdP"):
            TRANSPORT(host.config, method, bad_path, bad_body, headers=bad_headers)
    assert len(calls) == 1
    # Existing dictionary request serialization must not silently gain a LF.
    TRANSPORT(host.config, "POST", "/internal/legacy", {"a": 1})
    assert calls[-1][1] == b'{"a":1}'
