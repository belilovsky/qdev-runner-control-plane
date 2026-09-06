"""Retained journal recovery with synthetic provider/runtime; never deploy proof."""

import json
from copy import deepcopy
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from test_idp_file_runtime import AGENT, NOW, make_associated_pair, make_idp_host, make_native_pair

from qdev_runner import idp_file_runtime as runtime


def setup_recovery(tmp_path, monkeypatch, *, associated=False):
    pair, previous = make_associated_pair() if associated else (make_native_pair(), None)
    host = make_idp_host(pair, tmp_path, monkeypatch, previous=previous)
    adapter, reader, raw, state, profile, lane, candidate, active = host
    job = json.loads(adapter._job)
    invocation = AGENT.IdPNativeInvocation(
        adapter._config, profile, lane, job, json.loads(adapter._candidate)
    )
    binding = json.loads(raw)
    bundle = SimpleNamespace(
        bundle_sha256=binding["bundle_sha256"], manifest_sha256=binding["manifest_sha256"]
    )
    original_reader = reader.observe_installed

    def fresh_observation():
        observed = original_reader()
        observed["observed_at"] = datetime.fromtimestamp(
            AGENT.time.time(), UTC
        ).isoformat().replace("+00:00", "Z")
        return observed

    reader.observe_installed = fresh_observation
    return SimpleNamespace(
        adapter=adapter, reader=reader, raw=raw, state=state, profile=profile,
        invocation=invocation, bundle=bundle, transaction=binding["transaction"],
        active=active, candidate=candidate,
    )


def recover(case):
    return case.invocation._reconcile_controller(case.reader, case.bundle, case.transaction)


@pytest.mark.parametrize("associated", [False, True])
@pytest.mark.parametrize("failure", ["before_complete", "after_ready", "state_write", "completed"])
def test_recovery_after_each_host_boundary_keeps_first_receipt(
    tmp_path, monkeypatch, associated, failure
):
    case = setup_recovery(tmp_path, monkeypatch, associated=associated)
    original_request, original_write = AGENT.request, AGENT.write_state

    def request(*args, **kwargs):
        if args[1] == "POST" and failure == "after_ready":
            raise AGENT.ControllerTransportError("synthetic lost transport")
        return original_request(*args, **kwargs)

    def write(*args, **kwargs):
        if failure == "state_write":
            raise OSError("synthetic state failure")
        return original_write(*args, **kwargs)

    monkeypatch.setattr(AGENT, "request", request)
    monkeypatch.setattr(AGENT, "write_state", write)
    try:
        with case.adapter(case.reader)(case.raw):
            case.state["installed"] = True
            if failure == "before_complete":
                raise OSError("synthetic lost native return")
    except (OSError, AGENT.ControllerOutcomeUnresolved):
        assert failure != "completed"
    monkeypatch.setattr(AGENT, "request", original_request)
    monkeypatch.setattr(AGENT, "write_state", original_write)
    pending = AGENT._pending_operation(case.profile, include_completed=True)
    retained = deepcopy(pending.get("runtime_receipt"))
    # The short dispatch has expired, but a first completion still requires its
    # existing live controller lease. Already-verified outcomes need no renewal.
    at = NOW + (400 if failure in {"before_complete", "after_ready"} else 1000)
    monkeypatch.setattr(AGENT.time, "time", lambda: at)
    assert recover(case)["status"] == "verified"
    assert AGENT.read_state(case.profile.state_path, case.profile) == (case.candidate, case.active)
    assert AGENT._pending_operation(case.profile) is None
    if retained is not None:
        assert case.state["completion"] == retained
    immutable = deepcopy(AGENT._journal_events(case.profile))
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1001)
    assert recover(case)["status"] == "verified"
    assert AGENT._journal_events(case.profile) == immutable


def test_expired_uncompleted_lease_remains_pending_without_submission(tmp_path, monkeypatch):
    case = setup_recovery(tmp_path, monkeypatch)
    with pytest.raises(OSError), case.adapter(case.reader)(case.raw):
        case.state["installed"] = True
        raise OSError("synthetic interruption")
    original = AGENT.request
    def readonly(*args, **kwargs):
        assert args[1] == "GET", "expired lease must not submit completion"
        return original(*args, **kwargs)
    monkeypatch.setattr(AGENT, "request", readonly)
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    with pytest.raises(AGENT.ControllerOutcomeUnresolved):
        recover(case)
    assert AGENT._pending_operation(case.profile) is not None
    assert case.state["completion"] is None
    assert AGENT.read_state(case.profile.state_path, case.profile)[0] == case.active


@pytest.mark.parametrize("fault", ["transaction", "manifest", "bundle", "signature", "no_journal"])
def test_recovery_rejects_foreign_or_unowned_operation(tmp_path, monkeypatch, fault):
    case = setup_recovery(tmp_path, monkeypatch)
    if fault != "no_journal":
        with pytest.raises(OSError), case.adapter(case.reader)(case.raw):
            case.state["installed"] = True
            raise OSError("synthetic interruption")
    if fault == "transaction":
        case.transaction = "foreign-transaction-000"
    elif fault in {"manifest", "bundle"}:
        setattr(case.bundle, fault + "_sha256", "0" * 64)
    elif fault == "signature":
        job = json.loads(case.invocation._job)
        job["dispatch_claim_signature"] = "0" * 64
        case.invocation._job = AGENT._canonical_bytes(job)
    with pytest.raises(AGENT.AgentError):
        recover(case)
    assert case.state["completion"] is None
    assert AGENT.read_state(case.profile.state_path, case.profile)[0] == case.active


@pytest.mark.parametrize("fault", ["digest", "check", "role", "backdated", "terminal_digest"])
def test_reobservation_cannot_normalize_invalid_or_different_evidence(tmp_path, monkeypatch, fault):
    case = setup_recovery(tmp_path, monkeypatch)
    with case.adapter(case.reader)(case.raw):
        case.state["installed"] = True
    old = case.state["completion"]
    new = deepcopy(old)
    proof = new["artifact_provenance"]
    if fault == "digest":
        proof["observation_sha256"] = "0" * 64
    elif fault == "role":
        new["placement"] = "foreign-host"
    else:
        observed = proof["observation"]
        if fault == "check":
            observed["current_checks"]["installed_component_digests"] = "fail"
        elif fault == "backdated":
            observed["observed_at"] = "2000-01-01T00:00:00Z"
        else:
            observed["terminal_event_sha256"] = "0" * 64
        proof["observation_sha256"] = runtime.digest(observed)
    with pytest.raises(AGENT.ControllerOutcomeUnresolved):
        AGENT._idp_reobserved_completion(old, new)


def test_controller_verified_still_requires_unchanged_full_observation(tmp_path, monkeypatch):
    case = setup_recovery(tmp_path, monkeypatch)
    with case.adapter(case.reader)(case.raw):
        case.state["installed"] = True
    original = case.reader.observe_installed

    def drift():
        observed = original()
        observed["runtime_images"][0]["image_digest"] = "sha256:" + "0" * 64
        return observed

    case.reader.observe_installed = drift
    with pytest.raises((runtime.IdPObservationError, AGENT.ControllerOutcomeUnresolved)):
        recover(case)
