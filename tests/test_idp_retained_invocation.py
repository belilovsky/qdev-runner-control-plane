"""Restart boundary verifies retained bytes before loading native helpers."""

import json
from types import SimpleNamespace

import pytest
import test_idp_retained_dispatch as retention_tests
from test_file_apply_authorization import NOW
from test_idp_native_invocation import AGENT, make_invocation

from qdev_runner import idp_retained_dispatch as storage
from qdev_runner.idp_native_bundle import VerifiedNativeBundle

TRANSACTION = retention_tests.TRANSACTION


@pytest.fixture
def retained_store(monkeypatch):
    yield from retention_tests.store.__wrapped__(monkeypatch)


@pytest.fixture
def invocation(tmp_path, monkeypatch, retained_store):
    return make_invocation(tmp_path, monkeypatch)


def retain(invocation):
    return invocation.invocation.retain(invocation.archive, transaction=TRANSACTION)


def invoke(invocation, action="inspect", **kwargs):
    return AGENT.invoke_retained_idp(
        invocation.config,
        invocation.profile,
        invocation.lane,
        transaction=TRANSACTION,
        action=action,
        **kwargs,
    )


def test_retention_never_loads_code_and_is_not_acceptance(invocation, monkeypatch):
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: pytest.fail("helper loaded"))
    result = retain(invocation)
    assert result["status"] == "retained"
    assert result["artifact_digest"] == invocation.job["artifact_digest"]
    assert set(result) == {"schema", "status", "artifact_digest", "source_sha", "transaction"}
    metadata, archive = storage.read(TRANSACTION)
    assert metadata["job"] == invocation.job
    assert metadata["candidate"] == invocation.candidate
    assert archive == invocation.archive


@pytest.mark.parametrize("fault", ["signature", "attempt", "candidate", "archive", "expiry"])
def test_unverified_inputs_cannot_be_published(invocation, monkeypatch, fault):
    if fault == "signature":
        invocation.job["dispatch_claim_signature"] = "synthetic-private-value"
    elif fault == "attempt":
        invocation.job["dispatch_claim"]["attempt"] += 1
    elif fault == "candidate":
        invocation.candidate["artifact_uri"] = "https://synthetic-private-value.test/archive"
    elif fault == "archive":
        invocation.archive += b"synthetic-private-value"
    else:
        monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    invocation.invocation = AGENT.IdPNativeInvocation(
        invocation.config,
        invocation.profile,
        invocation.lane,
        invocation.job,
        invocation.candidate,
    )
    monkeypatch.setattr(storage, "retain", lambda *a: pytest.fail("unverified write"))
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: pytest.fail("unverified load"))
    with pytest.raises(AGENT.AgentError) as caught:
        retain(invocation)
    assert "synthetic-private-value" not in str(caught.value)
    assert not storage.ROOT.exists()


def test_expired_exact_published_retry_finishes_durability_without_mutation(
    invocation,
    monkeypatch,
):
    original = retain(invocation)
    snapshot = storage.read(TRANSACTION)
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    monkeypatch.setattr(storage, "_write_file", lambda *a: pytest.fail("immutable rewrite"))
    assert retain(invocation) == original
    assert storage.read(TRANSACTION) == snapshot


def test_final_sync_failure_is_recoverable_without_rebuilding(invocation, monkeypatch):
    original = storage.os.rename

    def interrupted(*args, **kwargs):
        original(*args, **kwargs)
        raise OSError("synthetic-private-value")

    with monkeypatch.context() as patch:
        patch.setattr(storage.os, "rename", interrupted)
        with pytest.raises(AGENT.AgentError):
            retain(invocation)
    assert storage.read(TRANSACTION) is not None
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    assert retain(invocation)["status"] == "retained"


@pytest.mark.parametrize("published", [False, True])
def test_incomplete_intake_inspect_never_executes_helper(invocation, monkeypatch, published):
    if published:
        storage.ROOT.mkdir(mode=0o700)
        (storage.ROOT / ".incomplete.pending").mkdir(mode=0o700)
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: pytest.fail("helper loaded"))
    assert invoke(invocation) == {
        "schema": storage.SCHEMA,
        "transaction": TRANSACTION,
        "status": "inputs_not_published",
    }
    for action in ("reconcile", "observe", "apply", "rollback"):
        with pytest.raises(AGENT.AgentError):
            invoke(invocation, action)


@pytest.mark.parametrize("fault", ["signature", "candidate", "archive", "corrupt", "extra"])
def test_restart_revalidates_full_retained_chain(invocation, monkeypatch, fault):
    retain(invocation)
    path = storage.ROOT / TRANSACTION / "dispatch.json"
    value = json.loads(path.read_bytes())
    if fault == "signature":
        value["job"]["dispatch_claim_signature"] = "synthetic-private-value"
    elif fault == "candidate":
        value["candidate"]["attempt"] += 1
    elif fault == "archive":
        archive = storage.ROOT / TRANSACTION / "artifact.tar.gz"
        archive.write_bytes(archive.read_bytes() + b"synthetic-private-value")
        # Matching this outer metadata digest still cannot alter the signed job.
        value["archive_sha256"] = storage.hashlib.sha256(archive.read_bytes()).hexdigest()
    elif fault == "extra":
        value["job"]["target"] = "/synthetic-private-value"
    path.write_bytes(b"invalid" if fault == "corrupt" else storage._canonical(value))
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: pytest.fail("unverified load"))
    with pytest.raises(AGENT.AgentError) as caught:
        invoke(invocation)
    assert "synthetic-private-value" not in str(caught.value)


@pytest.mark.parametrize("action", ["inspect", "reconcile", "observe", "apply"])
def test_restart_releases_intake_lock_before_fixed_native_invocation(
    invocation,
    monkeypatch,
    action,
):
    retain(invocation)
    calls = []

    def dispatch(root, stage, target, args, helpers, **kwargs):
        with storage._root(create=False) as descriptor, storage._lock(descriptor):
            calls.append(args.action)
        assert root == AGENT.IdPNativeInvocation.STATE_ROOT
        assert target == AGENT.IdPNativeInvocation.TARGET
        assert stage == root / TRANSACTION
        assert (kwargs["controller_adapter"] is not None) == (action == "apply")
        assert callable(kwargs.get("controller_recovery")) == (action == "reconcile")
        return {"synthetic": True}

    native = SimpleNamespace(
        dispatch=dispatch,
        contract=SimpleNamespace(validate_native_response=lambda *a, **k: None),
    )
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: (native, {}))
    # Invocation reconstructs from disk, not the original object's mutable args.
    invocation.job.clear()
    invocation.candidate.clear()
    invoke(invocation, action, ci="ci-0123456789abcdef.json" if action == "apply" else "none")
    assert calls == [action]


def test_retained_expired_dispatch_cannot_apply(invocation, monkeypatch):
    retain(invocation)
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: pytest.fail("expired load"))
    with pytest.raises(AGENT.AgentError):
        invoke(invocation, "apply", ci="ci-0123456789abcdef.json")


def test_unknown_native_result_requires_inspection_not_retry(invocation, monkeypatch):
    retain(invocation)
    calls = []

    def fail(*args, **kwargs):
        calls.append(1)
        raise RuntimeError("synthetic-private-value")

    monkeypatch.setattr(
        VerifiedNativeBundle,
        "load",
        lambda self: (SimpleNamespace(dispatch=fail), {}),
    )
    with pytest.raises(AGENT.AgentError) as caught:
        invoke(invocation)
    assert calls == [1]
    assert "synthetic-private-value" not in str(caught.value)
    assert storage.read(TRANSACTION) is not None
