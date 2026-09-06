"""Fixed invocation tests use synthetic source and dispatch, never production."""

import json
from dataclasses import replace
from types import SimpleNamespace

import pytest
import test_admin_platform_release_lanes as host_tests
from test_file_apply_authorization import KEY, NOW, fixture
from test_idp_native_bundle import digest, publish

from qdev_runner.idp_native_bundle import VerifiedNativeBundle
from qdev_runner.release_lane import ReleaseLaneError, candidate_evidence, sign_host_dispatch_claim

AGENT = host_tests.AGENT


def make_invocation(tmp_path, monkeypatch):
    _, claim, lane, candidate = fixture.__wrapped__()
    lane = replace(lane, required_readiness=("identity", "native", "public"))
    archive, binding = publish()
    artifact_digest = "sha256:" + binding["archive_sha256"]
    artifact_ref = "qdev/idp-release@" + artifact_digest
    candidate.update(
        artifact_digest=artifact_digest,
        artifact_ref=artifact_ref,
        archive_sha256=binding["archive_sha256"],
        payload_sha256=binding["bundle_sha256"],
    )
    claim.update(
        artifact_digest=artifact_digest,
        artifact_ref=artifact_ref,
        candidate_evidence=candidate_evidence({"candidate_receipt": candidate}, lane),
    )
    profile = replace(
        host_tests._test_profile(tmp_path),
        name="idp",
        lane=lane.name,
        project_id=lane.project_id,
        repository=lane.canonical_repository,
        placement=lane.placement,
        artifact_prefix=lane.artifact_ref_prefix,
        adapter=lane.native_host_adapter,
    )
    config = replace(host_tests._config(profile), dispatch_secret=KEY)
    job = host_tests._signed_job(
        profile,
        config,
        {
            "source_sha": candidate["source_sha"],
            "artifact_digest": artifact_digest,
            "artifact_ref": artifact_ref,
        },
        now=NOW,
        rollback_anchor=claim["rollback_anchor"],
    )
    job.update(
        release_id=claim["release_id"],
        lease_id=claim["lease_id"],
        lease_expires_at=claim["lease_expires_at"],
        candidate_evidence=claim["candidate_evidence"],
        dispatch_claim=claim,
        dispatch_claim_signature=sign_host_dispatch_claim(claim, signing_key=KEY),
    )
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW)
    invocation = AGENT.IdPNativeInvocation(config, profile, lane, job, candidate)
    return SimpleNamespace(
        invocation=invocation,
        archive=archive,
        job=job,
        candidate=candidate,
        binding=binding,
        config=config,
        profile=profile,
        lane=lane,
    )


@pytest.fixture
def invocation(tmp_path, monkeypatch):
    return make_invocation(tmp_path, monkeypatch)


def test_load_after_signature_verification_and_fixed_arguments(invocation, monkeypatch):
    calls = []

    def dispatch(
        root,
        stage,
        target,
        args,
        helpers,
        *,
        controller_adapter,
        controller_recovery=None,
    ):
        calls.append(args.action)
        assert str(root) == "/var/lib/qdev-idp/releases"
        assert stage == root / "native-test-001"
        assert str(target) == "/opt/id.qdev.run"
        assert args.source_sha == invocation.candidate["source_sha"]
        assert args.bundle_digest == invocation.binding["bundle_sha256"]
        assert args.expected_previous == invocation.job["rollback_anchor"]["source_sha"]
        assert isinstance(controller_adapter, AGENT.ControllerIssuedIdPFileApplyAdapter)
        assert controller_recovery is None
        return {"synthetic": True}

    native = SimpleNamespace(
        dispatch=dispatch,
        contract=SimpleNamespace(
            validate_native_response=lambda *args, **kwargs: None,
        ),
    )
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: (native, {}))
    invocation.invocation.invoke(
        invocation.archive,
        action="apply",
        transaction="native-test-001",
        ci="ci-0123456789abcdef.json",
    )
    assert calls == ["apply"]


@pytest.mark.parametrize("fault", ["signature", "attempt", "candidate", "archive", "expiry"])
def test_no_helper_load_before_all_bindings_pass(invocation, monkeypatch, fault):
    if fault == "signature":
        invocation.job["dispatch_claim_signature"] = "bad"
    elif fault == "attempt":
        invocation.job["dispatch_claim"]["attempt"] = 2
    elif fault == "candidate":
        invocation.candidate["artifact_uri"] = "https://other.example.test/archive"
    elif fault == "archive":
        invocation.archive += b"tampered"
    else:
        monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    invocation.invocation = AGENT.IdPNativeInvocation(
        invocation.config, invocation.profile, invocation.lane, invocation.job, invocation.candidate
    )
    monkeypatch.setattr(
        VerifiedNativeBundle, "load", lambda self: pytest.fail("unverified execution")
    )
    with pytest.raises((AGENT.AgentError, ReleaseLaneError)):
        invocation.invocation.invoke(
            invocation.archive,
            action="apply",
            transaction="native-test-001",
            ci="ci-0123456789abcdef.json",
        )


@pytest.mark.parametrize("action", ["inspect", "reconcile", "observe"])
def test_historical_signature_does_not_create_live_adapter(invocation, monkeypatch, action):
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)

    def dispatch(*args, **kwargs):
        assert kwargs["controller_adapter"] is None
        assert callable(kwargs.get("controller_recovery")) == (action == "reconcile")
        return {"synthetic": True}

    native = SimpleNamespace(
        dispatch=dispatch,
        contract=SimpleNamespace(
            validate_native_response=lambda *args, **kwargs: None,
        ),
    )
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: (native, {}))
    invocation.invocation.invoke(invocation.archive, action=action, transaction="native-test-001")


@pytest.mark.parametrize("action", ["stage", "prepare", "rollback", "preflight"])
def test_does_not_expand_action_scope(invocation, action):
    with pytest.raises(AGENT.AgentError):
        invocation.invocation.invoke(
            invocation.archive, action=action, transaction="native-test-001"
        )


def test_input_mutation_does_not_change_verified_snapshot(invocation):
    invocation.candidate.clear()
    invocation.job.clear()
    job, candidate = invocation.invocation._verified_job(live=True)
    assert job["source_sha"] == "a" * 40
    assert candidate["archive_sha256"] == digest(invocation.archive)


def test_unknown_native_outcome_is_redacted_and_not_retried(invocation, monkeypatch):
    calls = []

    def dispatch(*args, **kwargs):
        calls.append(1)
        raise RuntimeError("synthetic-private-value")

    monkeypatch.setattr(
        VerifiedNativeBundle, "load", lambda self: (SimpleNamespace(dispatch=dispatch), {})
    )
    with pytest.raises(AGENT.AgentError, match="retained-state") as caught:
        invocation.invocation.invoke(
            invocation.archive, action="inspect", transaction="native-test-001"
        )
    assert "synthetic-private-value" not in str(caught.value)
    assert calls == [1]


def test_invalid_response_requires_reconciliation(invocation, monkeypatch):
    def reject(*args, **kwargs):
        raise ValueError("synthetic-private-value")

    native = SimpleNamespace(
        dispatch=lambda *args, **kwargs: {"wrong": True},
        contract=SimpleNamespace(validate_native_response=reject),
    )
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: (native, {}))
    with pytest.raises(AGENT.AgentError, match="retained-state"):
        invocation.invocation.invoke(
            invocation.archive, action="inspect", transaction="native-test-001"
        )


def test_historical_claim_is_still_signature_checked(invocation, monkeypatch):
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    job = json.loads(invocation.invocation._job)
    job["dispatch_claim"]["issued_at"] += 1
    invocation.invocation._job = AGENT._canonical_bytes(job)
    with pytest.raises(AGENT.AgentError):
        invocation.invocation.invoke(
            invocation.archive, action="inspect", transaction="native-test-001"
        )


def test_expiry_during_archive_validation_cannot_execute_helper(invocation, monkeypatch):
    import qdev_runner.idp_native_bundle as loader

    verify = loader.verify_native_archive

    def slow_verify(*args, **kwargs):
        result = verify(*args, **kwargs)
        monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
        return result

    monkeypatch.setattr(loader, "verify_native_archive", slow_verify)
    monkeypatch.setattr(VerifiedNativeBundle, "load", lambda self: pytest.fail("expired execution"))
    with pytest.raises(AGENT.AgentError):
        invocation.invocation.invoke(
            invocation.archive,
            action="apply",
            transaction="native-test-001",
            ci="ci-0123456789abcdef.json",
        )


@pytest.mark.parametrize("value", [None, [], 1, "bad"])
def test_malformed_retained_dispatch_is_rejected(invocation, value):
    invocation.job["dispatch_claim"] = value
    invocation.invocation._job = AGENT._canonical_bytes(invocation.job)
    with pytest.raises(AGENT.AgentError):
        invocation.invocation.invoke(
            invocation.archive, action="inspect", transaction="native-test-001"
        )
