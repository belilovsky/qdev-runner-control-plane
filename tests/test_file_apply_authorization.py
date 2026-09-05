"""Binding adapter tests use a fake native transaction, never live admission."""

import copy
from contextlib import contextmanager, suppress
from datetime import UTC, datetime

import pytest

from qdev_runner.file_apply_authorization import (
    FileApplyBridge,
    authorization_payload,
    canonical_bytes,
)
from qdev_runner.release_lane import ReleaseLane, ReleaseLaneError, sign_host_dispatch_claim

KEY = b"file-apply-fixture-key-not-a-real-secret"
NOW = 1_788_600_000
SHA = "a" * 40


@pytest.fixture
def fixture():
    ci = {
        "source_sha": SHA,
        "status": "completed",
        "conclusion": "success",
        "profile": "qdev-ci-docker",
        "run_id": 1,
        "job_id": 2,
        "attempt": 1,
    }
    artifact = {
        "schema_version": "qdev-idp-ci-bundle-v1",
        "repository": "belilovsky/id-qdev-run",
        "source_sha": SHA,
        "bundle_sha256": "b" * 64,
        "manifest_sha256": "c" * 64,
        "artifact_sha256": "d" * 64,
        "artifact_name": "idp-release",
        "storage_key": f"belilovsky/id-qdev-run/{SHA}/2/idp-release.tar.gz",
        "profile": "qdev-ci-docker",
        "run_id": 1,
        "job_id": 2,
        "attempt": 1,
    }
    binding = {
        "schema_version": "qdev-idp-controller-apply-binding-v1",
        "repository": "belilovsky/id-qdev-run",
        "source_sha": SHA,
        "transaction": "native-transaction-001",
        "expected_previous_sha": "e" * 40,
        "bundle_sha256": "b" * 64,
        "manifest_sha256": "c" * 64,
        "snapshot_sha256": "f" * 64,
        "ci_observation": {
            "path": "ci-0123456789abcdef.json",
            "sha256": "1" * 64,
            "observed_at": datetime.fromtimestamp(NOW, UTC).isoformat(),
            "quality": ci,
            "runner_contract": {**ci, "profile": "qdev-ci", "run_id": 3, "job_id": 4},
            "artifact": artifact,
        },
    }
    lane = ReleaseLane(
        name="qdev-release-idp",
        project_id="id-qdev-run",
        placement="idp-host",
        client_mtls_identity="operator",
        host_agent_mtls_identity="qdev-host-agent:idp-host",
        minimum_free_gib=1,
        heartbeat_ttl_seconds=60,
        artifact_repository="idp-release",
        canonical_repository="belilovsky/id-qdev-run",
        artifact_ref_prefix="qdev/idp-release",
        native_host_adapter="idp-file-v1",
        runtime_endpoints=(),
        rollback_reference="retained",
        required_readiness=(),
    )
    claim = {
        "schema": "qdev-controller-host-dispatch-claim-v2",
        "repository": binding["repository"],
        "workflow": "ci.yml",
        "job": "quality",
        "exact_sha": SHA,
        "run_id": 1,
        "job_id": 2,
        "attempt": 1,
        "runner_profile": "qdev-ci-docker",
        "host_identity": lane.host_agent_mtls_identity,
        "release_id": "release-operation-001",
        "release_lane": lane.name,
        "project_id": lane.project_id,
        "placement": lane.placement,
        "artifact_digest": "sha256:" + "d" * 64,
        "artifact_ref": "qdev/idp-release@sha256:" + "d" * 64,
        "lease_id": "lease-operation-0001",
        "fence": "f" * 24,
        "lease_expires_at": NOW + 600,
        "rollback_anchor": {
            "source_sha": "e" * 40,
            "artifact_digest": "sha256:" + "e" * 64,
            "artifact_ref": "qdev/idp-release@sha256:" + "e" * 64,
        },
        "issued_at": NOW,
        "expires_at": NOW + 120,
        "nonce": "n" * 32,
    }
    return binding, claim, lane


class FakeNativeTransaction:
    """In-memory test double, explicitly NOT the installed replay/lease ledger."""

    def __init__(self):
        self.events = []
        self.consumed = False
        self.current = True

    def assert_current(self):
        self.events.append("live_check")
        if not self.current:
            raise ReleaseLaneError("lease revoked")

    @contextmanager
    def __call__(self, claim):
        if self.consumed:
            raise ReleaseLaneError("replay")
        self.consumed = True
        self.events.extend(["dispatch_accepted", "release_started"])
        try:
            yield self
        finally:
            self.events.append("exit")


def bridge(fixture, transaction=None, clock=lambda: NOW):
    binding, claim, lane = fixture
    raw = canonical_bytes(binding)
    envelope = authorization_payload(raw, claim)
    native = transaction if transaction is not None else FakeNativeTransaction()
    result = FileApplyBridge(
        lane=lane,
        dispatch_claim=claim,
        dispatch_signature=sign_host_dispatch_claim(claim, signing_key=KEY),
        authorization=envelope,
        authorization_signature=sign_host_dispatch_claim(envelope, signing_key=KEY),
        signing_key=KEY,
        dispatch_transaction=native,
        clock=clock,
    )
    return result, raw, native


def test_consumes_before_apply_keeps_context_and_invalidates_guard(fixture):
    authorize, raw, native = bridge(fixture)
    with authorize(raw) as guard:
        assert native.events[:2] == ["dispatch_accepted", "release_started"]
        guard.assert_current()
        assert "exit" not in native.events
    assert native.events[-1] == "exit"
    with pytest.raises(ReleaseLaneError, match="outside"):
        guard.assert_current()
    with pytest.raises(ReleaseLaneError, match="replay"), authorize(raw):
        pytest.fail("replay reached apply")


@pytest.mark.parametrize(
    "field",
    [
        "snapshot_sha256",
        "transaction",
        "expected_previous_sha",
        "bundle_sha256",
    ],
)
def test_binding_tamper_before_consume(fixture, field):
    authorize, _, native = bridge(fixture)
    binding = copy.deepcopy(fixture[0])
    binding[field] = "0" * len(binding[field])
    with pytest.raises(ReleaseLaneError), authorize(canonical_bytes(binding)):
        pytest.fail("tamper reached apply")
    assert not native.consumed


@pytest.mark.parametrize(
    "target,field,value",
    [
        ("quality", "attempt", True),
        ("quality", "conclusion", "skipped"),
        ("quality", "profile", "qdev-ci"),
        ("runner_contract", "source_sha", "b" * 40),
        ("runner_contract", "conclusion", "failure"),
        ("runner_contract", "profile", "unknown"),
        ("artifact", "job_id", 100),
        ("artifact", "storage_key", "../other"),
    ],
)
def test_invalid_even_when_resigned(fixture, target, field, value):
    fixture[0]["ci_observation"][target][field] = value
    authorize, raw, native = bridge(fixture)
    with pytest.raises(ReleaseLaneError), authorize(raw):
        pytest.fail("invalid CI reached apply")
    assert not native.consumed


@pytest.mark.parametrize(
    "field,value",
    [
        ("exact_sha", "b" * 40),
        ("repository", "other/repo"),
        ("host_identity", "other"),
        ("run_id", 22),
        ("attempt", 2),
        ("expires_at", NOW - 1),
        ("issued_at", NOW + 100),
        ("fence", "invalid"),
        ("nonce", "short"),
        ("extra", True),
    ],
)
def test_wrong_dispatch_even_when_resigned(fixture, field, value):
    fixture[1][field] = value
    authorize, raw, native = bridge(fixture)
    with pytest.raises(ReleaseLaneError), authorize(raw):
        pytest.fail("wrong dispatch reached apply")
    assert not native.consumed


def test_no_unsigned_envelope_or_dispatch(fixture):
    for field in ("_authorization_signature", "_dispatch_signature"):
        authorize, raw, native = bridge(fixture)
        setattr(authorize, field, "0" * 64)
        with pytest.raises(ReleaseLaneError), authorize(raw):
            pytest.fail("bad signature reached apply")
        assert not native.consumed


@pytest.mark.parametrize("transform", [lambda raw: raw[:-1], lambda raw: raw + b"\n"])
def test_canonical_bytes_only(fixture, transform):
    authorize, raw, native = bridge(fixture)
    with pytest.raises(ReleaseLaneError), authorize(transform(raw)):
        pytest.fail("noncanonical input reached apply")
    assert not native.consumed


def test_guard_rechecks_expiry_and_revocation(fixture):
    clock = [NOW]
    authorize, raw, native = bridge(fixture, clock=lambda: clock[0])
    with authorize(raw) as guard:
        native.current = False
        with pytest.raises(ReleaseLaneError, match="revoked"):
            guard.assert_current()
        native.current = True
        clock[0] += 121
        with pytest.raises(ReleaseLaneError, match="lifetime"):
            guard.assert_current()


def test_apply_failure_never_replayed(fixture):
    authorize, raw, native = bridge(fixture)
    with pytest.raises(RuntimeError, match="apply failed"), authorize(raw):
        raise RuntimeError("apply failed")
    assert native.events[-1] == "exit"
    with pytest.raises(ReleaseLaneError, match="replay"), authorize(raw):
        pytest.fail("failed apply retried")


def test_broken_native_context_cannot_suppress_apply_error(fixture):
    @contextmanager
    def suppressing(claim):
        with suppress(RuntimeError):
            yield FakeNativeTransaction()

    authorize, raw, _ = bridge(fixture, transaction=suppressing)
    with pytest.raises(RuntimeError, match="apply failed"), authorize(raw):
        raise RuntimeError("apply failed")
