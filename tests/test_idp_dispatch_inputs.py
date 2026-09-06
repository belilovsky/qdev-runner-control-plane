"""Full candidate readback authenticates existing admission, never allocates it."""

import json
from dataclasses import replace

import pytest
from fastapi.testclient import TestClient
from test_broker_idp_authorization import api as api_fixture
from test_file_apply_authorization import KEY, NOW
from test_idp_file_issuer import mutate_job

from qdev_runner.release_lane import (
    ReleaseLaneError,
    ReleaseStore,
    candidate_evidence,
    sign_host_dispatch_claim,
)

api = api_fixture


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    original = ReleaseStore.idp_dispatch_inputs

    def fixed(self, *args, **kwargs):
        return original(self, *args, **kwargs, now=NOW)

    monkeypatch.setattr(ReleaseStore, "idp_dispatch_inputs", fixed)


def get(api, *, headers=None, factory=None, url=None):
    with TestClient((factory or api.factory)()) as client:
        return client.get(
            url or api.url.replace("idp-file-authorization", "idp-inputs"),
            headers=api.headers if headers is None else headers,
        )


def test_read_full_signed_candidate_does_not_admit_or_collect(api, monkeypatch):
    before = api.store.operation_events(api.lane)
    snapshot = api.store._job_path(api.lane.name).read_bytes()
    monkeypatch.setattr(ReleaseStore, "next_job", lambda *a, **k: pytest.fail("new dispatch"))
    first = get(api)
    assert first.status_code == 200, first.text
    value = first.json()
    assert value == {
        "schema": "qdev-controller-idp-dispatch-inputs-v1",
        "status": "authenticated_inputs",
        "acceptance": "not_run",
        "candidate_receipt": api.candidate,
        "job": {
            "schema": "qdev-release-host-agent-job-v1",
            "source_sha": api.candidate["source_sha"],
            **{
                key: api.claim[key]
                for key in (
                    "release_id",
                    "release_lane",
                    "project_id",
                    "placement",
                    "artifact_digest",
                    "artifact_ref",
                    "lease_id",
                    "fence",
                    "lease_expires_at",
                    "rollback_anchor",
                    "candidate_evidence",
                )
            },
            "dispatch_claim": api.claim,
            "dispatch_claim_signature": sign_host_dispatch_claim(api.claim, signing_key=KEY),
        },
    }
    assert get(api).content == first.content
    assert api.store.operation_events(api.lane) == before
    assert api.store._job_path(api.lane.name).read_bytes() == snapshot
    assert not api.provider.calls
    assert KEY not in first.content


@pytest.mark.parametrize("identity", [None, "operator", "qdev-host-agent:other"])
def test_unauthenticated_never_reads_private_state_or_key(api, monkeypatch, identity):
    headers = dict(api.headers)
    headers.pop("X-QDev-mTLS-Identity")
    if identity is not None:
        headers["X-QDev-mTLS-Identity"] = identity
    api.key_file.unlink()
    monkeypatch.setattr(ReleaseStore, "__init__", lambda *a: pytest.fail("private store read"))
    assert get(api, headers=headers).status_code == 403


def test_public_surface_never_exposes_private_inputs(api):
    response = get(api, factory=lambda: api.factory(surface="public"))
    assert response.status_code == 404 and not response.content


@pytest.mark.parametrize("field", ["X-QDev-Release-Lease", "X-QDev-Release-Fence"])
@pytest.mark.parametrize("wrong", [False, True])
def test_exact_lease_and_fence_required(api, field, wrong):
    headers = dict(api.headers)
    headers.pop(field)
    if wrong:
        headers[field] = "wrong-fixture"
    before = api.store.operation_events(api.lane)
    assert get(api, headers=headers).status_code == 409
    assert api.store.operation_events(api.lane) == before


@pytest.mark.parametrize(
    "fault",
    [
        "status",
        "release",
        "expired_lease",
        "expired_claim",
        "future_claim",
        "signature",
        "unicode_signature",
        "candidate",
        "attempt",
        "rollback",
        "profile",
        "workflow",
        "job",
        "archive_digest",
        "omitted_candidate",
        "omitted_source",
        "boolean_time",
    ],
)
def test_drift_or_expiry_cannot_refresh_admission(api, fault):
    def mutation(job):
        if fault == "status":
            job["status"] = "completed"
        elif fault == "release":
            job["release_id"] = "other-release"
        elif fault == "expired_lease":
            job["lease_expires_at"] = NOW
        elif fault == "expired_claim":
            job["dispatch_claim"]["expires_at"] = NOW
        elif fault == "future_claim":
            job["dispatch_claim"]["issued_at"] = NOW + 1000
        elif fault in {"signature", "unicode_signature"}:
            job["dispatch_claim_signature"] = (
                "\u0430" * 64 if fault.startswith("unicode") else "0" * 64
            )
        elif fault == "candidate":
            job["candidate_receipt"]["artifact_uri"] = "https://private-fixture.invalid/drift"
        elif fault == "attempt":
            job["candidate_receipt"]["attempt"] += 1
        elif fault == "rollback":
            job["rollback_anchor"]["source_sha"] = "f" * 40
        elif fault in {"profile", "workflow", "job"}:
            key = "runner_profile" if fault == "profile" else fault
            job["candidate_receipt"][key] = "qdev-ci" if fault == "profile" else "other"
            job["dispatch_claim"][key] = job["candidate_receipt"][key]
            job["dispatch_claim"]["candidate_evidence"] = candidate_evidence(job, api.lane)
            job["dispatch_claim_signature"] = sign_host_dispatch_claim(
                job["dispatch_claim"],
                signing_key=KEY,
            )
        elif fault == "archive_digest":
            job["candidate_receipt"]["archive_sha256"] = "f" * 64
        elif fault == "omitted_candidate":
            del job["candidate_receipt"]
        elif fault == "omitted_source":
            del job["source_sha"]
        else:
            job["dispatch_claim"]["issued_at"] = True

    mutate_job(api, mutation)
    before = api.store.operation_events(api.lane)
    response = get(api)
    assert response.status_code == 409, response.text
    assert response.json() == {"detail": "IdP dispatch inputs are unavailable"}
    assert api.store.operation_events(api.lane) == before
    assert not api.provider.calls


@pytest.mark.parametrize("defect", ["key", "key_symlink", "state_mode", "journal_symlink"])
def test_private_storage_checked_before_generic_constructor(api, monkeypatch, defect):
    if defect == "key":
        api.key_file.chmod(0o644)
    elif defect == "key_symlink":
        api.key_map.unlink()
        api.key_map.symlink_to(api.key_file)
    elif defect == "state_mode":
        api.store.root.chmod(0o755)
    else:
        path = api.store._operation_path(api.lane.name)
        target = path.with_suffix(".retained")
        path.rename(target)
        path.symlink_to(target)
    monkeypatch.setattr(ReleaseStore, "__init__", lambda *a: pytest.fail("unsafe constructor"))
    assert get(api).status_code == 409


def test_missing_snapshot_restores_only_existing_journal_job(api):
    before = api.store.operation_events(api.lane)
    path = api.store._job_path(api.lane.name)
    path.unlink()
    assert get(api).status_code == 200
    assert json.loads(path.read_bytes()) == before[-1]["job_snapshot"]
    assert api.store.operation_events(api.lane) == before


def test_no_idp_disclosure_on_another_lane(api):
    with pytest.raises(ReleaseLaneError, match="fixed IdP"):
        api.store.idp_dispatch_inputs(
            replace(api.lane, project_id="another-product"),
            api.claim["release_id"],
            lease_id=api.claim["lease_id"],
            fence=api.claim["fence"],
            signing_key=KEY,
        )


def test_explicit_lane_and_wrong_release_are_resolved(api):
    base = api.url.replace("idp-file-authorization", "idp-inputs")
    assert get(api, url=base + "?release_lane=" + api.lane.name).status_code == 200
    assert get(api, url=base + "?release_lane=other-lane").status_code == 404
    assert get(api, url=base.replace(api.claim["release_id"], "unknown-release")).status_code == 409


def test_read_is_candidate_provenance_not_fresh_provider_evidence(api):
    first = get(api).json()
    api.provider.calls.append("provider_changed_outside_this_read")
    assert get(api).json() == first
    assert first["acceptance"] == "not_run"
