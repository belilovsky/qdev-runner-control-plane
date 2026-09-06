"""Synthetic admission/provider/native fixtures; no production authorization."""

import copy
import hashlib
import json
import os
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from threading import Barrier
from types import SimpleNamespace

import pytest
from test_file_apply_authorization import KEY, NOW
from test_idp_file_evidence import Provider
from test_idp_file_runtime import (
    completion,
    make_associated_pair,
    make_native_pair,
    refresh_snapshot_binding,
    rehash,
    release,
)

from qdev_runner import idp_file_evidence
from qdev_runner import idp_file_runtime as runtime
from qdev_runner.file_apply_authorization import canonical_bytes
from qdev_runner.idp_file_issuer import check_storage, private_bytes
from qdev_runner.release_lane import (
    ReleaseLaneError,
    ReleaseStore,
    candidate_evidence,
    sign_host_dispatch_claim,
)


def make_issuer(tmp_path, *, associated=False):
    root = tmp_path.resolve()
    root.chmod(0o700)
    previous = None
    if associated:
        pair, previous = make_associated_pair()
    else:
        pair = make_native_pair()
        before = pair[0]
        before["schema_version"] = "qdev-idp-prepared-observation-v2"
        before["rollback_snapshot"] = {
            "schema_version": "qdev-idp-file-snapshot-v1",
            "snapshot_sha256": "0" * 64,
            "index": {
                "public/.well-known/qdev-release.json": {"sha256": "6" * 64, "mode": 0o644},
                runtime.INSTALLED_MANIFEST: None,
            },
            "previous_component_manifest": None,
        }
        refresh_snapshot_binding(pair)
    before, after, binding, claim, lane, candidate = pair
    after["schema_version"] = "qdev-idp-release-observation-v2"
    artifact_root = root / "artifacts"
    artifact = binding["ci_observation"]["artifact"]
    archive = artifact_root / artifact["storage_key"]
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"synthetic outer archive; not a production release")
    archive.chmod(0o600)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    artifact["artifact_sha256"] = digest
    ci = after["ci_observation"]
    ci["artifact"]["artifact_sha256"] = digest
    ci["download"]["artifact_sha256"] = digest
    binding["ci_observation"]["sha256"] = runtime.digest(ci)
    for event in before["events"]:
        if "ci_observation" in event:
            event["ci_observation"] = {
                **copy.deepcopy(binding["ci_observation"]),
                "path": event["ci_observation"]["path"],
            }
    before["binding_sha256"] = runtime.digest(binding)
    rehash(before)
    for event in after["events"]:
        if "ci_observation" in event:
            event["ci_observation"] = {
                **copy.deepcopy(binding["ci_observation"]),
                "path": event["ci_observation"]["path"],
            }
    after["events"][6]["controller_apply_binding_sha256"] = runtime.digest(binding)
    rehash(after)
    claim.update(
        artifact_digest="sha256:" + digest,
        artifact_ref=runtime.ARTIFACT_PREFIX + "@sha256:" + digest,
    )
    candidate.update(
        archive_sha256=digest,
        artifact_digest=claim["artifact_digest"],
        artifact_ref=claim["artifact_ref"],
    )
    claim["candidate_evidence"] = candidate_evidence({"candidate_receipt": candidate}, lane)
    if previous is None:
        claim["rollback_anchor"] = release(runtime.native_receipt(before, installed=False))
    store = ReleaseStore(root / "release-jobs")
    job = {
        **claim,
        "source_sha": binding["source_sha"],
        "candidate_receipt": candidate,
        "dispatch_claim": claim,
        "dispatch_claim_signature": sign_host_dispatch_claim(claim, signing_key=KEY),
        "status": "dispatched",
        "operation_phase": "dispatched",
        "operation_seq": 1,
    }
    with store._lock(lane.name):
        if previous is not None:
            prior_pair = make_native_pair(
                previous_release=True,
                extra_components={
                    "removed-only.txt": {"sha256": "6" * 64, "mode": 0o755, "size": 123},
                },
            )
            prepared = runtime.native_receipt(prior_pair[0], installed=False)
            installed = runtime.native_receipt(previous, installed=True)
            prior_job = {
                **job,
                **release(installed),
                "release_id": "release-operation-000",
                "status": "verified",
                "rollback_anchor": release(prepared),
                "runtime_receipt": completion(prepared, installed, lane),
            }
            store._append_operation_unlocked(lane, prior_job, "verified", recorded_at=NOW - 1)
        store._append_operation_unlocked(lane, job, "dispatched", recorded_at=NOW)
        store._write(store._job_path(lane.name), job)
    return SimpleNamespace(
        pair=pair,
        native=before,
        binding=binding,
        claim=claim,
        lane=lane,
        candidate=candidate,
        provider=Provider(binding),
        artifact_root=artifact_root,
        archive=archive,
        store=store,
        previous=previous,
    )


@pytest.fixture
def issued(tmp_path):
    return make_issuer(tmp_path)


def issue(data, **overrides):
    return data.store.authorize_idp_file_apply(
        data.lane,
        data.claim["release_id"],
        canonical_bytes(data.native),
        **{
            "lease_id": data.claim["lease_id"],
            "fence": data.claim["fence"],
            "signing_key": KEY,
            "github": data.provider,
            "artifact_root": data.artifact_root,
            "clock": lambda: NOW,
            **overrides,
        },
    )


def mutate_job(data, mutation):
    with data.store._lock(data.lane.name):
        job = data.store._job_unlocked(data.lane)
        mutation(job)
        data.store._append_operation_unlocked(data.lane, job, "fixture_change", recorded_at=NOW)
        data.store._write(data.store._job_path(data.lane.name), job)


@pytest.mark.parametrize("associated", [False, True])
def test_issuer_collects_provider_and_native_before_durable_authorization(tmp_path, associated):
    data = make_issuer(tmp_path, associated=associated)
    before = data.store.operation_events(data.lane)
    receipt = issue(data)
    after = data.store.operation_events(data.lane)
    assert after[:-1] == before
    assert after[-1]["phase"] == "idp_file_authorized"
    observation = after[-1]["idp_file_authorization"]
    assert observation["native_origin"] == "configured_release_host_mtls"
    assert observation["native_observation"] == data.native
    assert observation["ci"]["status"] == "provider_ci_archive_verified"
    assert observation["ci"]["controller_admission"] == "not_verified"
    assert observation["prior_observation_sha256"] == (
        runtime.digest(data.previous) if associated else None
    )
    assert receipt["authorization_signature"] == sign_host_dispatch_claim(
        receipt["authorization"],
        signing_key=KEY,
    )
    assert receipt["dispatch_claim"] == data.claim
    assert receipt["acceptance"] == "not_run"
    assert "log" in data.provider.calls
    job = after[-1]["job_snapshot"]
    assert job["status"] == job["operation_phase"] == "dispatched"
    assert job["idp_file_transaction"] == data.native["transaction"]
    assert job["lease_expires_at"] == data.claim["lease_expires_at"]


def test_two_requests_reobserve_and_append_without_renewing_dispatch(issued):
    first = issue(issued)
    first_events = issued.store.operation_events(issued.lane)
    second = issue(issued)
    assert issued.store.operation_events(issued.lane)[:-1] == first_events
    for field in ("authorization", "authorization_signature", "dispatch_claim"):
        assert second[field] == first[field]
    assert second["journal_seq"] == first["journal_seq"] + 1
    assert issued.provider.calls.count("log") == 2


def test_concurrent_retry_cannot_sign_against_changed_journal(issued, monkeypatch):
    barrier = Barrier(2)
    original = idp_file_evidence.observe_idp_ci

    def synchronized_observation(*args, **kwargs):
        result = original(*args, **kwargs)
        barrier.wait(timeout=10)
        return result

    monkeypatch.setattr(idp_file_evidence, "observe_idp_ci", synchronized_observation)

    def attempt():
        try:
            return issue(issued, github=Provider(issued.binding))
        except ReleaseLaneError as error:
            return str(error)

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))
    successes = [result for result in results if isinstance(result, dict)]
    assert len(successes) == 1
    assert results.count("IdP dispatch changed during provider observation") == 1
    assert len(issued.store.operation_events(issued.lane)) == 2
    monkeypatch.setattr(idp_file_evidence, "observe_idp_ci", original)
    retry = issue(issued)
    assert retry["authorization"] == successes[0]["authorization"]
    assert retry["authorization_signature"] == successes[0]["authorization_signature"]
    assert retry["dispatch_claim"] == issued.claim
    assert retry["journal_seq"] == successes[0]["journal_seq"] + 1


@pytest.mark.parametrize(
    "defect",
    [
        "lease",
        "fence",
        "status",
        "signature",
        "source_sha",
        "attempt",
        "candidate",
        "transaction",
    ],
)
def test_invalid_current_dispatch_never_queries_provider(issued, defect):
    def mutate(job):
        if defect == "candidate":
            job["candidate_receipt"]["archive_sha256"] = "9" * 64
        elif defect == "attempt":
            job["dispatch_claim"]["attempt"] = 2
        else:
            field, value = {
                "lease": ("lease_expires_at", NOW),
                "fence": ("fence", "1" * 24),
                "status": ("status", "verified"),
                "signature": ("dispatch_claim_signature", "0" * 64),
                "source_sha": ("source_sha", "9" * 40),
                "transaction": ("idp_file_transaction", "native-transaction-other"),
            }[defect]
            job[field] = value

    mutate_job(issued, mutate)
    with pytest.raises(ReleaseLaneError):
        issue(issued)
    assert not issued.provider.calls


@pytest.mark.parametrize("defect", ["v1", "snapshot", "chain", "capacity", "field", "manifest"])
def test_untrusted_native_observation_never_reaches_provider(issued, defect):
    if defect == "v1":
        issued.native["schema_version"] = "qdev-idp-prepared-observation-v1"
    elif defect == "snapshot":
        issued.native["rollback_snapshot"]["index"]["public/.well-known/qdev-release.json"][
            "sha256"
        ] = "1" * 64
    elif defect == "chain":
        issued.native["events"][0]["source_sha"] = "9" * 40
    elif defect == "capacity":
        issued.native["capacity"]["filesystems"][0]["free_bytes"] = 0
    elif defect == "manifest":
        issued.native["component_manifest"]["source_sha"] = "9" * 40
    else:
        issued.native["client_secret"] = "synthetic-sensitive-value"  # noqa: S105
    history = issued.store.operation_events(issued.lane)
    with pytest.raises(ReleaseLaneError) as error:
        issue(issued)
    assert "synthetic-sensitive-value" not in str(error.value)
    assert not issued.provider.calls
    assert issued.store.operation_events(issued.lane) == history


@pytest.mark.parametrize("defect", ["queued", "attempt", "archive", "provider_race"])
def test_actual_provider_or_archive_failure_does_not_issue(issued, defect):
    if defect == "queued":
        issued.provider.runs[1]["status"] = "queued"
    elif defect == "attempt":
        issued.provider.runs[1]["run_attempt"] = 2
    elif defect == "archive":
        issued.archive.write_bytes(b"modified")
    else:
        issued.provider.mutate_after_archive = True
    history = issued.store.operation_events(issued.lane)
    with pytest.raises(ReleaseLaneError):
        issue(issued)
    assert issued.store.operation_events(issued.lane) == history


def test_dispatch_change_during_network_rejected_without_holding_lane_lock(issued):
    original = issued.provider.workflow_job_log

    def change(*args):
        # This acquires the same lock: would deadlock if held across network.
        mutate_job(issued, lambda job: job.update(fence="1" * 24))
        return original(*args)

    issued.provider.workflow_job_log = change
    with pytest.raises(ReleaseLaneError):
        issue(issued)
    assert all(
        e["phase"] != "idp_file_authorized" for e in issued.store.operation_events(issued.lane)
    )


def test_fresh_ci_expires_while_reacquiring_lock(issued, monkeypatch):
    mutate_job(issued, lambda job: job["dispatch_claim"].update(expires_at=NOW + 300))
    mutate_job(
        issued,
        lambda job: job.update(
            dispatch_claim_signature=sign_host_dispatch_claim(
                job["dispatch_claim"], signing_key=KEY
            )
        ),
    )
    now = [NOW]
    calls = [0]
    original = issued.store._lock

    @contextmanager
    def delayed(name):
        calls[0] += 1
        if calls[0] == 2:
            now[0] += 121
        with original(name):
            yield

    monkeypatch.setattr(issued.store, "_lock", delayed)
    with pytest.raises(ReleaseLaneError, match="provider observation expired"):
        issue(issued, clock=lambda: now[0])


@pytest.mark.parametrize("boundary", ["append", "snapshot"])
def test_durable_failure_reconciles_before_retry_without_new_dispatch(
    issued, monkeypatch, boundary
):
    method = "_append_operation_unlocked" if boundary == "append" else "_write"
    original = getattr(issued.store, method)

    def fail(*args, **kwargs):
        raise ReleaseLaneError("synthetic durable failure")

    monkeypatch.setattr(issued.store, method, fail)
    with pytest.raises(ReleaseLaneError, match="synthetic durable failure"):
        issue(issued)
    monkeypatch.setattr(issued.store, method, original)
    events = issued.store.operation_events(issued.lane)
    assert len(events) == (1 if boundary == "append" else 2)
    result = issue(issued)
    assert result["dispatch_claim"] == issued.claim
    assert result["journal_seq"] == len(events) + 1


def test_missing_snapshot_recovers_from_durable_journal(issued):
    issued.store._job_path(issued.lane.name).unlink()
    assert issue(issued)["journal_seq"] == 2


def test_previous_archive_is_not_inferred_without_verified_history(tmp_path):
    data = make_issuer(tmp_path, associated=True)
    # A new store has a dispatch but no accepted previous release history.
    other = ReleaseStore(tmp_path.resolve() / "other-store")
    job = data.store.operation_events(data.lane)[-1]["job_snapshot"]
    with other._lock(data.lane.name):
        other._append_operation_unlocked(data.lane, job, "dispatched", recorded_at=NOW)
        other._write(other._job_path(data.lane.name), job)
    data.store = other
    with pytest.raises(ReleaseLaneError):
        issue(data)
    assert not data.provider.calls


@pytest.mark.parametrize("target", ["root", "jobs", "operations", "lock", "snapshot", "journal"])
def test_private_state_symlink_never_chmods_target_or_authorizes(issued, target):
    root = issued.store.root
    path = {
        "root": root,
        "jobs": root / "jobs",
        "operations": root / "operations",
        "lock": root / "locks" / f"{issued.lane.name}.lock",
        "snapshot": issued.store._job_path(issued.lane.name),
        "journal": issued.store._operation_path(issued.lane.name),
    }[target]
    moved = path.with_name(path.name + ".original")
    path.rename(moved)
    path.symlink_to(moved, target_is_directory=moved.is_dir())
    mode = moved.stat().st_mode
    with pytest.raises(ReleaseLaneError):
        issue(issued)
    assert moved.stat().st_mode == mode
    assert not issued.provider.calls


@pytest.mark.parametrize(
    "defect", ["parent_mode", "file_mode", "symlink", "hardlink", "fifo", "size"]
)
def test_private_key_file_rejects_unsafe_storage(tmp_path, defect):
    parent = tmp_path.resolve() / "private"
    parent.mkdir(mode=0o700)
    path = parent / "key"
    path.write_bytes(KEY)
    path.chmod(0o600)
    if defect == "parent_mode":
        parent.chmod(0o755)
    elif defect == "file_mode":
        path.chmod(0o644)
    elif defect == "hardlink":
        os.link(path, parent / "copy")
    elif defect == "symlink":
        path.rename(parent / "real")
        path.symlink_to(parent / "real")
    elif defect == "fifo":
        path.unlink()
        os.mkfifo(path, mode=0o600)
    with pytest.raises(ReleaseLaneError):
        private_bytes(path, limit=1 if defect == "size" else 4096)


def test_private_key_file_reads_private_regular_bytes(tmp_path):
    parent = tmp_path.resolve()
    parent.chmod(0o700)
    path = parent / "key"
    path.write_bytes(KEY)
    path.chmod(0o600)
    assert private_bytes(path, limit=4096) == KEY


def test_wrong_lane_is_not_an_idp_authorizer(issued):
    issued.lane = replace(issued.lane, project_id="other")
    with pytest.raises(ReleaseLaneError):
        issue(issued)
    assert not issued.provider.calls


def test_private_storage_check_is_read_only(issued):
    check_storage(issued.store.root, issued.lane)
    assert len(issued.store.operation_events(issued.lane)) == 1
    assert KEY.decode() not in json.dumps(issued.store.operation_events(issued.lane))
