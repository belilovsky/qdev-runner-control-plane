"""Synthetic native observations: contract/journal tests, never live evidence."""

import fcntl
from copy import deepcopy
from dataclasses import replace
from types import SimpleNamespace

import pytest
import test_admin_platform_release_lanes as host_tests
import test_file_apply_authorization as auth_tests

from qdev_runner import idp_file_runtime as runtime
from qdev_runner.file_apply_authorization import authorization_payload
from qdev_runner.release_lane import (
    RUNTIME_RECEIPT_SCHEMA,
    ReleaseLaneError,
    sign_host_dispatch_claim,
    validate_native_runtime_receipt,
    validate_runtime_receipt,
)

AGENT = host_tests.AGENT
NOW = auth_tests.NOW


def capacity(at, *, database=False):
    result = {
        "observed_at": at,
        "filesystems": [
            {
                "filesystem": "synthetic-fixture-mount",
                "free_bytes": 10**12,
                "free_inodes": 10**6,
                "peak_additional_bytes": 10000,
                "peak_inodes": 6000,
                "reserve_bytes": 512 * 1024 * 1024,
                "lanes": (
                    ["database-dump", "postgres-data-and-temp", "postgres-wal"]
                    if database
                    else ["release-files", "bundle-backup-drill"]
                ),
            }
        ],
    }
    if database:
        result.update(database_bytes=100, estimate_policy="dump-2x_data-temp-3x_wal-2x_v1")
    return result


def rehash(observation):
    previous = None
    for event in observation["events"]:
        event["previous_event_digest"] = previous
        previous = runtime.digest(event)
    key = (
        "terminal_event_sha256"
        if "terminal_event_sha256" in observation
        else "prepared_event_sha256"
    )
    observation[key] = previous


@pytest.fixture
def native_pair():
    binding, claim, lane, candidate = auth_tests.fixture.__wrapped__()
    lane = replace(lane, required_readiness=tuple(runtime.READINESS))
    at = binding["ci_observation"]["observed_at"]
    marker = "public/.well-known/qdev-release.json"
    manifest = {
        "schema_version": "qdev-idp-release-bundle-v1",
        "repository": runtime.REPOSITORY,
        "source_sha": binding["source_sha"],
        "tree_sha": "3" * 40,
        "generated_components": {marker: "commit-time-release-identity-v1"},
        "components": {marker: {"sha256": "4" * 64, "mode": 0o644, "size": 100}},
    }
    binding["manifest_sha256"] = runtime.digest(manifest)
    binding["ci_observation"]["artifact"]["manifest_sha256"] = binding["manifest_sha256"]
    reference = binding["ci_observation"]
    artifact = reference["artifact"]
    ci = {
        "schema_version": "qdev-idp-ci-release-observation-v1",
        "repository": runtime.REPOSITORY,
        "source_sha": binding["source_sha"],
        "status": "source_ci_bundle_verified",
        "observed_at": at,
        "component_manifest_sha256": binding["manifest_sha256"],
        **{key: deepcopy(reference[key]) for key in ("quality", "runner_contract", "artifact")},
        "download": {
            "transport": "operator_ssh_existing_store",
            "status": "retrieved_verified",
            "storage_key": artifact["storage_key"],
            "artifact_sha256": artifact["artifact_sha256"],
        },
    }
    reference["sha256"] = runtime.digest(ci)
    prior_gate = {**deepcopy(reference), "path": "ci-0000000000000001.json"}
    images = [
        {"container_id": str(i) * 64, "image_digest": "sha256:" + str(i) * 64} for i in range(1, 6)
    ]
    common = {
        "repository": runtime.REPOSITORY,
        "source_sha": binding["source_sha"],
        "transaction": binding["transaction"],
        "observed_at": at,
        "events": [],
        "component_manifest": manifest,
        "runtime_images": deepcopy(images),
        "acceptance": "not_run",
        "redacted": True,
    }
    observation = {
        **common,
        "schema_version": "qdev-idp-prepared-observation-v1",
        "status": "prepared_runtime_reobserved",
        "binding": binding,
        "binding_sha256": runtime.digest(binding),
        "prepared_event_sha256": None,
        "rollback_material": {
            "snapshot_sha256": binding["snapshot_sha256"],
            "database_backup_sha256": "5" * 64,
            "restored_tables": 1,
            "disposable_database_removed": True,
        },
        "capacity": capacity(at),
        "previous_provenance": runtime.PREVIOUS_PROVENANCE,
        "controller_admission": "not_authorized",
        "deployment": "not_applied",
    }
    event_common = {
        "schema_version": "qdev-idp-release-transaction-v1",
        "transaction": binding["transaction"],
        "source_sha": binding["source_sha"],
        "previous_runtime_sha": binding["expected_previous_sha"],
        "bundle_sha256": binding["bundle_sha256"],
        "component_manifest_sha256": binding["manifest_sha256"],
        "observed_at": at,
        "release_scope": "files_only_no_database_image_or_mfa_change",
        "acceptance": "not_run",
    }
    extras = [
        {},
        {
            "runtime_images": images,
            "ci_observation": prior_gate,
            "previous_provenance": runtime.PREVIOUS_PROVENANCE,
            "capacity": capacity(at),
        },
        {"ci_observation": prior_gate},
        {
            "disposable_database": "qdev_restore_" + "1" * 24,
            "backup_sha256": "5" * 64,
            "capacity": capacity(at, database=True),
        },
        {"backup_sha256": "5" * 64, "restored_tables": 1, "disposable_database_removed": True},
        {
            "snapshot_sha256": binding["snapshot_sha256"],
            "file_restore": "exact_files_and_configuration",
            "database_restore": "disposable_database_read_verified",
        },
    ]
    observation["events"] = [
        {**event_common, "phase": phase, **extra}
        for phase, extra in zip(runtime.PREFIX, extras, strict=True)
    ]
    rehash(observation)
    installed = {
        **deepcopy(common),
        "events": deepcopy(observation["events"]),
        "schema_version": "qdev-idp-release-observation-v1",
        "status": "installed_release_reobserved",
        "controller_admission": "historical_binding_only_not_current_authorization",
        "previous_runtime_sha": binding["expected_previous_sha"],
        "bundle_sha256": binding["bundle_sha256"],
        "component_manifest_sha256": binding["manifest_sha256"],
        "terminal_event_sha256": None,
        "ci_observation": ci,
        "installed_components": 1,
        "current_checks": dict(runtime.CHECKS),
    }
    installed["events"].extend(
        [
            {
                **event_common,
                "phase": "apply_started",
                "ci_observation": deepcopy(reference),
                "controller_apply_binding_sha256": runtime.digest(binding),
                "capacity": capacity(at),
            },
            {**event_common, "phase": "files_installed"},
            {
                **event_common,
                "phase": "verified",
                "runtime_images": images,
                "installed_components": 1,
                "rollback": "verified",
                "public_checks": "passed",
                "protected_acceptance": "not_run",
            },
        ]
    )
    rehash(installed)
    return observation, installed, binding, claim, lane, candidate


def release(receipt):
    return {key: receipt[key] for key in ("source_sha", "artifact_digest", "artifact_ref")}


def completion(prepared, installed, lane):
    result = {
        **installed,
        "schema": RUNTIME_RECEIPT_SCHEMA,
        "status": "verified",
        "project": lane.project_id,
        "release_lane": lane.name,
        "placement": lane.placement,
        "health": "ok",
        "rollback": {"verified": True, **release(prepared)},
    }
    del result["project_id"], result["native_host_adapter"]
    return result


def test_native_pair_preserves_content_and_distinguishes_previous_provenance(native_pair):
    before, after, binding, _, lane, _ = native_pair
    prepared = runtime.native_receipt(
        before, installed=False, expected_binding=runtime.canonical(binding), now=NOW
    )
    installed = runtime.native_receipt(
        after, installed=True, expected_binding=runtime.canonical(binding), now=NOW
    )
    for receipt in (prepared, installed):
        validate_native_runtime_receipt(receipt, lane=lane, **release(receipt))
    assert prepared["source_sha"] == binding["expected_previous_sha"]
    assert prepared["artifact_digest"] == "sha256:" + binding["snapshot_sha256"]
    assert (
        installed["artifact_digest"]
        == "sha256:" + binding["ci_observation"]["artifact"]["artifact_sha256"]
    )
    receipt = completion(prepared, installed, lane)
    validate_runtime_receipt(receipt, lane=lane, **release(installed))
    assert receipt["artifact_provenance"]["observation"]["acceptance"] == "not_run"
    assert before["deployment"] == "not_applied"
    after["current_checks"]["retained_file_restore"] = "failed"
    assert installed["artifact_provenance"]["observation"]["current_checks"] == runtime.CHECKS


@pytest.mark.parametrize("stage", [0, 1])
@pytest.mark.parametrize(
    "defect",
    [
        "hash_chain",
        "manifest",
        "previous_sha",
        "extra_event_field",
        "db_not_removed",
        "db_empty",
        "wrong_role_of_receipt",
        "secret_field",
        "image_drift",
        "capacity",
        "queued",
        "wrong_attempt",
        "missing_database_capacity",
        "restore_failed",
    ],
)
def test_rejects_inconsistent_or_rehashed_evidence(native_pair, stage, defect):
    observation = deepcopy(native_pair[stage])
    if defect == "hash_chain":
        observation["events"][2]["previous_event_digest"] = "0" * 64
    elif defect == "manifest":
        observation["component_manifest"]["components"][".env"] = {
            "sha256": "1" * 64,
            "mode": 0o644,
            "size": 10,
        }
    elif defect == "previous_sha":
        observation["events"][0]["previous_runtime_sha"] = "0" * 40
    elif defect == "extra_event_field":
        observation["events"][1]["operator_session"] = "do-not-emit-fixture"
    elif defect == "db_not_removed":
        observation["events"][4]["disposable_database_removed"] = False
    elif defect == "db_empty":
        observation["events"][4]["restored_tables"] = 0
    elif defect == "wrong_role_of_receipt":
        observation["acceptance"] = "accepted"
    elif defect == "secret_field":
        observation["secret"] = "do-not-emit-fixture"  # noqa: S105 -- forbidden-field fixture
    elif defect == "image_drift":
        observation["runtime_images"][0]["image_digest"] = "sha256:" + "0" * 64
    elif defect == "capacity":
        observation["events"][1]["capacity"]["filesystems"][0]["free_bytes"] = 1
    elif defect == "queued":
        observation["events"][1]["ci_observation"]["quality"]["status"] = "queued"
    elif defect == "wrong_attempt":
        observation["events"][2]["ci_observation"]["quality"]["attempt"] = 2
    elif defect == "missing_database_capacity":
        del observation["events"][3]["capacity"]
    elif defect == "restore_failed":
        observation["events"][5]["file_restore"] = "failed"
    if defect != "hash_chain":
        rehash(observation)
    with pytest.raises(runtime.IdPObservationError) as error:
        runtime.native_receipt(observation, installed=bool(stage))
    assert "do-not-emit-fixture" not in str(error.value)


@pytest.mark.parametrize("defect", ["digest", "current_checks", "download", "replay", "rollback"])
def test_installed_receipt_cannot_override_collected_observation(native_pair, defect):
    before, after, _, _, lane, _ = native_pair
    prepared = runtime.native_receipt(before, installed=False)
    installed = runtime.native_receipt(after, installed=True)
    result = completion(prepared, installed, lane)
    if defect == "digest":
        result["artifact_provenance"]["observation_sha256"] = "0" * 64
    elif defect == "current_checks":
        result["artifact_provenance"]["observation"]["current_checks"][
            "retained_database_backup"
        ] = "auth_blocked"
    elif defect == "download":
        result["artifact_provenance"]["observation"]["ci_observation"]["download"][
            "artifact_sha256"
        ] = "0" * 64
    elif defect == "replay":
        result["artifact_provenance"] = prepared["artifact_provenance"]
    else:
        result["rollback"]["artifact_digest"] = "sha256:" + "0" * 64
        result["rollback"]["artifact_ref"] = "qdev/idp-release@sha256:" + "0" * 64
    with pytest.raises(ReleaseLaneError):
        validate_runtime_receipt(result, lane=lane, **release(result))


@pytest.mark.parametrize("stage", [0, 1])
def test_freshness_binding_and_digest_only_are_not_authorization(native_pair, stage):
    observation = native_pair[stage]
    with pytest.raises(runtime.IdPObservationError):
        runtime.native_receipt(observation, installed=bool(stage), now=NOW + 301)
    with pytest.raises(runtime.IdPObservationError):
        runtime.native_receipt(observation, installed=bool(stage), expected_binding=b"{}\n")
    receipt = runtime.native_receipt(observation, installed=bool(stage))
    del receipt["artifact_provenance"]["observation"]
    with pytest.raises(runtime.IdPObservationError):
        runtime.validate_runtime_evidence(receipt)


@pytest.fixture
def idp_host(native_pair, tmp_path, monkeypatch):
    before, after, binding, claim, lane, candidate_receipt = native_pair
    profile = replace(
        host_tests._test_profile(tmp_path),
        name="idp",
        lane=lane.name,
        project_id=runtime.PROJECT,
        repository=runtime.REPOSITORY,
        placement=lane.placement,
        artifact_prefix=runtime.ARTIFACT_PREFIX,
        adapter=runtime.ADAPTER,
    )
    config = host_tests._config(profile)
    config = replace(config, dispatch_secret=auth_tests.KEY)
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW)
    host_tests._patch_local_security(monkeypatch)
    active = release(runtime.native_receipt(before, installed=False))
    candidate = release(runtime.native_receipt(after, installed=True))
    rollback = host_tests._variant(profile, "9")
    host_tests._provision_agent_state(profile, active, rollback)
    claim = {**claim, "release_id": host_tests.RELEASE_ID, "lease_id": host_tests.LEASE_ID}
    job = host_tests._signed_job(profile, config, candidate, now=NOW, rollback_anchor=active)
    job.update(
        lease_expires_at=claim["lease_expires_at"],
        candidate_evidence=claim["candidate_evidence"],
        dispatch_claim=claim,
        dispatch_claim_signature=sign_host_dispatch_claim(claim, signing_key=auth_tests.KEY),
    )
    state = {"installed": False, "completion": None, "reads": [], "controller": "dispatched"}

    def observe(installed):
        with AGENT._acquire_lock(profile.lock_path) as competing, pytest.raises(BlockingIOError):
            fcntl.flock(competing.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        state["reads"].append("installed" if installed else "prepared")
        assert state["installed"] is installed
        return deepcopy(after if installed else before)

    reader = SimpleNamespace(
        observe_prepared=lambda: observe(False), observe_installed=lambda: observe(True)
    )

    def request(_config, method, path, payload=None, *, headers=None):
        assert headers == AGENT._controller_headers(host_tests.LEASE_ID, host_tests.FENCE)
        if method == "GET" and path.endswith(f"/jobs/{host_tests.RELEASE_ID}"):
            return 200, AGENT._canonical_bytes(
                host_tests._controller_status(
                    profile,
                    candidate,
                    state["controller"],
                    runtime_receipt=state["completion"],
                )
            )
        if method == "POST" and path.endswith(f"/jobs/{host_tests.RELEASE_ID}/complete"):
            validate_runtime_receipt(payload, lane=lane, **candidate, rollback_anchor=active)
            state["completion"], state["controller"] = payload, "verified"
            return 200, AGENT._canonical_bytes(payload)
        pytest.fail("unexpected controller request")

    def no_dispatch(*_args, **_kwargs):
        pytest.fail("locked IdP adapter reentered a dispatcher")

    monkeypatch.setattr(AGENT, "request", request)
    monkeypatch.setattr(AGENT, "native_receipt", no_dispatch)
    monkeypatch.setattr(AGENT, "invoke_native", no_dispatch)
    raw = runtime.canonical(binding)
    authorization = authorization_payload(raw, claim)
    adapter = AGENT.IdPFileApplyAdapter(
        config,
        profile,
        lane,
        job,
        authorization,
        sign_host_dispatch_claim(authorization, signing_key=auth_tests.KEY),
        candidate_receipt=candidate_receipt,
    )
    return adapter, reader, raw, state, profile, lane, candidate, active


def test_fixed_adapter_uses_real_journal_locked_collectors_and_completion(idp_host):
    adapter, reader, raw, state, profile, _, candidate, active = idp_host
    authorize = adapter(reader)
    with authorize(raw) as guard:
        assert state["reads"] == ["prepared"]
        assert [e["phase"] for e in AGENT._journal_events(profile)][-2:] == [
            "dispatch_accepted",
            "release_started",
        ]
        guard.assert_current()
        state["installed"] = True
    assert state["reads"] == ["prepared", "installed", "installed"]
    assert state["controller"] == "verified"
    assert AGENT.read_state(profile.state_path, profile) == (candidate, active)
    assert AGENT._pending_operation(profile) is None
    with pytest.raises(ReleaseLaneError, match="outside"):
        guard.assert_current()
    with pytest.raises(AGENT.AgentError, match="consumed"), authorize(raw):
        pytest.fail("replayed file apply")


@pytest.mark.parametrize("phase", ["prepared", "installed", "reconciliation"])
def test_fixed_adapter_invalid_observation_never_completes_or_reapplies(idp_host, phase):
    adapter, reader, raw, state, profile, *_ = idp_host
    original_before, original_after = reader.observe_prepared, reader.observe_installed
    count = 0

    def observe(installed):
        nonlocal count
        count += 1
        result = original_after() if installed else original_before()
        current = ("reconciliation" if count == 3 else "installed") if installed else "prepared"
        if current == phase:
            result["acceptance"] = "accepted"
        return result

    reader.observe_prepared = lambda: observe(False)
    reader.observe_installed = lambda: observe(True)
    with pytest.raises(runtime.IdPObservationError), adapter(reader)(raw):
        state["installed"] = True
    assert state["completion"] is None
    assert (AGENT._pending_operation(profile) is None) is (phase == "prepared")
    if phase != "prepared":
        with pytest.raises(AGENT.ControllerOutcomeUnresolved), adapter(reader)(raw):
            pytest.fail("unknown outcome repeated apply")


def test_adapter_is_code_only_and_does_not_enroll_idp(idp_host):
    adapter, _, _, _, profile, *_ = idp_host
    assert profile.project_id not in {item.project_id for item in AGENT.PROFILES.values()}
    with pytest.raises(AGENT.AgentError):
        adapter({"observe_prepared": "pass", "observe_installed": "pass"})


@pytest.mark.parametrize("field,value", [
    ("repository", "belilovsky/other"),
    ("adapter", "avds"),
    ("project_id", "admin-platform"),
    ("artifact_prefix", "qdev/other"),
    ("lane", "other"),
    ("placement", "other"),
])
def test_adapter_rejects_other_profile_even_with_valid_documents(idp_host, field, value):
    adapter, *_ = idp_host
    with pytest.raises(AGENT.AgentError):
        AGENT.IdPFileApplyAdapter(
            adapter._config,
            replace(adapter._profile, **{field: value}),
            adapter._lane,
            {}, {}, "unused",
            candidate_receipt={},
        )


def test_native_observation_cannot_replace_already_known_active_identity(idp_host):
    adapter, reader, raw, state, profile, _, _, active = idp_host
    known = {**active, "artifact_digest": "sha256:" + "7" * 64,
             "artifact_ref": "qdev/idp-release@sha256:" + "7" * 64}
    host_tests._provision_agent_state(profile, known, host_tests._variant(profile, "9"))
    with pytest.raises(AGENT.AgentError), adapter(reader)(raw):
        pytest.fail("snapshot replaced a different known active artifact")
    assert state["completion"] is None
    assert AGENT.read_state(profile.state_path, profile)[0] == known
    assert AGENT._pending_operation(profile) is None
