import importlib.util
import json
import sys
from pathlib import Path

import yaml

from qdev_runner.release_lane import ReleaseLanePolicy

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qdev_admin_platform_release_host_agent.py"
SPEC = importlib.util.spec_from_file_location("qdev_admin_platform_release_host_agent", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AGENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AGENT
SPEC.loader.exec_module(AGENT)

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


def _release(profile: object) -> dict[str, str]:
    return {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"{profile.artifact_prefix}@{DIGEST}",
    }


def test_admin_platform_lanes_are_exact_and_total_has_no_total_kz_endpoint() -> None:
    policy = ReleaseLanePolicy(ROOT / "config/release-lanes.yml")
    expected = {
        "qdev-release-ortcom": ("belilovsky/ortcom-kz", "ortcom-root-deploy-v1"),
        "qdev-release-cmnt": ("belilovsky/cmnt-web", "cmnt-root-rolling-launcher-v1"),
        "qdev-release-total": ("belilovsky/total-kz", "total-qdev-native-release-v1"),
        "qdev-release-qazposter": ("belilovsky/qazposter", "qazposter-native-release-v1"),
    }
    for lane_name, (repository, adapter) in expected.items():
        lane = policy.lane(lane_name)
        assert lane.canonical_repository == repository
        assert lane.native_host_adapter == adapter
        assert lane.runtime_endpoints
        assert lane.required_readiness == ("native", "public", "identity")
    total_lane = policy.lane("qdev-release-total")
    assert all("total.kz" not in endpoint for endpoint in total_lane.runtime_endpoints)


def test_product_lanes_cannot_drift_from_the_managed_registry() -> None:
    policy = ReleaseLanePolicy(ROOT / "config/release-lanes.yml")
    registry = yaml.safe_load((ROOT / "config/managed-registry.yml").read_text(encoding="utf-8"))
    entries = registry["entries"]
    names = {
        "qdev-release-ortcom": "ortcom",
        "qdev-release-cmnt": "cmnt",
        "qdev-release-total": "total",
        "qdev-release-qazposter": "qazposter",
    }
    for lane_name, registry_name in names.items():
        lane = policy.lane(lane_name)
        entry = entries[registry_name]
        assert lane.project_id == entry["project_id"]
        assert lane.canonical_repository == entry["repository"]
        assert list(lane.runtime_endpoints) == entry["runtime_endpoints"]
        assert lane.rollback_reference == entry["rollback_reference"]


def test_agent_profiles_bind_each_release_to_a_compiled_native_adapter() -> None:
    assert set(AGENT.PROFILES) == {"ortcom", "cmnt", "total", "qazposter"}
    for profile in AGENT.PROFILES.values():
        release = _release(profile)
        assert AGENT._release(release, profile) == release
        assert profile.release_dispatcher.is_absolute()
        assert profile.rollback_dispatcher.is_absolute()
        assert profile.receipt_dispatcher.is_absolute()
        assert profile.readiness == {"identity": "ok", "native": "ok", "public": "ok"}
        invalid = {**release, "artifact_ref": "registry.example.invalid/unsafe@" + DIGEST}
        try:
            AGENT._release(invalid, profile)
        except AGENT.AgentError:
            pass
        else:  # pragma: no cover - protects the fail-closed boundary
            raise AssertionError("untrusted artifact reference was accepted")


def test_agent_rejects_a_job_for_another_compiled_placement() -> None:
    profile = AGENT.PROFILES["total"]
    release = _release(profile)
    job = {
        "schema": "qdev-release-host-agent-job-v1",
        "release_id": "release-1",
        "release_lane": profile.lane,
        "project_id": profile.project_id,
        "placement": profile.placement,
        **release,
    }
    assert AGENT.validate_job(job, profile) == ("release-1", release)
    try:
        AGENT.validate_job({**job, "placement": "arbitrary-host"}, profile)
    except AGENT.AgentError:
        pass
    else:  # pragma: no cover - protects the fail-closed boundary
        raise AssertionError("foreign placement was accepted")


def test_agent_accepts_only_a_typed_native_receipt(monkeypatch: object) -> None:
    profile = AGENT.PROFILES["cmnt"]
    release = _release(profile)
    document = {
        "schema": AGENT.NATIVE_RECEIPT_SCHEMA,
        "project_id": profile.project_id,
        "native_host_adapter": profile.adapter,
        **release,
        "readiness": profile.readiness,
    }
    monkeypatch.setattr(AGENT, "_ensure_dispatcher", lambda _: None)
    monkeypatch.setattr(AGENT, "_run", lambda _: json.dumps(document).encode())
    AGENT.native_receipt(profile, release)
    document["readiness"] = {"native": "ok"}
    try:
        AGENT.native_receipt(profile, release)
    except AGENT.AgentError:
        pass
    else:  # pragma: no cover - protects the fail-closed boundary
        raise AssertionError("incomplete native receipt was accepted")


def test_agent_rejects_blank_dependency_identity_keys() -> None:
    profile = AGENT.PROFILES["cmnt"]
    release = _release(profile)
    evidence = {
        "runtime_identity": {**release, "measured": True},
        "dependency_identity": {" ": "1.31.1"},
        "artifact_provenance": {
            "qak_wheel_sha256": "d" * 64,
            "avds_artifact_sha256": "e" * 64,
            "avds_source_sha": "f" * 40,
        },
    }
    try:
        AGENT._runtime_evidence(evidence, profile, release)
    except AGENT.AgentError as error:
        assert "dependency identity" in str(error)
    else:  # pragma: no cover - protects the fail-closed boundary
        raise AssertionError("blank dependency identity key was accepted")


def test_agent_cannot_be_reconfigured_with_host_paths() -> None:
    source = SCRIPT.read_text(encoding="utf-8")
    assert "QDEV_RELEASE_STATE_PATH" not in source
    assert "QDEV_RELEASE_LOCK_PATH" not in source
    assert "QDEV_RELEASE_NATIVE" not in source
    assert "total.kz" not in source
    assert "ssh" not in source.lower()
