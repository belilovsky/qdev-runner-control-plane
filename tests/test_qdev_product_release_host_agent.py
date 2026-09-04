import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qdev_product_release_host_agent.py"
SPEC = importlib.util.spec_from_file_location("qdev_product_release_host_agent", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AGENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AGENT
SPEC.loader.exec_module(AGENT)

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


@pytest.mark.parametrize("name", ["qaz-fund", "qaz-events", "qmt"])
def test_product_agent_binds_jobs_to_fixed_lane_and_registry(name: str) -> None:
    profile = AGENT.PROFILES[name]
    reference = f"registry.ci.qdev.run/{profile.repository}@{DIGEST}"
    release = {"source_sha": SHA, "artifact_digest": DIGEST, "artifact_ref": reference}
    assert AGENT._release(release, profile) == release
    with pytest.raises(AGENT.AgentError):
        AGENT._release({**release, "artifact_ref": "unsafe:latest"}, profile)
    job = {
        "schema": "qdev-release-host-agent-job-v1",
        "release_id": "release-1",
        "release_lane": profile.lane,
        "project_id": profile.project,
        "placement": profile.placement,
        **release,
    }
    assert AGENT.validate_job(job, profile) == ("release-1", release)
    with pytest.raises(AGENT.AgentError):
        AGENT.validate_job({**job, "placement": "other-host"}, profile)


def test_product_agent_is_no_build_and_proves_public_identity() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert '"--no-build"' in script
    assert '"--pull", "never"' in script
    assert "https://qaz.fund/.well-known/release.json" in script
    assert "https://qaz.events/.well-known/qdev-ecosystem.json" in script
    assert "https://qmt.digital/release.json" in script
    assert "qdev-release-qmt" in script
    assert "QMT_IMAGE" in script
    assert "preloaded_image_required" in script
    assert "docker system prune" not in script
    assert "docker image prune" not in script
    assert "runtime_proof(profile, active)" in script
