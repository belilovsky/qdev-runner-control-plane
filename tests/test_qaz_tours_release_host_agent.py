import importlib.util
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qaz_tours_release_host_agent.py"
SPEC = importlib.util.spec_from_file_location("qaz_tours_release_host_agent", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AGENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AGENT
SPEC.loader.exec_module(AGENT)

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
REFERENCE = f"registry.ci.qdev.run/qaz-tours@{DIGEST}"


def test_release_agent_requires_the_fixed_immutable_registry_reference() -> None:
    release = {"source_sha": SHA, "artifact_digest": DIGEST, "artifact_ref": REFERENCE}

    assert AGENT._release(release) == release
    with pytest.raises(AGENT.AgentError):
        AGENT._release({**release, "artifact_ref": "qaz-tours:latest"})


def test_release_agent_accepts_only_its_controller_job_identity() -> None:
    job = {
        "schema": "qdev-release-host-agent-job-v1",
        "release_id": "release-1",
        "release_lane": "qdev-release-qaz-tours",
        "project_id": "qaz-tours",
        "placement": "vps-hostinger-186",
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": REFERENCE,
    }
    expected_release = {key: job[key] for key in ("source_sha", "artifact_digest", "artifact_ref")}

    assert AGENT.validate_job(job) == ("release-1", expected_release)
    with pytest.raises(AGENT.AgentError):
        AGENT.validate_job({**job, "placement": "other-host"})


def test_release_agent_never_builds_or_prunes_and_proves_public_runtime() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert '"--no-build"' in script
    assert '"--pull",' in script
    assert '"never"' in script
    assert "https://qaz.tours/api/health/live" in script
    assert "docker system prune" not in script
    assert "docker image prune" not in script
    assert "runtime_proof(active)" in script
