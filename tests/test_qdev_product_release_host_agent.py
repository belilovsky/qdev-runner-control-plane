import importlib.util
import sys
from dataclasses import replace
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


def test_qmt_requires_a_preloaded_digest_and_never_pulls(monkeypatch: pytest.MonkeyPatch) -> None:
    profile = AGENT.PROFILES["qmt"]
    release = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/kaztilshi@{DIGEST}",
    }
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> bytes:
        commands.append(command)
        if any("RepoDigests" in token for token in command):
            return f'["{release["artifact_ref"]}"]'.encode()
        return SHA.encode()

    monkeypatch.setattr(AGENT, "_run", fake_run)
    AGENT.verify_image(release, profile)
    assert ["docker", "pull", release["artifact_ref"]] not in commands


def test_qgeo_materializes_static_from_candidate_image_idempotently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = replace(
        AGENT.PROFILES["qazgeo"],
        static_directory_root=tmp_path / "static",
        rollback_static_directory=tmp_path / "rollback",
    )
    release = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/belilovsky/qazgeo@{DIGEST}",
    }
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> bytes:
        commands.append(command)
        if command[:2] == ["docker", "create"]:
            return b"candidate-container\n"
        if command[:2] == ["docker", "cp"]:
            destination = Path(command[-1])
            (destination / "css").mkdir()
            (destination / "css" / "app.css").write_text("candidate", encoding="utf-8")
            return b""
        if command[:3] == ["docker", "rm", "--force"]:
            return b""
        raise AssertionError(command)

    monkeypatch.setattr(AGENT, "_run", fake_run)
    first = AGENT.materialize_static(release, profile)
    second = AGENT.materialize_static(release, profile)
    assert first == second
    assert first is not None and first["digest"].startswith("sha256:")
    assert (tmp_path / "static" / SHA / "css" / "app.css").read_text() == "candidate"
    assert sum(command[:2] == ["docker", "create"] for command in commands) == 1


def test_qgeo_materialization_rejects_unproven_existing_static_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = replace(
        AGENT.PROFILES["qazgeo"],
        static_directory_root=tmp_path / "static",
        rollback_static_directory=tmp_path / "rollback",
    )
    release = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/belilovsky/qazgeo@{DIGEST}",
    }
    target = profile.static_directory_root / SHA
    target.mkdir(parents=True)
    (target / "app.css").write_text("unknown", encoding="utf-8")
    monkeypatch.setattr(AGENT, "_run", lambda *_args, **_kwargs: b"")
    with pytest.raises(AGENT.AgentError, match="without proof"):
        AGENT.materialize_static(release, profile)
