import importlib.util
import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qdev_admin_platform_release_host_agent.py"
SPEC = importlib.util.spec_from_file_location("qdev_admin_platform_release_host_agent", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AGENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AGENT
SPEC.loader.exec_module(AGENT)


SHA = "a" * 40
CURRENT_SHA = "c" * 40
DIGEST = "sha256:" + "b" * 64
CURRENT_DIGEST = "sha256:" + "d" * 64


def _release(profile: object, source_sha: str, digest: str) -> dict[str, str]:
    return {
        "source_sha": source_sha,
        "artifact_digest": digest,
        "artifact_ref": f"{profile.artifact_prefix}@{digest}",
    }


def test_unknown_controller_completion_does_not_trigger_native_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = replace(
        AGENT.PROFILES["cmnt"],
        state_path=tmp_path / "state" / "cmnt.json",
        lock_path=tmp_path / "lock" / "cmnt.lock",
    )
    profile.state_path.parent.mkdir()
    profile.lock_path.parent.mkdir()
    monkeypatch.setattr(AGENT, "_root_directory", lambda _path: None)

    active = _release(profile, CURRENT_SHA, CURRENT_DIGEST)
    candidate = _release(profile, SHA, DIGEST)
    job = {
        "schema": "qdev-release-host-agent-job-v1",
        "release_id": "release-unknown-completion",
        "release_lane": profile.lane,
        "project_id": profile.project_id,
        "placement": profile.placement,
        "lease_id": "lease-unknown-completion",
        "fence": "a" * 24,
        **candidate,
    }
    phases: list[str] = []
    rollback_calls: list[object] = []

    def fake_native_receipt(
        _profile: object, release: dict[str, str] | None = None, *, current: bool = False
    ) -> dict[str, object]:
        measured = active if current else (release or active)
        return {
            "schema": AGENT.NATIVE_RECEIPT_SCHEMA,
            "project_id": profile.project_id,
            "native_host_adapter": profile.adapter,
            **measured,
            "readiness": profile.readiness,
        }

    def fake_request(*args: object, **_kwargs: object) -> tuple[int, bytes]:
        path = str(args[2])
        if path.endswith("/heartbeat"):
            return 200, b"{}"
        if path.endswith("/jobs/next"):
            return 200, json.dumps(job).encode()
        raise AssertionError(f"unexpected controller request: {path}")

    def fake_complete(*_args: object, **_kwargs: object) -> None:
        raise AGENT.ControllerTransportError("completion transport is unknown")

    def fake_reconcile(*_args: object, **_kwargs: object) -> None:
        raise AGENT.ControllerTransportError("reconcile transport is unknown")

    monkeypatch.setattr(AGENT, "native_receipt", fake_native_receipt)
    monkeypatch.setattr(
        AGENT,
        "heartbeat",
        lambda *_args, **_kwargs: {"capacity_free_gib": profile.minimum_free_gib},
    )
    monkeypatch.setattr(AGENT, "write_state", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(AGENT, "invoke_native", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        AGENT,
        "_write_journal",
        lambda _profile, phase, **_kwargs: phases.append(phase),
    )
    monkeypatch.setattr(AGENT, "request", fake_request)
    monkeypatch.setattr(AGENT, "complete", fake_complete)
    monkeypatch.setattr(AGENT, "reconcile", fake_reconcile)
    monkeypatch.setattr(
        AGENT,
        "rollback_remote",
        lambda *_args, **_kwargs: rollback_calls.append(True),
    )

    config = AGENT.Config(
        controller_url="https://worker.ci.qdev.run",
        client_cert=tmp_path / "client.crt",
        client_key=tmp_path / "client.key",
        controller_ca=tmp_path / "ca.crt",
    )
    with pytest.raises(AGENT.ControllerOutcomeUnresolved):
        AGENT.run_once(config, profile)

    assert "completion_unresolved" in phases
    assert "rolled_back" not in phases
    assert rollback_calls == []
