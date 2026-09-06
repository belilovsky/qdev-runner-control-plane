from __future__ import annotations

import hashlib
import hmac
import importlib.util
import io
import json
import subprocess
import sys
import tarfile
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qdev_runner_recovery_host_agent.py"
SPEC = importlib.util.spec_from_file_location("qdev_runner_recovery_host_agent", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AGENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AGENT
SPEC.loader.exec_module(AGENT)

SHA = "a" * 40
HEX_DIGEST = "b" * 64
DIGEST = "sha256:" + "c" * 64
NOW = datetime(2026, 9, 5, 12, tzinfo=UTC)


def _config(tmp_path: Path) -> Any:
    return AGENT.Config(
        controller_url="https://worker.ci.qdev.run",
        client_cert=tmp_path / "agent.pem",
        client_key=tmp_path / "agent-key.pem",
        controller_ca=tmp_path / "ca.pem",
        command_verification_key="command-verification-key-with-32-bytes",
        reconcile_signing_key="reconcile-signing-key-with-32-bytes",
        state_path=tmp_path / "state.json",
        lock_path=tmp_path / "agent.lock",
        receipts_dir=tmp_path / "receipts",
        expected_controller_revision=SHA,
        expected_controller_release_digest=HEX_DIGEST,
        expected_policy_digest=DIGEST,
        expected_agent_release_digest="sha256:" + "d" * 64,
        expected_interface_version="qdev-worker-recovery-v2",
        expected_interface_digest="e" * 64,
    )


def _command(profile: Any, config: Any, *, provider_runner_id: int | None = None) -> dict[str, Any]:
    command: dict[str, Any] = {
        "schema": "qdev-runner-recovery-agent-command-v1",
        "operation_id": "1" * 64,
        "request_fingerprint": "2" * 64,
        "target_id": profile.target_id,
        "worker_name": profile.worker_name,
        "repository": profile.repository,
        "provider_runner_id": (
            profile.expected_provider_runner_id
            if profile.expected_provider_runner_id is not None
            else (279 if provider_runner_id is None else provider_runner_id)
        ),
        "labels": list(profile.labels),
        "recovery_action": profile.recovery_action,
        "operator_certificate_sha256": "3" * 64,
        "expected_agent_certificate_sha256": "4" * 64,
        "interface_version": config.expected_interface_version,
        "interface_digest": config.expected_interface_digest,
        "controller_revision": config.expected_controller_revision,
        "controller_release_digest": config.expected_controller_release_digest,
        "controller_receipt_id": "5" * 64,
        "policy_digest": config.expected_policy_digest,
        "agent_release_digest": config.expected_agent_release_digest,
        "provider_idle_proof_digest": "sha256:" + "6" * 64,
        "provider_reconciliation_digest": "sha256:" + "7" * 64,
        "request_nonce": "recovery-nonce-001",
        "issued_at": NOW.isoformat().replace("+00:00", "Z"),
        "expires_at": (NOW + timedelta(seconds=90)).isoformat().replace("+00:00", "Z"),
        "registration_token": None,
        "registration_token_expires_at": None,
    }
    if profile.recovery_action == "replace_existing_registration":
        command["registration_token"] = "short-lived-registration-token"  # noqa: S105
        command["registration_token_expires_at"] = (
            (NOW + timedelta(minutes=5)).isoformat().replace("+00:00", "Z")
        )
    return command


def _envelope(command: dict[str, Any], config: Any) -> dict[str, Any]:
    canonical = AGENT._canonical(command)
    return {
        "schema": "qdev-runner-recovery-agent-envelope-v1",
        "command": command,
        "command_digest": "sha256:" + hashlib.sha256(canonical).hexdigest(),
        "signature": hmac.new(
            config.command_verification_key.encode(), canonical, hashlib.sha256
        ).hexdigest(),
    }


@pytest.mark.parametrize("profile_name", ["platform", "qazstack"])
def test_signed_command_is_bound_to_one_compiled_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, profile_name: str
) -> None:
    profile = AGENT.PROFILES[profile_name]
    config = _config(tmp_path)
    command = _command(profile, config)
    monkeypatch.setattr(AGENT, "_certificate_sha256", lambda _path: "4" * 64)

    assert AGENT.validate_envelope(_envelope(command, config), profile, config, now=NOW) == command

    command["repository"] = "belilovsky/other"
    with pytest.raises(AGENT.AgentError, match="fixed profile"):
        AGENT.validate_envelope(_envelope(command, config), profile, config, now=NOW)


def test_replacement_target_accepts_absent_provider_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = AGENT.PROFILES["qazstack"]
    config = _config(tmp_path)
    command = _command(profile, config)
    command["provider_runner_id"] = None
    monkeypatch.setattr(AGENT, "_certificate_sha256", lambda _path: "4" * 64)

    assert AGENT.validate_envelope(_envelope(command, config), profile, config, now=NOW) == command


def test_saved_configuration_target_rejects_absent_provider_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = AGENT.PROFILES["platform"]
    config = _config(tmp_path)
    command = _command(profile, config)
    command["provider_runner_id"] = None
    monkeypatch.setattr(AGENT, "_certificate_sha256", lambda _path: "4" * 64)

    with pytest.raises(AGENT.AgentError, match="provider runner id is invalid"):
        AGENT.validate_envelope(_envelope(command, config), profile, config, now=NOW)


def test_signed_command_rejects_extra_fields_and_expired_validity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = AGENT.PROFILES["platform"]
    config = _config(tmp_path)
    monkeypatch.setattr(AGENT, "_certificate_sha256", lambda _path: "4" * 64)
    command = _command(profile, config)
    command["host"] = "caller-selected-host"
    with pytest.raises(AGENT.AgentError, match="fields"):
        AGENT.validate_envelope(_envelope(command, config), profile, config, now=NOW)

    command = _command(profile, config)
    with pytest.raises(AGENT.AgentError, match="currently valid"):
        AGENT.validate_envelope(
            _envelope(command, config), profile, config, now=NOW + timedelta(minutes=3)
        )


def test_archive_validation_rejects_traversing_links(tmp_path: Path) -> None:
    archive = tmp_path / "runner.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        regular = tarfile.TarInfo("bin/Runner.Listener")
        payload = b"runner"
        regular.size = len(payload)
        bundle.addfile(regular, io.BytesIO(payload))
        link = tarfile.TarInfo("bin/escape")
        link.type = tarfile.SYMTYPE
        link.linkname = "../../outside"
        bundle.addfile(link)

    with pytest.raises(AGENT.AgentError, match="unsafe link"):
        AGENT._safe_archive(archive)


def test_archive_validation_accepts_relative_link_that_stays_inside_root(tmp_path: Path) -> None:
    archive = tmp_path / "runner.tar.gz"
    with tarfile.open(archive, "w:gz") as bundle:
        regular = tarfile.TarInfo("externals/node24/lib/node_modules/npm/bin/npm-cli.js")
        payload = b"runner"
        regular.size = len(payload)
        bundle.addfile(regular, io.BytesIO(payload))
        link = tarfile.TarInfo("externals/node24/bin/npm")
        link.type = tarfile.SYMTYPE
        link.linkname = "../lib/node_modules/npm/bin/npm-cli.js"
        bundle.addfile(link)

    AGENT._safe_archive(archive)


def test_qazstack_partial_registration_is_ambiguous(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner_root = tmp_path / "qazstack-ci"
    runner_root.mkdir()
    profile = replace(AGENT.PROFILES["qazstack"], runner_root=runner_root)
    monkeypatch.setattr(AGENT, "_qazstack_identity", lambda _profile: False)
    monkeypatch.setattr(
        AGENT.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "not-found\n", ""),
    )

    with pytest.raises(AGENT.ExecutionFailure) as failure:
        AGENT._recover_qazstack(profile, {})

    assert failure.value.outcome == "ambiguous"
    assert failure.value.proof == {
        "mutation": "preexisting_or_interrupted",
        "rollback": "unavailable",
    }
    assert runner_root.is_dir()


def test_config_rejects_duplicate_keys(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    config_path = tmp_path / "recovery.env"
    config_path.write_text("QDEV_RECOVERY_CONTROLLER_URL=https://worker.ci.qdev.run\n" * 2)
    monkeypatch.setattr(AGENT, "_private", lambda *_args, **_kwargs: None)

    with pytest.raises(AGENT.AgentError, match="invalid line"):
        AGENT.load_config(config_path)


def test_private_file_check_rejects_symlinks(tmp_path: Path) -> None:
    target = tmp_path / "target.pem"
    target.write_text("certificate", encoding="utf-8")
    target.chmod(0o600)
    link = tmp_path / "agent.pem"
    link.symlink_to(target)

    with pytest.raises(AGENT.AgentError, match="root-owned and private"):
        AGENT._private(link)


def test_qazstack_recovery_rejects_group_writable_runner_parent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner_parent = tmp_path / "github-runners"
    runner_parent.mkdir(mode=0o770)
    runner_parent.chmod(0o770)
    profile = replace(AGENT.PROFILES["qazstack"], runner_root=runner_parent / "qazstack-ci")
    monkeypatch.setattr(AGENT, "_qazstack_identity", lambda _profile: False)
    monkeypatch.setattr(
        AGENT.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "not-found\n", ""),
    )
    monkeypatch.setattr(
        AGENT.pwd,
        "getpwnam",
        lambda _user: SimpleNamespace(pw_uid=123, pw_gid=123),
    )

    with pytest.raises(AGENT.ExecutionFailure, match="parent is absent or unsafe") as failure:
        AGENT._recover_qazstack(profile, {"registration_token": "unused"})

    assert failure.value.outcome == "not_applied"
    assert failure.value.proof == {"mutation": "none", "rollback": "not_required"}


def test_controller_request_uses_one_fixed_mtls_ca_argument(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = _config(tmp_path)
    observed: list[str] = []

    def fake_run(arguments: list[str], **_kwargs: Any) -> bytes:
        observed.extend(arguments)
        return b"{}\n200"

    monkeypatch.setattr(AGENT, "_run", fake_run)

    status, body = AGENT.request(config, "/internal/v1/worker-recovery/claim", {})

    assert (status, body) == (200, b"{}")
    assert observed.count("--cacert") == 1
    ca_index = observed.index("--cacert")
    assert observed[ca_index + 1] == str(config.controller_ca)
    assert observed[-1] == "https://worker.ci.qdev.run/internal/v1/worker-recovery/claim"


def test_qazstack_registration_attempt_failure_preserves_ambiguous_state(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner_root = tmp_path / "runners" / "qazstack-ci"
    runner_root.parent.mkdir()
    profile = replace(AGENT.PROFILES["qazstack"], runner_root=runner_root)
    command = {"registration_token": "short-lived-token"}
    calls: list[list[str]] = []

    monkeypatch.setattr(AGENT, "_qazstack_identity", lambda _profile: False)
    monkeypatch.setattr(
        AGENT.subprocess,
        "run",
        lambda *_args, **_kwargs: subprocess.CompletedProcess([], 0, "not-found\n", ""),
    )
    monkeypatch.setattr(
        AGENT.pwd,
        "getpwnam",
        lambda _user: SimpleNamespace(pw_uid=123, pw_gid=123),
    )
    monkeypatch.setattr(AGENT, "_sha256_file", lambda _path: AGENT._RUNNER_ARCHIVE_SHA256)
    monkeypatch.setattr(AGENT, "_safe_archive", lambda _path: None)

    def fake_run(arguments: list[str], **_kwargs: Any) -> bytes:
        calls.append(arguments)
        if arguments[0] == "curl":
            Path(arguments[arguments.index("--output") + 1]).write_bytes(b"archive")
        if arguments[0] == "runuser":
            raise AGENT.AgentError("registration failed")
        return b""

    monkeypatch.setattr(AGENT, "_run", fake_run)

    with pytest.raises(AGENT.ExecutionFailure) as failure:
        AGENT._recover_qazstack(profile, command)

    assert failure.value.outcome == "ambiguous"
    assert failure.value.proof["mutation"] == "provider_registration_attempted"
    assert failure.value.proof["rollback"] == "unavailable_after_provider_registration"
    assert runner_root.is_dir()
    runuser = next(arguments for arguments in calls if arguments[0] == "runuser")
    assert runuser[4:7] == ["env", f"HOME={runner_root}", "RUNNER_ALLOW_RUNASROOT=0"]


def test_native_receipt_excludes_registration_token(tmp_path: Path) -> None:
    profile = AGENT.PROFILES["qazstack"]
    config = _config(tmp_path)
    command = _command(profile, config)

    payload, private_proof = AGENT._reconcile_payload(
        profile, command, "completed", {"service": "active_enabled"}, config
    )

    assert "registration_token" not in repr((payload, private_proof))
    assert payload["agent_release_digest"] == config.expected_agent_release_digest


def test_host_agent_has_no_general_remote_execution_surface() -> None:
    script = SCRIPT.read_text(encoding="utf-8")

    assert "shell=True" not in script
    assert " ssh " not in script
    assert "--profile" in script
    assert set(AGENT.PROFILES) == {"platform", "qazstack"}
    assert {profile.target_id for profile in AGENT.PROFILES.values()} == {
        "qdev-platform-ci-187",
        "qdev-qazstack-01",
    }


def test_host_agent_release_digest_is_canonical_and_target_independent() -> None:
    installer = ROOT / "scripts/install_qdev_runner_recovery_host_agent.sh"
    artifact_paths = [
        "deploy/qdev-runner-recovery-platform.service",
        "deploy/qdev-runner-recovery-qazstack.service",
        "scripts/install_qdev_runner_recovery_host_agent.sh",
        "scripts/qdev_runner_recovery_host_agent.py",
    ]
    manifest = {
        "schema": "qdev-runner-recovery-agent-release-v1",
        "artifacts": [
            {
                "path": path,
                "sha256": f"sha256:{hashlib.sha256((ROOT / path).read_bytes()).hexdigest()}",
            }
            for path in artifact_paths
        ],
    }
    canonical = json.dumps(
        manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True
    ).encode()
    expected = f"sha256:{hashlib.sha256(canonical).hexdigest()}"

    observed = {
        subprocess.run(  # noqa: S603
            [str(installer), "--profile", profile, "--digest-only"],
            capture_output=True,
            check=True,
            text=True,
        ).stdout.strip()
        for profile in ("platform", "qazstack")
    }

    assert observed == {expected}

    installer_text = installer.read_text(encoding="utf-8")
    assert '"$install_root" "$install_root/releases"' in installer_text
    assert '! -d "$directory" || -L "$directory"' in installer_text
    assert '! -d "$release_root" || -L "$release_root"' in installer_text


@pytest.mark.parametrize("profile", ["platform", "qazstack"])
def test_recovery_service_is_bound_to_one_fixed_profile(profile: str) -> None:
    unit = (ROOT / f"deploy/qdev-runner-recovery-{profile}.service").read_text(encoding="utf-8")

    assert f"--profile {profile}" in unit
    assert f"/etc/qdev-runner-recovery/{profile}.env" in unit
    assert "User=root" in unit
    assert "Type=oneshot" in unit
    assert "EnvironmentFile=" not in unit
