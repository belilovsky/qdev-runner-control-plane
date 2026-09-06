"""Fixed installed entrypoint with real private reads and synthetic authority."""

import json
import os
from dataclasses import replace

import pytest
from test_file_apply_authorization import KEY, NOW
from test_idp_input_intake import inputs as inputs_fixture
from test_idp_native_invocation import AGENT
from test_idp_retained_dispatch import TRANSACTION

from qdev_runner import idp_retained_dispatch as storage
from qdev_runner.idp_native_bundle import VerifiedNativeBundle
from qdev_runner.release_lane import sign_host_dispatch_claim

inputs = inputs_fixture


@pytest.fixture
def host(inputs, monkeypatch):
    root = storage.ROOT.parent
    profile = replace(
        AGENT.IDP_PROFILE,
        state_path=inputs.profile.state_path,
        lock_path=inputs.profile.lock_path,
    )
    monkeypatch.setattr(AGENT, "IDP_PROFILE", profile)
    inputs.profile, inputs.lane = profile, AGENT._idp_lane()
    inputs.config = replace(inputs.config, host_identity=inputs.lane.host_agent_mtls_identity)
    inputs.job["placement"] = profile.placement
    inputs.job["dispatch_claim"].update(
        placement=profile.placement,
        host_identity=inputs.config.host_identity,
    )
    inputs.job["dispatch_claim_signature"] = sign_host_dispatch_claim(
        inputs.job["dispatch_claim"],
        signing_key=KEY,
    )
    inputs.response["job"] = json.loads(json.dumps(inputs.job))
    inputs.stage = root / "releases" / TRANSACTION
    inputs.stage.mkdir(parents=True, mode=0o700)
    monkeypatch.setattr(AGENT.IdPNativeInvocation, "STATE_ROOT", inputs.stage.parent)
    config = root / "idp.env"
    cert, key, ca, secret = (root / name for name in ("cert", "key", "ca", "secret"))
    for path in (cert, key, ca, secret):
        path.write_bytes(KEY if path == secret else b"synthetic-credential-not-production")
        path.chmod(0o600)
    config.write_text(
        "\n".join(
            [
                "QDEV_RELEASE_CONTROLLER_URL=https://worker.ci.qdev.run",
                f"QDEV_RELEASE_AGENT_CERT={cert}",
                f"QDEV_RELEASE_AGENT_KEY={key}",
                f"QDEV_RELEASE_CONTROLLER_CA={ca}",
                f"QDEV_RELEASE_HOST_IDENTITY={inputs.config.host_identity}",
                f"QDEV_RELEASE_DISPATCH_SECRET_FILE={secret}",
            ]
        )
        + "\n"
    )
    config.chmod(0o600)
    inputs.config_path = config
    inputs.config = replace(inputs.config, client_cert=cert, client_key=key, controller_ca=ca)
    monkeypatch.setattr(AGENT, "IDP_CONFIG_PATH", config)
    monkeypatch.setattr(AGENT, "_require_idp_host", lambda: None)
    monkeypatch.setattr(AGENT, "run_once", lambda *a: pytest.fail("generic poll/host lock"))
    for name, value in (
        ("controller-job.json", json.dumps(inputs.job).encode()),
        ("artifact.tar.gz", inputs.archive),
    ):
        path = inputs.stage / name
        path.write_bytes(value)
        path.chmod(0o600)
    return inputs


def run(action="intake", ci="none"):
    return AGENT.run_idp_once(transaction=TRANSACTION, action=action, ci=ci)


def test_cli_intake_and_expired_exact_retry_without_network_or_rewrite(host, monkeypatch, capsys):
    assert AGENT.main(["idp", "intake", "--transaction", TRANSACTION]) == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "retained" and len(host.calls) == 1
    snapshots = {
        p.name: (p.read_bytes(), p.stat().st_ino) for p in (storage.ROOT / TRANSACTION).iterdir()
    }
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    monkeypatch.setattr(AGENT, "request", lambda *a, **k: pytest.fail("network retry"))
    monkeypatch.setattr(storage, "_write_file", lambda *a, **k: pytest.fail("overwrite"))
    assert run() == result
    assert snapshots == {
        p.name: (p.read_bytes(), p.stat().st_ino) for p in (storage.ROOT / TRANSACTION).iterdir()
    }
    with pytest.raises(AGENT.AgentError):
        run("apply", "ci-0123456789abcdef.json")


def test_initial_inspect_does_not_need_uploads_or_run_helpers(host):
    for path in host.stage.iterdir():
        path.unlink()
    assert run("inspect")["status"] == "inputs_not_published"
    assert not host.calls and not storage.ROOT.exists()


def test_publication_sync_failure_recovers_expired_without_a_second_get(host, monkeypatch):
    fsync = os.fsync

    def fail_after_publication(fd):
        if (
            storage.ROOT.exists()
            and os.fstat(fd).st_ino == storage.ROOT.stat().st_ino
            and (storage.ROOT / TRANSACTION).exists()
        ):
            raise OSError("synthetic-private-sync-error")
        return fsync(fd)

    monkeypatch.setattr(storage.os, "fsync", fail_after_publication)
    with pytest.raises(AGENT.AgentError):
        run()
    assert storage.read(TRANSACTION)[0]["job"] == host.job
    monkeypatch.setattr(storage.os, "fsync", fsync)
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    assert run()["status"] == "retained" and len(host.calls) == 1


def test_expired_unpublished_intake_cannot_contact_controller(host, monkeypatch):
    monkeypatch.setattr(AGENT.time, "time", lambda: NOW + 1000)
    with pytest.raises(AGENT.AgentError):
        run()
    assert not storage.ROOT.exists() and not host.calls


@pytest.mark.parametrize("action", ["apply", "inspect", "reconcile", "observe"])
def test_retained_actions_enter_native_without_outer_host_lock_or_poll(host, monkeypatch, action):
    run()
    calls = []

    def invoke(self, archive, **kwargs):
        assert archive == host.archive
        assert kwargs == dict(action=action, transaction=TRANSACTION, ci="ci-0123456789abcdef.json")
        assert self._profile == host.profile and self._lane == host.lane
        calls.append(action)
        return {"synthetic": True}

    monkeypatch.setattr(AGENT.IdPNativeInvocation, "invoke", invoke)
    assert run(action, "ci-0123456789abcdef.json") == {"synthetic": True}
    assert calls == [action] and len(host.calls) == 1


@pytest.mark.parametrize("fault", ["job", "archive"])
def test_conflicting_retry_never_overwrites_or_refreshes_authority(host, fault):
    run()
    path = host.stage / ("controller-job.json" if fault == "job" else "artifact.tar.gz")
    path.write_bytes(b"{}" if fault == "job" else b"different-synthetic-archive")
    with pytest.raises(AGENT.AgentError):
        run()
    assert len(host.calls) == 1
    metadata, archive = storage.read(TRANSACTION)
    assert metadata["job"] == host.job and archive == host.archive


@pytest.mark.parametrize(
    "name",
    [
        "idp.env",
        "secret",
        "cert",
        "key",
        "ca",
        "controller-job.json",
        "artifact.tar.gz",
    ],
)
@pytest.mark.parametrize("fault", ["missing", "symlink", "hardlink", "permissions"])
def test_private_input_failures_are_redacted_and_do_not_publish(host, name, fault, capsys):
    parent = (
        host.stage
        if name in {"controller-job.json", "artifact.tar.gz"}
        else host.config_path.parent
    )
    path = parent / name
    if fault == "missing":
        path.unlink()
    elif fault == "permissions":
        path.chmod(0o644)
    else:
        outside = path.with_suffix(".outside")
        if fault == "symlink":
            path.rename(outside)
            path.symlink_to(outside)
        else:
            outside.hardlink_to(path)
    assert AGENT.main(["idp", "intake", "--transaction", TRANSACTION]) == 1
    output = capsys.readouterr()
    assert not output.out and "synthetic-credential" not in output.err
    assert str(host.config_path.parent) not in output.err
    assert json.loads(output.err)["status"] == "blocked"
    assert not storage.ROOT.exists()


@pytest.mark.parametrize("target", ["config", "stage"])
def test_symlink_ancestor_rejected(host, monkeypatch, target):
    alias = host.config_path.parent / "alias"
    alias.symlink_to(host.config_path.parent, target_is_directory=True)
    if target == "config":
        monkeypatch.setattr(AGENT, "IDP_CONFIG_PATH", alias / "idp.env")
    else:
        monkeypatch.setattr(AGENT.IdPNativeInvocation, "STATE_ROOT", alias / "releases")
    with pytest.raises(AGENT.AgentError):
        run()
    assert not storage.ROOT.exists() and not host.calls


@pytest.mark.parametrize(
    "value",
    [
        "https://worker.ci.qdev.run:444",
        "https://user@worker.ci.qdev.run",
        "https://other.invalid",
    ],
)
def test_config_cannot_select_another_endpoint(host, value):
    host.config_path.write_text(
        host.config_path.read_text().replace("https://worker.ci.qdev.run", value),
    )
    with pytest.raises(AGENT.AgentError):
        run()
    assert not host.calls


def test_duplicate_config_and_json_fields_rejected_before_network(host):
    original = host.config_path.read_text()
    host.config_path.write_text(original + original.splitlines()[0] + "\n")
    with pytest.raises(AGENT.AgentError):
        run()
    host.config_path.write_text(original)
    (host.stage / "controller-job.json").write_bytes(b'{"source_sha":"a","source_sha":"b"}')
    with pytest.raises(AGENT.AgentError):
        run()
    assert not host.calls


def test_invalid_signature_does_not_read_archive_or_contact_controller(host, monkeypatch):
    from qdev_runner import idp_file_issuer

    host.job["dispatch_claim_signature"] = "0" * 64
    (host.stage / "controller-job.json").write_text(json.dumps(host.job))
    reader = idp_file_issuer.private_bytes

    def read(path, **kwargs):
        assert path.name != "artifact.tar.gz"
        return reader(path, **kwargs)

    monkeypatch.setattr(idp_file_issuer, "private_bytes", read)
    with pytest.raises(AGENT.AgentError):
        run()
    assert not host.calls


@pytest.mark.parametrize("uid,hostname", [(501, "srv1380923"), (0, "srv138jump"), (0, "other")])
def test_real_host_guard_rejects_wrong_placement_or_nonroot(monkeypatch, uid, hostname):
    monkeypatch.setattr(AGENT.os, "geteuid", lambda: uid)
    monkeypatch.setattr(AGENT.socket, "gethostname", lambda: hostname)
    with pytest.raises(AGENT.AgentError):
        AGENT._require_idp_host()


@pytest.mark.parametrize(
    "arguments",
    [
        ["--config", "/untrusted/other"],
        ["--profile", "qmt"],
        ["--target", "/untrusted/other"],
        ["--command", "sh"],
        ["--state-root", "/untrusted/other"],
    ],
)
def test_cli_has_no_arbitrary_paths_profiles_or_commands(arguments):
    with pytest.raises(SystemExit) as error:
        AGENT.main(["idp", "inspect", "--transaction", TRANSACTION, *arguments])
    assert error.value.code == 2 and "idp" not in AGENT.PROFILES


@pytest.mark.parametrize(
    "action,transaction,ci",
    [
        ("apply", TRANSACTION, "none"),
        ("intake", TRANSACTION, "ci-0123456789abcdef.json"),
        ("inspect", "../other-stage", "none"),
        ("observe", TRANSACTION, "../secret"),
        ("rollback", TRANSACTION, "none"),
    ],
)
def test_invalid_operations_never_read_configuration(host, monkeypatch, action, transaction, ci):
    monkeypatch.setattr(AGENT, "load_config", lambda *a, **k: pytest.fail("config read"))
    with pytest.raises(AGENT.AgentError):
        AGENT.run_idp_once(transaction=transaction, action=action, ci=ci)


def test_unknown_native_outcome_is_redacted_and_not_retried(host, monkeypatch, capsys):
    run()
    calls = []

    def invoke(*args, **kwargs):
        calls.append(1)
        raise RuntimeError("synthetic-credential-private-error")

    monkeypatch.setattr(VerifiedNativeBundle, "load", invoke)
    assert (
        AGENT.main(
            [
                "idp",
                "apply",
                "--transaction",
                TRANSACTION,
                "--ci",
                "ci-0123456789abcdef.json",
            ]
        )
        == 1
    )
    output = capsys.readouterr()
    assert "synthetic-credential" not in output.err and not output.out
    assert calls == [1] and len(host.calls) == 1
