"""Fault injection of real durable journals; Docker/network are explicit test doubles."""

import copy
import errno
import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest
from test_qdev_product_release_host_agent import AGENT


def release(profile, char):
    digest = "sha256:" + char * 64
    return {
        "source_sha": char * 40,
        "artifact_digest": digest,
        "artifact_ref": f"registry.ci.qdev.run/{profile.repository}@{digest}",
    }


def image(value, version="4.4.2"):
    return {
        "Id": "sha256:" + value["source_sha"][0] * 64,
        "RepoDigests": [value["artifact_ref"]],
        "Config": {
            "Labels": {
                "org.opencontainers.image.revision": value["source_sha"],
                "org.opencontainers.image.version": version,
            }
        },
    }


@pytest.fixture
def transaction(tmp_path, monkeypatch):
    p = AGENT.PROFILES["qmt"]
    config = AGENT.Config(
        "https://worker.ci.qdev.run",
        tmp_path / "cert",
        tmp_path / "key",
        tmp_path / "ca",
        tmp_path / "state.json",
        tmp_path / "lock",
    )
    old, previous, candidate = (release(p, char) for char in ("b", "c", "a"))
    t = {"composed": [], "runtime": [], "acks": [], "restored": []}
    # The test runner need not be root. This exemption is test-local; file
    # writes, fsync, atomic replace, operation serialization are real.
    monkeypatch.setattr(AGENT, "_private", lambda *a, **kw: None)
    AGENT.write_state(config.state_path, old, previous)
    monkeypatch.setattr(
        AGENT,
        "verify_image",
        lambda value, *a, **kw: image(value, "4.3.1" if value == old else "4.4.2"),
    )
    monkeypatch.setattr(
        AGENT,
        "container_proof",
        lambda p, value: {
            "image_id": image(value)["Id"],
            "services": {service: image(value)["Id"] for service in p.services},
        },
    )

    def runtime(_profile, value, **kwargs):
        t["runtime"].append((value, kwargs.get("expected_version")))
        return {"local": "ok", "startup": "ok", "public": "ok"}

    def acknowledge(_config, _profile, job, receipt, **kwargs):
        state = AGENT.read_state(config.state_path, p)[0]
        assert state == (old if kwargs.get("rollback") else candidate)
        t["acks"].append(copy.deepcopy(receipt))

    monkeypatch.setattr(AGENT, "runtime_proof", runtime)
    monkeypatch.setattr(AGENT, "snapshot_config", lambda *a: [{"sha256": "f" * 64, "mode": 0o600}])
    monkeypatch.setattr(AGENT, "restore_config", lambda *a: t["restored"].append(True))
    monkeypatch.setattr(AGENT, "verify_config", lambda *a: None)
    monkeypatch.setattr(AGENT, "_compose", lambda p, value: t["composed"].append(value))
    t["acknowledge"] = AGENT.acknowledge
    monkeypatch.setattr(AGENT, "acknowledge", acknowledge)
    job = {
        "schema": "qdev-release-host-agent-job-v1",
        "release_id": "release-1",
        "release_lane": p.lane,
        "project_id": p.project,
        "placement": p.placement,
        "lease_id": "L" * 24,
        "fence": "f" * 24,
        **candidate,
    }
    t.update(config=config, profile=p, old=old, previous=previous, candidate=candidate, job=job)
    return t


def execute(t):
    return AGENT.execute_job(t["config"], t["profile"], t["job"], t["old"], t["previous"])


def operation(t):
    return json.loads(AGENT._operation_path(t["config"]).read_text())


def test_success_is_durable_and_preserves_own_rollback_version(transaction):
    t = transaction
    assert execute(t)["status"] == "verified"
    assert operation(t)["previous_version"] == "4.3.1"
    assert (t["old"], "4.3.1") in t["runtime"]
    assert (t["candidate"], "4.4.2") in t["runtime"]
    assert t["composed"] == [t["candidate"]]
    AGENT.archive_operation(t["config"], t["profile"], operation(t))
    AGENT.archive_operation(t["config"], t["profile"], operation(t))
    changed = operation(t)
    changed["previous_version"] = "4.3.0"
    with pytest.raises(AGENT.AgentError, match="cannot be replaced"):
        AGENT.archive_operation(t["config"], t["profile"], changed)


@pytest.mark.parametrize("failure", ["pull", "start", "health_json", "state", "journal"])
def test_failures_restore_previous_without_false_success(transaction, monkeypatch, failure):
    t = transaction
    if failure == "pull":
        original = AGENT.verify_image

        def verify(value, *args, **kwargs):
            if value == t["candidate"]:
                raise AGENT.AgentError("pull failed")
            return original(value, *args, **kwargs)

        monkeypatch.setattr(AGENT, "verify_image", verify)
    elif failure == "start":

        def compose(_profile, value):
            t["composed"].append(value)
            if value == t["candidate"]:
                raise AGENT.AgentError("start failed")

        monkeypatch.setattr(AGENT, "_compose", compose)
    elif failure == "health_json":
        original = AGENT.runtime_proof

        def runtime(profile, value, **kwargs):
            if value == t["candidate"]:
                raise ValueError("bad JSON")
            return original(profile, value, **kwargs)

        monkeypatch.setattr(AGENT, "runtime_proof", runtime)
    else:
        original = AGENT._write_json

        def write(path, document):
            if (
                failure == "state"
                and document.get("active_release") == t["candidate"]
                or failure == "journal"
                and document.get("phase") == "ack_pending"
            ):
                raise OSError("metadata write failed")
            original(path, document)

        monkeypatch.setattr(AGENT, "_write_json", write)
    assert execute(t)["status"] == "rolled_back"
    assert t["composed"][-1] == t["old"] and t["restored"] == [True]
    assert len(t["acks"]) == 1 and t["acks"][0]["status"] == "rolled_back"
    assert (t["old"], "4.3.1") in t["runtime"]


def test_full_disk_does_not_prevent_physical_rollback(transaction, monkeypatch):
    t = transaction
    original = AGENT._write_json

    def write(path, document):
        if t["composed"]:
            raise OSError("disk full")
        original(path, document)

    monkeypatch.setattr(AGENT, "_write_json", write)
    with pytest.raises(OSError):
        execute(t)
    assert t["composed"] == [t["candidate"], t["old"]] and not t["acks"]
    assert operation(t)["phase"] == "applying"
    monkeypatch.setattr(AGENT, "_write_json", original)
    assert (
        AGENT.resume_operation(t["config"], t["profile"], operation(t))["status"] == "rolled_back"
    )


def test_real_configuration_restore_needs_no_new_file_allocation(tmp_path, monkeypatch):
    config = tmp_path / "compose.yml"
    environment = tmp_path / "runtime.env"
    for path in (config, environment):
        path.write_bytes(b"original\n")
        path.chmod(0o600)
    profile = replace(
        AGENT.PROFILES["qmt"],
        compose_files=(config,),
        runtime_env=environment,
        controller_overlay=None,
    )
    # Simulate privileged ownership only; snapshot, restore, fsync, rename and
    # every byte of both the immutable and reserve copies are real.
    original_lstat, original_stat = Path.lstat, Path.stat
    for name, original in (("lstat", original_lstat), ("stat", original_stat)):

        def info(path, *args, _original=original, **kwargs):
            value = _original(path, *args, **kwargs)
            return SimpleNamespace(st_uid=0, st_mode=value.st_mode)

        monkeypatch.setattr(Path, name, info)
    monkeypatch.setattr(AGENT, "_private", lambda *a, **kw: None)
    directory = tmp_path / "snapshot"
    records = AGENT.snapshot_config(profile, directory)
    config.write_bytes(b"candidate\n")
    environment.unlink()

    def full(*a, **kw):
        raise OSError(errno.ENOSPC, "test filesystem full")

    monkeypatch.setattr(AGENT.tempfile, "mkstemp", full)
    AGENT.restore_config(profile, directory, records)
    # The reserve copies have been consumed. Identical recovery is still safe.
    AGENT.restore_config(profile, directory, records)
    assert config.read_bytes() == environment.read_bytes() == b"original\n"
    assert (directory / "0").read_bytes() == b"original\n"


def test_crash_after_container_start_resumes_with_rollback(transaction, monkeypatch):
    t = transaction
    original = AGENT._compose

    def power_loss(profile, value):
        original(profile, value)
        raise SystemExit("simulated power loss")

    monkeypatch.setattr(AGENT, "_compose", power_loss)
    with pytest.raises(SystemExit):
        execute(t)
    assert operation(t)["phase"] == "applying"
    monkeypatch.setattr(AGENT, "_compose", original)
    assert (
        AGENT.resume_operation(t["config"], t["profile"], operation(t))["status"] == "rolled_back"
    )
    assert t["composed"] == [t["candidate"], t["old"]]


def test_lost_ack_is_fenced_idempotent_and_never_redeploys(transaction, monkeypatch):
    t = transaction
    calls = []

    def request(config, method, path, payload, **kwargs):
        calls.append((path, copy.deepcopy(payload), kwargs))
        assert AGENT.read_state(config.state_path, t["profile"])[0] == t["candidate"]
        return (200, b"not-json") if len(calls) == 1 else (200, json.dumps(payload).encode())

    monkeypatch.setattr(AGENT, "acknowledge", t["acknowledge"])
    monkeypatch.setattr(AGENT, "request", request)
    with pytest.raises(AGENT.AcknowledgementPending):
        execute(t)
    assert operation(t)["phase"] == "ack_pending"
    assert AGENT.resume_operation(t["config"], t["profile"], operation(t))["status"] == "verified"
    assert calls[0] == calls[1] and calls[0][2]["headers"] == AGENT._headers(t["job"])
    assert "?release_lane=qdev-release-qmt" in calls[0][0]
    assert t["composed"] == [t["candidate"]]


@pytest.mark.parametrize("field", ["Image", "Config.Image", "State.Running", "service"])
def test_running_container_proof_rejects_substitution(monkeypatch, field):
    p = AGENT.PROFILES["qmt"]
    value = release(p, "a")
    expected_image = image(value)
    container = {
        "Image": expected_image["Id"],
        "State": {"Running": True},
        "Config": {
            "Image": value["artifact_ref"],
            "Labels": {
                "com.docker.compose.project": p.name,
                "com.docker.compose.service": p.services[0],
            },
        },
    }
    if field == "Image":
        container["Image"] = "sha256:" + "d" * 64
    elif field == "Config.Image":
        container["Config"]["Image"] = "mutable:latest"
    elif field == "State.Running":
        container["State"]["Running"] = False
    else:
        container["Config"]["Labels"]["com.docker.compose.service"] = "other"
    monkeypatch.setattr(AGENT, "verify_image", lambda *a, **kw: expected_image)
    monkeypatch.setattr(AGENT, "_compose_command", lambda *a: (["compose"], {}))

    def run(command, **kwargs):
        return ("a" * 64).encode() if command[0] == "compose" else json.dumps([container]).encode()

    monkeypatch.setattr(AGENT, "_run", run)
    with pytest.raises(AGENT.AgentError, match="running container"):
        AGENT.container_proof(p, value)
