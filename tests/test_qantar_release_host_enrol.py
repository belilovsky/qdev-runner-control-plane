from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import sys
import tarfile
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
ROLLBACK = {
    "source_sha": "c" * 40,
    "artifact_digest": "sha256:" + "d" * 64,
    "internal_artifact_digest": "sha256:" + "e" * 64,
    "policy_digest": "sha256:" + "f" * 64,
    "generation": 7,
}


def _load(name: str) -> ModuleType:
    path = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


ENROL = _load("qantar_release_host_enrol_adapter")
APPLY = _load("qantar_release_host_enrol_apply")
PARENT = _load("qdev_release_host_agent_enrol_adapter")


def _request() -> dict[str, Any]:
    return {
        "schema": "qdev-fleet-bootstrap-request-v1",
        "action": "enrol-host-agent",
        "source_sha": SHA,
        "run_id": 101,
        "job_id": 202,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": SHA,
        "controller_release_digest": DIGEST,
        "release_lane": ENROL.TARGET_LANE,
        "worker_name": None,
        "controller_rollback": ROLLBACK,
    }


def _target() -> dict[str, str]:
    return {
        "release_lane": ENROL.TARGET_LANE,
        "project_id": ENROL.TARGET_PROJECT,
        "placement": ENROL.TARGET_PLACEMENT,
        "host_agent_mtls_identity": ENROL.TARGET_IDENTITY,
        "native_host_adapter": ENROL.TARGET_ADAPTER,
        "rollback_reference": ENROL.TARGET_ROLLBACK,
    }


def _tar_bundle(values: dict[str, bytes], *, revision: str = SHA) -> bytes:
    manifest = {
        "schema": APPLY.SCHEMA,
        "controller_revision": revision,
        "controller_release_digest": DIGEST,
        "host_identity": APPLY.HOST_IDENTITY,
        "files": {
            name: f"sha256:{hashlib.sha256(payload).hexdigest()}"
            for name, payload in sorted(values.items())
        },
    }
    payloads = {
        **values,
        "manifest.json": json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(),
    }
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, payload in sorted(payloads.items()):
            member = tarfile.TarInfo(name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def _replace_tar_member(bundle: bytes, name: str, replacement: bytes) -> bytes:
    output = io.BytesIO()
    with tarfile.open(fileobj=io.BytesIO(bundle), mode="r:gz") as source:
        values = {
            member.name: source.extractfile(member).read()
            for member in source.getmembers()
            if member.isfile()
        }
    values[name] = replacement
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for member_name, payload in sorted(values.items()):
            member = tarfile.TarInfo(member_name)
            member.size = len(payload)
            archive.addfile(member, io.BytesIO(payload))
    return output.getvalue()


def test_qantar_fleet_request_is_bound_to_one_controller_and_one_host() -> None:
    envelope = {
        "schema": "qdev-fleet-bootstrap-adapter-request-v1",
        "request": _request(),
        "target": _target(),
    }
    payload = json.dumps(envelope).encode()
    original = ENROL.sys.stdin
    ENROL.sys.stdin = type("Input", (), {"buffer": io.BytesIO(payload)})()
    try:
        parsed_envelope, request, target, rollback = ENROL._parse()
    finally:
        ENROL.sys.stdin = original
    assert parsed_envelope == envelope
    assert request["controller_revision"] == SHA
    assert target == _target()
    assert rollback == ROLLBACK

    malformed = {
        **envelope,
        "target": {**_target(), "host_agent_mtls_identity": "qdev-host-agent:other"},
    }
    ENROL.sys.stdin = type("Input", (), {"buffer": io.BytesIO(json.dumps(malformed).encode())})()
    try:
        with pytest.raises(ENROL.EnrolError, match="request_identity_invalid"):
            ENROL._parse()
    finally:
        ENROL.sys.stdin = original


def test_qantar_ssh_uses_only_the_pinned_root_identity() -> None:
    command = ENROL._ssh_base()
    assert command[0] == str(ENROL.SSH)
    assert "-F" in command and command[command.index("-F") + 1] == "/dev/null"
    assert "StrictHostKeyChecking=yes" in command
    assert f"UserKnownHostsFile={ENROL.KNOWN_HOSTS}" in command
    assert f"root@{ENROL.TARGET_HOST}" == command[-1]
    assert "ssh-keyscan" not in " ".join(command)
    assert "shell=True" not in (ROOT / "scripts/qantar_release_host_enrol_adapter.py").read_text()


def test_host_bundle_checks_exact_files_revision_and_digests() -> None:
    values = {name: f"payload:{name}".encode() for name in APPLY.FILES}
    bundle = _tar_bundle(values)
    assert APPLY._parse_bundle(bundle, SHA, DIGEST) == values
    with pytest.raises(APPLY.ApplyError, match="enrolment_bundle_digest_mismatch"):
        APPLY._parse_bundle(_replace_tar_member(bundle, "agent.py", b"changed"), SHA, DIGEST)
    with pytest.raises(APPLY.ApplyError, match="enrolment_bundle_manifest_invalid"):
        APPLY._parse_bundle(bundle, "1" * 40, DIGEST)


def test_host_config_has_only_fixed_runtime_identity_and_paths() -> None:
    expected = {
        "QDEV_RELEASE_CONTROLLER_URL": "https://worker.ci.qdev.run",
        "QDEV_RELEASE_AGENT_CERT": str(APPLY.MTLS_ROOT / "agent-cert.pem"),
        "QDEV_RELEASE_AGENT_KEY": str(APPLY.MTLS_ROOT / "agent-key.pem"),
        "QDEV_RELEASE_CONTROLLER_CA": str(APPLY.MTLS_ROOT / "ca.pem"),
        "QDEV_RELEASE_HOST_IDENTITY": APPLY.HOST_IDENTITY,
        "QDEV_RELEASE_DISPATCH_SECRET_FILE": str(APPLY.DISPATCH_SECRET),
    }
    config = "".join(f"{key}={value}\n" for key, value in expected.items()).encode()
    APPLY._validate_config(config)
    with pytest.raises(APPLY.ApplyError, match="enrolment_config_identity_invalid"):
        APPLY._validate_config(config.replace(b"worker.ci.qdev.run", b"example.invalid"))


def test_host_agent_timer_is_packaged_for_the_dedicated_qantar_home() -> None:
    service = (ROOT / "deploy/qdev-release-qantar.service").read_text(encoding="utf-8")
    timer = (ROOT / "deploy/qdev-release-qantar.timer").read_text(encoding="utf-8")
    assert "/opt/qdev-release-agents/current/qdev_admin_platform_release_host_agent.py" in service
    assert "--profile qantar" in service
    assert "OnUnitActiveSec=30s" in timer
    assert "Unit=qdev-release-qantar.service" in timer


def test_child_receipt_must_echo_the_controller_rollback_anchor() -> None:
    request = {
        **_request(),
        "controller_internal_image_digest": DIGEST,
        "activation_envelope_digest": DIGEST,
        "controller_image_digest": DIGEST,
    }
    response = {
        "schema": PARENT.CHILD_SCHEMA,
        "status": "completed",
        "action": "enrol-host-agent",
        "controller_revision": SHA,
        "controller_release_digest": DIGEST,
        "release_lane": ENROL.TARGET_LANE,
        "host_agent_mtls_identity": ENROL.TARGET_IDENTITY,
        "rollback_source_sha": ROLLBACK["source_sha"],
        "rollback_artifact_digest": ROLLBACK["artifact_digest"],
        "result": {"bootstrap_heartbeat": "accepted"},
    }
    assert (
        PARENT._validate_child(
            response,
            request,
            _target(),
            (
                ROLLBACK["source_sha"],
                ROLLBACK["artifact_digest"],
                ROLLBACK["internal_artifact_digest"],
                ROLLBACK["policy_digest"],
                ROLLBACK["generation"],
            ),
        )
        == response
    )
    with pytest.raises(PARENT.AdapterError, match="child_identity_invalid"):
        PARENT._validate_child(
            {**response, "rollback_artifact_digest": DIGEST},
            request,
            _target(),
            (
                ROLLBACK["source_sha"],
                ROLLBACK["artifact_digest"],
                ROLLBACK["internal_artifact_digest"],
                ROLLBACK["policy_digest"],
                ROLLBACK["generation"],
            ),
        )


def test_helper_does_not_copy_host_private_key_to_its_result() -> None:
    source = (ROOT / "scripts/qantar_release_host_enrol_apply.py").read_text(encoding="utf-8")
    assert "agent-key.pem" in source
    assert "key_b64" not in source
    assert "private_key_b64" not in source
    assert "csr_b64" in source
    assert "certificate_b64" in source
