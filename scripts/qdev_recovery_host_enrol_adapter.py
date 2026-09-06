#!/usr/bin/python3
"""Rebind one fixed recovery host to the active controller release."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

SHA = re.compile(r"^[0-9a-f]{40}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SCHEMA = "qdev-recovery-host-enrol-result-v1"
ACTIVE = Path("/opt/qdev-runner-control-plane/current")
STATUS = Path("/var/lib/qdev-runner/controller-status/controller-release.json")
BROKER_ENV = Path("/etc/qdev-runner/broker.env")
RECOVERY_ENV = Path("/etc/qdev-runner/recovery-controller.env")
CONTROLLER_CA = Path("/etc/qdev-runner/mtls/controller/ca.pem")
SSH = Path("/usr/bin/ssh")
SCP = Path("/usr/bin/scp")
IDENTITY_ROOT = Path("/etc/qdev-runner/worker-recovery-dispatch")
IDENTITY = IDENTITY_ROOT / "id_ed25519"
KNOWN_HOSTS = IDENTITY_ROOT / "known_hosts"
RECEIPTS = Path("/var/lib/qdev-runner/operator-closure/recovery-host-enrol")
REMOTE_ROOT = "/var/lib/qdev-runner-recovery/enrol"
TARGETS = {
    "actions.runner.belilovsky-platform-portal.qdev-platform-ci-187": {
        "profile": "platform",
        "host": "187.55.228.239",
        "certificate_key": "QDEV_RECOVERY_PLATFORM_AGENT_CERTIFICATE_SHA256",
    },
    "actions.runner.belilovsky-qazstack.qdev-qazstack-01": {
        "profile": "qazstack",
        "host": "148.230.117.131",
        "certificate_key": "QDEV_RECOVERY_QAZSTACK_AGENT_CERTIFICATE_SHA256",
    },
}
ARTIFACTS = {
    "payload/deploy/qdev-runner-recovery-platform.service": Path(
        "deploy/qdev-runner-recovery-platform.service"
    ),
    "payload/deploy/qdev-runner-recovery-qazstack.service": Path(
        "deploy/qdev-runner-recovery-qazstack.service"
    ),
    "payload/scripts/install_qdev_runner_recovery_host_agent.sh": Path(
        "scripts/install_qdev_runner_recovery_host_agent.sh"
    ),
    "payload/scripts/qdev_runner_recovery_host_agent.py": Path(
        "scripts/qdev_runner_recovery_host_agent.py"
    ),
}


class EnrolError(RuntimeError):
    pass


def _root_regular(path: Path, *, private: bool) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or (private and stat.S_IMODE(metadata.st_mode) & 0o077)
        or (not private and stat.S_IMODE(metadata.st_mode) & 0o022)
    ):
        raise EnrolError("controller_file_permissions_invalid")


def _private_env(path: Path) -> dict[str, str]:
    _root_regular(path, private=True)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or not value or key in values:
            raise EnrolError("controller_private_environment_invalid")
        values[key] = value
    return values


def _active_release() -> tuple[Path, str, str]:
    try:
        link = ACTIVE.lstat()
        root = ACTIVE.resolve(strict=True)
        releases = (ACTIVE.parent / "releases").resolve(strict=True)
        status = json.loads(STATUS.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EnrolError("active_controller_release_unavailable") from error
    # The release-status projection is intentionally mounted read-only into the
    # rootless brokers and is written by activation with mode 0644.  It carries
    # only public runtime identity, so require root ownership and immutability
    # by non-root users without incorrectly treating it as a secret file.
    _root_regular(STATUS, private=False)
    if (
        not stat.S_ISLNK(link.st_mode)
        or link.st_uid != 0
        or root.parent != releases
        or not SHA.fullmatch(root.name)
        or not isinstance(status, dict)
        or status.get("state") != "active"
        or status.get("revision") != root.name
        or not isinstance(status.get("release_digest"), str)
        or DIGEST.fullmatch(status["release_digest"]) is None
    ):
        raise EnrolError("active_controller_release_invalid")
    return root, root.name, status["release_digest"]


def _load_constants(root: Path) -> tuple[str, str, str]:
    sys.path.insert(0, str(root / "src"))
    try:
        from qdev_runner.worker_recovery import (
            INTERFACE_DIGEST,
            INTERFACE_VERSION,
            POLICY_DIGEST,
        )
    finally:
        sys.path.pop(0)
    return POLICY_DIGEST, INTERFACE_VERSION, INTERFACE_DIGEST


def _ssh_base(host: str) -> list[str]:
    return [
        str(SSH),
        "-F",
        "/dev/null",
        "-i",
        str(IDENTITY),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o",
        "ConnectTimeout=15",
        f"root@{host}",
    ]


def _fixed_env() -> dict[str, str]:
    return {
        "PATH": "/usr/bin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def _run(command: list[str], *, input_bytes: bytes | None = None, timeout: int = 180) -> bytes:
    completed = subprocess.run(
        command,
        input=input_bytes,
        capture_output=True,
        check=False,
        timeout=timeout,
        env=_fixed_env(),
    )
    if completed.returncode != 0:
        raise EnrolError("fixed_host_enrol_failed")
    return completed.stdout


def _config(
    profile: str,
    revision: str,
    release_digest: str,
    policy_digest: str,
    agent_digest: str,
    interface_version: str,
    interface_digest: str,
    broker: dict[str, str],
    recovery: dict[str, str],
) -> bytes:
    values = {
        "QDEV_RECOVERY_CONTROLLER_URL": "https://worker.ci.qdev.run",
        "QDEV_RECOVERY_AGENT_CERT": "/etc/qdev-runner-recovery/mtls/agent-cert.pem",
        "QDEV_RECOVERY_AGENT_KEY": "/etc/qdev-runner-recovery/mtls/agent-key.pem",
        "QDEV_RECOVERY_CONTROLLER_CA": "/etc/qdev-runner-recovery/mtls/ca.pem",
        "QDEV_RECOVERY_COMMAND_VERIFICATION_KEY": broker["QDEV_OPERATOR_RECEIPT_KEY"],
        "QDEV_RECOVERY_RECONCILE_SIGNING_KEY": recovery["QDEV_RECOVERY_AGENT_SIGNING_KEY"],
        "QDEV_RECOVERY_STATE_PATH": f"/var/lib/qdev-runner-recovery/{profile}-state.json",
        "QDEV_RECOVERY_LOCK_PATH": f"/run/qdev-runner-recovery/{profile}.lock",
        "QDEV_RECOVERY_RECEIPTS_DIR": "/var/lib/qdev-runner-recovery/receipts",
        "QDEV_RECOVERY_EXPECTED_CONTROLLER_REVISION": revision,
        "QDEV_RECOVERY_EXPECTED_CONTROLLER_RELEASE_DIGEST": release_digest.removeprefix("sha256:"),
        "QDEV_RECOVERY_EXPECTED_POLICY_DIGEST": policy_digest,
        "QDEV_RECOVERY_EXPECTED_AGENT_RELEASE_DIGEST": agent_digest,
        "QDEV_RECOVERY_EXPECTED_INTERFACE_VERSION": interface_version,
        "QDEV_RECOVERY_EXPECTED_INTERFACE_DIGEST": interface_digest,
    }
    if any("\n" in value or "\r" in value for value in values.values()):
        raise EnrolError("controller_private_environment_invalid")
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode()


def _bundle(
    root: Path,
    *,
    profile: str,
    revision: str,
    release_digest: str,
    policy_digest: str,
    agent_digest: str,
    interface_version: str,
    interface_digest: str,
    certificate_sha256: str,
    config: bytes,
) -> bytes:
    payloads: dict[str, bytes] = {
        name: (root / relative).read_bytes() for name, relative in ARTIFACTS.items()
    }
    payloads["payload/platform.env"] = config
    payloads["payload/ca.pem"] = CONTROLLER_CA.read_bytes()
    manifest = {
        "schema": "qdev-recovery-host-enrol-bundle-v1",
        "profile": profile,
        "controller_revision": revision,
        "controller_release_digest": release_digest,
        "policy_digest": policy_digest,
        "agent_release_digest": agent_digest,
        "interface_version": interface_version,
        "interface_digest": interface_digest,
        "expected_agent_certificate_sha256": certificate_sha256,
        "files": {
            name: f"sha256:{hashlib.sha256(payload).hexdigest()}"
            for name, payload in sorted(payloads.items())
        },
    }
    payloads["manifest.json"] = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name, payload in sorted(payloads.items()):
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o600
            info.uid = 0
            info.gid = 0
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))
    return buffer.getvalue()


def _validate_response(raw: bytes, expected: dict[str, str]) -> dict[str, str]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EnrolError("host_response_invalid") from error
    fields = {
        "schema",
        "status",
        "profile",
        "controller_revision",
        "controller_release_digest",
        "agent_release_digest",
        "agent_certificate_sha256",
        "rollback_agent_release_digest",
    }
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or value.get("schema") != SCHEMA
        or value.get("status") not in {"completed", "already_completed"}
        or any(value.get(key) != item for key, item in expected.items())
        or not isinstance(value.get("rollback_agent_release_digest"), str)
        or (
            value["rollback_agent_release_digest"] != "none"
            and DIGEST.fullmatch(value["rollback_agent_release_digest"]) is None
        )
    ):
        raise EnrolError("host_response_invalid")
    return {key: str(item) for key, item in value.items()}


def _write_receipt(value: dict[str, str]) -> str:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    digest = hashlib.sha256(payload).hexdigest()
    RECEIPTS.mkdir(parents=True, exist_ok=True, mode=0o700)
    if RECEIPTS.is_symlink() or RECEIPTS.stat().st_uid != 0 or RECEIPTS.stat().st_mode & 0o077:
        raise EnrolError("receipt_directory_unsafe")
    path = RECEIPTS / f"{digest}.json"
    if path.exists():
        _root_regular(path, private=True)
        if path.read_bytes() != payload:
            raise EnrolError("receipt_conflict")
        return f"sha256:{digest}"
    descriptor, temporary = tempfile.mkstemp(prefix=".receipt.", dir=RECEIPTS)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, 0, 0)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)
    return f"sha256:{digest}"


def enrol(target_id: str) -> dict[str, str]:
    if os.geteuid() != 0 or target_id not in TARGETS:
        raise EnrolError("target_not_allowlisted")
    for path, private in (
        (IDENTITY, True),
        (KNOWN_HOSTS, True),
        (CONTROLLER_CA, False),
    ):
        _root_regular(path, private=private)
    target = TARGETS[target_id]
    root, revision, release_digest = _active_release()
    for relative in [*ARTIFACTS.values(), Path("scripts/qdev_recovery_host_apply.py")]:
        _root_regular(root / relative, private=False)
    broker = _private_env(BROKER_ENV)
    recovery = _private_env(RECOVERY_ENV)
    policy_digest, interface_version, interface_digest = _load_constants(root)
    if recovery.get("QDEV_RECOVERY_POLICY_DIGEST") != policy_digest:
        raise EnrolError("controller_binding_mismatch")
    agent_digest = recovery.get("QDEV_RECOVERY_AGENT_RELEASE_DIGEST", "")
    certificate_sha256 = recovery.get(str(target["certificate_key"]), "")
    if DIGEST.fullmatch(agent_digest) is None or HEX.fullmatch(certificate_sha256) is None:
        raise EnrolError("controller_binding_mismatch")
    config = _config(
        str(target["profile"]),
        revision,
        release_digest,
        policy_digest,
        agent_digest,
        interface_version,
        interface_digest,
        broker,
        recovery,
    )
    bundle = _bundle(
        root,
        profile=str(target["profile"]),
        revision=revision,
        release_digest=release_digest,
        policy_digest=policy_digest,
        agent_digest=agent_digest,
        interface_version=interface_version,
        interface_digest=interface_digest,
        certificate_sha256=certificate_sha256,
        config=config,
    )
    helper = root / "scripts/qdev_recovery_host_apply.py"
    helper_digest = hashlib.sha256(helper.read_bytes()).hexdigest()
    host = str(target["host"])
    remote_helper = f"{REMOTE_ROOT}/apply-{helper_digest}.py"
    _run(
        _ssh_base(host)
        + ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0700", REMOTE_ROOT]
    )
    scp = [
        str(SCP),
        "-F",
        "/dev/null",
        "-i",
        str(IDENTITY),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-q",
        str(helper),
        f"root@{host}:{remote_helper}",
    ]
    _run(scp)
    _run(_ssh_base(host) + ["/usr/bin/chown", "root:root", remote_helper])
    _run(_ssh_base(host) + ["/usr/bin/chmod", "0700", remote_helper])
    response = _run(
        _ssh_base(host)
        + [
            "/usr/bin/python3",
            remote_helper,
            "--profile",
            str(target["profile"]),
            "--self-sha256",
            helper_digest,
        ],
        input_bytes=bundle,
        timeout=300,
    )
    expected = {
        "profile": str(target["profile"]),
        "controller_revision": revision,
        "controller_release_digest": release_digest,
        "agent_release_digest": agent_digest,
        "agent_certificate_sha256": certificate_sha256,
    }
    result = _validate_response(response, expected)
    result["receipt_digest"] = _write_receipt(result)
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-id", choices=sorted(TARGETS), required=True)
    arguments = parser.parse_args()
    print(json.dumps(enrol(arguments.target_id), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EnrolError,
        FileNotFoundError,
        KeyError,
        OSError,
        subprocess.TimeoutExpired,
    ) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
