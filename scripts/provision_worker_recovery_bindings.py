#!/usr/bin/python3
"""Provision private, source-bound controller and edge recovery bindings."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import secrets
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from qdev_runner.worker_recovery import (  # noqa: E402
    INTERFACE_DIGEST,
    INTERFACE_VERSION,
    POLICY_DIGEST,
)

HEX = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SECRET = re.compile(r"^[A-Za-z0-9_-]{32,256}$")


class ProvisionError(RuntimeError):
    """Raised when a recovery binding cannot be provisioned safely."""


def _private_values(path: Path) -> dict[str, str]:
    if not path.exists():
        return {}
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ProvisionError(f"private environment is unsafe: {path}")
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or key in values or "\n" in value or "\r" in value:
            raise ProvisionError(f"private environment is malformed: {path}")
        values[key] = value
    return values


def _certificate_fingerprint(path: Path) -> str:
    if not path.is_file() or path.is_symlink():
        raise ProvisionError(f"certificate is unavailable: {path}")
    result = subprocess.run(
        ["openssl", "x509", "-in", str(path), "-outform", "DER"],
        check=True,
        capture_output=True,
        timeout=15,
    )
    return hashlib.sha256(result.stdout).hexdigest()


def _active_release(path: Path) -> dict[str, str]:
    try:
        metadata = path.lstat()
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ProvisionError("active controller release status is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_mode & 0o022
        or not isinstance(document, dict)
        or document.get("state") != "active"
        or not re.fullmatch(r"[0-9a-f]{40}", str(document.get("revision", "")))
        or not HEX.fullmatch(str(document.get("release_digest", "")))
    ):
        raise ProvisionError("active controller release status is invalid")
    return {
        "revision": str(document["revision"]),
        "release_digest": str(document["release_digest"]),
    }


def _agent_release_digest() -> str:
    result = subprocess.run(
        [
            str(ROOT / "scripts" / "install_qdev_runner_recovery_host_agent.sh"),
            "--profile",
            "platform",
            "--digest-only",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=15,
    )
    value = result.stdout.strip()
    if not DIGEST.fullmatch(value):
        raise ProvisionError("host-agent release digest is invalid")
    return value


def _secret(existing: dict[str, str], key: str, rotate: bool) -> str:
    value = existing.get(key, "")
    if not rotate and SECRET.fullmatch(value):
        return value
    return secrets.token_urlsafe(48)


def _write_private(path: Path, values: dict[str, str]) -> None:
    path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    if path.parent.is_symlink() or path.parent.stat().st_mode & 0o022:
        raise ProvisionError(f"private environment parent is unsafe: {path.parent}")
    payload = "".join(f"{key}={value}\n" for key, value in values.items())
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, 0, 0)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--operator-cert", type=Path, required=True)
    parser.add_argument("--platform-agent-cert", type=Path, required=True)
    parser.add_argument("--qazstack-agent-cert", type=Path, required=True)
    parser.add_argument(
        "--release-status",
        type=Path,
        default=Path("/var/lib/qdev-runner/controller-status/controller-release.json"),
    )
    parser.add_argument(
        "--controller-env",
        type=Path,
        default=Path("/etc/qdev-runner/recovery-controller.env"),
    )
    parser.add_argument(
        "--edge-env",
        type=Path,
        default=Path("/etc/qdev-runner/recovery-edge.env"),
    )
    parser.add_argument("--rotate-secrets", action="store_true")
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise ProvisionError("run as root")

    release = _active_release(arguments.release_status)
    current = _private_values(arguments.controller_env)
    proxy_secret = _secret(current, "QDEV_OPERATOR_PROXY_SECRET", arguments.rotate_secrets)
    signing_key = _secret(
        current, "QDEV_RECOVERY_AGENT_SIGNING_KEY", arguments.rotate_secrets
    )
    controller = {
        "QDEV_OPERATOR_PROXY_SECRET": proxy_secret,
        "QDEV_RECOVERY_OPERATOR_CERTIFICATE_SHA256S": _certificate_fingerprint(
            arguments.operator_cert
        ),
        "QDEV_RECOVERY_PLATFORM_AGENT_CERTIFICATE_SHA256": _certificate_fingerprint(
            arguments.platform_agent_cert
        ),
        "QDEV_RECOVERY_QAZSTACK_AGENT_CERTIFICATE_SHA256": _certificate_fingerprint(
            arguments.qazstack_agent_cert
        ),
        "QDEV_RECOVERY_POLICY_DIGEST": POLICY_DIGEST,
        "QDEV_RECOVERY_AGENT_RELEASE_DIGEST": _agent_release_digest(),
        "QDEV_RECOVERY_AGENT_SIGNING_KEY": signing_key,
    }
    _write_private(arguments.controller_env, controller)
    _write_private(arguments.edge_env, {"QDEV_OPERATOR_PROXY_SECRET": proxy_secret})
    print(
        json.dumps(
            {
                "schema": "qdev-worker-recovery-binding-provision-v1",
                "controller_revision": release["revision"],
                "controller_release_digest": release["release_digest"],
                "policy_digest": POLICY_DIGEST,
                "agent_release_digest": controller["QDEV_RECOVERY_AGENT_RELEASE_DIGEST"],
                "interface_version": INTERFACE_VERSION,
                "interface_digest": INTERFACE_DIGEST,
                "controller_env": str(arguments.controller_env),
                "edge_env": str(arguments.edge_env),
                "secrets_rotated": arguments.rotate_secrets,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ProvisionError, OSError, subprocess.SubprocessError) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(66) from error
