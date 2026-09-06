#!/usr/bin/python3
"""Provision private fixed-target registries and controller signing material."""

from __future__ import annotations

import json
import os
import secrets
import stat
import tempfile
from pathlib import Path
from typing import Any

CONFIG_ROOT = Path("/etc/qdev-runner")
SECRET_ROOT = CONFIG_ROOT / "host-dispatch-secrets"
KEY_MAP = CONFIG_ROOT / "release-host-dispatch-keys.json"
ENROLMENT_REGISTRY = CONFIG_ROOT / "release-host-enrolment-targets.json"
RECOVERY_REGISTRY = CONFIG_ROOT / "fleet-worker-recovery-targets.json"
RECOVERY_ADAPTER = "/usr/local/sbin/qdev-fixed-worker-recovery-dispatch"
RECOVERY_TARGETS: dict[str, dict[str, object]] = {
    "actions.runner.belilovsky-platform-portal.qdev-platform-ci-187": {
        "worker_name": "qdev-platform-ci-187",
        "target_id": "actions.runner.belilovsky-platform-portal.qdev-platform-ci-187",
        "service_unit": (
            "actions.runner.belilovsky-platform-portal.qdev-platform-ci-187.service"
        ),
        "host_binding": "controller-registry",
        "labels": ["self-hosted", "Linux", "X64", "qdev-platform-ci"],
        "adapter_path": RECOVERY_ADAPTER,
    },
    "actions.runner.belilovsky-qazstack.qdev-qazstack-01": {
        "worker_name": "qdev-qazstack-01",
        "target_id": "actions.runner.belilovsky-qazstack.qdev-qazstack-01",
        "service_unit": "actions.runner.belilovsky-qazstack.qdev-qazstack-01.service",
        "host_binding": "controller-registry",
        "labels": ["self-hosted", "Linux", "X64", "qdev-ci"],
        "adapter_path": RECOVERY_ADAPTER,
    },
}
HOST_IDENTITIES = (
    "qdev-host-agent:ortcom-production-controller",
    "qdev-host-agent:cmnt-rolling-controller",
    "qdev-host-agent:total-qdev-origin",
    "qdev-host-agent:qazposter-production-controller",
)


class ProvisionError(RuntimeError):
    pass


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _private_regular(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o600
    ):
        raise ProvisionError(f"unsafe private controller file: {path.name}")


def _root_directory(path: Path, *, mode: int, parents: bool) -> None:
    """Create a directory without accepting a symlink or writable root."""

    try:
        metadata = path.lstat()
    except FileNotFoundError:
        path.mkdir(mode=mode, parents=parents, exist_ok=False)
        metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise ProvisionError(f"unsafe private controller directory: {path.name}")


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    descriptor, temporary = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.")
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary_path, 0, 0)
        os.chmod(temporary_path, 0o600)
        os.replace(temporary_path, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise


def _read_or_create_registry(path: Path, schema: str) -> None:
    if not path.exists() and not path.is_symlink():
        _atomic_json(path, {"schema": schema, "targets": {}})
    _private_regular(path)
    document = json.loads(path.read_text(encoding="utf-8"))
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "targets"}
        or document.get("schema") != schema
        or not isinstance(document.get("targets"), dict)
    ):
        raise ProvisionError(f"invalid private controller registry: {path.name}")


def _reconcile_recovery_registry() -> None:
    _read_or_create_registry(RECOVERY_REGISTRY, "qdev-fleet-worker-recovery-targets-v1")
    document = json.loads(RECOVERY_REGISTRY.read_text(encoding="utf-8"))
    targets = document["targets"]
    if set(targets) - set(RECOVERY_TARGETS):
        raise ProvisionError("worker recovery registry contains an unknown target")
    for target_id, expected in RECOVERY_TARGETS.items():
        existing = targets.get(target_id)
        if existing is not None and existing != expected:
            raise ProvisionError("worker recovery registry target conflicts with policy")
    if targets != RECOVERY_TARGETS:
        _atomic_json(
            RECOVERY_REGISTRY,
            {
                "schema": "qdev-fleet-worker-recovery-targets-v1",
                "targets": RECOVERY_TARGETS,
            },
        )


def _slug(identity: str) -> str:
    return identity.replace(":", "-").replace("/", "-")


def _read_map() -> dict[str, str]:
    if not KEY_MAP.exists() and not KEY_MAP.is_symlink():
        return {}
    _private_regular(KEY_MAP)
    document = json.loads(KEY_MAP.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or not all(
        isinstance(key, str) and isinstance(value, str) for key, value in document.items()
    ):
        raise ProvisionError("invalid release host dispatch key map")
    if set(document) - set(HOST_IDENTITIES):
        raise ProvisionError("release host dispatch key map contains an unknown identity")
    return dict(document)


def main() -> int:
    if os.geteuid() != 0:
        raise ProvisionError("run as root")
    _root_directory(CONFIG_ROOT, mode=0o755, parents=True)
    _root_directory(SECRET_ROOT, mode=0o700, parents=False)
    os.chown(SECRET_ROOT, 0, 0)
    os.chmod(SECRET_ROOT, 0o700)
    mapping = _read_map()
    for identity in HOST_IDENTITIES:
        configured = mapping.get(identity)
        secret_path = (
            Path(configured)
            if configured is not None
            else SECRET_ROOT / f"{_slug(identity)}.secret"
        )
        if not secret_path.is_absolute() or secret_path.parent != SECRET_ROOT:
            raise ProvisionError("dispatch secret path is outside the private root")
        if not secret_path.exists() and not secret_path.is_symlink():
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            descriptor = os.open(secret_path, flags, 0o600)
            try:
                with os.fdopen(descriptor, "w", encoding="ascii") as handle:
                    descriptor = -1
                    handle.write(secrets.token_urlsafe(48) + "\n")
                    handle.flush()
                    os.fsync(handle.fileno())
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
            os.chown(secret_path, 0, 0)
            os.chmod(secret_path, 0o600)
            _fsync_directory(SECRET_ROOT)
        _private_regular(secret_path)
        size = secret_path.stat().st_size
        if size < 32 or size > 4096:
            raise ProvisionError("dispatch secret has an invalid size")
        mapping[identity] = str(secret_path)
    _atomic_json(KEY_MAP, mapping)
    _read_or_create_registry(ENROLMENT_REGISTRY, "qdev-release-host-enrolment-targets-v1")
    _reconcile_recovery_registry()
    print("fleet_host_dispatch_state=ready identities=4")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
