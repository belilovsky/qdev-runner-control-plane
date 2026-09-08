#!/usr/bin/env python3
"""Install the fixed controller-activation verifier binding.

This root-only helper never creates, rotates, exports, or reads a private key.
It can only mirror the already-provisioned controller admission *public* key
into the fixed activation verifier location, then writes an immutable binding
record.  A later invocation is idempotent only when every byte already agrees;
it refuses to replace a key or binding with different material.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


ADMISSION_PUBLIC_KEY = Path("/etc/qdev-runner/admission/ed25519-public.pem")
TRUST_ROOT = Path("/etc/qdev-runner/trust")
ACTIVATION_PUBLIC_KEY = TRUST_ROOT / "controller-activation-ed25519.pub"
BINDING_PATH = TRUST_ROOT / "controller-activation-trust-binding.json"


class ProvisionError(RuntimeError):
    """The fixed trust binding cannot be safely established."""


def _require_root_regular(path: Path, *, mode_mask: int) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise ProvisionError(f"trusted file is unavailable: {path}") from exc
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & mode_mask
        ):
            raise ProvisionError(f"trusted file ownership is unsafe: {path}")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    except OSError as exc:
        raise ProvisionError(f"trusted file is unavailable: {path}") from exc
    finally:
        os.close(descriptor)


def _canonical(value: dict[str, str]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _binding(admission_key: bytes) -> dict[str, str]:
    digest = "sha256:" + hashlib.sha256(admission_key).hexdigest()
    return {
        "schema": "qdev-controller-activation-trust-binding-v1",
        "binding": "controller-registry",
        "authority": "controller-admission",
        "source_path": str(ADMISSION_PUBLIC_KEY),
        "source_sha256": digest,
        "activation_public_key_path": str(ACTIVATION_PUBLIC_KEY),
        "activation_public_key_sha256": digest,
    }


def _require_trust_root() -> None:
    if os.geteuid() != 0:
        raise ProvisionError("controller activation trust provisioning requires root")
    parent = TRUST_ROOT.parent
    try:
        parent_metadata = parent.lstat()
    except OSError as exc:
        raise ProvisionError("controller configuration directory is unavailable") from exc
    if (
        not stat.S_ISDIR(parent_metadata.st_mode)
        or stat.S_ISLNK(parent_metadata.st_mode)
        or parent_metadata.st_uid != 0
        or stat.S_IMODE(parent_metadata.st_mode) & 0o022
    ):
        raise ProvisionError("controller configuration directory is unsafe")
    if TRUST_ROOT.exists() or TRUST_ROOT.is_symlink():
        metadata = TRUST_ROOT.lstat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ProvisionError("controller activation trust directory is unsafe")
        return
    TRUST_ROOT.mkdir(mode=0o755, parents=False)


def _write_once(path: Path, payload: bytes, *, mode: int) -> None:
    if path.exists() or path.is_symlink():
        existing = _require_root_regular(path, mode_mask=0o022)
        if existing != payload:
            raise ProvisionError(f"refusing to replace existing trust material: {path}")
        return
    descriptor = -1
    temporary_name: str | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=TRUST_ROOT)
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb", closefd=False) as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary_name, path)
    except OSError as exc:
        raise ProvisionError(f"cannot install trust material: {path}") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_name is not None:
            try:
                Path(temporary_name).unlink()
            except FileNotFoundError:
                pass


def provision() -> dict[str, str]:
    _require_trust_root()
    admission_key = _require_root_regular(ADMISSION_PUBLIC_KEY, mode_mask=0o022)
    if not admission_key:
        raise ProvisionError("controller admission public key is empty")
    try:
        parsed_key = serialization.load_pem_public_key(admission_key)
    except ValueError as exc:
        raise ProvisionError("controller admission public key is invalid") from exc
    if not isinstance(parsed_key, Ed25519PublicKey):
        raise ProvisionError("controller admission public key is not Ed25519")
    binding = _binding(admission_key)
    _write_once(ACTIVATION_PUBLIC_KEY, admission_key, mode=0o644)
    _write_once(BINDING_PATH, _canonical(binding) + b"\n", mode=0o644)
    return {
        "status": "passed",
        "binding": binding["binding"],
        "authority": binding["authority"],
        "key_sha256": binding["activation_public_key_sha256"],
    }


def main() -> int:
    try:
        receipt = provision()
    except ProvisionError as exc:
        raise SystemExit(f"controller_activation_trust_provision_failed: {exc}") from exc
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
