#!/usr/bin/env python3
"""Provision or validate the root-owned QazCoop controller signing keypair."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from qdev_runner.controller_admission import initialize_keypair


def _keypair(private_path: Path, public_path: Path) -> str:
    if private_path.parent != public_path.parent:
        raise ValueError("QazCoop release signing keys must share one directory")
    parent = private_path.parent
    if parent.exists() or parent.is_symlink():
        status = parent.lstat()
        if (
            not stat.S_ISDIR(status.st_mode)
            or stat.S_ISLNK(status.st_mode)
            or status.st_uid != 0
            or stat.S_IMODE(status.st_mode) != 0o700
        ):
            raise ValueError("QazCoop release signing directory metadata is invalid")
    present = (
        private_path.exists() or private_path.is_symlink(),
        public_path.exists() or public_path.is_symlink(),
    )
    if present == (False, False):
        parent.mkdir(parents=True, mode=0o700)
        os.chown(parent, 0, 0)
        parent.chmod(0o700)
        initialize_keypair(private_path, public_path)
    elif present != (True, True):
        raise ValueError("QazCoop release signing keypair is incomplete")
    for path, mode in ((private_path, 0o600), (public_path, 0o644)):
        status = path.lstat()
        if (
            not stat.S_ISREG(status.st_mode)
            or stat.S_ISLNK(status.st_mode)
            or status.st_uid != 0
            or stat.S_IMODE(status.st_mode) != mode
        ):
            raise ValueError(f"QazCoop release signing key metadata is invalid: {path.name}")
    private = serialization.load_pem_private_key(private_path.read_bytes(), password=None)
    public = serialization.load_pem_public_key(public_path.read_bytes())
    if not isinstance(private, Ed25519PrivateKey) or not isinstance(public, Ed25519PublicKey):
        raise ValueError("QazCoop release signing keypair must be Ed25519")
    expected = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    observed = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if observed != expected:
        raise ValueError("QazCoop release signing public key does not match private key")
    return "sha256:" + hashlib.sha256(observed).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--private-key",
        type=Path,
        default=Path("/etc/qdev-runner/qazcoop-release-signing/ed25519-private.pem"),
    )
    parser.add_argument(
        "--public-key",
        type=Path,
        default=Path("/etc/qdev-runner/qazcoop-release-signing/ed25519-public.pem"),
    )
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise PermissionError("run as root")
    key_id = _keypair(args.private_key, args.public_key)
    print(f"qazcoop_release_signing_key={key_id}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
