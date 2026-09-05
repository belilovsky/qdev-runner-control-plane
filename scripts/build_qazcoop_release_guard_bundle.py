#!/usr/bin/env python3
"""Build an immutable QazCoop verifier bundle from an exact controller revision."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

REPOSITORY_ID = 1_357_887_516
REPOSITORY = "belilovsky/qazcoop"
PROTECTED_REF = "refs/heads/codex/qazcoop-mvp"
SHA = re.compile(r"^[0-9a-f]{40}$")
REPOSITORY_FILES = {
    "admission.schema.json": (
        "docs/schemas/qdev-ci-controller-admission-v1.schema.json",
        Path("trust/admission.schema.json"),
        0o644,
    ),
    "controller_admission.py": (
        "src/qdev_runner/controller_admission.py",
        Path("lib/qdev_runner/controller_admission.py"),
        0o644,
    ),
    "qazcoop_release_guard.py": (
        "src/qdev_runner/qazcoop_release_guard.py",
        Path("lib/qdev_runner/qazcoop_release_guard.py"),
        0o644,
    ),
    "qdev_runner.__init__.py": (
        "src/qdev_runner/__init__.py",
        Path("lib/qdev_runner/__init__.py"),
        0o644,
    ),
    "qazcoop-update": (
        "scripts/qazcoop_update_hook.py",
        Path("bin/qazcoop-update"),
        0o755,
    ),
}


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def require_regular(path: Path, label: str, *, owner_only: bool = False) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is unavailable")
    mode = stat.S_IMODE(path.stat().st_mode)
    forbidden = 0o077 if owner_only else 0o022
    if mode & forbidden:
        raise ValueError(f"{label} has unsafe permissions")


def _git(root: Path, *arguments: str, text: bool = True) -> str | bytes:
    return subprocess.run(
        ["/usr/bin/git", *arguments],
        cwd=root,
        check=True,
        capture_output=True,
        text=text,
    ).stdout


def committed_blob(root: Path, revision: str, relative: str) -> bytes:
    entry = str(_git(root, "ls-tree", revision, "--", relative)).strip()
    if not entry or "\t" not in entry:
        raise ValueError(f"bundle source is absent from exact revision: {relative}")
    metadata, observed_path = entry.split("\t", 1)
    fields = metadata.split()
    if observed_path != relative or len(fields) != 3 or fields[1] != "blob":
        raise ValueError(f"bundle source is not an exact regular blob: {relative}")
    if fields[0] not in {"100644", "100755"}:
        raise ValueError(f"bundle source mode is invalid: {relative}")
    return bytes(_git(root, "show", f"{revision}:{relative}", text=False))


def load_keypair(private_key: Path, public_key: Path) -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    require_regular(private_key, "controller private key", owner_only=True)
    require_regular(public_key, "controller public key")
    private = serialization.load_pem_private_key(private_key.read_bytes(), password=None)
    public = serialization.load_pem_public_key(public_key.read_bytes())
    if not isinstance(private, Ed25519PrivateKey) or not isinstance(public, Ed25519PublicKey):
        raise ValueError("controller signing keypair must be Ed25519")
    expected = private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    observed = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    if observed != expected:
        raise ValueError("controller public key does not match private key")
    return private, public


def public_key_id(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def build_bundle(
    root: Path,
    revision: str,
    private_key: Path,
    public_key: Path,
    output: Path,
) -> None:
    observed = str(_git(root, "rev-parse", "HEAD")).strip()
    if observed != revision or SHA.fullmatch(revision) is None:
        raise ValueError("bundle revision must equal the exact source HEAD")
    for arguments in (("diff", "--quiet", "--"), ("diff", "--cached", "--quiet", "--")):
        if subprocess.run(["/usr/bin/git", *arguments], cwd=root, check=False).returncode:
            raise ValueError("tracked controller worktree must be clean before bundle export")
    committed_blob(root, revision, "scripts/build_qazcoop_release_guard_bundle.py")
    private, public = load_keypair(private_key, public_key)
    if output.exists() or output.is_symlink():
        raise ValueError("bundle output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        installed: dict[str, Path] = {}
        public_target = temporary / "trust/public.pem"
        public_target.parent.mkdir(parents=True)
        public_target.write_bytes(public_key.read_bytes())
        public_target.chmod(0o644)
        installed["public.pem"] = public_target

        for name, (relative, destination, mode) in REPOSITORY_FILES.items():
            target = temporary / destination
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(committed_blob(root, revision, relative))
            target.chmod(mode)
            installed[name] = target

        launcher = temporary / "bin/qdev-controller-verify-admission"
        launcher.write_text(
            "#!/usr/bin/env bash\n"
            "# QAZCOOP_RELEASE_GUARD_LAUNCHER_MANAGED_V1\n"
            "set -euo pipefail\n"
            f"guard_root=/usr/local/lib/qazcoop-release-guard/{revision}\n"
            "export QAZCOOP_GUARD_LAUNCHER=/usr/local/sbin/qdev-controller-verify-admission\n"
            "export QAZCOOP_GUARD_HOOK=/opt/qazcoop.git/hooks/update\n"
            "exec /usr/bin/python3 -I -c 'import runpy,sys; "
            "sys.path.insert(0,sys.argv.pop(1)); "
            "runpy.run_module(\"qdev_runner.qazcoop_release_guard\",run_name=\"__main__\")' "
            "\"$guard_root/lib\" \"$@\"\n",
            encoding="utf-8",
        )
        launcher.chmod(0o755)
        installed["qdev-controller-verify-admission"] = launcher

        key_id = public_key_id(public)
        canary_payload = {
            "contract": "qazcoop-release-guard-key-canary/v1",
            "controller_revision": revision,
            "public_key_id": key_id,
            "repository": {"id": REPOSITORY_ID, "full_name": REPOSITORY},
        }
        signature = base64.urlsafe_b64encode(private.sign(canonical(canary_payload))).rstrip(b"=")
        canary = {
            "payload": canary_payload,
            "signature": {
                "algorithm": "Ed25519",
                "key_id": key_id,
                "value": signature.decode("ascii"),
            },
        }
        canary_target = temporary / "trust/key-canary.json"
        canary_target.write_bytes(canonical(canary) + b"\n")
        canary_target.chmod(0o644)
        installed["key-canary.json"] = canary_target

        files = {name: digest(path) for name, path in sorted(installed.items())}
        manifest = {
            "contract": "qazcoop-release-guard-trust-bundle/v1",
            "controller_revision": revision,
            "repository": {
                "id": REPOSITORY_ID,
                "full_name": REPOSITORY,
                "protected_ref": PROTECTED_REF,
            },
            "files": files,
        }
        manifest_target = temporary / "bundle.json"
        manifest_target.write_bytes(canonical(manifest) + b"\n")
        manifest_target.chmod(0o644)
        for directory in (
            temporary / "trust",
            temporary / "lib",
            temporary / "lib/qdev_runner",
            temporary / "bin",
        ):
            directory.chmod(0o755)
        temporary.chmod(0o755)
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-repository", type=Path, required=True)
    parser.add_argument("--controller-revision", required=True)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build_bundle(
        args.controller_repository.resolve(strict=True),
        args.controller_revision,
        args.private_key.resolve(strict=True),
        args.public_key.resolve(strict=True),
        args.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
