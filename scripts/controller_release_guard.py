#!/usr/bin/env python3
"""Bind a native controller activation to immutable source and expected runtime.

The manifest is generated from git objects, never a dirty checkout. It is not
an authorization signature: the operator supplies its independently observed
digest and current runtime tuple to the existing privileged release command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "qdev-controller-source-artifact-v1"
MANIFEST = "controller-source-artifact.json"


def digest(value: dict[str, Any]) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def exact(value: str, length: int) -> str:
    if not re.fullmatch(rf"[0-9a-f]{{{length}}}", value):
        raise ValueError("invalid exact revision or digest")
    return value


def source_manifest(repository: Path, revision: str) -> dict[str, Any]:
    exact(revision, 40)
    tree = subprocess.check_output(
        ["git", "ls-tree", "-rz", "--full-tree", revision], cwd=repository
    )
    files = {}
    for entry in tree.split(b"\0"):
        if not entry:
            continue
        metadata, name = entry.split(b"\t", 1)
        mode, kind, object_id = metadata.decode().split()
        if kind != "blob" or mode not in {"100644", "100755"}:
            raise ValueError("release source cannot contain symlinks or submodules")
        path = name.decode("utf-8")
        validate_path(path)
        content = subprocess.check_output(["git", "cat-file", "blob", object_id], cwd=repository)
        files[path] = {
            "sha256": hashlib.sha256(content).hexdigest(),
            "executable": mode == "100755",
        }
    if not files:
        raise ValueError("empty source artifact")
    payload = {"schema": SCHEMA, "revision": revision, "files": files}
    return {**payload, "digest": digest(payload)}


def validate_path(value: str) -> None:
    path = PurePosixPath(value)
    if not value or path.is_absolute() or ".." in path.parts or str(path) != value:
        raise ValueError("unsafe artifact path")
    if value == MANIFEST or ".git" in path.parts:
        raise ValueError("reserved artifact path")


def verify_artifact(root: Path, revision: str, expected_digest: str) -> str:
    exact(revision, 40)
    exact(expected_digest, 64)
    manifest_path = root / MANIFEST
    if manifest_path.is_symlink():
        raise ValueError("artifact manifest cannot be a symlink")
    manifest = json.loads(manifest_path.read_text())
    if not isinstance(manifest, dict) or set(manifest) != {"schema", "revision", "files", "digest"}:
        raise ValueError("invalid source artifact manifest")
    payload = {key: manifest[key] for key in ("schema", "revision", "files")}
    if (
        manifest["schema"] != SCHEMA
        or manifest["revision"] != revision
        or manifest["digest"] != expected_digest
        or digest(payload) != expected_digest
    ):
        raise ValueError("artifact source binding mismatch")
    files = manifest["files"]
    if not isinstance(files, dict) or not files:
        raise ValueError("empty artifact file list")
    actual = set()
    for path in root.rglob("*"):
        if path.is_symlink():
            raise ValueError("artifact cannot contain symlinks")
        if path.is_file():
            actual.add(path.relative_to(root).as_posix())
    if actual != set(files) | {MANIFEST}:
        raise ValueError("artifact contains missing or unbound files")
    for relative, binding in files.items():
        validate_path(relative)
        path = root / relative
        if not isinstance(binding, dict) or set(binding) != {"sha256", "executable"}:
            raise ValueError("invalid file binding")
        if hashlib.sha256(path.read_bytes()).hexdigest() != binding["sha256"]:
            raise ValueError(f"artifact content mismatch: {relative}")
        if bool(path.stat().st_mode & 0o111) != binding["executable"]:
            raise ValueError(f"artifact mode mismatch: {relative}")
    return expected_digest


def check_current(status_path: Path, expected_revision: str, expected_digest: str) -> None:
    exact(expected_revision, 40)
    exact(expected_digest, 64)
    status = json.loads(status_path.read_text())
    if (
        not isinstance(status, dict)
        or status.get("state") != "active"
        or status.get("revision") != expected_revision
        or status.get("release_digest") != expected_digest
    ):
        raise ValueError("current runtime changed; reconcile before a new release transaction")


def main() -> int:
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("manifest")
    prepare.add_argument("--repository", type=Path, required=True)
    prepare.add_argument("--revision", required=True)
    prepare.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--root", type=Path, required=True)
    verify.add_argument("--revision", required=True)
    verify.add_argument("--digest", required=True)
    current = sub.add_parser("current")
    current.add_argument("--status", type=Path, required=True)
    current.add_argument("--revision", required=True)
    current.add_argument("--digest", required=True)
    args = parser.parse_args()
    try:
        if args.command == "manifest":
            manifest = source_manifest(args.repository, args.revision)
            with args.output.open("x") as stream:
                json.dump(manifest, stream, sort_keys=True, indent=2)
                stream.write("\n")
            print(manifest["digest"])
        elif args.command == "verify":
            print(verify_artifact(args.root, args.revision, args.digest))
        else:
            check_current(args.status, args.revision, args.digest)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"controller_release_guard_failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
