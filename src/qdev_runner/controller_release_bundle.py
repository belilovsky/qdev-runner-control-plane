"""Build and verify the immutable controller release filesystem bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path
from typing import Any

SCHEMA = "qdev-controller-release-bundle-v1"
MANIFEST = "controller-release-bundle.json"
_REVISION = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TREES = ("config", "deploy", "inventory", "scripts", "src")
_OPTIONAL_TREES = ("wheelhouse",)
_FILES = ("README.md", "pyproject.toml", "requirements.runtime.txt")
_GENERATED_DIRECTORIES = frozenset({"__pycache__", ".mypy_cache", ".pytest_cache", ".ruff_cache"})


class BundleError(RuntimeError):
    """The release bundle is incomplete, mutable, or incorrectly bound."""


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _regular(path: Path) -> os.stat_result:
    metadata = path.lstat()
    if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
        raise BundleError(f"release entry is not a regular file: {path}")
    return metadata


def _source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for name in _FILES:
        path = root / name
        _regular(path)
        files.append(path)
    for name in _TREES:
        tree = root / name
        metadata = tree.lstat()
        if tree.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise BundleError(f"release tree is invalid: {name}")
        for path in sorted(tree.rglob("*")):
            relative = path.relative_to(root)
            if any(
                part in _GENERATED_DIRECTORIES or part.endswith(".egg-info")
                for part in relative.parts
            ):
                continue
            if path.is_dir() and not path.is_symlink():
                continue
            _regular(path)
            if relative.suffix in {".pyc", ".pyo"}:
                continue
            files.append(path)
    for name in _OPTIONAL_TREES:
        tree = root / name
        if not tree.exists() and not tree.is_symlink():
            continue
        metadata = tree.lstat()
        if tree.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
            raise BundleError(f"release tree is invalid: {name}")
        for path in sorted(tree.rglob("*")):
            if path.is_dir() and not path.is_symlink():
                continue
            _regular(path)
            files.append(path)
    return sorted(files, key=lambda path: path.relative_to(root).as_posix())


def _records(root: Path) -> dict[str, dict[str, Any]]:
    records: dict[str, dict[str, Any]] = {}
    for path in _source_files(root):
        metadata = _regular(path)
        relative = path.relative_to(root).as_posix()
        records[relative] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mode": stat.S_IMODE(metadata.st_mode),
        }
    return records


def _identity(source_revision: str, files: dict[str, dict[str, Any]]) -> dict[str, Any]:
    return {"schema": SCHEMA, "source_revision": source_revision, "files": files}


def bundle_digest(source_revision: str, files: dict[str, dict[str, Any]]) -> str:
    return hashlib.sha256(_canonical(_identity(source_revision, files))).hexdigest()


def build(
    source: Path,
    destination: Path,
    source_revision: str,
    *,
    wheelhouse: Path | None = None,
) -> dict[str, Any]:
    if not _REVISION.fullmatch(source_revision):
        raise BundleError("source revision is invalid")
    source = source.resolve(strict=True)
    if destination.exists() or destination.is_symlink():
        raise BundleError("bundle destination must not exist")
    destination.mkdir(parents=True, mode=0o755)
    try:
        source_files = _records(source)
        for relative, record in source_files.items():
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source / relative, target, follow_symlinks=False)
            target.chmod(record["mode"])
        if wheelhouse is not None:
            wheelhouse = wheelhouse.resolve(strict=True)
            metadata = wheelhouse.lstat()
            if wheelhouse.is_symlink() or not stat.S_ISDIR(metadata.st_mode):
                raise BundleError("bootstrap wheelhouse is invalid")
            target_root = destination / "wheelhouse"
            target_root.mkdir(mode=0o755)
            for path in sorted(wheelhouse.rglob("*")):
                if path.is_dir() and not path.is_symlink():
                    continue
                metadata = _regular(path)
                wheel_relative = path.relative_to(wheelhouse)
                if len(wheel_relative.parts) != 1:
                    raise BundleError("bootstrap wheelhouse must be flat")
                target = target_root / wheel_relative
                shutil.copyfile(path, target, follow_symlinks=False)
                target.chmod(stat.S_IMODE(metadata.st_mode))
        files = _records(destination)
        manifest = {
            **_identity(source_revision, files),
            "bundle_digest": bundle_digest(source_revision, files),
        }
        manifest_path = destination / MANIFEST
        manifest_path.write_bytes(_canonical(manifest) + b"\n")
        manifest_path.chmod(0o444)
        verify(
            destination,
            source_revision=source_revision,
            expected_digest=manifest["bundle_digest"],
        )
        return manifest
    except BaseException:
        shutil.rmtree(destination, ignore_errors=True)
        raise


def verify(
    root: Path, *, source_revision: str | None = None, expected_digest: str | None = None
) -> dict[str, Any]:
    root = root.resolve(strict=True)
    try:
        manifest = json.loads((root / MANIFEST).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BundleError("release bundle manifest is unavailable") from error
    if not isinstance(manifest, dict) or set(manifest) != {
        "schema",
        "source_revision",
        "files",
        "bundle_digest",
    }:
        raise BundleError("release bundle manifest shape is invalid")
    revision = manifest.get("source_revision")
    digest = manifest.get("bundle_digest")
    files = manifest.get("files")
    if (
        manifest.get("schema") != SCHEMA
        or not isinstance(revision, str)
        or not _REVISION.fullmatch(revision)
        or not isinstance(digest, str)
        or not _DIGEST.fullmatch(digest)
        or not isinstance(files, dict)
    ):
        raise BundleError("release bundle identity is invalid")
    if source_revision is not None and revision != source_revision:
        raise BundleError("release bundle source revision mismatch")
    if expected_digest is not None and digest != expected_digest:
        raise BundleError("release bundle digest mismatch")
    actual = _records(root)
    if files != actual or digest != bundle_digest(revision, actual):
        raise BundleError("release bundle contents do not match manifest")
    expected_paths = set(actual) | {MANIFEST}
    actual_paths = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() or path.is_symlink()
    }
    if actual_paths != expected_paths:
        raise BundleError("release bundle contains undeclared files")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    build_parser = subparsers.add_parser("build")
    build_parser.add_argument("source", type=Path)
    build_parser.add_argument("destination", type=Path)
    build_parser.add_argument("--source-revision", required=True)
    build_parser.add_argument("--wheelhouse", type=Path)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("root", type=Path)
    verify_parser.add_argument("--source-revision")
    verify_parser.add_argument("--bundle-digest")
    args = parser.parse_args()
    try:
        if args.command == "build":
            result = build(
                args.source,
                args.destination,
                args.source_revision,
                wheelhouse=args.wheelhouse,
            )
        else:
            result = verify(
                args.root,
                source_revision=args.source_revision,
                expected_digest=args.bundle_digest,
            )
    except (BundleError, OSError, ValueError):
        print("controller_release_bundle_invalid")
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
