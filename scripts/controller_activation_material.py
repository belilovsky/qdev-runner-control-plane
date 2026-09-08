#!/usr/bin/env python3
"""Durable, root-owned rollback material for controller activations.

The activation state machine proves who may mutate the controller.  This
helper preserves the exact host files needed to undo that mutation after the
original shell process (and its /tmp directory) no longer exists.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
from pathlib import Path
from typing import Any

SCHEMA = "qdev-controller-activation-material-v1"
TX_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
PHASES = {
    "prepared",
    "mutating",
    "config-installed",
    "candidate-active",
    "committed",
    "anchor-published",
    "external-guard-reconciling",
    "external-guard-reconciled",
    "rolled-back",
    "finalized",
}


class MaterialError(RuntimeError):
    """Fail-closed material validation error."""


def _prepare_fault(_stage: str) -> None:
    """Test-only fault boundary for crash-safety verification."""


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_directory(path: Path, *, mode: int | None = None) -> None:
    metadata = path.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or path.is_symlink() or metadata.st_uid != 0:
        raise MaterialError(f"unsafe activation material directory: {path}")
    if metadata.st_mode & 0o022:
        raise MaterialError(f"writable activation material directory: {path}")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise MaterialError(f"unexpected activation material mode: {path}")


def _safe_regular(path: Path, *, mode_mask: int = 0o022) -> os.stat_result:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink() or metadata.st_uid != 0:
        raise MaterialError(f"unsafe activation material file: {path}")
    if metadata.st_mode & mode_mask:
        raise MaterialError(f"writable activation material file: {path}")
    return metadata


def _atomic_bytes(path: Path, content: bytes, *, mode: int, uid: int = 0, gid: int = 0) -> None:
    _safe_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.chown(temporary, uid, gid)
        os.chmod(temporary, mode)
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    _atomic_bytes(path, encoded, mode=0o600)


def _parse_snapshot(value: str) -> tuple[str, Path]:
    try:
        group, raw_path = value.split("=", 1)
    except ValueError as error:
        raise MaterialError("snapshot must be GROUP=/absolute/path") from error
    if not re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", group):
        raise MaterialError("snapshot group is invalid")
    path = Path(raw_path)
    if not path.is_absolute() or ".." in path.parts:
        raise MaterialError("snapshot destination must be an absolute normalized path")
    return group, path


def _transaction_directory(root: Path, transaction_id: str, envelope_digest: str) -> Path:
    if not TX_RE.fullmatch(transaction_id) or not DIGEST_RE.fullmatch(envelope_digest):
        raise MaterialError("activation transaction identity is invalid")
    _safe_directory(root)
    return root / f"{transaction_id}-{envelope_digest}"


def _manifest_path(directory: Path) -> Path:
    _safe_directory(directory, mode=0o700)
    return directory / "material.json"


def _load(directory: Path) -> dict[str, Any]:
    path = _manifest_path(directory)
    _safe_regular(path, mode_mask=0o077)
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MaterialError("activation material manifest is unreadable") from error
    if not isinstance(value, dict) or value.get("schema") != SCHEMA:
        raise MaterialError("activation material manifest schema is invalid")
    if value.get("phase") not in PHASES or not isinstance(value.get("snapshots"), list):
        raise MaterialError("activation material manifest state is invalid")
    return value


def _assert_binding(
    value: dict[str, Any], *, transaction_id: str, envelope_digest: str, release_path: str
) -> None:
    if (
        value.get("transaction_id") != transaction_id
        or value.get("envelope_digest") != envelope_digest
        or value.get("release_path") != release_path
    ):
        raise MaterialError("activation material binding does not match signed transaction")


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    directory = _transaction_directory(args.root, args.transaction_id, args.envelope_digest)
    release = Path(args.release_path).resolve(strict=True)
    if directory.exists() or directory.is_symlink():
        value = _load(directory)
        _assert_binding(
            value,
            transaction_id=args.transaction_id,
            envelope_digest=args.envelope_digest,
            release_path=str(release),
        )
        return value
    # Build the complete snapshot in a private sibling and publish it with one
    # atomic rename.  The canonical transaction path must never expose the
    # mkdir/files/manifest intermediate states: a SIGKILL at any earlier point
    # merely leaves an unreferenced hidden staging directory, and an exact retry
    # can safely construct and publish a new complete snapshot.
    staging = Path(tempfile.mkdtemp(prefix=f".{directory.name}.prepare.", dir=args.root))
    try:
        os.chmod(staging, 0o700)
        os.chown(staging, 0, 0)
        _prepare_fault("after-staging-directory")
        backups = staging / "files"
        backups.mkdir(mode=0o700)
        os.chown(backups, 0, 0)
        _prepare_fault("after-files-directory")
        snapshots: list[dict[str, Any]] = []
        destinations: set[str] = set()
        for index, raw in enumerate(args.snapshot):
            group, destination = _parse_snapshot(raw)
            destination_text = str(destination)
            if destination_text in destinations:
                raise MaterialError("duplicate activation snapshot destination")
            destinations.add(destination_text)
            present = destination.exists() or destination.is_symlink()
            record: dict[str, Any] = {
                "destination": destination_text,
                "group": group,
                "present": present,
            }
            if present:
                metadata = destination.lstat()
                if not stat.S_ISREG(metadata.st_mode) or destination.is_symlink():
                    raise MaterialError(f"snapshot source is not a regular file: {destination}")
                backup = backups / f"{index:03d}.bin"
                content = destination.read_bytes()
                _atomic_bytes(backup, content, mode=0o600)
                record.update(
                    {
                        "backup": str(backup.relative_to(staging)),
                        "sha256": hashlib.sha256(content).hexdigest(),
                        "mode": stat.S_IMODE(metadata.st_mode),
                        "uid": metadata.st_uid,
                        "gid": metadata.st_gid,
                    }
                )
            snapshots.append(record)
            _prepare_fault(f"after-snapshot-{index}")
        value = {
            "schema": SCHEMA,
            "transaction_id": args.transaction_id,
            "envelope_digest": args.envelope_digest,
            "release_path": str(release),
            "previous_release_path": args.previous_release_path,
            "previous_public_image": args.previous_public_image,
            "previous_public_ref": args.previous_public_ref,
            "previous_internal_image": args.previous_internal_image,
            "previous_internal_ref": args.previous_internal_ref,
            "rollback_public_ref": args.rollback_public_ref,
            "rollback_internal_ref": args.rollback_internal_ref,
            "dispatcher_enabled": args.dispatcher_enabled,
            "dispatcher_active": args.dispatcher_active,
            "phase": "prepared",
            "snapshots": snapshots,
        }
        _atomic_json(staging / "material.json", value)
        _prepare_fault("after-manifest")
        _fsync_directory(backups)
        _fsync_directory(staging)
        # ``directory`` was checked above while the caller holds the global
        # activation lock.  os.rename refuses to replace a non-empty directory,
        # retaining fail-closed behaviour if that invariant is ever violated.
        _prepare_fault("before-rename")
        os.rename(staging, directory)
        _prepare_fault("after-rename")
        _fsync_directory(args.root)
        return value
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        _fsync_directory(args.root)
        raise


def restore(args: argparse.Namespace) -> dict[str, Any]:
    value = _load(args.directory)
    groups = set(args.group)
    for record in reversed(value["snapshots"]):
        if record.get("group") not in groups:
            continue
        destination = Path(record["destination"])
        if not destination.parent.is_dir() or destination.parent.is_symlink():
            raise MaterialError(f"snapshot destination parent is unsafe: {destination}")
        _safe_directory(destination.parent)
        if record["present"]:
            backup = args.directory / record["backup"]
            _safe_regular(backup, mode_mask=0o077)
            content = backup.read_bytes()
            if hashlib.sha256(content).hexdigest() != record["sha256"]:
                raise MaterialError("activation snapshot digest mismatch")
            _atomic_bytes(
                destination,
                content,
                mode=int(record["mode"]),
                uid=int(record["uid"]),
                gid=int(record["gid"]),
            )
        elif destination.exists() or destination.is_symlink():
            metadata = destination.lstat()
            if not stat.S_ISREG(metadata.st_mode) or destination.is_symlink():
                raise MaterialError(f"refusing to unlink unsafe destination: {destination}")
            destination.unlink()
            _fsync_directory(destination.parent)
    return value


def extract(args: argparse.Namespace) -> dict[str, Any]:
    value = _load(args.directory)
    destination = str(Path(args.destination))
    records = [item for item in value["snapshots"] if item["destination"] == destination]
    if len(records) != 1 or not records[0]["present"]:
        raise MaterialError("requested snapshot was not present")
    record = records[0]
    backup = args.directory / record["backup"]
    content = backup.read_bytes()
    if hashlib.sha256(content).hexdigest() != record["sha256"]:
        raise MaterialError("activation snapshot digest mismatch")
    _atomic_bytes(args.output, content, mode=0o600)
    return value


def set_phase(args: argparse.Namespace) -> dict[str, Any]:
    if args.phase not in PHASES:
        raise MaterialError("activation material phase is invalid")
    value = _load(args.directory)
    value["phase"] = args.phase
    _atomic_json(args.directory / "material.json", value)
    return value


def install_file(args: argparse.Namespace) -> dict[str, Any]:
    """Install a root-owned release file with durable replace semantics."""

    value = _load(args.directory)
    source = args.source.resolve(strict=True)
    release = Path(value["release_path"]).resolve(strict=True)
    if source != release and release not in source.parents:
        raise MaterialError("activation install source is outside the signed release")
    _safe_regular(source)
    destination = args.destination
    if not destination.is_absolute() or ".." in destination.parts:
        raise MaterialError("activation install destination is invalid")
    _atomic_bytes(
        destination,
        source.read_bytes(),
        mode=args.mode,
        uid=args.uid,
        gid=args.gid,
    )
    return value


def activate_link(args: argparse.Namespace) -> dict[str, Any]:
    """Flip the current-release symlink atomically and fsync its directory."""

    value = _load(args.directory)
    link = args.link
    target = args.target.resolve(strict=True)
    parent = link.parent.resolve(strict=True)
    _safe_directory(parent)
    releases = parent / "releases" if (parent / "releases").exists() else parent
    _safe_directory(releases)
    _safe_directory(target)
    if target.parent != releases:
        raise MaterialError("activation link target is outside the release root")
    temporary = parent / f".{link.name}.{value['transaction_id']}.tmp"
    if temporary.exists() or temporary.is_symlink():
        temporary.unlink()
    try:
        temporary.symlink_to(target)
        os.replace(temporary, link)
        _fsync_directory(parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise
    return value


def stage_anchor(args: argparse.Namespace) -> dict[str, Any]:
    value = _load(args.directory)
    metadata = _safe_regular(args.source, mode_mask=0o077)
    content = args.source.read_bytes()
    try:
        anchor = json.loads(content)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MaterialError("staged rollback anchor is unreadable") from error
    required_keys = {
        "schema",
        "revision",
        "release_digest",
        "release_path",
        "public_image_id",
        "internal_image_id",
        "public_image_ref",
        "internal_image_ref",
        "public_saved_ref",
        "internal_saved_ref",
        "recorded_at",
    }
    if (
        not isinstance(anchor, dict)
        or set(anchor) != required_keys
        or anchor.get("schema") != "qdev-controller-rollback-anchor-v1"
    ):
        raise MaterialError("staged rollback anchor schema is invalid")
    revision = anchor.get("revision")
    if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise MaterialError("staged rollback anchor revision is invalid")
    if re.fullmatch(r"sha256:[0-9a-f]{64}", str(anchor.get("release_digest"))) is None:
        raise MaterialError("staged rollback anchor release digest is invalid")
    expected = {
        "release_path": value.get("previous_release_path"),
        "public_image_id": value.get("previous_public_image"),
        "internal_image_id": value.get("previous_internal_image"),
        "public_image_ref": value.get("previous_public_ref"),
        "internal_image_ref": value.get("previous_internal_ref"),
        "public_saved_ref": f"qdev-runner-controller-anchor-public:{revision}",
        "internal_saved_ref": f"qdev-runner-controller-anchor-internal:{revision}",
    }
    if any(anchor.get(key) != expected_value for key, expected_value in expected.items()):
        raise MaterialError("staged rollback anchor does not match preserved runtime material")
    if not isinstance(anchor.get("recorded_at"), str) or not anchor["recorded_at"].endswith("Z"):
        raise MaterialError("staged rollback anchor timestamp is invalid")
    _atomic_bytes(args.directory / "staged-rollback-anchor.json", content, mode=0o600)
    value["staged_anchor_sha256"] = hashlib.sha256(content).hexdigest()
    value["staged_anchor_mode"] = stat.S_IMODE(metadata.st_mode)
    value["staged_public_saved_ref"] = anchor["public_saved_ref"]
    value["staged_internal_saved_ref"] = anchor["internal_saved_ref"]
    _atomic_json(args.directory / "material.json", value)
    return value


def publish_anchor(args: argparse.Namespace) -> dict[str, Any]:
    value = _load(args.directory)
    source = args.directory / "staged-rollback-anchor.json"
    _safe_regular(source, mode_mask=0o077)
    content = source.read_bytes()
    if hashlib.sha256(content).hexdigest() != value.get("staged_anchor_sha256"):
        raise MaterialError("staged rollback anchor digest mismatch")
    _atomic_bytes(args.destination, content, mode=0o600)
    value["phase"] = "anchor-published"
    _atomic_json(args.directory / "material.json", value)
    return value


def finish(args: argparse.Namespace) -> dict[str, Any]:
    value = _load(args.directory)
    if args.outcome not in {"rolled-back", "finalized"}:
        raise MaterialError("terminal activation material outcome is invalid")
    value["phase"] = args.outcome
    _atomic_json(args.directory / "material.json", value)
    root = args.directory.parent
    _safe_directory(root)
    expected = root / f"{value['transaction_id']}-{value['envelope_digest']}"
    if args.directory != expected:
        raise MaterialError("activation material directory identity is invalid")
    for path in args.directory.rglob("*"):
        if path.is_symlink():
            raise MaterialError("activation material contains an unsafe symlink")
    retired = root / f".{args.directory.name}.{args.outcome}.{os.getpid()}.retired"
    if retired.exists() or retired.is_symlink():
        raise MaterialError("activation material retirement path already exists")
    os.rename(args.directory, retired)
    _fsync_directory(root)
    shutil.rmtree(retired)
    _fsync_directory(root)
    return value


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)
    create = commands.add_parser("prepare")
    create.add_argument("--root", type=Path, required=True)
    create.add_argument("--transaction-id", required=True)
    create.add_argument("--envelope-digest", required=True)
    create.add_argument("--release-path", required=True)
    create.add_argument("--previous-release-path", default="")
    for name in (
        "previous-public-image",
        "previous-public-ref",
        "previous-internal-image",
        "previous-internal-ref",
        "rollback-public-ref",
        "rollback-internal-ref",
        "dispatcher-enabled",
        "dispatcher-active",
    ):
        create.add_argument(f"--{name}", default="")
    create.add_argument("--snapshot", action="append", default=[])
    for name in (
        "show",
        "restore",
        "extract",
        "phase",
        "install",
        "activate-link",
        "stage-anchor",
        "publish-anchor",
        "finish",
    ):
        command = commands.add_parser(name)
        command.add_argument("--directory", type=Path, required=True)
        if name == "restore":
            command.add_argument("--group", action="append", required=True)
        elif name == "extract":
            command.add_argument("--destination", required=True)
            command.add_argument("--output", type=Path, required=True)
        elif name == "phase":
            command.add_argument("--phase", required=True)
        elif name == "install":
            command.add_argument("--source", type=Path, required=True)
            command.add_argument("--destination", type=Path, required=True)
            command.add_argument("--mode", type=lambda value: int(value, 8), required=True)
            command.add_argument("--uid", type=int, default=0)
            command.add_argument("--gid", type=int, default=0)
        elif name == "activate-link":
            command.add_argument("--link", type=Path, required=True)
            command.add_argument("--target", type=Path, required=True)
        elif name == "stage-anchor":
            command.add_argument("--source", type=Path, required=True)
        elif name == "publish-anchor":
            command.add_argument("--destination", type=Path, required=True)
        elif name == "finish":
            command.add_argument("--outcome", required=True)
    return result


def main() -> int:
    args = parser().parse_args()
    try:
        if args.command == "prepare":
            value = prepare(args)
        elif args.command == "show":
            value = _load(args.directory)
        elif args.command == "restore":
            value = restore(args)
        elif args.command == "extract":
            value = extract(args)
        elif args.command == "phase":
            value = set_phase(args)
        elif args.command == "install":
            value = install_file(args)
        elif args.command == "activate-link":
            value = activate_link(args)
        elif args.command == "stage-anchor":
            value = stage_anchor(args)
        elif args.command == "publish-anchor":
            value = publish_anchor(args)
        elif args.command == "finish":
            value = finish(args)
        else:  # pragma: no cover
            raise MaterialError("unknown activation material command")
    except (MaterialError, OSError, ValueError, KeyError, TypeError) as error:
        print(str(error), file=sys.stderr)
        return 2
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
