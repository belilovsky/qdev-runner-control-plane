"""Safe migration for controller files consumed through container bind mounts.

Docker binds a single host file by inode.  Replacing that file atomically on
the host therefore leaves a running container reading the old inode.  These
two controller records live in dedicated, directory-mounted stores instead;
the historical ``/etc`` paths remain compatibility symlinks for old releases.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import os
import stat
import sys
import tempfile
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Final


class DurableStateError(RuntimeError):
    """A controller state file cannot be migrated without weakening safety."""


@dataclass(frozen=True)
class StateFileSpec:
    """Fixed ownership and location contract for one durable state file."""

    name: str
    legacy_path: Path
    canonical_path: Path
    archive_root: Path
    file_uid: int
    file_gid: int
    file_mode: int
    directory_uid: int = 0
    directory_gid: int = 0
    directory_mode: int = 0o755
    archive_mode: int = 0o700


STATUS_SPEC: Final = StateFileSpec(
    name="status",
    legacy_path=Path("/etc/qdev-runner/controller-release.json"),
    canonical_path=Path("/var/lib/qdev-runner/controller-status/controller-release.json"),
    archive_root=Path("/var/lib/qdev-runner/controller-status-migrations"),
    file_uid=0,
    file_gid=0,
    file_mode=0o644,
)
LEDGER_SPEC: Final = StateFileSpec(
    name="ledger",
    legacy_path=Path("/etc/qdev-runner/admin-platform-ledger.yml"),
    canonical_path=Path("/var/lib/qdev-runner/admin-platform-state/admin-platform-ledger.yml"),
    archive_root=Path("/var/lib/qdev-runner/admin-platform-ledger-migrations"),
    file_uid=9020,
    file_gid=9020,
    file_mode=0o600,
)
_SPECS: Final = {"status": STATUS_SPEC, "ledger": LEDGER_SPEC}


def _metadata(path: Path) -> os.stat_result | None:
    try:
        return path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise DurableStateError(f"{path} metadata is unavailable") from exc


def _fsync_directory(path: Path) -> None:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    except OSError as exc:
        raise DurableStateError(f"{path} cannot be opened for durable update") from exc
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    metadata = _metadata(path)
    if metadata is None:
        raise DurableStateError(f"{path} directory is unavailable")
    try:
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise DurableStateError(f"{path} directory cannot be resolved") from exc
    if (
        not path.is_absolute()
        or resolved != path
        or not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != uid
        or metadata.st_gid != gid
        or stat.S_IMODE(metadata.st_mode) != mode
    ):
        raise DurableStateError(f"{path} directory ownership or permissions are unsafe")


def _ensure_directory(
    path: Path,
    *,
    uid: int,
    gid: int,
    mode: int,
) -> None:
    if not path.is_absolute():
        raise DurableStateError(f"{path} must be absolute")
    metadata = _metadata(path)
    if metadata is None:
        parent = path.parent
        parent_metadata = _metadata(parent)
        if (
            parent_metadata is None
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_ISLNK(parent_metadata.st_mode)
        ):
            raise DurableStateError(f"{parent} parent directory is unsafe")
        try:
            path.mkdir(mode=mode)
            os.chown(path, uid, gid)
            os.chmod(path, mode)
            _fsync_directory(parent)
        except OSError as exc:
            raise DurableStateError(f"{path} directory cannot be created safely") from exc
    _validate_directory(path, uid=uid, gid=gid, mode=mode)


def _validate_regular_file(path: Path, spec: StateFileSpec) -> bytes:
    metadata = _metadata(path)
    if (
        metadata is None
        or not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != spec.file_uid
        or metadata.st_gid != spec.file_gid
        or stat.S_IMODE(metadata.st_mode) != spec.file_mode
    ):
        raise DurableStateError(f"{spec.name} file ownership or permissions are unsafe")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise DurableStateError(f"{spec.name} file is unreadable") from exc


def _write_atomic(raw: bytes, destination: Path, spec: StateFileSpec) -> None:
    descriptor, temporary_name = tempfile.mkstemp(
        dir=destination.parent,
        prefix=f".{destination.name}.",
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), spec.file_mode)
            current = os.fstat(stream.fileno())
            if current.st_uid != spec.file_uid or current.st_gid != spec.file_gid:
                os.fchown(stream.fileno(), spec.file_uid, spec.file_gid)
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        _fsync_directory(destination.parent)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def _archive_legacy(raw: bytes, spec: StateFileSpec) -> Path:
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    digest = hashlib.sha256(raw).hexdigest()
    destination = spec.archive_root / (f"{spec.legacy_path.name}.{digest}.legacy-{timestamp}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(destination, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fchmod(stream.fileno(), 0o600)
            current = os.fstat(stream.fileno())
            if current.st_uid != spec.directory_uid or current.st_gid != spec.directory_gid:
                os.fchown(stream.fileno(), spec.directory_uid, spec.directory_gid)
            os.fsync(stream.fileno())
        _fsync_directory(spec.archive_root)
    except OSError as exc:
        destination.unlink(missing_ok=True)
        raise DurableStateError(f"{spec.name} legacy file could not be archived") from exc
    return destination


def _replace_with_compatibility_link(spec: StateFileSpec) -> None:
    temporary = spec.legacy_path.parent / (
        f".{spec.legacy_path.name}.link.{os.getpid()}.{os.urandom(8).hex()}"
    )
    try:
        os.symlink(os.fspath(spec.canonical_path), temporary)
        os.replace(temporary, spec.legacy_path)
        _fsync_directory(spec.legacy_path.parent)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise DurableStateError(f"{spec.name} compatibility link could not be installed") from exc


def migrate_state_file(spec: StateFileSpec) -> Path | None:
    """Migrate one fixed file and return its immutable legacy archive, if any."""

    for path in (spec.legacy_path, spec.canonical_path, spec.archive_root):
        if not path.is_absolute():
            raise DurableStateError(f"{spec.name} state paths must be absolute")
    _validate_directory(
        spec.legacy_path.parent,
        uid=spec.directory_uid,
        gid=spec.directory_gid,
        mode=spec.directory_mode,
    )
    _ensure_directory(
        spec.canonical_path.parent,
        uid=spec.directory_uid,
        gid=spec.directory_gid,
        mode=spec.directory_mode,
    )
    _ensure_directory(
        spec.archive_root,
        uid=spec.directory_uid,
        gid=spec.directory_gid,
        mode=spec.archive_mode,
    )

    canonical_metadata = _metadata(spec.canonical_path)
    legacy_metadata = _metadata(spec.legacy_path)
    if canonical_metadata is None:
        if legacy_metadata is None or stat.S_ISLNK(legacy_metadata.st_mode):
            raise DurableStateError(f"{spec.name} source file is unavailable")
        raw = _validate_regular_file(spec.legacy_path, spec)
        _write_atomic(raw, spec.canonical_path, spec)
    canonical_raw = _validate_regular_file(spec.canonical_path, spec)

    legacy_metadata = _metadata(spec.legacy_path)
    if legacy_metadata is not None and stat.S_ISLNK(legacy_metadata.st_mode):
        try:
            target = os.readlink(spec.legacy_path)
        except OSError as exc:
            raise DurableStateError(f"{spec.name} compatibility link is unreadable") from exc
        if legacy_metadata.st_uid != spec.directory_uid or target != os.fspath(spec.canonical_path):
            raise DurableStateError(f"{spec.name} compatibility link is unsafe")
        return None
    if legacy_metadata is not None:
        legacy_raw = _validate_regular_file(spec.legacy_path, spec)
        if legacy_raw != canonical_raw:
            raise DurableStateError(f"{spec.name} legacy and canonical files conflict")
        archive = _archive_legacy(legacy_raw, spec)
    else:
        archive = None
    _replace_with_compatibility_link(spec)
    return archive


def migrate_controller_files(names: Iterable[str]) -> dict[str, str | None]:
    selected = tuple(names)
    if not selected:
        raise DurableStateError("durable state selection is empty")
    if len(set(selected)) != len(selected) or any(name not in _SPECS for name in selected):
        raise DurableStateError("durable state selection is invalid")

    results: dict[str, str | None] = {}
    for name in selected:
        spec = _SPECS[name]
        archive = migrate_state_file(spec)
        results[name] = os.fspath(archive) if archive is not None else None
    return results


def main() -> None:
    if os.geteuid() != 0:
        raise SystemExit("durable controller migration requires root")
    names = sys.argv[1:]
    if any(name not in _SPECS for name in names) or len(set(names)) != len(names):
        raise SystemExit("usage: python -m qdev_runner.durable_state [status] [ledger]")
    try:
        results = migrate_controller_files(names)
    except DurableStateError as exc:
        raise SystemExit(str(exc)) from exc
    for name, archive in results.items():
        print(f"{name}_canonical={_SPECS[name].canonical_path} archive={archive or 'none'}")


if __name__ == "__main__":
    main()
