from __future__ import annotations

import os
from pathlib import Path

import pytest

from qdev_runner.durable_state import (
    DurableStateError,
    StateFileSpec,
    migrate_controller_files,
    migrate_state_file,
)


def _spec(tmp_path: Path, *, mode: int = 0o600) -> StateFileSpec:
    root = tmp_path.resolve()
    legacy_root = root / "legacy"
    canonical_root = root / "canonical"
    archive_root = root / "archive"
    for path in (legacy_root, canonical_root, archive_root):
        path.mkdir(mode=0o700)
    uid = os.getuid()
    gid = os.getgid()
    return StateFileSpec(
        name="test",
        legacy_path=legacy_root / "state.json",
        canonical_path=canonical_root / "state.json",
        archive_root=archive_root,
        file_uid=uid,
        file_gid=gid,
        file_mode=mode,
        directory_uid=uid,
        directory_gid=gid,
        directory_mode=0o700,
        archive_mode=0o700,
    )


def _write(path: Path, raw: bytes, mode: int) -> None:
    path.write_bytes(raw)
    path.chmod(mode)


def test_migration_archives_source_and_installs_absolute_compatibility_link(
    tmp_path: Path,
) -> None:
    spec = _spec(tmp_path)
    raw = b'{"schema":"test-v1"}\n'
    _write(spec.legacy_path, raw, spec.file_mode)

    archive = migrate_state_file(spec)

    assert archive is not None
    assert archive.read_bytes() == raw
    assert spec.canonical_path.read_bytes() == raw
    assert spec.canonical_path.stat().st_mode & 0o777 == spec.file_mode
    assert spec.legacy_path.is_symlink()
    assert os.readlink(spec.legacy_path) == os.fspath(spec.canonical_path)
    assert migrate_state_file(spec) is None


def test_migration_rejects_conflicting_legacy_and_canonical_files(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    _write(spec.legacy_path, b"legacy\n", spec.file_mode)
    _write(spec.canonical_path, b"canonical\n", spec.file_mode)

    with pytest.raises(DurableStateError, match="conflict"):
        migrate_state_file(spec)

    assert not spec.legacy_path.is_symlink()
    assert list(spec.archive_root.iterdir()) == []


def test_migration_rejects_unsafe_file_and_link_permissions(tmp_path: Path) -> None:
    spec = _spec(tmp_path)
    _write(spec.legacy_path, b"unsafe\n", 0o644)
    with pytest.raises(DurableStateError, match="permissions"):
        migrate_state_file(spec)

    spec.legacy_path.unlink()
    _write(spec.canonical_path, b"canonical\n", spec.file_mode)
    spec.legacy_path.symlink_to(spec.canonical_path)
    if hasattr(os, "lchown"):
        os.lchown(spec.legacy_path, os.getuid(), os.getgid())
    assert migrate_state_file(spec) is None


def test_migration_rejects_empty_duplicate_or_unknown_selection() -> None:
    with pytest.raises(DurableStateError, match="empty"):
        migrate_controller_files([])
    with pytest.raises(DurableStateError, match="invalid"):
        migrate_controller_files(["status", "status"])
    with pytest.raises(DurableStateError, match="invalid"):
        migrate_controller_files(["unknown"])
