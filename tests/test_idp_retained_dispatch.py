"""Private retained inputs are not CI, admission, or production evidence."""

import json
import os
import stat
import tempfile
from pathlib import Path

import pytest

from qdev_runner import idp_retained_dispatch as storage

TRANSACTION = "retention-test-001"
JOB = {"synthetic_job": True}
CANDIDATE = {"synthetic_candidate": True}
ARCHIVE = b"synthetic-storage-only-not-an-artifact"


@pytest.fixture
def store(monkeypatch):
    # /var and /tmp can be symlinks on macOS. Use private fixture data beneath
    # the checkout, retaining the real no-follow traversal on every component.
    with tempfile.TemporaryDirectory(prefix=".retention-test-", dir=Path.cwd()) as temporary:
        root = Path(temporary) / "dispatches"
        monkeypatch.setattr(storage, "OWNER_UID", os.getuid())
        monkeypatch.setattr(storage, "ROOT", root)
        yield root


def save():
    storage.retain(TRANSACTION, JOB, CANDIDATE, ARCHIVE)


def assert_saved():
    metadata, archive = storage.read(TRANSACTION)
    assert metadata["job"] == JOB
    assert metadata["candidate"] == CANDIDATE
    assert archive == ARCHIVE


def test_exact_retry_is_immutable_and_private(store, monkeypatch):
    assert storage.read(TRANSACTION) is None
    assert not store.exists()
    save()
    snapshots = {p.name: (p.read_bytes(), p.stat().st_ino) for p in (store / TRANSACTION).iterdir()}
    monkeypatch.setattr(storage, "_write_file", lambda *a: pytest.fail("rewrite"))
    save()
    assert_saved()
    assert snapshots == {
        p.name: (p.read_bytes(), p.stat().st_ino) for p in (store / TRANSACTION).iterdir()
    }
    assert stat.S_IMODE(store.stat().st_mode) == 0o700
    assert stat.S_IMODE((store / TRANSACTION).stat().st_mode) == 0o700
    for path in [store / "intake.lock", *(store / TRANSACTION).iterdir()]:
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
        assert path.stat().st_nlink == 1


@pytest.mark.parametrize("change", ["job", "candidate", "archive"])
def test_conflicting_retry_never_overwrites(store, change):
    save()
    args = [TRANSACTION, JOB, CANDIDATE, ARCHIVE]
    args[{"job": 1, "candidate": 2, "archive": 3}[change]] = (
        b"different" if change == "archive" else {"different": True}
    )
    with pytest.raises(storage.RetentionError, match="immutable"):
        storage.retain(*args)
    assert_saved()


@pytest.mark.parametrize("name", ["dispatch.json", "artifact.tar.gz"])
@pytest.mark.parametrize("fault", ["missing", "content", "mode", "symlink", "hardlink"])
def test_corrupt_publication_is_not_repaired(store, name, fault):
    save()
    path = store / TRANSACTION / name
    if fault == "missing":
        path.unlink()
    elif fault == "content":
        path.write_bytes(b"corrupt-synthetic-input")
    elif fault == "mode":
        path.chmod(0o644)
    elif fault == "hardlink":
        os.link(path, store / "outside")
    else:
        path.rename(store / "outside")
        path.symlink_to(store / "outside")
    with pytest.raises((ValueError, OSError)):
        storage.read(TRANSACTION)
    with pytest.raises((ValueError, OSError)):
        save()


@pytest.mark.parametrize("target", ["root", "transaction", "ancestor", "lock"])
def test_symlink_component_is_rejected(store, target, monkeypatch):
    save()
    path = {
        "root": store, "transaction": store / TRANSACTION,
        "ancestor": store.parent, "lock": store / "intake.lock",
    }[target]
    if target == "ancestor":
        alias = store.parent / "alias"
        alias.symlink_to(store.parent, target_is_directory=True)
        monkeypatch.setattr(storage, "ROOT", alias / "dispatches")
    else:
        outside = path.with_name(path.name + "-original")
        path.rename(outside)
        path.symlink_to(outside, target_is_directory=outside.is_dir())
    with pytest.raises((storage.RetentionError, OSError)):
        save()


@pytest.mark.parametrize("target", ["root", "transaction", "ancestor", "lock"])
def test_writable_or_nonprivate_mode_is_rejected(store, target):
    save()
    path = {
        "root": store, "transaction": store / TRANSACTION,
        "ancestor": store.parent, "lock": store / "intake.lock",
    }[target]
    original = stat.S_IMODE(path.stat().st_mode)
    try:
        path.chmod(0o777 if path.is_dir() else 0o666)
        with pytest.raises(storage.RetentionError):
            save()
    finally:
        path.chmod(original)


@pytest.mark.parametrize("kind", ["directory", "file"])
def test_wrong_owner_rejected(store, monkeypatch, kind):
    save()
    original = storage.os.fstat

    def wrong_owner(fd):
        value = original(fd)
        if (stat.S_ISDIR(value.st_mode)) == (kind == "directory"):
            values = list(value)
            values[4] = 999999
            return os.stat_result(values)
        return value

    monkeypatch.setattr(storage.os, "fstat", wrong_owner)
    with pytest.raises(storage.RetentionError):
        storage.read(TRANSACTION)


def test_nonregular_file_is_rejected_without_blocking(store):
    save()
    path = store / TRANSACTION / "artifact.tar.gz"
    path.unlink()
    os.mkfifo(path, 0o600)
    with pytest.raises(storage.RetentionError):
        storage.read(TRANSACTION)


def test_concurrent_intake_is_nonblocking_and_no_partial_publish(store):
    with storage._root(create=True) as root, storage._lock(root):
        with pytest.raises(BlockingIOError):
            save()
        assert storage.read(TRANSACTION) is None
    save()
    assert_saved()


@pytest.mark.parametrize("after", [False, True])
@pytest.mark.parametrize("phase", ["artifact.tar.gz", "dispatch.json", "rename"])
def test_interruption_at_every_write_and_publish_boundary(store, monkeypatch, phase, after):
    original_write, original_rename = storage._write_file, storage.os.rename

    def write(fd, name, data):
        if after or name != phase:
            original_write(fd, name, data)
        if name == phase:
            raise OSError("synthetic-interruption")

    def rename(*args, **kwargs):
        if after:
            original_rename(*args, **kwargs)
        raise OSError("synthetic-interruption")

    with monkeypatch.context() as patch:
        if phase == "rename":
            patch.setattr(storage.os, "rename", rename)
        else:
            patch.setattr(storage, "_write_file", write)
        with pytest.raises(OSError, match="synthetic"):
            save()
    result = storage.read(TRANSACTION)
    assert (result is not None) == (phase == "rename" and after)
    save()
    assert_saved()
    assert len([p for p in store.iterdir() if p.name == TRANSACTION]) == 1


@pytest.mark.parametrize("after", [False, True])
def test_interruption_at_every_fsync_boundary(store, monkeypatch, after):
    original = storage.os.fsync
    calls = []

    def count(fd):
        calls.append(fd)
        original(fd)

    with monkeypatch.context() as patch:
        patch.setattr(storage.os, "fsync", count)
        save()
    for boundary in range(len(calls)):
        selected_root = store.with_name(f"dispatches-{boundary}")
        index = 0

        def interrupt(fd, boundary=boundary):
            nonlocal index
            current = index
            index += 1
            if after or current != boundary:
                original(fd)
            if current == boundary:
                raise OSError("synthetic-fsync-interruption")

        with monkeypatch.context() as patch:
            patch.setattr(storage, "ROOT", selected_root)
            with patch.context() as fault:
                fault.setattr(storage.os, "fsync", interrupt)
                with pytest.raises(OSError, match="synthetic"):
                    save()
            # Every interruption leaves either no publication or a complete set.
            if storage.read(TRANSACTION) is not None:
                assert_saved()
            save()
            assert_saved()


@pytest.mark.parametrize("name", ["../escape", "/absolute", "short", "a" * 81, None])
def test_invalid_transaction_no_write(store, name):
    with pytest.raises(storage.RetentionError):
        storage.retain(name, JOB, CANDIDATE, ARCHIVE)
    assert not store.exists()


def test_noncanonical_metadata_and_extra_members_rejected(store):
    save()
    path = store / TRANSACTION / "dispatch.json"
    metadata = json.loads(path.read_bytes())
    original = path.read_bytes()
    path.write_text(json.dumps(metadata))
    with pytest.raises(storage.RetentionError):
        storage.read(TRANSACTION)
    path.write_bytes(original)
    (path.parent / "unexpected").touch()
    with pytest.raises(storage.RetentionError):
        storage.read(TRANSACTION)


@pytest.mark.parametrize("bound", ["MAX_ARCHIVE", "MAX_METADATA"])
def test_oversized_input_rejected_before_write(store, monkeypatch, bound):
    monkeypatch.setattr(storage, bound, 1)
    with pytest.raises(storage.RetentionError):
        save()
    assert not store.exists()
