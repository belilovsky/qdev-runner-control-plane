"""Private immutable input retention for the existing IdP host invocation.

This is storage, not admission: the host verifies signatures and all archive
members before retention and again before execution. No helper is loaded here.
Only a completed directory rename publishes inputs; interrupted temporary
directories are retained, never mistaken for an executable operation.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import secrets
import stat
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Any

from .idp_native_bundle import MAX_ARCHIVE

ROOT = Path("/var/lib/qdev-idp/dispatches")
OWNER_UID = 0
SCHEMA = "qdev-idp-retained-dispatch-v1"
MAX_METADATA = 1024 * 1024
DIRECTORY = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class RetentionError(ValueError):
    """Untrusted or incomplete retained inputs; no native execution permitted."""


def transaction_name(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{7,79}", value):
        raise RetentionError("invalid retained IdP transaction")
    return value


def _directory(fd: int, *, private: bool) -> None:
    metadata = os.fstat(fd)
    forbidden = 0o077 if private else 0o022
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid not in ({OWNER_UID} if private else {0, OWNER_UID})
        or stat.S_IMODE(metadata.st_mode) & forbidden
        or (private and stat.S_IMODE(metadata.st_mode) != 0o700)
    ):
        raise RetentionError("unsafe retained IdP directory")


@contextmanager
def _root(*, create: bool) -> Iterator[int]:
    # Traverse pinned descriptors; not resolve(), which would hide symlinks.
    if not ROOT.is_absolute() or ".." in ROOT.parts:
        raise RetentionError("invalid installed IdP retention root")
    fd = os.open(ROOT.anchor, DIRECTORY)
    try:
        _directory(fd, private=False)
        for index, component in enumerate(ROOT.parts[1:], 1):
            last = index == len(ROOT.parts) - 1
            if create and last:
                with suppress(FileExistsError):
                    os.mkdir(component, 0o700, dir_fd=fd)
            child = os.open(component, DIRECTORY, dir_fd=fd)
            try:
                _directory(child, private=last)
                if create:
                    os.fsync(fd)
            except BaseException:
                os.close(child)
                raise
            os.close(fd)
            fd = child
        yield fd
    finally:
        os.close(fd)


def _regular(fd: int, limit: int) -> None:
    metadata = os.fstat(fd)
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != OWNER_UID
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_size > limit
    ):
        raise RetentionError("unsafe retained IdP file")


@contextmanager
def _lock(root: int) -> Iterator[None]:
    fd = os.open(
        "intake.lock",
        os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK,
        0o600,
        dir_fd=root,
    )
    try:
        _regular(fd, 0)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        os.fsync(root)
        yield
    finally:
        os.close(fd)


def _read_file(directory: int, name: str, limit: int) -> bytes:
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    with os.fdopen(fd, "rb") as stream:
        _regular(stream.fileno(), limit)
        value = stream.read(limit + 1)
        if len(value) > limit:
            raise RetentionError("retained IdP input exceeds its bound")
        return value


def _write_file(directory: int, name: str, value: bytes) -> None:
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def _canonical(value: Any) -> bytes:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return (encoded + "\n").encode()


def _load(root: int, transaction: str) -> tuple[dict[str, Any], bytes]:
    directory = os.open(transaction, DIRECTORY, dir_fd=root)
    try:
        _directory(directory, private=True)
        if set(os.listdir(directory)) != {"dispatch.json", "artifact.tar.gz"}:
            raise RetentionError("retained IdP input set is incomplete")
        raw = _read_file(directory, "dispatch.json", MAX_METADATA)
        archive = _read_file(directory, "artifact.tar.gz", MAX_ARCHIVE)
        value = json.loads(raw)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "transaction", "job", "candidate", "archive_sha256"}
            or value.get("schema") != SCHEMA
            or value.get("transaction") != transaction
            or _canonical(value) != raw
            or not archive
            or value.get("archive_sha256") != hashlib.sha256(archive).hexdigest()
            or not isinstance(value.get("job"), dict)
            or not isinstance(value.get("candidate"), dict)
        ):
            raise RetentionError("retained IdP binding is invalid")
        return value, archive
    finally:
        os.close(directory)


def retain(
    transaction: str,
    job: dict[str, Any],
    candidate: dict[str, Any],
    archive: bytes,
) -> None:
    """Persist already-verified inputs; exact replay never overwrites history."""
    transaction_name(transaction)
    if not isinstance(job, dict) or not isinstance(candidate, dict):
        raise RetentionError("invalid retained IdP job or candidate")
    if not isinstance(archive, bytes) or not 0 < len(archive) <= MAX_ARCHIVE:
        raise RetentionError("invalid retained IdP archive size")
    value = {
        "schema": SCHEMA,
        "transaction": transaction,
        "job": job,
        "candidate": candidate,
        "archive_sha256": hashlib.sha256(archive).hexdigest(),
    }
    raw = _canonical(value)
    if len(raw) > MAX_METADATA:
        raise RetentionError("retained IdP metadata exceeds its bound")
    with _root(create=True) as root, _lock(root):
        try:
            existing = _load(root, transaction)
        except FileNotFoundError:
            # Missing members of an existing final directory are corruption,
            # not permission to overwrite or repair its authenticated history.
            try:
                os.stat(transaction, dir_fd=root, follow_symlinks=False)
            except FileNotFoundError:
                pass
            else:
                raise RetentionError("retained IdP input set is incomplete") from None
        else:
            if existing != (value, archive):
                raise RetentionError("immutable retained IdP transaction conflict")
            os.fsync(root)  # Complete a previously interrupted directory sync.
            return
        temporary = f".{transaction}.{secrets.token_hex(8)}.pending"
        os.mkdir(temporary, 0o700, dir_fd=root)
        directory = os.open(temporary, DIRECTORY, dir_fd=root)
        try:
            _directory(directory, private=True)
            _write_file(directory, "artifact.tar.gz", archive)
            _write_file(directory, "dispatch.json", raw)
            os.fsync(directory)
        finally:
            os.close(directory)
        # No other installed owner can publish while intake.lock is held. This
        # lock is released BEFORE native-global or host-journal locks are taken.
        os.rename(temporary, transaction, src_dir_fd=root, dst_dir_fd=root)
        os.fsync(root)


def read(transaction: str) -> tuple[dict[str, Any], bytes] | None:
    """Missing publication is inspectable without running any bundle code."""
    transaction_name(transaction)
    try:
        with _root(create=False) as root:
            try:
                os.stat(transaction, dir_fd=root, follow_symlinks=False)
            except FileNotFoundError:
                return None
            return _load(root, transaction)
    except FileNotFoundError as error:
        # A missing file inside a published directory is not an empty operation.
        if error.filename == ROOT.name:
            return None
        raise RetentionError("retained IdP input set is incomplete") from None
