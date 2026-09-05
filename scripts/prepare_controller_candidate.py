#!/usr/bin/python3
"""Root-owned preparation of one clean controller release candidate."""

from __future__ import annotations

import fcntl
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if SOURCE_ROOT.is_dir():
    sys.path.insert(0, str(SOURCE_ROOT))

from qdev_runner.admin_platform_state import AdminPlatformStateError  # noqa: E402
from qdev_runner.controller_candidate import (  # noqa: E402
    ControllerCandidateError,
    prepare_controller_candidate,
)
from qdev_runner.fleet_host_dispatch import (  # noqa: E402
    FleetHostDispatchError,
    verified_controller_runtime_anchor,
)

RELEASES_ROOT = Path("/opt/qdev-runner-control-plane/releases")
LEDGER_PATH = Path("/var/lib/qdev-runner/admin-platform-state/admin-platform-ledger.yml")
RECEIPT_ROOT = Path("/var/lib/qdev-runner/admin-platform-receipts")
SIGNER_STATE_ROOT = Path("/var/lib/qdev-runner/admin-platform-bootstrap")
BROKER_ENV_PATH = Path("/etc/qdev-runner/broker.env")
RELEASE_STATUS_PATH = Path("/var/lib/qdev-runner/controller-status/controller-release.json")
RELEASE_LOCK_PATH = Path("/run/lock/qdev-controller-release.lock")
RUNTIME_UID = 9020
RUNTIME_GID = 9020


def _git(release: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(release), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ControllerCandidateError("controller release Git identity is unavailable") from exc
    return result.stdout.strip()


def _exact_release(argument: str) -> tuple[Path, str]:
    try:
        releases = RELEASES_ROOT.resolve(strict=True)
        release = Path(argument).resolve(strict=True)
    except OSError as exc:
        raise ControllerCandidateError("controller release is unavailable") from exc
    if release.parent != releases or release.name == "":
        raise ControllerCandidateError("controller release is outside the release archive")
    for path in (releases, release):
        metadata = path.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ControllerCandidateError("controller release ownership is unsafe")
    root = Path(_git(release, "rev-parse", "--show-toplevel")).resolve(strict=True)
    source_sha = _git(release, "rev-parse", "HEAD")
    if root != release or release.name != source_sha:
        raise ControllerCandidateError("controller release path is not bound to its exact SHA")
    if _git(release, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ControllerCandidateError("controller release contains uncommitted files")
    return release, source_sha


def _receipt_key() -> str:
    try:
        metadata = BROKER_ENV_PATH.lstat()
        raw = BROKER_ENV_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        raise ControllerCandidateError("broker environment is unavailable") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise ControllerCandidateError("broker environment ownership is unsafe")
    values = [
        line.partition("=")[2]
        for line in raw.splitlines()
        if line.partition("=")[0] == "QDEV_OPERATOR_RECEIPT_KEY" and "=" in line
    ]
    if len(values) != 1 or re.fullmatch(r"[A-Za-z0-9_-]{32,256}", values[0]) is None:
        raise ControllerCandidateError("controller receipt key is unavailable")
    return values[0]


def _active_runtime_source_sha() -> str:
    try:
        revision, _ = verified_controller_runtime_anchor(
            RELEASE_STATUS_PATH,
            expected_uid=os.geteuid(),
        )
    except FleetHostDispatchError as exc:
        raise ControllerCandidateError("active controller status is unsafe") from exc
    return revision


@contextmanager
def _release_lock() -> Iterator[None]:
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(RELEASE_LOCK_PATH, flags, 0o600)
    except OSError as exc:
        raise ControllerCandidateError("controller release lock is unavailable") from exc
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != 0:
            raise ControllerCandidateError("controller release lock is unsafe")
        os.fchmod(descriptor, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ControllerCandidateError(
                "another controller release transaction is active"
            ) from exc
        yield
    finally:
        os.close(descriptor)


def main() -> int:
    if os.geteuid() != 0:
        raise ControllerCandidateError("root identity is required")
    if len(sys.argv) != 2:
        raise ControllerCandidateError("usage: prepare_controller_candidate.py RELEASE")
    with _release_lock():
        _, source_sha = _exact_release(sys.argv[1])
        result = prepare_controller_candidate(
            source_sha=source_sha,
            expected_current_source_sha=_active_runtime_source_sha(),
            receipt_key=_receipt_key(),
            ledger_path=LEDGER_PATH,
            receipt_root=RECEIPT_ROOT,
            signer_state_root=SIGNER_STATE_ROOT,
            runtime_uid=RUNTIME_UID,
            runtime_gid=RUNTIME_GID,
        )
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ControllerCandidateError, AdminPlatformStateError, OSError) as error:
        print(f"controller_candidate_preparation_failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
