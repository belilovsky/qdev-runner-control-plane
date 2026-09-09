"""Deterministic identity for one controller release checkout.

The digest intentionally covers only Git-tracked controller runtime inputs.
It is computed from the checked-out source and is never stored inside the
release policy, avoiding a self-referential release digest.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
from pathlib import Path

_RELEASE_SCOPES = (
    "pyproject.toml",
    "requirements.runtime.txt",
    "src/qdev_runner",
    "scripts",
    "deploy",
    "config",
    "inventory",
)
_GIT = "/usr/bin/git"
_REQUIRED_FILES = frozenset(
    {
        "pyproject.toml",
        "requirements.runtime.txt",
        "src/qdev_runner/controller_release.py",
        "src/qdev_runner/controller_candidate.py",
        "src/qdev_runner/controller_activation_assets.py",
        "src/qdev_runner/controller_recovery_artifact.py",
        "src/qdev_runner/durable_state.py",
        "scripts/activate_controller_release.sh",
        "scripts/prepare_controller_candidate.py",
        "scripts/controller_activation_assets.py",
        "scripts/controller_recovery_artifact.py",
        "scripts/rollback_controller_release.sh",
        "scripts/qdev_controller_activation_adapter.py",
        "scripts/qdev_release_host_agent_enrol_adapter.py",
        "scripts/qdev_fleet_worker_recovery_adapter.py",
        "scripts/qdev_runner_recovery_host_agent.py",
        "scripts/install_qdev_runner_recovery_host_agent.sh",
        "scripts/issue_scoped_worker_certificate.sh",
        "scripts/provision_fleet_host_dispatch_state.py",
        "deploy/qdev-runner-recovery-platform.service",
        "deploy/qdev-runner-recovery-qazstack.service",
        "config/fleet-bootstrap.yml",
        "config/controller-capacity.json",
        "config/admin-platform-package-bindings.json",
        "config/release-lanes.yml",
        "deploy/compose.yml",
    }
)


class ControllerReleaseIdentityError(RuntimeError):
    """The supplied checkout cannot be used as an immutable release."""


def _git(root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(  # noqa: S603
            [_GIT, "-C", os.fspath(root), *arguments],
            check=False,
            capture_output=True,
        )
    except OSError as exc:
        raise ControllerReleaseIdentityError("git is unavailable") from exc
    if completed.returncode != 0:
        raise ControllerReleaseIdentityError("controller release Git identity is unavailable")
    return completed.stdout


def controller_release_digest(root: Path) -> str:
    """Return a content and executable-mode digest for one exact checkout."""

    try:
        release_root = root.resolve(strict=True)
    except OSError as exc:
        raise ControllerReleaseIdentityError("controller release root is unavailable") from exc
    if not release_root.is_dir():
        raise ControllerReleaseIdentityError("controller release root is not a directory")

    try:
        top_level = Path(
            _git(release_root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
        ).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as exc:
        raise ControllerReleaseIdentityError("controller release Git root is invalid") from exc
    if top_level != release_root:
        raise ControllerReleaseIdentityError("controller release must be the Git root")

    raw_entries = _git(
        release_root,
        "ls-files",
        "--stage",
        "-z",
        "--",
        *_RELEASE_SCOPES,
    )
    entries: list[tuple[str, str, Path]] = []
    names: set[str] = set()
    for raw_entry in raw_entries.split(b"\0"):
        if not raw_entry:
            continue
        try:
            index_metadata, raw_name = raw_entry.split(b"\t", 1)
            mode, _object_id, stage = index_metadata.decode("ascii").split(" ")
            name = raw_name.decode("utf-8")
        except (ValueError, UnicodeDecodeError) as exc:
            raise ControllerReleaseIdentityError(
                "controller release index entry is invalid"
            ) from exc
        if stage != "0" or mode not in {"100644", "100755"}:
            raise ControllerReleaseIdentityError(
                "controller release contains an unsupported tracked entry"
            )
        path = release_root / name
        try:
            file_stat = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ControllerReleaseIdentityError(
                "controller release tracked file is unavailable"
            ) from exc
        if (
            not stat.S_ISREG(file_stat.st_mode)
            or stat.S_ISLNK(file_stat.st_mode)
            or release_root not in resolved.parents
        ):
            raise ControllerReleaseIdentityError("controller release tracked file is unsafe")
        actual_mode = "100755" if file_stat.st_mode & stat.S_IXUSR else "100644"
        if actual_mode != mode:
            raise ControllerReleaseIdentityError(
                "controller release executable mode differs from the Git index"
            )
        if name in names:
            raise ControllerReleaseIdentityError(
                "controller release contains a duplicate tracked entry"
            )
        names.add(name)
        entries.append((name, mode, path))

    if not _REQUIRED_FILES.issubset(names):
        raise ControllerReleaseIdentityError("controller release is incomplete")

    digest = hashlib.sha256()
    for name, mode, path in sorted(entries):
        digest.update(name.encode("utf-8"))
        digest.update(b"\0")
        digest.update(mode.encode("ascii"))
        digest.update(b"\0")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
        digest.update(b"\0")
    return "sha256:" + digest.hexdigest()


def main() -> None:
    root = Path(sys.argv[1]) if len(sys.argv) == 2 else Path.cwd()
    if len(sys.argv) > 2:
        raise SystemExit("usage: python -m qdev_runner.controller_release [RELEASE_ROOT]")
    try:
        print(controller_release_digest(root))
    except ControllerReleaseIdentityError as exc:
        raise SystemExit(str(exc)) from exc


if __name__ == "__main__":
    main()
