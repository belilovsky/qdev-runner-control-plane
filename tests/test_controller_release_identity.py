from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from qdev_runner.controller_release import (
    ControllerReleaseIdentityError,
    controller_release_digest,
)

ROOT = Path(__file__).resolve().parents[1]
GIT = "/usr/bin/git"


def _copy_release(tmp_path: Path) -> Path:
    release = tmp_path / "release"
    release.mkdir()
    tracked = subprocess.run(  # noqa: S603
        [GIT, "-C", os.fspath(ROOT), "ls-files", "-z"],
        check=True,
        capture_output=True,
    ).stdout
    for raw_name in tracked.split(b"\0"):
        if not raw_name:
            continue
        name = raw_name.decode("utf-8")
        source = ROOT / name
        target = release / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    for new_runtime_module in (
        Path("src/qdev_runner/controller_release.py"),
        Path("src/qdev_runner/controller_candidate.py"),
        Path("src/qdev_runner/durable_state.py"),
        Path("scripts/prepare_controller_candidate.py"),
        Path("src/qdev_runner/controller_recovery_artifact.py"),
        Path("scripts/controller_recovery_artifact.py"),
    ):
        if not (release / new_runtime_module).exists():
            (release / new_runtime_module).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / new_runtime_module, release / new_runtime_module)
    subprocess.run([GIT, "init", "-q", os.fspath(release)], check=True)  # noqa: S603
    subprocess.run([GIT, "-C", os.fspath(release), "add", "."], check=True)  # noqa: S603
    return release


def test_release_digest_is_stable_and_ignores_untracked_files(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    expected = controller_release_digest(release)
    (release / "untracked.txt").write_text("ignored", encoding="utf-8")
    assert controller_release_digest(release) == expected


def test_release_digest_changes_with_runtime_content(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    before = controller_release_digest(release)
    target = release / "config" / "profiles.yml"
    target.write_text(target.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    assert controller_release_digest(release) != before


def test_release_digest_rejects_executable_mode_drift(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    target = release / "scripts" / "activate_controller_release.sh"
    target.chmod(0o644)
    with pytest.raises(ControllerReleaseIdentityError, match="executable mode"):
        controller_release_digest(release)


def test_release_digest_requires_exact_git_root(tmp_path: Path) -> None:
    release = _copy_release(tmp_path)
    with pytest.raises(ControllerReleaseIdentityError, match="Git root"):
        controller_release_digest(release / "src")
