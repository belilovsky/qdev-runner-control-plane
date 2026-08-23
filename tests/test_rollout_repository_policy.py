from __future__ import annotations

import importlib.util
import shutil
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]
GIT = shutil.which("git")
assert GIT is not None


def load_rollout() -> ModuleType:
    path = ROOT / "scripts/rollout_repository_policy.py"
    spec = importlib.util.spec_from_file_location("rollout_repository_policy", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def git(repo: Path, *args: str) -> None:
    subprocess.run(  # noqa: S603
        [GIT, *args], cwd=repo, check=True, capture_output=True
    )


def conflicting_repository(tmp_path: Path, path: str) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    git(repo, "init", "-b", "master")
    git(repo, "config", "user.name", "Test")
    git(repo, "config", "user.email", "test@example.com")
    target = repo / path
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text("base\n", encoding="utf-8")
    git(repo, "add", path)
    git(repo, "commit", "-m", "base")
    git(repo, "checkout", "-b", "policy")
    target.write_text("policy\n", encoding="utf-8")
    git(repo, "commit", "-am", "policy")
    git(repo, "checkout", "master")
    target.write_text("default\n", encoding="utf-8")
    git(repo, "commit", "-am", "default")
    git(repo, "update-ref", "refs/remotes/origin/master", "master")
    git(repo, "checkout", "policy")
    return repo


def test_merge_default_preserves_default_side_of_managed_conflict(tmp_path: Path) -> None:
    repo = conflicting_repository(tmp_path, "AGENTS.md")
    load_rollout().merge_default(repo, "master")
    assert (repo / "AGENTS.md").read_text(encoding="utf-8") == "default\n"
    assert subprocess.run(  # noqa: S603
        [GIT, "diff", "--name-only", "--diff-filter=U"],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    ).stdout == ""


def test_merge_default_rejects_product_conflict(tmp_path: Path) -> None:
    repo = conflicting_repository(tmp_path, "product.txt")
    with pytest.raises(subprocess.CalledProcessError):
        load_rollout().merge_default(repo, "master")
