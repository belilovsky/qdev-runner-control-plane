#!/usr/bin/env python3
"""One complete verification entrypoint for hosted, owner recovery and local CI."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def source_fingerprint(root: Path) -> str:
    names = subprocess.check_output(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"], cwd=root
    )
    digest = hashlib.sha256()
    for name in sorted(set(names.split(b"\0")) - {b""}):
        path = root / os.fsdecode(name)
        digest.update(name + b"\0")
        if path.is_symlink():
            digest.update(b"link:" + os.fsencode(os.readlink(path)))
        elif path.is_file():
            digest.update(str(path.stat().st_mode & 0o111).encode() + b":" + path.read_bytes())
        else:
            digest.update(b"missing")
        digest.update(b"\0")
    return digest.hexdigest()


def validate_context(lane: str, environment: dict[str, str], sha: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("exact checkout SHA is required")
    expected = environment.get("QDEV_EXPECTED_SHA", "")
    if expected and expected != sha:
        raise ValueError("checkout does not match requested SHA")
    if environment.get("GITHUB_ACTIONS") != "true":
        if lane != "local":
            raise ValueError("provider CI evidence requires a real Actions execution")
        return
    if lane == "local":
        raise ValueError("Actions must identify its real execution lane")
    if environment.get("GITHUB_SHA") != sha:
        raise ValueError("provider SHA does not match checkout")
    runner_environment = "github-hosted" if lane == "hosted" else "self-hosted"
    if environment.get("RUNNER_ENVIRONMENT") != runner_environment:
        raise ValueError("runner environment does not match requested execution lane")
    if lane == "controller-recovery":
        owner = environment.get("GITHUB_REPOSITORY_OWNER", "")
        if not owner or environment.get("GITHUB_ACTOR") != owner:
            raise ValueError("recovery requires the nonempty repository owner actor")
        if environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
            raise ValueError("recovery requires manual workflow_dispatch")
        if environment.get("QDEV_OWNER_RECOVERY") != "true" or not expected:
            raise ValueError("explicit owner recovery confirmation and exact SHA are required")


def commands(python: str) -> list[list[str]]:
    # Every lane executes every check. Failures stop the sequence; no partial success receipt.
    return [
        [python, "-m", "ruff", "check", "."],
        [python, "-m", "mypy"],
        [python, "-m", "pytest", "-q"],
        [python, ".github/scripts/qdev-runner-policy.py", "--root", "."],
        [python, "scripts/verify_runtime_install.py"],
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lane", choices=("local", "hosted", "controller-recovery"), required=True)
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        parser.error("complete controller CI requires Python 3.12")
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
    if dirty and args.lane != "local":
        parser.error("provider evidence requires an unchanged exact-SHA checkout")
    try:
        validate_context(args.lane, dict(os.environ), sha)
    except ValueError as error:
        parser.error(str(error))
    fingerprint = source_fingerprint(ROOT)
    for command in commands(sys.executable):
        subprocess.run(command, cwd=ROOT, check=True)
    if (
        source_fingerprint(ROOT) != fingerprint
        or subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip() != sha
    ):
        parser.error("source changed during CI; no success receipt may be issued")
    print(
        json.dumps(
            {
                "schema": "qdev-controller-ci-execution-v1",
                "sha": sha,
                "source_fingerprint": fingerprint,
                "source_scope": "working-tree" if dirty else "commit",
                "dirty": dirty,
                "lane": args.lane,
                "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
                "run_id": os.environ.get("GITHUB_RUN_ID"),
                "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                "checks": ["lint", "typing", "pytest", "runner-policy", "runtime-install"],
                "status": "passed",
                "signed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
