#!/usr/bin/env python3
"""One complete verification entrypoint for hosted, owner recovery and local CI."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


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
    if lane == "managed":
        if environment.get("QDEV_MANAGED_CI") != "true" or not expected:
            raise ValueError("managed CI requires an exact controller-bound checkout")
        if not environment.get("RUNNER_NAME"):
            raise ValueError("managed CI requires an enrolled ephemeral runner")
        event = environment.get("GITHUB_EVENT_NAME")
        if event not in {"push", "workflow_dispatch", "pull_request"}:
            raise ValueError("managed CI received an untrusted event")
        owner = environment.get("GITHUB_REPOSITORY_OWNER", "")
        expected_repository = f"{owner}/qdev-runner-control-plane"
        if not owner or environment.get("GITHUB_REPOSITORY") != expected_repository:
            raise ValueError("managed CI is bound to the controller repository")
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
    parser.add_argument(
        "--lane", choices=("local", "hosted", "managed", "controller-recovery"), required=True
    )
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
    for command in commands(sys.executable):
        subprocess.run(command, cwd=ROOT, check=True)
    print(
        json.dumps(
            {
                "schema": "qdev-controller-ci-execution-v1",
                "sha": sha,
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
