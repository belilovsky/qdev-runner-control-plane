#!/usr/bin/env python3
"""Roll out the managed runner policy through isolated temporary clones."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts/apply_repository_policy.py"
PIN_ACTIONS = ROOT / "scripts/pin_workflow_actions.py"
REWRITE_DEPENDENCIES = ROOT / "scripts/rewrite_github_dependencies.py"
REWRITE_SELECTORS = ROOT / "scripts/rewrite_runner_selectors.py"
MIGRATION_BRANCH = "codex/self-hosted-runner-v1"
POLICY_BRANCH = "codex/qdev-runner-policy-v1"
MANAGED_PATHS = {
    "AGENTS.md",
    ".github/QDEV_RUNNERS.md",
    ".github/scripts/qdev-runner-policy.py",
    ".github/scripts/qdev-upload-artifact.sh",
    ".github/workflows/qdev-runner-contract.yml",
}


def run(args: list[str], cwd: Path | None = None, capture: bool = False) -> str:
    completed = subprocess.run(  # noqa: S603
        args,
        cwd=cwd,
        check=True,
        text=True,
        capture_output=capture,
    )
    return completed.stdout.strip() if capture else ""


def gh_json(args: list[str]) -> Any:
    for attempt in range(5):
        try:
            return json.loads(run(["gh", *args], capture=True))
        except subprocess.CalledProcessError:
            if attempt == 4:
                raise
            time.sleep(0.5 * (2**attempt))
    raise RuntimeError("unreachable GitHub CLI retry state")


def open_pr(full_name: str, branch: str) -> dict[str, Any] | None:
    pulls = gh_json(
        [
            "pr",
            "list",
            "--repo",
            full_name,
            "--state",
            "open",
            "--head",
            branch,
            "--json",
            "number,url",
        ]
    )
    return pulls[0] if pulls else None


def merge_default(checkout: Path, default_branch: str) -> None:
    try:
        run(["git", "merge", "--no-edit", f"origin/{default_branch}"], cwd=checkout)
        return
    except subprocess.CalledProcessError:
        conflicted = set(
            run(
                ["git", "diff", "--name-only", "--diff-filter=U"],
                cwd=checkout,
                capture=True,
            ).splitlines()
        )
        if not conflicted or not conflicted <= MANAGED_PATHS:
            raise
        for path in sorted(conflicted):
            run(["git", "checkout", "--theirs", "--", path], cwd=checkout)
            run(["git", "add", "--", path], cwd=checkout)
        run(["git", "commit", "--no-edit"], cwd=checkout)


def rollout(repo: dict[str, Any], *, prepare_only: bool = False) -> dict[str, Any]:
    full_name = repo["full_name"]
    default_branch = repo["default_branch"]
    migration_pr = open_pr(full_name, MIGRATION_BRANCH)
    policy_pr = open_pr(full_name, POLICY_BRANCH)
    branch = MIGRATION_BRANCH if migration_pr else POLICY_BRANCH
    existing_pr = migration_pr or policy_pr

    with tempfile.TemporaryDirectory(prefix=f"qdev-policy-{full_name.split('/')[-1]}-") as raw:
        checkout = Path(raw) / "repo"
        run(
            [
                "git",
                "-c",
                "http.version=HTTP/1.1",
                "clone",
                "--filter=blob:none",
                "--sparse",
                "--no-checkout",
                f"https://github.com/{full_name}.git",
                str(checkout),
            ]
        )
        # Persist the transport choice for lazy blob fetches triggered later by
        # checkout/merge. GitHub occasionally cancels long-lived HTTP/2 streams
        # in large promisor repositories, leaving an otherwise valid rollout
        # without the managed policy commit.
        run(["git", "config", "http.version", "HTTP/1.1"], cwd=checkout)
        run(["git", "sparse-checkout", "set", ".github"], cwd=checkout)
        run(["git", "fetch", "origin", default_branch], cwd=checkout)
        remote_branch = run(
            ["git", "ls-remote", "--heads", "origin", branch], cwd=checkout, capture=True
        )
        if remote_branch:
            run(["git", "fetch", "origin", branch], cwd=checkout)
            run(["git", "checkout", "-B", branch, f"origin/{branch}"], cwd=checkout)
            merge_default(checkout, default_branch)
        else:
            run(["git", "checkout", "-B", branch, f"origin/{default_branch}"], cwd=checkout)

        run([sys.executable, str(INSTALLER), str(checkout)], cwd=checkout)
        workflow_root = checkout / ".github/workflows"
        workflow_files = sorted(workflow_root.glob("*.yml")) + sorted(
            workflow_root.glob("*.yaml")
        )
        if workflow_files:
            paths = [str(path) for path in workflow_files]
            run(
                [
                    sys.executable,
                    str(REWRITE_SELECTORS),
                    "--docker-job",
                    "(?i)(docker|container|image|buildkit|trivy|zap|service)",
                    "--browser-job",
                    "(?i)(browser|playwright|visual|e2e|lighthouse|android|emulator)",
                    *paths,
                ],
                cwd=checkout,
            )
            run([sys.executable, str(REWRITE_DEPENDENCIES), *paths], cwd=checkout)
            run([sys.executable, str(PIN_ACTIONS), *paths], cwd=checkout)
        run(
            [
                sys.executable,
                str(checkout / ".github/scripts/qdev-runner-policy.py"),
                "--root",
                str(checkout),
            ],
            cwd=checkout,
        )
        run(["git", "diff", "--check"], cwd=checkout)
        changed = run(["git", "status", "--porcelain"], cwd=checkout, capture=True)
        if changed:
            run(["git", "config", "user.name", "Codex"], cwd=checkout)
            run(["git", "config", "user.email", "codex@qdev.run"], cwd=checkout)
            run(["git", "add", "--force", "AGENTS.md", ".github"], cwd=checkout)
            run(["git", "commit", "-m", "ci: enforce centralized runner policy"], cwd=checkout)
            if not prepare_only:
                run(["git", "push", "--set-upstream", "origin", branch], cwd=checkout)

        if existing_pr is None and not prepare_only:
            url = run(
                [
                    "gh",
                    "pr",
                    "create",
                    "--repo",
                    full_name,
                    "--base",
                    default_branch,
                    "--head",
                    branch,
                    "--title",
                    "ci: enforce centralized runner policy",
                    "--body",
                    "Adds the managed QDev runner instructions and machine guard. "
                    "No deployment workflow is executed or weakened.",
                ],
                cwd=checkout,
                capture=True,
            )
            existing_pr = {"url": url}
        return {
            "repository": full_name,
            "branch": branch,
            "pr": existing_pr["url"] if existing_pr else None,
            "changed": bool(changed),
            "prepare_only": prepare_only,
        }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--start-at")
    parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="clone, refresh, validate and commit locally without push or PR creation",
    )
    args = parser.parse_args()
    inventory = json.loads((ROOT / "inventory/repos.json").read_text(encoding="utf-8"))
    selected = inventory["repositories"]
    if args.repository:
        names = {
            name if "/" in name else f"{inventory['owner']}/{name}"
            for name in args.repository
        }
        selected = [repo for repo in selected if repo["full_name"] in names]
        missing = names - {repo["full_name"] for repo in selected}
        if missing:
            parser.error(f"repositories not in inventory: {', '.join(sorted(missing))}")
    if args.start_at:
        start_name = (
            args.start_at if "/" in args.start_at else f"{inventory['owner']}/{args.start_at}"
        )
        positions = [
            index for index, repo in enumerate(selected) if repo["full_name"] == start_name
        ]
        if not positions:
            parser.error(f"start repository not selected: {start_name}")
        selected = selected[positions[0] :]
    for repo in selected:
        try:
            print(
                json.dumps(
                    rollout(repo, prepare_only=args.prepare_only), sort_keys=True
                ),
                flush=True,
            )
        except subprocess.CalledProcessError as exc:
            print(
                json.dumps(
                    {"repository": repo["full_name"], "error": exc.returncode, "command": exc.cmd}
                ),
                flush=True,
            )
            raise


if __name__ == "__main__":
    main()
