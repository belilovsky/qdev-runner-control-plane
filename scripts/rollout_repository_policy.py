#!/usr/bin/env python3
"""Roll out the managed runner policy through isolated temporary clones."""

from __future__ import annotations

import argparse
import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts/apply_repository_policy.py"
MIGRATION_BRANCH = "codex/self-hosted-runner-v1"
POLICY_BRANCH = "codex/qdev-runner-policy-v1"


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
    return json.loads(run(["gh", *args], capture=True))


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


def rollout(repo: dict[str, Any]) -> dict[str, Any]:
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
                "clone",
                "--filter=blob:none",
                "--no-checkout",
                f"https://github.com/{full_name}.git",
                str(checkout),
            ]
        )
        run(["git", "fetch", "origin", default_branch], cwd=checkout)
        remote_branch = run(
            ["git", "ls-remote", "--heads", "origin", branch], cwd=checkout, capture=True
        )
        if remote_branch:
            run(["git", "fetch", "origin", branch], cwd=checkout)
            run(["git", "checkout", "-B", branch, f"origin/{branch}"], cwd=checkout)
            run(["git", "merge", "--no-edit", f"origin/{default_branch}"], cwd=checkout)
        else:
            run(["git", "checkout", "-B", branch, f"origin/{default_branch}"], cwd=checkout)

        run(["python3", str(INSTALLER), str(checkout)], cwd=checkout)
        run(
            [
                "python3",
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
            run(
                [
                    "git",
                    "add",
                    "AGENTS.md",
                    ".github/QDEV_RUNNERS.md",
                    ".github/scripts/qdev-runner-policy.py",
                    ".github/workflows/qdev-runner-contract.yml",
                ],
                cwd=checkout,
            )
            run(["git", "commit", "-m", "ci: enforce centralized runner policy"], cwd=checkout)
            run(["git", "push", "--set-upstream", "origin", branch], cwd=checkout)

        if existing_pr is None:
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
        return {"repository": full_name, "branch": branch, "pr": existing_pr["url"]}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", action="append", default=[])
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
    for repo in selected:
        try:
            print(json.dumps(rollout(repo), sort_keys=True), flush=True)
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
