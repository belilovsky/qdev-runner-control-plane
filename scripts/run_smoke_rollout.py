#!/usr/bin/env python3
"""Dispatch default-branch runner smokes in bounded batches and save evidence."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = "runner-smoke.yml"


def github_token() -> str:
    token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
    if token:
        return token
    return subprocess.run(
        ["gh", "auth", "token"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def parse_github_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def queue_seconds(run: dict[str, Any], job: dict[str, Any]) -> float | None:
    created = run.get("created_at")
    started = job.get("started_at")
    if not isinstance(created, str) or not isinstance(started, str):
        return None
    return max(0.0, (parse_github_time(started) - parse_github_time(created)).total_seconds())


def select_new_run(
    runs: list[dict[str, Any]],
    *,
    head_sha: str,
    previous_ids: set[int],
) -> dict[str, Any] | None:
    candidates = [
        run
        for run in runs
        if run.get("head_sha") == head_sha
        and isinstance(run.get("id"), int)
        and run["id"] not in previous_ids
    ]
    return max(candidates, key=lambda run: int(run["id"])) if candidates else None


class GitHub:
    def __init__(self) -> None:
        self.client = httpx.Client(
            base_url="https://api.github.com",
            headers={
                "Authorization": f"Bearer {github_token()}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=30,
        )

    def close(self) -> None:
        self.client.close()

    def json(self, method: str, endpoint: str, **kwargs: Any) -> Any:
        response = self.client.request(method, endpoint, **kwargs)
        response.raise_for_status()
        return response.json() if response.content else None


def workflow_runs(github: GitHub, full_name: str, branch: str) -> list[dict[str, Any]]:
    encoded = quote(branch, safe="")
    data = github.json(
        "GET",
        f"/repos/{full_name}/actions/workflows/{WORKFLOW}/runs"
        f"?event=workflow_dispatch&branch={encoded}&per_page=30",
    )
    return list(data.get("workflow_runs", []))


def dispatch_batch(
    github: GitHub,
    repositories: list[dict[str, Any]],
    *,
    poll_seconds: float,
    timeout_seconds: float,
) -> list[dict[str, Any]]:
    pending: dict[str, dict[str, Any]] = {}
    for repo in repositories:
        full_name = repo["full_name"]
        branch = repo["default_branch"]
        branch_data = github.json("GET", f"/repos/{full_name}/branches/{quote(branch, safe='')}")
        head_sha = branch_data["commit"]["sha"]
        previous_ids = {int(run["id"]) for run in workflow_runs(github, full_name, branch)}
        github.json(
            "POST",
            f"/repos/{full_name}/actions/workflows/{WORKFLOW}/dispatches",
            json={"ref": branch},
        )
        pending[full_name] = {
            "repository": full_name,
            "branch": branch,
            "sha": head_sha,
            "previous_ids": previous_ids,
            "dispatched_at": datetime.now(UTC).isoformat(),
            "run": None,
        }

    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        complete = True
        for item in pending.values():
            run = item["run"]
            if run is None:
                run = select_new_run(
                    workflow_runs(github, item["repository"], item["branch"]),
                    head_sha=item["sha"],
                    previous_ids=item["previous_ids"],
                )
                item["run"] = run
            elif run.get("status") != "completed":
                run = github.json("GET", f"/repos/{item['repository']}/actions/runs/{run['id']}")
                item["run"] = run
            if run is None or run.get("status") != "completed":
                complete = False
        if complete:
            break
        time.sleep(poll_seconds)
    else:
        raise TimeoutError("runner smoke batch did not complete before timeout")

    receipts: list[dict[str, Any]] = []
    for item in pending.values():
        run = item["run"]
        jobs_data = github.json(
            "GET", f"/repos/{item['repository']}/actions/runs/{run['id']}/jobs?per_page=20"
        )
        jobs = jobs_data.get("jobs", [])
        smoke = next((job for job in jobs if job.get("name") == "runner-smoke"), None)
        receipts.append(
            {
                "repository": item["repository"],
                "branch": item["branch"],
                "sha": item["sha"],
                "run_id": run["id"],
                "run_url": run.get("html_url"),
                "conclusion": run.get("conclusion"),
                "runner_name": smoke.get("runner_name") if smoke else None,
                "queue_seconds": queue_seconds(run, smoke) if smoke else None,
                "job_conclusion": smoke.get("conclusion") if smoke else None,
            }
        )
    return receipts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--repository", action="append", default=[])
    parser.add_argument("--batch-size", type=int, default=15)
    parser.add_argument("--poll-seconds", type=float, default=5.0)
    parser.add_argument("--timeout-seconds", type=float, default=1800.0)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.apply:
        parser.error("--apply is required because workflow dispatch changes GitHub state")
    if args.batch_size < 1:
        parser.error("--batch-size must be positive")

    inventory = json.loads((ROOT / "inventory/repos.json").read_text(encoding="utf-8"))
    selected = inventory["repositories"]
    if args.repository:
        requested = {
            name if "/" in name else f"{inventory['owner']}/{name}" for name in args.repository
        }
        selected = [repo for repo in selected if repo["full_name"] in requested]
        missing = requested - {repo["full_name"] for repo in selected}
        if missing:
            parser.error(f"repositories not in inventory: {', '.join(sorted(missing))}")

    receipts: list[dict[str, Any]] = []
    github = GitHub()
    try:
        for index in range(0, len(selected), args.batch_size):
            receipts.extend(
                dispatch_batch(
                    github,
                    selected[index : index + args.batch_size],
                    poll_seconds=args.poll_seconds,
                    timeout_seconds=args.timeout_seconds,
                )
            )
    finally:
        github.close()

    report = {
        "schema_version": "qdev-runner-smoke-receipt-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "repositories": len(receipts),
        "passed": sum(
            item["conclusion"] == "success" and item["job_conclusion"] == "success"
            for item in receipts
        ),
        "results": receipts,
    }
    rendered = json.dumps(report, indent=2) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    if report["passed"] != report["repositories"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
