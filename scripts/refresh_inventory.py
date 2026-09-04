#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]


def command(*args: str) -> str:
    completed = subprocess.run(args, check=True, capture_output=True, text=True)
    return completed.stdout


def api(endpoint: str) -> Any:
    return json.loads(command("gh", "api", endpoint))


def inspect_repo(repo: dict[str, Any], ref: str | None = None) -> dict[str, Any] | None:
    full_name = repo["nameWithOwner"]
    metadata = api(f"/repos/{full_name}")
    workflows_endpoint = f"/repos/{full_name}/actions/workflows?per_page=100"
    if ref:
        workflows_endpoint += f"&ref={ref}"
    workflows = api(workflows_endpoint)["workflows"]
    if not workflows:
        return None
    profiles = {"qdev-ci"}
    workflow_files: list[dict[str, Any]] = []
    try:
        contents_endpoint = f"/repos/{full_name}/contents/.github/workflows"
        if ref:
            contents_endpoint += f"?ref={ref}"
        contents = api(contents_endpoint)
    except subprocess.CalledProcessError:
        contents = []
    for entry in contents:
        content_endpoint = f"/repos/{full_name}/contents/{entry['path']}"
        if ref:
            content_endpoint += f"?ref={ref}"
        content_data = api(content_endpoint)
        text = base64.b64decode(content_data["content"]).decode("utf-8", errors="replace")
        lowered = text.lower()
        if any(marker in lowered for marker in ("playwright", "chromium", "browser")):
            profiles.add("qdev-ci-browser")
        if any(
            marker in lowered
            for marker in (
                "docker build",
                "docker compose",
                "docker/build-push-action",
                "services:",
                "ghcr.io",
            )
        ):
            profiles.add("qdev-ci-docker")
        workflow_files.append(
            {
                "path": entry["path"],
                "sha": entry["sha"],
                "hosted_selectors": text.count("ubuntu-latest") + text.count("ubuntu-24.04"),
                "cache_refs": text.count("actions/cache@"),
                "artifact_refs": text.count("actions/upload-artifact@"),
                "ghcr_refs": text.count("ghcr.io"),
            }
        )
    return {
        "id": metadata["id"],
        "full_name": full_name,
        "private": repo["isPrivate"],
        "archived": repo["isArchived"],
        "default_branch": (repo.get("defaultBranchRef") or {}).get("name") or "main",
        "profiles": sorted(profiles),
        "workflow_count": len(workflows),
        "workflow_files": sorted(workflow_files, key=lambda item: item["path"]),
    }


def write_atomic(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def normalise_repository_name(name: str, owner: str) -> str:
    return name if "/" in name else f"{owner}/{name}"


def inventory_payload(
    *, owner: str, active_count: int, repositories: list[dict[str, Any]]
) -> dict[str, Any]:
    repositories = sorted(repositories, key=lambda item: item["full_name"].lower())
    return {
        "schema_version": "qdev-runner-inventory-v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "owner": owner,
        "active_repository_count": active_count,
        "runner_repository_count": len(repositories),
        "repositories": repositories,
    }


def write_inventory(payload: dict[str, Any]) -> None:
    repositories = payload["repositories"]
    write_atomic(
        ROOT / "inventory/repos.json",
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    )
    rows = [
        "repository\tprivate\tdefault_branch\tprofiles\tworkflows\thosted\tartifacts\tcache\tghcr"
    ]
    for repo in repositories:
        files = repo["workflow_files"]
        rows.append(
            "\t".join(
                [
                    repo["full_name"],
                    str(repo["private"]).lower(),
                    repo["default_branch"],
                    ",".join(repo["profiles"]),
                    str(repo["workflow_count"]),
                    str(sum(item["hosted_selectors"] for item in files)),
                    str(sum(item["artifact_refs"] for item in files)),
                    str(sum(item["cache_refs"] for item in files)),
                    str(sum(item["ghcr_refs"] for item in files)),
                ]
            )
        )
    write_atomic(ROOT / "inventory/repos.tsv", "\n".join(rows) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--owner", default="belilovsky")
    parser.add_argument("--expected", type=int, default=96)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument(
        "--repository",
        action="append",
        default=[],
        help=(
            "refresh only this repository in the existing inventory; may be "
            "repeated, and never changes other records"
        ),
    )
    parser.add_argument(
        "--ref",
        help="inspect workflow files at this exact Git ref (use with --repository)",
    )
    args = parser.parse_args()

    if args.repository:
        existing = json.loads((ROOT / "inventory/repos.json").read_text(encoding="utf-8"))
        selected_names = {
            normalise_repository_name(name, args.owner) for name in args.repository
        }
        existing_repositories = existing.get("repositories")
        if not isinstance(existing_repositories, list):
            parser.error("existing inventory has no repositories list")
        existing_by_name = {item["full_name"]: item for item in existing_repositories}
        missing = selected_names - existing_by_name.keys()
        if missing:
            parser.error(
                "repositories not in existing inventory: " + ", ".join(sorted(missing))
            )
        repo_metadata = [
            {
                "nameWithOwner": name,
                "isArchived": bool(existing_by_name[name].get("archived", False)),
                "isPrivate": bool(existing_by_name[name].get("private", False)),
                "defaultBranchRef": {
                    "name": existing_by_name[name].get("default_branch", "main")
                },
            }
            for name in sorted(selected_names)
        ]
        refreshed: dict[str, dict[str, Any]] = {}
        for repo in repo_metadata:
            if repo["isArchived"]:
                parser.error(f"repository is archived: {repo['nameWithOwner']}")
            item = inspect_repo(repo, ref=args.ref)
            if item is None:
                parser.error(f"repository has no workflows: {repo['nameWithOwner']}")
            refreshed[item["full_name"]] = item
        merged = [
            refreshed.get(item["full_name"], item) for item in existing_repositories
        ]
        payload = inventory_payload(
            owner=existing.get("owner", args.owner),
            active_count=int(existing.get("active_repository_count", len(merged))),
            repositories=merged,
        )
        write_inventory(payload)
        print(
            "inventory_ok targeted="
            + ",".join(sorted(refreshed))
            + f" repositories={len(merged)} active={payload['active_repository_count']}"
        )
        return

    if args.ref:
        parser.error("--ref requires --repository")

    repos = json.loads(
        command(
            "gh",
            "repo",
            "list",
            args.owner,
            "--limit",
            "300",
            "--json",
            "nameWithOwner,isArchived,isPrivate,defaultBranchRef",
        )
    )
    active = [repo for repo in repos if not repo["isArchived"]]
    inspected: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(inspect_repo, repo) for repo in active]
        for future in as_completed(futures):
            item = future.result()
            if item:
                inspected.append(item)
    inspected.sort(key=lambda item: item["full_name"].lower())
    if len(inspected) != args.expected:
        raise SystemExit(
            f"inventory cardinality changed: expected {args.expected}, found {len(inspected)}"
        )
    write_inventory(
        inventory_payload(
            owner=args.owner, active_count=len(active), repositories=inspected
        )
    )
    print(f"inventory_ok repositories={len(inspected)} active={len(active)}")


if __name__ == "__main__":
    main()
