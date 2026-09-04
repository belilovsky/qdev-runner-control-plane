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
KNOWN_PROFILES = {"qdev-ci", "qdev-ci-browser", "qdev-ci-docker"}


def command(*args: str) -> str:
    completed = subprocess.run(args, check=True, capture_output=True, text=True)
    return completed.stdout


def api(endpoint: str) -> Any:
    return json.loads(command("gh", "api", endpoint))


def inspect_repo(repo: dict[str, Any]) -> dict[str, Any] | None:
    full_name = repo["nameWithOwner"]
    metadata = api(f"/repos/{full_name}")
    workflows = api(f"/repos/{full_name}/actions/workflows?per_page=100")["workflows"]
    if not workflows:
        return None
    profiles = {"qdev-ci"}
    workflow_files: list[dict[str, Any]] = []
    try:
        contents = api(f"/repos/{full_name}/contents/.github/workflows")
    except subprocess.CalledProcessError:
        contents = []
    for entry in contents:
        content_data = api(f"/repos/{full_name}/contents/{entry['path']}")
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


def inventory_payload(
    *,
    existing: dict[str, Any],
    replacements: list[dict[str, Any]],
    generated_at: str,
) -> dict[str, Any]:
    """Merge bounded refresh results without rewriting unrelated records."""
    original = existing.get("repositories")
    if not isinstance(original, list):
        raise SystemExit("existing inventory has no repositories list")
    original_names = {item["full_name"] for item in original}
    if any(item["full_name"] not in original_names for item in replacements):
        raise SystemExit("bounded refresh cannot add a repository absent from the inventory")
    by_name = {item["full_name"]: item for item in replacements}
    merged = [by_name.get(item["full_name"], item) for item in original]
    if len(merged) != len(original):
        raise SystemExit("bounded refresh changed inventory cardinality")
    return {
        "schema_version": existing.get("schema_version", "qdev-runner-inventory-v1"),
        "generated_at": generated_at,
        "owner": existing.get("owner", "belilovsky"),
        "active_repository_count": existing.get("active_repository_count", len(merged)),
        "runner_repository_count": len(merged),
        "repositories": merged,
    }


def apply_profile_overrides(
    item: dict[str, Any], add_profiles: list[str]
) -> dict[str, Any]:
    if not add_profiles:
        return item
    unknown = sorted(set(add_profiles) - KNOWN_PROFILES)
    if unknown:
        raise SystemExit(f"unknown profile override: {', '.join(unknown)}")
    result = dict(item)
    result["profiles"] = sorted(set(item.get("profiles", [])) | set(add_profiles))
    return result


def render_tsv(inspected: list[dict[str, Any]]) -> str:
    rows = [
        "repository\tprivate\tdefault_branch\tprofiles\tworkflows\thosted\tartifacts\tcache\tghcr"
    ]
    for repo in inspected:
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
    return "\n".join(rows) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--owner", default="belilovsky")
    parser.add_argument("--expected", type=int, default=96)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument(
        "--repository",
        action="append",
        dest="repositories",
        help="refresh only this existing repository (repeatable; preserves all others)",
    )
    parser.add_argument(
        "--add-profile",
        action="append",
        default=[],
        help="bounded source-validated profile addition for selected repositories",
    )
    args = parser.parse_args()

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
    selected_names = {name.lower() for name in (args.repositories or [])}
    if selected_names:
        selected = [
            repo for repo in active if repo["nameWithOwner"].lower() in selected_names
        ]
        missing = sorted(
            selected_names - {repo["nameWithOwner"].lower() for repo in selected}
        )
        if missing:
            raise SystemExit(f"repository not found or archived: {', '.join(missing)}")
    else:
        selected = active
        if args.add_profile:
            raise SystemExit("--add-profile requires --repository")

    inspected: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(inspect_repo, repo) for repo in selected]
        for future in as_completed(futures):
            item = future.result()
            if item:
                inspected.append(apply_profile_overrides(item, args.add_profile))
    inspected.sort(key=lambda item: item["full_name"].lower())

    inventory_path = ROOT / "inventory/repos.json"
    if selected_names:
        existing = json.loads(inventory_path.read_text(encoding="utf-8"))
        payload = inventory_payload(
            existing=existing,
            replacements=inspected,
            generated_at=datetime.now(UTC).isoformat(),
        )
        inspected = payload["repositories"]
        expected_count = len(inspected)
    else:
        payload = {
            "schema_version": "qdev-runner-inventory-v1",
            "generated_at": datetime.now(UTC).isoformat(),
            "owner": args.owner,
            "active_repository_count": len(active),
            "runner_repository_count": len(inspected),
            "repositories": inspected,
        }
        expected_count = args.expected
    if len(inspected) != expected_count:
        raise SystemExit(
            f"inventory cardinality changed: expected {expected_count}, found {len(inspected)}"
        )
    write_atomic(
        inventory_path,
        json.dumps(payload, ensure_ascii=False, indent=2) + "\n",
    )
    write_atomic(ROOT / "inventory/repos.tsv", render_tsv(inspected))
    mode = "bounded" if selected_names else "full"
    print(f"inventory_ok mode={mode} repositories={len(inspected)} active={len(active)}")


if __name__ == "__main__":
    main()
