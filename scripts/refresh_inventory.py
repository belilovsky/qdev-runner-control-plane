#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import fcntl
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, BinaryIO

import yaml

ROOT = Path(__file__).resolve().parents[1]
EXACT_SHA = re.compile(r"^[0-9a-f]{40}$")


def acquire_inventory_lock() -> BinaryIO:
    """Serialize every inventory read/modify/write across Git worktrees."""

    lock_path_text = command(
        "git", "-C", str(ROOT), "rev-parse", "--git-path", "qdev-runner-inventory.lock"
    ).strip()
    if not lock_path_text:
        raise RuntimeError("cannot resolve the shared inventory lock path")
    lock_path = Path(lock_path_text)
    if not lock_path.is_absolute():
        lock_path = ROOT / lock_path
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    handle = lock_path.open("a+b")
    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
    return handle


def command(*args: str) -> str:
    completed = subprocess.run(args, check=True, capture_output=True, text=True)
    return completed.stdout


def api(endpoint: str) -> Any:
    return json.loads(command("gh", "api", endpoint))


def contract_endpoint(full_name: str, ref: str | None = None) -> str:
    endpoint = f"/repos/{full_name}/contents/.github/qdev-runner.yml"
    if ref:
        endpoint += f"?ref={ref}"
    return endpoint


def declared_profiles(full_name: str, ref: str | None = None) -> set[str]:
    """Read the repository contract before inferring workflow text markers."""

    try:
        content_data = api(contract_endpoint(full_name, ref))
    except subprocess.CalledProcessError:
        # Legacy repositories without the contract remain on the conservative
        # default profile until they are deliberately migrated.
        return set()

    try:
        contract = yaml.safe_load(
            base64.b64decode(content_data["content"]).decode("utf-8", errors="replace")
        )
    except (KeyError, TypeError, ValueError, yaml.YAMLError) as exc:
        raise RuntimeError(
            f"{full_name}: invalid .github/qdev-runner.yml: {exc}"
        ) from exc

    if not isinstance(contract, dict):
        raise RuntimeError(f"{full_name}: runner contract must be a YAML mapping")
    raw_profiles = contract.get("profiles", [])
    if not isinstance(raw_profiles, list) or any(
        not isinstance(profile, str) or not profile.strip() for profile in raw_profiles
    ):
        raise RuntimeError(f"{full_name}: runner contract profiles must be a list of names")
    profiles = {profile.strip() for profile in raw_profiles}
    supported = {"qdev-ci", "qdev-ci-browser", "qdev-ci-docker"}
    unknown = profiles - supported
    if unknown:
        raise RuntimeError(
            f"{full_name}: runner contract declares unsupported profiles: "
            + ", ".join(sorted(unknown))
        )
    return profiles


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
    profiles.update(declared_profiles(full_name, ref))
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


def repository_metadata(full_name: str) -> dict[str, Any]:
    metadata = api(f"/repos/{full_name}")
    owner = metadata.get("owner")
    if not isinstance(owner, dict):
        raise RuntimeError(f"{full_name}: repository metadata has no owner")
    return {
        "id": metadata.get("id"),
        "nameWithOwner": metadata.get("full_name"),
        "isPrivate": metadata.get("private"),
        "isArchived": metadata.get("archived"),
        "defaultBranchRef": {"name": metadata.get("default_branch")},
        "owner": owner.get("login"),
    }


def validate_exact_commit(full_name: str, ref: str) -> None:
    if EXACT_SHA.fullmatch(ref) is None:
        raise RuntimeError(f"{full_name}: --ref must be a full lowercase commit SHA")
    commit = api(f"/repos/{full_name}/git/commits/{ref}")
    if not isinstance(commit, dict) or commit.get("sha") != ref:
        raise RuntimeError(f"{full_name}: --ref did not resolve to the exact commit SHA")


def validate_add_candidate(
    repo: dict[str, Any],
    *,
    owner: str,
    expected_repository_id: int,
    expected_full_name: str,
    expected_default_branch: str,
) -> None:
    checks = {
        "repository id": (repo.get("id"), expected_repository_id),
        "full name": (repo.get("nameWithOwner"), expected_full_name),
        "owner": (repo.get("owner"), owner),
        "default branch": (
            (repo.get("defaultBranchRef") or {}).get("name"),
            expected_default_branch,
        ),
    }
    mismatches = [
        f"{label} expected {expected!r}, got {actual!r}"
        for label, (actual, expected) in checks.items()
        if actual != expected
    ]
    if mismatches:
        raise RuntimeError(
            f"{expected_full_name}: repository identity mismatch: "
            + "; ".join(mismatches)
        )
    if repo.get("isArchived") is not False:
        raise RuntimeError(f"{expected_full_name}: repository is archived")
    if repo.get("isPrivate") is not True:
        raise RuntimeError(f"{expected_full_name}: repository must be private")


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


def validate_inventory_uniqueness(repositories: list[dict[str, Any]]) -> None:
    names: set[str] = set()
    repository_ids: set[int] = set()
    for repository in repositories:
        full_name = str(repository.get("full_name", ""))
        normalized_name = full_name.casefold()
        repository_id = repository.get("id")
        if not full_name or normalized_name in names:
            raise RuntimeError(f"inventory has duplicate repository name: {full_name}")
        if isinstance(repository_id, bool) or not isinstance(repository_id, int):
            raise RuntimeError(f"inventory has invalid repository id: {full_name}")
        if repository_id in repository_ids:
            raise RuntimeError(f"inventory has duplicate repository id: {repository_id}")
        names.add(normalized_name)
        repository_ids.add(repository_id)


def validate_refreshed_identity(
    expected: dict[str, Any], refreshed: dict[str, Any]
) -> None:
    expected_name = expected.get("nameWithOwner")
    expected_id = expected.get("id")
    if refreshed.get("full_name") != expected_name or refreshed.get("id") != expected_id:
        raise RuntimeError(
            f"repository identity changed for {expected_name}: "
            f"expected id {expected_id}, got {refreshed.get('id')}"
        )


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
    parser.add_argument(
        "--add-repository",
        help="add exactly one missing private repository without refreshing other records",
    )
    parser.add_argument("--expected-repository-id", type=int)
    parser.add_argument("--expected-full-name")
    parser.add_argument("--expected-default-branch")
    args = parser.parse_args()

    try:
        inventory_lock = acquire_inventory_lock()
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        parser.error(f"cannot acquire inventory lock: {exc}")

    if args.add_repository:
        if args.repository:
            parser.error("--add-repository cannot be combined with --repository")
        required = {
            "--ref": args.ref,
            "--expected-repository-id": args.expected_repository_id,
            "--expected-full-name": args.expected_full_name,
            "--expected-default-branch": args.expected_default_branch,
        }
        missing_arguments = [name for name, value in required.items() if value is None]
        if missing_arguments:
            parser.error(
                "--add-repository requires " + ", ".join(missing_arguments)
            )
        full_name = normalise_repository_name(args.add_repository, args.owner)
        if full_name != args.expected_full_name:
            parser.error("--add-repository must match --expected-full-name")
        existing = json.loads((ROOT / "inventory/repos.json").read_text(encoding="utf-8"))
        existing_repositories = existing.get("repositories")
        if not isinstance(existing_repositories, list):
            parser.error("existing inventory has no repositories list")
        try:
            validate_inventory_uniqueness(existing_repositories)
        except RuntimeError as exc:
            parser.error(str(exc))
        existing_names = {str(item["full_name"]).casefold() for item in existing_repositories}
        existing_ids = {int(item["id"]) for item in existing_repositories}
        if full_name.casefold() in existing_names:
            parser.error(f"repository already exists in inventory: {full_name}")
        if args.expected_repository_id in existing_ids:
            parser.error(
                f"repository id already exists in inventory: {args.expected_repository_id}"
            )
        try:
            repo = repository_metadata(full_name)
            validate_add_candidate(
                repo,
                owner=args.owner,
                expected_repository_id=args.expected_repository_id,
                expected_full_name=args.expected_full_name,
                expected_default_branch=args.expected_default_branch,
            )
            validate_exact_commit(full_name, args.ref)
            item = inspect_repo(repo, ref=args.ref)
        except RuntimeError as exc:
            parser.error(str(exc))
        if item is None:
            parser.error(f"repository has no workflows at {args.ref}: {full_name}")
        inspected_identity = {
            "repository id": (item.get("id"), args.expected_repository_id),
            "full name": (item.get("full_name"), args.expected_full_name),
            "default branch": (
                item.get("default_branch"),
                args.expected_default_branch,
            ),
        }
        drift = [
            f"{label} expected {expected!r}, got {actual!r}"
            for label, (actual, expected) in inspected_identity.items()
            if actual != expected
        ]
        if drift:
            parser.error("repository changed during inspection: " + "; ".join(drift))
        merged = [*existing_repositories, item]
        try:
            validate_inventory_uniqueness(merged)
        except RuntimeError as exc:
            parser.error(str(exc))
        if len(merged) != args.expected:
            parser.error(
                f"inventory cardinality changed: expected {args.expected}, found {len(merged)}"
            )
        payload = inventory_payload(
            owner=existing.get("owner", args.owner),
            active_count=int(existing.get("active_repository_count", len(merged))),
            repositories=merged,
        )
        write_inventory(payload)
        print(
            f"inventory_ok added={full_name} ref={args.ref} "
            f"repositories={len(merged)} active={payload['active_repository_count']}"
        )
        return

    if args.repository:
        existing = json.loads((ROOT / "inventory/repos.json").read_text(encoding="utf-8"))
        selected_names = {
            normalise_repository_name(name, args.owner) for name in args.repository
        }
        existing_repositories = existing.get("repositories")
        if not isinstance(existing_repositories, list):
            parser.error("existing inventory has no repositories list")
        try:
            validate_inventory_uniqueness(existing_repositories)
        except RuntimeError as exc:
            parser.error(str(exc))
        existing_by_name = {item["full_name"]: item for item in existing_repositories}
        missing = selected_names - existing_by_name.keys()
        if missing:
            parser.error(
                "repositories not in existing inventory: " + ", ".join(sorted(missing))
            )
        repo_metadata = [
            {
                "id": int(existing_by_name[name]["id"]),
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
            try:
                validate_refreshed_identity(repo, item)
            except RuntimeError as exc:
                parser.error(str(exc))
            refreshed[item["full_name"]] = item
        merged = [
            refreshed.get(item["full_name"], item) for item in existing_repositories
        ]
        try:
            validate_inventory_uniqueness(merged)
        except RuntimeError as exc:
            parser.error(str(exc))
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
    inventory_lock.close()


if __name__ == "__main__":
    main()
