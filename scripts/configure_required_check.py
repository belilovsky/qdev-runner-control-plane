#!/usr/bin/env python3
"""Add the QDev contract check to existing classic branch protection."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
from pathlib import Path
from typing import Any
from urllib.parse import quote

import httpx

ROOT = Path(__file__).resolve().parents[1]
CONTEXT = "qdev-runner-contract"
WORKFLOW = ".github/workflows/qdev-runner-contract.yml"


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


def required_contexts(protection: dict[str, Any]) -> set[str]:
    required = protection.get("required_status_checks") or {}
    contexts = {value for value in required.get("contexts", []) if isinstance(value, str)}
    contexts.update(
        check["context"]
        for check in required.get("checks", [])
        if isinstance(check, dict) and isinstance(check.get("context"), str)
    )
    return contexts


def _actor_names(block: dict[str, Any], key: str, field: str) -> list[str]:
    return [
        actor[field]
        for actor in block.get(key, [])
        if isinstance(actor, dict) and isinstance(actor.get(field), str)
    ]


def _actor_block(block: dict[str, Any]) -> dict[str, list[str]]:
    return {
        "users": _actor_names(block, "users", "login"),
        "teams": _actor_names(block, "teams", "slug"),
        "apps": _actor_names(block, "apps", "slug"),
    }


def protection_update_payload(protection: dict[str, Any]) -> dict[str, Any]:
    reviews = protection.get("required_pull_request_reviews")
    review_payload: dict[str, Any] | None = None
    if isinstance(reviews, dict):
        review_payload = {
            "dismissal_restrictions": _actor_block(reviews.get("dismissal_restrictions") or {}),
            "dismiss_stale_reviews": bool(reviews.get("dismiss_stale_reviews")),
            "require_code_owner_reviews": bool(reviews.get("require_code_owner_reviews")),
            "required_approving_review_count": int(
                reviews.get("required_approving_review_count", 0)
            ),
            "require_last_push_approval": bool(reviews.get("require_last_push_approval")),
            "bypass_pull_request_allowances": _actor_block(
                reviews.get("bypass_pull_request_allowances") or {}
            ),
        }
    restrictions = protection.get("restrictions")
    return {
        "required_status_checks": {"strict": False, "contexts": [CONTEXT]},
        "enforce_admins": bool((protection.get("enforce_admins") or {}).get("enabled")),
        "required_pull_request_reviews": review_payload,
        "restrictions": _actor_block(restrictions) if isinstance(restrictions, dict) else None,
        "required_linear_history": bool(
            (protection.get("required_linear_history") or {}).get("enabled")
        ),
        "allow_force_pushes": bool((protection.get("allow_force_pushes") or {}).get("enabled")),
        "allow_deletions": bool((protection.get("allow_deletions") or {}).get("enabled")),
        "block_creations": bool((protection.get("block_creations") or {}).get("enabled")),
        "required_conversation_resolution": bool(
            (protection.get("required_conversation_resolution") or {}).get("enabled")
        ),
        "lock_branch": bool((protection.get("lock_branch") or {}).get("enabled")),
        "allow_fork_syncing": bool((protection.get("allow_fork_syncing") or {}).get("enabled")),
    }


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

    def get(self, endpoint: str) -> httpx.Response:
        return self.client.get(endpoint)

    def put(self, endpoint: str, body: dict[str, Any]) -> httpx.Response:
        return self.client.put(endpoint, json=body)

    def post(self, endpoint: str, body: dict[str, Any]) -> httpx.Response:
        return self.client.post(endpoint, json=body)


def configure_repository(
    github: GitHub,
    repo: dict[str, Any],
    *,
    apply: bool,
) -> dict[str, Any]:
    full_name = repo["full_name"]
    branch = repo["default_branch"]
    encoded_branch = quote(branch, safe="")
    workflow = github.get(f"/repos/{full_name}/contents/{WORKFLOW}?ref={encoded_branch}")
    if workflow.status_code == 404:
        return {"repository": full_name, "result": "workflow-not-on-default"}
    workflow.raise_for_status()

    protection_path = f"/repos/{full_name}/branches/{encoded_branch}/protection"
    protection_response = github.get(protection_path)
    if protection_response.status_code == 404:
        return {"repository": full_name, "result": "no-classic-protection"}
    protection_response.raise_for_status()
    protection = protection_response.json()
    existing = required_contexts(protection)
    if CONTEXT in existing:
        return {"repository": full_name, "result": "already-required"}
    if not apply:
        return {
            "repository": full_name,
            "result": "would-add",
            "existing_contexts": sorted(existing),
        }

    required = protection.get("required_status_checks")
    checks_path = f"{protection_path}/required_status_checks"
    if required is None:
        response = github.put(protection_path, protection_update_payload(protection))
    else:
        response = github.post(f"{checks_path}/contexts", {"contexts": [CONTEXT]})
    response.raise_for_status()

    verified = github.get(protection_path)
    verified.raise_for_status()
    if CONTEXT not in required_contexts(verified.json()):
        raise RuntimeError(f"required check was not persisted for {full_name}")
    return {
        "repository": full_name,
        "result": "added",
        "preserved_contexts": sorted(existing),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--apply", action="store_true")
    parser.add_argument("--repository", action="append", default=[])
    args = parser.parse_args()
    inventory = json.loads((ROOT / "inventory/repos.json").read_text(encoding="utf-8"))
    selected = inventory["repositories"]
    if args.repository:
        requested = {
            value if "/" in value else f"{inventory['owner']}/{value}" for value in args.repository
        }
        selected = [repo for repo in selected if repo["full_name"] in requested]
        missing = requested - {repo["full_name"] for repo in selected}
        if missing:
            parser.error(f"repositories not in inventory: {', '.join(sorted(missing))}")

    github = GitHub()
    try:
        results = [configure_repository(github, repo, apply=args.apply) for repo in selected]
    finally:
        github.close()
    print(json.dumps({"apply": args.apply, "results": results}, indent=2))


if __name__ == "__main__":
    main()
