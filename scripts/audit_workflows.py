#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
HOSTED = re.compile(r"\b(?:ubuntu|windows|macos)-(?:latest|\d[\w.-]*)\b", re.I)
FORBIDDEN = {
    "actions/cache@": "github-cache",
    "actions/upload-artifact@": "github-artifact",
    "actions/download-artifact@": "github-artifact",
    "ghcr.io": "ghcr",
    "npm.pkg.github.com": "github-packages",
}
SETUP_CACHE = re.compile(r"^\s*cache:\s*(?:pip|npm|yarn|pnpm)\s*$", re.I)
USES = re.compile(r"\buses:\s*['\"]?([^\s'\"#]+)")
PINNED_SHA = re.compile(r"^[0-9a-f]{40}$")
QDEV_PROFILES = {"qdev-ci", "qdev-ci-browser", "qdev-ci-docker"}


def gh_api(endpoint: str) -> Any:
    completed = subprocess.run(["gh", "api", endpoint], check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


def content_text(full_name: str, path: str, ref: str) -> str:
    data = gh_api(f"/repos/{full_name}/contents/{path}?ref={ref}")
    return base64.b64decode(data["content"]).decode("utf-8", errors="replace")


def workflow_paths(full_name: str, ref: str) -> list[str]:
    data = gh_api(f"/repos/{full_name}/contents/.github/workflows?ref={ref}")
    return sorted(
        item["path"]
        for item in data
        if item["type"] == "file" and item["name"].endswith((".yml", ".yaml"))
    )


def violation(path: str, line: int, kind: str, detail: str = "") -> dict[str, Any]:
    result: dict[str, Any] = {"path": path, "line": line, "kind": kind}
    if detail:
        result["detail"] = detail
    return result


def audit_repository(repo: dict[str, Any], requested_ref: str | None) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []
    full_name = repo["full_name"]
    ref = requested_ref or repo["default_branch"]
    contract_path = ".github/qdev-runner.yml"
    smoke_path = ".github/workflows/runner-smoke.yml"
    contract: dict[str, Any] = {}
    try:
        contract = yaml.safe_load(content_text(full_name, contract_path, ref)) or {}
    except subprocess.CalledProcessError:
        violations.append(violation(contract_path, 1, "missing-contract"))
    if contract and contract.get("schema_version") != "qdev-runner-v1":
        violations.append(violation(contract_path, 1, "invalid-contract-version"))
    allowed_profiles = set(contract.get("profiles", []))
    if not allowed_profiles or not allowed_profiles <= QDEV_PROFILES:
        violations.append(
            violation(contract_path, 1, "invalid-contract-profiles", ",".join(allowed_profiles))
        )
    try:
        paths = workflow_paths(full_name, ref)
    except subprocess.CalledProcessError:
        return {
            "repository": full_name,
            "ref": ref,
            "violations": violations
            + [violation(".github/workflows", 1, "workflow-directory-unavailable")],
        }
    if smoke_path not in paths:
        violations.append(violation(smoke_path, 1, "missing-runner-smoke"))
    for path in paths:
        text = content_text(full_name, path, ref)
        document = yaml.safe_load(text) or {}
        for line_number, line in enumerate(text.splitlines(), start=1):
            if HOSTED.search(line):
                violations.append(violation(path, line_number, "hosted-runner"))
            for marker, kind in FORBIDDEN.items():
                if marker in line:
                    violations.append(violation(path, line_number, kind))
            if SETUP_CACHE.match(line):
                violations.append(violation(path, line_number, "github-cache"))
            action = USES.search(line)
            if action:
                reference = action.group(1)
                if not reference.startswith(("./", "docker://")):
                    revision = reference.rsplit("@", 1)[-1] if "@" in reference else ""
                    if not PINNED_SHA.fullmatch(revision):
                        violations.append(
                            violation(path, line_number, "unpinned-action", reference)
                        )
        jobs = document.get("jobs", {})
        if isinstance(jobs, dict):
            for job_name, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                runner = job.get("runs-on", [])
                labels = [runner] if isinstance(runner, str) else runner
                labels = [str(label) for label in labels if isinstance(label, str)]
                profiles = QDEV_PROFILES.intersection(labels)
                if profiles:
                    if not profiles <= allowed_profiles:
                        violations.append(
                            violation(path, 1, "profile-not-allowed", str(job_name))
                        )
                    if not any(label.startswith("qdev-job-") for label in labels):
                        violations.append(
                            violation(path, 1, "missing-unique-job-label", str(job_name))
                        )
    return {"repository": full_name, "ref": ref, "violations": violations}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-migration", action="store_true")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--ref")
    parser.add_argument("--repository", action="append", default=[])
    args = parser.parse_args()
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
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(audit_repository, repo, args.ref) for repo in selected]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: item["repository"].lower())
    violations = sum(len(item["violations"]) for item in results)
    report = {
        "schema_version": "qdev-runner-workflow-audit-v1",
        "repositories": len(results),
        "violations": violations,
        "results": results,
    }
    print(json.dumps(report, indent=2))
    if violations and not args.allow_migration:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
