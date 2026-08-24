#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import os
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

import httpx
import yaml

ROOT = Path(__file__).resolve().parents[1]
HOSTED = re.compile(r"\b(?:ubuntu|windows|macos)-(?:latest|\d[\w.-]*)\b", re.I)
FORBIDDEN = {
    "actions/cache@": "github-cache",
    "actions/upload-artifact@": "github-artifact",
    "actions/download-artifact@": "github-artifact",
    "ghcr.io": "ghcr",
    "pkg.github.com": "github-packages",
}
SETUP_CACHE = re.compile(
    r"(?:^|[\s,{])['\"]?cache['\"]?\s*:\s*(['\"]?)(?:pip|npm|yarn|pnpm)\1(?:\s|[,}]|$)",
    re.I,
)
USES = re.compile(r"(?:^|[\s,{])['\"]?uses['\"]?\s*:\s*['\"]?([^\s'\",}#]+)")
PINNED_SHA = re.compile(r"^[0-9a-f]{40}$")
PINNED_CONTAINER = re.compile(r"^docker://[^\s]+@sha256:[0-9a-f]{64}$", re.I)
QDEV_PROFILES = {"qdev-ci", "qdev-ci-browser", "qdev-ci-docker"}
MANAGED_START = "<!-- qdev-runner-policy:start -->"
MANAGED_END = "<!-- qdev-runner-policy:end -->"
REQUIRED_POLICY_FILES = {
    "AGENTS.md": "missing-agent-policy",
    ".github/QDEV_RUNNERS.md": "missing-runner-documentation",
    ".github/scripts/qdev-runner-policy.py": "missing-policy-checker",
    ".github/workflows/qdev-runner-contract.yml": "missing-policy-workflow",
}
_CLIENT: httpx.Client | None = None
_CLIENT_LOCK = threading.Lock()


def strip_yaml_comment(line: str) -> str:
    single = False
    double = False
    escaped = False
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and double:
            escaped = True
            continue
        if char == "'" and not double:
            single = not single
            continue
        if char == '"' and not single:
            double = not double
            continue
        if char == "#" and not single and not double and (
            index == 0 or line[index - 1].isspace()
        ):
            return line[:index].rstrip()
    return line


def github_client() -> httpx.Client:
    global _CLIENT
    with _CLIENT_LOCK:
        if _CLIENT is None:
            token = os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN")
            if not token:
                token = subprocess.run(
                    ["gh", "auth", "token"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout.strip()
            _CLIENT = httpx.Client(
                base_url="https://api.github.com",
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                },
                timeout=30,
                limits=httpx.Limits(max_connections=16, max_keepalive_connections=16),
            )
        return _CLIENT


def gh_api(endpoint: str, *, attempts: int = 4) -> Any:
    last_error: subprocess.CalledProcessError | None = None
    for attempt in range(attempts):
        try:
            response = github_client().get(endpoint)
        except httpx.TransportError as error:
            last_error = subprocess.CalledProcessError(1, endpoint, stderr=str(error))
        else:
            if response.status_code < 400:
                return response.json()
            last_error = subprocess.CalledProcessError(
                response.status_code,
                endpoint,
                output=response.text,
                stderr=response.text,
            )
            if response.status_code < 500:
                break
        if attempt + 1 < attempts:
            time.sleep(0.5 * (2**attempt))
    assert last_error is not None
    raise last_error


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


def audit_local_action(
    full_name: str,
    ref: str,
    action_dir: str,
    visited: set[str],
) -> list[dict[str, Any]]:
    action_dir = action_dir.removeprefix("./").rstrip("/")
    for filename in ("action.yml", "action.yaml"):
        path = f"{action_dir}/{filename}"
        try:
            text = content_text(full_name, path, ref)
        except subprocess.CalledProcessError:
            continue
        if path in visited:
            return []
        visited.add(path)
        violations: list[dict[str, Any]] = []
        for line_number, raw in enumerate(text.splitlines(), start=1):
            line = strip_yaml_comment(raw)
            if not line.strip():
                continue
            for marker, kind in FORBIDDEN.items():
                if marker.lower() in line.lower():
                    violations.append(violation(path, line_number, kind))
            if SETUP_CACHE.search(line):
                violations.append(violation(path, line_number, "github-cache"))
            action = USES.search(line)
            if not action:
                continue
            reference = action.group(1)
            if reference.startswith("./"):
                violations.extend(audit_local_action(full_name, ref, reference, visited))
            elif reference.startswith("docker://"):
                if not PINNED_CONTAINER.fullmatch(reference):
                    violations.append(
                        violation(path, line_number, "unpinned-container-action", reference)
                    )
            else:
                revision = reference.rsplit("@", 1)[-1] if "@" in reference else ""
                if not PINNED_SHA.fullmatch(revision):
                    violations.append(violation(path, line_number, "unpinned-action", reference))
        return violations
    return []


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
    release_runners = {
        value
        for value in [contract.get("release_runner"), *(contract.get("release_runners") or [])]
        if isinstance(value, str) and value
    }
    if not allowed_profiles or not allowed_profiles <= QDEV_PROFILES:
        violations.append(
            violation(contract_path, 1, "invalid-contract-profiles", ",".join(allowed_profiles))
        )
    for required_path, kind in REQUIRED_POLICY_FILES.items():
        try:
            required_text = content_text(full_name, required_path, ref)
        except subprocess.CalledProcessError:
            violations.append(violation(required_path, 1, kind))
            continue
        if required_path == "AGENTS.md" and (
            MANAGED_START not in required_text or MANAGED_END not in required_text
        ):
            violations.append(violation(required_path, 1, "invalid-agent-policy"))
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
        visited_actions: set[str] = set()
        for line_number, raw in enumerate(text.splitlines(), start=1):
            line = strip_yaml_comment(raw)
            if not line.strip():
                continue
            if HOSTED.search(line):
                violations.append(violation(path, line_number, "hosted-runner"))
            for marker, kind in FORBIDDEN.items():
                if marker in line:
                    violations.append(violation(path, line_number, kind))
            if SETUP_CACHE.search(line):
                violations.append(violation(path, line_number, "github-cache"))
            action = USES.search(line)
            if action:
                reference = action.group(1)
                if reference.startswith("docker://"):
                    if not PINNED_CONTAINER.fullmatch(reference):
                        violations.append(
                            violation(path, line_number, "unpinned-container-action", reference)
                        )
                elif reference.startswith("./"):
                    violations.extend(
                        audit_local_action(full_name, ref, reference, visited_actions)
                    )
                else:
                    revision = reference.rsplit("@", 1)[-1] if "@" in reference else ""
                    if not PINNED_SHA.fullmatch(revision):
                        violations.append(
                            violation(path, line_number, "unpinned-action", reference)
                        )
        jobs = document.get("jobs", {})
        if isinstance(jobs, dict):
            unique_labels: dict[str, str] = {}
            for job_name, job in jobs.items():
                if not isinstance(job, dict):
                    continue
                runner = job.get("runs-on", [])
                labels = [runner] if isinstance(runner, str) else runner
                labels = [str(label) for label in labels if isinstance(label, str)]
                profiles = QDEV_PROFILES.intersection(labels)
                if isinstance(runner, str) and "${{" in runner and not profiles:
                    violations.append(violation(path, 1, "dynamic-runner-selector", str(job_name)))
                if profiles:
                    if len(profiles) != 1:
                        violations.append(
                            violation(path, 1, "multiple-runner-profiles", str(job_name))
                        )
                    if not profiles <= allowed_profiles:
                        violations.append(violation(path, 1, "profile-not-allowed", str(job_name)))
                    if not {"self-hosted", "Linux", "X64"} <= set(labels):
                        violations.append(
                            violation(path, 1, "missing-required-runner-label", str(job_name))
                        )
                    if not any(
                        label.startswith("qdev-job-")
                        and "github.run_id" in label
                        and "github.run_attempt" in label
                        for label in labels
                    ):
                        violations.append(
                            violation(path, 1, "missing-unique-job-label", str(job_name))
                        )
                    for label in labels:
                        if not label.startswith("qdev-job-"):
                            continue
                        if label in unique_labels:
                            violations.append(
                                violation(path, 1, "duplicate-unique-job-label", str(job_name))
                            )
                        else:
                            unique_labels[label] = str(job_name)
                elif not (isinstance(runner, str) and "${{" in runner) and not (
                    release_runners.intersection(labels)
                ):
                    violations.append(
                        violation(path, 1, "unapproved-runner-profile", str(job_name))
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
