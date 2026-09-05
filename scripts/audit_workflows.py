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
UNIQUE_JOB_LABEL = re.compile(
    r"qdev-job-\$\{\{\s*github\.run_id\s*\}\}-"
    r"\$\{\{\s*github\.run_attempt\s*\}\}-[^,\]\"']+"
)
MATRIX_JOB_INDEX = re.compile(r"\$\{\{\s*strategy\.job-index\s*\}\}")
FORK_REPOSITORY_GUARD = "github.event.pull_request.head.repo.full_name == github.repository"
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


def is_manual_only_workflow(triggers: object) -> bool:
    """Return true only for an explicit workflow_dispatch-only trigger."""
    if triggers == "workflow_dispatch":
        return True
    if isinstance(triggers, list):
        return set(triggers) == {"workflow_dispatch"}
    if isinstance(triggers, dict):
        return set(triggers) == {"workflow_dispatch"}
    return False


def audit_local_action(
    full_name: str,
    ref: str,
    action_dir: str,
    visited: set[str],
    *,
    allow_ghcr: bool = False,
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
                if kind == "ghcr" and allow_ghcr:
                    continue
                if marker.lower() in line.lower():
                    violations.append(violation(path, line_number, kind))
            if SETUP_CACHE.search(line):
                violations.append(violation(path, line_number, "github-cache"))
            action = USES.search(line)
            if not action:
                continue
            reference = action.group(1)
            if reference.startswith("./"):
                violations.extend(
                    audit_local_action(
                        full_name,
                        ref,
                        reference,
                        visited,
                        allow_ghcr=allow_ghcr,
                    )
                )
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
    contract_version = str(contract.get("schema_version") or "")
    if contract and contract_version not in {"qdev-runner-v1", "qdev-runner-v2"}:
        violations.append(violation(contract_path, 1, "invalid-contract-version"))
    execution_mode = str(contract.get("execution_mode") or "")
    allow_hosted = (
        contract_version == "qdev-runner-v2"
        and execution_mode == "github-hosted-primary"
    )
    self_hosted_primary = (
        contract_version == "qdev-runner-v2"
        and execution_mode == "self-hosted-primary"
    )
    if contract_version == "qdev-runner-v2" and not (allow_hosted or self_hosted_primary):
        violations.append(violation(contract_path, 1, "invalid-execution-mode"))
    if allow_hosted and contract.get("self_hosted_recovery") is not True:
        violations.append(violation(contract_path, 1, "self-hosted-recovery-not-enabled"))
    if self_hosted_primary and contract.get("self_hosted_recovery") is True:
        violations.append(violation(contract_path, 1, "hosted-recovery-not-allowed"))
    allowed_profiles = set(contract.get("profiles", []))
    release_runners = {
        value
        for value in [contract.get("release_runner"), *(contract.get("release_runners") or [])]
        if isinstance(value, str) and value
    }
    release_registry_workflows: set[str] = set()
    release_registry_value = contract.get("release_registry_workflows")
    if release_registry_value is not None:
        if isinstance(release_registry_value, list) and all(
            isinstance(value, str) for value in release_registry_value
        ):
            release_registry_workflows = set(release_registry_value)
        else:
            violations.append(
                violation(contract_path, 1, "invalid-release-registry-workflows")
            )
    recovery_workflows: set[str] = set()
    recovery_value = contract.get("recovery_workflows")
    if recovery_value is not None:
        if isinstance(recovery_value, list) and all(
            isinstance(value, str) for value in recovery_value
        ):
            recovery_workflows = set(recovery_value)
        else:
            violations.append(violation(contract_path, 1, "invalid-recovery-workflows"))
    if allow_hosted and not recovery_workflows:
        violations.append(violation(contract_path, 1, "missing-recovery-workflows"))
    if recovery_workflows and not allow_hosted:
        violations.append(violation(contract_path, 1, "recovery-workflows-requires-v2"))
    if release_registry_workflows and not allow_hosted:
        violations.append(violation(contract_path, 1, "release-registry-requires-v2"))
    for workflow_name in sorted(release_registry_workflows):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", workflow_name):
            violations.append(
                violation(
                    contract_path,
                    1,
                    "invalid-release-registry-workflow",
                    workflow_name,
                )
            )
    for workflow_name in sorted(recovery_workflows):
        if not re.fullmatch(r"[A-Za-z0-9_.-]+\.ya?ml", workflow_name):
            violations.append(
                violation(contract_path, 1, "invalid-recovery-workflow", workflow_name)
            )
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
    available_workflows = {Path(path).name for path in paths}
    for workflow_name in sorted(release_registry_workflows - available_workflows):
        violations.append(
            violation(
                contract_path,
                1,
                "release-registry-workflow-missing",
                workflow_name,
            )
        )
    for workflow_name in sorted(recovery_workflows - available_workflows):
        violations.append(
            violation(contract_path, 1, "recovery-workflow-missing", workflow_name)
        )
    if smoke_path not in paths:
        violations.append(violation(smoke_path, 1, "missing-runner-smoke"))
    for path in paths:
        text = content_text(full_name, path, ref)
        document = yaml.safe_load(text) or {}
        triggers = document.get("on", document.get(True, {}))
        pull_request_triggered = (
            triggers == "pull_request"
            or isinstance(triggers, list)
            and "pull_request" in triggers
            or isinstance(triggers, dict)
            and "pull_request" in triggers
        )
        allow_ghcr = allow_hosted and Path(path).name in release_registry_workflows
        is_recovery_workflow = allow_hosted and Path(path).name in recovery_workflows
        if is_recovery_workflow and not is_manual_only_workflow(triggers):
            violations.append(violation(path, 1, "recovery-workflow-not-manual-only"))
        if allow_ghcr and pull_request_triggered:
            violations.append(
                violation(path, 1, "release-registry-workflow-pull-request")
            )
        visited_actions: set[str] = set()
        for line_number, raw in enumerate(text.splitlines(), start=1):
            line = strip_yaml_comment(raw)
            if not line.strip():
                continue
            if not allow_hosted and HOSTED.search(line):
                violations.append(violation(path, line_number, "hosted-runner"))
            for marker, kind in FORBIDDEN.items():
                if kind == "ghcr" and allow_ghcr:
                    continue
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
                        audit_local_action(
                            full_name,
                            ref,
                            reference,
                            visited_actions,
                            allow_ghcr=allow_ghcr,
                        )
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
                # A reusable-workflow call is itself pinned by the action scan
                # above and deliberately has no local runner selector.
                if "uses" in job and "runs-on" not in job:
                    continue
                runner = job.get("runs-on", [])
                labels = [runner] if isinstance(runner, str) else runner
                labels = [str(label) for label in labels if isinstance(label, str)]
                profiles = QDEV_PROFILES.intersection(labels)
                if isinstance(runner, str) and "${{" in runner and not profiles:
                    violations.append(violation(path, 1, "dynamic-runner-selector", str(job_name)))
                if profiles:
                    if allow_hosted and not is_recovery_workflow:
                        violations.append(
                            violation(path, 1, "self-hosted-runner-outside-recovery", str(job_name))
                        )
                    condition = str(job.get("if", ""))
                    if pull_request_triggered and FORK_REPOSITORY_GUARD not in condition:
                        violations.append(
                            violation(path, 1, "unguarded-public-fork-job", str(job_name))
                        )
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
                    unique_label = next(
                        (label for label in labels if UNIQUE_JOB_LABEL.fullmatch(label)), None
                    )
                    if unique_label is None:
                        violations.append(
                            violation(path, 1, "missing-unique-job-label", str(job_name))
                        )
                    strategy = job.get("strategy")
                    if (
                        isinstance(strategy, dict)
                        and strategy.get("matrix") is not None
                        and (
                            unique_label is None
                            or MATRIX_JOB_INDEX.search(unique_label) is None
                        )
                    ):
                        violations.append(
                            violation(path, 1, "matrix-job-label-not-unique", str(job_name))
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
                ) and not (allow_hosted and any(HOSTED.fullmatch(label) for label in labels)):
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
