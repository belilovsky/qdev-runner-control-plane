#!/usr/bin/env python3
# ruff: noqa: E501, FURB167
"""Repository-local, dependency-free QDev workflow policy check."""

from __future__ import annotations

# Managed source is kept byte-identical across repositories with different
# formatter line-length settings.
# fmt: off
import argparse
import re
from pathlib import Path

HOSTED = re.compile(r"\b(?:ubuntu|windows|macos)-(?:latest|\d[\w.-]*)\b", re.I)
HOSTED_SELECTOR = re.compile(
    r"\s*['\"]?(?:ubuntu|windows|macos)-(?:latest|\d[\w.-]*)['\"]?\s*", re.I
)
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
QDEV_PROFILE = re.compile(r"\bqdev-ci(?:-browser|-docker)?\b")
UNIQUE_JOB_LABEL = re.compile(
    r"qdev-job-\$\{\{\s*github\.run_id\s*\}\}-"
    r"\$\{\{\s*github\.run_attempt\s*\}\}-[^\s,\]\"']+"
)
RUNS_ON = re.compile(r"^(\s*)['\"]?runs-on['\"]?\s*:\s*(.*)$")
FLOW_RUNS_ON = re.compile(r"(?:^|[{,])\s*['\"]?runs-on['\"]?\s*:\s*(.*)$")
FORK_REPOSITORY_GUARD = "github.event.pull_request.head.repo.full_name == github.repository"
MANAGED_START = "<!-- qdev-runner-policy:start -->"
MANAGED_END = "<!-- qdev-runner-policy:end -->"


def strip_yaml_comment(line: str) -> str:
    """Remove an actual YAML comment while preserving hashes inside quotes."""
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


def contract_list(text: str, key: str) -> list[str]:
    """Read a top-level YAML list without accepting similarly named nested data."""
    lines = text.splitlines()
    values: list[str] = []
    in_block = False
    for raw in lines:
        line = strip_yaml_comment(raw)
        if not line.strip():
            continue
        if not in_block:
            if re.fullmatch(rf"{re.escape(key)}\s*:\s*", line):
                in_block = True
            continue
        if line == line.lstrip():
            break
        match = re.fullmatch(r"\s+-\s+([A-Za-z0-9_.-]+)\s*", line)
        if match:
            values.append(match.group(1))
    return values


def has_pull_request_trigger(lines: list[str]) -> bool:
    """Recognize block and flow forms of a top-level pull_request trigger."""
    for index, line in enumerate(lines):
        match = re.fullmatch(r"['\"]?on['\"]?\s*:\s*(.*)", line)
        if not match:
            continue
        value = match.group(1)
        if re.search(r"\bpull_request\b", value):
            return True
        for candidate in lines[index + 1 :]:
            if candidate.strip() and candidate == candidate.lstrip():
                break
            if re.search(r"\bpull_request\b", candidate):
                return True
        return False
    return False


def job_blocks(lines: list[str]) -> list[tuple[int, str]]:
    """Return top-level job blocks as normalized text with their start line."""
    jobs_index: int | None = None
    for index, line in enumerate(lines):
        if re.fullmatch(r"jobs\s*:\s*", line):
            jobs_index = index
            break
    if jobs_index is None:
        return []
    blocks: list[tuple[int, str]] = []
    start: int | None = None
    collected: list[str] = []
    for index in range(jobs_index + 1, len(lines)):
        line = lines[index]
        if line.strip() and line == line.lstrip():
            break
        is_job = bool(re.match(r"^  ['\"]?[A-Za-z0-9_.-]+['\"]?\s*:\s*", line))
        if is_job:
            if start is not None:
                blocks.append((start + 1, " ".join(collected)))
            start = index
            collected = [line.strip()]
        elif start is not None:
            collected.append(line.strip())
    if start is not None:
        blocks.append((start + 1, " ".join(collected)))
    return blocks


def action_violations(path: Path, root: Path, visited: set[Path]) -> list[str]:
    """Check external pins and forbidden services in a local composite action tree."""
    path = path.resolve()
    if path in visited or not path.is_file():
        return []
    visited.add(path)
    rel = path.relative_to(root).as_posix()
    errors: list[str] = []
    for number, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = strip_yaml_comment(raw)
        if not line.strip():
            continue
        for marker, kind in FORBIDDEN.items():
            if marker.lower() in line.lower():
                errors.append(f"{rel}:{number}: {kind}")
        if SETUP_CACHE.search(line):
            errors.append(f"{rel}:{number}: github-cache")
        action = USES.search(line)
        if not action:
            continue
        reference = action.group(1)
        if reference.startswith("./"):
            candidate = root / reference[2:]
            for name in ("action.yml", "action.yaml"):
                errors.extend(action_violations(candidate / name, root, visited))
        elif reference.startswith("docker://"):
            if not PINNED_CONTAINER.fullmatch(reference):
                errors.append(f"{rel}:{number}: unpinned-container-action {reference}")
        else:
            revision = reference.rsplit("@", 1)[-1] if "@" in reference else ""
            if not PINNED_SHA.fullmatch(revision):
                errors.append(f"{rel}:{number}: unpinned-action {reference}")
    return errors


def workflow_violations(
    path: Path,
    root: Path,
    allowed_profiles: set[str],
    release_runners: set[str],
    allow_hosted: bool,
) -> list[str]:
    rel = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8")
    lines = [strip_yaml_comment(line) for line in text.splitlines()]
    errors: list[str] = []
    unique_labels: dict[str, int] = {}
    visited_actions: set[Path] = set()
    if has_pull_request_trigger(lines):
        for job_line, block in job_blocks(lines):
            if QDEV_PROFILE.search(block) and FORK_REPOSITORY_GUARD not in block:
                errors.append(f"{rel}:{job_line}: unguarded-public-fork-job")
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        if not allow_hosted and HOSTED.search(line):
            errors.append(f"{rel}:{number}: hosted-runner")
        for marker, kind in FORBIDDEN.items():
            if marker.lower() in line.lower():
                errors.append(f"{rel}:{number}: {kind}")
        if SETUP_CACHE.search(line):
            errors.append(f"{rel}:{number}: github-cache")
        action = USES.search(line)
        if action:
            reference = action.group(1)
            if reference.startswith("docker://"):
                if not PINNED_CONTAINER.fullmatch(reference):
                    errors.append(f"{rel}:{number}: unpinned-container-action {reference}")
            elif reference.startswith("./"):
                candidate = root / reference[2:]
                for name in ("action.yml", "action.yaml"):
                    errors.extend(action_violations(candidate / name, root, visited_actions))
            else:
                revision = reference.rsplit("@", 1)[-1] if "@" in reference else ""
                if not PINNED_SHA.fullmatch(revision):
                    errors.append(f"{rel}:{number}: unpinned-action {reference}")

        match = RUNS_ON.match(line)
        flow_match = None if match else FLOW_RUNS_ON.search(line)
        if not match and not flow_match:
            continue
        if match:
            indent = len(match.group(1))
            selector = match.group(2)
            index = number
            while index < len(lines):
                candidate = lines[index]
                if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indent:
                    break
                selector += " " + candidate.strip()
                index += 1
        else:
            assert flow_match is not None
            selector = flow_match.group(1)
        if "${{" in selector and not QDEV_PROFILE.search(selector):
            errors.append(f"{rel}:{number}: dynamic-runner-selector")
        selected_profiles = set(QDEV_PROFILE.findall(selector))
        if selected_profiles:
            if len(selected_profiles) != 1:
                errors.append(f"{rel}:{number}: multiple-runner-profiles")
            if not selected_profiles <= allowed_profiles:
                errors.append(f"{rel}:{number}: profile-not-allowed")
            required = ("self-hosted", "Linux", "X64")
            patterns = (rf"\b{re.escape(label)}\b" for label in required)
            if not all(re.search(pattern, selector) for pattern in patterns):
                errors.append(f"{rel}:{number}: missing-required-runner-label")
            has_unique_components = all(
                marker in selector
                for marker in ("qdev-job-", "github.run_id", "github.run_attempt")
            )
            label_match = UNIQUE_JOB_LABEL.search(selector)
            if not has_unique_components or not label_match:
                errors.append(f"{rel}:{number}: missing-unique-job-label")
            else:
                label = label_match.group(0)
                if label in unique_labels:
                    errors.append(f"{rel}:{number}: duplicate-unique-job-label")
                else:
                    unique_labels[label] = number
        elif "${{" not in selector:
            approved_hosted = allow_hosted and bool(HOSTED_SELECTOR.fullmatch(selector))
            approved_release = any(
                re.search(rf"\b{re.escape(label)}\b", selector) for label in release_runners
            )
            if not approved_hosted and not approved_release:
                errors.append(f"{rel}:{number}: unapproved-runner-profile")
    return errors


def check_repository(root: Path) -> list[str]:
    errors: list[str] = []
    allowed_profiles: set[str] = set()
    release_runners: set[str] = set()
    allow_hosted = False
    contract = root / ".github/qdev-runner.yml"
    if not contract.is_file():
        errors.append(".github/qdev-runner.yml:1: missing-contract")
    else:
        text = contract.read_text(encoding="utf-8")
        version_match = re.search(r"(?m)^schema_version:\s*(qdev-runner-v[12])\s*$", text)
        if not version_match:
            errors.append(".github/qdev-runner.yml:1: invalid-contract-version")
        version = version_match.group(1) if version_match else ""
        allow_hosted = version == "qdev-runner-v2"
        if version == "qdev-runner-v1" and not re.search(
            r"(?m)^github_hosted_fallback:\s*false\s*$", text
        ):
            errors.append(".github/qdev-runner.yml:1: hosted-fallback-not-disabled")
        if allow_hosted and not re.search(
            r"(?m)^execution_mode:\s*github-hosted-primary\s*$", text
        ):
            errors.append(".github/qdev-runner.yml:1: invalid-execution-mode")
        if allow_hosted and not re.search(r"(?m)^self_hosted_recovery:\s*true\s*$", text):
            errors.append(".github/qdev-runner.yml:1: self-hosted-recovery-not-enabled")
        allowed_profiles = set(contract_list(text, "profiles"))
        allowed_profiles &= {"qdev-ci", "qdev-ci-browser", "qdev-ci-docker"}
        if not allowed_profiles:
            errors.append(".github/qdev-runner.yml:1: invalid-contract-profiles")
        release_match = re.search(r"(?m)^release_runner:\s*([^\s#]+)", text)
        if release_match and release_match.group(1).lower() != "null":
            release_runners.add(release_match.group(1))
        release_runners.update(contract_list(text, "release_runners"))

    agents = root / "AGENTS.md"
    agents_text = agents.read_text(encoding="utf-8") if agents.is_file() else ""
    if MANAGED_START not in agents_text or MANAGED_END not in agents_text:
        errors.append("AGENTS.md:1: missing-managed-runner-policy")
    if not (root / ".github/QDEV_RUNNERS.md").is_file():
        errors.append(".github/QDEV_RUNNERS.md:1: missing-runner-documentation")

    workflows = root / ".github/workflows"
    if not workflows.is_dir():
        errors.append(".github/workflows:1: missing-workflow-directory")
        return errors
    for path in sorted((*workflows.glob("*.yml"), *workflows.glob("*.yaml"))):
        errors.extend(
            workflow_violations(path, root, allowed_profiles, release_runners, allow_hosted)
        )
    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    errors = check_repository(args.root.resolve())
    if errors:
        print("\n".join(errors))
        print(f"qdev_runner_contract_failed violations={len(errors)}")
        return 1
    print("qdev_runner_contract_ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
