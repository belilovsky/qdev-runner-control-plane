#!/usr/bin/env python3
"""Repository-local, dependency-free QDev workflow policy check."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

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
QDEV_PROFILE = re.compile(r"\bqdev-ci(?:-browser|-docker)?\b")
RUNS_ON = re.compile(r"^(\s*)runs-on:\s*(.*)$")
DYNAMIC_DEPLOYMENT = re.compile(
    r"^\s*\$\{\{\s*fromJSON\(inputs\.deployment_labels\)\s*\}\}\s*$"
)
MANAGED_START = "<!-- qdev-runner-policy:start -->"
MANAGED_END = "<!-- qdev-runner-policy:end -->"


def workflow_violations(path: Path, root: Path) -> list[str]:
    rel = path.relative_to(root).as_posix()
    text = path.read_text(encoding="utf-8")
    lines = text.splitlines()
    errors: list[str] = []
    for number, line in enumerate(lines, 1):
        if HOSTED.search(line):
            errors.append(f"{rel}:{number}: hosted-runner")
        for marker, kind in FORBIDDEN.items():
            if marker.lower() in line.lower():
                errors.append(f"{rel}:{number}: {kind}")
        if SETUP_CACHE.match(line):
            errors.append(f"{rel}:{number}: github-cache")
        action = USES.search(line)
        if action:
            reference = action.group(1)
            if not reference.startswith(("./", "docker://")):
                revision = reference.rsplit("@", 1)[-1] if "@" in reference else ""
                if not PINNED_SHA.fullmatch(revision):
                    errors.append(f"{rel}:{number}: unpinned-action {reference}")

        match = RUNS_ON.match(line)
        if not match:
            continue
        indent = len(match.group(1))
        selector = match.group(2)
        index = number
        while index < len(lines):
            candidate = lines[index]
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) <= indent:
                break
            selector += " " + candidate.strip()
            index += 1
        if (
            "${{" in selector
            and not QDEV_PROFILE.search(selector)
            and not DYNAMIC_DEPLOYMENT.fullmatch(selector)
        ):
            errors.append(f"{rel}:{number}: dynamic-runner-selector")
        if QDEV_PROFILE.search(selector) and "qdev-job-" not in selector:
            errors.append(f"{rel}:{number}: missing-unique-job-label")
    return errors


def check_repository(root: Path) -> list[str]:
    errors: list[str] = []
    contract = root / ".github/qdev-runner.yml"
    if not contract.is_file():
        errors.append(".github/qdev-runner.yml:1: missing-contract")
    else:
        text = contract.read_text(encoding="utf-8")
        if not re.search(r"(?m)^schema_version:\s*qdev-runner-v1\s*$", text):
            errors.append(".github/qdev-runner.yml:1: invalid-contract-version")
        if not re.search(r"(?m)^github_hosted_fallback:\s*false\s*$", text):
            errors.append(".github/qdev-runner.yml:1: hosted-fallback-not-disabled")

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
        errors.extend(workflow_violations(path, root))
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
