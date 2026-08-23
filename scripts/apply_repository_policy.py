#!/usr/bin/env python3
"""Install or refresh the managed QDev runner policy in one checkout."""

from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "templates"
START = "<!-- qdev-runner-policy:start -->"
END = "<!-- qdev-runner-policy:end -->"


def managed_agents(existing: str, managed: str) -> str:
    managed = managed.strip() + "\n"
    if START in existing and END in existing:
        before, remainder = existing.split(START, 1)
        _, after = remainder.split(END, 1)
        return before.rstrip() + "\n\n" + managed + after.lstrip("\n")
    if not existing.strip():
        return managed
    return existing.rstrip() + "\n\n" + managed


def install(checkout: Path) -> list[Path]:
    contract = checkout / ".github/qdev-runner.yml"
    if not contract.is_file():
        raise SystemExit(f"missing existing runner contract: {contract}")

    targets = {
        checkout / ".github/QDEV_RUNNERS.md": TEMPLATES / "QDEV_RUNNERS.md",
        checkout / ".github/workflows/qdev-runner-contract.yml": TEMPLATES
        / "qdev-runner-contract.yml",
        checkout / ".github/scripts/qdev-runner-policy.py": TEMPLATES
        / "qdev-runner-policy.py",
    }
    changed: list[Path] = []
    agents = checkout / "AGENTS.md"
    current = agents.read_text(encoding="utf-8") if agents.is_file() else ""
    desired = managed_agents(
        current, (TEMPLATES / "AGENTS.qdev-runner.md").read_text(encoding="utf-8")
    )
    if current != desired:
        agents.write_text(desired, encoding="utf-8")
        changed.append(agents)

    for target, source in targets.items():
        target.parent.mkdir(parents=True, exist_ok=True)
        desired_bytes = source.read_bytes()
        current_bytes = target.read_bytes() if target.is_file() else b""
        if current_bytes != desired_bytes:
            shutil.copyfile(source, target)
            changed.append(target)
    policy = checkout / ".github/scripts/qdev-runner-policy.py"
    policy.chmod(0o755)
    return changed


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("checkout", type=Path)
    args = parser.parse_args()
    checkout = args.checkout.resolve()
    changed = install(checkout)
    print(f"qdev_repository_policy_applied changed={len(changed)} checkout={checkout}")
    for path in changed:
        print(path.relative_to(checkout))


if __name__ == "__main__":
    main()
