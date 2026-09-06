#!/usr/bin/env python3
# QAZCOOP_RELEASE_GUARD_MANAGED_V1
"""Root-owned update hook for the QazCoop protected release branch."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

BRANCH = "refs/heads/codex/qazcoop-mvp"
LOCK_PATH = "app/contracts/release_lock.v1.json"
PAYLOAD_PATH = "docs/acceptance/release-receipt.v3.payload.json"
VERIFIER = Path("/usr/local/sbin/qdev-controller-verify-admission")
ZERO = "0" * 40
SHA = re.compile(r"^[0-9a-f]{40}$")


class GuardError(ValueError):
    """Raised when a protected ref update is not admitted."""


def git(repository: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(
            ["/usr/bin/git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise GuardError("protected repository cannot be inspected") from error
    return result.stdout.strip()


def strict_json(raw: str, relative_path: str) -> dict[str, object]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise GuardError(f"{relative_path} contains duplicate key {key}")
            value[key] = item
        return value

    def constant(value: str) -> None:
        raise GuardError(f"{relative_path} contains forbidden constant {value}")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except json.JSONDecodeError as error:
        raise GuardError(f"{relative_path} is not valid JSON") from error
    if not isinstance(value, dict):
        raise GuardError(f"{relative_path} must contain an object")
    return value


def object_at(repository: Path, revision: str, relative_path: str) -> dict[str, object]:
    return strict_json(git(repository, "show", f"{revision}:{relative_path}"), relative_path)


def release_lock(repository: Path, revision: str) -> dict[str, object]:
    value = object_at(repository, revision, LOCK_PATH)
    source = value.get("functional_source_sha")
    if (
        value.get("contract") != "qazcoop-release-lock/v1"
        or value.get("status") != "active"
        or not isinstance(source, str)
        or SHA.fullmatch(source) is None
        or value.get("public_marker") != f"qazcoop-{source[:7]}"
    ):
        raise GuardError("release lock is invalid")
    return value


def require_ancestor(repository: Path, older: str, newer: str, message: str) -> None:
    if subprocess.run(
        ["/usr/bin/git", "merge-base", "--is-ancestor", older, newer],
        cwd=repository,
        check=False,
        capture_output=True,
    ).returncode:
        raise GuardError(message)


def validate_update(repository: Path, reference: str, old: str, new: str) -> None:
    if reference != BRANCH:
        return
    if old == ZERO or new == ZERO or SHA.fullmatch(old) is None or SHA.fullmatch(new) is None:
        raise GuardError("protected branch cannot be created, deleted, or ambiguously updated")
    require_ancestor(repository, old, new, "non-fast-forward update is denied")
    previous = release_lock(repository, old)
    candidate = release_lock(repository, new)
    payload = object_at(repository, new, PAYLOAD_PATH)
    payload_source = payload.get("functional_source_sha")
    if candidate != previous:
        raise GuardError("historical release lock changed before deployment")
    for source, message in (
        (previous["functional_source_sha"], "locked release is not retained"),
        (payload_source, "receipt source does not point into the branch"),
    ):
        if not isinstance(source, str) or SHA.fullmatch(source) is None:
            raise GuardError("release source binding is malformed")
        require_ancestor(repository, source, new, message)
    command = [
        str(VERIFIER),
        "verify-qazcoop-admission",
        "--repository",
        str(repository),
        "--protected-ref",
        BRANCH,
        "--evidence-commit-sha",
        new,
    ]
    # The tracked lock is immutable historical deployment evidence. Require
    # controller admission for every protected update so that an unsigned
    # evidence chain cannot advance the deployable functional source.
    command.append("--require-authoritative-admission")
    result = subprocess.run(command, cwd=repository, capture_output=True, text=True)
    if result.returncode:
        detail = result.stderr.strip() or result.stdout.strip() or "admission rejected"
        raise GuardError(detail.splitlines()[-1])


def main() -> int:
    if len(sys.argv) != 4:
        print("qazcoop release guard: expected ref old new", file=sys.stderr)
        return 2
    repository = Path.cwd().resolve()
    try:
        validate_update(repository, *sys.argv[1:4])
    except (GuardError, OSError) as error:
        print(f"qazcoop release guard: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
