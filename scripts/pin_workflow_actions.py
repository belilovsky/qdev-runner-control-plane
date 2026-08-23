#!/usr/bin/env python3
"""Resolve external workflow actions to immutable Git commit SHAs."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from collections.abc import Callable
from pathlib import Path

ACTION = re.compile(
    r"(?P<prefix>\buses:\s*)"
    r"(?P<action>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[^\s@#]+)?)"
    r"@(?P<ref>[^\s#]+)(?P<suffix>\s*(?:#.*)?)$"
)
SHA = re.compile(r"^[0-9a-fA-F]{40}$")
GIT = shutil.which("git")
if GIT is None:
    raise RuntimeError("git executable is required")


def resolve(repository: str, ref: str) -> str:
    refs = [f"refs/tags/{ref}^{{}}", f"refs/tags/{ref}", f"refs/heads/{ref}"]
    completed = subprocess.run(  # noqa: S603
        [GIT, "ls-remote", "--exit-code", f"https://github.com/{repository}.git", *refs],
        check=True,
        capture_output=True,
        text=True,
    )
    candidates = {
        remote_ref: commit
        for line in completed.stdout.splitlines()
        for commit, remote_ref in [line.split(maxsplit=1)]
    }
    for remote_ref in refs:
        if remote_ref in candidates:
            commit = candidates[remote_ref]
            if SHA.fullmatch(commit):
                return commit.lower()
    raise RuntimeError(f"could not resolve action ref: {repository}@{ref}")


def rewrite(text: str, resolver: Callable[[str, str], str] = resolve) -> str:
    cache: dict[tuple[str, str], str] = {}
    output: list[str] = []
    for line in text.splitlines(keepends=True):
        ending = "\n" if line.endswith("\n") else ""
        content = line.removesuffix("\n")
        match = ACTION.search(content)
        if not match or SHA.fullmatch(match.group("ref")):
            output.append(line)
            continue
        action = match.group("action")
        repository = "/".join(action.split("/")[:2])
        ref = match.group("ref")
        key = (repository, ref)
        if key not in cache:
            cache[key] = resolver(repository, ref)
        commit = cache[key]
        suffix = match.group("suffix") or f" # {ref}"
        replacement = (
            content[: match.start()]
            + match.group("prefix")
            + action
            + "@"
            + commit
            + suffix
        )
        output.append(replacement + ending)
    return "".join(output)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", type=Path)
    args = parser.parse_args()
    for path in args.files:
        original = path.read_text(encoding="utf-8")
        rewritten = rewrite(original)
        if rewritten != original:
            path.write_text(rewritten, encoding="utf-8")


if __name__ == "__main__":
    main()
