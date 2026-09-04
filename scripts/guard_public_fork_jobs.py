#!/usr/bin/env python3
"""Prevent public fork code from reaching QDev self-hosted runners."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

JOB = re.compile(r"^  (?P<name>[A-Za-z0-9_-]+):\s*(?:#.*)?$")
JOB_IF = re.compile(r"^    if:\s*(?P<value>.+?)\s*$")
QDEV_PROFILE = re.compile(r"\bqdev-ci(?:-browser|-docker)?\b")
FORK_GUARD = (
    "github.event_name != 'pull_request' || "
    "github.event.pull_request.head.repo.full_name == github.repository"
)


def has_pull_request_trigger(lines: list[str]) -> bool:
    for index, raw in enumerate(lines):
        line = raw.rstrip("\r\n")
        match = re.match(r'^on:\s*(?P<value>.*)$', line)
        if not match:
            continue
        value = match.group("value")
        if value:
            return bool(re.search(r"\bpull_request\b", value))
        for candidate in lines[index + 1 :]:
            stripped = candidate.rstrip("\r\n")
            if stripped and not stripped.startswith((" ", "\t", "#")):
                break
            if re.match(r"^  pull_request:\s*", stripped):
                return True
        return False
    return False


def guarded_condition(value: str) -> str:
    if FORK_GUARD in value:
        return value
    expression = value.strip()
    if expression.startswith("${{") and expression.endswith("}}"):
        expression = expression[3:-2].strip()
    if expression in {">", ">-", "|", "|-"}:
        raise ValueError("multiline job if conditions require a manual fork guard")
    return f"({expression}) && ({FORK_GUARD})"


def rewrite(text: str) -> str:
    lines = text.splitlines(keepends=True)
    if not has_pull_request_trigger(lines):
        return text

    starts = [index for index, line in enumerate(lines) if JOB.match(line.rstrip("\r\n"))]
    for position, start in reversed(list(enumerate(starts))):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        block = "".join(lines[start:end])
        if not QDEV_PROFILE.search(block):
            continue
        existing = next(
            (
                index
                for index in range(start + 1, end)
                if JOB_IF.match(lines[index].rstrip("\r\n"))
            ),
            None,
        )
        if existing is None:
            newline = "\r\n" if lines[start].endswith("\r\n") else "\n"
            lines.insert(start + 1, f"    if: {FORK_GUARD}{newline}")
            continue
        match = JOB_IF.match(lines[existing].rstrip("\r\n"))
        assert match is not None
        replacement = guarded_condition(match.group("value"))
        newline = "\r\n" if lines[existing].endswith("\r\n") else "\n"
        lines[existing] = f"    if: {replacement}{newline}"
    return "".join(lines)


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
