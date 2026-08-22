#!/usr/bin/env python3
"""Rewrite hosted-only GitHub cache/artifact steps for the QDev CI contract."""

from __future__ import annotations

import argparse
import re
import shlex
from pathlib import Path

STEP_START = re.compile(r"^(?P<indent>\s*)-\s+")
UPLOAD = re.compile(r"uses:\s*actions/upload-artifact@")
CACHE = re.compile(r"uses:\s*actions/cache@")


def _step_blocks(lines: list[str]) -> list[list[str]]:
    blocks: list[list[str]] = []
    index = 0
    while index < len(lines):
        match = STEP_START.match(lines[index])
        if not match or len(match.group("indent")) < 6:
            blocks.append([lines[index]])
            index += 1
            continue
        indent = match.group("indent")
        end = index + 1
        while end < len(lines):
            candidate = lines[end]
            if STEP_START.match(candidate) and candidate.startswith(indent + "-"):
                break
            if candidate.strip() and len(candidate) - len(candidate.lstrip()) < len(indent):
                break
            end += 1
        blocks.append(lines[index:end])
        index = end
    return blocks


def _with_values(block: list[str]) -> tuple[str, list[str], bool]:
    with_index = next(i for i, line in enumerate(block) if line.strip() == "with:")
    values: dict[str, str] = {}
    paths: list[str] = []
    index = with_index + 1
    while index < len(block):
        stripped = block[index].strip()
        match = re.match(r"([a-zA-Z0-9_-]+):\s*(.*)", stripped)
        if not match:
            index += 1
            continue
        key, value = match.groups()
        if key == "path" and value in {"|", ">", ">-", "|-"}:
            child_indent = len(block[index]) - len(block[index].lstrip())
            index += 1
            while index < len(block):
                line = block[index]
                if not line.strip():
                    index += 1
                    continue
                if len(line) - len(line.lstrip()) <= child_indent:
                    break
                paths.append(line.strip())
                index += 1
            continue
        values[key] = value.strip("'\"")
        index += 1
    if not paths and values.get("path"):
        paths.append(values["path"])
    artifact_name = values.get("name", "qdev-artifact")
    warn = values.get("if-no-files-found", "error") in {"ignore", "warn"}
    return artifact_name, paths, warn


def _artifact_step(block: list[str]) -> list[str]:
    indent = STEP_START.match(block[0]).group("indent")  # type: ignore[union-attr]
    display = "Upload QDev artifact"
    for line in block:
        match = re.match(r"\s*-?\s*name:\s*(.+)", line)
        if match:
            display = match.group(1)
            break
    condition = next((line.strip() for line in block if line.strip().startswith("if:")), "")
    name, paths, warn = _with_values(block)
    command = ".github/scripts/qdev-upload-artifact.sh " + shlex.quote(name)
    if paths:
        command += " " + " ".join(shlex.quote(path) for path in paths if not path.startswith("!"))
    output = [f"{indent}- name: {display}\n"]
    if condition:
        output.append(f"{indent}  {condition}\n")
    if warn:
        output.extend(
            [
                f"{indent}  env:\n",
                f"{indent}    QDEV_IF_NO_FILES: warn\n",
            ]
        )
    output.append(f"{indent}  run: {command}\n")
    return output


def _without_setup_cache(block: list[str]) -> list[str]:
    output: list[str] = []
    index = 0
    while index < len(block):
        line = block[index]
        if re.match(r"^\s+cache:\s*['\"]?(?:pip|npm|yarn|pnpm)['\"]?\s*$", line):
            index += 1
            continue
        if re.match(r"^\s+cache-dependency-path:", line):
            indent = len(line) - len(line.lstrip())
            index += 1
            while index < len(block):
                child = block[index]
                if child.strip() and len(child) - len(child.lstrip()) <= indent:
                    break
                index += 1
            continue
        output.append(line)
        index += 1
    return output


def rewrite(text: str) -> str:
    output: list[str] = []
    for block in _step_blocks(text.splitlines(keepends=True)):
        joined = "".join(block)
        if CACHE.search(joined):
            continue
        if UPLOAD.search(joined):
            output.extend(_artifact_step(block))
            continue
        output.extend(_without_setup_cache(block))
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
