#!/usr/bin/env python3
"""Replace hosted/general CI runner selectors with the QDev ephemeral contract."""

from __future__ import annotations

import argparse
import re
from pathlib import Path

JOB = re.compile(r"^  (?P<name>[A-Za-z0-9_-]+):\s*(?:#.*)?$")
RUNS_ON = re.compile(r"^(?P<indent>\s*)runs-on:\s*(?P<value>.+?)\s*$")
HOSTED = re.compile(r"(?:ubuntu|windows|macos)-(?:latest|\d[\w.-]*)", re.I)
QDEV = re.compile(r"\bqdev-ci(?:-browser|-docker)?\b")


def _matches(patterns: list[re.Pattern[str]], value: str) -> bool:
    return any(pattern.search(value) for pattern in patterns)


def rewrite(
    text: str,
    *,
    docker_jobs: list[re.Pattern[str]],
    browser_jobs: list[re.Pattern[str]],
    convert_jobs: list[re.Pattern[str]],
) -> str:
    current_job = ""
    output: list[str] = []
    for line in text.splitlines(keepends=True):
        job = JOB.match(line.rstrip("\r\n"))
        if job:
            current_job = job.group("name")
        selector = RUNS_ON.match(line.rstrip("\r\n"))
        if not selector or not current_job:
            output.append(line)
            continue
        value = selector.group("value")
        should_convert = bool(HOSTED.search(value) or QDEV.search(value)) or _matches(
            convert_jobs, current_job
        )
        if not should_convert:
            output.append(line)
            continue
        if _matches(docker_jobs, current_job):
            profile = "qdev-ci-docker"
        elif _matches(browser_jobs, current_job):
            profile = "qdev-ci-browser"
        else:
            profile = "qdev-ci"
        job_label = current_job.lower().replace("_", "-")
        replacement = (
            f'{selector.group("indent")}runs-on: [self-hosted, Linux, X64, {profile}, '
            f'"qdev-job-${{{{ github.run_id }}}}-${{{{ github.run_attempt }}}}-{job_label}"]\n'
        )
        output.append(replacement)
    return "".join(output)


def _patterns(values: list[str]) -> list[re.Pattern[str]]:
    return [re.compile(value) for value in values]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="+", type=Path)
    parser.add_argument("--docker-job", action="append", default=[])
    parser.add_argument("--browser-job", action="append", default=[])
    parser.add_argument("--convert-job", action="append", default=[])
    args = parser.parse_args()
    options = {
        "docker_jobs": _patterns(args.docker_job),
        "browser_jobs": _patterns(args.browser_job),
        "convert_jobs": _patterns(args.convert_job),
    }
    for path in args.files:
        original = path.read_text(encoding="utf-8")
        rewritten = rewrite(original, **options)
        if rewritten != original:
            path.write_text(rewritten, encoding="utf-8")


if __name__ == "__main__":
    main()
