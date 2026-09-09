#!/usr/bin/env python3
"""One complete verification entrypoint for controller-managed, recovery and local CI."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REPOSITORY = "belilovsky/qdev-runner-control-plane"
GITHUB_ENDPOINTS = {
    "server_url": "https://github.com",
    "api_url": "https://api.github.com",
    "graphql_url": "https://api.github.com/graphql",
}


def provider_binding(environment: dict[str, str], sha: str) -> dict[str, str | int]:
    """Bind the checkout to the provider event, preserving its separate merge SHA."""
    provider_sha = environment.get("GITHUB_SHA", "")
    if not re.fullmatch(r"[0-9a-f]{40}", provider_sha):
        raise ValueError("exact provider SHA is required")
    event_path = environment.get("GITHUB_EVENT_PATH", "")
    try:
        with Path(event_path).open("rb") as stream:
            raw = stream.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("provider event exceeds size limit")
        event = json.loads(raw)
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError("readable provider event is required") from error
    if not isinstance(event, dict):
        raise ValueError("provider event must be an object")
    repository = event.get("repository")
    if (
        not isinstance(repository, dict)
        or repository.get("full_name") != REPOSITORY
        or environment.get("GITHUB_REPOSITORY") != REPOSITORY
        or type(repository.get("id")) is not int
        or repository["id"] <= 0
        or str(repository["id"]) != environment.get("GITHUB_REPOSITORY_ID")
        or environment.get("GITHUB_REPOSITORY_OWNER") != REPOSITORY.split("/")[0]
    ):
        raise ValueError("provider repository identity mismatch")
    name = environment.get("GITHUB_EVENT_NAME", "")
    binding: dict[str, str | int] = {
        "event": name,
        "repository": REPOSITORY,
        "repository_id": repository["id"],
        "provider_sha": provider_sha,
        "checkout_sha": sha,
    }
    if name == "pull_request":
        pr = event.get("pull_request")
        number = event.get("number")
        if (
            event.get("action") not in ("opened", "synchronize", "reopened")
            or not isinstance(pr, dict)
            or type(number) is not int
            or number <= 0
            or pr.get("number") != number
            or environment.get("GITHUB_REF") != f"refs/pull/{number}/merge"
        ):
            raise ValueError("pull request merge context mismatch")
        event_merge_sha = pr.get("merge_commit_sha")
        if event_merge_sha is not None and not re.fullmatch(r"[0-9a-f]{40}", str(event_merge_sha)):
            raise ValueError("pull request event merge SHA is invalid")
        # GitHub can regenerate refs/pull/<number>/merge after the webhook
        # payload was created but before the job starts.  Both values are
        # provider evidence, but only GITHUB_SHA identifies this execution's
        # merge context; the exact checked-out head is bound separately below.
        if provider_sha == sha:
            raise ValueError("pull request provider merge must differ from checkout")
        for side, ref_variable in (("base", "GITHUB_BASE_REF"), ("head", "GITHUB_HEAD_REF")):
            revision = pr.get(side)
            if not isinstance(revision, dict):
                raise ValueError("pull request source identity missing")
            repo = revision.get("repo")
            if (
                not isinstance(repo, dict)
                or repo.get("full_name") != REPOSITORY
                or type(repo.get("id")) is not int
                or repo["id"] != repository["id"]
                or not revision.get("ref")
                or revision["ref"] != environment.get(ref_variable)
                or not re.fullmatch(r"[0-9a-f]{40}", str(revision.get("sha", "")))
            ):
                raise ValueError("pull request source identity mismatch")
        if pr["head"]["sha"] != sha:
            raise ValueError("pull request head does not match checkout")
        binding.update({"pull_request": number, "provider_merge_sha": provider_sha})
    elif name in {"push", "workflow_dispatch"}:
        if provider_sha != sha:
            raise ValueError("provider SHA does not match checkout")
        ref = environment.get("GITHUB_REF", "")
        if not ref.startswith("refs/heads/") or ref == "refs/heads/":
            raise ValueError("provider branch ref is required")
        if name == "push" and (event.get("after") != sha or event.get("ref") != ref):
            raise ValueError("push event does not match checkout")
        if name == "workflow_dispatch":
            sender = event.get("sender")
            owner = environment["GITHUB_REPOSITORY_OWNER"]
            event_ref = event.get("ref")
            if (
                environment.get("GITHUB_ACTOR") != owner
                or not isinstance(sender, dict)
                or sender.get("login") != owner
                or event_ref not in (ref, ref.removeprefix("refs/heads/"))
            ):
                raise ValueError("dispatch requires a confirmed owner and exact branch")
    else:
        raise ValueError("unsupported provider event")
    return binding


def provider_execution_binding(
    environment: dict[str, str], *, workflow: str, job: str
) -> dict[str, str | int]:
    """Bind provider evidence to the official endpoint, workflow and exact job run."""
    for field, expected in (
        ("GITHUB_SERVER_URL", GITHUB_ENDPOINTS["server_url"]),
        ("GITHUB_API_URL", GITHUB_ENDPOINTS["api_url"]),
        ("GITHUB_GRAPHQL_URL", GITHUB_ENDPOINTS["graphql_url"]),
    ):
        if environment.get(field) != expected:
            raise ValueError("provider endpoint identity mismatch")
    ref = environment.get("GITHUB_REF", "")
    workflow_ref = environment.get("GITHUB_WORKFLOW_REF", "")
    expected_workflow_ref = f"{REPOSITORY}/.github/workflows/{workflow}@{ref}"
    if workflow_ref != expected_workflow_ref:
        raise ValueError("provider workflow identity mismatch")
    if environment.get("GITHUB_JOB") != job:
        raise ValueError("provider job identity mismatch")
    numeric: dict[str, int] = {}
    for field, key in (
        ("GITHUB_RUN_ID", "run_id"),
        ("GITHUB_RUN_ATTEMPT", "run_attempt"),
    ):
        value = environment.get(field, "")
        if not value.isdigit() or int(value) < 1:
            raise ValueError("provider run identity mismatch")
        numeric[key] = int(value)
    return {
        **GITHUB_ENDPOINTS,
        "workflow_ref": workflow_ref,
        "job": job,
        "ref": ref,
        **numeric,
    }


def validate_context(
    lane: str, environment: dict[str, str], sha: str
) -> dict[str, str | int] | None:
    if lane not in {
        "local",
        "github-hosted",
        "managed",
        "controller-recovery",
        "controller-recovery-build",
    }:
        raise ValueError("unknown execution lane")
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("exact checkout SHA is required")
    expected = environment.get("QDEV_EXPECTED_SHA", "")
    if expected and expected != sha:
        raise ValueError("checkout does not match requested SHA")
    if environment.get("GITHUB_ACTIONS") != "true":
        if lane != "local":
            raise ValueError("provider CI evidence requires a real Actions execution")
        return
    if lane == "local":
        raise ValueError("Actions must identify its real execution lane")
    binding = provider_binding(environment, sha)
    recovery = lane == "controller-recovery"
    recovery_build = lane == "controller-recovery-build"
    binding.update(
        provider_execution_binding(
            environment,
            workflow=(
                "runner-smoke.yml"
                if recovery
                else "controller-recovery-build.yml"
                if recovery_build
                else "ci.yml"
            ),
            job=(
                "runner-smoke"
                if recovery
                else "controller-recovery-build"
                if recovery_build
                else "verify"
            ),
        )
    )
    runner_environment = (
        "github-hosted" if lane in {"github-hosted", "controller-recovery-build"} else "self-hosted"
    )
    if environment.get("RUNNER_ENVIRONMENT") != runner_environment:
        raise ValueError("runner environment does not match requested execution lane")
    if lane == "managed":
        if environment.get("QDEV_MANAGED_CI") != "true" or not expected:
            raise ValueError("managed CI requires an exact controller-bound checkout")
        if not environment.get("RUNNER_NAME"):
            raise ValueError("managed CI requires an enrolled ephemeral runner")
        event = environment.get("GITHUB_EVENT_NAME")
        if event not in {"push", "workflow_dispatch", "pull_request"}:
            raise ValueError("managed CI received an untrusted event")
        owner = environment.get("GITHUB_REPOSITORY_OWNER", "")
        expected_repository = f"{owner}/qdev-runner-control-plane"
        if not owner or environment.get("GITHUB_REPOSITORY") != expected_repository:
            raise ValueError("managed CI is bound to the controller repository")
    if recovery or recovery_build:
        owner = environment.get("GITHUB_REPOSITORY_OWNER", "")
        if not owner or environment.get("GITHUB_ACTOR") != owner:
            raise ValueError("recovery requires the nonempty repository owner actor")
        repository = environment.get("GITHUB_REPOSITORY")
        if repository != f"{owner}/qdev-runner-control-plane":
            raise ValueError("recovery is bound to the controller repository")
        if environment.get("GITHUB_EVENT_NAME") != "workflow_dispatch":
            raise ValueError("recovery requires manual workflow_dispatch")
        ref = environment.get("GITHUB_REF", "")
        if not ref.startswith("refs/heads/") or ref == "refs/heads/":
            raise ValueError("recovery requires a selected repository branch")
        if recovery_build and ref != "refs/heads/main":
            raise ValueError("recovery build requires the default branch")
        if environment.get("QDEV_OWNER_RECOVERY") != "true" or not expected:
            raise ValueError("explicit owner recovery confirmation and exact SHA are required")
    return binding


def commands(python: str) -> list[list[str]]:
    # Every lane executes every check. Failures stop the sequence; no partial success receipt.
    return [
        [python, "-m", "ruff", "check", "."],
        [python, "-m", "ruff", "format", "--check", "."],
        [python, "-m", "mypy"],
        [python, "-m", "pytest", "-q"],
        [python, ".github/scripts/qdev-runner-policy.py", "--root", "."],
        [python, "scripts/verify_runtime_install.py"],
    ]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--lane",
        choices=(
            "local",
            "github-hosted",
            "managed",
            "controller-recovery",
            "controller-recovery-build",
        ),
        required=True,
    )
    args = parser.parse_args()
    if sys.version_info[:2] != (3, 12):
        parser.error("complete controller CI requires Python 3.12")
    sha = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    dirty = bool(subprocess.check_output(["git", "status", "--porcelain"], cwd=ROOT))
    if dirty and args.lane != "local":
        parser.error("provider evidence requires an unchanged exact-SHA checkout")
    try:
        binding = validate_context(args.lane, dict(os.environ), sha)
    except ValueError as error:
        parser.error(str(error))
    for command in commands(sys.executable):
        subprocess.run(command, cwd=ROOT, check=True)
    print(
        json.dumps(
            {
                "schema": "qdev-controller-ci-execution-v1",
                "sha": sha,
                "source_scope": "working-tree" if dirty else "commit",
                "dirty": dirty,
                "lane": args.lane,
                "source_binding": binding,
                "runner_environment": os.environ.get("RUNNER_ENVIRONMENT"),
                "run_id": os.environ.get("GITHUB_RUN_ID"),
                "attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
                "checks": [
                    "lint",
                    "format",
                    "typing",
                    "pytest",
                    "runner-policy",
                    "runtime-install",
                ],
                "status": "passed",
                "signed": False,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
