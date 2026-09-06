"""Read-only, provider-backed CI observation for the fixed IdP release lane.

This is deliberately not admission, a native-runtime observation, or acceptance.
Candidate code is never imported/executed by the controller to verify itself.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from .file_apply_authorization import Artifact, CITuple, parse_binding
from .github import GitHubAppClient, GitHubError
from .release_lane import ReleaseLaneError

REPOSITORY = "belilovsky/id-qdev-run"
SCHEMA = "qdev-controller-idp-ci-observation-v1"
QUALITY_STEPS = (
    "Check shell scripts",
    "Check repository contracts",
    "Validate Compose",
    "Publish immutable release bundle",
)
MAX_ARCHIVE = 250 * 1024 * 1024


def _positive_int(value: object, expected: int) -> bool:
    return type(value) is int and value == expected and expected > 0


def _verify_job(github: GitHubAppClient, installation: int, expected: CITuple) -> None:
    current = github.workflow_run(installation, REPOSITORY, expected.run_id)
    attempt = github.workflow_run_attempt(
        installation, REPOSITORY, expected.run_id, expected.attempt
    )
    job = github.workflow_job(installation, REPOSITORY, expected.job_id)
    for run in (current, attempt):
        if (
            not _positive_int(run.get("id"), expected.run_id)
            or not _positive_int(run.get("run_attempt"), expected.attempt)
            or run.get("head_sha") != expected.source_sha
            or run.get("repository", {}).get("full_name") != REPOSITORY
            or run.get("head_repository", {}).get("full_name") != REPOSITORY
            or run.get("path") != f".github/workflows/{expected.workflow}"
            or run.get("event") not in ("push", "pull_request")
            or run.get("status") != "completed"
            or run.get("conclusion") != "success"
        ):
            raise ReleaseLaneError("IdP provider CI run or current attempt mismatch")
    quality = expected.workflow == "quality.yml"
    job_name = "static-contracts" if quality else "qdev-runner-contract"
    suffix = "static-contracts" if quality else "contract"
    labels = job.get("labels")
    required_labels = {
        "self-hosted",
        "Linux",
        "X64",
        expected.profile,
        f"qdev-job-{expected.run_id}-{expected.attempt}-{suffix}",
    }
    if (
        not _positive_int(job.get("id"), expected.job_id)
        or not _positive_int(job.get("run_id"), expected.run_id)
        or not _positive_int(job.get("run_attempt"), expected.attempt)
        or job.get("head_sha") != expected.source_sha
        or job.get("name") != job_name
        or job.get("status") != "completed"
        or job.get("conclusion") != "success"
        or job.get("started_at") != expected.started_at
        or job.get("completed_at") != expected.completed_at
        or not isinstance(labels, list)
        or any(not isinstance(x, str) for x in labels)
        or not required_labels.issubset(labels)
    ):
        raise ReleaseLaneError("IdP provider CI job identity, profile or result mismatch")
    required_steps = QUALITY_STEPS if quality else ("Validate QDev runner contract",)
    steps = job.get("steps")
    if not isinstance(steps, list) or any(not isinstance(x, dict) for x in steps):
        raise ReleaseLaneError("IdP provider CI steps are missing")
    for name in required_steps:
        matches = [step for step in steps if step.get("name") == name]
        if (
            len(matches) != 1
            or matches[0].get("status") != "completed"
            or matches[0].get("conclusion") != "success"
        ):
            raise ReleaseLaneError("IdP provider mandatory CI step did not succeed")


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _log_artifact(raw: bytes) -> Artifact:
    try:
        matches = []
        for line in raw.decode("utf-8").splitlines():
            line = re.sub(r"^\d{4}-\d\d-\d\dT[\d:.]+Z ", "", line)
            if line.startswith("QDEV_IDP_CI_BUNDLE "):
                matches.append(line.removeprefix("QDEV_IDP_CI_BUNDLE "))
        if len(matches) != 1 or len(matches[0]) > 16384:
            raise ValueError("ambiguous artifact observation")
        return Artifact.model_validate(json.loads(matches[0], object_pairs_hook=_unique_pairs))
    except (ValueError, ValidationError):
        raise ReleaseLaneError("IdP provider artifact log binding is invalid") from None


def _artifact_digest(root: Path, key: str) -> tuple[str, int]:
    """Hash the existing CI store file via no-follow handles; no local rebuild.

    Root comes only from broker configuration, key from the validated fixed
    schema. All ancestors must be root/controller-owned and non-writable by
    others. The archive itself must be controller-owned 0600 with one link.
    """
    if not root.is_absolute() or ".." in root.parts or ".." in Path(key).parts:
        raise ReleaseLaneError("IdP artifact store path is invalid")
    descriptor = -1
    try:
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        parts = (root / key).parts[1:]
        for index, part in enumerate(parts):
            final = index == len(parts) - 1
            child = os.open(
                part,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | (0 if final else os.O_DIRECTORY),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
            metadata = os.fstat(descriptor)
            if metadata.st_uid not in (0, os.geteuid()) or stat.S_IMODE(metadata.st_mode) & 0o022:
                raise ReleaseLaneError("IdP artifact store ownership or mode mismatch")
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or stat.S_IMODE(before.st_mode) != 0o600
            or not 0 < before.st_size <= MAX_ARCHIVE
        ):
            raise ReleaseLaneError("IdP CI archive ownership, type, mode or size mismatch")
        digest = hashlib.sha256()
        size = 0
        while chunk := os.read(descriptor, 1024 * 1024):
            size += len(chunk)
            if size > MAX_ARCHIVE:
                raise ReleaseLaneError("IdP CI archive exceeded its size limit")
            digest.update(chunk)
        after = os.fstat(descriptor)
        if (
            size != before.st_size
            or before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or after.st_nlink != 1
        ):
            raise ReleaseLaneError("IdP CI archive changed during verification")
        return digest.hexdigest(), size
    except OSError:
        raise ReleaseLaneError("IdP CI archive is unavailable or unsafe") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def observe_idp_ci(
    raw_binding: bytes,
    *,
    github: GitHubAppClient,
    artifact_root: Path,
    clock: Callable[[], float] = time.time,
) -> dict[str, Any]:
    """Verify current provider state both before and after archive observation.

    Only the CI portion is attested. Native rollback, local observation files,
    component bytes and admission need their separate host/controller proofs.
    """
    started = clock()
    binding = parse_binding(raw_binding, now=started)
    ci = binding.ci_observation
    try:
        installation = github.repository_installation_id(REPOSITORY)
        for expected in (ci.quality, ci.runner_contract):
            _verify_job(github, installation, expected)
        artifact = _log_artifact(
            github.workflow_job_log(installation, REPOSITORY, ci.quality.job_id)
        )
        if artifact != ci.artifact:
            raise ReleaseLaneError("IdP requested artifact differs from provider observation")
        digest, size = _artifact_digest(artifact_root, artifact.storage_key)
        if digest != artifact.artifact_sha256:
            raise ReleaseLaneError("IdP stored archive differs from provider digest")
        for expected in (ci.quality, ci.runner_contract):
            _verify_job(github, installation, expected)
    except (GitHubError, AttributeError, TypeError, ValueError):
        # Do not surface raw provider responses, job logs or signed download URLs.
        raise ReleaseLaneError("IdP provider verification is unavailable or malformed") from None
    finished = clock()
    parse_binding(raw_binding, now=finished)
    if not 0 <= finished - started <= 300:
        raise ReleaseLaneError("IdP CI verification exceeded its freshness window")
    return {
        "schema": SCHEMA,
        "status": "provider_ci_archive_verified",
        "repository": REPOSITORY,
        "source_sha": binding.source_sha,
        "observed_at": datetime.fromtimestamp(finished, UTC).isoformat(),
        "expires_at": datetime.fromtimestamp(finished + 120, UTC).isoformat(),
        "quality": ci.quality.model_dump(),
        "runner_contract": ci.runner_contract.model_dump(),
        "artifact": artifact.model_dump(),
        "archive_size": size,
        "verification": {
            "provider": "github_app",
            "current_attempt_rechecked": True,
            "archive": "existing_controller_ci_store_sha256",
        },
        "controller_admission": "not_verified",
        "native_runtime": "not_verified",
        "bundle_components": "not_verified",
        "rollback": "not_verified",
        "acceptance": "not_run",
    }
