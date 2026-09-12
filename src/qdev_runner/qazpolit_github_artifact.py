"""Acquire one exact successful QazPolit Actions artifact into private storage.

This module deliberately has no HTTP route and no release-host hand-off.  It
binds a controller-owned GitHub App observation to the immutable archive store:
the repository, workflow run, run attempt, source commit, artifact identity,
artifact name, and provider-declared byte count must all agree before bytes are
accepted.  The GitHub download URL in provider metadata is never used here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from qdev_runner.qazpolit_artifact_store import (
    QazPolitArtifactStore,
    StoredQazPolitReleaseArtifact,
)

_REPOSITORY_PATTERN = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_SOURCE_SHA_PATTERN = re.compile(r"^[0-9a-f]{40}$")


class QazPolitGitHubArtifactError(RuntimeError):
    """Raised when Actions metadata cannot prove one permitted archive."""


class QazPolitGitHubArtifactClient(Protocol):
    """Small GitHub boundary needed to acquire a fixed release artifact."""

    def repository_installation_id(self, repository: str) -> int: ...

    def workflow_run(
        self, installation_id: int, repository: str, run_id: int
    ) -> dict[str, Any]: ...

    def workflow_run_artifacts(
        self, installation_id: int, repository: str, run_id: int
    ) -> list[dict[str, Any]]: ...

    def download_actions_artifact_to_file(
        self,
        installation_id: int,
        repository: str,
        artifact_id: int,
        destination: Path,
        *,
        maximum_bytes: int,
    ) -> None: ...


@dataclass(frozen=True)
class QazPolitActionsArtifactRequest:
    """All immutable facts that authorize one GitHub Actions artifact fetch."""

    repository: str
    source_sha: str
    run_id: int
    run_attempt: int
    artifact_id: int
    artifact_size_bytes: int

    def __post_init__(self) -> None:
        if not _REPOSITORY_PATTERN.fullmatch(self.repository):
            raise QazPolitGitHubArtifactError("QazPolit artifact repository is invalid")
        if not _SOURCE_SHA_PATTERN.fullmatch(self.source_sha):
            raise QazPolitGitHubArtifactError("QazPolit artifact source SHA is invalid")
        for name, value in (
            ("workflow run", self.run_id),
            ("workflow run attempt", self.run_attempt),
            ("artifact", self.artifact_id),
            ("artifact size", self.artifact_size_bytes),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < 1:
                raise QazPolitGitHubArtifactError(f"QazPolit {name} identity is invalid")

    @property
    def artifact_name(self) -> str:
        return f"qazpolit-production-{self.source_sha}-{self.run_id}"


def acquire_qazpolit_actions_artifact(
    client: QazPolitGitHubArtifactClient,
    store: QazPolitArtifactStore,
    request: QazPolitActionsArtifactRequest,
) -> StoredQazPolitReleaseArtifact:
    """Fetch and store only the artifact uniquely bound to a successful run."""

    installation_id = client.repository_installation_id(request.repository)
    run = client.workflow_run(installation_id, request.repository, request.run_id)
    _validate_workflow_run(run, request)
    artifacts = client.workflow_run_artifacts(installation_id, request.repository, request.run_id)
    artifact = _select_artifact(artifacts, request)

    def download_to(destination: Path) -> None:
        client.download_actions_artifact_to_file(
            installation_id,
            request.repository,
            request.artifact_id,
            destination,
            maximum_bytes=request.artifact_size_bytes,
        )

    return store.ingest_download(
        download_to,
        expected_source_sha=request.source_sha,
        expected_archive_bytes=_require_positive_int(artifact, "size_in_bytes", "artifact size"),
    )


def _validate_workflow_run(run: dict[str, Any], request: QazPolitActionsArtifactRequest) -> None:
    if _require_positive_int(run, "id", "workflow run") != request.run_id:
        raise QazPolitGitHubArtifactError("workflow run does not match QazPolit artifact request")
    if _require_string(run, "head_sha", "workflow run") != request.source_sha:
        raise QazPolitGitHubArtifactError(
            "workflow run source SHA does not match QazPolit artifact"
        )
    if _require_positive_int(run, "run_attempt", "workflow run") != request.run_attempt:
        raise QazPolitGitHubArtifactError("workflow run attempt does not match QazPolit artifact")
    if _require_string(run, "status", "workflow run") != "completed":
        raise QazPolitGitHubArtifactError("workflow run is not completed")
    if _require_string(run, "conclusion", "workflow run") != "success":
        raise QazPolitGitHubArtifactError("workflow run did not succeed")
    repository = run.get("repository")
    if (
        not isinstance(repository, dict)
        or _require_string(repository, "full_name", "workflow run repository") != request.repository
    ):
        raise QazPolitGitHubArtifactError(
            "workflow run repository does not match QazPolit artifact"
        )


def _select_artifact(
    artifacts: list[dict[str, Any]], request: QazPolitActionsArtifactRequest
) -> dict[str, Any]:
    matches = [
        artifact
        for artifact in artifacts
        if isinstance(artifact, dict)
        and _require_positive_int(artifact, "id", "workflow artifact") == request.artifact_id
    ]
    if len(matches) != 1:
        raise QazPolitGitHubArtifactError("QazPolit Actions artifact is missing or ambiguous")
    artifact = matches[0]
    if _require_string(artifact, "name", "workflow artifact") != request.artifact_name:
        raise QazPolitGitHubArtifactError("QazPolit Actions artifact name does not match its run")
    if artifact.get("expired") is not False:
        raise QazPolitGitHubArtifactError("QazPolit Actions artifact is expired or malformed")
    if (
        _require_positive_int(artifact, "size_in_bytes", "workflow artifact")
        != request.artifact_size_bytes
    ):
        raise QazPolitGitHubArtifactError("QazPolit Actions artifact size does not match request")
    workflow_run = artifact.get("workflow_run")
    if not isinstance(workflow_run, dict):
        raise QazPolitGitHubArtifactError("QazPolit Actions artifact workflow run is malformed")
    if _require_positive_int(workflow_run, "id", "artifact workflow run") != request.run_id:
        raise QazPolitGitHubArtifactError(
            "QazPolit Actions artifact belongs to another workflow run"
        )
    if _require_string(workflow_run, "head_sha", "artifact workflow run") != request.source_sha:
        raise QazPolitGitHubArtifactError("QazPolit Actions artifact source SHA does not match")
    return artifact


def _require_positive_int(value: dict[str, Any], key: str, context: str) -> int:
    item = value.get(key)
    if isinstance(item, bool) or not isinstance(item, int) or item < 1:
        raise QazPolitGitHubArtifactError(f"{context} metadata is malformed")
    return item


def _require_string(value: dict[str, Any], key: str, context: str) -> str:
    item = value.get(key)
    if not isinstance(item, str) or not item:
        raise QazPolitGitHubArtifactError(f"{context} metadata is malformed")
    return item
