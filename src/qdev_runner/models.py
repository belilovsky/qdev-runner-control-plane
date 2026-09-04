from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Profile:
    name: str
    labels: tuple[str, ...]
    cpu: float
    memory_mb: int
    disk_mb: int
    pids_limit: int
    timeout_minutes: int
    allow_public_pr: bool


@dataclass(frozen=True)
class TestWorkflowRegistration:
    """A server-owned allowlist entry for a test-only GitHub workflow."""

    path: str
    suites: tuple[str, ...] = ()
    profile: str | None = None
    refs: tuple[str, ...] = ()
    required: bool = True


@dataclass(frozen=True)
class RepositoryPolicy:
    full_name: str
    repository_id: int
    private: bool
    archived: bool
    default_branch: str
    profiles: tuple[str, ...]
    # Workflow paths are optional for backwards-compatible inventories.  An
    # empty tuple keeps the legacy marker-based admission until the inventory
    # has been regenerated with explicit registrations.
    workflows: tuple[str, ...] = ()
    # ``test_workflows`` is deliberately separate from the discovered list of
    # workflow files.  A repository may contain deploy, release, or reusable
    # workflows which must never become an operator-dispatch target merely
    # because they are present in GitHub.
    test_workflows: tuple[TestWorkflowRegistration, ...] = ()
    # The distinction matters: an explicit empty list means "no test workflow
    # is allowed", while a missing key preserves the old inventory contract
    # during the migration window.
    workflow_registration_present: bool = False


@dataclass(frozen=True)
class QueuedJob:
    delivery_id: str
    job_id: int
    run_id: int
    repository: str
    repository_id: int
    installation_id: int
    labels: tuple[str, ...]
    head_sha: str
    head_branch: str
    payload: dict[str, Any]
