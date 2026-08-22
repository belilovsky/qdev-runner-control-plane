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
class RepositoryPolicy:
    full_name: str
    repository_id: int
    private: bool
    archived: bool
    default_branch: str
    profiles: tuple[str, ...]


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
