from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any

import yaml

from .models import Profile, RepositoryPolicy


class PolicyError(RuntimeError):
    pass


PROJECT_PRIORITY_POLICY_SCHEMA = "qdev-runner-project-priority-v1"


@dataclass(frozen=True)
class ProjectPriorityPolicy:
    """A release-bound, auditable project ordering overlay.

    GitHub's signed queue timestamp and the controller sequence remain the
    immutable ordering keys.  This policy only selects an explicit project
    tier before that FIFO order; it must be delivered as part of a controller
    release, never through an operational database edit.
    """

    policy_id: str
    default_priority: int
    priorities: dict[str, int]
    definition_json: str
    sha256: str

    @classmethod
    def from_file(cls, path: Path) -> ProjectPriorityPolicy:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise PolicyError(f"cannot load project-priority policy {path}: {error}") from error
        return cls.from_data(data)

    @classmethod
    def from_data(cls, data: object) -> ProjectPriorityPolicy:
        if not isinstance(data, dict):
            raise PolicyError("project-priority policy must be a JSON object")
        if data.get("schema") != PROJECT_PRIORITY_POLICY_SCHEMA:
            raise PolicyError("unsupported project-priority policy schema")
        policy_id = data.get("policy_id")
        default_priority = data.get("default_priority")
        raw_priorities = data.get("priorities")
        if not isinstance(policy_id, str) or not policy_id.strip():
            raise PolicyError("project-priority policy_id is required")
        if (
            not isinstance(default_priority, int)
            or isinstance(default_priority, bool)
            or default_priority < 0
        ):
            raise PolicyError("project-priority default_priority must be a non-negative integer")
        if not isinstance(raw_priorities, dict):
            raise PolicyError("project-priority priorities must be an object")

        priorities: dict[str, int] = {}
        for repository, priority in raw_priorities.items():
            if not isinstance(repository, str) or "/" not in repository:
                raise PolicyError("project-priority repository must be an owner/name string")
            if (
                not isinstance(priority, int)
                or isinstance(priority, bool)
                or priority < 0
            ):
                raise PolicyError("project-priority values must be non-negative integers")
            normalized = repository.lower()
            if normalized in priorities:
                raise PolicyError(f"duplicate project-priority repository: {repository}")
            priorities[normalized] = priority

        canonical = {
            "schema": PROJECT_PRIORITY_POLICY_SCHEMA,
            "policy_id": policy_id.strip(),
            "default_priority": default_priority,
            "priorities": priorities,
        }
        definition_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return cls(
            policy_id=policy_id.strip(),
            default_priority=default_priority,
            priorities=priorities,
            definition_json=definition_json,
            sha256=sha256(definition_json.encode("utf-8")).hexdigest(),
        )

    def priority_for(self, repository: str) -> int:
        return self.priorities.get(repository.lower(), self.default_priority)


class Policy:
    def __init__(self, inventory_path: Path, profiles_path: Path) -> None:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        profiles_data = yaml.safe_load(profiles_path.read_text(encoding="utf-8"))
        self.repositories: dict[str, RepositoryPolicy] = {}
        for item in inventory["repositories"]:
            policy = RepositoryPolicy(
                full_name=item["full_name"],
                repository_id=int(item["id"]),
                private=bool(item["private"]),
                archived=bool(item["archived"]),
                default_branch=item["default_branch"],
                profiles=tuple(item.get("profiles", ["qdev-ci"])),
            )
            self.repositories[policy.full_name.lower()] = policy

        self.profiles: dict[str, Profile] = {}
        for name, data in profiles_data["profiles"].items():
            self.profiles[name] = Profile(
                name=name,
                labels=tuple(data["labels"]),
                cpu=float(data["resources"]["cpu"]),
                memory_mb=int(data["resources"]["memory_mb"]),
                disk_mb=int(data["resources"]["disk_mb"]),
                pids_limit=int(data["resources"]["pids_limit"]),
                timeout_minutes=int(data["timeout_minutes"]),
                allow_public_pr=bool(data.get("allow_public_pr", False)),
            )

    def repository(self, full_name: str) -> RepositoryPolicy:
        repo = self.repositories.get(full_name.lower())
        if repo is None or repo.archived:
            raise PolicyError(f"repository is not in the active runner allowlist: {full_name}")
        return repo

    def profile_for_labels(self, full_name: str, labels: list[str] | tuple[str, ...]) -> Profile:
        repo = self.repository(full_name)
        normalized = {label.lower() for label in labels}
        matches = [
            profile
            for profile in self.profiles.values()
            if profile.name.lower() in normalized and profile.name in repo.profiles
        ]
        if len(matches) != 1:
            raise PolicyError(
                "job must select exactly one allowed qdev profile; "
                f"repo={full_name} labels={labels}"
            )
        required = {label.lower() for label in matches[0].labels}
        if not required.issubset(normalized):
            raise PolicyError(f"runner labels do not satisfy profile {matches[0].name}")
        return matches[0]

    def authorize_run(self, full_name: str, profile: Profile, run: dict[str, Any]) -> None:
        repo = self.repository(full_name)
        event = str(run.get("event", ""))
        if event != "pull_request" or repo.private:
            return
        pull_requests = run.get("pull_requests") or []
        head_repo_id = None
        if pull_requests:
            head_repo_id = ((pull_requests[0].get("head") or {}).get("repo") or {}).get("id")
        if not profile.allow_public_pr or int(head_repo_id or 0) != repo.repository_id:
            raise PolicyError(
                "public fork pull requests are not authorized for self-hosted execution"
            )
