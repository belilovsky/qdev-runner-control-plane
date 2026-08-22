from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .models import Profile, RepositoryPolicy


class PolicyError(RuntimeError):
    pass


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
