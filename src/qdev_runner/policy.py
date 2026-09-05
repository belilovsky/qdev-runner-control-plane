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

        self.repository_profile_disk_mb: dict[tuple[str, str], int] = {}
        self.worker_enrollments: dict[str, dict[str, Any]] = {}
        workers = profiles_data.get("worker_enrollments", {})
        if not isinstance(workers, dict):
            raise PolicyError("worker_enrollments must be a mapping")
        for name, enrollment in workers.items():
            if (
                not isinstance(name, str) or not name
                or not isinstance(enrollment, dict)
                or enrollment.get("tier") not in ("primary", "reserve")
                or not name.endswith("-" + enrollment["tier"])
                or not isinstance(enrollment.get("profiles"), list)
                or not enrollment["profiles"]
                or any(not isinstance(profile, str) or profile not in self.profiles
                       for profile in enrollment["profiles"])
                or len(set(enrollment["profiles"])) != len(enrollment["profiles"])
            ):
                raise PolicyError("worker enrollment identity/profile is invalid")
            self.worker_enrollments[name] = enrollment
        raw_overrides = profiles_data.get("repository_admission_disk_mb", {})
        if not isinstance(raw_overrides, dict):
            raise PolicyError("repository_admission_disk_mb must be a mapping")
        for full_name, profile_overrides in raw_overrides.items():
            repository_name = str(full_name).lower()
            repository = self.repositories.get(repository_name)
            if repository is None or repository.archived:
                raise PolicyError(
                    "repository admission override is not in the active allowlist: "
                    f"{full_name}"
                )
            if not isinstance(profile_overrides, dict):
                raise PolicyError(
                    f"repository admission overrides must be a mapping: {full_name}"
                )
            for profile_name, raw_disk_mb in profile_overrides.items():
                profile_key = str(profile_name)
                profile = self.profiles.get(profile_key)
                if profile is None or profile_key not in repository.profiles:
                    raise PolicyError(
                        "repository admission override selects a disallowed profile: "
                        f"{full_name}/{profile_name}"
                    )
                if isinstance(raw_disk_mb, bool) or not isinstance(raw_disk_mb, int):
                    raise PolicyError(
                        "repository admission override must be an integer MiB value: "
                        f"{full_name}/{profile_name}"
                    )
                # A repository override is combined with the worker's hard
                # free-space floor, so the reservation may follow a measured
                # small workload without weakening the independent floor.
                minimum_disk_mb = min(profile.disk_mb, 4 * 1024)
                if not minimum_disk_mb <= raw_disk_mb < profile.disk_mb:
                    raise PolicyError(
                        "repository admission override must be below the profile default "
                        f"and at least {minimum_disk_mb} MiB: {full_name}/{profile_name}"
                    )
                self.repository_profile_disk_mb[(repository_name, profile_key.lower())] = (
                    raw_disk_mb
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
