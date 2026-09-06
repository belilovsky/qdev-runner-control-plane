from __future__ import annotations

import json
import math
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
        repository_ids: set[int] = set()
        for item in inventory["repositories"]:
            policy = RepositoryPolicy(
                full_name=item["full_name"],
                repository_id=int(item["id"]),
                private=bool(item["private"]),
                archived=bool(item["archived"]),
                default_branch=item["default_branch"],
                profiles=tuple(item.get("profiles", ["qdev-ci"])),
            )
            repository_key = policy.full_name.casefold()
            if repository_key in self.repositories:
                raise PolicyError(f"duplicate repository name in inventory: {policy.full_name}")
            if policy.repository_id in repository_ids:
                raise PolicyError(f"duplicate repository id in inventory: {policy.repository_id}")
            self.repositories[repository_key] = policy
            repository_ids.add(policy.repository_id)

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
        raw_overrides = profiles_data.get("repository_admission_disk_mb", {})
        if not isinstance(raw_overrides, dict):
            raise PolicyError("repository_admission_disk_mb must be a mapping")
        for full_name, profile_overrides in raw_overrides.items():
            repository_name = str(full_name).lower()
            repository = self.repositories.get(repository_name)
            if repository is None or repository.archived:
                raise PolicyError(
                    f"repository admission override is not in the active allowlist: {full_name}"
                )
            if not isinstance(profile_overrides, dict):
                raise PolicyError(f"repository admission overrides must be a mapping: {full_name}")
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

        self.repository_min_disk_free_gib: dict[str, float] = {}
        self.repository_max_concurrency: dict[str, int] = {}
        raw_constraints = profiles_data.get("repository_admission_constraints", {})
        if not isinstance(raw_constraints, dict):
            raise PolicyError("repository_admission_constraints must be a mapping")
        allowed_constraint_keys = {"min_disk_free_gib", "max_concurrency"}
        for full_name, raw_repository_constraints in raw_constraints.items():
            repository_name = str(full_name).casefold()
            repository = self.repositories.get(repository_name)
            if repository is None or repository.archived:
                raise PolicyError(
                    f"repository admission constraint is not in the active allowlist: {full_name}"
                )
            if not isinstance(raw_repository_constraints, dict):
                raise PolicyError(
                    f"repository admission constraints must be a mapping: {full_name}"
                )
            unknown_keys = set(raw_repository_constraints) - allowed_constraint_keys
            if unknown_keys:
                raise PolicyError(
                    "repository admission constraint has unknown fields: "
                    f"{full_name}/{','.join(sorted(str(item) for item in unknown_keys))}"
                )
            if not raw_repository_constraints:
                raise PolicyError(f"repository admission constraints cannot be empty: {full_name}")

            if "min_disk_free_gib" in raw_repository_constraints:
                raw_minimum = raw_repository_constraints["min_disk_free_gib"]
                if (
                    isinstance(raw_minimum, bool)
                    or not isinstance(raw_minimum, (int, float))
                    or not math.isfinite(float(raw_minimum))
                    or float(raw_minimum) <= 0
                ):
                    raise PolicyError(
                        "repository minimum free disk must be a positive finite GiB value: "
                        f"{full_name}"
                    )
                self.repository_min_disk_free_gib[repository_name] = float(raw_minimum)

            if "max_concurrency" in raw_repository_constraints:
                raw_concurrency = raw_repository_constraints["max_concurrency"]
                if (
                    isinstance(raw_concurrency, bool)
                    or not isinstance(raw_concurrency, int)
                    or raw_concurrency < 1
                ):
                    raise PolicyError(
                        f"repository maximum concurrency must be a positive integer: {full_name}"
                    )
                self.repository_max_concurrency[repository_name] = raw_concurrency

    def repository(self, full_name: str, repository_id: int | None = None) -> RepositoryPolicy:
        repo = self.repositories.get(full_name.casefold())
        if repo is None or repo.archived:
            raise PolicyError(f"repository is not in the active runner allowlist: {full_name}")
        if repository_id is not None and repo.repository_id != repository_id:
            raise PolicyError(f"repository id does not match the active allowlist: {full_name}")
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

    def authorize_worker_resources(
        self,
        full_name: str,
        *,
        disk_free_gib: object,
        concurrency: object,
    ) -> None:
        """Enforce server-owned per-repository capacity constraints."""

        repository_name = self.repository(full_name).full_name.casefold()
        minimum_free_gib = self.repository_min_disk_free_gib.get(repository_name)
        if minimum_free_gib is not None and (
            isinstance(disk_free_gib, bool)
            or not isinstance(disk_free_gib, (int, float))
            or not math.isfinite(float(disk_free_gib))
            or float(disk_free_gib) < minimum_free_gib
        ):
            raise PolicyError(
                "repository admission requires at least "
                f"{minimum_free_gib:g} GiB free disk: {repository_name}"
            )

        maximum_concurrency = self.repository_max_concurrency.get(repository_name)
        if maximum_concurrency is not None and (
            isinstance(concurrency, bool)
            or not isinstance(concurrency, int)
            or concurrency < 1
            or concurrency > maximum_concurrency
        ):
            raise PolicyError(
                "repository admission requires worker concurrency at most "
                f"{maximum_concurrency}: {repository_name}"
            )

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
