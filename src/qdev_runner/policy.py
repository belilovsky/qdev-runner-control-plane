from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

from .models import Profile, RepositoryPolicy, TestWorkflowRegistration


class PolicyError(RuntimeError):
    pass


def _normalise_workflow_path(value: Any) -> str:
    path = str(value or "").replace("\\", "/").strip()
    return path[2:] if path.startswith("./") else path


class Policy:
    def __init__(self, inventory_path: Path, profiles_path: Path) -> None:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        profiles_data = yaml.safe_load(profiles_path.read_text(encoding="utf-8"))
        self.repositories: dict[str, RepositoryPolicy] = {}
        self._catalog: list[dict[str, Any]] = []
        for item in inventory["repositories"]:
            workflow_paths: list[str] = []
            for workflow in item.get("workflow_files", []):
                path = (
                    workflow
                    if isinstance(workflow, str)
                    else workflow.get("path")
                    if isinstance(workflow, dict)
                    else None
                )
                if isinstance(path, str) and path.strip():
                    workflow_paths.append(_normalise_workflow_path(path))
            registrations: list[TestWorkflowRegistration] = []
            registration_present = "test_workflows" in item
            raw_registrations = item.get("test_workflows", [])
            if raw_registrations is None:
                raw_registrations = []
            if not isinstance(raw_registrations, list):
                raise PolicyError(f"test_workflows must be a list for {item.get('full_name')}")
            for raw in raw_registrations:
                if isinstance(raw, str):
                    raw = {"path": raw}
                if not isinstance(raw, dict):
                    raise PolicyError(
                        f"test_workflows entries must be objects for {item.get('full_name')}"
                    )
                path = _normalise_workflow_path(raw.get("path"))
                if not path:
                    raise PolicyError(
                        f"test_workflows entry is missing path for {item.get('full_name')}"
                    )
                suites_raw = raw.get("suites", ())
                if isinstance(suites_raw, str):
                    suites_raw = [suites_raw]
                if not isinstance(suites_raw, (list, tuple)):
                    raise PolicyError(f"test_workflows.suites is invalid for {path}")
                suites = tuple(
                    sorted({str(value).strip() for value in suites_raw if str(value).strip()})
                )
                profile_raw = raw.get("profile")
                profile = str(profile_raw).strip() if profile_raw is not None else None
                refs_raw = raw.get("refs", raw.get("allowed_refs", ()))
                if isinstance(refs_raw, str):
                    refs_raw = [refs_raw]
                if not isinstance(refs_raw, (list, tuple)):
                    raise PolicyError(f"test_workflows.refs is invalid for {path}")
                refs = tuple(
                    sorted({str(value).strip() for value in refs_raw if str(value).strip()})
                )
                registrations.append(
                    TestWorkflowRegistration(
                        path=path,
                        suites=suites,
                        profile=profile,
                        refs=refs,
                        required=bool(raw.get("required", True)),
                    )
                )
            policy = RepositoryPolicy(
                full_name=item["full_name"],
                repository_id=int(item["id"]),
                private=bool(item["private"]),
                archived=bool(item["archived"]),
                default_branch=item["default_branch"],
                profiles=tuple(item.get("profiles", ["qdev-ci"])),
                workflows=tuple(sorted(set(workflow_paths))),
                test_workflows=tuple(sorted(registrations, key=lambda value: value.path)),
                workflow_registration_present=registration_present,
            )
            self.repositories[policy.full_name.lower()] = policy
            if not policy.archived:
                self._catalog.append(self._catalog_entry(item, policy))

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
                    "repository admission override is not in the active allowlist: "
                    f"{full_name}"
                )
            if not isinstance(profile_overrides, dict):
                raise PolicyError(
                    f"repository admission overrides must be a mapping: {full_name}"
                )
            for profile_name, raw_disk_mb in profile_overrides.items():
                profile_key = str(profile_name)
                admission_profile = self.profiles.get(profile_key)
                if admission_profile is None or profile_key not in repository.profiles:
                    raise PolicyError(
                        "repository admission override selects a disallowed profile: "
                        f"{full_name}/{profile_name}"
                    )
                if isinstance(raw_disk_mb, bool) or not isinstance(raw_disk_mb, int):
                    raise PolicyError(
                        "repository admission override must be an integer MiB value: "
                        f"{full_name}/{profile_name}"
                    )
                minimum_disk_mb = min(admission_profile.disk_mb, 12 * 1024)
                if not minimum_disk_mb <= raw_disk_mb < admission_profile.disk_mb:
                    raise PolicyError(
                        "repository admission override must be below the profile default "
                        f"and at least {minimum_disk_mb} MiB: {full_name}/{profile_name}"
                    )
                self.repository_profile_disk_mb[(repository_name, profile_key.lower())] = (
                    raw_disk_mb
                )

    @staticmethod
    def _catalog_entry(item: dict[str, Any], policy: RepositoryPolicy) -> dict[str, Any]:
        """Build the controller-owned quality denominator from inventory data.

        Inventory generators may add the optional quality/suites projection at
        different nesting levels during the migration.  The adapter accepts
        all of those shapes, while retaining the old ``quality.commands.test``
        contract as the single ``legacy`` suite.
        """

        quality_value = item.get("quality")
        quality: dict[str, Any] = quality_value if isinstance(quality_value, dict) else {}
        raw_suites = quality.get("suites", item.get("suites", ()))
        if isinstance(raw_suites, dict):
            raw_suites = [raw_suites]
        suites: list[str] = []
        if isinstance(raw_suites, (list, tuple)):
            for raw_suite in raw_suites:
                if isinstance(raw_suite, str):
                    suite_id = raw_suite.strip()
                elif isinstance(raw_suite, dict):
                    suite_id = str(raw_suite.get("id") or raw_suite.get("name") or "").strip()
                else:
                    suite_id = ""
                if suite_id:
                    suites.append(suite_id)
        registrations = [registration for registration in policy.test_workflows]
        registered_suites = [
            suite for registration in registrations for suite in registration.suites
        ]
        required_suites = suites or sorted(set(registered_suites))
        commands_value = quality.get("commands")
        commands: dict[str, Any] = (
            commands_value if isinstance(commands_value, dict) else {}
        )
        legacy_command = commands.get("test")
        configured = bool(required_suites or legacy_command or registrations)
        if not required_suites and legacy_command:
            required_suites = ["legacy"]
        coverage_value = quality.get("coverage")
        coverage: dict[str, Any] = (
            coverage_value if isinstance(coverage_value, dict) else {}
        )
        minimum = coverage.get(
            "minimum", quality.get("coverage_minimum", item.get("coverage_minimum"))
        )
        try:
            minimum_value = float(minimum) if minimum is not None else None
        except (TypeError, ValueError):
            minimum_value = None
        critical = quality.get(
            "critical_scenarios",
            quality.get("critical_scenarios_required", item.get("critical_scenarios_required", ())),
        )
        if isinstance(critical, dict):
            critical = list(critical)
        if isinstance(critical, str):
            critical = [critical]
        critical_values = (
            [str(value).strip() for value in critical]
            if isinstance(critical, (list, tuple))
            else []
        )
        current_sha = (
            item.get("current_sha")
            or item.get("head_sha")
            or item.get("default_sha")
            or quality.get("current_sha")
        )
        return {
            "project_id": item.get("project_id", item.get("id")),
            "repository": policy.full_name,
            "private": policy.private,
            "default_branch": policy.default_branch,
            "configured": configured,
            "required_suites": sorted(set(required_suites)),
            "current_sha": str(current_sha).lower() if current_sha else None,
            "coverage_required": bool(coverage.get("required", minimum is not None)),
            "coverage_minimum": minimum_value,
            "critical_scenarios_required": sorted(set(value for value in critical_values if value)),
        }

    def test_catalog(self) -> list[dict[str, Any]]:
        """Return a copy of the full active project denominator."""

        return [dict(entry) for entry in self._catalog]

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

    def test_workflow(
        self,
        full_name: str,
        workflow: str,
        *,
        suite: str | None = None,
        profile: str | None = None,
        ref: str | None = None,
    ) -> TestWorkflowRegistration | None:
        """Return a registered test workflow or reject an unsafe binding.

        A present ``test_workflows`` key is fail-closed, including an empty
        list.  Older inventories continue to use their discovered workflow
        paths/marker admission until regenerated.
        """

        repo = self.repository(full_name)
        if repo.workflow_registration_present:
            normalized_workflow = _normalise_workflow_path(workflow)
            entry = next(
                (item for item in repo.test_workflows if item.path == normalized_workflow),
                None,
            )
            if entry is None:
                raise PolicyError(f"test workflow is not registered for {full_name}: {workflow}")
            if suite and entry.suites and suite not in entry.suites:
                raise PolicyError(f"suite is not registered for {full_name}: {suite}")
            if profile and entry.profile and profile != entry.profile:
                raise PolicyError(f"profile is not registered for {full_name}: {profile}")
            if ref and entry.refs and ref not in entry.refs:
                raise PolicyError(f"ref is not registered for {full_name}: {ref}")
            return entry
        normalized_workflow = _normalise_workflow_path(workflow)
        if repo.workflows and normalized_workflow not in repo.workflows:
            raise PolicyError(f"test workflow is not registered for {full_name}: {workflow}")
        return None

    def authorize_test_workflow(
        self,
        full_name: str,
        workflow: str,
        *,
        suite: str | None = None,
        profile: str | None = None,
        ref: str | None = None,
    ) -> None:
        self.test_workflow(full_name, workflow, suite=suite, profile=profile, ref=ref)
