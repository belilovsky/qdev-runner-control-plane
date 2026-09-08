from __future__ import annotations

import json
import math
from pathlib import Path
from typing import Any

import yaml

from .models import Profile, RepositoryPolicy, TestWorkflowRegistration


class PolicyError(RuntimeError):
    pass


_SUPPORTED_TEST_REPORT_FORMATS = frozenset({"qdev-test-run", "json", "junit", "lcov", "cobertura"})


def _normalise_workflow_path(value: Any) -> str:
    path = str(value or "").replace("\\", "/").strip()
    return path[2:] if path.startswith("./") else path


class Policy:
    def __init__(self, inventory_path: Path, profiles_path: Path) -> None:
        inventory = json.loads(inventory_path.read_text(encoding="utf-8"))
        profiles_data = yaml.safe_load(profiles_path.read_text(encoding="utf-8"))
        self.repositories: dict[str, RepositoryPolicy] = {}
        repository_ids: set[int] = set()
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
            repository_key = policy.full_name.casefold()
            if repository_key in self.repositories:
                raise PolicyError(f"duplicate repository name in inventory: {policy.full_name}")
            if policy.repository_id in repository_ids:
                raise PolicyError(f"duplicate repository id in inventory: {policy.repository_id}")
            self.repositories[repository_key] = policy
            repository_ids.add(policy.repository_id)
            if not policy.archived:
                self._catalog.append(self._catalog_entry(item, policy))

        self.profiles: dict[str, Profile] = {}
        for name, data in profiles_data["profiles"].items():
            raw_required_formats = data.get("required_test_report_formats", ())
            if raw_required_formats is None:
                raw_required_formats = ()
            if not isinstance(raw_required_formats, (list, tuple)):
                raise PolicyError(f"required_test_report_formats must be a list for profile {name}")
            required_formats: list[str] = []
            for raw_format in raw_required_formats:
                if not isinstance(raw_format, str) or not raw_format.strip():
                    raise PolicyError(
                        "required_test_report_formats contains an invalid format "
                        f"for profile {name}"
                    )
                report_format = raw_format.strip().lower()
                if report_format not in _SUPPORTED_TEST_REPORT_FORMATS:
                    raise PolicyError(
                        "required_test_report_formats contains an unsupported format for "
                        f"profile {name}: {report_format}"
                    )
                required_formats.append(report_format)
            if len(required_formats) != len(set(required_formats)):
                raise PolicyError(
                    f"required_test_report_formats contains a duplicate for profile {name}"
                )
            self.profiles[name] = Profile(
                name=name,
                labels=tuple(data["labels"]),
                cpu=float(data["resources"]["cpu"]),
                memory_mb=int(data["resources"]["memory_mb"]),
                disk_mb=int(data["resources"]["disk_mb"]),
                pids_limit=int(data["resources"]["pids_limit"]),
                timeout_minutes=int(data["timeout_minutes"]),
                allow_public_pr=bool(data.get("allow_public_pr", False)),
                required_test_report_formats=tuple(sorted(required_formats)),
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
                selected_profile: Profile | None = self.profiles.get(profile_key)
                if selected_profile is None or profile_key not in repository.profiles:
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
                minimum_disk_mb = min(selected_profile.disk_mb, 4 * 1024)
                if not minimum_disk_mb <= raw_disk_mb < selected_profile.disk_mb:
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

    @staticmethod
    def _catalog_entry(item: dict[str, Any], policy: RepositoryPolicy) -> dict[str, Any]:
        quality_value = item.get("quality")
        quality: dict[str, Any] = quality_value if isinstance(quality_value, dict) else {}
        raw_suites = quality.get("suites", item.get("suites", ()))
        if isinstance(raw_suites, dict):
            raw_suites = [raw_suites]
        suites: list[str] = []
        if isinstance(raw_suites, (list, tuple)):
            for raw_suite in raw_suites:
                if isinstance(raw_suite, str):
                    suite_id, suite_required = raw_suite.strip(), True
                elif isinstance(raw_suite, dict):
                    suite_id = str(raw_suite.get("id") or raw_suite.get("name") or "").strip()
                    suite_required = bool(raw_suite.get("required", True))
                else:
                    suite_id, suite_required = "", False
                if suite_id and suite_required:
                    suites.append(suite_id)
        registered_suites = [
            suite
            for registration in policy.test_workflows
            if registration.required
            for suite in registration.suites
        ]
        required_suites = suites or sorted(set(registered_suites))
        commands_value = quality.get("commands")
        commands: dict[str, Any] = commands_value if isinstance(commands_value, dict) else {}
        legacy_command = commands.get("test")
        configured = bool(required_suites or legacy_command or policy.test_workflows)
        if not required_suites and legacy_command:
            required_suites = ["legacy"]
        suite_critical: list[str] = []
        required_suite_ids = set(required_suites)
        if isinstance(raw_suites, (list, tuple)):
            for raw_suite in raw_suites:
                if not isinstance(raw_suite, dict):
                    continue
                suite_id = str(raw_suite.get("id") or raw_suite.get("name") or "").strip()
                if (
                    not suite_id
                    or suite_id not in required_suite_ids
                    or raw_suite.get("required", True) is False
                ):
                    continue
                values = raw_suite.get(
                    "critical_scenarios", raw_suite.get("critical_scenarios_required", ())
                )
                if isinstance(values, dict):
                    values = list(values)
                if isinstance(values, str):
                    values = [values]
                if isinstance(values, (list, tuple)):
                    suite_critical.extend(
                        str(value).strip() for value in values if str(value).strip()
                    )
        coverage_value = quality.get("coverage")
        coverage: dict[str, Any] = coverage_value if isinstance(coverage_value, dict) else {}
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
        critical_values.extend(suite_critical)
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
        return [dict(entry) for entry in self._catalog]

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

    def test_workflow(
        self,
        full_name: str,
        workflow: str,
        *,
        suite: str | None = None,
        profile: str | None = None,
        ref: str | None = None,
    ) -> TestWorkflowRegistration | None:
        repo = self.repository(full_name)
        normalized_workflow = _normalise_workflow_path(workflow)
        if repo.workflow_registration_present:
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
