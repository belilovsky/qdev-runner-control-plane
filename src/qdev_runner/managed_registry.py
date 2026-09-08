"""Validated, non-secret registry for controller-managed release consumers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .claim_scope import PORTFOLIO_PROFILES

SCHEMA = "qdev-managed-registry-v4"
_ENTRY_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_ARTIFACT_REPOSITORY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{1,191}$")
_HOST_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{1,191}$")
_SOURCE_SCOPE = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_SOURCE_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,255}$")
_PENDING_ENROLMENT = "pending_external_enrolment"


class ManagedRegistryError(ValueError):
    """Raised when a controller-managed registry is absent or unsafe."""


@dataclass(frozen=True)
class ManagedRegistryEntry:
    entry_id: str
    project_id: str
    kind: str
    repository: str
    canonical_ref: str
    allowed_profiles: frozenset[str]
    native_release_profile: str
    runtime_endpoints: tuple[str, ...]
    rollback_reference: str | None
    artifact_repository: str
    host_identity: str | None
    owner: str
    admission_ledger: str
    source_scope: str | None = None
    source_paths: tuple[str, ...] = ()
    activation_state: str = "active"
    activation_prerequisites: tuple[str, ...] = ()

    @property
    def is_scoped(self) -> bool:
        """Whether this record applies only to an explicit release source scope."""
        return self.source_scope is not None


class ManagedRegistry:
    def __init__(self, path: Path) -> None:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ManagedRegistryError("managed registry is unavailable") from exc
        if not isinstance(document, dict) or set(document) != {"schema_version", "entries"}:
            raise ManagedRegistryError("managed registry shape is invalid")
        if document["schema_version"] != SCHEMA:
            raise ManagedRegistryError("managed registry schema is invalid")
        raw_entries = document["entries"]
        if not isinstance(raw_entries, dict) or not raw_entries:
            raise ManagedRegistryError("managed registry has no entries")

        entries: dict[str, ManagedRegistryEntry] = {}
        unscoped_repositories: set[str] = set()
        scoped_repositories: set[tuple[str, str]] = set()
        legacy_expected = {
            "project_id",
            "kind",
            "repository",
            "canonical_ref",
            "allowed_profiles",
            "native_release_profile",
            "runtime_endpoints",
            "rollback_reference",
            "artifact_repository",
            "host_identity",
            "owner",
            "admission_ledger",
        }
        scoped_expected = {
            "project_id",
            "kind",
            "repository",
            "canonical_ref",
            "allowed_profiles",
            "native_release_profile",
            "runtime_endpoints",
            "artifact_repository",
            "owner",
            "admission_ledger",
            "source_scope",
            "source_paths",
            "activation",
        }
        for entry_id, raw in raw_entries.items():
            if not isinstance(entry_id, str) or not _ENTRY_ID.fullmatch(entry_id):
                raise ManagedRegistryError("managed registry entry id is invalid")
            if not isinstance(raw, dict):
                raise ManagedRegistryError("managed registry fields are invalid")

            is_scoped = set(raw) == scoped_expected
            if set(raw) != legacy_expected and not is_scoped:
                raise ManagedRegistryError("managed registry fields are invalid")

            required = (scoped_expected if is_scoped else legacy_expected) - {
                "allowed_profiles",
                "runtime_endpoints",
                "source_paths",
                "activation",
            }
            if not all(isinstance(raw[key], str) and raw[key].strip() for key in required):
                raise ManagedRegistryError("managed registry strings must be non-empty")
            kind = str(raw["kind"])
            repository = str(raw["repository"])
            artifact_repository = str(raw["artifact_repository"])
            if (
                kind not in {"package", "service"}
                or not _REPOSITORY.fullmatch(repository)
                or not _ARTIFACT_REPOSITORY.fullmatch(artifact_repository)
            ):
                raise ManagedRegistryError("managed registry identity is invalid")

            profiles = raw["allowed_profiles"]
            if (
                not isinstance(profiles, list)
                or not profiles
                or any(
                    not isinstance(item, str) or item not in PORTFOLIO_PROFILES for item in profiles
                )
            ):
                raise ManagedRegistryError("managed registry profiles are invalid")
            endpoints = raw["runtime_endpoints"]
            if (
                not isinstance(endpoints, list)
                or not endpoints
                or any(
                    not isinstance(item, str) or not item.startswith("https://")
                    for item in endpoints
                )
            ):
                raise ManagedRegistryError("managed registry endpoints must be HTTPS")

            if is_scoped:
                source_scope = raw["source_scope"]
                source_paths = raw["source_paths"]
                activation = raw["activation"]
                if (
                    raw["admission_ledger"] != "controller-claim"
                    or not isinstance(source_scope, str)
                    or not _SOURCE_SCOPE.fullmatch(source_scope)
                    or not isinstance(source_paths, list)
                    or not source_paths
                    or len(source_paths) != len(set(source_paths))
                    or not all(_is_source_path(item) for item in source_paths)
                    or not isinstance(activation, dict)
                    or set(activation) != {"state", "prerequisites"}
                    or activation.get("state") != _PENDING_ENROLMENT
                    or not _valid_prerequisites(activation.get("prerequisites"))
                ):
                    raise ManagedRegistryError("managed registry scoped admission is invalid")
                key = (repository, source_scope)
                if key in scoped_repositories:
                    raise ManagedRegistryError("managed registry scoped repository is duplicated")
                scoped_repositories.add(key)
                host_identity: str | None = None
                rollback_reference: str | None = None
                activation_prerequisites = tuple(activation["prerequisites"])
            else:
                host_identity = str(raw["host_identity"])
                rollback_reference = str(raw["rollback_reference"])
                if raw["admission_ledger"] not in {
                    "admin-platform",
                    "managed-production",
                } or not _HOST_IDENTITY.fullmatch(host_identity):
                    raise ManagedRegistryError("managed registry admission ledger is invalid")
                if repository in unscoped_repositories:
                    raise ManagedRegistryError("managed registry repository is duplicated")
                unscoped_repositories.add(repository)
                source_scope = None
                source_paths = []
                activation_prerequisites = ()

            entries[entry_id] = ManagedRegistryEntry(
                entry_id=entry_id,
                project_id=str(raw["project_id"]),
                kind=kind,
                repository=repository,
                canonical_ref=str(raw["canonical_ref"]),
                allowed_profiles=frozenset(profiles),
                native_release_profile=str(raw["native_release_profile"]),
                runtime_endpoints=tuple(endpoints),
                rollback_reference=rollback_reference,
                artifact_repository=artifact_repository,
                host_identity=host_identity,
                owner=str(raw["owner"]),
                admission_ledger=str(raw["admission_ledger"]),
                source_scope=source_scope,
                source_paths=tuple(source_paths),
                activation_state=_PENDING_ENROLMENT if is_scoped else "active",
                activation_prerequisites=activation_prerequisites,
            )
        self.entries = tuple(entries.values())
        self._by_entry_id = entries
        self._by_repository = {
            entry.repository: entry for entry in self.entries if not entry.is_scoped
        }
        self._by_repository_scope = {
            (entry.repository, entry.source_scope): entry
            for entry in self.entries
            if entry.source_scope is not None
        }

    def entry_for_id(self, entry_id: str) -> ManagedRegistryEntry | None:
        """Return one registry record by its stable controller identity."""
        return self._by_entry_id.get(entry_id)

    def snapshot(self) -> dict[str, object]:
        """Return the explicit non-secret registry projection used by signed audits."""
        return {
            "schema": SCHEMA,
            "entries": [
                {
                    "entry_id": entry.entry_id,
                    "project_id": entry.project_id,
                    "kind": entry.kind,
                    "repository": entry.repository,
                    "canonical_ref": entry.canonical_ref,
                    "allowed_profiles": sorted(entry.allowed_profiles),
                    "native_release_profile": entry.native_release_profile,
                    "runtime_endpoints": list(entry.runtime_endpoints),
                    "rollback_reference": entry.rollback_reference,
                    "artifact_repository": entry.artifact_repository,
                    "host_identity": entry.host_identity,
                    "owner": entry.owner,
                    "admission_ledger": entry.admission_ledger,
                    "source_scope": entry.source_scope,
                    "source_paths": list(entry.source_paths),
                    "activation": {
                        "state": entry.activation_state,
                        "prerequisites": list(entry.activation_prerequisites),
                    },
                }
                for entry in self.entries
            ],
        }

    def entry_for_repository(self, repository: str) -> ManagedRegistryEntry | None:
        """Return only a repository-wide record.

        Scoped release records deliberately do not change ordinary CI admission
        for a shared repository.
        """
        return self._by_repository.get(repository)

    def entry_for_repository_scope(
        self, repository: str, source_scope: str
    ) -> ManagedRegistryEntry | None:
        """Return one source-scoped record when both boundaries match exactly."""
        return self._by_repository_scope.get((repository, source_scope))

    def validate_claim_if_managed(
        self, repository: str, profile: str
    ) -> ManagedRegistryEntry | None:
        """Apply repository-wide profile restrictions to ordinary CI only.

        Source-scoped records must use :meth:`validate_release_scope`; allowing
        them through this generic claim path would blur the boundary between
        public IPOS CI and the reports-private release profile.
        """
        entry = self.entry_for_repository(repository)
        if entry is not None and profile not in entry.allowed_profiles:
            raise ManagedRegistryError("runner profile is not allowed for managed repository")
        return entry

    def validate_release_scope(
        self,
        *,
        entry_id: str,
        repository: str,
        profile: str,
        source_scope: str,
        source_paths: tuple[str, ...],
    ) -> ManagedRegistryEntry:
        """Bind a controller release candidate to one pending scoped contract."""
        entry = self.entry_for_id(entry_id)
        if (
            entry is None
            or not entry.is_scoped
            or entry.admission_ledger != "controller-claim"
            or entry.repository != repository
            or entry.source_scope != source_scope
            or entry.source_paths != source_paths
        ):
            raise ManagedRegistryError("managed release scope is not allowlisted")
        if profile not in entry.allowed_profiles:
            raise ManagedRegistryError("runner profile is not allowed for managed release scope")
        return entry


def _is_source_path(value: object) -> bool:
    if not isinstance(value, str) or _SOURCE_PATH.fullmatch(value) is None:
        return False
    return not value.startswith("/") and all(
        part not in {"", ".", ".."} for part in value.split("/")
    )


def _valid_prerequisites(value: object) -> bool:
    return (
        isinstance(value, list)
        and bool(value)
        and len(value) == len(set(value))
        and all(isinstance(item, str) and _ENTRY_ID.fullmatch(item) for item in value)
    )
