"""Validated, non-secret registry for controller-managed release consumers."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from .claim_scope import PORTFOLIO_PROFILES

SCHEMA = "qdev-managed-registry-v2"
_ENTRY_ID = re.compile(r"^[a-z][a-z0-9-]{1,63}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")


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
    rollback_reference: str
    owner: str


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
        repositories: set[str] = set()
        expected = {
            "project_id",
            "kind",
            "repository",
            "canonical_ref",
            "allowed_profiles",
            "native_release_profile",
            "runtime_endpoints",
            "rollback_reference",
            "owner",
        }
        for entry_id, raw in raw_entries.items():
            if not isinstance(entry_id, str) or not _ENTRY_ID.fullmatch(entry_id):
                raise ManagedRegistryError("managed registry entry id is invalid")
            if not isinstance(raw, dict) or set(raw) != expected:
                raise ManagedRegistryError("managed registry fields are invalid")
            required = expected - {"allowed_profiles", "runtime_endpoints"}
            if not all(isinstance(raw[key], str) and raw[key].strip() for key in required):
                raise ManagedRegistryError("managed registry strings must be non-empty")
            kind = str(raw["kind"])
            repository = str(raw["repository"])
            if kind not in {"package", "service"} or not _REPOSITORY.fullmatch(repository):
                raise ManagedRegistryError("managed registry identity is invalid")
            if repository in repositories:
                raise ManagedRegistryError("managed registry repository is duplicated")
            profiles = raw["allowed_profiles"]
            if (
                not isinstance(profiles, list)
                or not profiles
                or any(
                    not isinstance(item, str) or item not in PORTFOLIO_PROFILES
                    for item in profiles
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
            entries[entry_id] = ManagedRegistryEntry(
                entry_id=entry_id,
                project_id=str(raw["project_id"]),
                kind=kind,
                repository=repository, canonical_ref=str(raw["canonical_ref"]),
                allowed_profiles=frozenset(profiles),
                native_release_profile=str(raw["native_release_profile"]),
                runtime_endpoints=tuple(endpoints),
                rollback_reference=str(raw["rollback_reference"]),
                owner=str(raw["owner"]),
            )
            repositories.add(repository)
        self._by_repository = {entry.repository: entry for entry in entries.values()}

    def entry_for_repository(self, repository: str) -> ManagedRegistryEntry | None:
        return self._by_repository.get(repository)

    def validate_claim_if_managed(
        self, repository: str, profile: str
    ) -> ManagedRegistryEntry | None:
        """Apply registry profile restrictions without disrupting non-managed v2 scopes."""
        entry = self.entry_for_repository(repository)
        if entry is not None and profile not in entry.allowed_profiles:
            raise ManagedRegistryError("runner profile is not allowed for managed repository")
        return entry
