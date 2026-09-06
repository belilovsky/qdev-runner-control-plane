from __future__ import annotations

import json
import os
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# v1 remains the published compatibility contract for already-running scopes.
# v2 binds every claim to the complete immutable provider tuple so that a
# generic portfolio scope cannot be reused for another run, attempt, SHA, or
# profile.
SCHEMA_V1 = "claim-scope-v1"
SCHEMA_V2 = "claim-scope-v2"
SCHEMA = SCHEMA_V1
LEGACY_SCHEMA = "qdev-runner-claim-scopes-v1"
# A mixed document is the v2 container used while v1 scopes are still valid.
# Existing root-level v1 documents continue to load unchanged.
MIXED_SCHEMA = "qdev-runner-claim-scopes-v2"
SUPPORTED_SCHEMAS = frozenset({SCHEMA_V1, SCHEMA_V2, LEGACY_SCHEMA, MIXED_SCHEMA})
ALLOWED_REPOSITORY = "belilovsky/qazagents"
ALLOWED_PROFILES = frozenset({"qdev-ci", "qdev-ci-docker"})
PORTFOLIO_PROFILES = frozenset({"qdev-ci", "qdev-ci-docker", "qdev-ci-browser"})
MAX_TTL = timedelta(minutes=15)
_SHA256 = re.compile(r"^[0-9a-f]{40}$")
_CERT_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SCOPE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_WORKER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
_FIFO_SKIP_REASONS = frozenset(
    {
        "active-admin-platform-controller-priority",
        "admin-platform-candidate-not-active",
        "admin-platform-candidate-tuple-not-admitted",
        "managed-release-candidate-not-active",
        "managed-release-candidate-tuple-not-admitted",
    }
)


class ClaimScopeError(ValueError):
    """Raised when a temporary worker scope is missing or cannot be trusted."""


@dataclass(frozen=True)
class ScopedJob:
    job_id: int
    profile: str
    repository: str | None = None
    run_id: int | None = None
    attempt: int | None = None
    exact_sha: str | None = None


@dataclass(frozen=True)
class ScopedFifoSkip:
    job_id: int
    profile: str
    repository: str
    run_id: int
    attempt: int
    exact_sha: str
    managed_registry_entry: str | None
    reason: str


@dataclass(frozen=True)
class ClaimScope:
    scope_id: str
    worker_name: str
    tier: str
    repository: str
    head_sha: str
    expires_at: datetime
    jobs: tuple[ScopedJob, ...]
    worker_certificate_sha256: str | None = None
    schema: str = LEGACY_SCHEMA
    host: str | None = None
    runner: str | None = None
    correlation_id: str | None = None
    fifo_skipped: tuple[ScopedFifoSkip, ...] = ()

    def permits(
        self,
        job_id: int,
        repository: str,
        head_sha: str,
        profile: str,
        *,
        run_id: int | None = None,
        attempt: int | None = None,
    ) -> bool:
        if self.schema == SCHEMA_V2:
            return any(
                item.job_id == job_id
                and item.repository == repository
                and item.run_id == run_id
                and item.attempt == attempt
                and item.exact_sha == head_sha
                and item.profile == profile
                for item in self.jobs
            )
        return (
            repository == self.repository
            and head_sha == self.head_sha
            and any(item.job_id == job_id and item.profile == profile for item in self.jobs)
        )

    def certificate_matches(self, fingerprint: str | None) -> bool:
        """Match a Caddy-provided mTLS certificate fingerprint exactly."""
        normalized = (fingerprint or "").strip()
        return bool(
            self.worker_certificate_sha256
            and _CERT_SHA256.fullmatch(normalized)
            and secrets.compare_digest(self.worker_certificate_sha256, normalized)
        )

    def skips(
        self,
        job_id: int,
        repository: str,
        head_sha: str,
        profile: str,
        *,
        run_id: int | None = None,
        attempt: int | None = None,
    ) -> bool:
        """Allow FIFO bypass only for an exact controller-signed stale tuple."""
        if self.schema != SCHEMA_V2:
            return False
        return any(
            item.job_id == job_id
            and item.repository == repository
            and item.run_id == run_id
            and item.attempt == attempt
            and item.exact_sha == head_sha
            and item.profile == profile
            for item in self.fifo_skipped
        )


def _required_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ClaimScopeError(f"claim scope {field} must be a non-empty string")
    return value.strip()


def _positive_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ClaimScopeError(f"claim scope {field} must be a positive integer")
    return value


def _parse_expiry(value: object) -> datetime:
    raw = _required_string(value, "expires_at")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ClaimScopeError("claim scope expires_at must be RFC3339") from error
    if parsed.tzinfo is None:
        raise ClaimScopeError("claim scope expires_at must include a timezone")
    return parsed.astimezone(UTC)


def _parse_certificate(raw: dict[str, object]) -> str | None:
    value = raw.get("worker_certificate_sha256")
    if value is None:
        return None
    fingerprint = _required_string(value, "worker_certificate_sha256")
    if not _CERT_SHA256.fullmatch(fingerprint):
        raise ClaimScopeError("claim scope worker_certificate_sha256 must be a lowercase SHA-256")
    return fingerprint


def _parse_v2_job(raw: object) -> ScopedJob:
    if not isinstance(raw, dict):
        raise ClaimScopeError("claim scope job must be an object")
    job_id = _positive_int(raw.get("job_id"), "job_id")
    repository = _required_string(raw.get("repository"), "job repository")
    run_id = _positive_int(raw.get("run_id"), "job run_id")
    attempt = _positive_int(raw.get("attempt"), "job attempt")
    exact_sha = _required_string(raw.get("exact_sha"), "job exact_sha")
    if not _SHA256.fullmatch(exact_sha):
        raise ClaimScopeError("claim scope job exact_sha must be a lowercase Git SHA")
    profile = _required_string(raw.get("profile"), "job profile")
    if profile not in PORTFOLIO_PROFILES:
        raise ClaimScopeError("claim scope job profile is not supported")
    return ScopedJob(job_id, profile, repository, run_id, attempt, exact_sha)


def _parse_v2_fifo_skip(raw: object) -> ScopedFifoSkip:
    if not isinstance(raw, dict):
        raise ClaimScopeError("claim scope fifo skip must be an object")
    job_id = _positive_int(raw.get("job_id"), "fifo skip job_id")
    repository = _required_string(raw.get("repository"), "fifo skip repository")
    run_id = _positive_int(raw.get("run_id"), "fifo skip run_id")
    attempt = _positive_int(raw.get("attempt"), "fifo skip attempt")
    exact_sha = _required_string(raw.get("exact_sha"), "fifo skip exact_sha")
    if not _SHA256.fullmatch(exact_sha):
        raise ClaimScopeError("claim scope fifo skip exact_sha must be a lowercase Git SHA")
    profile = _required_string(raw.get("profile"), "fifo skip profile")
    if profile not in PORTFOLIO_PROFILES:
        raise ClaimScopeError("claim scope fifo skip profile is not supported")
    managed_registry_entry_raw = raw.get("managed_registry_entry")
    managed_registry_entry = (
        None
        if managed_registry_entry_raw is None
        else _required_string(managed_registry_entry_raw, "fifo skip managed_registry_entry")
    )
    if managed_registry_entry is not None and not _SCOPE_ID.fullmatch(managed_registry_entry):
        raise ClaimScopeError("claim scope fifo skip managed_registry_entry is unsafe")
    reason = _required_string(raw.get("reason"), "fifo skip reason")
    if reason not in _FIFO_SKIP_REASONS:
        raise ClaimScopeError("claim scope fifo skip reason is not supported")
    return ScopedFifoSkip(
        job_id=job_id,
        profile=profile,
        repository=repository,
        run_id=run_id,
        attempt=attempt,
        exact_sha=exact_sha,
        managed_registry_entry=managed_registry_entry,
        reason=reason,
    )


def _parse_scope(raw: object, *, schema: str) -> ClaimScope:
    if not isinstance(raw, dict):
        raise ClaimScopeError("claim scope entry must be an object")
    scope_id = _required_string(raw.get("scope_id"), "scope_id")
    if not _SCOPE_ID.fullmatch(scope_id):
        raise ClaimScopeError("claim scope scope_id contains unsafe characters")
    worker_name = _required_string(raw.get("worker_name"), "worker_name")
    tier = _required_string(raw.get("tier"), "tier")
    if tier not in {"primary", "reserve"}:
        raise ClaimScopeError("claim scope tier must be primary or reserve")
    if schema in {SCHEMA_V1, SCHEMA_V2}:
        if not _WORKER_NAME.fullmatch(worker_name):
            raise ClaimScopeError("claim scope worker_name contains unsafe characters")
        if not worker_name.endswith(f"-{tier}"):
            raise ClaimScopeError("claim scope worker_name must end with its tier")

    jobs_raw = raw.get("jobs")
    if not isinstance(jobs_raw, list) or not jobs_raw:
        raise ClaimScopeError("claim scope jobs must be a non-empty list")
    if schema == SCHEMA_V2:
        host = _required_string(raw.get("host"), "host")
        runner = _required_string(raw.get("runner"), "runner")
        correlation_id = _required_string(raw.get("correlation_id"), "correlation_id")
        v2_jobs = [_parse_v2_job(item) for item in jobs_raw]
        fifo_skipped_raw = raw.get("fifo_skipped", [])
        if not isinstance(fifo_skipped_raw, list) or len(fifo_skipped_raw) > 512:
            raise ClaimScopeError("claim scope fifo_skipped must be a bounded list")
        fifo_skipped = [_parse_v2_fifo_skip(item) for item in fifo_skipped_raw]
        if len({item.job_id for item in v2_jobs}) != len(v2_jobs):
            raise ClaimScopeError("claim scope job IDs must be unique")
        immutable_tuples = {
            (item.repository, item.run_id, item.job_id, item.attempt, item.exact_sha, item.profile)
            for item in v2_jobs
        }
        if len(immutable_tuples) != len(v2_jobs):
            raise ClaimScopeError("claim scope immutable job tuples must be unique")
        skipped_tuples = {
            (item.repository, item.run_id, item.job_id, item.attempt, item.exact_sha, item.profile)
            for item in fifo_skipped
        }
        if len(skipped_tuples) != len(fifo_skipped):
            raise ClaimScopeError("claim scope fifo skip tuples must be unique")
        if immutable_tuples & skipped_tuples:
            raise ClaimScopeError("claim scope jobs and fifo skips must not overlap")
        first = v2_jobs[0]
        assert first.repository is not None and first.exact_sha is not None
        return ClaimScope(
            scope_id=scope_id,
            worker_name=worker_name,
            tier=tier,
            repository=first.repository,
            head_sha=first.exact_sha,
            expires_at=_parse_expiry(raw.get("expires_at")),
            jobs=tuple(v2_jobs),
            worker_certificate_sha256=_parse_certificate(raw),
            schema=schema,
            host=host,
            runner=runner,
            correlation_id=correlation_id,
            fifo_skipped=tuple(fifo_skipped),
        )

    repository = _required_string(raw.get("repository"), "repository")
    head_sha = _required_string(raw.get("head_sha"), "head_sha")
    if not _SHA256.fullmatch(head_sha):
        raise ClaimScopeError("claim scope head_sha must be a lowercase Git SHA")
    if schema == SCHEMA_V1 and len(jobs_raw) != 2:
        raise ClaimScopeError("claim scope jobs must contain exactly two jobs")
    jobs: list[ScopedJob] = []
    for item in jobs_raw:
        if not isinstance(item, dict):
            raise ClaimScopeError("claim scope job must be an object")
        job_id = _positive_int(item.get("job_id"), "job_id")
        profile = _required_string(item.get("profile"), "job profile")
        if schema == SCHEMA_V1 and profile not in ALLOWED_PROFILES:
            raise ClaimScopeError("claim scope job profile is not allowlisted")
        jobs.append(ScopedJob(job_id=job_id, profile=profile))
    if len({item.job_id for item in jobs}) != len(jobs):
        raise ClaimScopeError("claim scope job IDs must be unique")
    if schema == SCHEMA_V1:
        if {item.profile for item in jobs} != ALLOWED_PROFILES:
            raise ClaimScopeError("claim scope jobs must cover both expected profiles")
        if repository != ALLOWED_REPOSITORY:
            raise ClaimScopeError("claim scope repository is not allowlisted")
    return ClaimScope(
        scope_id=scope_id,
        worker_name=worker_name,
        tier=tier,
        repository=repository,
        head_sha=head_sha,
        expires_at=_parse_expiry(raw.get("expires_at")),
        jobs=tuple(jobs),
        worker_certificate_sha256=_parse_certificate(raw),
        schema=schema,
    )


def load_claim_scopes(path: Path) -> dict[str, ClaimScope]:
    if not path.exists():
        return {}
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ClaimScopeError("claim scope document is unreadable") from error
    if not isinstance(document, dict) or document.get("schema") not in SUPPORTED_SCHEMAS:
        raise ClaimScopeError("claim scope document has an unsupported schema")
    scopes_raw = document.get("scopes")
    if not isinstance(scopes_raw, list):
        raise ClaimScopeError("claim scope document scopes must be a list")
    schema = str(document["schema"])
    if schema == MIXED_SCHEMA:
        scopes = []
        for raw in scopes_raw:
            if not isinstance(raw, dict):
                raise ClaimScopeError("claim scope entry must be an object")
            entry_schema = raw.get("schema")
            if entry_schema not in {SCHEMA_V1, SCHEMA_V2, LEGACY_SCHEMA}:
                raise ClaimScopeError("claim scope entry has an unsupported schema")
            scopes.append(_parse_scope(raw, schema=str(entry_schema)))
    else:
        scopes = [_parse_scope(raw, schema=schema) for raw in scopes_raw]
    if len({scope.scope_id for scope in scopes}) != len(scopes):
        raise ClaimScopeError("claim scope IDs must be unique")
    return {scope.scope_id: scope for scope in scopes}


def _scope_entry(scope: ClaimScope) -> dict[str, object]:
    """Serialize one immutable scope for the mixed compatibility container."""
    entry: dict[str, object] = {
        "schema": scope.schema,
        "scope_id": scope.scope_id,
        "worker_name": scope.worker_name,
        "tier": scope.tier,
        "expires_at": scope.expires_at.astimezone(UTC).isoformat(),
        "worker_certificate_sha256": scope.worker_certificate_sha256,
    }
    if scope.schema == SCHEMA_V2:
        entry.update(
            {
                "host": scope.host,
                "runner": scope.runner,
                "correlation_id": scope.correlation_id,
                "jobs": [
                    {
                        "job_id": item.job_id,
                        "repository": item.repository,
                        "run_id": item.run_id,
                        "attempt": item.attempt,
                        "exact_sha": item.exact_sha,
                        "profile": item.profile,
                    }
                    for item in scope.jobs
                ],
                "fifo_skipped": [
                    {
                        "job_id": item.job_id,
                        "repository": item.repository,
                        "run_id": item.run_id,
                        "attempt": item.attempt,
                        "exact_sha": item.exact_sha,
                        "profile": item.profile,
                        "managed_registry_entry": item.managed_registry_entry,
                        "reason": item.reason,
                    }
                    for item in scope.fifo_skipped
                ],
            }
        )
    else:
        entry.update(
            {
                "repository": scope.repository,
                "head_sha": scope.head_sha,
                "jobs": [{"job_id": item.job_id, "profile": item.profile} for item in scope.jobs],
            }
        )
    return {key: value for key, value in entry.items() if value is not None}


def claim_scope_mapping(scope: ClaimScope) -> dict[str, object]:
    """Return the serialisable public portion of one verified scope."""
    return _scope_entry(scope)


def upsert_claim_scope(path: Path, scope: ClaimScope) -> None:
    """Atomically retain legacy scopes while replacing one controller-issued v2 scope.

    This is deliberately a narrow store update: it never changes a queued job,
    FIFO position, lease or provider state.  The controller later lets the
    already-configured worker claim the exact immutable tuple.
    """
    scopes = load_claim_scopes(path)
    scopes[scope.scope_id] = scope
    document = {
        "schema": MIXED_SCHEMA,
        "scopes": [_scope_entry(item) for _, item in sorted(scopes.items())],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    try:
        temporary.write_text(
            json.dumps(document, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def resolve_claim_scope(
    path: Path,
    scope_id: str | None,
    worker_name: str,
    tier: str,
    profiles: tuple[str, ...],
    *,
    now: datetime | None = None,
) -> ClaimScope | None:
    """Return an exact scope, or fail closed before the store can claim a job."""
    if scope_id is None:
        return None
    normalized_scope_id = scope_id.strip()
    if not _SCOPE_ID.fullmatch(normalized_scope_id):
        raise ClaimScopeError("claim scope ID contains unsafe characters")
    scope = load_claim_scopes(path).get(normalized_scope_id)
    if scope is None:
        raise ClaimScopeError("claim scope is absent")
    current = now or datetime.now(UTC)
    if scope.expires_at <= current:
        raise ClaimScopeError("claim scope has expired")
    if scope.schema in {SCHEMA_V1, SCHEMA_V2} and scope.expires_at > current + MAX_TTL:
        raise ClaimScopeError("claim scope expiry exceeds the 15 minute limit")
    if scope.worker_name != worker_name or scope.tier != tier:
        raise ClaimScopeError("claim scope worker identity does not match")
    if scope.schema == SCHEMA_V1 and (
        set(profiles) != ALLOWED_PROFILES or len(profiles) != len(ALLOWED_PROFILES)
    ):
        raise ClaimScopeError("claim scope profiles do not match worker profiles")
    if scope.schema == LEGACY_SCHEMA:
        allowed_profiles = {item.profile for item in scope.jobs}
        if allowed_profiles != set(profiles):
            raise ClaimScopeError("claim scope profiles do not match worker profiles")
    if scope.schema == SCHEMA_V2 and not {item.profile for item in scope.jobs}.issubset(
        set(profiles)
    ):
        raise ClaimScopeError("claim scope profiles do not match worker profiles")
    return scope


def resolve_bound_claim_scope(
    path: Path,
    scope_id: str | None,
    *,
    worker_name: str,
    job_id: int,
    repository: str,
    head_sha: str,
    profile: str,
    run_id: int | None = None,
    attempt: int | None = None,
) -> ClaimScope:
    """Resolve a previously bound scope without reopening its claim window."""
    normalized_scope_id = (scope_id or "").strip()
    if not _SCOPE_ID.fullmatch(normalized_scope_id):
        raise ClaimScopeError("claim scope ID contains unsafe characters")
    scope = load_claim_scopes(path).get(normalized_scope_id)
    if scope is None:
        raise ClaimScopeError("claim scope is absent")
    if scope.worker_name != worker_name:
        raise ClaimScopeError("claim scope worker identity does not match")
    if not scope.permits(job_id, repository, head_sha, profile, run_id=run_id, attempt=attempt):
        raise ClaimScopeError("claim scope job binding does not match")
    return scope
