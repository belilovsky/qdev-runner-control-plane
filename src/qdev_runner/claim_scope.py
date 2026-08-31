from __future__ import annotations

import json
import re
import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

# ``claim-scope-v1`` is the published, short-lived broker contract.  The
# plural name was used by the first candidate and remains readable so a
# broker upgrade cannot accidentally disable an already provisioned scope.
SCHEMA = "claim-scope-v1"
LEGACY_SCHEMA = "qdev-runner-claim-scopes-v1"
ALLOWED_REPOSITORY = "belilovsky/qazagents"
ALLOWED_PROFILES = frozenset({"qdev-ci", "qdev-ci-docker"})
MAX_TTL = timedelta(minutes=15)
_SHA256 = re.compile(r"^[0-9a-f]{40}$")
_CERT_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_SCOPE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,127}$")
_WORKER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")


class ClaimScopeError(ValueError):
    """Raised when a temporary worker scope is missing or cannot be trusted."""


@dataclass(frozen=True)
class ScopedJob:
    job_id: int
    profile: str


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

    def permits(self, job_id: int, repository: str, head_sha: str, profile: str) -> bool:
        return (
            repository == self.repository
            and head_sha == self.head_sha
            and any(item.job_id == job_id and item.profile == profile for item in self.jobs)
        )

    def certificate_matches(self, fingerprint: str | None) -> bool:
        """Match a Caddy-provided mTLS certificate fingerprint exactly.

        The field is optional for compatibility with existing scopes.  A
        scope that includes it must be authenticated by that certificate; a
        shared worker token is deliberately not an alternative credential.
        """
        normalized = (fingerprint or "").strip()
        return bool(
            self.worker_certificate_sha256
            and _CERT_SHA256.fullmatch(normalized)
            and secrets.compare_digest(self.worker_certificate_sha256, normalized)
        )


def _required_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ClaimScopeError(f"claim scope {field} must be a non-empty string")
    return value.strip()


def _parse_expiry(value: object) -> datetime:
    raw = _required_string(value, "expires_at")
    try:
        parsed = datetime.fromisoformat(raw.replace("Z", "+00:00"))
    except ValueError as error:
        raise ClaimScopeError("claim scope expires_at must be RFC3339") from error
    if parsed.tzinfo is None:
        raise ClaimScopeError("claim scope expires_at must include a timezone")
    return parsed.astimezone(UTC)


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
    repository = _required_string(raw.get("repository"), "repository")
    head_sha = _required_string(raw.get("head_sha"), "head_sha")
    if not _SHA256.fullmatch(head_sha):
        raise ClaimScopeError("claim scope head_sha must be a lowercase Git SHA")
    worker_certificate_sha256_raw = raw.get("worker_certificate_sha256")
    worker_certificate_sha256: str | None = None
    if worker_certificate_sha256_raw is not None:
        worker_certificate_sha256 = _required_string(
            worker_certificate_sha256_raw, "worker_certificate_sha256"
        )
        if not _CERT_SHA256.fullmatch(worker_certificate_sha256):
            raise ClaimScopeError(
                "claim scope worker_certificate_sha256 must be a lowercase SHA-256"
            )
    jobs_raw = raw.get("jobs")
    if (
        not isinstance(jobs_raw, list)
        or (schema == SCHEMA and len(jobs_raw) != 2)
        or (schema == LEGACY_SCHEMA and not jobs_raw)
    ):
        detail = "exactly two jobs" if schema == SCHEMA else "a non-empty list"
        raise ClaimScopeError(f"claim scope jobs must contain {detail}")
    jobs: list[ScopedJob] = []
    for item in jobs_raw:
        if not isinstance(item, dict):
            raise ClaimScopeError("claim scope job must be an object")
        job_id = item.get("job_id")
        if not isinstance(job_id, int) or isinstance(job_id, bool) or job_id <= 0:
            raise ClaimScopeError("claim scope job_id must be a positive integer")
        profile = _required_string(item.get("profile"), "job profile")
        if schema == SCHEMA and profile not in ALLOWED_PROFILES:
            raise ClaimScopeError("claim scope job profile is not allowlisted")
        jobs.append(ScopedJob(job_id=job_id, profile=profile))
    if len({item.job_id for item in jobs}) != len(jobs):
        raise ClaimScopeError("claim scope job IDs must be unique")
    if schema == SCHEMA and {item.profile for item in jobs} != ALLOWED_PROFILES:
        raise ClaimScopeError("claim scope jobs must cover both expected profiles")
    if schema == SCHEMA:
        if not _WORKER_NAME.fullmatch(worker_name):
            raise ClaimScopeError("claim scope worker_name contains unsafe characters")
        if not worker_name.endswith(f"-{tier}"):
            raise ClaimScopeError("claim scope worker_name must end with its tier")
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
        worker_certificate_sha256=worker_certificate_sha256,
        schema=schema,
    )


def load_claim_scopes(path: Path) -> dict[str, ClaimScope]:
    if not path.exists():
        return {}
    try:
        document: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ClaimScopeError("claim scope document is unreadable") from error
    if not isinstance(document, dict) or document.get("schema") not in {SCHEMA, LEGACY_SCHEMA}:
        raise ClaimScopeError("claim scope document has an unsupported schema")
    scopes_raw = document.get("scopes")
    if not isinstance(scopes_raw, list):
        raise ClaimScopeError("claim scope document scopes must be a list")
    schema = str(document["schema"])
    scopes = [_parse_scope(raw, schema=schema) for raw in scopes_raw]
    if len({scope.scope_id for scope in scopes}) != len(scopes):
        raise ClaimScopeError("claim scope IDs must be unique")
    return {scope.scope_id: scope for scope in scopes}


def resolve_claim_scope(
    path: Path,
    scope_id: str | None,
    worker_name: str,
    tier: str,
    profiles: tuple[str, ...],
    *,
    now: datetime | None = None,
) -> ClaimScope | None:
    """Return an exact scope, or fail closed before the store can claim a job.

    The lack of a scope deliberately preserves ordinary worker FIFO behavior.
    Once a worker supplies a scope identifier, no mismatch may fall back to the
    unscoped queue.
    """
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
    if scope.schema == SCHEMA and scope.expires_at > current + MAX_TTL:
        raise ClaimScopeError("claim scope expiry exceeds the 15 minute limit")
    if scope.worker_name != worker_name or scope.tier != tier:
        raise ClaimScopeError("claim scope worker identity does not match")
    if scope.schema == SCHEMA and (
        set(profiles) != ALLOWED_PROFILES or len(profiles) != len(ALLOWED_PROFILES)
    ):
        raise ClaimScopeError("claim scope profiles do not match worker profiles")
    if scope.schema == LEGACY_SCHEMA:
        allowed_profiles = {item.profile for item in scope.jobs}
        if allowed_profiles != set(profiles):
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
) -> ClaimScope:
    """Resolve the scope already bound to an active job without re-admitting it.

    Expiry prevents new claims.  A job claimed while the scope was valid must
    still be able to report status and completion; its immutable job binding
    and certificate fingerprint remain mandatory.
    """
    normalized_scope_id = (scope_id or "").strip()
    if not _SCOPE_ID.fullmatch(normalized_scope_id):
        raise ClaimScopeError("claim scope ID contains unsafe characters")
    scope = load_claim_scopes(path).get(normalized_scope_id)
    if scope is None:
        raise ClaimScopeError("claim scope is absent")
    if scope.worker_name != worker_name:
        raise ClaimScopeError("claim scope worker identity does not match")
    if not scope.permits(job_id, repository, head_sha, profile):
        raise ClaimScopeError("claim scope job binding does not match")
    return scope
