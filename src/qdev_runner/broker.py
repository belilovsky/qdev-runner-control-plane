from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import ssl
import time
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .admin_platform_ledger import AdminPlatformLedger, AdminPlatformLedgerError
from .claim_scope import (
    SCHEMA_V2,
    ClaimScope,
    ClaimScopeError,
    ScopedJob,
    claim_scope_mapping,
    load_claim_scopes,
    resolve_bound_claim_scope,
    resolve_claim_scope,
    upsert_claim_scope,
)
from .fleet_bootstrap import (
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
)
from .fleet_bootstrap_executor import execute_existing_worker_recovery
from .github import GitHubAppClient, GitHubError
from .github_oidc import GitHubActionsArtifactOIDCVerifier, GitHubActionsOIDCError
from .managed_registry import ManagedRegistry, ManagedRegistryError
from .managed_release_ledger import ManagedReleaseLedger, ManagedReleaseLedgerError
from .models import QueuedJob
from .operations import (
    DISK_ONLY_BLOCKERS,
    HARD_MAX_DISK_USED_PCT,
    HARD_MIN_FREE_GIB,
    MAX_OVERRIDE_SECONDS,
    OperationStore,
)
from .policy import Policy, PolicyError
from .release_lane import (
    HostHeartbeatRequest,
    ReleaseAdmissionRequest,
    ReleaseLane,
    ReleaseLaneError,
    ReleaseLanePolicy,
    ReleaseStore,
    admission_receipt,
    validate_candidate,
    validate_controller_claim,
    validate_host_heartbeat,
)
from .settings import BrokerSettings
from .store import Store
from .test_reports import (
    MAX_REPORT_BYTES,
    TestReportError,
    normalize_test_run,
    parse_cobertura,
    parse_junit,
    parse_lcov,
    report_digest,
)

LOGGER = logging.getLogger("qdev-runner-broker")
_CONTROLLER_RELEASE_SCHEMA = "qdev-controller-release-status-v1"
_GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SHA256_DIGEST = re.compile(r"^[0-9a-f]{64}$")


def controller_release_status(path: Path) -> dict[str, Any]:
    """Return a deliberately non-secret activation observation for /health.

    A signed operator receipt remains the authority for admission; the public
    projection exists solely to prevent a missing activation from looking like
    a capacity or runner failure.
    """
    unavailable = {
        "schema": _CONTROLLER_RELEASE_SCHEMA,
        "state": "unavailable",
    }
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return unavailable
    if not isinstance(value, dict):
        return unavailable
    required = {"schema", "state", "revision", "release_digest", "activated_at"}
    if set(value) != required or value.get("schema") != _CONTROLLER_RELEASE_SCHEMA:
        return unavailable
    if value.get("state") != "active":
        return unavailable
    revision = value.get("revision")
    release_digest = value.get("release_digest")
    activated_at = value.get("activated_at")
    if not isinstance(revision, str) or not _GIT_REVISION.fullmatch(revision):
        return unavailable
    if not isinstance(release_digest, str) or not _SHA256_DIGEST.fullmatch(release_digest):
        return unavailable
    if not isinstance(activated_at, str):
        return unavailable
    try:
        if datetime.fromisoformat(activated_at.replace("Z", "+00:00")).tzinfo is None:
            return unavailable
    except ValueError:
        return unavailable
    return dict(value)


def profile_admission_health(
    *,
    pending_jobs: list[dict[str, Any]],
    fresh_workers: list[dict[str, Any]],
    policy: Policy,
) -> dict[str, dict[str, int | str]]:
    """Project a non-secret, profile-specific admission summary.

    Aggregate worker capacity cannot show whether a queued job's required
    profile can be claimed. The summary deliberately contains only profile
    names and counts, and does not participate in admission.
    """
    pending_by_profile: dict[str, int] = {}
    for job in pending_jobs:
        try:
            profile = policy.profile_for_labels(
                str(job["repository"]), _json_strings(job["labels_json"])
            )
        except (KeyError, PolicyError):
            # Keep health observational. Invalid durable rows are handled by
            # the normal broker validation and reconciliation paths.
            continue
        pending_by_profile[profile.name] = pending_by_profile.get(profile.name, 0) + 1

    summary: dict[str, dict[str, int | str]] = {}
    for profile_name, pending in sorted(pending_by_profile.items()):
        slots = {"primary": 0, "reserve": 0}
        for worker in fresh_workers:
            if not worker["capacity_allowed"]:
                continue
            profiles = {item.lower() for item in _json_strings(worker["profiles_json"])}
            if profile_name.lower() not in profiles:
                continue
            tier = str(worker["tier"])
            if tier in slots:
                slots[tier] += int(worker["slots_available"])
        total = slots["primary"] + slots["reserve"]
        summary[profile_name] = {
            "pending": pending,
            "primary_slots_available": slots["primary"],
            "reserve_slots_available": slots["reserve"],
            "admission": "ready" if total else "no-fresh-eligible-worker",
        }
    return summary


class ClaimRequest(BaseModel):
    worker_name: str
    tier: Literal["primary", "reserve"]
    claim_scope_id: str | None = None
    profiles: list[str]
    disk_free_gib: float = Field(ge=0)
    min_disk_free_gib: float = Field(ge=0)
    capacity_directive_id: str | None = None
    capacity_repository: str | None = None


class CompletionRequest(BaseModel):
    worker_name: str
    job_id: int
    runner_exit_code: int
    infrastructure_error: bool = False
    detail: str = ""


class HeartbeatRequest(BaseModel):
    worker_name: str
    tier: Literal["primary", "reserve"]
    profiles: list[str]
    active_jobs: int = Field(ge=0)
    active_job_ids: list[int] = Field(default_factory=list)
    claim_scope_id: str | None = None
    detail: dict[str, Any]


class CapacityOverrideRequest(BaseModel):
    repository: str = Field(min_length=1, max_length=256)
    profiles: list[str] = Field(min_length=1)
    min_disk_free_gib: float = Field(ge=HARD_MIN_FREE_GIB)
    max_disk_used_pct: float = Field(ge=0, le=HARD_MAX_DISK_USED_PCT)
    duration_seconds: int = Field(ge=1, le=MAX_OVERRIDE_SECONDS)
    owner: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=500)


class ControllerClaimRequest(BaseModel):
    """One bounded controller admission for the current FIFO head."""

    job_id: int = Field(gt=0)
    worker_name: str = Field(min_length=3, max_length=128)
    tier: Literal["primary", "reserve"]
    scope_id: str = Field(min_length=3, max_length=128)
    host: str = Field(min_length=1, max_length=255)
    runner: str = Field(min_length=1, max_length=255)
    worker_certificate_sha256: str = Field(min_length=64, max_length=64)
    correlation_id: str = Field(min_length=1, max_length=255)
    duration_seconds: int = Field(default=900, ge=60, le=900)


class StaleJobRecoveryRequest(BaseModel):
    worker_timeout_seconds: int = Field(default=300, ge=300, le=3600)
    owner: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=500)


class FleetBootstrapRecoveryRequest(BaseModel):
    """Controller-observed request for one existing-worker recovery."""

    model_config = ConfigDict(extra="forbid")

    request: dict[str, Any] = Field(min_length=1)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
    active_jobs: int = Field(ge=0)
    timeout_seconds: float = Field(default=120.0, gt=0, le=600)


class RetryRequest(BaseModel):
    reason: str = Field(default="operator requested retry", max_length=512)
    # A caller may retry a timed-out request with the same id without creating
    # a second provider operation.  The platform proxy normally supplies this
    # value from Idempotency-Key; keeping it in the body also supports signed
    # non-browser operators.
    request_id: str | None = Field(
        default=None,
        min_length=1,
        max_length=128,
        pattern=r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$",
    )


class TestScheduleRequest(BaseModel):
    repository: str = Field(min_length=3, max_length=255)
    workflow: str = Field(min_length=1, max_length=200)
    suite: str = Field(default="all", min_length=1, max_length=80)
    installation_id: int = Field(ge=1)
    ref: str = Field(default="main", min_length=1, max_length=255)
    interval_seconds: int = Field(default=86400, ge=60, le=604800)
    enabled: bool = True
    next_run_at: float | None = Field(default=None, ge=0)


class SchedulerTickRequest(BaseModel):
    now: float | None = Field(default=None, ge=0)
    limit: int = Field(default=20, ge=1, le=100)


def verify_signature(secret: str, body: bytes, signature: str | None) -> bool:
    if not signature or not signature.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(signature.removeprefix("sha256="), expected)


def artifact_token(secret: str, repository: str, sha: str, job_id: int) -> str:
    value = f"{repository}:{sha}:{job_id}".encode()
    return hmac.new(secret.encode(), value, hashlib.sha256).hexdigest()


def artifact_job_is_active(
    job: dict[str, Any] | None, repository: str, sha: str, job_id: int
) -> bool:
    return bool(
        job
        and int(job["job_id"]) == job_id
        and str(job["repository"]) == repository
        and str(job["head_sha"]) == sha
        and str(job["status"]) in {"claimed", "running"}
    )


def registry_credentials(settings: BrokerSettings, profile_name: str) -> dict[str, str] | None:
    if not settings.registry_password or profile_name != "qdev-ci-docker":
        return None
    return {
        "url": settings.registry_url,
        "username": settings.registry_username,
        "password": settings.registry_password,
    }


def completed_run_conclusion(run: dict[str, Any]) -> str | None:
    if str(run.get("status") or "") != "completed":
        return None
    return str(run.get("conclusion") or "unknown")


def _json_object(value: object) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if not isinstance(value, str):
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_strings(value: object) -> tuple[str, ...]:
    if isinstance(value, (list, tuple)):
        return tuple(str(item) for item in value)
    if not isinstance(value, str):
        return ()
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError):
        return ()
    return tuple(str(item) for item in parsed) if isinstance(parsed, list) else ()


def _stale_job_tuple(row: dict[str, Any]) -> dict[str, Any]:
    payload = _json_object(row.get("payload_json"))
    workflow_job = _json_object(payload.get("workflow_job"))
    return {
        "project": str(row.get("repository") or ""),
        "run_id": int(row.get("run_id") or 0),
        "job_id": int(row.get("job_id") or 0),
        "attempt": int(workflow_job.get("run_attempt") or 1),
        "exact_sha": str(row.get("head_sha") or ""),
        "profile": str(row.get("profile") or ""),
        "worker": str(row.get("worker_name") or ""),
        "state": str(row.get("status") or ""),
        "created_at": float(row.get("created_at") or 0),
        "job_updated_at": float(row.get("updated_at") or 0),
        "worker_last_seen": (
            float(row["worker_last_seen"]) if row.get("worker_last_seen") is not None else None
        ),
    }


def _job_attempt(row: dict[str, Any]) -> int | None:
    """Return an explicitly supplied provider run attempt, if present.

    Scope v2 intentionally never assumes attempt one: a provider retry is a
    different immutable tuple and needs a fresh signed scope.
    """
    payload = _json_object(row.get("payload_json"))
    workflow_job = _json_object(payload.get("workflow_job"))
    attempt_raw = workflow_job.get("run_attempt")
    if isinstance(attempt_raw, bool) or not isinstance(attempt_raw, (int, str)):
        return None
    try:
        attempt = int(attempt_raw)
    except (TypeError, ValueError):
        return None
    return attempt if attempt > 0 else None


def _worker_audit(
    worker: dict[str, Any],
    now: float,
    *,
    operations: OperationStore | None = None,
) -> dict[str, Any]:
    detail = _json_object(worker.get("detail_json"))
    raw = _json_object(detail.get("raw_capacity"))
    baseline = _json_object(detail.get("baseline_capacity"))
    effective = _json_object(detail.get("effective_capacity"))
    profiles = _json_strings(worker.get("profiles_json"))
    directive_id = detail.get("capacity_directive_id")
    capacity_allowed = worker.get("capacity_allowed") is True
    if directive_id:
        # A heartbeat may outlive a bounded override. Never let its last
        # `allowed` bit turn an expired or replaced directive into admission.
        capacity_allowed = False
        if operations is not None:
            directive = operations.active(
                str(worker.get("name") or ""),
                registered_profiles=profiles,
                now=datetime.fromtimestamp(now, UTC),
            )
            capacity_allowed = bool(
                directive is not None and directive.operation_id == str(directive_id)
            )
    effective_profiles = _json_strings(detail.get("effective_profiles", []))
    if not capacity_allowed:
        effective_profiles = ()
    return {
        "worker": str(worker.get("name") or ""),
        "tier": str(worker.get("tier") or detail.get("tier") or ""),
        "profiles": list(profiles),
        "active_jobs": int(worker.get("active_jobs") or 0),
        "slots_available": int(worker.get("slots_available") or 0),
        "fresh": now - float(worker.get("last_seen") or 0) < 90,
        "last_seen": float(worker.get("last_seen") or 0),
        "raw_capacity": raw,
        "baseline_capacity": baseline,
        "effective_capacity": effective,
        "capacity_allowed": capacity_allowed,
        "configured_claim_scope_id": detail.get("configured_claim_scope_id"),
        "admission": {
            "allowed": capacity_allowed,
            "directive_id": directive_id,
            "profiles": list(effective_profiles),
        },
    }


def worker_authenticated(
    token: str | None,
    expected_token: str,
    *,
    claim_scope: ClaimScope | None = None,
    client_certificate_sha256: str | None = None,
) -> bool:
    """Authenticate a worker without letting a scoped certificate fall back.

    Ordinary workers retain the static-token contract.  A certificate-bound
    scope deliberately accepts only the mTLS certificate fingerprint injected
    by Caddy after verification; possession of the ordinary token cannot turn
    it into a general-queue credential.
    """
    if claim_scope is not None and claim_scope.worker_certificate_sha256:
        return claim_scope.certificate_matches(client_certificate_sha256)
    return bool(token and secrets.compare_digest(token, expected_token))


def _safe_segment(value: str) -> str:
    allowed = "-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if not value or value in {".", ".."} or any(char not in allowed for char in value):
        raise HTTPException(status_code=400, detail="invalid artifact path")
    return value


def create_app(
    settings: BrokerSettings | None = None,
    *,
    store: Store | None = None,
    policy: Policy | None = None,
    github: GitHubAppClient | None = None,
    github_actions_oidc_verifier: GitHubActionsArtifactOIDCVerifier | None = None,
) -> FastAPI:
    settings = settings or BrokerSettings.from_env()
    store = store or Store(settings.database_path)
    policy = policy or Policy(settings.inventory_path, settings.profiles_path)
    github = github or GitHubAppClient(
        settings.app_id,
        settings.app_private_key_path,
        settings.github_api_url,
        settings.github_api_version,
    )
    github_actions_oidc_verifier = (
        github_actions_oidc_verifier
        or GitHubActionsArtifactOIDCVerifier(
            issuer=settings.github_actions_oidc_issuer,
            audience=settings.github_actions_oidc_audience,
            jwks_url=settings.github_actions_oidc_jwks_url,
        )
    )
    settings.artifact_root.mkdir(parents=True, exist_ok=True)
    operator_values = (
        settings.operator_token,
        settings.operator_receipt_key,
        settings.operator_directive_key,
    )
    if any(operator_values) and not all(operator_values):
        raise RuntimeError(
            "QDEV_OPERATOR_TOKEN, QDEV_OPERATOR_RECEIPT_KEY and "
            "QDEV_OPERATOR_DIRECTIVE_KEY are atomic"
        )
    operations = (
        OperationStore(
            settings.operations_root,
            worker_signing_key=settings.operator_directive_key or "",
            receipt_signing_key=settings.operator_receipt_key or "",
        )
        if all(operator_values)
        else None
    )

    def require_test_operator(
        request: Request,
        token: str | None,
        user: str | None,
        email: str | None,
        groups: str | None,
        proxy_auth: str | None = None,
    ) -> str:
        """Authenticate the private test-center API.

        A worker credential is never accepted here.  The direct token is for
        the server-side Platform proxy; browser callers use the existing
        trusted OIDC proxy, which must provide an identity and operator group.
        """

        proxy_auth = proxy_auth or request.headers.get("x-qdev-operator-proxy-auth")
        if (
            token
            and settings.operator_token
            and secrets.compare_digest(token, settings.operator_token)
        ):
            return (email or user or "operator-token")[:256]
        client_host = request.client.host if request.client else ""
        trusted = client_host in {"127.0.0.1", "::1", "localhost"}
        if settings.operator_proxy_secret:
            if not proxy_auth or not secrets.compare_digest(
                proxy_auth, settings.operator_proxy_secret
            ):
                raise HTTPException(status_code=401, detail="operator proxy authentication failed")
        elif not settings.allow_legacy_local_oidc or not trusted:
            raise HTTPException(status_code=401, detail="operator authentication failed")
        if not trusted:
            raise HTTPException(status_code=401, detail="operator authentication failed")
        identity = (email or user or "").strip()
        supplied_groups = {
            item.strip() for item in (groups or "").replace(";", ",").split(",") if item.strip()
        }
        if not identity or settings.operator_group not in supplied_groups:
            raise HTTPException(status_code=403, detail="operator role is required")
        return identity[:256]

    def require_same_origin(request: Request, *, required: bool = False) -> None:
        """Reject browser cross-site mutations while keeping API clients usable."""

        origin = request.headers.get("origin")
        if not origin:
            if required:
                raise HTTPException(status_code=403, detail="origin is required")
            return
        host = request.headers.get("host", "").strip()
        parsed = urlparse(origin)
        if settings.operator_origin and (
            origin.rstrip("/").casefold() != settings.operator_origin.rstrip("/").casefold()
        ):
            raise HTTPException(status_code=403, detail="cross-origin mutation rejected")
        if (
            not host
            or parsed.scheme not in {"http", "https"}
            or not parsed.netloc
            or parsed.netloc.casefold() != host.casefold()
        ):
            raise HTTPException(status_code=403, detail="cross-origin mutation rejected")

    def is_allowed_test_workflow_name(
        name: str, path: str = "", *, explicitly_registered: bool = False
    ) -> bool:
        workflow_name = name.strip()
        workflow_path = path.strip()
        identity = f"{workflow_name} {workflow_path}".lower()
        if not identity or any(
            word in identity for word in ("release", "deploy", "publish", "production")
        ):
            return False
        # Registration is necessary but never overrides a dangerous workflow
        # classification.  A release/deploy workflow can therefore not be
        # smuggled into the test center by adding it to an inventory list.
        if explicitly_registered:
            return True
        return any(
            word in identity
            for word in ("test", "ci", "quality", "check", "verify", "smoke", "contract")
        )

    def is_registered_test_workflow(job: dict[str, Any]) -> bool:
        raw = job.get("payload_json", "")
        try:
            payload = json.loads(raw) if isinstance(raw, str) else raw
        except json.JSONDecodeError:
            return False
        workflow_job = payload.get("workflow_job") if isinstance(payload, dict) else None
        if not isinstance(workflow_job, dict):
            return False
        repository = str(job.get("repository") or "").strip()
        name = str(workflow_job.get("workflow_name") or workflow_job.get("name") or "").strip()
        path = _normalise_workflow_path(workflow_job.get("path"))
        if not repository or not path:
            return False
        try:
            repo = policy.repository(repository)
            registration = policy.test_workflow(repository, path)
        except PolicyError:
            return False
        explicitly_registered = registration is not None or bool(
            repo.workflows
            and path in {_normalise_workflow_path(item) for item in repo.workflows}
        )
        return is_allowed_test_workflow_name(
            name, path, explicitly_registered=explicitly_registered
        )

    def _safe_workflow_path(value: str, *, explicitly_registered: bool = False) -> str:
        path = value.strip()
        allowed = "-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/"
        if (
            not path
            or path.startswith(("/", "\\"))
            or any(part in {"", ".", ".."} for part in path.replace("\\", "/").split("/"))
            or any(char not in allowed for char in path)
            or not path.lower().endswith((".yml", ".yaml"))
        ):
            raise HTTPException(status_code=400, detail="invalid test workflow path")
        if not is_allowed_test_workflow_name(
            path, path, explicitly_registered=explicitly_registered
        ):
            raise HTTPException(status_code=403, detail="workflow is not an allowed test workflow")
        return path

    def _safe_ref(value: str, repository: str) -> str:
        ref = value.strip()
        allowed = "-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/"
        if (
            not ref
            or ref.startswith("-")
            or ref.startswith(("/", "\\"))
            or any(part in {"", ".", ".."} for part in ref.replace("\\", "/").split("/"))
            or any(char not in allowed for char in ref)
        ):
            raise HTTPException(status_code=400, detail="invalid test ref")
        repo = policy.repository(repository)
        if ref != repo.default_branch:
            raise HTTPException(
                status_code=403, detail="scheduled tests must use the default branch"
            )
        return ref

    def _resolve_ref_sha(due: dict[str, Any], repo: Any) -> str | None:
        """Resolve a strict registration to the provider's current full SHA."""

        if not repo.workflow_registration_present:
            return None
        resolver = getattr(github, "ref_sha", None)
        if not callable(resolver):
            raise PolicyError("GitHub ref resolution is required for registered test workflows")
        resolved = resolver(int(due["installation_id"]), str(due["repository"]), str(due["ref"]))
        if not isinstance(resolved, str) or not re.fullmatch(r"[0-9a-fA-F]{40}", resolved):
            raise PolicyError("GitHub ref resolution did not return a full commit SHA")
        return resolved.lower()

    def _normalise_workflow_path(value: Any) -> str:
        path = str(value or "").replace("\\", "/").strip()
        return path[2:] if path.startswith("./") else path

    def _run_workflow_path(run: dict[str, Any]) -> str:
        path = run.get("path") or run.get("workflow_path")
        workflow = run.get("workflow")
        if not path and isinstance(workflow, dict):
            path = workflow.get("path")
        return _normalise_workflow_path(path)

    def _run_id(run: dict[str, Any]) -> int | None:
        try:
            value = run.get("id", run.get("run_id"))
            parsed = int(value) if value is not None else 0
        except (TypeError, ValueError):
            return None
        return parsed if parsed > 0 else None

    def _run_attempt(run: dict[str, Any]) -> int | None:
        try:
            value = run.get("run_attempt", run.get("run_attempt_number"))
            parsed = int(value) if value is not None else 0
        except (TypeError, ValueError):
            return None
        return parsed if parsed > 0 else None

    def _run_branch(run: dict[str, Any]) -> str:
        value = run.get("head_branch", run.get("branch"))
        branch = str(value or "").strip()
        if branch.startswith("refs/heads/"):
            branch = branch.removeprefix("refs/heads/")
        return branch

    def _match_dispatch_run(intent: dict[str, Any], run: dict[str, Any]) -> bool:
        if _run_id(run) is None:
            return False
        expected_sha = str(intent.get("expected_sha") or "").lower()
        run_sha = str(run.get("head_sha") or "").lower()
        if expected_sha and (not run_sha or run_sha != expected_sha):
            return False
        event = run.get("event")
        if event is not None and str(event) != "workflow_dispatch":
            return False
        expected_branch = str(intent.get("ref") or "").strip()
        branch = _run_branch(run)
        if branch and branch != expected_branch:
            return False
        expected_workflow = _normalise_workflow_path(intent.get("workflow"))
        run_workflow = _run_workflow_path(run)
        return not (run_workflow and expected_workflow and run_workflow != expected_workflow)

    def reconcile_dispatch_intents(*, now: float | None = None, limit: int = 20) -> dict[str, Any]:
        """Resolve outbox rows after a provider call with an uncertain outcome."""

        current = time.time() if now is None else float(now)
        items: list[dict[str, Any]] = []
        intents = store.list_dispatch_intents(states=("ambiguous",))[: max(1, min(limit, 100))]
        for intent in intents:
            item = {
                "intent_id": intent["id"],
                "repository": intent["repository"],
                "workflow": intent["workflow"],
                "suite": intent["suite"],
                "ref": intent["ref"],
                "correlation_id": intent["correlation_id"],
            }
            try:
                runs = github.workflow_runs(
                    int(intent["installation_id"]),
                    str(intent["repository"]),
                    workflow=str(intent["workflow"]),
                    branch=str(intent["ref"]),
                    event="workflow_dispatch",
                    per_page=100,
                )
                matches = [
                    run
                    for run in runs
                    if isinstance(run, dict) and _match_dispatch_run(intent, run)
                ]
                if len(matches) != 1:
                    item.update(
                        {
                            "status": "ambiguous",
                            "matches": len(matches),
                            "error": "provider dispatch requires an exact single run",
                        }
                    )
                else:
                    run = matches[0]
                    provider_run_id = _run_id(run)
                    store.update_dispatch_intent(
                        str(intent["id"]),
                        state="dispatched",
                        provider_response=run,
                        provider_run_id=provider_run_id,
                        provider_job_id=(
                            int(run["job_id"])
                            if str(run.get("job_id") or "").isdigit() and int(run["job_id"]) > 0
                            else None
                        ),
                    )
                    store.advance_test_schedule(
                        repository=str(intent["repository"]),
                        workflow=str(intent["workflow"]),
                        suite=str(intent["suite"]),
                        ref=str(intent["ref"]),
                        due_at=float(intent["slot"]),
                        now=current,
                    )
                    item.update(
                        {
                            "status": "reconciled",
                            "provider_run_id": provider_run_id,
                        }
                    )
            except (GitHubError, PolicyError, TypeError, ValueError) as error:
                item.update({"status": "ambiguous", "error": str(error)[:400]})
            items.append(item)
        return {
            "schema": "qdev-test-dispatch-reconcile-v1",
            "generated_at": current,
            "items": items,
            "reconciled": sum(item.get("status") == "reconciled" for item in items),
            "ambiguous": sum(item.get("status") == "ambiguous" for item in items),
        }

    def reconcile_retry_attempts(*, now: float | None = None, limit: int = 20) -> dict[str, Any]:
        """Find a provider-created retry without issuing a second rerun."""

        current = time.time() if now is None else float(now)
        items: list[dict[str, Any]] = []
        attempts = [
            row
            for row in store.list_retry_attempts(states=("requested", "dispatched", "ambiguous"))
            if row.get("provider_run_id") is None
        ][: max(1, min(limit, 100))]
        for attempt in attempts:
            item = {
                "request_id": attempt["request_id"],
                "repository": attempt["repository"],
                "source_run_id": attempt["source_run_id"],
                "source_attempt": attempt["source_job_attempt"],
            }
            source_job = store.job(int(attempt["source_job_id"]))
            if source_job is None:
                item.update({"status": "error", "error": "source job is missing"})
                items.append(item)
                continue
            workflow_path = ""
            try:
                payload = json.loads(str(source_job.get("payload_json") or "{}"))
                workflow_job = payload.get("workflow_job") if isinstance(payload, dict) else {}
                workflow_path = _normalise_workflow_path((workflow_job or {}).get("path"))
            except json.JSONDecodeError:
                item.update({"status": "error", "error": "source job payload is malformed"})
                items.append(item)
                continue
            try:
                runs = github.workflow_runs(
                    int(source_job["installation_id"]),
                    str(attempt["repository"]),
                    workflow=workflow_path or None,
                    branch=str(source_job.get("head_branch") or "") or None,
                    per_page=100,
                )
                matches: list[dict[str, Any]] = []
                for run in runs:
                    if not isinstance(run, dict):
                        continue
                    run_id = _run_id(run)
                    sha = str(run.get("head_sha") or "").lower()
                    if run_id is None or sha != str(attempt["expected_sha"]).lower():
                        continue
                    run_attempt = _run_attempt(run)
                    if run_id == int(attempt["source_run_id"]) and (
                        run_attempt is None or run_attempt <= int(attempt["source_job_attempt"])
                    ):
                        continue
                    run_workflow = _run_workflow_path(run)
                    if workflow_path and run_workflow and run_workflow != workflow_path:
                        continue
                    matches.append(run)
                if len(matches) != 1:
                    item.update(
                        {
                            "status": "ambiguous",
                            "matches": len(matches),
                            "error": "retry outcome requires an exact single provider run",
                        }
                    )
                else:
                    run = matches[0]
                    provider_run_id = _run_id(run)
                    provider_job_id = run.get("job_id")
                    try:
                        provider_job_id = (
                            int(provider_job_id) if provider_job_id is not None else None
                        )
                    except (TypeError, ValueError):
                        provider_job_id = None
                    if provider_job_id is not None and provider_job_id < 1:
                        provider_job_id = None
                    store.update_retry_attempt(
                        str(attempt["request_id"]),
                        state="dispatched",
                        provider_response=run,
                        provider_run_id=provider_run_id,
                        provider_job_id=provider_job_id,
                    )
                    item.update({"status": "reconciled", "provider_run_id": provider_run_id})
            except (GitHubError, TypeError, ValueError) as error:
                item.update({"status": "ambiguous", "error": str(error)[:400]})
            items.append(item)
        return {
            "schema": "qdev-test-retry-reconcile-v1",
            "generated_at": current,
            "items": items,
            "reconciled": sum(item.get("status") == "reconciled" for item in items),
            "ambiguous": sum(item.get("status") == "ambiguous" for item in items),
        }

    def _remote_workflow_job(
        job: dict[str, Any],
        *,
        workflow: str | None = None,
        run_id: int | None = None,
        attempt: int | None = None,
        repository_id: int | None = None,
    ) -> dict[str, Any]:
        """Fetch and verify the provider-owned identity for a queued job.

        The webhook is only an admission hint.  Before accepting an artifact
        or issuing a retry we compare the immutable job row with GitHub's
        current representation.  Older test doubles/legacy inventories may
        omit newer fields, so absent provider fields are tolerated only when
        the repository has not opted into the strict registration contract.
        """

        try:
            remote = github.workflow_job(
                int(job["installation_id"]), str(job["repository"]), int(job["job_id"])
            )
        except GitHubError as error:
            raise HTTPException(
                status_code=503, detail="GitHub job identity unavailable"
            ) from error
        if not isinstance(remote, dict):
            raise HTTPException(status_code=503, detail="GitHub job identity is malformed")
        stored_sha = str(job.get("head_sha") or "").lower()
        remote_sha = str(remote.get("head_sha") or "").lower()
        if remote_sha and stored_sha and remote_sha != stored_sha:
            raise HTTPException(
                status_code=422, detail="GitHub job SHA differs from stored job SHA"
            )
        if run_id is not None and remote.get("run_id") is not None:
            try:
                if int(remote["run_id"]) != int(run_id):
                    raise HTTPException(
                        status_code=422, detail="GitHub job run differs from stored run"
                    )
            except (TypeError, ValueError) as error:
                raise HTTPException(
                    status_code=422, detail="GitHub job run is malformed"
                ) from error
        remote_attempt = remote.get("run_attempt", remote.get("run_attempt_number"))
        if attempt is not None and remote_attempt is not None:
            try:
                if int(remote_attempt) != int(attempt):
                    raise HTTPException(
                        status_code=422, detail="GitHub job attempt differs from stored attempt"
                    )
            except (TypeError, ValueError) as error:
                raise HTTPException(
                    status_code=422, detail="GitHub job attempt is malformed"
                ) from error
        remote_repository_id = remote.get("repository_id")
        if remote_repository_id is None and isinstance(remote.get("repository"), dict):
            remote_repository_id = remote["repository"].get("id")
        remote_repository = remote.get("repository")
        remote_full_name = (
            str(remote_repository.get("full_name") or "").strip()
            if isinstance(remote_repository, dict)
            else str(remote.get("repository_full_name") or "").strip()
        )
        if remote_full_name and remote_full_name.casefold() != str(job["repository"]).casefold():
            raise HTTPException(
                status_code=422,
                detail="GitHub job repository differs from stored repository",
            )
        if repository_id is not None and remote_repository_id is not None:
            try:
                if int(remote_repository_id) != int(repository_id):
                    raise HTTPException(
                        status_code=422,
                        detail="GitHub job repository differs from stored repository",
                    )
            except (TypeError, ValueError) as error:
                raise HTTPException(
                    status_code=422, detail="GitHub job repository is malformed"
                ) from error
        remote_path = str(remote.get("path") or remote.get("workflow_path") or "").strip()
        if workflow and remote_path:

            def _normalise_workflow_path(value: str) -> str:
                normalised = value.replace("\\", "/").strip()
                return normalised[2:] if normalised.startswith("./") else normalised

            if _normalise_workflow_path(remote_path) != _normalise_workflow_path(workflow):
                raise HTTPException(
                    status_code=422, detail="GitHub job workflow differs from stored workflow"
                )
        return remote

    def _validate_schedule(request: TestScheduleRequest) -> dict[str, Any]:
        parts = request.repository.strip().split("/")
        if len(parts) != 2:
            raise HTTPException(status_code=400, detail="invalid repository")
        repository = f"{_safe_segment(parts[0])}/{_safe_segment(parts[1])}"
        try:
            repo = policy.repository(repository)
        except PolicyError as error:
            raise HTTPException(status_code=403, detail="repository is not registered") from error
        suite = _safe_segment(request.suite.strip())
        ref = _safe_ref(request.ref, repository)
        requested_workflow = request.workflow.strip()
        explicitly_registered = bool(repo.workflows and requested_workflow in repo.workflows)
        workflow = _safe_workflow_path(
            requested_workflow,
            explicitly_registered=explicitly_registered or repo.workflow_registration_present,
        )
        try:
            registration = policy.test_workflow(
                repository,
                workflow,
                suite=None if suite == "all" else suite,
                ref=ref,
            )
        except PolicyError as error:
            raise HTTPException(
                status_code=403, detail="workflow or suite is not registered"
            ) from error
        if repo.workflow_registration_present and registration is None:
            raise HTTPException(status_code=403, detail="workflow is not registered")
        if (
            registration is not None
            and registration.profile
            and registration.profile not in repo.profiles
        ):
            raise HTTPException(status_code=403, detail="workflow profile is not allowed")
        return {
            "repository": repository,
            "workflow": workflow,
            "suite": suite,
            "installation_id": request.installation_id,
            "ref": ref,
            "interval_seconds": request.interval_seconds,
            "enabled": request.enabled,
            "next_run_at": request.next_run_at,
        }

    def dispatch_due_schedules(*, now: float | None = None, limit: int = 20) -> dict[str, Any]:
        current = time.time() if now is None else float(now)
        receipts: list[dict[str, Any]] = []
        for due in store.due_test_schedules(now=current, limit=limit):
            item = {
                "repository": due["repository"],
                "workflow": due["workflow"],
                "suite": due["suite"],
                "ref": due["ref"],
                "next_run_at": due["next_run_at"],
            }
            repository = str(due["repository"])
            workflow = str(due["workflow"])
            suite = str(due["suite"])
            ref = str(due["ref"])
            slot = float(due["next_run_at"])
            correlation_id = hashlib.sha256(
                f"{repository}|{workflow}|{suite}|{ref}|{slot:.6f}".encode()
            ).hexdigest()
            intent: dict[str, Any] | None = None
            existed = False
            claimed_for_dispatch = False
            provider_call_started = False
            try:
                repo = policy.repository(repository)
                registration = policy.test_workflow(
                    repository, workflow, suite=None if suite == "all" else suite, ref=ref
                )
                if repo.workflow_registration_present and registration is None:
                    raise PolicyError("workflow is not registered")
                expected_sha = _resolve_ref_sha(due, repo)
                if store.active_test_job_count() >= 1:
                    item.update(
                        {
                            "status": "runner_blocked",
                            "error": "test execution capacity is full",
                            "correlation_id": correlation_id,
                        }
                    )
                    receipts.append(item)
                    continue
                intent, existed = store.create_dispatch_intent(
                    intent_id=str(uuid.uuid4()),
                    repository=repository,
                    workflow=workflow,
                    suite=suite,
                    ref=ref,
                    installation_id=int(due["installation_id"]),
                    slot=slot,
                    expected_sha=expected_sha,
                    correlation_id=correlation_id,
                )
                item["correlation_id"] = correlation_id
                if existed:
                    intent_state = str(intent.get("state"))
                    if intent_state == "pending" and store.begin_dispatch_intent(str(intent["id"])):
                        # A concurrent tick created the outbox row but did not
                        # claim it yet.  This caller may safely become the
                        # single provider caller.
                        existed = False
                        claimed_for_dispatch = True
                    elif intent_state == "dispatched":
                        store.advance_test_schedule(
                            repository=repository,
                            workflow=workflow,
                            suite=suite,
                            ref=ref,
                            due_at=slot,
                            now=current,
                        )
                        item["status"] = "dispatched"
                    elif intent_state == "ambiguous":
                        item.update(
                            {
                                "status": "ambiguous",
                                "error": "provider dispatch requires reconciliation",
                            }
                        )
                    else:
                        item.update(
                            {
                                "status": "error",
                                "error": str(
                                    intent.get("last_error") or "dispatch intent is unresolved"
                                ),
                            }
                        )
                    if existed:
                        receipts.append(item)
                        continue
                if (
                    not claimed_for_dispatch
                    and store.begin_dispatch_intent(str(intent["id"])) is None
                ):
                    item.update(
                        {"status": "ambiguous", "error": "dispatch claimed by another tick"}
                    )
                    receipts.append(item)
                    continue
                inputs = None if suite == "all" else {"qdev_suite": suite}
                if repo.workflow_registration_present:
                    inputs = dict(inputs or {})
                    inputs["qdev_correlation_id"] = correlation_id
                provider_call_started = True
                response = github.dispatch_workflow(
                    int(due["installation_id"]), repository, workflow, ref, inputs
                )
            except GitHubError as error:
                detail = str(error)
                if intent is not None and not existed:
                    store.update_dispatch_intent(
                        str(intent["id"]),
                        state="ambiguous" if provider_call_started else "error",
                        error=detail,
                    )
                store.record_test_schedule_error(
                    repository=repository,
                    workflow=workflow,
                    suite=suite,
                    ref=ref,
                    error=detail,
                )
                item.update(
                    {
                        "status": "ambiguous" if provider_call_started else "error",
                        "error": detail[:400],
                    }
                )
            except (PolicyError, ValueError) as error:
                detail = str(error)
                if intent is not None and not existed:
                    store.update_dispatch_intent(str(intent["id"]), state="error", error=detail)
                store.record_test_schedule_error(
                    repository=repository,
                    workflow=workflow,
                    suite=suite,
                    ref=ref,
                    error=detail,
                )
                item.update({"status": "error", "error": detail[:400]})
            else:
                provider_response = response if isinstance(response, dict) else {}
                store.update_dispatch_intent(
                    str(intent["id"]), state="dispatched", provider_response=provider_response
                )
                store.advance_test_schedule(
                    repository=repository,
                    workflow=workflow,
                    suite=suite,
                    ref=ref,
                    due_at=slot,
                    now=current,
                )
                item["status"] = "dispatched"
            receipts.append(item)
        return {
            "schema": "qdev-test-scheduler-tick-v1",
            "generated_at": current,
            "items": receipts,
            "dispatched": sum(item["status"] == "dispatched" for item in receipts),
            "errors": sum(
                item["status"] in {"error", "runner_blocked", "ambiguous"} for item in receipts
            ),
        }

    async def scheduler_loop() -> None:
        while True:
            try:
                await asyncio.to_thread(reconcile_dispatch_intents, now=None, limit=20)
                await asyncio.to_thread(reconcile_retry_attempts, now=None, limit=20)
                await asyncio.to_thread(dispatch_due_schedules, now=None, limit=20)
            except asyncio.CancelledError:
                raise
            except Exception:
                LOGGER.exception("test scheduler tick failed")
            await asyncio.sleep(settings.scheduler_poll_seconds)

    @asynccontextmanager
    async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
        task = asyncio.create_task(scheduler_loop()) if settings.scheduler_enabled else None
        try:
            yield
        finally:
            if task is not None:
                task.cancel()
                with suppress(asyncio.CancelledError):
                    await task

    app = FastAPI(
        title="QDev runner broker",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.store = store
    app.state.policy = policy
    app.state.github = github
    app.state.github_actions_oidc_verifier = github_actions_oidc_verifier
    app.state.operations = operations
    release_store: ReleaseStore | None = None

    def require_worker(
        token: str | None,
        *,
        claim_scope: ClaimScope | None = None,
        client_certificate_sha256: str | None = None,
    ) -> None:
        if not worker_authenticated(
            token,
            settings.worker_token,
            claim_scope=claim_scope,
            client_certificate_sha256=client_certificate_sha256,
        ):
            raise HTTPException(status_code=401, detail="worker authentication failed")

    def require_operator(token: str | None) -> OperationStore:
        if operations is None or settings.operator_token is None:
            raise HTTPException(status_code=503, detail="operator control plane is not configured")
        if not token or not secrets.compare_digest(token, settings.operator_token):
            raise HTTPException(status_code=401, detail="operator authentication failed")
        return operations

    def require_operator_mtls(identity: str | None) -> None:
        """Require the fleet-operations client identity for control-plane audits."""
        if identity != "qdev-fleet-operations":
            raise HTTPException(
                status_code=403,
                detail="qdev-fleet-operations mTLS identity required",
            )

    def require_operator_session(token: str | None, mtls_identity: str | None) -> OperationStore:
        """Require the controller-issued fleet-operations session on every operator route.

        The edge authenticates the client certificate and injects this identity;
        the bearer token alone is deliberately never sufficient for a capacity
        operation or an audit receipt that can authorize one.
        """

        operation_store = require_operator(token)
        require_operator_mtls(mtls_identity)
        return operation_store

    def release_policy() -> ReleaseLanePolicy:
        try:
            return ReleaseLanePolicy(settings.release_lanes_path)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=503, detail="release-lane policy is unavailable"
            ) from error

    def fleet_bootstrap_policy() -> FleetBootstrapPolicy:
        try:
            return FleetBootstrapPolicy(
                settings.fleet_bootstrap_policy_path,
                settings.release_lanes_path,
            )
        except FleetBootstrapError as error:
            raise HTTPException(
                status_code=503, detail="fleet bootstrap policy is unavailable"
            ) from error

    def managed_registry() -> ManagedRegistry:
        try:
            return ManagedRegistry(settings.managed_registry_path)
        except ManagedRegistryError as error:
            raise HTTPException(
                status_code=503, detail="managed registry is unavailable"
            ) from error

    def admin_platform_ledger() -> AdminPlatformLedger:
        try:
            return AdminPlatformLedger(settings.admin_platform_ledger_path)
        except AdminPlatformLedgerError as error:
            raise HTTPException(
                status_code=503, detail="admin platform ledger is unavailable"
            ) from error

    def managed_release_ledger() -> ManagedReleaseLedger:
        try:
            return ManagedReleaseLedger(settings.managed_release_ledger_path)
        except ManagedReleaseLedgerError as error:
            raise HTTPException(
                status_code=503, detail="managed release ledger is unavailable"
            ) from error

    def release_state() -> ReleaseStore:
        nonlocal release_store
        if release_store is None:
            try:
                release_store = ReleaseStore(settings.release_jobs_root)
            except OSError as error:
                raise HTTPException(
                    status_code=503, detail="release-lane durable state is unavailable"
                ) from error
            app.state.release_store = release_store
        return release_store

    def require_release_mtls(identity: str | None, expected: str) -> None:
        if not identity or not secrets.compare_digest(identity, expected):
            raise HTTPException(status_code=403, detail="release-lane mTLS identity required")

    def stored_heartbeat(record: dict[str, Any]) -> HostHeartbeatRequest:
        fields = {
            "schema",
            "release_lane",
            "project_id",
            "placement",
            "state",
            "release_lock",
            "capacity_free_gib",
            "active_release",
            "rollback",
            "bootstrap",
        }
        try:
            heartbeat_data = {
                name: record.get(name, False) if name == "bootstrap" else record[name]
                for name in fields
            }
            return HostHeartbeatRequest.model_validate(heartbeat_data)
        except (KeyError, ValueError) as error:
            raise HTTPException(
                status_code=409, detail="host-agent heartbeat is invalid"
            ) from error

    def ready_host_agent(lane: ReleaseLane) -> None:
        state = release_state()
        record = state.fresh_agent(lane)
        if record is None:
            raise HTTPException(status_code=409, detail="host-agent heartbeat is missing or stale")
        try:
            heartbeat = stored_heartbeat(record)
            validate_host_heartbeat(heartbeat, lane)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=409, detail="host-agent preflight is not ready"
            ) from error
        if heartbeat.capacity_free_gib < lane.minimum_free_gib:
            raise HTTPException(
                status_code=409, detail="host-agent capacity is below release minimum"
            )

    def current_worker(worker_name: str) -> tuple[dict[str, Any], dict[str, Any]]:
        snapshot = store.health()
        worker = next(
            (item for item in snapshot["workers"] if item["name"] == worker_name),
            None,
        )
        if worker is None:
            raise HTTPException(status_code=404, detail="worker not registered")
        return worker, _worker_audit(
            worker,
            float(snapshot["now"]),
            operations=operations,
        )

    def bound_scope_for_job(
        job: dict[str, Any],
        scope_id: str | None,
        certificate_sha256: str | None,
    ) -> ClaimScope | None:
        """Validate the immutable scope-to-job binding for active callbacks."""
        if scope_id is None:
            if job.get("claim_scope_id") is not None:
                raise HTTPException(status_code=403, detail="claim scope required")
            return None
        if str(job.get("claim_scope_id") or "") != scope_id.strip():
            raise HTTPException(status_code=403, detail="claim scope job binding rejected")
        try:
            claim_scope = resolve_bound_claim_scope(
                settings.claim_scopes_path,
                scope_id,
                worker_name=str(job["worker_name"]),
                job_id=int(job["job_id"]),
                repository=str(job["repository"]),
                head_sha=str(job["head_sha"]),
                profile=str(job["profile"]),
                run_id=int(job["run_id"]),
                attempt=_job_attempt(job),
            )
        except ClaimScopeError as error:
            LOGGER.warning("rejected bound claim scope for job=%s: %s", job["job_id"], error)
            raise HTTPException(status_code=403, detail="claim scope rejected") from error
        require_worker(
            None,
            claim_scope=claim_scope,
            client_certificate_sha256=certificate_sha256,
        )
        return claim_scope

    def bound_scope_for_heartbeat(
        request: HeartbeatRequest, certificate_sha256: str | None
    ) -> ClaimScope | None:
        """Authenticate a scoped lease without extending its claim window.

        Scope expiry closes admission to new jobs.  A worker may nevertheless
        continue to heartbeat a job it claimed before expiry: every reported
        job must still have the same immutable scope binding, exact identity,
        profile, and certificate.  This avoids requeueing a legitimate job
        solely because its bounded admission scope elapsed while it ran.
        """
        if request.active_jobs != len(set(request.active_job_ids)):
            raise HTTPException(status_code=422, detail="active job count does not match IDs")
        # An idle worker authenticates with its enrolled worker credential.  Its
        # configured scope is a target for the next controller-issued FIFO
        # admission, not proof that a now-expired scope should be renewed.
        if request.claim_scope_id is None or not request.active_job_ids:
            return None

        scopes: list[ClaimScope] = []
        for job_id in request.active_job_ids:
            job = store.job(job_id)
            if job is None or str(job.get("status")) not in {"claimed", "running"}:
                raise HTTPException(status_code=403, detail="active claim scope job is absent")
            scope = bound_scope_for_job(
                job,
                request.claim_scope_id,
                certificate_sha256,
            )
            if scope is None:
                raise HTTPException(status_code=403, detail="claim scope required")
            scopes.append(scope)
        claim_scope = scopes[0]
        if any(scope.scope_id != claim_scope.scope_id for scope in scopes):
            raise HTTPException(status_code=403, detail="claim scope job binding rejected")
        if claim_scope.tier != request.tier:
            raise HTTPException(status_code=403, detail="claim scope worker binding rejected")
        if claim_scope.worker_name != request.worker_name:
            raise HTTPException(status_code=403, detail="claim scope worker binding rejected")
        expected_profiles = {job.profile for job in claim_scope.jobs}
        requested_profiles = set(request.profiles)
        if claim_scope.schema == SCHEMA_V2:
            profiles_match = expected_profiles.issubset(requested_profiles)
        else:
            profiles_match = requested_profiles == expected_profiles and len(
                request.profiles
            ) == len(expected_profiles)
        if not profiles_match:
            raise HTTPException(status_code=403, detail="claim scope profiles rejected")
        return claim_scope

    @app.get("/health")
    def health() -> dict[str, Any]:
        data = store.health()
        audited_workers = []
        for worker in data["workers"]:
            audit = _worker_audit(
                worker,
                float(data["now"]),
                operations=operations,
            )
            audited_workers.append(
                worker
                | {
                    "capacity_allowed": audit["capacity_allowed"],
                    "available": bool(
                        audit["capacity_allowed"] and int(worker["slots_available"]) > 0
                    ),
                }
            )
        fresh_workers = [
            worker for worker in audited_workers if data["now"] - worker["last_seen"] < 90
        ]
        primary = [worker for worker in fresh_workers if worker["tier"] == "primary"]
        reserve = [worker for worker in fresh_workers if worker["tier"] == "reserve"]
        return {
            "ok": True,
            "schema": "qdev-runner-health-v1",
            "pending": data["jobs"].get("pending", 0),
            "active_workers": len(fresh_workers),
            "primary_present": bool(primary),
            "reserve_present": bool(reserve),
            "primary_capacity_allowed": any(worker["capacity_allowed"] for worker in primary),
            "reserve_capacity_allowed": any(worker["capacity_allowed"] for worker in reserve),
            "primary_slots_available": sum(worker["slots_available"] for worker in primary),
            "reserve_slots_available": sum(worker["slots_available"] for worker in reserve),
            "primary_available": any(worker["available"] for worker in primary),
            "reserve_available": any(worker["available"] for worker in reserve),
            "profile_admission": profile_admission_health(
                pending_jobs=store.pending_jobs(),
                fresh_workers=fresh_workers,
                policy=policy,
            ),
            "controller_release": controller_release_status(
                settings.controller_release_status_path
            ),
        }

    @app.post("/internal/v1/release-hosts/{placement}/heartbeat")
    def release_host_heartbeat(
        placement: str,
        request: HostHeartbeatRequest,
        x_qdev_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_host(placement, request.release_lane)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release placement is not allowlisted"
            ) from error
        require_release_mtls(x_qdev_mtls_identity, lane.host_agent_mtls_identity)
        try:
            validate_host_heartbeat(request, lane)
            record = release_state().record_heartbeat(
                lane, request, identity=lane.host_agent_mtls_identity
            )
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=422, detail="host-agent heartbeat was rejected"
            ) from error
        return {
            "schema": "qdev-release-host-agent-heartbeat-receipt-v1",
            "status": "recorded",
            "release_lane": lane.name,
            "placement": lane.placement,
            "received_at": record["received_at"],
        }

    @app.post("/internal/v1/releases/qaz-tours", status_code=202)
    def admit_qaz_tours_release(
        request: ReleaseAdmissionRequest,
        x_qdev_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane("qdev-release-qaz-tours")
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=503, detail="qaz-tours release lane is unavailable"
            ) from error
        require_release_mtls(x_qdev_mtls_identity, lane.client_mtls_identity)
        try:
            validate_candidate(request, lane)
            validate_controller_claim(request, lane, signing_key=settings.controller_claim_key)
        except ReleaseLaneError as error:
            raise HTTPException(status_code=422, detail="release candidate was rejected") from error
        ready_host_agent(lane)
        try:
            job, _idempotent = release_state().admit(request, lane)
        except ReleaseLaneError as error:
            raise HTTPException(status_code=409, detail="release lane is busy") from error
        return admission_receipt(job)

    @app.get("/internal/v1/release-hosts/{placement}/jobs/next", response_model=None)
    def next_release_host_job(
        placement: str,
        release_lane: str | None = Query(default=None),
        x_qdev_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any] | Response:
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_host(placement, release_lane)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release placement is not allowlisted"
            ) from error
        require_release_mtls(x_qdev_mtls_identity, lane.host_agent_mtls_identity)
        ready_host_agent(lane)
        job = release_state().next_job(lane)
        if job is None:
            return Response(status_code=204)
        return {
            "schema": "qdev-release-host-agent-job-v1",
            "release_id": job["release_id"],
            "release_lane": lane.name,
            "project_id": lane.project_id,
            "placement": lane.placement,
            "source_sha": job["source_sha"],
            "artifact_digest": job["artifact_digest"],
            "artifact_ref": job["artifact_ref"],
            "lease_id": job["lease_id"],
            "fence": job["fence"],
        }

    @app.post("/internal/v1/release-hosts/{placement}/jobs/{release_id}/complete")
    @app.post("/internal/v1/release-hosts/{placement}/jobs/{release_id}/receipt")
    def complete_release_host_job(
        placement: str,
        release_id: str,
        receipt: dict[str, Any],
        release_lane: str | None = Query(default=None),
        x_qdev_mtls_identity: str | None = Header(default=None),
        x_qdev_release_lease: str | None = Header(default=None),
        x_qdev_release_fence: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_host(placement, release_lane)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release placement is not allowlisted"
            ) from error
        require_release_mtls(x_qdev_mtls_identity, lane.host_agent_mtls_identity)
        try:
            job = release_state().complete(
                lane,
                release_id,
                receipt,
                lease_id=x_qdev_release_lease,
                fence=x_qdev_release_fence,
            )
        except ReleaseLaneError as error:
            raise HTTPException(status_code=409, detail="runtime receipt was rejected") from error
        return dict(job["runtime_receipt"])

    @app.get("/internal/v1/release-hosts/{placement}/jobs/{release_id}")
    def release_host_job_status(
        placement: str,
        release_id: str,
        x_qdev_mtls_identity: str | None = Header(default=None),
        x_qdev_release_lease: str | None = Header(default=None),
        x_qdev_release_fence: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Return controller state to a host agent reconciling a lost response."""
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_placement(placement)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release placement is not allowlisted"
            ) from error
        require_release_mtls(x_qdev_mtls_identity, lane.host_agent_mtls_identity)
        job = release_state().job(lane, release_id)
        if job is None:
            raise HTTPException(status_code=404, detail="release job was not found")
        # A managed host may reconcile only the operation it was admitted for.
        # Legacy lanes retain their historical status-only read path, while
        # v2 lanes require both durable fencing values to prevent a stale
        # worker from learning or acting on another attempt's outcome.
        if lane.canonical_repository is not None:
            if (
                not x_qdev_release_lease
                or not x_qdev_release_fence
                or x_qdev_release_lease != job.get("lease_id")
                or x_qdev_release_fence != job.get("fence")
            ):
                raise HTTPException(status_code=409, detail="release lease is stale")
        elif (x_qdev_release_lease is not None and x_qdev_release_lease != job.get("lease_id")) or (
            x_qdev_release_fence is not None and x_qdev_release_fence != job.get("fence")
        ):
            raise HTTPException(status_code=409, detail="release lease is stale")
        return {
            "schema": "qdev-controller-release-status-v1",
            "release_id": release_id,
            "status": job["status"],
            "release_lane": lane.name,
            "project_id": lane.project_id,
            "placement": lane.placement,
            "source_sha": job["source_sha"],
            "artifact_digest": job["artifact_digest"],
            "artifact_ref": job["artifact_ref"],
            "runtime_receipt": job.get("runtime_receipt"),
            "rollback_receipt": job.get("rollback_receipt"),
        }

    @app.post("/internal/v1/release-hosts/{placement}/jobs/{release_id}/rollback")
    def rollback_release_host_job(
        placement: str,
        release_id: str,
        receipt: dict[str, Any],
        x_qdev_mtls_identity: str | None = Header(default=None),
        x_qdev_release_lease: str | None = Header(default=None),
        x_qdev_release_fence: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_placement(placement)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release placement is not allowlisted"
            ) from error
        require_release_mtls(x_qdev_mtls_identity, lane.host_agent_mtls_identity)
        try:
            job = release_state().rollback(
                lane,
                release_id,
                receipt,
                lease_id=x_qdev_release_lease,
                fence=x_qdev_release_fence,
            )
        except ReleaseLaneError as error:
            raise HTTPException(status_code=409, detail="rollback receipt was rejected") from error
        return dict(job["rollback_receipt"])

    @app.get("/internal/v1/releases/qaz-tours/{release_id}")
    def qaz_tours_release_status(
        release_id: str,
        x_qdev_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane("qdev-release-qaz-tours")
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=503, detail="qaz-tours release lane is unavailable"
            ) from error
        require_release_mtls(x_qdev_mtls_identity, lane.client_mtls_identity)
        job = release_state().job(lane, release_id)
        if job is None:
            raise HTTPException(status_code=404, detail="release receipt was not found")
        return {
            "schema": "qdev-controller-release-status-v1",
            "release_id": job["release_id"],
            "status": job["status"],
            "release_lane": job["release_lane"],
            "project_id": job["project_id"],
            "placement": job["placement"],
            "source_sha": job["source_sha"],
            "artifact_digest": job["artifact_digest"],
            "artifact_ref": job["artifact_ref"],
            "runtime_receipt": job.get("runtime_receipt"),
        }

    @app.post("/internal/v1/releases/{lane_name}", status_code=202)
    def admit_release(
        lane_name: str,
        request: ReleaseAdmissionRequest,
        x_qdev_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane(lane_name)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release lane is not allowlisted"
            ) from error
        require_release_mtls(x_qdev_mtls_identity, lane.client_mtls_identity)
        try:
            validate_candidate(request, lane)
            validate_controller_claim(request, lane, signing_key=settings.controller_claim_key)
        except ReleaseLaneError as error:
            raise HTTPException(status_code=422, detail="release candidate was rejected") from error
        ready_host_agent(lane)
        try:
            job, _idempotent = release_state().admit(request, lane)
        except ReleaseLaneError as error:
            raise HTTPException(status_code=409, detail="release lane is busy") from error
        return admission_receipt(job)

    @app.get("/internal/v1/releases/{lane_name}/{release_id}")
    def release_status(
        lane_name: str,
        release_id: str,
        x_qdev_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane(lane_name)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release lane is not allowlisted"
            ) from error
        require_release_mtls(x_qdev_mtls_identity, lane.client_mtls_identity)
        job = release_state().job(lane, release_id)
        if job is None:
            raise HTTPException(status_code=404, detail="release receipt was not found")
        return {
            "schema": "qdev-controller-release-status-v1",
            "release_id": job["release_id"],
            "status": job["status"],
            "release_lane": job["release_lane"],
            "project_id": job["project_id"],
            "placement": job["placement"],
            "source_sha": job["source_sha"],
            "artifact_digest": job["artifact_digest"],
            "artifact_ref": job["artifact_ref"],
            "runtime_receipt": job.get("runtime_receipt"),
        }

    @app.get("/internal/v1/operations/controller-release")
    def operation_controller_release(
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        return operation_store.receipt(
            {
                "kind": "controller-release-audit",
                "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "controller_release": controller_release_status(
                    settings.controller_release_status_path
                ),
            }
        )

    @app.get("/internal/v1/operations/admin-platform")
    def operation_admin_platform(
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Issue the signed, read-only Admin Platform control-plane audit.

        This endpoint never advances the ledger or claims a job.  It binds the
        observed registry and ordered candidate ledger to the controller
        activation observation, and is intentionally mTLS-protected so the
        result can be used as the documented admission audit for the current
        AVDS candidate.
        """
        operation_store = require_operator(x_qdev_operator_token)
        require_operator_mtls(x_qdev_operator_mtls_identity)
        registry = managed_registry()
        ledger = admin_platform_ledger()
        active_candidate = ledger.active_candidate
        if active_candidate is None:
            raise HTTPException(
                status_code=503,
                detail="admin platform has no active candidate",
            )
        active_entry = next(entry for entry in ledger.entries if entry.entry_id == active_candidate)
        if active_entry.source_sha is None:
            raise HTTPException(
                status_code=503,
                detail="admin platform active candidate has no source SHA",
            )
        active = ledger.validate_admission(active_candidate, active_entry.source_sha)
        managed = registry.entry_for_id(active.entry_id)
        if managed is None or managed.project_id != active.project_id:
            raise HTTPException(
                status_code=503,
                detail="admin platform registry and ledger are not aligned",
            )
        controller = controller_release_status(settings.controller_release_status_path)
        return operation_store.receipt(
            {
                "kind": "admin-platform-audit",
                "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "controller_release": controller,
                "managed_registry": registry.snapshot(),
                "admin_platform_ledger": ledger.snapshot(),
                "active_candidate": active.entry_id,
                "admission": {
                    "state": "controller-release-observed",
                    "source_sha": active.source_sha,
                    "registry_entry": managed.entry_id,
                    "ledger_status": active.status,
                    "claim_scope": "controller-signed-only",
                },
            }
        )

    @app.get("/internal/v1/operations/workers")
    def operation_workers(
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        snapshot = store.health()
        observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        payload = {
            "kind": "worker-audit",
            "observed_at": observed_at,
            "workers": [
                _worker_audit(
                    worker,
                    float(snapshot["now"]),
                    operations=operation_store,
                )
                for worker in snapshot["workers"]
            ],
            "pending": int(snapshot["jobs"].get("pending", 0)),
        }
        return operation_store.receipt(payload)

    @app.post("/internal/v1/operations/fleet-bootstrap/recover-existing-worker")
    def recover_existing_worker(
        request: FleetBootstrapRecoveryRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Run one controller-owned recovery for an allowlisted existing worker.

        GitHub validation produces the signed request, but this endpoint is
        deliberately reachable only through the fleet-operations mTLS session.
        The controller supplies the policy, operation paths and recovery
        adapter; callers cannot select a host, service, executable or CA key.
        Non-completed results are signed receipts and leave durable operation
        state pending so an operator can retry after the external condition is
        repaired.
        """

        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        try:
            bootstrap_request = FleetBootstrapRequest.model_validate(request.request)
            policy_value = fleet_bootstrap_policy()
            operation_path = (
                settings.fleet_bootstrap_operation_root / f"{request.idempotency_key}.json"
            )
            receipt_path = settings.fleet_bootstrap_receipt_root / f"{request.idempotency_key}.json"
            execution = execute_existing_worker_recovery(
                policy=policy_value,
                store=BootstrapOperationStore(operation_path),
                request=bootstrap_request,
                idempotency_key=request.idempotency_key,
                active_jobs=request.active_jobs,
                adapter=settings.fleet_recovery_executable,
                timeout_seconds=request.timeout_seconds,
                receipt_path=receipt_path,
            )
        except (FleetBootstrapError, ValidationError, ValueError) as error:
            raise HTTPException(
                status_code=422,
                detail="fleet bootstrap recovery request is invalid",
            ) from error
        return operation_store.receipt(
            {
                "kind": "fleet-bootstrap-recovery",
                "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "status": execution.status,
                "operation_status": execution.operation_status,
                "idempotency_key": execution.idempotency_key,
                "request_fingerprint": execution.request_fingerprint,
                "worker_name": execution.worker_name,
                "target_id": execution.target_id,
                "service_unit": execution.service_unit,
                "active_jobs": request.active_jobs,
                "error_code": execution.error_code,
                "result": execution.result,
            }
        )

    @app.post("/internal/v1/operations/jobs/{job_id}/claim-scope")
    def issue_fifo_claim_scope(
        job_id: int,
        request: ControllerClaimRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Issue one idempotent v2 scope for the current compatible FIFO head.

        Scope issuance is deliberately separate from broker claiming: the
        enrolled worker resolves it through its ordinary claim path and claims
        the existing provider job.  This preserves exact-SHA FIFO and avoids a
        direct broker mutation from the operator endpoint.
        """

        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        if request.job_id != job_id:
            raise HTTPException(status_code=422, detail="path and payload job_id must match")
        certificate_sha256 = request.worker_certificate_sha256.lower()
        if not _SHA256_DIGEST.fullmatch(certificate_sha256):
            raise HTTPException(
                status_code=422,
                detail="worker_certificate_sha256 must be a SHA-256 digest",
            )

        worker, audit = current_worker(request.worker_name)
        if audit.get("tier") != request.tier:
            raise HTTPException(
                status_code=409,
                detail="worker tier does not match requested scope",
            )
        if not audit.get("fresh"):
            raise HTTPException(status_code=409, detail="worker heartbeat is stale")
        if int(audit.get("active_jobs") or 0) != 0:
            raise HTTPException(status_code=409, detail="worker still has active jobs")
        if int(audit.get("slots_available") or 0) < 1:
            raise HTTPException(status_code=409, detail="worker has no available slot")
        if not audit.get("capacity_allowed"):
            raise HTTPException(status_code=409, detail="worker capacity admission is closed")
        if audit.get("configured_claim_scope_id") != request.scope_id:
            raise HTTPException(
                status_code=409,
                detail="worker is not enrolled for requested claim scope",
            )

        candidate = store.job(job_id)
        if candidate is None:
            raise HTTPException(status_code=404, detail="job not found")
        if candidate.get("status") != "pending":
            raise HTTPException(status_code=409, detail="job is not pending")

        labels = _json_strings(candidate["labels_json"])
        try:
            profile = policy.profile_for_labels(str(candidate["repository"]), labels)
        except PolicyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        if profile.name not in audit.get("profiles", []):
            raise HTTPException(status_code=409, detail="worker is not registered for job profile")
        if profile.name not in audit.get("admission", {}).get("profiles", []):
            raise HTTPException(
                status_code=409,
                detail="profile admission is not confirmed for worker",
            )
        try:
            managed_entry = managed_registry().validate_claim_if_managed(
                str(candidate["repository"]), profile.name
            )
        except ManagedRegistryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        admission_ledger: str | None = None
        admin_platform_ledger_entry: str | None = None
        managed_release_ledger_entry: str | None = None
        if managed_entry is not None:
            try:
                admission_ledger = managed_entry.admission_ledger
                if admission_ledger == "admin-platform":
                    admin_platform_ledger().validate_admission(
                        managed_entry.entry_id, str(candidate["head_sha"])
                    )
                    admin_platform_ledger_entry = managed_entry.entry_id
                else:
                    managed_release_ledger().validate_admission(
                        managed_entry.entry_id, str(candidate["head_sha"])
                    )
                    managed_release_ledger_entry = managed_entry.entry_id
            except (AdminPlatformLedgerError, ManagedReleaseLedgerError) as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

        profile_queue: list[dict[str, Any]] = []
        fifo_skipped: list[dict[str, Any]] = []
        queued_admin_platform_ledger: AdminPlatformLedger | None = None
        for queued in store.pending_jobs():
            try:
                queued_profile = policy.profile_for_labels(
                    str(queued["repository"]), _json_strings(queued["labels_json"])
                )
            except PolicyError:
                continue
            if queued_profile.name == profile.name:
                try:
                    queued_managed = managed_registry().validate_claim_if_managed(
                        str(queued["repository"]), queued_profile.name
                    )
                except ManagedRegistryError:
                    # Keep malformed managed rows in the strict queue.  They
                    # must not be silently bypassed by this observational
                    # stale-candidate filter.
                    profile_queue.append(queued)
                    continue
                if (
                    queued_managed is not None
                    and queued_managed.admission_ledger == "admin-platform"
                ):
                    if queued_admin_platform_ledger is None:
                        try:
                            queued_admin_platform_ledger = admin_platform_ledger()
                        except AdminPlatformLedgerError as exc:
                            raise HTTPException(
                                status_code=503,
                                detail=f"admin platform ledger unavailable: {exc}",
                            ) from exc
                    admitted, reason = queued_admin_platform_ledger.classify_admission(
                        queued_managed.entry_id, str(queued["head_sha"])
                    )
                    if not admitted:
                        # This row is retained as evidence in the signed
                        # receipt, but cannot hold an unrelated profile FIFO.
                        # Direct requests for the same managed row still use
                        # validate_admission above and remain fail-closed.
                        assert reason is not None
                        fifo_skipped.append(
                            {
                                "job_id": int(queued["job_id"]),
                                "repository": str(queued["repository"]),
                                "run_id": int(queued["run_id"]),
                                "head_sha": str(queued["head_sha"]),
                                "profile": queued_profile.name,
                                "managed_registry_entry": queued_managed.entry_id,
                                "reason": reason,
                            }
                        )
                        continue
                profile_queue.append(queued)
        if not profile_queue or int(profile_queue[0]["job_id"]) != job_id:
            raise HTTPException(status_code=409, detail="job is not the FIFO head for its profile")

        attempt = _job_attempt(candidate)
        if attempt is None:
            raise HTTPException(status_code=409, detail="provider attempt is unavailable")

        try:
            scopes = load_claim_scopes(settings.claim_scopes_path)
        except ClaimScopeError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"claim scope configuration unavailable: {exc}",
            ) from exc
        existing = scopes.get(request.scope_id)
        replaced_expired_scope = False
        rolled_over_terminal_scope = False
        rebound_legacy_scope = False
        retained_jobs: tuple[ScopedJob, ...] = ()
        if existing is not None:
            same_scope = (
                existing.schema == SCHEMA_V2
                and existing.worker_name == request.worker_name
                and existing.tier == request.tier
                and existing.host == request.host
                and existing.runner == request.runner
                and existing.correlation_id == request.correlation_id
                and existing.worker_certificate_sha256 == certificate_sha256
                and existing.permits(
                    job_id=job_id,
                    repository=str(candidate["repository"]),
                    head_sha=str(candidate["head_sha"]),
                    profile=profile.name,
                    run_id=int(candidate["run_id"]),
                    attempt=attempt,
                )
            )
            if same_scope:
                if existing.expires_at > datetime.now(UTC):
                    payload = {
                        "kind": "fifo-claim-scope-issued",
                        "operator_session": "verified",
                        "mtls_identity": x_qdev_operator_mtls_identity,
                        "idempotent": True,
                        "claim_scope": claim_scope_mapping(existing),
                        "immutable_tuple": {
                            "repository": candidate["repository"],
                            "run_id": candidate["run_id"],
                            "job_id": job_id,
                            "attempt": attempt,
                            "exact_sha": candidate["head_sha"],
                            "profile": profile.name,
                            "runner": request.runner,
                            "host": request.host,
                        },
                        "fifo_skipped": fifo_skipped,
                        "managed_registry_entry": (
                            managed_entry.entry_id if managed_entry else None
                        ),
                        "admission_ledger": admission_ledger,
                        "admin_platform_ledger_entry": admin_platform_ledger_entry,
                        "managed_release_ledger_entry": managed_release_ledger_entry,
                        "worker": audit,
                    }
                    return operation_store.receipt(payload)
                replaced_expired_scope = True
            elif (
                # A legacy v2 document issued before certificate binding was
                # enforced cannot be claimed: the worker-side claim endpoint
                # intentionally requires the mTLS digest.  It is safe to
                # replace only when it already permits this *same* immutable
                # tuple and retains every non-certificate binding field.
                # This is not a FIFO advance or a profile/runner swap.
                existing.schema == SCHEMA_V2
                and existing.worker_certificate_sha256 is None
                and existing.worker_name == request.worker_name
                and existing.tier == request.tier
                and existing.host == request.host
                and existing.runner == request.runner
                and existing.permits(
                    job_id=job_id,
                    repository=str(candidate["repository"]),
                    head_sha=str(candidate["head_sha"]),
                    profile=profile.name,
                    run_id=int(candidate["run_id"]),
                    attempt=attempt,
                )
            ):
                rebound_legacy_scope = True
            elif (
                existing.schema == SCHEMA_V2
                and existing.worker_name == request.worker_name
                and existing.tier == request.tier
                and existing.host == request.host
                and existing.runner == request.runner
                and existing.worker_certificate_sha256 == certificate_sha256
                and existing.expires_at > datetime.now(UTC)
            ):
                # A v2 scope may advance only after every earlier immutable
                # tuple it contains has a provider-terminal local record.  This
                # lets one enrolled worker progress through profile FIFO without
                # widening scope, requeueing, or changing the worker binding.
                previous = [store.job(item.job_id) for item in existing.jobs]
                if any(
                    item is None
                    or str(item.get("status")) not in {"completed", "failed", "rejected"}
                    for item in previous
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="claim scope has non-terminal immutable tuple",
                    )
                rolled_over_terminal_scope = True
                retained_jobs = existing.jobs
            elif not (
                existing.schema == SCHEMA_V2
                and existing.worker_name == request.worker_name
                and existing.tier == request.tier
                and existing.host == request.host
                and existing.runner == request.runner
                and existing.worker_certificate_sha256 == certificate_sha256
                and existing.expires_at <= datetime.now(UTC)
            ):
                raise HTTPException(
                    status_code=409,
                    detail="claim scope ID is already bound to another tuple",
                )
            else:
                replaced_expired_scope = True

        scoped_job = ScopedJob(
            job_id=job_id,
            repository=str(candidate["repository"]),
            exact_sha=str(candidate["head_sha"]),
            profile=profile.name,
            run_id=int(candidate["run_id"]),
            attempt=attempt,
        )
        scope = ClaimScope(
            schema=SCHEMA_V2,
            scope_id=request.scope_id,
            worker_name=request.worker_name,
            tier=request.tier,
            repository=str(candidate["repository"]),
            head_sha=str(candidate["head_sha"]),
            host=request.host,
            runner=request.runner,
            correlation_id=request.correlation_id,
            worker_certificate_sha256=certificate_sha256,
            expires_at=datetime.now(UTC) + timedelta(seconds=request.duration_seconds),
            jobs=retained_jobs + (scoped_job,),
        )
        try:
            upsert_claim_scope(settings.claim_scopes_path, scope)
        except ClaimScopeError as exc:
            raise HTTPException(
                status_code=503,
                detail=f"claim scope configuration unavailable: {exc}",
            ) from exc

        payload = {
            "kind": "fifo-claim-scope-issued",
            "operator_session": "verified",
            "mtls_identity": x_qdev_operator_mtls_identity,
            "idempotent": False,
            "replaced_expired_scope": replaced_expired_scope,
            "rolled_over_terminal_scope": rolled_over_terminal_scope,
            "rebound_legacy_scope": rebound_legacy_scope,
            "claim_scope": claim_scope_mapping(scope),
            "immutable_tuple": {
                "repository": candidate["repository"],
                "run_id": candidate["run_id"],
                "job_id": job_id,
                "attempt": attempt,
                "exact_sha": candidate["head_sha"],
                "profile": profile.name,
                "runner": request.runner,
                "host": request.host,
            },
            "fifo_skipped": fifo_skipped,
            "managed_registry_entry": managed_entry.entry_id if managed_entry else None,
            "admission_ledger": admission_ledger,
            "admin_platform_ledger_entry": admin_platform_ledger_entry,
            "managed_release_ledger_entry": managed_release_ledger_entry,
            "worker": audit,
        }
        return operation_store.receipt(payload)

    @app.post("/internal/v1/operations/workers/{worker_name}/capacity-override")
    def create_capacity_override(
        worker_name: str,
        request: CapacityOverrideRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        worker, audit = current_worker(worker_name)
        registered_profiles = _json_strings(worker.get("profiles_json"))
        requested_profiles = tuple(dict.fromkeys(request.profiles))
        repository_name = request.repository.strip().lower()
        if not audit["fresh"]:
            raise HTTPException(status_code=409, detail="worker heartbeat is stale")
        if audit["active_jobs"] != 0:
            raise HTTPException(status_code=409, detail="worker has an active task")
        if not requested_profiles or not set(requested_profiles).issubset(registered_profiles):
            raise HTTPException(status_code=409, detail="requested profile is not registered")
        if not set(requested_profiles).issubset(policy.profiles):
            raise HTTPException(status_code=409, detail="requested profile is not in policy")
        try:
            policy.repository(repository_name)
        except PolicyError as error:
            raise HTTPException(status_code=409, detail="repository is not in policy") from error
        if len(requested_profiles) != 1:
            raise HTTPException(
                status_code=409,
                detail="repository-scoped capacity override requires exactly one profile",
            )
        baseline = audit["baseline_capacity"]
        raw = audit["raw_capacity"]
        blockers = {str(value) for value in baseline.get("blockers", [])}
        if not blockers or not blockers.issubset(DISK_ONLY_BLOCKERS):
            raise HTTPException(status_code=409, detail="capacity blocker is not disk-only")
        try:
            disk_free_gib = float(raw["disk_free_gib"])
            disk_used_pct = float(raw["disk_used_pct"])
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(
                status_code=409,
                detail="raw capacity evidence is incomplete",
            ) from error
        profile_name = requested_profiles[0].lower()
        profile_disk_mb = policy.repository_profile_disk_mb.get(
            (repository_name, profile_name),
            policy.profiles[requested_profiles[0]].disk_mb,
        )
        profile_headroom_gib = profile_disk_mb / 1024
        required_free_gib = request.min_disk_free_gib + profile_headroom_gib
        if disk_free_gib < required_free_gib:
            raise HTTPException(
                status_code=409,
                detail=("measured free space does not cover the hard floor and profile headroom"),
            )
        if disk_used_pct >= request.max_disk_used_pct:
            raise HTTPException(
                status_code=409,
                detail="measured disk use exceeds override ceiling",
            )
        if (
            operation_store.active(
                worker_name,
                registered_profiles=registered_profiles,
            )
            is not None
        ):
            raise HTTPException(status_code=409, detail="capacity override is already active")
        directive = operation_store.create_capacity_override(
            worker_name=worker_name,
            repository=repository_name,
            profiles=requested_profiles,
            min_disk_free_gib=request.min_disk_free_gib,
            max_disk_used_pct=request.max_disk_used_pct,
            owner=request.owner,
            reason=request.reason,
            duration_seconds=request.duration_seconds,
        )
        payload = {
            "kind": "capacity-override-created",
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "worker_audit": audit,
            "operation": directive.model_dump(mode="json", by_alias=True),
            "required_free_gib": round(required_free_gib, 3),
        }
        return operation_store.receipt(payload)

    @app.delete("/internal/v1/operations/workers/{worker_name}/capacity-override")
    def cancel_capacity_override(
        worker_name: str,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        worker, audit = current_worker(worker_name)
        directive = operation_store.cancel_capacity_override(
            worker_name,
            registered_profiles=_json_strings(worker.get("profiles_json")),
        )
        payload = {
            "kind": "capacity-override-cancelled",
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "worker_audit": audit,
            "operation": (directive.model_dump(mode="json", by_alias=True) if directive else None),
        }
        return operation_store.receipt(payload)

    @app.get("/internal/v1/operations/jobs/stale")
    def audit_stale_jobs(
        worker_timeout_seconds: int = Query(default=300, ge=300, le=3600),
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        candidates = [_stale_job_tuple(row) for row in store.stale_jobs(worker_timeout_seconds)]
        payload = {
            "kind": "stale-job-audit",
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "worker_timeout_seconds": worker_timeout_seconds,
            "provider_reconciliation_required": True,
            "candidates": candidates,
        }
        return operation_store.receipt(payload)

    @app.post("/internal/v1/operations/jobs/{job_id}/recover-stale")
    def recover_stale_job(
        job_id: int,
        request: StaleJobRecoveryRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        row = next(
            (
                candidate
                for candidate in store.stale_jobs(request.worker_timeout_seconds)
                if int(candidate["job_id"]) == job_id
            ),
            None,
        )
        if row is None:
            raise HTTPException(status_code=409, detail="job is not stale")
        immutable_job = _stale_job_tuple(row)
        installation_id = int(row["installation_id"])
        repository = str(row["repository"])
        try:
            remote_job = github.workflow_job(installation_id, repository, job_id)
            remote_run = github.workflow_run(installation_id, repository, int(row["run_id"]))
            provider_tuple = {
                "run_id": int(remote_run.get("id") or 0),
                "job_run_id": int(remote_job.get("run_id") or 0),
                "job_id": int(remote_job.get("id") or 0),
                "attempt": int(remote_run.get("run_attempt") or 0),
                "exact_sha": str(remote_run.get("head_sha") or ""),
            }
            expected_tuple = {
                "run_id": immutable_job["run_id"],
                "job_run_id": immutable_job["run_id"],
                "job_id": immutable_job["job_id"],
                "attempt": immutable_job["attempt"],
                "exact_sha": immutable_job["exact_sha"],
            }
            if provider_tuple != expected_tuple:
                raise HTTPException(
                    status_code=409,
                    detail="provider immutable tuple does not match the queued job",
                )
            provider_status = str(remote_job.get("status") or "unknown")
            provider_conclusion = remote_job.get("conclusion")
            if provider_status == "completed":
                conclusion = str(provider_conclusion or "unknown")
                store.complete_from_webhook(job_id, conclusion)
                action = "completed-from-provider"
            elif provider_status == "in_progress":
                raise HTTPException(
                    status_code=409,
                    detail="provider reports the job is still in progress",
                )
            elif provider_status == "queued":
                run_conclusion = completed_run_conclusion(remote_run)
                if run_conclusion is not None:
                    store.complete_from_webhook(job_id, run_conclusion)
                    action = "completed-from-parent-run"
                elif not store.release_stale_job(
                    job_id,
                    f"operator recovery: {request.reason}",
                    request.worker_timeout_seconds,
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="stale job changed during provider reconciliation",
                    )
                else:
                    action = "released-preserving-fifo"
            else:
                raise HTTPException(
                    status_code=409,
                    detail=f"provider job state is not recoverable: {provider_status}",
                )
        except GitHubError as error:
            raise HTTPException(
                status_code=503,
                detail="provider reconciliation failed",
            ) from error
        payload = {
            "kind": "stale-job-recovery",
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "owner": request.owner,
            "reason": request.reason,
            "immutable_job": immutable_job,
            "provider": {
                **provider_tuple,
                "status": provider_status,
                "conclusion": provider_conclusion,
                "run_status": str(remote_run.get("status") or "unknown"),
                "run_conclusion": remote_run.get("conclusion"),
            },
            "action": action,
            "fifo_preserved": True,
        }
        return operation_store.receipt(payload)

    @app.post("/github/workflow-job")
    async def workflow_job(
        request: Request,
        x_hub_signature_256: str | None = Header(default=None),
        x_github_delivery: str | None = Header(default=None),
        x_github_event: str | None = Header(default=None),
    ) -> Response:
        body = await request.body()
        if not verify_signature(settings.webhook_secret, body, x_hub_signature_256):
            raise HTTPException(status_code=401, detail="invalid webhook signature")
        if x_github_event == "ping":
            return Response(status_code=204)
        if x_github_event != "workflow_job" or not x_github_delivery:
            raise HTTPException(status_code=400, detail="unsupported webhook event")
        payload = json.loads(body)
        action = payload.get("action")
        raw_job = payload.get("workflow_job") or {}
        repository = payload.get("repository") or {}
        try:
            policy.repository(str(repository["full_name"]))
        except (KeyError, PolicyError) as error:
            LOGGER.warning("rejected webhook: %s", error)
            return Response(status_code=202)
        job_id = int(raw_job["id"])
        if action == "completed":
            store.complete_from_webhook(job_id, str(raw_job.get("conclusion") or "unknown"))
            store.complete_retry_for_provider_job(
                job_id, str(raw_job.get("conclusion") or "unknown")
            )
            return Response(status_code=204)
        if action != "queued":
            return Response(status_code=204)
        try:
            queued = QueuedJob(
                delivery_id=x_github_delivery,
                job_id=job_id,
                run_id=int(raw_job["run_id"]),
                repository=str(repository["full_name"]),
                repository_id=int(repository["id"]),
                installation_id=int(payload["installation"]["id"]),
                labels=tuple(str(label) for label in raw_job.get("labels", [])),
                head_sha=str(raw_job["head_sha"]),
                head_branch=str(raw_job.get("head_branch") or ""),
                payload=payload,
            )
            policy.profile_for_labels(queued.repository, queued.labels)
            store.enqueue(queued)
            if is_registered_test_workflow(store.job(job_id) or {}):
                store.link_retry_provider_job(
                    repository=queued.repository,
                    expected_sha=queued.head_sha,
                    provider_run_id=queued.run_id,
                    provider_job_id=queued.job_id,
                )
        except (KeyError, TypeError, ValueError, PolicyError) as error:
            LOGGER.warning("rejected queued job: %s", error)
            return Response(status_code=202)
        return Response(status_code=202)

    @app.post("/internal/v1/jobs/claim", response_model=None)
    def claim_job(
        request: ClaimRequest,
        x_qdev_worker_token: str | None = Header(default=None),
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any] | Response:
        try:
            claim_scope = resolve_claim_scope(
                settings.claim_scopes_path,
                request.claim_scope_id,
                request.worker_name,
                request.tier,
                tuple(request.profiles),
            )
        except ClaimScopeError as error:
            LOGGER.warning("rejected claim scope for worker=%s: %s", request.worker_name, error)
            raise HTTPException(status_code=403, detail="claim scope rejected") from error
        require_worker(
            x_qdev_worker_token,
            claim_scope=claim_scope,
            client_certificate_sha256=x_qdev_client_certificate_sha256,
        )
        active_directive = (
            operations.active(
                request.worker_name,
                registered_profiles=tuple(policy.profiles),
            )
            if operations is not None
            else None
        )
        supplied_override = bool(request.capacity_directive_id or request.capacity_repository)
        if supplied_override and active_directive is None:
            raise HTTPException(status_code=403, detail="capacity override is not active")
        if active_directive is not None and (
            request.capacity_directive_id != active_directive.operation_id
            or (request.capacity_repository or "").lower() != active_directive.repository.lower()
            or tuple(request.profiles) != active_directive.profiles
        ):
            raise HTTPException(status_code=403, detail="capacity override binding rejected")
        repository = active_directive.repository if active_directive is not None else None
        claimed = store.claim(
            request.worker_name,
            tuple(request.profiles),
            tier=request.tier,
            disk_free_gib=request.disk_free_gib,
            min_disk_free_gib=request.min_disk_free_gib,
            profile_disk_mb={name: profile.disk_mb for name, profile in policy.profiles.items()},
            repository_profile_disk_mb=policy.repository_profile_disk_mb,
            claim_scope=claim_scope,
            repository=repository,
        )
        if claimed is None:
            return Response(status_code=204)
        job_id = int(claimed["job_id"])
        try:
            labels = tuple(json.loads(claimed["labels_json"]))
            profile = policy.profile_for_labels(claimed["repository"], labels)
            if claim_scope is not None and not claim_scope.permits(
                job_id,
                claimed["repository"],
                claimed["head_sha"],
                profile.name,
                run_id=int(claimed["run_id"]),
                attempt=_job_attempt(claimed),
            ):
                # Store.claim() already enforces the same immutable binding.
                # If a concurrent invariant violation is ever observed, retain
                # an auditable terminal record instead of silently requeueing
                # and changing FIFO position.
                store.set_status(job_id, "rejected", "claim scope binding invariant violation")
                raise HTTPException(status_code=403, detail="claim scope rejected")
            run = github.workflow_run(
                int(claimed["installation_id"]), claimed["repository"], int(claimed["run_id"])
            )
            policy.authorize_run(claimed["repository"], profile, run)
            if conclusion := completed_run_conclusion(run):
                store.complete_from_webhook(job_id, conclusion)
                return Response(status_code=204)
            remote_job = github.workflow_job(
                int(claimed["installation_id"]), claimed["repository"], job_id
            )
            if str(remote_job.get("head_sha") or "").lower() != str(claimed["head_sha"]).lower():
                store.set_status(job_id, "rejected", "GitHub job SHA differs from queued SHA")
                raise PolicyError("GitHub job SHA differs from queued SHA")
            remote_run_id = remote_job.get("run_id")
            if remote_run_id is None or int(remote_run_id) != int(claimed["run_id"]):
                store.set_status(job_id, "rejected", "GitHub job run differs from queued run")
                raise PolicyError("GitHub job run differs from queued run")
            if str(remote_job.get("status")) != "queued":
                store.complete_from_webhook(
                    job_id,
                    str(remote_job.get("conclusion") or remote_job.get("status") or "unknown"),
                )
                return Response(status_code=204)
            runner_name = f"qdev-{claimed['repository'].split('/')[-1]}-{job_id}"[:63]
            jit_config = github.generate_jit_config(
                int(claimed["installation_id"]),
                claimed["repository"],
                runner_name,
                tuple(dict.fromkeys(labels)),
            )
            store.set_status(job_id, "running", f"runner={runner_name}")
            token = artifact_token(
                settings.worker_token, claimed["repository"], claimed["head_sha"], job_id
            )
            response: dict[str, Any] = {
                "schema": "qdev-runner-job-v1",
                "job_id": job_id,
                "repository": claimed["repository"],
                "head_sha": claimed["head_sha"],
                "runner_name": runner_name,
                "jit_config": jit_config,
                "profile": {
                    "name": profile.name,
                    "cpu": profile.cpu,
                    "memory_mb": profile.memory_mb,
                    "disk_mb": profile.disk_mb,
                    "pids_limit": profile.pids_limit,
                    "timeout_minutes": profile.timeout_minutes,
                },
                "artifact": {
                    "base_url": "https://ci.qdev.run/artifacts",
                    "token": token,
                },
            }
            if registry := registry_credentials(settings, profile.name):
                response["registry"] = registry
            return response
        except PolicyError as error:
            store.set_status(job_id, "rejected", str(error))
            raise HTTPException(status_code=403, detail="job rejected by policy") from error
        except GitHubError as error:
            store.requeue_infrastructure(job_id, str(error))
            raise HTTPException(
                status_code=503, detail="GitHub JIT configuration unavailable"
            ) from error

    @app.post("/internal/v1/jobs/complete")
    def complete_job(
        request: CompletionRequest,
        x_qdev_worker_token: str | None = Header(default=None),
        x_qdev_claim_scope_id: str | None = Header(default=None),
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> Response:
        job = store.job(request.job_id)
        if job is None:
            require_worker(x_qdev_worker_token)
            return Response(status_code=204)
        claim_scope = bound_scope_for_job(
            job, x_qdev_claim_scope_id, x_qdev_client_certificate_sha256
        )
        if claim_scope is None:
            require_worker(x_qdev_worker_token)
        elif str(job["worker_name"]) != request.worker_name:
            raise HTTPException(status_code=403, detail="claim scope worker binding rejected")
        if request.runner_exit_code != 0:
            result = (
                f"worker={request.worker_name} exit={request.runner_exit_code} {request.detail}"
            )
            if request.infrastructure_error:
                store.requeue_infrastructure(request.job_id, result)
            else:
                store.fail_if_active(request.job_id, result)
            return Response(status_code=204)
        try:
            remote_job = github.workflow_job(
                int(job["installation_id"]), str(job["repository"]), request.job_id
            )
        except GitHubError:
            LOGGER.warning("could not reconcile successful worker exit job=%s", request.job_id)
            return Response(status_code=204)
        remote_status = str(remote_job.get("status") or "unknown")
        if remote_status == "queued":
            try:
                run = github.workflow_run(
                    int(job["installation_id"]),
                    str(job["repository"]),
                    int(job["run_id"]),
                )
            except GitHubError:
                LOGGER.warning("could not reconcile parent run job=%s", request.job_id)
                return Response(status_code=204)
            if conclusion := completed_run_conclusion(run):
                store.complete_from_webhook(request.job_id, conclusion)
            else:
                store.requeue_infrastructure(
                    request.job_id, "runner exited before GitHub assigned the job"
                )
        elif remote_status == "completed":
            store.complete_from_webhook(
                request.job_id, str(remote_job.get("conclusion") or "unknown")
            )
        return Response(status_code=204)

    @app.get("/internal/v1/jobs/{job_id}/status")
    def job_status(
        job_id: int,
        x_qdev_worker_token: str | None = Header(default=None),
        x_qdev_claim_scope_id: str | None = Header(default=None),
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        job = store.job(job_id)
        if job is None:
            require_worker(x_qdev_worker_token)
            raise HTTPException(status_code=404, detail="job not found")
        if (
            bound_scope_for_job(job, x_qdev_claim_scope_id, x_qdev_client_certificate_sha256)
            is None
        ):
            require_worker(x_qdev_worker_token)
        status = str(job["status"])
        if status in {"claimed", "running"}:
            try:
                remote_job = github.workflow_job(
                    int(job["installation_id"]), str(job["repository"]), job_id
                )
                if str(remote_job.get("status")) == "completed":
                    store.complete_from_webhook(
                        job_id, str(remote_job.get("conclusion") or "unknown")
                    )
                    status = "completed"
                elif str(remote_job.get("status")) == "queued":
                    run = github.workflow_run(
                        int(job["installation_id"]),
                        str(job["repository"]),
                        int(job["run_id"]),
                    )
                    if conclusion := completed_run_conclusion(run):
                        store.complete_from_webhook(job_id, conclusion)
                        status = "completed"
            except GitHubError:
                LOGGER.warning("could not reconcile active job=%s", job_id)
        return {"schema": "qdev-runner-job-status-v1", "job_id": job_id, "status": status}

    @app.post("/internal/v1/workers/heartbeat")
    def heartbeat(
        request: HeartbeatRequest,
        x_qdev_worker_token: str | None = Header(default=None),
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        claim_scope = bound_scope_for_heartbeat(request, x_qdev_client_certificate_sha256)
        require_worker(
            x_qdev_worker_token,
            claim_scope=claim_scope,
            client_certificate_sha256=x_qdev_client_certificate_sha256,
        )
        store.heartbeat(
            request.worker_name,
            tuple(request.profiles),
            request.active_jobs,
            tuple(request.active_job_ids),
            request.detail | {"tier": request.tier},
        )
        directive = (
            operations.active(
                request.worker_name,
                registered_profiles=tuple(request.profiles),
            )
            if operations is not None
            else None
        )
        return {
            "schema": "qdev-worker-directives-v1",
            "capacity_override": (
                directive.model_dump(mode="json", by_alias=True) if directive else None
            ),
        }

    @app.put("/artifacts/{owner}/{repo}/{sha}/{job_id}/{artifact_attempt}/{artifact_suite}/{name}")
    @app.put("/artifacts/{owner}/{repo}/{sha}/{job_id}/{name}")
    async def put_artifact(
        owner: str,
        repo: str,
        sha: str,
        job_id: int,
        name: str,
        request: Request,
        x_qdev_artifact_token: str | None = Header(default=None),
        x_qdev_github_oidc: str | None = Header(default=None),
        x_qdev_sha256: str | None = Header(default=None),
        x_qdev_test_suite: str | None = Header(default=None),
        x_qdev_test_attempt: str | None = Header(default=None),
        x_qdev_test_workflow: str | None = Header(default=None),
        x_qdev_test_format: str | None = Header(default=None),
        x_qdev_test_profile: str | None = Header(default=None),
        artifact_attempt: int | None = None,
        artifact_suite: str | None = None,
    ) -> dict[str, Any]:
        full_name = f"{_safe_segment(owner)}/{_safe_segment(repo)}"
        safe_sha = _safe_segment(sha)
        safe_name = _safe_segment(name)
        if artifact_attempt is not None and artifact_attempt < 1:
            raise HTTPException(status_code=422, detail="invalid test attempt")
        path_suite = None
        if artifact_suite is not None:
            try:
                path_suite = _safe_segment(artifact_suite)
            except HTTPException:
                raise HTTPException(status_code=422, detail="invalid test suite") from None
        job = None
        if bool(x_qdev_artifact_token) == bool(x_qdev_github_oidc):
            raise HTTPException(status_code=401, detail="exactly one artifact identity is required")
        if x_qdev_artifact_token:
            job = store.job(job_id)
            if not artifact_job_is_active(job, full_name, safe_sha, job_id):
                raise HTTPException(status_code=401, detail="artifact credentials expired")
            expected_token = artifact_token(settings.worker_token, full_name, safe_sha, job_id)
            if not secrets.compare_digest(x_qdev_artifact_token, expected_token):
                raise HTTPException(status_code=401, detail="artifact authentication failed")
        else:
            try:
                github_actions_oidc_verifier.verify(
                    x_qdev_github_oidc or "",
                    repository=full_name,
                    sha=safe_sha,
                    run_id=job_id,
                )
            except GitHubActionsOIDCError as error:
                raise HTTPException(
                    status_code=401, detail="artifact OIDC authentication failed"
                ) from error
        raw_content_length = request.headers.get("content-length")
        try:
            content_length = int(raw_content_length) if raw_content_length is not None else None
        except ValueError as error:
            raise HTTPException(status_code=400, detail="invalid content length") from error
        if content_length is not None and content_length < 0:
            raise HTTPException(status_code=400, detail="invalid content length")
        report_format = (x_qdev_test_format or "").strip().lower()
        suffix = safe_name.rsplit(".", 1)[-1].lower() if "." in safe_name else ""
        if not report_format:
            report_format = {
                "xml": "junit" if safe_name.lower().startswith("junit") else "cobertura",
                "info": "lcov",
            }.get(suffix, "qdev-test-run" if safe_name == "qdev-test-run.json" else "")
        report_like = bool(
            report_format in {"qdev-test-run", "json", "junit", "lcov", "cobertura"}
            or x_qdev_test_suite
            or x_qdev_test_workflow
        )
        maximum = (
            MAX_REPORT_BYTES if report_like else min(settings.max_artifact_bytes, 250 * 1024 * 1024)
        )
        if content_length is not None and content_length > maximum:
            raise HTTPException(status_code=413, detail="artifact is larger than the allowed limit")
        body = await request.body()
        if len(body) > maximum:
            raise HTTPException(status_code=413, detail="artifact is larger than the allowed limit")
        digest = hashlib.sha256(body).hexdigest()
        if not x_qdev_sha256 or not secrets.compare_digest(x_qdev_sha256, digest):
            raise HTTPException(status_code=422, detail="artifact checksum mismatch")
        if not report_like:
            target = settings.artifact_root / owner / repo / safe_sha / str(job_id) / safe_name
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_name(f".{target.name}.{uuid.uuid4().hex}.tmp")
            temporary.write_bytes(body)
            os.chmod(temporary, 0o600)
            temporary.replace(target)
            return {"schema": "qdev-artifact-v1", "sha256": digest, "size": len(body)}
        if job is None:
            raise HTTPException(
                status_code=422,
                detail="test reports require a provider-bound job identity",
            )
        try:
            job_payload = json.loads(str(job["payload_json"]))
        except (TypeError, json.JSONDecodeError) as error:
            raise HTTPException(
                status_code=422, detail="stored workflow payload is invalid"
            ) from error
        workflow_job = job_payload.get("workflow_job") if isinstance(job_payload, dict) else None
        if not isinstance(workflow_job, dict):
            workflow_job = {}
        raw_report: dict[str, Any] | None = None
        if report_format in {"qdev-test-run", "json"}:
            try:
                decoded = json.loads(body)
            except (json.JSONDecodeError, UnicodeDecodeError) as error:
                raise HTTPException(status_code=422, detail="invalid JSON test report") from error
            if not isinstance(decoded, dict):
                raise HTTPException(status_code=422, detail="test report must be a JSON object")
            raw_report = decoded
        suite = (x_qdev_test_suite or path_suite or (raw_report or {}).get("suite") or "").strip()
        if not suite:
            raise HTTPException(status_code=422, detail="test suite is required")
        try:
            suite = _safe_segment(suite)
        except HTTPException:
            raise HTTPException(status_code=422, detail="invalid test suite") from None
        if path_suite and x_qdev_test_suite and path_suite != x_qdev_test_suite.strip():
            raise HTTPException(status_code=422, detail="test suite does not match artifact path")
        workflow_path = (
            (x_qdev_test_workflow or "").strip()
            or str(workflow_job.get("path") or "").strip()
            or str((raw_report or {}).get("workflow") or "").strip()
        )
        if workflow_path:
            workflow_path = _safe_workflow_path(workflow_path, explicitly_registered=True)
        elif report_like:
            raise HTTPException(status_code=422, detail="test workflow is required")
        try:
            attempt = int(
                x_qdev_test_attempt
                or artifact_attempt
                or workflow_job.get("run_attempt")
                or (raw_report or {}).get("attempt")
                or 1
            )
        except (TypeError, ValueError) as error:
            raise HTTPException(status_code=422, detail="invalid test attempt") from error
        if attempt < 1:
            raise HTTPException(status_code=422, detail="invalid test attempt")
        run_id = int(job.get("run_id") or workflow_job.get("run_id") or 0)
        repository_id = int(job.get("repository_id") or 0)
        profile = (x_qdev_test_profile or str(job.get("profile") or "")).strip()
        try:
            repo_policy = policy.repository(full_name)
            registration = (
                policy.test_workflow(
                    full_name,
                    workflow_path,
                    suite=suite,
                    profile=profile or None,
                    ref=str(job.get("head_branch") or repo_policy.default_branch),
                )
                if workflow_path
                else None
            )
            if repo_policy.workflow_registration_present and registration is None:
                raise PolicyError("test workflow is not registered")
        except PolicyError as error:
            raise HTTPException(
                status_code=403, detail="workflow or suite is not registered"
            ) from error
        strict_identity = bool(repo_policy.workflow_registration_present)
        remote_job = _remote_workflow_job(
            job,
            workflow=workflow_path or None,
            run_id=run_id or None,
            attempt=attempt,
            repository_id=repository_id or None,
        )
        remote_attempt = remote_job.get("run_attempt", remote_job.get("run_attempt_number"))
        if remote_attempt is not None:
            try:
                attempt = int(remote_attempt)
            except (TypeError, ValueError) as error:
                raise HTTPException(
                    status_code=422, detail="GitHub job attempt is malformed"
                ) from error
            if attempt < 1:
                raise HTTPException(status_code=422, detail="invalid test attempt")
        if not run_id and remote_job.get("run_id") is not None:
            run_id = int(remote_job["run_id"])
        remote_repository_id = remote_job.get("repository_id")
        if remote_repository_id is None and isinstance(remote_job.get("repository"), dict):
            remote_repository_id = remote_job["repository"].get("id")
        remote_repository = remote_job.get("repository")
        remote_full_name = (
            str(remote_repository.get("full_name") or "").strip()
            if isinstance(remote_repository, dict)
            else str(remote_job.get("repository_full_name") or "").strip()
        )
        if not repository_id and remote_repository_id is not None:
            repository_id = int(remote_repository_id)
        if strict_identity:
            remote_path = str(
                remote_job.get("path") or remote_job.get("workflow_path") or ""
            ).strip()
            if (
                not str(remote_job.get("head_sha") or "")
                or remote_job.get("run_id") is None
                or remote_attempt is None
                or remote_repository_id is None
                or not remote_full_name
                or not remote_path
            ):
                raise HTTPException(status_code=422, detail="GitHub job identity is incomplete")
        expected: dict[str, Any] = {
            "repository": full_name,
            "commit_sha": safe_sha,
            "job_id": job_id,
        }
        if strict_identity:
            if not workflow_path or not profile or run_id < 1 or repository_id < 1:
                raise HTTPException(status_code=422, detail="workflow identity is incomplete")
            expected.update(
                {
                    "run_id": run_id,
                    "repository_id": repository_id,
                    "suite": suite,
                    "workflow": workflow_path,
                    "attempt": attempt,
                    "profile": profile,
                }
            )
        context = {
            "repository": full_name,
            "commit_sha": safe_sha,
            "suite": suite,
            "workflow": workflow_path or str((raw_report or {}).get("workflow") or safe_name),
            "job_id": job_id,
            "attempt": attempt,
            "run_id": run_id or None,
            "repository_id": repository_id or None,
            "profile": profile or None,
            "environment": f"self-hosted:{profile}" if profile else "self-hosted",
        }
        normalized_report: dict[str, Any] | None = None
        is_test_result = report_format in {"qdev-test-run", "json", "junit"}
        try:
            if report_format in {"qdev-test-run", "json"}:
                assert raw_report is not None
                if strict_identity:
                    for key, value in {
                        "run_id": run_id,
                        "repository_id": repository_id,
                        "profile": profile,
                        "workflow": workflow_path,
                        "suite": suite,
                        "attempt": attempt,
                    }.items():
                        raw_report.setdefault(key, value)
                normalized_report = normalize_test_run(raw_report, expected=expected)
            elif report_format == "junit":
                normalized_report = parse_junit(body, context=context, report_path=safe_name)
                normalized_report = normalize_test_run(normalized_report, expected=expected)
            elif report_format == "lcov":
                normalized_report = parse_lcov(body, context=context, report_path=safe_name)
                normalized_report = normalize_test_run(normalized_report, expected=expected)
                is_test_result = False
            elif report_format == "cobertura":
                normalized_report = parse_cobertura(body, context=context, report_path=safe_name)
                normalized_report = normalize_test_run(normalized_report, expected=expected)
                is_test_result = False
            elif report_like:
                raise TestReportError("unsupported test report format")
        except (AssertionError, TestReportError, json.JSONDecodeError, UnicodeDecodeError) as error:
            raise HTTPException(status_code=422, detail=f"invalid test report: {error}") from error
        report_descriptor = {
            "path": safe_name,
            "format": report_format or "artifact",
            "sha256": digest,
            "size": len(body),
            "url": f"/artifacts/{owner}/{repo}/{safe_sha}/{job_id}/{attempt}/{suite}/{safe_name}",
        }
        if normalized_report is not None:
            # Only the controller may mint report URLs.  Client supplied
            # external links are intentionally discarded.
            normalized_report = normalize_test_run(
                normalized_report | {"reports": [report_descriptor]}, expected=expected
            )
        target = (
            settings.artifact_root
            / owner
            / repo
            / safe_sha
            / str(job_id)
            / str(attempt)
            / suite
            / safe_name
        )
        target_existed = target.exists()
        if target_existed:
            existing_digest = hashlib.sha256(target.read_bytes()).hexdigest()
            if not secrets.compare_digest(existing_digest, digest):
                raise HTTPException(
                    status_code=409, detail="conflicting artifact for this test attempt"
                )
        if not target_existed:
            target.parent.mkdir(parents=True, exist_ok=True)
            temporary = target.with_suffix(target.suffix + ".tmp")
            temporary.write_bytes(body)
            os.chmod(temporary, 0o600)
            temporary.replace(target)
        response: dict[str, Any] = {
            "schema": "qdev-artifact-v1",
            "sha256": digest,
            "size": len(body),
            "report": report_descriptor if report_like else None,
        }
        if normalized_report is not None:
            source_payload = normalized_report
            try:
                source_row, source_idempotent = store.record_test_report(
                    source_payload,
                    report=report_descriptor,
                    storage_path=str(target),
                    size=len(body),
                    sha256=digest,
                )
                report_digest_value = report_digest(source_payload)
                if is_test_result:
                    row, idempotent = store.record_test_run(source_payload, report_digest_value)
                else:
                    row, idempotent = None, source_idempotent
            except ValueError as error:
                if not target_existed:
                    target.unlink(missing_ok=True)
                raise HTTPException(status_code=409, detail=str(error)) from error
            response["test_report"] = {
                "id": source_row["id"],
                "idempotent": source_idempotent,
                "format": report_format,
            }
            if row is not None:
                response["test_run"] = {
                    "id": row["id"],
                    "digest": row["digest"],
                    "idempotent": idempotent,
                    "status": row["test_status"],
                }
                # A delivered receipt proves that the requested rerun reached
                # the controller.  Clear the one-shot legacy guard while the
                # immutable attempt row remains in history.
                store.clear_test_retry(job_id)
        return response

    @app.get("/operator/v1/test-runs")
    def operator_test_runs(
        request: Request,
        repository: str | None = None,
        status: str | None = None,
        limit: int = 50,
        offset: int = 0,
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator = require_test_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        if status is not None and status not in {"passed", "failed", "not_run"}:
            raise HTTPException(status_code=400, detail="invalid test status")
        runs, total = store.list_test_runs(
            repository=repository,
            status=status,
            limit=max(1, min(limit, 200)),
            offset=max(0, offset),
        )
        return {
            "schema": "qdev-test-runs-v1",
            "operator": operator,
            "items": runs,
            "total": total,
            "limit": max(1, min(limit, 200)),
            "offset": max(0, offset),
        }

    @app.get("/operator/v1/test-runs/{job_id}")
    def operator_test_run_detail(
        job_id: int,
        request: Request,
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> dict[str, Any]:
        require_test_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        job = store.job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        return {
            "schema": "qdev-test-run-detail-v1",
            "job": job,
            "runs": store.test_runs_for_job(job_id),
            "reports": store.test_reports_for_job(job_id),
            "retry_attempts": store.retry_attempts_for_job(job_id),
        }

    @app.get("/operator/v1/test-summary")
    def operator_test_summary(
        request: Request,
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> dict[str, Any]:
        require_test_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        return store.test_summary(policy.test_catalog())

    @app.get("/operator/v1/dispatch-intents")
    def operator_dispatch_intents(
        request: Request,
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator = require_test_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        return {
            "schema": "qdev-test-dispatch-intents-v1",
            "operator": operator,
            "items": store.list_dispatch_intents(),
        }

    @app.post("/operator/v1/dispatch-intents/reconcile")
    def operator_reconcile_dispatch_intents(
        request: Request,
        tick: SchedulerTickRequest | None = None,
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator = require_test_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        require_same_origin(request)
        result = reconcile_dispatch_intents(
            now=tick.now if tick else None,
            limit=tick.limit if tick else 20,
        )
        result["operator"] = operator
        return result

    @app.post("/operator/v1/retry-attempts/reconcile")
    def operator_reconcile_retry_attempts(
        request: Request,
        tick: SchedulerTickRequest | None = None,
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator = require_test_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        require_same_origin(request)
        result = reconcile_retry_attempts(
            now=tick.now if tick else None,
            limit=tick.limit if tick else 20,
        )
        result["operator"] = operator
        return result

    @app.get("/operator/v1/test-schedules")
    def operator_test_schedules(
        request: Request,
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator = require_test_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        return {
            "schema": "qdev-test-schedules-v1",
            "operator": operator,
            "items": store.list_test_schedules(),
        }

    @app.put("/operator/v1/test-schedules")
    def operator_upsert_test_schedule(
        request: TestScheduleRequest,
        http_request: Request,
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator = require_test_operator(
            http_request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        require_same_origin(http_request)
        values = _validate_schedule(request)
        schedule = store.upsert_test_schedule(**values)
        return {
            "schema": "qdev-test-schedule-v1",
            "operator": operator,
            "schedule": schedule,
        }

    @app.post("/internal/v1/scheduler/tick")
    def scheduler_tick(
        request: SchedulerTickRequest,
        x_qdev_worker_token: str | None = Header(default=None),
    ) -> dict[str, Any]:
        require_worker(x_qdev_worker_token)
        reconciled_dispatches = reconcile_dispatch_intents(now=request.now, limit=request.limit)
        reconciled_retries = reconcile_retry_attempts(now=request.now, limit=request.limit)
        result = dispatch_due_schedules(now=request.now, limit=request.limit)
        result["reconciled_dispatches"] = reconciled_dispatches
        result["reconciled_retries"] = reconciled_retries
        return result

    @app.post("/operator/v1/jobs/{job_id}/retry")
    def operator_retry_job(
        job_id: int,
        request: Request,
        retry: RetryRequest,
        idempotency_key: str | None = Header(default=None, alias="Idempotency-Key"),
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operator = require_test_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        require_same_origin(request)
        job = store.job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        if str(job["status"]) in {"pending", "claimed", "running"}:
            raise HTTPException(status_code=409, detail="job is already active")
        if not is_registered_test_workflow(job):
            raise HTTPException(status_code=403, detail="workflow is not an allowed test workflow")
        request_id = (retry.request_id or idempotency_key or uuid.uuid4().hex).strip()
        if (
            not request_id
            or len(request_id) > 128
            or not all(char.isalnum() or char in "_.:-" for char in request_id)
            or not request_id[0].isalnum()
        ):
            raise HTTPException(status_code=422, detail="invalid retry request id")
        try:
            repo_policy = policy.repository(str(job["repository"]))
            raw_payload = json.loads(str(job["payload_json"]))
            workflow_payload = (
                raw_payload.get("workflow_job") if isinstance(raw_payload, dict) else {}
            )
            workflow_path = str((workflow_payload or {}).get("path") or "").strip()
            remote_job = _remote_workflow_job(
                job,
                workflow=workflow_path or None,
                run_id=int(job.get("run_id") or 0) or None,
                repository_id=int(job.get("repository_id") or 0) or None,
            )
            remote_attempt_raw = remote_job.get("run_attempt", remote_job.get("run_attempt_number"))
            source_attempt = int(
                remote_attempt_raw or (workflow_payload or {}).get("run_attempt") or 1
            )
            if source_attempt < 1:
                raise PolicyError("GitHub job attempt is invalid")
            source_run_id = int(job.get("run_id") or remote_job.get("run_id") or 0)
            if source_run_id < 1:
                raise PolicyError("GitHub job run is missing")
            strict_identity = bool(repo_policy.workflow_registration_present)
            if strict_identity:
                remote_repo_id = remote_job.get("repository_id")
                if remote_repo_id is None and isinstance(remote_job.get("repository"), dict):
                    remote_repo_id = remote_job["repository"].get("id")
                remote_repository = remote_job.get("repository")
                remote_full_name = (
                    str(remote_repository.get("full_name") or "").strip()
                    if isinstance(remote_repository, dict)
                    else str(remote_job.get("repository_full_name") or "").strip()
                )
                if (
                    not remote_job.get("head_sha")
                    or remote_job.get("run_id") is None
                    or remote_attempt_raw is None
                    or remote_repo_id is None
                    or not remote_full_name
                    or not workflow_path
                ):
                    raise PolicyError("GitHub job identity is incomplete")
            row, existed = store.retry_attempt(
                request_id=request_id,
                source_job_id=job_id,
                repository=str(job["repository"]),
                source_run_id=source_run_id,
                source_job_attempt=source_attempt,
                expected_sha=str(job["head_sha"]),
                requested_by=operator,
                reason=retry.reason,
            )
            if existed:
                if any(
                    str(row.get(key)) != str(value)
                    for key, value in {
                        "source_job_id": job_id,
                        "repository": str(job["repository"]),
                        "source_run_id": source_run_id,
                        "source_job_attempt": source_attempt,
                        "expected_sha": str(job["head_sha"]),
                    }.items()
                ):
                    raise HTTPException(
                        status_code=409, detail="retry request id targets another job"
                    )
                return {
                    "schema": "qdev-test-retry-v1",
                    "job_id": job_id,
                    "repository": job["repository"],
                    "commit_sha": job["head_sha"],
                    "requested_by": row.get("requested_by", operator),
                    "reason": row.get("reason", retry.reason),
                    "request_id": request_id,
                    "idempotent": True,
                    "state": row.get("state", "requested"),
                    "source_run_id": row.get("source_run_id", source_run_id),
                    "source_attempt": row.get("source_job_attempt", source_attempt),
                    "provider_response": row.get("provider_response", {}),
                    "provider_run_id": row.get("provider_run_id"),
                    "provider_job_id": row.get("provider_job_id"),
                }
            try:
                provider_result = github.rerun_job(
                    int(job["installation_id"]), str(job["repository"]), job_id
                )
            except GitHubError as error:
                provider_result = {"error": str(error)[:1000]}
                store.update_retry_attempt(
                    request_id, state="ambiguous", provider_response=provider_result
                )
                raise HTTPException(
                    status_code=503, detail="GitHub retry outcome requires reconciliation"
                ) from error
            provider_response = provider_result if isinstance(provider_result, dict) else {}
            provider_run_id = provider_response.get("run_id")
            provider_job_id = provider_response.get("job_id")
            try:
                provider_run_id = int(provider_run_id) if provider_run_id is not None else None
            except (TypeError, ValueError):
                provider_run_id = None
            try:
                provider_job_id = int(provider_job_id) if provider_job_id is not None else None
            except (TypeError, ValueError):
                provider_job_id = None
            saved = store.update_retry_attempt(
                request_id,
                state="dispatched",
                provider_response=provider_response,
                provider_run_id=provider_run_id,
                provider_job_id=provider_job_id,
            )
        except HTTPException:
            raise
        except (PolicyError, ValueError, json.JSONDecodeError) as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        return {
            "schema": "qdev-test-retry-v1",
            "job_id": job_id,
            "repository": job["repository"],
            "commit_sha": job["head_sha"],
            "requested_by": operator,
            "reason": retry.reason,
            "request_id": request_id,
            "idempotent": False,
            "state": (saved or {}).get("state", "dispatched"),
            "source_run_id": source_run_id,
            "source_attempt": source_attempt,
            "provider_response": (saved or {}).get("provider_response", provider_response),
            "provider_run_id": (saved or {}).get("provider_run_id", provider_run_id),
            "provider_job_id": (saved or {}).get("provider_job_id", provider_job_id),
        }

    return app


def main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    certificate = os.environ.get("QDEV_TLS_CERT")
    private_key = os.environ.get("QDEV_TLS_KEY")
    client_ca = os.environ.get("QDEV_TLS_CLIENT_CA")
    tls_options: dict[str, Any] = {}
    if certificate or private_key or client_ca:
        if not certificate or not private_key or not client_ca:
            raise RuntimeError("QDEV_TLS_CERT, QDEV_TLS_KEY and QDEV_TLS_CLIENT_CA are atomic")
        tls_options = {
            "ssl_certfile": certificate,
            "ssl_keyfile": private_key,
            "ssl_ca_certs": client_ca,
            "ssl_cert_reqs": ssl.CERT_REQUIRED,
        }
    uvicorn.run(
        create_app(),
        host=os.environ.get("QDEV_LISTEN_HOST", "127.0.0.1"),
        port=int(os.environ.get("PORT", "9020")),
        **tls_options,
    )


if __name__ == "__main__":
    main()
