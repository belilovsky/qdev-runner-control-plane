from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import ssl
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

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
from .github import GitHubAppClient, GitHubError
from .github_oidc import GitHubActionsArtifactOIDCVerifier, GitHubActionsOIDCError
from .managed_registry import ManagedRegistry, ManagedRegistryError
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
    validate_host_heartbeat,
)
from .settings import BrokerSettings
from .store import Store

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


def _worker_audit(worker: dict[str, Any], now: float) -> dict[str, Any]:
    detail = _json_object(worker.get("detail_json"))
    raw = _json_object(detail.get("raw_capacity"))
    baseline = _json_object(detail.get("baseline_capacity"))
    effective = _json_object(detail.get("effective_capacity"))
    profiles = _json_strings(worker.get("profiles_json"))
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
        "capacity_allowed": worker.get("capacity_allowed") is True,
        "configured_claim_scope_id": detail.get("configured_claim_scope_id"),
        "admission": {
            "allowed": worker.get("capacity_allowed") is True,
            "directive_id": detail.get("capacity_directive_id"),
            "profiles": list(_json_strings(detail.get("effective_profiles", []))),
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

    app = FastAPI(title="QDev runner broker", version="0.1.0", docs_url=None, redoc_url=None)
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

    def release_policy() -> ReleaseLanePolicy:
        try:
            return ReleaseLanePolicy(settings.release_lanes_path)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=503, detail="release-lane policy is unavailable"
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
        }
        try:
            return HostHeartbeatRequest.model_validate({name: record[name] for name in fields})
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
        return worker, _worker_audit(worker, float(snapshot["now"]))

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
        fresh_workers = [
            worker for worker in data["workers"] if data["now"] - worker["last_seen"] < 90
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
            lane = policy_value.lane_for_placement(placement)
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
        x_qdev_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any] | Response:
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_placement(placement)
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
        }

    @app.post("/internal/v1/release-hosts/{placement}/jobs/{release_id}/complete")
    def complete_release_host_job(
        placement: str,
        release_id: str,
        receipt: dict[str, Any],
        x_qdev_mtls_identity: str | None = Header(default=None),
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
            job = release_state().complete(lane, release_id, receipt)
        except ReleaseLaneError as error:
            raise HTTPException(status_code=409, detail="runtime receipt was rejected") from error
        return dict(job["runtime_receipt"])

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

    @app.get("/internal/v1/operations/controller-release")
    def operation_controller_release(
        x_qdev_operator_token: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator(x_qdev_operator_token)
        return operation_store.receipt(
            {
                "kind": "controller-release-audit",
                "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "controller_release": controller_release_status(
                    settings.controller_release_status_path
                ),
            }
        )

    @app.get("/internal/v1/operations/workers")
    def operation_workers(
        x_qdev_operator_token: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator(x_qdev_operator_token)
        snapshot = store.health()
        observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
        payload = {
            "kind": "worker-audit",
            "observed_at": observed_at,
            "workers": [
                _worker_audit(worker, float(snapshot["now"])) for worker in snapshot["workers"]
            ],
            "pending": int(snapshot["jobs"].get("pending", 0)),
        }
        return operation_store.receipt(payload)

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

        operation_store = require_operator(x_qdev_operator_token)
        if request.job_id != job_id:
            raise HTTPException(status_code=422, detail="path and payload job_id must match")
        if x_qdev_operator_mtls_identity != "qdev-fleet-operations":
            raise HTTPException(
                status_code=403,
                detail="qdev-fleet-operations mTLS identity required",
            )
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
        if managed_entry is not None:
            try:
                admin_platform_ledger().validate_admission(
                    managed_entry.entry_id, str(candidate["head_sha"])
                )
            except AdminPlatformLedgerError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

        profile_queue: list[dict[str, Any]] = []
        for queued in store.pending_jobs():
            try:
                queued_profile = policy.profile_for_labels(
                    str(queued["repository"]), _json_strings(queued["labels_json"])
                )
            except PolicyError:
                continue
            if queued_profile.name == profile.name:
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
                        "managed_registry_entry": (
                            managed_entry.entry_id if managed_entry else None
                        ),
                        "admin_platform_ledger_entry": (
                            managed_entry.entry_id if managed_entry else None
                        ),
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
            "managed_registry_entry": managed_entry.entry_id if managed_entry else None,
            "admin_platform_ledger_entry": managed_entry.entry_id if managed_entry else None,
            "worker": audit,
        }
        return operation_store.receipt(payload)

    @app.post("/internal/v1/operations/workers/{worker_name}/capacity-override")
    def create_capacity_override(
        worker_name: str,
        request: CapacityOverrideRequest,
        x_qdev_operator_token: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator(x_qdev_operator_token)
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
    ) -> dict[str, Any]:
        operation_store = require_operator(x_qdev_operator_token)
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
    ) -> dict[str, Any]:
        operation_store = require_operator(x_qdev_operator_token)
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
    ) -> dict[str, Any]:
        operation_store = require_operator(x_qdev_operator_token)
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
            store.requeue(job_id, str(error))
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
            store.fail_if_active(
                request.job_id,
                f"worker={request.worker_name} exit={request.runner_exit_code} {request.detail}",
            )
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
                store.requeue_active(request.job_id, "runner exited before GitHub assigned the job")
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
    ) -> dict[str, Any]:
        full_name = f"{_safe_segment(owner)}/{_safe_segment(repo)}"
        safe_sha = _safe_segment(sha)
        safe_name = _safe_segment(name)
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
        body = await request.body()
        if len(body) > 250 * 1024 * 1024:
            raise HTTPException(status_code=413, detail="artifact is larger than 250 MiB")
        digest = hashlib.sha256(body).hexdigest()
        if not x_qdev_sha256 or not secrets.compare_digest(x_qdev_sha256, digest):
            raise HTTPException(status_code=422, detail="artifact checksum mismatch")
        target = settings.artifact_root / owner / repo / safe_sha / str(job_id) / safe_name
        target.parent.mkdir(parents=True, exist_ok=True)
        temporary = target.with_suffix(target.suffix + ".tmp")
        temporary.write_bytes(body)
        os.chmod(temporary, 0o600)
        temporary.replace(target)
        return {"schema": "qdev-artifact-v1", "sha256": digest, "size": len(body)}

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
