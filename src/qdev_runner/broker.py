from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import secrets
import ssl
from datetime import UTC, datetime
from typing import Any, Literal

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from pydantic import BaseModel, Field

from .claim_scope import ClaimScope, ClaimScopeError, resolve_bound_claim_scope, resolve_claim_scope
from .github import GitHubAppClient, GitHubError
from .models import QueuedJob
from .operations import (
    DISK_ONLY_BLOCKERS,
    HARD_MAX_DISK_USED_PCT,
    HARD_MIN_FREE_GIB,
    MAX_OVERRIDE_SECONDS,
    OperationStore,
)
from .policy import Policy, PolicyError
from .settings import BrokerSettings
from .store import Store

LOGGER = logging.getLogger("qdev-runner-broker")


class ClaimRequest(BaseModel):
    worker_name: str
    tier: Literal["primary", "reserve"]
    claim_scope_id: str | None = None
    profiles: list[str]
    disk_free_gib: float = Field(ge=0)
    min_disk_free_gib: float = Field(ge=0)


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
    app.state.operations = operations

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
        if request.claim_scope_id is None:
            return None
        if not request.active_job_ids:
            try:
                return resolve_claim_scope(
                    settings.claim_scopes_path,
                    request.claim_scope_id,
                    request.worker_name,
                    request.tier,
                    tuple(request.profiles),
                )
            except ClaimScopeError as error:
                LOGGER.warning(
                    "rejected idle heartbeat scope for worker=%s: %s",
                    request.worker_name,
                    error,
                )
                raise HTTPException(status_code=403, detail="claim scope rejected") from error

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
        if set(request.profiles) != expected_profiles or len(request.profiles) != len(
            expected_profiles
        ):
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
        }

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
        claimed = store.claim(
            request.worker_name,
            tuple(request.profiles),
            tier=request.tier,
            disk_free_gib=request.disk_free_gib,
            min_disk_free_gib=request.min_disk_free_gib,
            profile_disk_mb={name: profile.disk_mb for name, profile in policy.profiles.items()},
            repository_profile_disk_mb=policy.repository_profile_disk_mb,
            claim_scope=claim_scope,
        )
        if claimed is None:
            return Response(status_code=204)
        job_id = int(claimed["job_id"])
        try:
            labels = tuple(json.loads(claimed["labels_json"]))
            profile = policy.profile_for_labels(claimed["repository"], labels)
            if claim_scope is not None and not claim_scope.permits(
                job_id, claimed["repository"], claimed["head_sha"], profile.name
            ):
                store.requeue(job_id, "claim scope no longer permits this job")
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
        x_qdev_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        full_name = f"{_safe_segment(owner)}/{_safe_segment(repo)}"
        safe_sha = _safe_segment(sha)
        safe_name = _safe_segment(name)
        job = store.job(job_id)
        if not artifact_job_is_active(job, full_name, safe_sha, job_id):
            raise HTTPException(status_code=401, detail="artifact credentials expired")
        expected_token = artifact_token(settings.worker_token, full_name, safe_sha, job_id)
        if not x_qdev_artifact_token or not secrets.compare_digest(
            x_qdev_artifact_token, expected_token
        ):
            raise HTTPException(status_code=401, detail="artifact authentication failed")
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
