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
import stat
import time
import uuid
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager, suppress
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal, TypeVar, cast
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .admin_platform import (
    CONTROLLER_RELEASE_SCHEMA_V2,
    AdminPlatformCandidate,
    AdminPlatformLedger,
    AdminPlatformLedgerError,
    ControllerRuntimeHealth,
    controller_runtime_health,
)
from .claim_scope import (
    MANAGED_EXACT_CANDIDATE_FIFO_EXCEPTION,
    QGEO_REPOSITORY,
    SCHEMA_V2,
    ClaimScope,
    ClaimScopeError,
    ScopedFifoSkip,
    ScopedJob,
    claim_scope_mapping,
    load_claim_scopes,
    resolve_bound_claim_scope,
    resolve_claim_scope,
    upsert_claim_scope,
)
from .controller_activation import (
    STATUS_SCHEMA as CONTROLLER_ACTIVATION_STATUS_SCHEMA,
)
from .controller_activation import (
    ControllerActivationError,
    ControllerReleaseStatus,
)
from .fleet_bootstrap import (
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
)
from .fleet_host_dispatch import FleetHostDispatchSpool
from .github import GitHubAppClient, GitHubError
from .github_oidc import GitHubActionsArtifactOIDCVerifier
from .managed_registry import ManagedRegistry, ManagedRegistryError
from .managed_release_ledger import (
    QGEO_REQUIRED_JOB_PROFILES,
    ManagedReleaseLedger,
    ManagedReleaseLedgerError,
    qgeo_dynamic_job_label,
)
from .models import (
    QueuedJob,
    RecoveryAcceptRequest,
    RecoveryAgentClaimRequest,
    RecoveryBindingsResponse,
    RecoveryOperationResponse,
    RecoveryPrepareRequest,
    RecoveryReconcileRequest,
    RecoveryStatusRequest,
    RecoverySupersedeRequest,
)
from .operations import (
    DISK_ONLY_BLOCKERS,
    HARD_MAX_DISK_USED_PCT,
    HARD_MIN_FREE_GIB,
    MAX_OVERRIDE_SECONDS,
    CapacityOverrideConflict,
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
    qgeo_artifact_provenance_from_evidence,
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
from .worker_recovery import (
    WorkerRecoveryConfigurationError,
    WorkerRecoveryController,
    WorkerRecoveryError,
)

LOGGER = logging.getLogger("qdev-runner-broker")
_CONTROLLER_RELEASE_SCHEMA = CONTROLLER_RELEASE_SCHEMA_V2
_CONTROLLER_REPOSITORY = "belilovsky/qdev-runner-control-plane"
_GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
_SHA256_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_RecoveryResult = TypeVar("_RecoveryResult")


def controller_release_status(path: Path) -> dict[str, Any]:
    """Return the measured, deliberately non-secret runtime receipt for /health.

    A signed operator receipt remains the authority for admission; the public
    projection exists solely to prevent a missing activation from looking like
    a capacity or runner failure.
    """
    runtime = controller_runtime_health(path)
    return (
        dict(runtime.receipt)
        if runtime.receipt is not None
        and runtime.state == "active"
        and runtime.receipt.get("schema") == _CONTROLLER_RELEASE_SCHEMA
        else {"schema": _CONTROLLER_RELEASE_SCHEMA, "state": "unavailable"}
    )


def controller_activation_status(path: Path) -> dict[str, Any]:
    """Return the monotonic activation/CAS ledger without conflating runtime evidence."""

    unavailable = {"schema": CONTROLLER_ACTIVATION_STATUS_SCHEMA, "state": "unavailable"}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return unavailable
    try:
        return ControllerReleaseStatus.parse(value).mapping()
    except ControllerActivationError:
        return unavailable


def worker_recovery_release_binding(path: Path) -> dict[str, Any]:
    """Project measured v2 identity into the legacy recovery digest shape."""

    status = controller_release_status(path)
    digest = status.get("release_digest")
    if (
        status.get("state") != "active"
        or not isinstance(digest, str)
        or not digest.startswith("sha256:")
    ):
        return {"state": "unavailable"}
    return {
        "state": "active",
        "revision": status["revision"],
        "release_digest": digest.removeprefix("sha256:"),
    }


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
    capacity_head_sha: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")


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
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
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
    pending_terminal_only: bool = False
    worker_timeout_seconds: int = Field(default=300, ge=300, le=3600)
    owner: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=500)


class FailedJobRecoveryRequest(BaseModel):
    owner: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=500)


class FleetBootstrapOperationRequest(BaseModel):
    """Controller-observed activation or host-agent enrolment request."""

    model_config = ConfigDict(extra="forbid")

    request: dict[str, Any] = Field(min_length=1)
    idempotency_key: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
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


class QGeoCIRegistrationRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    repository: str = Field(min_length=1, max_length=256)
    source_sha: str = Field(min_length=40, max_length=40)
    run_id: int = Field(gt=0)
    attempt: int = Field(ge=1)
    job_id: int = Field(gt=0)


class QGeoCIReconcileRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source_sha: str = Field(min_length=40, max_length=40)


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


def _release_host_dispatch_signing_key(path: Path, identity: str) -> str:
    """Resolve one managed host key without accepting key material from a request.

    Both the identity-to-file map and the selected secret must be private,
    non-symlink regular files owned by root or by the broker process.  The
    generic error deliberately prevents path, identity and secret disclosure.
    """

    def private_file(value: Path) -> str:
        try:
            if not value.is_absolute() or value.is_symlink():
                raise ReleaseLaneError("managed release dispatch key is unavailable")
            metadata = value.stat()
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid not in {0, os.geteuid()}
                or metadata.st_mode & 0o077
            ):
                raise ReleaseLaneError("managed release dispatch key is unavailable")
            return value.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as error:
            raise ReleaseLaneError("managed release dispatch key is unavailable") from error

    try:
        mapping = json.loads(private_file(path))
    except (TypeError, json.JSONDecodeError) as error:
        raise ReleaseLaneError("managed release dispatch key is unavailable") from error
    if not isinstance(mapping, dict) or any(
        not isinstance(key, str) or not isinstance(value, str) for key, value in mapping.items()
    ):
        raise ReleaseLaneError("managed release dispatch key is unavailable")
    secret_path = mapping.get(identity)
    if not isinstance(secret_path, str):
        raise ReleaseLaneError("managed release dispatch key is unavailable")
    secret = private_file(Path(secret_path)).strip()
    if not 32 <= len(secret.encode("utf-8")) <= 4096:
        raise ReleaseLaneError("managed release dispatch key is unavailable")
    return secret


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


def _pending_job_tuple(row: dict[str, Any], profile: str) -> dict[str, Any]:
    return {
        "repository": str(row.get("repository") or "").lower(),
        "run_id": int(row.get("run_id") or 0),
        "job_id": int(row.get("job_id") or 0),
        "attempt": _job_attempt(row),
        "exact_sha": str(row.get("head_sha") or "").lower(),
        "profile": profile,
        "state": "pending",
        "created_at": float(row.get("created_at") or 0),
    }


def durable_profile_heads(
    pending_jobs: list[dict[str, Any]], policy: Policy
) -> tuple[list[dict[str, Any]], list[int]]:
    """Return one immutable durable FIFO head per valid profile without mutation."""
    heads: dict[str, dict[str, Any]] = {}
    unclassified: list[int] = []
    for row in pending_jobs:
        try:
            profile = policy.profile_for_labels(
                str(row["repository"]), _json_strings(row["labels_json"])
            )
        except (KeyError, PolicyError):
            unclassified.append(int(row["job_id"]))
            continue
        heads.setdefault(profile.name, _pending_job_tuple(row, profile.name))
    return [heads[name] for name in sorted(heads)], unclassified


def _provider_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, (int, str)):
        return None
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed > 0 else None


def _provider_conclusion(value: object) -> str | None:
    if value is None:
        return None
    text = str(value).strip().lower()
    return text or None


_QGEO_PROVIDER_JOB_NAMES = {
    "lint": "lint",
    "security-source": "security-source",
    "test": "test",
    "docker-build": "docker-build",
    "contract": "qdev-runner-contract",
}
_QGEO_IGNORED_PR_JOBS = {
    ".github/workflows/ci.yml": {"docker-build": "qdev-ci-docker"},
}


class _QGeoCIObservationError(ValueError):
    """Raised when provider or durable QGeo CI evidence is not exact."""


def _qgeo_run_identity(
    provider_run: dict[str, Any],
    *,
    repository: str,
    candidate_sha: str,
    run_id: int,
    attempt: int,
    required_workflows: tuple[str, ...],
) -> dict[str, Any]:
    """Normalize one exact GitHub run without conflating PR head and checkout SHA."""

    provider_repository = provider_run.get("repository")
    if (
        _provider_int(provider_run.get("id")) != run_id
        or _provider_int(provider_run.get("run_attempt")) != attempt
        or not isinstance(provider_repository, dict)
        or provider_repository.get("full_name") != repository
    ):
        raise _QGeoCIObservationError("GitHub workflow run tuple does not match")
    workflow_path = provider_run.get("path")
    if not isinstance(workflow_path, str) or workflow_path not in required_workflows:
        raise _QGeoCIObservationError("GitHub workflow path is not required")
    event = provider_run.get("event")
    if event not in {"pull_request", "push"}:
        raise _QGeoCIObservationError("GitHub workflow event is not admitted")
    checkout_sha = provider_run.get("head_sha")
    head_branch = provider_run.get("head_branch")
    if (
        not isinstance(checkout_sha, str)
        or _GIT_REVISION.fullmatch(checkout_sha) is None
        or not isinstance(head_branch, str)
        or not head_branch
    ):
        raise _QGeoCIObservationError("GitHub workflow source identity is invalid")

    if event == "pull_request":
        pull_requests = provider_run.get("pull_requests")
        if not isinstance(pull_requests, list) or len(pull_requests) != 1:
            raise _QGeoCIObservationError("GitHub pull request identity is invalid")
        pull_request = pull_requests[0]
        if not isinstance(pull_request, dict):
            raise _QGeoCIObservationError("GitHub pull request identity is invalid")
        head = pull_request.get("head")
        base = pull_request.get("base")
        pr_number = _provider_int(pull_request.get("number"))
        if (
            not isinstance(head, dict)
            or not isinstance(base, dict)
            or pr_number is None
            or head.get("sha") != candidate_sha
            or head.get("ref") != head_branch
            or base.get("ref") != "main"
        ):
            raise _QGeoCIObservationError("GitHub pull request identity is invalid")
        head_repository = head.get("repo")
        if not isinstance(head_repository, dict) or head_repository.get("full_name") != repository:
            raise _QGeoCIObservationError("GitHub pull request repository is foreign")
        ref = f"refs/pull/{pr_number}/merge"
    else:
        if (
            checkout_sha != candidate_sha
            or head_branch != "main"
            or provider_run.get("pull_requests") not in (None, [])
        ):
            raise _QGeoCIObservationError("GitHub main push identity is invalid")
        ref = "refs/heads/main"
    provider_ref = provider_run.get("ref")
    if provider_ref is not None and provider_ref != ref:
        raise _QGeoCIObservationError("GitHub workflow ref does not match")

    status = str(provider_run.get("status") or "").lower()
    conclusion = _provider_conclusion(provider_run.get("conclusion"))
    if status not in {"queued", "in_progress", "completed"}:
        raise _QGeoCIObservationError("GitHub workflow state is not admissible")
    if status == "completed":
        if conclusion != "success":
            raise _QGeoCIObservationError("GitHub workflow run did not succeed")
    elif conclusion is not None:
        raise _QGeoCIObservationError("GitHub workflow conclusion is premature")
    return {
        "repository": repository,
        "candidate_sha": candidate_sha,
        "checkout_sha": checkout_sha,
        "run_id": str(run_id),
        "attempt": str(attempt),
        "workflow_path": workflow_path,
        "event": event,
        "ref": ref,
        "head_branch": head_branch,
        "status": status,
        "conclusion": conclusion,
    }


def _qgeo_job_selector(workflow_path: str, provider_name: object, phase: str) -> str:
    if not isinstance(provider_name, str):
        raise _QGeoCIObservationError("GitHub workflow job name is invalid")
    selectors = QGEO_REQUIRED_JOB_PROFILES.get(phase, {}).get(workflow_path, {})
    matches = [
        selector for selector in selectors if _QGEO_PROVIDER_JOB_NAMES[selector] == provider_name
    ]
    if len(matches) != 1:
        raise _QGeoCIObservationError("GitHub workflow job is not required")
    return matches[0]


def _qgeo_exact_labels(*, run_id: str, attempt: str, job_name: str, profile: str) -> list[str]:
    return sorted(
        [
            "self-hosted",
            "Linux",
            "X64",
            profile,
            qgeo_dynamic_job_label(run_id, attempt, job_name),
        ]
    )


def _exact_string_multiset(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, (list, tuple)) or any(not isinstance(item, str) for item in value):
        return None
    return tuple(sorted(value))


def _qgeo_durable_payload(
    row: dict[str, Any], *, repository: str, run: dict[str, Any], job: dict[str, Any]
) -> int:
    """Verify the signed webhook projection backing a fresh provider observation."""

    payload = _json_object(row.get("payload_json"))
    durable_repository = _json_object(payload.get("repository"))
    durable_installation = _json_object(payload.get("installation"))
    durable_job = _json_object(payload.get("workflow_job"))
    installation_id = _provider_int(row.get("installation_id"))
    repository_id = _provider_int(row.get("repository_id"))
    labels = _json_strings(row.get("labels_json"))
    provider_labels = job.get("labels")
    normalized_provider_labels = _exact_string_multiset(provider_labels)
    normalized_durable_labels = _exact_string_multiset(durable_job.get("labels"))
    if (
        payload.get("action") != "queued"
        or installation_id is None
        or repository_id is None
        or durable_repository.get("full_name") != repository
        or _provider_int(durable_repository.get("id")) != repository_id
        or _provider_int(durable_installation.get("id")) != installation_id
        or _provider_int(row.get("run_id")) != int(run["run_id"])
        or _job_attempt(row) != int(run["attempt"])
        or str(row.get("head_sha")) != run["checkout_sha"]
        or str(row.get("head_branch")) != run["head_branch"]
        or _provider_int(durable_job.get("id")) != _provider_int(job.get("id"))
        or _provider_int(durable_job.get("run_id")) != int(run["run_id"])
        or _provider_int(durable_job.get("run_attempt")) != int(run["attempt"])
        or durable_job.get("head_sha") != run["checkout_sha"]
        or durable_job.get("head_branch") != run["head_branch"]
        or durable_job.get("name") != job.get("name")
        or normalized_provider_labels is None
        or normalized_provider_labels != tuple(sorted(labels))
        or normalized_durable_labels != normalized_provider_labels
    ):
        raise _QGeoCIObservationError("durable workflow job tuple does not match")
    return installation_id


def _qgeo_job_identity(
    provider_job: dict[str, Any],
    row: dict[str, Any],
    *,
    run: dict[str, Any],
    policy: Policy,
) -> dict[str, Any]:
    selector = _qgeo_job_selector(run["workflow_path"], provider_job.get("name"), run["event"])
    profile_name = QGEO_REQUIRED_JOB_PROFILES[run["event"]][run["workflow_path"]][selector]
    expected_labels = _qgeo_exact_labels(
        run_id=run["run_id"],
        attempt=run["attempt"],
        job_name=selector,
        profile=profile_name,
    )
    labels = provider_job.get("labels")
    if not isinstance(labels, list) or any(not isinstance(item, str) for item in labels):
        raise _QGeoCIObservationError("GitHub workflow labels are invalid")
    if sorted(labels) != expected_labels or len(labels) != len(expected_labels):
        raise _QGeoCIObservationError("GitHub workflow labels do not match")
    try:
        profile = policy.profile_for_labels(run["repository"], labels)
    except PolicyError as error:
        raise _QGeoCIObservationError("GitHub workflow profile is invalid") from error
    if profile.name != profile_name:
        raise _QGeoCIObservationError("GitHub workflow profile does not match")
    if (
        _provider_int(provider_job.get("run_id")) != int(run["run_id"])
        or _provider_int(provider_job.get("run_attempt")) != int(run["attempt"])
        or provider_job.get("head_sha") != run["checkout_sha"]
        or provider_job.get("head_branch") != run["head_branch"]
    ):
        raise _QGeoCIObservationError("GitHub workflow job tuple does not match")
    _qgeo_durable_payload(row, repository=run["repository"], run=run, job=provider_job)

    status = str(provider_job.get("status") or "").lower()
    conclusion = _provider_conclusion(provider_job.get("conclusion"))
    if status not in {"queued", "in_progress", "completed"}:
        raise _QGeoCIObservationError("GitHub workflow job state is not admissible")
    if status == "completed":
        if conclusion != "success":
            raise _QGeoCIObservationError("GitHub workflow job did not succeed")
        state = "terminal"
    elif conclusion is not None:
        raise _QGeoCIObservationError("GitHub workflow job conclusion is premature")
    else:
        state = status
    if run["status"] == "completed" and state != "terminal":
        raise _QGeoCIObservationError("GitHub workflow state is inconsistent")
    provider_job_id = _provider_int(provider_job.get("id"))
    if provider_job_id is None:
        raise _QGeoCIObservationError("GitHub workflow job identity is invalid")
    return {
        **{
            key: run[key]
            for key in (
                "repository",
                "candidate_sha",
                "checkout_sha",
                "run_id",
                "attempt",
                "workflow_path",
                "event",
                "ref",
                "head_branch",
            )
        },
        "job_id": str(provider_job_id),
        "profile": profile_name,
        "labels": expected_labels,
        "job_name": selector,
        "state": state,
        "conclusion": conclusion,
    }


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
        "reported_concurrency": detail.get("concurrency"),
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
    expected_token: str | None,
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
    return bool(token and expected_token and secrets.compare_digest(token, expected_token))


def _safe_segment(value: str) -> str:
    allowed = "-_.abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    if not value or value in {".", ".."} or any(char not in allowed for char in value):
        raise HTTPException(status_code=400, detail="invalid artifact path")
    return value


def _surface_allows_path(surface: Literal["public", "internal", "test"], path: str) -> bool:
    """Keep the public webhook/artifact broker separate from mTLS control APIs.

    The source-owned edge remains responsible for authenticating client
    certificates on the internal backhaul.  This second, application-level
    boundary ensures that a peer on the shared public Docker network cannot
    reach an operator or release handler by forging the edge identity header.
    """

    if surface == "test":
        return True
    if surface == "public":
        return path == "/health" or path == "/github/workflow-job" or path.startswith("/artifacts/")
    return path in {"/health", "/health/runtime"} or path.startswith("/internal/")


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
    if github is None and settings.surface != "public":
        if settings.app_id is None or settings.app_private_key_path is None:
            raise RuntimeError("the internal broker requires GitHub App credentials")
        github = GitHubAppClient(
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

    def require_github_client() -> GitHubAppClient:
        """Return the provider client for routes that need GitHub authority."""

        if github is None:
            raise HTTPException(status_code=503, detail="GitHub integration unavailable")
        return github

    settings.artifact_root.mkdir(parents=True, exist_ok=True)
    artifact_token_key = settings.artifact_token_key
    if settings.surface == "test" and artifact_token_key is None:
        # Directly constructed legacy test settings remain source-compatible;
        # production from_env() never permits this fallback.
        artifact_token_key = settings.worker_token
    if not artifact_token_key:
        raise RuntimeError("QDEV_ARTIFACT_TOKEN_KEY is required")
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

    def require_same_origin(request: Request, *, required: bool = False) -> None:
        """Reject browser cross-site mutations while keeping API clients usable."""

        origin = request.headers.get("origin")
        if not origin:
            supplied_token = request.headers.get("x-qdev-operator-token")
            server_token = bool(
                isinstance(supplied_token, str)
                and settings.operator_token
                and secrets.compare_digest(supplied_token, settings.operator_token)
            )
            if required or not server_token:
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
        """Require an inventory binding; workflow names are not authorization.

        A filename containing ``test`` or ``ci`` is not evidence that a
        workflow is safe to dispatch.  The controller's registration is the
        allowlist, while provider reconciliation validates the actual run.
        ``name`` and ``path`` remain arguments for compatibility with older
        callers and are deliberately not used as a word-based policy.
        """

        del name, path
        return explicitly_registered

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
        # Manual retries are a test-center operation.  Discovered workflow
        # files remain usable by the legacy webhook/worker path, but they are
        # never sufficient authorization for an operator-triggered rerun.
        explicitly_registered = repo.workflow_registration_present and registration is not None
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
                runs = require_github_client().workflow_runs(
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
                runs = require_github_client().workflow_runs(
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
            remote = require_github_client().workflow_job(
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
        # Scheduling is a new test-center dispatch surface.  The generated
        # inventory must contain an explicit test_workflows registration; a
        # discovered workflow filename is not an allowlist.
        explicitly_registered = False
        if repo.workflow_registration_present:
            try:
                explicitly_registered = (
                    policy.test_workflow(repository, requested_workflow) is not None
                )
            except PolicyError:
                explicitly_registered = False
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
        if not repo.workflow_registration_present or registration is None:
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
                if not repo.workflow_registration_present or registration is None:
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
                response = require_github_client().dispatch_workflow(
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
    worker_recovery = WorkerRecoveryController(
        settings=settings,
        store=store,
        github=cast(GitHubAppClient, github),
        release_status_reader=lambda: worker_recovery_release_binding(
            settings.controller_release_status_path
        ),
    )
    app.state.worker_recovery = worker_recovery
    release_store: ReleaseStore | None = None

    @app.middleware("http")
    async def enforce_broker_surface(request: Request, call_next: Any) -> Response:
        if not _surface_allows_path(settings.surface, request.url.path):
            # Deliberately hide the existence of control-plane endpoints from
            # the shared public network rather than returning an auth oracle.
            return Response(status_code=404)
        response = await call_next(request)
        return cast(Response, response)

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

    def require_github() -> GitHubAppClient:
        if github is None:
            # This is unreachable through the public route allowlist.  Keep a
            # second fail-closed guard so future route refactors cannot turn a
            # missing public credential into an implicit fallback.
            raise HTTPException(status_code=503, detail="GitHub control plane is unavailable")
        return github

    def require_operator(
        token_or_request: str | Request | None,
        *args: Any,
    ) -> OperationStore | str:
        """Authenticate either the native operations API or test-center proxy.

        The original operations routes pass a bearer token and then require
        the exact fleet mTLS identity separately.  The test-center routes were
        added with the Platform proxy's request/identity argument shape.  A
        server-side operator token (and, in production, the separate proxy
        credential) is accepted for those routes; a browser request must come
        through the authenticated proxy and carry the configured operator
        group.  Client-supplied identity headers are never sufficient by
        themselves.
        """

        if isinstance(token_or_request, Request):
            request = token_or_request
            token = args[0] if len(args) > 0 else None
            user = args[1] if len(args) > 1 else None
            email = args[2] if len(args) > 2 else None
            groups = args[3] if len(args) > 3 else None
            proxy_auth = args[4] if len(args) > 4 else None
            configured_token = settings.operator_token
            valid_token = bool(
                isinstance(token, str)
                and configured_token
                and secrets.compare_digest(token, configured_token)
            )
            supplied_proxy = proxy_auth or request.headers.get("x-qdev-operator-proxy-auth")
            valid_proxy = bool(
                settings.operator_proxy_secret
                and supplied_proxy
                and secrets.compare_digest(supplied_proxy, settings.operator_proxy_secret)
            )
            if settings.operator_proxy_secret and not valid_proxy:
                raise HTTPException(status_code=401, detail="operator proxy authentication failed")
            if configured_token is None and not valid_proxy:
                raise HTTPException(
                    status_code=503, detail="operator control plane is not configured"
                )
            if not valid_token and not valid_proxy:
                # Development may explicitly opt into the loopback OIDC
                # adapter.  The source address is only an additional bound;
                # it is never an authorization decision on its own.
                client_host = request.client.host if request.client else ""
                if not settings.allow_legacy_local_oidc or client_host not in {
                    "127.0.0.1",
                    "::1",
                    "localhost",
                }:
                    raise HTTPException(status_code=401, detail="operator authentication failed")
            supplied_groups = {
                item.strip()
                for item in str(groups or request.headers.get("x-auth-request-groups") or "")
                .replace(";", ",")
                .split(",")
                if item.strip()
            }
            if not valid_token and settings.operator_group not in supplied_groups:
                raise HTTPException(status_code=403, detail="operator role is required")
            identity = str(
                email
                or request.headers.get("x-auth-request-email")
                or user
                or request.headers.get("x-auth-request-user")
                or ""
            ).strip()
            if not identity and valid_token:
                identity = "platform-proxy"
            if not identity:
                raise HTTPException(status_code=403, detail="operator identity is required")
            return identity[:256]
        token = token_or_request
        if operations is None or settings.operator_token is None:
            raise HTTPException(status_code=503, detail="operator control plane is not configured")
        if not isinstance(token, str) or not secrets.compare_digest(token, settings.operator_token):
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
        if not isinstance(operation_store, OperationStore):
            raise HTTPException(status_code=503, detail="operator control plane is not configured")
        return operation_store

    def recovery_edge_certificate(
        proxy_auth: str | None,
        certificate_sha256: str | None,
    ) -> str:
        """Trust only certificate evidence overwritten by the authenticated edge."""

        if settings.operator_proxy_secret is None:
            raise HTTPException(
                status_code=503,
                detail="recovery edge authentication is not configured",
            )
        if not proxy_auth or not secrets.compare_digest(proxy_auth, settings.operator_proxy_secret):
            raise HTTPException(
                status_code=401,
                detail="recovery edge authentication failed",
            )
        certificate = (certificate_sha256 or "").strip().lower()
        if not _SHA256_DIGEST.fullmatch(certificate):
            raise HTTPException(
                status_code=403,
                detail="verified recovery certificate is invalid",
            )
        return certificate

    def require_recovery_operator(
        token: str | None,
        proxy_auth: str | None,
        certificate_sha256: str | None,
    ) -> str:
        require_operator(token)
        certificate = recovery_edge_certificate(proxy_auth, certificate_sha256)
        allowlist = settings.recovery_operator_certificate_sha256s
        if not allowlist or any(not _SHA256_DIGEST.fullmatch(item) for item in allowlist):
            raise HTTPException(
                status_code=503,
                detail="recovery operator certificate allowlist is not configured",
            )
        if not any(secrets.compare_digest(certificate, allowed) for allowed in allowlist):
            raise HTTPException(
                status_code=403,
                detail="recovery operator certificate is not allowlisted",
            )
        return certificate

    def require_recovery_agent(
        proxy_auth: str | None,
        certificate_sha256: str | None,
    ) -> str:
        certificate = recovery_edge_certificate(proxy_auth, certificate_sha256)
        try:
            worker_recovery.target_for_agent_certificate(certificate)
        except WorkerRecoveryConfigurationError as error:
            raise HTTPException(
                status_code=503,
                detail="worker recovery is not configured",
            ) from error
        except WorkerRecoveryError as error:
            raise HTTPException(
                status_code=403,
                detail="recovery agent certificate is not allowlisted",
            ) from error
        return certificate

    def execute_worker_recovery(
        callback: Callable[[], _RecoveryResult],
    ) -> _RecoveryResult:
        try:
            return callback()
        except WorkerRecoveryConfigurationError as error:
            raise HTTPException(
                status_code=503,
                detail="worker recovery is not configured",
            ) from error
        except GitHubError as error:
            raise HTTPException(
                status_code=503,
                detail="GitHub recovery observation is unavailable",
            ) from error
        except (WorkerRecoveryError, ValueError) as error:
            raise HTTPException(
                status_code=409,
                detail="worker recovery request rejected",
            ) from error

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
            return AdminPlatformLedger(
                settings.admin_platform_ledger_path,
                receipt_key=settings.operator_receipt_key,
                receipt_root=settings.admin_platform_receipt_root,
            )
        except AdminPlatformLedgerError as error:
            raise HTTPException(
                status_code=503, detail="admin platform ledger is unavailable"
            ) from error

    def admissible_profile_queue(
        profile_name: str,
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Return one profile FIFO with inactive managed candidates omitted.

        The same fail-closed classification is used both when the operator
        signs an exact scope and when the worker consumes it. Malformed managed
        rows remain in FIFO, while an inactive managed candidate cannot
        indefinitely hold an unrelated profile queue.
        """

        profile_queue: list[dict[str, Any]] = []
        fifo_skipped: list[dict[str, Any]] = []
        queued_admin_platform_ledger: AdminPlatformLedger | None = None
        queued_managed_release_ledger: ManagedReleaseLedger | None = None
        registry = managed_registry()
        for queued in store.pending_jobs():
            try:
                queued_profile = policy.profile_for_labels(
                    str(queued["repository"]), _json_strings(queued["labels_json"])
                )
            except PolicyError:
                continue
            if queued_profile.name != profile_name:
                continue
            try:
                queued_managed = registry.validate_claim_if_managed(
                    str(queued["repository"]), queued_profile.name
                )
            except ManagedRegistryError:
                # Keep malformed managed rows in the strict queue. They must
                # not be silently bypassed by this observational filter.
                profile_queue.append(queued)
                continue
            if queued_managed is not None and queued_managed.admission_ledger == "admin-platform":
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
                    assert reason is not None
                    queued_attempt = _job_attempt(queued)
                    if queued_attempt is None:
                        profile_queue.append(queued)
                        continue
                    fifo_skipped.append(
                        {
                            "job_id": int(queued["job_id"]),
                            "repository": str(queued["repository"]),
                            "run_id": int(queued["run_id"]),
                            "attempt": queued_attempt,
                            "head_sha": str(queued["head_sha"]),
                            "profile": queued_profile.name,
                            "managed_registry_entry": queued_managed.entry_id,
                            "reason": reason,
                        }
                    )
                    continue
            elif (
                queued_managed is not None
                and queued_managed.admission_ledger == "managed-production"
            ):
                queued_attempt = _job_attempt(queued)
                if queued_attempt is None:
                    profile_queue.append(queued)
                    continue
                if queued_managed_release_ledger is None:
                    try:
                        queued_managed_release_ledger = managed_release_ledger()
                    except ManagedReleaseLedgerError as exc:
                        raise HTTPException(
                            status_code=503,
                            detail=f"managed release ledger unavailable: {exc}",
                        ) from exc
                admitted, reason = queued_managed_release_ledger.classify_admission(
                    queued_managed.entry_id,
                    str(queued["head_sha"]),
                    run_id=int(queued["run_id"]),
                    run_attempt=queued_attempt,
                )
                if not admitted:
                    assert reason is not None
                    fifo_skipped.append(
                        {
                            "job_id": int(queued["job_id"]),
                            "repository": str(queued["repository"]),
                            "run_id": int(queued["run_id"]),
                            "attempt": queued_attempt,
                            "head_sha": str(queued["head_sha"]),
                            "profile": queued_profile.name,
                            "managed_registry_entry": queued_managed.entry_id,
                            "reason": reason,
                        }
                    )
                    continue
            profile_queue.append(queued)
        return profile_queue, fifo_skipped

    def managed_release_ledger() -> ManagedReleaseLedger:
        try:
            return ManagedReleaseLedger(settings.managed_release_ledger_path)
        except ManagedReleaseLedgerError as error:
            raise HTTPException(
                status_code=503, detail="managed release ledger is unavailable"
            ) from error

    def revalidate_fifo_skip_job_ids(
        claim_scope: ClaimScope,
        requested_job_ids: frozenset[int],
    ) -> frozenset[int]:
        """Re-read every external admission source at the durable claim boundary."""

        if claim_scope.schema != SCHEMA_V2 or not requested_job_ids:
            return frozenset()
        current_registry = managed_registry()
        allowed: set[int] = set()
        for item in claim_scope.fifo_skipped:
            if item.job_id not in requested_job_ids:
                continue
            if item.reason == "active-admin-platform-controller-priority":
                current_ledger = admin_platform_ledger()
                active = current_ledger.active_candidate
                if (
                    current_ledger.active_stage == "controller"
                    and active is not None
                    and active.repository == _CONTROLLER_REPOSITORY
                    and any(
                        scoped.repository == active.repository
                        and scoped.exact_sha == active.source_sha
                        for scoped in claim_scope.jobs
                    )
                ):
                    try:
                        current_ledger.validate_admission("controller", active.source_sha)
                    except AdminPlatformLedgerError:
                        continue
                    allowed.add(item.job_id)
                continue
            try:
                managed_entry = current_registry.validate_claim_if_managed(
                    item.repository, item.profile
                )
            except ManagedRegistryError as error:
                raise HTTPException(
                    status_code=503,
                    detail="managed registry changed during FIFO claim",
                ) from error
            if managed_entry is None or managed_entry.entry_id != item.managed_registry_entry:
                continue
            if managed_entry.admission_ledger == "admin-platform":
                admitted, _ = admin_platform_ledger().classify_admission(
                    managed_entry.entry_id, item.exact_sha
                )
            elif managed_entry.admission_ledger == "managed-production":
                admitted, _ = managed_release_ledger().classify_admission(
                    managed_entry.entry_id,
                    item.exact_sha,
                    run_id=item.run_id,
                    run_attempt=item.attempt,
                )
            else:
                continue
            if not admitted:
                allowed.add(item.job_id)
        return frozenset(allowed)

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

    def require_release_mtls(
        identity: str | None,
        expected: str,
        certificate_sha256: str | None = None,
        expected_certificate_sha256: str | None = None,
    ) -> None:
        """Authenticate a release caller against the controller's mTLS binding.

        The public edge terminates client mTLS and forwards the verified
        certificate fingerprint.  Once a lane has an explicit fingerprint
        binding, a caller-supplied identity header is deliberately ignored;
        this prevents direct header spoofing from authorizing a release.  The
        legacy identity-only path remains for lanes that have not yet enrolled
        a certificate, preserving compatibility while they are migrated.
        """
        if expected_certificate_sha256 is not None:
            normalized = (certificate_sha256 or "").strip().lower()
            if not secrets.compare_digest(normalized, expected_certificate_sha256):
                raise HTTPException(
                    status_code=403,
                    detail="release-lane mTLS certificate binding required",
                )
            return
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

    def validate_managed_candidate(request: ReleaseAdmissionRequest, lane: ReleaseLane) -> None:
        """Require the controller's complete CI ledger before a QGeo release.

        The candidate receipt is an input to admission, never an authority of
        its own.  QGeo's provider run/job/attempt bindings and terminal state
        live in the managed ledger loaded by the controller.
        """

        if lane.project_id != "qazgeo":
            return
        evidence = request.candidate_receipt.get("evidence")
        ci = evidence.get("ci") if isinstance(evidence, dict) else None
        run_ids = ci.get("run_ids") if isinstance(ci, dict) else None
        if not isinstance(run_ids, list) or any(not isinstance(run_id, str) for run_id in run_ids):
            raise HTTPException(status_code=422, detail="release candidate was rejected")
        typed_run_ids = [run_id for run_id in run_ids]
        try:
            managed_release_ledger().validate_candidate_ci_runs(
                "qazgeo",
                request.source_sha,
                typed_run_ids,
                receipt_scope=request.candidate_receipt,
            )
        except ManagedReleaseLedgerError as error:
            raise HTTPException(
                status_code=409, detail="managed CI admission is not complete"
            ) from error

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
            "controller_activation": controller_activation_status(
                settings.controller_activation_status_path
            ),
        }

    @app.get("/health/runtime", response_model=ControllerRuntimeHealth)
    def health_runtime() -> ControllerRuntimeHealth:
        """Expose only identity measured from the activated controller receipt."""

        return controller_runtime_health(settings.controller_release_status_path)

    @app.post("/internal/v1/release-hosts/{placement}/heartbeat")
    def release_host_heartbeat(
        placement: str,
        request: HostHeartbeatRequest,
        x_qdev_mtls_identity: str | None = Header(default=None),
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_host(placement, request.release_lane)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release placement is not allowlisted"
            ) from error
        require_release_mtls(
            x_qdev_mtls_identity,
            lane.host_agent_mtls_identity,
            x_qdev_client_certificate_sha256,
            lane.host_agent_certificate_sha256,
        )
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
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane("qdev-release-qaz-tours")
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=503, detail="qaz-tours release lane is unavailable"
            ) from error
        require_release_mtls(
            x_qdev_mtls_identity,
            lane.client_mtls_identity,
            x_qdev_client_certificate_sha256,
            lane.client_certificate_sha256,
        )
        admission_now = int(datetime.now(tz=UTC).timestamp())
        try:
            validate_candidate(request, lane)
            validate_controller_claim(
                request,
                lane,
                signing_key=settings.controller_claim_key,
                now=admission_now,
            )
        except ReleaseLaneError as error:
            raise HTTPException(status_code=422, detail="release candidate was rejected") from error
        ready_host_agent(lane)
        try:
            job, _idempotent = release_state().admit(
                request,
                lane,
                now=admission_now,
                lease_ttl_seconds=settings.release_job_lease_ttl_seconds,
            )
        except ReleaseLaneError as error:
            raise HTTPException(status_code=409, detail="release lane is busy") from error
        return admission_receipt(job)

    @app.get("/internal/v1/release-hosts/{placement}/jobs/next", response_model=None)
    def next_release_host_job(
        placement: str,
        release_lane: str | None = Query(default=None),
        x_qdev_mtls_identity: str | None = Header(default=None),
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any] | Response:
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_host(placement, release_lane)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release placement is not allowlisted"
            ) from error
        require_release_mtls(
            x_qdev_mtls_identity,
            lane.host_agent_mtls_identity,
            x_qdev_client_certificate_sha256,
            lane.host_agent_certificate_sha256,
        )
        # Authentication has resolved the caller to this lane.  For
        # certificate-bound lanes the forwarded identity header is deliberately
        # optional and untrusted, so every downstream identity-sensitive
        # operation must use the controller-owned lane identity.
        authenticated_host_identity = lane.host_agent_mtls_identity
        ready_host_agent(lane)
        dispatch_signing_key: str | None = None
        if lane.canonical_repository is not None:
            # Key material is selected exclusively from a controller-owned
            # private map by the authenticated lane identity; it is never
            # accepted or selected from caller-controlled headers.
            try:
                dispatch_signing_key = _release_host_dispatch_signing_key(
                    settings.release_host_dispatch_keys_file,
                    authenticated_host_identity,
                )
            except ReleaseLaneError as error:
                raise HTTPException(
                    status_code=503,
                    detail="managed release host dispatch is unavailable",
                ) from error
        try:
            job = release_state().next_job(
                lane,
                host_identity=authenticated_host_identity,
                dispatch_signing_key=dispatch_signing_key,
                claim_ttl_seconds=settings.release_host_dispatch_claim_ttl_seconds,
            )
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=503,
                detail="managed release host dispatch is unavailable",
            ) from error
        if job is None:
            return Response(status_code=204)
        response = {
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
        if lane.canonical_repository is not None:
            claim = job.get("dispatch_claim")
            signature = job.get("dispatch_claim_signature")
            lease_expires_at = job.get("lease_expires_at")
            rollback_anchor = job.get("rollback_anchor")
            if (
                not isinstance(claim, dict)
                or not isinstance(signature, str)
                or not isinstance(lease_expires_at, int)
                or not isinstance(rollback_anchor, dict)
            ):
                raise HTTPException(
                    status_code=503,
                    detail="managed release host dispatch is unavailable",
                )
            response["lease_expires_at"] = lease_expires_at
            response["rollback_anchor"] = rollback_anchor
            response["candidate_evidence"] = claim.get("candidate_evidence")
            response["dispatch_claim"] = claim
            response["dispatch_claim_signature"] = signature
        if lane.project_id == "qazgeo":
            response["artifact_provenance"] = qgeo_artifact_provenance_from_evidence(
                job.get("candidate_receipt", {}).get("evidence")
            )
        return response

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
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_host(placement, release_lane)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release placement is not allowlisted"
            ) from error
        require_release_mtls(
            x_qdev_mtls_identity,
            lane.host_agent_mtls_identity,
            x_qdev_client_certificate_sha256,
            lane.host_agent_certificate_sha256,
        )
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
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Return controller state to a host agent reconciling a lost response."""
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_placement(placement)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release placement is not allowlisted"
            ) from error
        require_release_mtls(
            x_qdev_mtls_identity,
            lane.host_agent_mtls_identity,
            x_qdev_client_certificate_sha256,
            lane.host_agent_certificate_sha256,
        )
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
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane_for_placement(placement)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release placement is not allowlisted"
            ) from error
        require_release_mtls(
            x_qdev_mtls_identity,
            lane.host_agent_mtls_identity,
            x_qdev_client_certificate_sha256,
            lane.host_agent_certificate_sha256,
        )
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
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane("qdev-release-qaz-tours")
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=503, detail="qaz-tours release lane is unavailable"
            ) from error
        require_release_mtls(
            x_qdev_mtls_identity,
            lane.client_mtls_identity,
            x_qdev_client_certificate_sha256,
            lane.client_certificate_sha256,
        )
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
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane(lane_name)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release lane is not allowlisted"
            ) from error
        require_release_mtls(
            x_qdev_mtls_identity,
            lane.client_mtls_identity,
            x_qdev_client_certificate_sha256,
            lane.client_certificate_sha256,
        )
        admission_now = int(datetime.now(tz=UTC).timestamp())
        try:
            validate_candidate(request, lane)
            validate_controller_claim(
                request,
                lane,
                signing_key=settings.controller_claim_key,
                now=admission_now,
            )
        except ReleaseLaneError as error:
            raise HTTPException(status_code=422, detail="release candidate was rejected") from error
        validate_managed_candidate(request, lane)
        ready_host_agent(lane)
        try:
            job, _idempotent = release_state().admit(
                request,
                lane,
                now=admission_now,
                lease_ttl_seconds=settings.release_job_lease_ttl_seconds,
            )
        except ReleaseLaneError as error:
            raise HTTPException(status_code=409, detail="release lane is busy") from error
        return admission_receipt(job)

    @app.get("/internal/v1/releases/{lane_name}/{release_id}")
    def release_status(
        lane_name: str,
        release_id: str,
        x_qdev_mtls_identity: str | None = Header(default=None),
        x_qdev_client_certificate_sha256: str | None = Header(default=None),
    ) -> dict[str, Any]:
        policy_value = release_policy()
        try:
            lane = policy_value.lane(lane_name)
        except ReleaseLaneError as error:
            raise HTTPException(
                status_code=404, detail="release lane is not allowlisted"
            ) from error
        require_release_mtls(
            x_qdev_mtls_identity,
            lane.client_mtls_identity,
            x_qdev_client_certificate_sha256,
            lane.client_certificate_sha256,
        )
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
                "controller_activation": controller_activation_status(
                    settings.controller_activation_status_path
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
        if not isinstance(operation_store, OperationStore):
            raise HTTPException(status_code=503, detail="operator control plane is not configured")
        registry = managed_registry()
        ledger = admin_platform_ledger()
        active_stage = ledger.active_stage
        if active_stage is None:
            raise HTTPException(
                status_code=503,
                detail="admin platform has no active candidate",
            )
        active_entry = next(entry for entry in ledger.entries if entry.entry_id == active_stage)
        if active_entry.source_sha is None:
            raise HTTPException(
                status_code=503,
                detail="admin platform active candidate has no source SHA",
            )
        active = ledger.validate_admission(active_stage, active_entry.source_sha)
        managed = registry.entry_for_id(active.entry_id)
        controller_owned_stages = {
            "controller",
            "qaz-admin-kit",
            "platform-registry-qak-1",
        }
        if (managed is None and active.entry_id not in controller_owned_stages) or (
            managed is not None and managed.project_id != active.project_id
        ):
            raise HTTPException(
                status_code=503,
                detail="admin platform registry and ledger are not aligned",
            )
        controller = controller_release_status(settings.controller_release_status_path)
        activation = controller_activation_status(settings.controller_activation_status_path)
        return operation_store.receipt(
            {
                "kind": "admin-platform-audit",
                "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "controller_release": controller,
                "controller_activation": activation,
                "managed_registry": registry.snapshot(),
                "admin_platform_ledger": ledger.snapshot(),
                "active_candidate": active.entry_id,
                "admission": {
                    "state": "controller-release-observed",
                    "source_sha": active.source_sha,
                    "registry_entry": managed.entry_id if managed is not None else None,
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

    @app.post(
        "/internal/v1/operations/worker-recovery/bindings",
        response_model=RecoveryBindingsResponse,
    )
    def worker_recovery_bindings(
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_proxy_auth: str | None = Header(default=None),
        x_qdev_verified_client_certificate_sha256: str | None = Header(default=None),
    ) -> RecoveryBindingsResponse:
        certificate = require_recovery_operator(
            x_qdev_operator_token,
            x_qdev_operator_proxy_auth,
            x_qdev_verified_client_certificate_sha256,
        )
        return execute_worker_recovery(
            lambda: worker_recovery.bindings(
                operator_certificate_sha256=certificate,
            )
        )

    @app.post(
        "/internal/v1/operations/worker-recovery/prepare",
        response_model=RecoveryOperationResponse,
    )
    def prepare_worker_recovery(
        request: RecoveryPrepareRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_proxy_auth: str | None = Header(default=None),
        x_qdev_verified_client_certificate_sha256: str | None = Header(default=None),
    ) -> RecoveryOperationResponse:
        certificate = require_recovery_operator(
            x_qdev_operator_token,
            x_qdev_operator_proxy_auth,
            x_qdev_verified_client_certificate_sha256,
        )
        return execute_worker_recovery(
            lambda: worker_recovery.prepare(
                request,
                operator_certificate_sha256=certificate,
            )
        )

    @app.post(
        "/internal/v1/operations/worker-recovery/status",
        response_model=RecoveryOperationResponse,
    )
    def worker_recovery_status(
        request: RecoveryStatusRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_proxy_auth: str | None = Header(default=None),
        x_qdev_verified_client_certificate_sha256: str | None = Header(default=None),
    ) -> RecoveryOperationResponse:
        certificate = require_recovery_operator(
            x_qdev_operator_token,
            x_qdev_operator_proxy_auth,
            x_qdev_verified_client_certificate_sha256,
        )
        return execute_worker_recovery(
            lambda: worker_recovery.status(
                request,
                operator_certificate_sha256=certificate,
            )
        )

    @app.post(
        "/internal/v1/operations/worker-recovery/supersede",
        response_model=RecoveryOperationResponse,
    )
    def supersede_worker_recovery(
        request: RecoverySupersedeRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_proxy_auth: str | None = Header(default=None),
        x_qdev_verified_client_certificate_sha256: str | None = Header(default=None),
    ) -> RecoveryOperationResponse:
        certificate = require_recovery_operator(
            x_qdev_operator_token,
            x_qdev_operator_proxy_auth,
            x_qdev_verified_client_certificate_sha256,
        )
        return execute_worker_recovery(
            lambda: worker_recovery.supersede(request, operator_certificate_sha256=certificate)
        )

    @app.post(
        "/internal/v1/operations/worker-recovery/accept",
        response_model=RecoveryOperationResponse,
    )
    def accept_worker_recovery(
        request: RecoveryAcceptRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_proxy_auth: str | None = Header(default=None),
        x_qdev_verified_client_certificate_sha256: str | None = Header(default=None),
    ) -> RecoveryOperationResponse:
        certificate = require_recovery_operator(
            x_qdev_operator_token,
            x_qdev_operator_proxy_auth,
            x_qdev_verified_client_certificate_sha256,
        )
        return execute_worker_recovery(
            lambda: worker_recovery.accept(
                request,
                operator_certificate_sha256=certificate,
            )
        )

    @app.post("/internal/v1/worker-recovery/claim", response_model=None)
    def claim_worker_recovery(
        request: RecoveryAgentClaimRequest,
        x_qdev_operator_proxy_auth: str | None = Header(default=None),
        x_qdev_verified_client_certificate_sha256: str | None = Header(default=None),
    ) -> Response | dict[str, Any]:
        certificate = require_recovery_agent(
            x_qdev_operator_proxy_auth,
            x_qdev_verified_client_certificate_sha256,
        )
        envelope = execute_worker_recovery(
            lambda: worker_recovery.claim(
                request,
                agent_certificate_sha256=certificate,
            )
        )
        if envelope is None:
            return Response(status_code=204)
        return envelope

    @app.post(
        "/internal/v1/worker-recovery/reconcile",
        response_model=RecoveryOperationResponse,
    )
    def reconcile_worker_recovery(
        request: RecoveryReconcileRequest,
        x_qdev_operator_proxy_auth: str | None = Header(default=None),
        x_qdev_verified_client_certificate_sha256: str | None = Header(default=None),
        x_qdev_recovery_agent_signature: str | None = Header(default=None),
    ) -> RecoveryOperationResponse:
        certificate = require_recovery_agent(
            x_qdev_operator_proxy_auth,
            x_qdev_verified_client_certificate_sha256,
        )
        return execute_worker_recovery(
            lambda: worker_recovery.reconcile(
                request,
                agent_certificate_sha256=certificate,
                supplied_signature=x_qdev_recovery_agent_signature or "",
            )
        )

    @app.post("/internal/v1/operations/fleet-bootstrap/recover-existing-worker")
    def recover_existing_worker(
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> None:
        """Retire caller-owned recovery behind the existing operator boundary."""

        require_operator_session(
            x_qdev_operator_token,
            x_qdev_operator_mtls_identity,
        )

        raise HTTPException(
            status_code=410,
            detail="legacy worker recovery endpoint is retired",
        )

    def run_fleet_bootstrap_operation(
        expected_action: Literal["activate-controller", "enrol-host-agent"],
        request: FleetBootstrapOperationRequest,
        operator_token: str | None,
        operator_mtls_identity: str | None,
    ) -> dict[str, Any]:
        """Queue one route-frozen bootstrap action for root dispatch.

        The rootless broker has no host executable or Docker socket.  It
        publishes an immutable policy-validated request and observes only the
        durable result returned by the root-owned dispatcher.
        """

        operation_store = require_operator_session(operator_token, operator_mtls_identity)
        try:
            bootstrap_request = FleetBootstrapRequest.model_validate(request.request)
            if bootstrap_request.action != expected_action:
                raise FleetBootstrapError("fleet bootstrap action does not match route")
            policy_value = fleet_bootstrap_policy()
            operation_path = (
                settings.fleet_bootstrap_operation_root / f"{request.idempotency_key}.json"
            )
            execution = FleetHostDispatchSpool(
                settings.fleet_host_dispatch_request_root,
                settings.fleet_host_dispatch_result_root,
            ).submit(
                policy=policy_value,
                store=BootstrapOperationStore(operation_path),
                request=bootstrap_request,
                idempotency_key=request.idempotency_key,
            )
        except (FleetBootstrapError, ValidationError, ValueError) as error:
            raise HTTPException(
                status_code=422,
                detail="fleet bootstrap operation request is invalid",
            ) from error
        return operation_store.receipt(
            {
                "kind": "fleet-bootstrap-operation",
                "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "execution": execution.as_dict(),
            }
        )

    @app.post("/internal/v1/operations/fleet-bootstrap/activate-controller")
    def activate_controller(
        request: FleetBootstrapOperationRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        return run_fleet_bootstrap_operation(
            "activate-controller",
            request,
            x_qdev_operator_token,
            x_qdev_operator_mtls_identity,
        )

    @app.post("/internal/v1/operations/fleet-bootstrap/enrol-host-agent")
    def enrol_host_agent(
        request: FleetBootstrapOperationRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        return run_fleet_bootstrap_operation(
            "enrol-host-agent",
            request,
            x_qdev_operator_token,
            x_qdev_operator_mtls_identity,
        )

    @app.post("/internal/v1/operations/releases/qazgeo/ci-registration")
    def register_qgeo_ci(
        request: QGeoCIRegistrationRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Register one exact QGeo provider job from an admitted workflow.

        The durable webhook row and fresh GitHub API observations are both
        required.  Nothing in the request body can manufacture CI evidence;
        the controller derives state from the provider and records only the
        exact repository/run/attempt/job tuple in its managed ledger.
        """

        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        provider = require_github()
        if request.repository != QGEO_REPOSITORY:
            raise HTTPException(status_code=409, detail="managed release repository is not QGeo")
        if not _GIT_REVISION.fullmatch(request.source_sha):
            raise HTTPException(status_code=422, detail="source_sha must be a lowercase Git SHA")
        ledger = managed_release_ledger()
        entry = next((item for item in ledger.entries if item.entry_id == "qazgeo"), None)
        if entry is None:
            raise HTTPException(status_code=503, detail="managed release ledger is unavailable")
        row = store.job(request.job_id)
        if row is None:
            raise HTTPException(status_code=404, detail="workflow job is not registered")
        if (
            str(row.get("repository")) != request.repository
            or _provider_int(row.get("run_id")) != request.run_id
            or _job_attempt(row) != request.attempt
            or _provider_int(row.get("job_id")) != request.job_id
        ):
            raise HTTPException(status_code=409, detail="durable workflow job tuple does not match")
        try:
            installation_id = int(row["installation_id"])
            if installation_id < 1:
                raise ValueError
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(
                status_code=409, detail="workflow job installation is invalid"
            ) from error
        try:
            provider_run = provider.workflow_run(
                installation_id, request.repository, request.run_id
            )
            provider_job = provider.workflow_job(
                installation_id, request.repository, request.job_id
            )
        except GitHubError as error:
            raise HTTPException(
                status_code=503, detail="GitHub provider observation failed"
            ) from error
        if not isinstance(provider_run, dict) or not isinstance(provider_job, dict):
            raise HTTPException(status_code=503, detail="GitHub provider observation is invalid")
        try:
            if _provider_int(provider_job.get("id")) != request.job_id:
                raise _QGeoCIObservationError("GitHub workflow job tuple does not match")
            run_identity = _qgeo_run_identity(
                provider_run,
                repository=request.repository,
                candidate_sha=request.source_sha,
                run_id=request.run_id,
                attempt=request.attempt,
                required_workflows=entry.required_workflows,
            )
            binding = _qgeo_job_identity(provider_job, row, run=run_identity, policy=policy)
            result = ledger.register_qgeo_ci_binding(
                repository=binding["repository"],
                source_sha=binding["candidate_sha"],
                checkout_sha=binding["checkout_sha"],
                run_id=binding["run_id"],
                attempt=binding["attempt"],
                job_id=binding["job_id"],
                workflow_path=binding["workflow_path"],
                event=binding["event"],
                ref=binding["ref"],
                head_branch=binding["head_branch"],
                profile=binding["profile"],
                labels=binding["labels"],
                job_name=binding["job_name"],
                state=binding["state"],
                conclusion=binding["conclusion"],
            )
        except (_QGeoCIObservationError, ManagedReleaseLedgerError) as error:
            raise HTTPException(
                status_code=409, detail="managed CI binding was rejected"
            ) from error
        return operation_store.receipt(
            {
                "kind": "managed-ci-registration",
                "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "repository": request.repository,
                "source_sha": request.source_sha,
                "run_id": request.run_id,
                "attempt": request.attempt,
                "job_id": request.job_id,
                "profile": binding["profile"],
                "provider": {
                    "event": binding["event"],
                    "ref": binding["ref"],
                    "head_branch": binding["head_branch"],
                    "candidate_sha": binding["candidate_sha"],
                    "checkout_sha": binding["checkout_sha"],
                    "workflow_path": binding["workflow_path"],
                    "job_name": binding["job_name"],
                    "run_status": run_identity["status"],
                    "run_conclusion": run_identity["conclusion"],
                    "job_state": binding["state"],
                    "job_conclusion": binding["conclusion"],
                    "labels": binding["labels"],
                },
                "idempotent": bool(result["idempotent"]),
                "backup_path": result["backup_path"],
            }
        )

    @app.post("/internal/v1/operations/releases/qazgeo/ci-reconcile")
    def reconcile_qgeo_ci(
        request: QGeoCIReconcileRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        """Verify every allowlisted QGeo CI job and promote the ledger once."""

        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        provider = require_github()
        if not _GIT_REVISION.fullmatch(request.source_sha):
            raise HTTPException(status_code=422, detail="source_sha must be a lowercase Git SHA")
        ledger = managed_release_ledger()
        try:
            entry = ledger.validate_candidate("qazgeo", request.source_sha)
        except ManagedReleaseLedgerError as error:
            raise HTTPException(
                status_code=409, detail="managed QGeo candidate is not admitted"
            ) from error

        expected_bindings: list[dict[str, Any]] = []
        run_receipts: dict[int, dict[str, Any]] = {}
        job_receipts: list[dict[str, Any]] = []
        by_run: dict[int, list[dict[str, Any]]] = {}
        for binding in entry.ci_runs:
            try:
                run_id = int(binding["run_id"])
            except (KeyError, TypeError, ValueError) as error:
                raise HTTPException(
                    status_code=409, detail="managed CI binding is invalid"
                ) from error
            by_run.setdefault(run_id, []).append(dict(binding))

        observed_workflows: set[str] = set()
        for run_id, stored_bindings in by_run.items():
            first = stored_bindings[0]
            attempt = int(first["attempt"])
            first_row = store.job(int(first["job_id"]))
            if first_row is None:
                raise HTTPException(status_code=409, detail="durable managed CI binding is missing")
            try:
                installation_id = int(first_row["installation_id"])
                provider_run = provider.workflow_run(installation_id, QGEO_REPOSITORY, run_id)
                provider_jobs = provider.workflow_run_jobs(
                    installation_id, QGEO_REPOSITORY, run_id, attempt
                )
            except (KeyError, TypeError, ValueError) as error:
                raise HTTPException(
                    status_code=409, detail="managed CI installation is invalid"
                ) from error
            except GitHubError as error:
                raise HTTPException(
                    status_code=503, detail="GitHub provider observation failed"
                ) from error
            if not isinstance(provider_run, dict) or not isinstance(provider_jobs, list):
                raise HTTPException(
                    status_code=503, detail="GitHub provider observation is invalid"
                )
            try:
                run_identity = _qgeo_run_identity(
                    provider_run,
                    repository=QGEO_REPOSITORY,
                    candidate_sha=request.source_sha,
                    run_id=run_id,
                    attempt=attempt,
                    required_workflows=entry.required_workflows,
                )
            except _QGeoCIObservationError as error:
                raise HTTPException(
                    status_code=409, detail="managed CI run was rejected"
                ) from error
            if run_identity["status"] != "completed" or run_identity["conclusion"] != "success":
                raise HTTPException(status_code=409, detail="managed CI is still running")
            observed_workflows.add(run_identity["workflow_path"])
            required = QGEO_REQUIRED_JOB_PROFILES[entry.registration_phase or ""].get(
                run_identity["workflow_path"], {}
            )
            ignored = (
                _QGEO_IGNORED_PR_JOBS.get(run_identity["workflow_path"], {})
                if entry.registration_phase == "pull_request"
                else {}
            )
            seen_required: set[str] = set()
            for provider_job in provider_jobs:
                if not isinstance(provider_job, dict):
                    raise HTTPException(
                        status_code=503, detail="GitHub provider observation is invalid"
                    )
                provider_name = provider_job.get("name")
                ignored_selector = next(
                    (
                        selector
                        for selector in ignored
                        if _QGEO_PROVIDER_JOB_NAMES[selector] == provider_name
                    ),
                    None,
                )
                if ignored_selector is not None:
                    expected_ignored_labels = _qgeo_exact_labels(
                        run_id=run_identity["run_id"],
                        attempt=run_identity["attempt"],
                        job_name=ignored_selector,
                        profile=ignored[ignored_selector],
                    )
                    labels = provider_job.get("labels")
                    if (
                        _provider_int(provider_job.get("id")) is None
                        or _provider_int(provider_job.get("run_id")) != run_id
                        or _provider_int(provider_job.get("run_attempt")) != attempt
                        or provider_job.get("head_sha") != run_identity["checkout_sha"]
                        or provider_job.get("head_branch") != run_identity["head_branch"]
                        or provider_job.get("status") != "completed"
                        or _provider_conclusion(provider_job.get("conclusion")) != "skipped"
                        or (
                            labels not in (None, [])
                            and (
                                not isinstance(labels, list)
                                or sorted(labels) != expected_ignored_labels
                                or len(labels) != len(expected_ignored_labels)
                            )
                        )
                    ):
                        raise HTTPException(status_code=409, detail="ignored PR job is invalid")
                    continue
                try:
                    selector = _qgeo_job_selector(
                        run_identity["workflow_path"], provider_name, run_identity["event"]
                    )
                except _QGeoCIObservationError as error:
                    raise HTTPException(
                        status_code=409, detail="GitHub job set is not exact"
                    ) from error
                if selector in seen_required:
                    raise HTTPException(status_code=409, detail="GitHub job set is duplicated")
                seen_required.add(selector)
                provider_job_id = _provider_int(provider_job.get("id"))
                row = store.job(provider_job_id or 0)
                if row is None or _provider_int(row.get("installation_id")) != installation_id:
                    raise HTTPException(
                        status_code=409, detail="durable managed CI binding is missing"
                    )
                try:
                    verified = _qgeo_job_identity(
                        provider_job, row, run=run_identity, policy=policy
                    )
                except _QGeoCIObservationError as error:
                    raise HTTPException(
                        status_code=409, detail="managed CI job was rejected"
                    ) from error
                if verified["state"] != "terminal" or verified["conclusion"] != "success":
                    raise HTTPException(status_code=409, detail="managed CI is still running")
                expected_bindings.append(verified)
                job_receipts.append(
                    {
                        "job_id": provider_job_id,
                        "run_id": run_id,
                        "attempt": attempt,
                        "job_name": selector,
                        "status": "completed",
                        "conclusion": "success",
                    }
                )
            if seen_required != set(required):
                raise HTTPException(
                    status_code=409, detail="managed CI required job set is incomplete"
                )
            run_receipts[run_id] = {
                "run_id": run_id,
                "attempt": attempt,
                "candidate_sha": request.source_sha,
                "checkout_sha": run_identity["checkout_sha"],
                "workflow_path": run_identity["workflow_path"],
                "event": run_identity["event"],
                "ref": run_identity["ref"],
                "status": "completed",
                "conclusion": "success",
            }
        if observed_workflows != set(entry.required_workflows):
            raise HTTPException(status_code=409, detail="managed CI workflow set is incomplete")
        try:
            result = ledger.reconcile_qgeo_ci_terminal(
                source_sha=request.source_sha,
                verified_bindings=expected_bindings,
            )
        except ManagedReleaseLedgerError as error:
            raise HTTPException(
                status_code=409, detail="managed CI reconciliation was rejected"
            ) from error
        return operation_store.receipt(
            {
                "kind": "managed-ci-reconciliation",
                "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "repository": QGEO_REPOSITORY,
                "source_sha": request.source_sha,
                "run_ids": sorted(run_receipts),
                "bindings": expected_bindings,
                "provider": {
                    "runs": list(run_receipts.values()),
                    "jobs": job_receipts,
                },
                "idempotent": bool(result["idempotent"]),
                "backup_path": result["backup_path"],
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
        attempt = _job_attempt(candidate)
        if attempt is None:
            raise HTTPException(status_code=409, detail="provider attempt is unavailable")

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
            policy.authorize_worker_resources(
                str(candidate["repository"]),
                disk_free_gib=audit.get("raw_capacity", {}).get("disk_free_gib"),
                concurrency=audit.get("reported_concurrency"),
            )
        except PolicyError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        try:
            managed_entry = managed_registry().validate_claim_if_managed(
                str(candidate["repository"]), profile.name
            )
        except ManagedRegistryError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        admission_ledger: str | None = None
        admin_platform_ledger_entry: str | None = None
        managed_release_ledger_entry: str | None = None
        controller_candidate_priority = False
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
                        managed_entry.entry_id,
                        str(candidate["head_sha"]),
                        repository=str(candidate["repository"]),
                        run_id=str(candidate["run_id"]),
                        attempt=str(attempt),
                        job_id=str(job_id),
                    )
                    managed_release_ledger_entry = managed_entry.entry_id
            except (AdminPlatformLedgerError, ManagedReleaseLedgerError) as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        elif str(candidate["repository"]) == _CONTROLLER_REPOSITORY:
            try:
                ledger = admin_platform_ledger()
                active = ledger.active_candidate
                if (
                    ledger.active_stage == "controller"
                    and active is not None
                    and active.repository == _CONTROLLER_REPOSITORY
                    and active.source_sha == str(candidate["head_sha"])
                ):
                    ledger.validate_admission("controller", str(candidate["head_sha"]))
                    admission_ledger = "admin-platform"
                    admin_platform_ledger_entry = "controller"
                    controller_candidate_priority = True
            except AdminPlatformLedgerError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc

        # The two QGeo workflow jobs were admitted before the controller was
        # restored and are deliberately not being requeued or duplicated.  A
        # signed managed-production ledger entry may therefore opt these exact
        # immutable tuples into a narrow recovery lane.  This does not create
        # a general priority queue: every other scope remains strict FIFO.
        managed_exact_candidate_fifo = managed_release_ledger_entry == "qazgeo"
        profile_queue: list[dict[str, Any]] = []
        fifo_skipped: list[dict[str, Any]] = []
        queued_admin_platform_ledger: AdminPlatformLedger | None = None
        queued_managed_release_ledger: ManagedReleaseLedger | None = None
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
                    controller_candidate_priority
                    and int(queued["job_id"]) != job_id
                    and not profile_queue
                ):
                    # The active controller exact SHA is the bounded bootstrap
                    # prerequisite for restoring normal signed admission.  It
                    # may bypass earlier rows without cancelling or mutating
                    # them; the signed receipt preserves every skipped tuple.
                    queued_attempt = _job_attempt(queued)
                    if queued_attempt is None:
                        profile_queue.append(queued)
                        continue
                    fifo_skipped.append(
                        {
                            "job_id": int(queued["job_id"]),
                            "repository": str(queued["repository"]),
                            "run_id": int(queued["run_id"]),
                            "attempt": queued_attempt,
                            "head_sha": str(queued["head_sha"]),
                            "profile": queued_profile.name,
                            "managed_registry_entry": (
                                queued_managed.entry_id if queued_managed else None
                            ),
                            "reason": "active-admin-platform-controller-priority",
                        }
                    )
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
                        queued_attempt = _job_attempt(queued)
                        if queued_attempt is None:
                            # An incomplete provider tuple cannot become a
                            # signed exception to durable FIFO.
                            profile_queue.append(queued)
                            continue
                        fifo_skipped.append(
                            {
                                "job_id": int(queued["job_id"]),
                                "repository": str(queued["repository"]),
                                "run_id": int(queued["run_id"]),
                                "attempt": queued_attempt,
                                "head_sha": str(queued["head_sha"]),
                                "profile": queued_profile.name,
                                "managed_registry_entry": queued_managed.entry_id,
                                "reason": reason,
                            }
                        )
                        continue
                elif (
                    queued_managed is not None
                    and queued_managed.admission_ledger == "managed-production"
                ):
                    queued_attempt = _job_attempt(queued)
                    if queued_attempt is None:
                        profile_queue.append(queued)
                        continue
                    if queued_managed_release_ledger is None:
                        try:
                            queued_managed_release_ledger = managed_release_ledger()
                        except ManagedReleaseLedgerError as exc:
                            raise HTTPException(
                                status_code=503,
                                detail=f"managed release ledger unavailable: {exc}",
                            ) from exc
                    admitted, reason = queued_managed_release_ledger.classify_admission(
                        queued_managed.entry_id,
                        str(queued["head_sha"]),
                        run_id=int(queued["run_id"]),
                        run_attempt=queued_attempt,
                    )
                    if not admitted:
                        assert reason is not None
                        fifo_skipped.append(
                            {
                                "job_id": int(queued["job_id"]),
                                "repository": str(queued["repository"]),
                                "run_id": int(queued["run_id"]),
                                "attempt": queued_attempt,
                                "head_sha": str(queued["head_sha"]),
                                "profile": queued_profile.name,
                                "managed_registry_entry": queued_managed.entry_id,
                                "reason": reason,
                            }
                        )
                        continue
                profile_queue.append(queued)
        if not managed_exact_candidate_fifo and (
            not profile_queue or int(profile_queue[0]["job_id"]) != job_id
        ):
            raise HTTPException(status_code=409, detail="job is not the FIFO head for its profile")

        attempt = _job_attempt(candidate)
        if attempt is None:
            raise HTTPException(status_code=409, detail="provider attempt is unavailable")
        scoped_fifo_skipped = tuple(
            ScopedFifoSkip(
                job_id=int(item["job_id"]),
                repository=str(item["repository"]),
                run_id=int(item["run_id"]),
                attempt=int(item["attempt"]),
                exact_sha=str(item["head_sha"]),
                profile=str(item["profile"]),
                managed_registry_entry=(
                    str(item["managed_registry_entry"])
                    if item["managed_registry_entry"] is not None
                    else None
                ),
                reason=str(item["reason"]),
            )
            for item in fifo_skipped
        )
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
        repaired_managed_scope = False
        retained_jobs: tuple[ScopedJob, ...] = ()
        reuse_existing_jobs = False
        fifo_exception: str | None = (
            MANAGED_EXACT_CANDIDATE_FIFO_EXCEPTION if managed_exact_candidate_fifo else None
        )
        if existing is not None:
            managed_scope_is_narrow = (
                existing.schema == SCHEMA_V2
                and existing.fifo_exception == MANAGED_EXACT_CANDIDATE_FIFO_EXCEPTION
                and all(
                    item.repository == QGEO_REPOSITORY
                    and item.exact_sha == str(candidate["head_sha"])
                    for item in existing.jobs
                )
            )
            terminal_managed_job_ids: set[int] = set()
            if existing.expires_at > datetime.now(UTC) and managed_exact_candidate_fifo:
                # A managed scope may span the qdev-ci and qdev-ci-docker
                # jobs from the same provider run. Once the first profile's
                # tuple is terminal, the worker's capacity directive can
                # legitimately narrow to the next profile. Prune only
                # provider-terminal QGeo tuples; missing or non-terminal
                # records remain fail-closed and block scope reuse.
                for item in existing.jobs:
                    if (
                        item.job_id == job_id
                        or item.repository != QGEO_REPOSITORY
                        or item.exact_sha != str(candidate["head_sha"])
                    ):
                        continue
                    record = store.job(item.job_id)
                    if record is not None and str(record.get("status")) in {
                        "completed",
                        "failed",
                        "rejected",
                    }:
                        terminal_managed_job_ids.add(item.job_id)
            same_scope = (
                existing.schema == SCHEMA_V2
                and existing.worker_name == request.worker_name
                and existing.tier == request.tier
                and existing.host == request.host
                and existing.runner == request.runner
                and existing.correlation_id == request.correlation_id
                and existing.worker_certificate_sha256 == certificate_sha256
                and existing.fifo_skipped == scoped_fifo_skipped
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
                if existing.expires_at > datetime.now(UTC) and (
                    not managed_exact_candidate_fifo
                    or (managed_scope_is_narrow and not terminal_managed_job_ids)
                ):
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
                if existing.expires_at <= datetime.now(UTC):
                    replaced_expired_scope = True
                elif managed_exact_candidate_fifo:
                    # A prior controller version could persist a managed
                    # exception scope containing an unrelated provider job,
                    # or a terminal tuple from the previous profile. Repair
                    # that durable scope in place while leaving unrelated or
                    # non-terminal provider jobs pending in the queue.
                    retained_jobs = tuple(
                        item
                        for item in existing.jobs
                        if item.repository == QGEO_REPOSITORY
                        and item.exact_sha == str(candidate["head_sha"])
                        and item.job_id != job_id
                        and item.job_id not in terminal_managed_job_ids
                    )
                    repaired_managed_scope = True
            elif (
                existing.schema == SCHEMA_V2
                and existing.worker_name == request.worker_name
                and existing.tier == request.tier
                and existing.host == request.host
                and existing.runner == request.runner
                and existing.correlation_id == request.correlation_id
                and existing.worker_certificate_sha256 == certificate_sha256
                and existing.expires_at > datetime.now(UTC)
                and existing.permits(
                    job_id=job_id,
                    repository=str(candidate["repository"]),
                    head_sha=str(candidate["head_sha"]),
                    profile=profile.name,
                    run_id=int(candidate["run_id"]),
                    attempt=attempt,
                )
            ):
                # Refresh only controller-derived skip evidence for the same
                # already-bound immutable target.
                retained_jobs = existing.jobs
                reuse_existing_jobs = True
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
                rollover_jobs = existing.jobs
                if managed_exact_candidate_fifo:
                    rollover_jobs = tuple(
                        item
                        for item in existing.jobs
                        if item.repository == QGEO_REPOSITORY
                        and item.exact_sha == str(candidate["head_sha"])
                    )
                    if len(rollover_jobs) != len(existing.jobs):
                        repaired_managed_scope = True
                previous = [store.job(item.job_id) for item in rollover_jobs]
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
                retained_jobs = tuple(item for item in rollover_jobs if item.job_id != job_id)
                fifo_exception = existing.fifo_exception or fifo_exception
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
            jobs=retained_jobs if reuse_existing_jobs else retained_jobs + (scoped_job,),
            fifo_skipped=scoped_fifo_skipped,
            fifo_exception=fifo_exception,
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
            "repaired_managed_scope": repaired_managed_scope,
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
        pending_for_override: list[dict[str, Any]] = []
        fifo_skipped: list[dict[str, Any]] = []
        queued_admin_platform_ledger: AdminPlatformLedger | None = None
        queued_managed_release_ledger: ManagedReleaseLedger | None = None
        requested_profile = requested_profiles[0]
        controller_candidate_priority = False
        if repository_name == _CONTROLLER_REPOSITORY:
            try:
                ledger = admin_platform_ledger()
                active = ledger.active_candidate
                if (
                    ledger.active_stage == "controller"
                    and active is not None
                    and active.repository == _CONTROLLER_REPOSITORY
                    and active.source_sha == request.head_sha
                ):
                    ledger.validate_admission("controller", request.head_sha)
                    controller_candidate_priority = True
            except AdminPlatformLedgerError as exc:
                raise HTTPException(status_code=409, detail=str(exc)) from exc
        for queued in store.pending_jobs():
            try:
                queued_profile = policy.profile_for_labels(
                    str(queued["repository"]), _json_strings(queued["labels_json"])
                )
            except PolicyError:
                continue
            if queued_profile.name != requested_profile:
                continue
            try:
                queued_managed = managed_registry().validate_claim_if_managed(
                    str(queued["repository"]), queued_profile.name
                )
            except ManagedRegistryError:
                # Malformed managed rows remain strict FIFO blockers.
                pending_for_override.append(queued)
                continue
            if (
                controller_candidate_priority
                and (
                    str(queued["repository"]).strip().lower() != repository_name
                    or str(queued["head_sha"]) != request.head_sha
                )
                and not pending_for_override
            ):
                # Capacity and claim-scope issuance must agree on the same
                # narrowly ledger-bound controller prerequisite.  The skipped
                # row remains pending and is recorded in the signed receipt.
                queued_attempt = _job_attempt(queued)
                if queued_attempt is None:
                    pending_for_override.append(queued)
                    continue
                fifo_skipped.append(
                    {
                        "job_id": int(queued["job_id"]),
                        "repository": str(queued["repository"]),
                        "run_id": int(queued["run_id"]),
                        "attempt": queued_attempt,
                        "head_sha": str(queued["head_sha"]),
                        "profile": queued_profile.name,
                        "managed_registry_entry": (
                            queued_managed.entry_id if queued_managed else None
                        ),
                        "reason": "active-admin-platform-controller-priority",
                    }
                )
                continue
            if queued_managed is not None and queued_managed.admission_ledger == "admin-platform":
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
                    assert reason is not None
                    queued_attempt = _job_attempt(queued)
                    if queued_attempt is None:
                        pending_for_override.append(queued)
                        continue
                    fifo_skipped.append(
                        {
                            "job_id": int(queued["job_id"]),
                            "repository": str(queued["repository"]),
                            "run_id": int(queued["run_id"]),
                            "attempt": queued_attempt,
                            "head_sha": str(queued["head_sha"]),
                            "profile": queued_profile.name,
                            "managed_registry_entry": queued_managed.entry_id,
                            "reason": reason,
                        }
                    )
                    continue
            elif (
                queued_managed is not None
                and queued_managed.admission_ledger == "managed-production"
            ):
                queued_attempt = _job_attempt(queued)
                if queued_attempt is None:
                    pending_for_override.append(queued)
                    continue
                if queued_managed_release_ledger is None:
                    try:
                        queued_managed_release_ledger = managed_release_ledger()
                    except ManagedReleaseLedgerError as exc:
                        raise HTTPException(
                            status_code=503,
                            detail=f"managed release ledger unavailable: {exc}",
                        ) from exc
                admitted, reason = queued_managed_release_ledger.classify_admission(
                    queued_managed.entry_id,
                    str(queued["head_sha"]),
                    run_id=int(queued["run_id"]),
                    run_attempt=queued_attempt,
                )
                if not admitted:
                    assert reason is not None
                    fifo_skipped.append(
                        {
                            "job_id": int(queued["job_id"]),
                            "repository": str(queued["repository"]),
                            "run_id": int(queued["run_id"]),
                            "attempt": queued_attempt,
                            "head_sha": str(queued["head_sha"]),
                            "profile": queued_profile.name,
                            "managed_registry_entry": queued_managed.entry_id,
                            "reason": reason,
                        }
                    )
                    continue
            pending_for_override.append(queued)
        profile_heads, _ = durable_profile_heads(pending_for_override, policy)
        fifo_head = next(
            (item for item in profile_heads if item["profile"] == requested_profiles[0]),
            None,
        )
        if fifo_head is None:
            raise HTTPException(status_code=409, detail="profile has no durable FIFO head")
        if fifo_head["attempt"] is None:
            raise HTTPException(
                status_code=409,
                detail="profile FIFO head has no immutable provider attempt",
            )
        if fifo_head["repository"] != repository_name or fifo_head["exact_sha"] != request.head_sha:
            raise HTTPException(
                status_code=409,
                detail="capacity override target is not the durable FIFO head",
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
        try:
            policy.authorize_worker_resources(
                repository_name,
                disk_free_gib=disk_free_gib,
                concurrency=audit.get("reported_concurrency"),
            )
        except PolicyError as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        profile_name = requested_profiles[0].lower()
        profile_disk_mb = policy.repository_profile_disk_mb.get(
            (repository_name, profile_name),
            policy.profiles[requested_profiles[0]].disk_mb,
        )
        profile_headroom_gib = profile_disk_mb / 1024
        required_free_gib = max(
            request.min_disk_free_gib + profile_headroom_gib,
            policy.repository_min_disk_free_gib.get(repository_name, 0.0),
        )
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
        try:
            directive = operation_store.create_capacity_override(
                worker_name=worker_name,
                repository=repository_name,
                head_sha=request.head_sha,
                profiles=requested_profiles,
                min_disk_free_gib=request.min_disk_free_gib,
                max_disk_used_pct=request.max_disk_used_pct,
                owner=request.owner,
                reason=request.reason,
                duration_seconds=request.duration_seconds,
                registered_profiles=registered_profiles,
            )
        except CapacityOverrideConflict as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        payload = {
            "kind": "capacity-override-created",
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "worker_audit": audit,
            "operation": directive.model_dump(mode="json", by_alias=True),
            "required_free_gib": round(required_free_gib, 3),
            "immutable_tuple": fifo_head,
            "fifo_skipped": fifo_skipped,
        }
        return operation_store.receipt(payload)

    @app.delete("/internal/v1/operations/workers/{worker_name}/capacity-override")
    def cancel_capacity_override(
        worker_name: str,
        operation_id: str = Query(min_length=1, max_length=128),
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        worker, audit = current_worker(worker_name)
        try:
            directive = operation_store.cancel_capacity_override(
                worker_name,
                expected_operation_id=operation_id,
                registered_profiles=_json_strings(worker.get("profiles_json")),
            )
        except CapacityOverrideConflict as error:
            raise HTTPException(status_code=409, detail=str(error)) from error
        payload = {
            "kind": "capacity-override-cancelled",
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "worker_audit": audit,
            "operation": directive.model_dump(mode="json", by_alias=True),
        }
        return operation_store.receipt(payload)

    @app.get("/internal/v1/operations/jobs/pending")
    def audit_pending_jobs(
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        pending_jobs = store.pending_jobs()
        profile_heads: list[dict[str, Any]] = []
        for profile_name in policy.profiles:
            profile_queue, _ = admissible_profile_queue(profile_name)
            candidates, _ = durable_profile_heads(profile_queue, policy)
            profile_heads.extend(item for item in candidates if item["profile"] == profile_name)
        _, unclassified = durable_profile_heads(pending_jobs, policy)
        return operation_store.receipt(
            {
                "kind": "durable-queue-audit",
                "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
                "pending": len(pending_jobs),
                "profile_heads": profile_heads,
                "unclassified": unclassified,
            }
        )

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
        if row is None and request.pending_terminal_only:
            row = store.job(job_id)
            if row is None or row["status"] != "pending":
                raise HTTPException(status_code=409, detail="job is not pending")
        if row is None:
            raise HTTPException(status_code=409, detail="job is not stale")
        if request.pending_terminal_only and row["status"] != "pending":
            raise HTTPException(status_code=409, detail="job is not pending")
        immutable_job = _stale_job_tuple(row)
        installation_id = int(row["installation_id"])
        repository = str(row["repository"])
        try:
            github_client = require_github()
            remote_job = github_client.workflow_job(installation_id, repository, job_id)
            remote_run = github_client.workflow_run(installation_id, repository, int(row["run_id"]))
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
            if request.pending_terminal_only:
                terminal_conclusions = {
                    "success",
                    "failure",
                    "neutral",
                    "cancelled",
                    "skipped",
                    "timed_out",
                    "action_required",
                    "stale",
                    "startup_failure",
                }
                if (
                    provider_status != "completed"
                    or provider_conclusion not in terminal_conclusions
                ):
                    raise HTTPException(status_code=409, detail="provider job is not terminal")
                if not store.complete_pending_from_provider(job_id, str(provider_conclusion)):
                    raise HTTPException(
                        status_code=409, detail="pending job changed during reconciliation"
                    )
                action = "pending-completed-from-provider"
            elif provider_status == "completed":
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

    @app.get("/internal/v1/operations/jobs/failed-worker-exit")
    def audit_failed_worker_jobs(
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        candidates = [_stale_job_tuple(row) for row in store.failed_worker_jobs()]
        payload = {
            "kind": "failed-job-audit",
            "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            "provider_reconciliation_required": True,
            "candidates": candidates,
        }
        return operation_store.receipt(payload)

    @app.post("/internal/v1/operations/jobs/{job_id}/recover-failed-worker-exit")
    def recover_failed_worker_job(
        job_id: int,
        request: FailedJobRecoveryRequest,
        x_qdev_operator_token: str | None = Header(default=None),
        x_qdev_operator_mtls_identity: str | None = Header(default=None),
    ) -> dict[str, Any]:
        operation_store = require_operator_session(
            x_qdev_operator_token, x_qdev_operator_mtls_identity
        )
        row = next(
            (
                candidate
                for candidate in store.failed_worker_jobs()
                if int(candidate["job_id"]) == job_id
            ),
            None,
        )
        if row is None:
            raise HTTPException(status_code=409, detail="job is not a recoverable worker failure")
        immutable_job = _stale_job_tuple(row)
        installation_id = int(row["installation_id"])
        repository = str(row["repository"])
        try:
            github_client = require_github()
            remote_job = github_client.workflow_job(installation_id, repository, job_id)
            remote_run = github_client.workflow_run(installation_id, repository, int(row["run_id"]))
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
                    detail="provider immutable tuple does not match the failed job",
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
                elif not store.release_failed_job(
                    job_id,
                    f"operator recovery: {request.reason}",
                    expected_updated_at=float(row["updated_at"]),
                ):
                    raise HTTPException(
                        status_code=409,
                        detail="failed job changed during provider reconciliation",
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
            "kind": "failed-job-recovery",
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
            policy.repository(str(repository["full_name"]), repository_id=int(repository["id"]))
        except (KeyError, TypeError, ValueError, PolicyError) as error:
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
        registered_profiles = tuple(request.profiles)
        if request.claim_scope_id is not None:
            # A capacity directive deliberately narrows the profiles sent in a
            # claim request to one admitted profile.  A v2 scope can retain
            # provider-terminal tuples from earlier profiles as it rolls
            # forward, so its identity binding must be checked against the
            # worker's durable registration rather than that temporary subset.
            try:
                registered_worker, _ = current_worker(request.worker_name)
            except HTTPException as error:
                raise HTTPException(status_code=403, detail="claim scope rejected") from error
            registered_profiles = _json_strings(registered_worker.get("profiles_json"))
        try:
            claim_scope = resolve_claim_scope(
                settings.claim_scopes_path,
                request.claim_scope_id,
                request.worker_name,
                request.tier,
                registered_profiles,
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
        supplied_override = bool(
            request.capacity_directive_id
            or request.capacity_repository
            or request.capacity_head_sha
        )
        if supplied_override and active_directive is None:
            raise HTTPException(status_code=403, detail="capacity override is not active")
        if active_directive is not None and (
            request.capacity_directive_id != active_directive.operation_id
            or (request.capacity_repository or "").lower() != active_directive.repository.lower()
            or (request.capacity_head_sha or "").lower() != active_directive.head_sha.lower()
            or tuple(request.profiles) != active_directive.profiles
        ):
            raise HTTPException(status_code=403, detail="capacity override binding rejected")
        # A capacity directive normally keeps the durable claim bound to its
        # repository/SHA.  The sole bootstrap exception is an exact active
        # controller tuple already admitted by the admin-platform ledger and a
        # certificate-bound v2 scope.  This lets the controller restore its own
        # admission path without weakening FIFO for any other scoped job.
        controller_scoped_admission: AdminPlatformCandidate | None = None
        if claim_scope is not None and claim_scope.schema == SCHEMA_V2:
            _, audit = current_worker(request.worker_name)
            if (
                not audit.get("fresh")
                or int(audit.get("active_jobs") or 0) != 0
                or int(audit.get("slots_available") or 0) < 1
                or not audit.get("capacity_allowed")
                or audit.get("configured_claim_scope_id") != claim_scope.scope_id
            ):
                return Response(status_code=204)
            try:
                ledger = admin_platform_ledger()
                active_candidate = ledger.active_candidate
                if (
                    ledger.active_stage == "controller"
                    and active_candidate is not None
                    and active_candidate.repository == _CONTROLLER_REPOSITORY
                    and any(
                        item.repository == active_candidate.repository
                        and item.exact_sha == active_candidate.source_sha
                        for item in claim_scope.jobs
                    )
                ):
                    ledger.validate_admission("controller", active_candidate.source_sha)
                    controller_scoped_admission = active_candidate
            except AdminPlatformLedgerError as error:
                raise HTTPException(
                    status_code=503,
                    detail=f"admin platform ledger unavailable: {error}",
                ) from error
        repository = (
            controller_scoped_admission.repository
            if controller_scoped_admission is not None
            else active_directive.repository
            if active_directive is not None
            else None
        )
        head_sha = (
            controller_scoped_admission.source_sha
            if controller_scoped_admission is not None
            else active_directive.head_sha
            if active_directive is not None
            else None
        )
        fifo_skip_job_ids = frozenset[int]()
        fifo_skip_guard: Callable[[frozenset[int]], frozenset[int]] | None = None
        if claim_scope is not None and claim_scope.schema == SCHEMA_V2:
            skipped: set[int] = set()
            for profile_name in request.profiles:
                _, profile_skipped = admissible_profile_queue(profile_name)
                skipped.update(int(item["job_id"]) for item in profile_skipped)
            fifo_skip_job_ids = frozenset(skipped)
            bound_claim_scope = claim_scope

            def scoped_fifo_skip_guard(requested: frozenset[int]) -> frozenset[int]:
                return revalidate_fifo_skip_job_ids(bound_claim_scope, requested)

            fifo_skip_guard = scoped_fifo_skip_guard
        claimed = store.claim(
            request.worker_name,
            tuple(request.profiles),
            tier=request.tier,
            disk_free_gib=request.disk_free_gib,
            min_disk_free_gib=request.min_disk_free_gib,
            profile_disk_mb={name: profile.disk_mb for name, profile in policy.profiles.items()},
            repository_profile_disk_mb=policy.repository_profile_disk_mb,
            repository_min_disk_free_gib=policy.repository_min_disk_free_gib,
            repository_max_concurrency=policy.repository_max_concurrency,
            claim_scope=claim_scope,
            repository=repository,
            head_sha=head_sha,
            authorized_min_disk_free_gib=(
                active_directive.min_disk_free_gib
                if active_directive is not None
                and claim_scope is not None
                and claim_scope.schema == SCHEMA_V2
                else None
            ),
            fifo_skip_job_ids=fifo_skip_job_ids,
            fifo_skip_guard=fifo_skip_guard,
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
            github_client = require_github()
            run = github_client.workflow_run(
                int(claimed["installation_id"]), claimed["repository"], int(claimed["run_id"])
            )
            policy.authorize_run(claimed["repository"], profile, run)
            if conclusion := completed_run_conclusion(run):
                store.complete_from_webhook(job_id, conclusion)
                return Response(status_code=204)
            remote_job = github_client.workflow_job(
                int(claimed["installation_id"]), claimed["repository"], job_id
            )
            # Test-center registrations require provider-owned identity.  The
            # legacy worker path remains compatible with older provider
            # payloads which do not expose the newer fields, while still
            # rejecting a field when it is present and contradicts the queue.
            registered_test_job = is_registered_test_workflow(claimed)
            remote_head_sha = str(remote_job.get("head_sha") or "").lower()
            if (registered_test_job and not remote_head_sha) or (
                remote_head_sha and remote_head_sha != str(claimed["head_sha"]).lower()
            ):
                store.set_status(job_id, "rejected", "GitHub job SHA differs from queued SHA")
                raise PolicyError("GitHub job SHA differs from queued SHA")
            remote_run_id = remote_job.get("run_id")
            try:
                remote_run_matches = remote_run_id is not None and int(remote_run_id) == int(
                    claimed["run_id"]
                )
            except (TypeError, ValueError):
                remote_run_matches = False
            if registered_test_job and not remote_run_matches:
                store.set_status(job_id, "rejected", "GitHub job run differs from queued run")
                raise PolicyError("GitHub job run differs from queued run")
            if str(remote_job.get("status")) != "queued":
                store.complete_from_webhook(
                    job_id,
                    str(remote_job.get("conclusion") or remote_job.get("status") or "unknown"),
                )
                return Response(status_code=204)
            runner_name = f"qdev-{claimed['repository'].split('/')[-1]}-{job_id}"[:63]
            jit_config = github_client.generate_jit_config(
                int(claimed["installation_id"]),
                claimed["repository"],
                runner_name,
                tuple(dict.fromkeys(labels)),
            )
            store.set_status(job_id, "running", f"runner={runner_name}")
            token = artifact_token(
                artifact_token_key, claimed["repository"], claimed["head_sha"], job_id
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
            github_client = require_github()
            remote_job = github_client.workflow_job(
                int(job["installation_id"]), str(job["repository"]), request.job_id
            )
        except GitHubError:
            LOGGER.warning("could not reconcile successful worker exit job=%s", request.job_id)
            return Response(status_code=204)
        remote_status = str(remote_job.get("status") or "unknown")
        if remote_status == "queued":
            try:
                run = github_client.workflow_run(
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
                github_client = require_github()
                remote_job = github_client.workflow_job(
                    int(job["installation_id"]), str(job["repository"]), job_id
                )
                if str(remote_job.get("status")) == "completed":
                    store.complete_from_webhook(
                        job_id, str(remote_job.get("conclusion") or "unknown")
                    )
                    status = "completed"
                elif str(remote_job.get("status")) == "queued":
                    run = github_client.workflow_run(
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
        if bool(x_qdev_artifact_token) == bool(x_qdev_github_oidc):
            raise HTTPException(status_code=401, detail="exactly one artifact identity is required")
        if x_qdev_github_oidc:
            # GitHub-hosted jobs have no controller lease. Their sealed
            # material is reconciled later against the exact workflow/job
            # identity under a signed recovery claim, never through this
            # generic write endpoint.
            raise HTTPException(
                status_code=403,
                detail="hosted artifact intake is disabled; use recovery reconciliation",
            )
        if artifact_attempt is not None and artifact_attempt < 1:
            raise HTTPException(status_code=422, detail="invalid test attempt")
        path_suite = None
        if artifact_suite is not None:
            try:
                path_suite = _safe_segment(artifact_suite)
            except HTTPException:
                raise HTTPException(status_code=422, detail="invalid test suite") from None
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
        job = store.job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        assert x_qdev_artifact_token is not None
        if not artifact_job_is_active(job, full_name, safe_sha, job_id):
            raise HTTPException(status_code=401, detail="artifact credentials expired")
        expected_token = artifact_token(artifact_token_key, full_name, safe_sha, job_id)
        if not secrets.compare_digest(x_qdev_artifact_token, expected_token):
            raise HTTPException(status_code=401, detail="artifact authentication failed")
        raw_content_length = request.headers.get("content-length")
        try:
            content_length = int(raw_content_length) if raw_content_length is not None else None
        except ValueError as error:
            raise HTTPException(status_code=400, detail="invalid content length") from error
        if content_length is not None and content_length < 0:
            raise HTTPException(status_code=400, detail="invalid content length")
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
            # Keep ordinary release archives out of the test-result pipeline.
            # They have no test suite or controller job, but their OIDC
            # identity has already been bound above.  The fixed path segment
            # prevents a generic artifact from acquiring a synthetic suite.
            generic_attempt = artifact_attempt or 1
            generic_suite = "artifact"
            target = (
                settings.artifact_root
                / owner
                / repo
                / safe_sha
                / str(job_id)
                / str(generic_attempt)
                / generic_suite
                / safe_name
            )
            target_existed = target.exists()
            if target_existed:
                existing_digest = hashlib.sha256(target.read_bytes()).hexdigest()
                if not secrets.compare_digest(existing_digest, digest):
                    raise HTTPException(
                        status_code=409, detail="conflicting artifact for this path"
                    )
            if not target_existed:
                target.parent.mkdir(parents=True, exist_ok=True)
                temporary = target.with_suffix(target.suffix + ".tmp")
                temporary.write_bytes(body)
                os.chmod(temporary, 0o600)
                temporary.replace(target)
            return {
                "schema": "qdev-artifact-v1",
                "sha256": digest,
                "size": len(body),
                "report": None,
            }
        assert job is not None
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
        try:
            run_id = int(job.get("run_id") or workflow_job.get("run_id") or 0)
            repository_id = int(job.get("repository_id") or 0)
        except (TypeError, ValueError) as error:
            raise HTTPException(
                status_code=422, detail="stored workflow identity is malformed"
            ) from error
        if run_id < 0 or repository_id < 0:
            raise HTTPException(status_code=422, detail="stored workflow identity is invalid")
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
            # A test receipt is accepted only for an explicitly registered
            # test workflow.  Legacy discovered workflow paths may still
            # upload ordinary artifacts and continue the old execution path,
            # but they cannot mint a qdev-test-run result.
            if report_like and (
                not repo_policy.workflow_registration_present or registration is None
            ):
                raise PolicyError("test workflow is not registered")
        except PolicyError as error:
            raise HTTPException(
                status_code=403, detail="workflow or suite is not registered"
            ) from error
        strict_identity = bool(repo_policy.workflow_registration_present)
        required_test_report_formats: tuple[str, ...] = ()
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
            try:
                run_id = int(remote_job["run_id"])
            except (TypeError, ValueError) as error:
                raise HTTPException(
                    status_code=422, detail="GitHub run identity is malformed"
                ) from error
            if run_id < 1:
                raise HTTPException(status_code=422, detail="GitHub run identity is invalid")
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
            try:
                repository_id = int(remote_repository_id)
            except (TypeError, ValueError) as error:
                raise HTTPException(
                    status_code=422, detail="GitHub repository identity is malformed"
                ) from error
            if repository_id < 1:
                raise HTTPException(status_code=422, detail="GitHub repository identity is invalid")
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
            selected_profile = policy.profiles.get(profile)
            if selected_profile is None:
                raise HTTPException(status_code=422, detail="workflow profile is not configured")
            required_test_report_formats = selected_profile.required_test_report_formats
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
        # Native XML/coverage reports usually do not carry the provider job's
        # execution window.  Bind their normalized receipt to the trusted job
        # timestamps when available, rather than to the controller delivery
        # time, so the same immutable sources produce the same digest in
        # either delivery order.
        remote_started_at = remote_job.get("started_at")
        remote_finished_at = remote_job.get("completed_at") or remote_job.get("finished_at")
        if isinstance(remote_started_at, str) and remote_started_at:
            context["started_at"] = remote_started_at
        if isinstance(remote_finished_at, str) and remote_finished_at:
            context["finished_at"] = remote_finished_at
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
        existing_source = store.test_report_for_attempt_path(job_id, suite, attempt, safe_name)
        exact_source_redelivery = bool(
            existing_source is not None
            and secrets.compare_digest(str(existing_source.get("sha256", "")), digest)
            and int(existing_source.get("size") or -1) == len(body)
        )
        existing_test_run = (
            store.test_run_for_attempt(job_id, suite, attempt) if is_test_result else None
        )
        if (
            existing_test_run is not None
            and normalized_report is not None
            and not exact_source_redelivery
        ):
            existing_execution = {
                "status": existing_test_run.get("execution_status"),
                "started_at": existing_test_run.get("started_at"),
                "finished_at": existing_test_run.get("finished_at"),
            }
            incoming_execution = normalized_report["execution"]
            incoming_execution_identity = {
                "status": incoming_execution.get("status"),
                "started_at": incoming_execution.get("started_at"),
                "finished_at": incoming_execution.get("finished_at"),
            }
            existing_result = {
                # A profile can make a successful execution receipt incomplete
                # until every required native report has arrived.  Compare the
                # immutable execution result, not that derived admission state,
                # so an exact JUnit redelivery stays idempotent.
                "status": (existing_test_run.get("payload", {}).get("result", {}).get("status")),
                "total": existing_test_run.get("total"),
                "executed": existing_test_run.get("executed"),
                "failed": existing_test_run.get("failed"),
                "skipped": existing_test_run.get("skipped"),
            }
            if (
                existing_execution != incoming_execution_identity
                or existing_result != normalized_report["result"]
            ):
                raise HTTPException(
                    status_code=409, detail="conflicting test result for job/suite/attempt"
                )
            if existing_test_run.get("critical_scenarios", []) != normalized_report.get(
                "critical_scenarios", []
            ):
                raise HTTPException(
                    status_code=409, detail="conflicting test result for job/suite/attempt"
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
                row: dict[str, Any] | None
                idempotent: bool
                if is_test_result:
                    # JUnit (or an already normalized envelope) owns the
                    # execution/result receipt.  Coverage reports may arrive
                    # before or after it, so merge every persisted source in
                    # one transaction before returning the displayed digest.
                    existing = store.test_run_for_attempt(job_id, suite, attempt)
                    if existing is None:
                        row, idempotent = store.record_test_run(
                            source_payload, report_digest(source_payload)
                        )
                    else:
                        row, idempotent = existing, True
                    row = (
                        store.merge_test_run_sources(
                            job_id,
                            suite,
                            attempt,
                            required_report_formats=required_test_report_formats,
                        )
                        or row
                    )
                else:
                    row = store.merge_test_run_sources(
                        job_id,
                        suite,
                        attempt,
                        required_report_formats=required_test_report_formats,
                    )
                    idempotent = source_idempotent
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
        operator = require_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        if not isinstance(operator, str):
            raise HTTPException(status_code=503, detail="operator control plane is not configured")
        if status is not None and status not in {"passed", "failed", "incomplete", "not_run"}:
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
        require_operator(
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

    @app.get("/operator/v1/test-reports/{report_id}")
    def operator_test_report(
        report_id: int,
        request: Request,
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> Response:
        """Download a stored source report through its server-issued id.

        The database row, not a path supplied by the caller, selects the
        artifact.  Resolve it beneath the configured artifact root and verify
        the recorded size and digest before serving it, so traversal, symlink
        escape and interrupted writes fail closed.
        """

        require_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        if report_id < 1:
            raise HTTPException(status_code=404, detail="report not found")
        report = store.test_report(report_id)
        if report is None:
            raise HTTPException(status_code=404, detail="report not found")
        root = settings.artifact_root.resolve()
        source = Path(str(report.get("storage_path") or ""))
        try:
            resolved = source.resolve(strict=True)
        except (FileNotFoundError, OSError) as error:
            raise HTTPException(status_code=404, detail="report is unavailable") from error
        if not resolved.is_file() or not resolved.is_relative_to(root):
            raise HTTPException(status_code=404, detail="report is unavailable")
        try:
            size = resolved.stat().st_size
            digest = hashlib.sha256(resolved.read_bytes()).hexdigest()
        except OSError as error:
            raise HTTPException(status_code=404, detail="report is unavailable") from error
        if size != int(report.get("size") or -1) or not secrets.compare_digest(
            digest, str(report.get("sha256") or "")
        ):
            raise HTTPException(status_code=409, detail="report integrity check failed")
        media_type = {
            "junit": "application/xml",
            "cobertura": "application/xml",
            "lcov": "text/plain",
            "qdev-test-run": "application/json",
            "json": "application/json",
        }.get(str(report.get("format") or "").lower(), "application/octet-stream")
        filename = Path(str(report.get("path") or "report")).name or "report"
        return FileResponse(
            resolved,
            media_type=media_type,
            filename=filename,
            headers={"X-Qdev-Report-SHA256": str(report["sha256"])},
        )

    @app.get("/operator/v1/test-summary")
    def operator_test_summary(
        request: Request,
        x_qdev_operator_token: str | None = Header(default=None),
        x_auth_request_user: str | None = Header(default=None),
        x_auth_request_email: str | None = Header(default=None),
        x_auth_request_groups: str | None = Header(default=None),
    ) -> dict[str, Any]:
        require_operator(
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
        operator = require_operator(
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
        operator = require_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        if not isinstance(operator, str):
            raise HTTPException(status_code=503, detail="operator control plane is not configured")
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
        operator = require_operator(
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
        operator = require_operator(
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
        operator = require_operator(
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
        operator = require_operator(
            request,
            x_qdev_operator_token,
            x_auth_request_user,
            x_auth_request_email,
            x_auth_request_groups,
        )
        if not isinstance(operator, str):
            raise HTTPException(status_code=503, detail="operator control plane is not configured")
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
            try:
                stored_run_id = int(job.get("run_id") or 0)
                stored_repository_id = int(job.get("repository_id") or 0)
            except (TypeError, ValueError) as error:
                raise PolicyError("stored workflow identity is malformed") from error
            if stored_run_id < 0 or stored_repository_id < 0:
                raise PolicyError("stored workflow identity is invalid")
            remote_job = _remote_workflow_job(
                job,
                workflow=workflow_path or None,
                run_id=stored_run_id or None,
                repository_id=stored_repository_id or None,
            )
            remote_attempt_raw = remote_job.get("run_attempt", remote_job.get("run_attempt_number"))
            source_attempt = int(
                remote_attempt_raw or (workflow_payload or {}).get("run_attempt") or 1
            )
            if source_attempt < 1:
                raise PolicyError("GitHub job attempt is invalid")
            try:
                source_run_id = int(job.get("run_id") or remote_job.get("run_id") or 0)
            except (TypeError, ValueError) as error:
                raise PolicyError("GitHub job run is malformed") from error
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
                provider_result = require_github_client().rerun_job(
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
