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
from typing import Any
from urllib.parse import urlparse

import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request, Response
from pydantic import BaseModel, Field

from .github import GitHubAppClient, GitHubError
from .models import QueuedJob
from .policy import Policy, PolicyError
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


class ClaimRequest(BaseModel):
    worker_name: str
    tier: str
    profiles: list[str]


class CompletionRequest(BaseModel):
    worker_name: str
    job_id: int
    runner_exit_code: int
    infrastructure_error: bool = False
    detail: str = ""


class HeartbeatRequest(BaseModel):
    worker_name: str
    tier: str
    profiles: list[str]
    active_jobs: int
    active_job_ids: list[int] = Field(default_factory=list)
    detail: dict[str, Any]


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

    def require_worker(token: str | None) -> None:
        if not token or not secrets.compare_digest(token, settings.worker_token):
            raise HTTPException(status_code=401, detail="worker authentication failed")

    def require_operator(
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

    @app.get("/health")
    def health() -> dict[str, Any]:
        data = store.health()
        fresh_workers = [
            worker for worker in data["workers"] if data["now"] - worker["last_seen"] < 90
        ]
        return {
            "ok": True,
            "schema": "qdev-runner-health-v1",
            "pending": data["jobs"].get("pending", 0),
            "active_workers": len(fresh_workers),
            "primary_available": any(
                worker["tier"] == "primary" and worker["available"] for worker in fresh_workers
            ),
            "reserve_available": any(
                worker["tier"] == "reserve" and worker["available"] for worker in fresh_workers
            ),
        }

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
    ) -> dict[str, Any] | Response:
        require_worker(x_qdev_worker_token)
        if request.tier not in {"primary", "reserve"}:
            raise HTTPException(status_code=400, detail="invalid worker tier")
        store.recover_stale_jobs(worker_timeout_seconds=300)
        if request.tier == "reserve" and store.has_fresh_tier("primary", max_age_seconds=90):
            return Response(status_code=204)
        claimed = store.claim(request.worker_name, tuple(request.profiles))
        if claimed is None:
            return Response(status_code=204)
        job_id = int(claimed["job_id"])
        try:
            labels = tuple(json.loads(claimed["labels_json"]))
            profile = policy.profile_for_labels(claimed["repository"], labels)
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
    ) -> Response:
        require_worker(x_qdev_worker_token)
        job = store.job(request.job_id)
        if job is None:
            return Response(status_code=204)
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
    ) -> dict[str, Any]:
        require_worker(x_qdev_worker_token)
        job = store.job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
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
    ) -> Response:
        require_worker(x_qdev_worker_token)
        store.heartbeat(
            request.worker_name,
            tuple(request.profiles),
            request.active_jobs,
            tuple(request.active_job_ids),
            request.detail | {"tier": request.tier},
        )
        return Response(status_code=204)

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
        job = store.job(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="job not found")
        if not artifact_job_is_active(job, full_name, safe_sha, job_id):
            raise HTTPException(status_code=401, detail="artifact credentials expired")
        expected_token = artifact_token(settings.worker_token, full_name, safe_sha, job_id)
        if not x_qdev_artifact_token or not secrets.compare_digest(
            x_qdev_artifact_token, expected_token
        ):
            raise HTTPException(status_code=401, detail="artifact authentication failed")
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
        operator = require_operator(
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
