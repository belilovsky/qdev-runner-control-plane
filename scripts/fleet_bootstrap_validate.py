#!/usr/bin/env python3
"""Validate one signed GitHub Actions request for fleet bootstrap.

This workflow is intentionally a validation boundary, not the privileged
executor.  It binds the current workflow attempt to the numeric GitHub job,
validates the immutable controller tuple against the checked-in policy and
records an idempotent, non-secret operation marker.  A controller process with
the QDev CA must still mint the short-lived claim and perform the allowlisted
transition.
"""

from __future__ import annotations

import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from qdev_runner.controller_release import controller_release_digest
from qdev_runner.fleet_bootstrap import (
    REQUEST_SCHEMA,
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    bootstrap_request_fingerprint,
)
from qdev_runner.github_oidc import GitHubActionsArtifactOIDCVerifier, GitHubActionsOIDCError

ROOT = Path(__file__).resolve().parents[1]
_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SAFE_JOB_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/()\-]{0,127}$")
_GITHUB_OIDC_HOSTS = frozenset(
    {
        "token.actions.githubusercontent.com",
        # GitHub Actions currently uses this host for the OIDC request URL on
        # some runner pools.  Keep the allowlist exact; do not accept an
        # arbitrary subdomain of githubusercontent.com.
        "pipelines.actions.githubusercontent.com",
    }
)


class BootstrapValidationError(RuntimeError):
    """The workflow request cannot be verified without exposing a secret."""


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise BootstrapValidationError(f"required environment value is missing: {name}")
    return value


def _positive_int(value: str, name: str) -> int:
    if not value.isdecimal():
        raise BootstrapValidationError(f"{name} must be a positive integer")
    parsed = int(value)
    if parsed < 1:
        raise BootstrapValidationError(f"{name} must be a positive integer")
    return parsed


def _source_sha() -> str:
    current = _required("GITHUB_SHA").lower()
    requested = os.environ.get("BOOTSTRAP_SOURCE_SHA", current).strip().lower()
    if not _SHA.fullmatch(current) or not _SHA.fullmatch(requested):
        raise BootstrapValidationError("workflow source SHA is invalid")
    if requested != current:
        raise BootstrapValidationError("requested source SHA is not the running workflow SHA")
    return current


def _https_url(
    name: str,
    value: str,
    *,
    allowed_host: str | None = None,
    allowed_hosts: frozenset[str] | None = None,
) -> str:
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
        raise BootstrapValidationError(f"{name} must be an HTTPS URL")
    if allowed_host is not None and allowed_hosts is not None:
        raise BootstrapValidationError(f"{name} has conflicting host allowlists")
    if allowed_host is not None and parsed.hostname != allowed_host:
        raise BootstrapValidationError(f"{name} host is not allowlisted")
    if allowed_hosts is not None and parsed.hostname not in allowed_hosts:
        raise BootstrapValidationError(f"{name} host is not allowlisted")
    return value


def _json_request(
    url: str,
    *,
    headers: dict[str, str],
    timeout: float = 10.0,
) -> Any:
    request = urllib.request.Request(  # noqa: S310
        url, headers=headers, method="GET"
    )
    try:
        # ``_https_url`` validates every caller-supplied endpoint before this
        # helper is reached.  Keep the explicit suppression local to the two
        # stdlib calls so a future unvalidated URL cannot hide in this module.
        with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
            body = response.read()
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as error:
        # Never include response bodies: GitHub errors can contain identity or
        # workflow details that are not needed in the action log.
        raise BootstrapValidationError("trusted GitHub endpoint is unavailable") from error
    try:
        return json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BootstrapValidationError("trusted GitHub endpoint returned invalid JSON") from error


def _oidc_token(audience: str) -> str:
    endpoint = _https_url(
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        _required("ACTIONS_ID_TOKEN_REQUEST_URL"),
        allowed_hosts=_GITHUB_OIDC_HOSTS,
    )
    token = _required("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not audience or len(audience) > 256:
        raise BootstrapValidationError("OIDC audience is invalid")
    parsed = urllib.parse.urlsplit(endpoint)
    query = urllib.parse.parse_qsl(parsed.query, keep_blank_values=False)
    query.append(("audience", audience))
    endpoint = urllib.parse.urlunsplit(
        parsed._replace(query=urllib.parse.urlencode(query, doseq=True))
    )
    body = _json_request(
        endpoint,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/jwt",
        },
    )
    token_value = body.get("value") if isinstance(body, dict) else None
    if not isinstance(token_value, str) or not token_value:
        raise BootstrapValidationError("GitHub OIDC endpoint returned no token")
    return token_value


def _github_api_base() -> str:
    return _https_url(
        "GITHUB_API_URL",
        os.environ.get("GITHUB_API_URL", "https://api.github.com"),
    ).rstrip("/")


def _job_list(repository: str, run_id: int) -> list[dict[str, Any]]:
    token = _required("GITHUB_TOKEN")
    endpoint = (
        f"{_github_api_base()}/repos/{urllib.parse.quote(repository, safe='/')}"
        f"/actions/runs/{run_id}/jobs?per_page=100"
    )
    body = _json_request(
        endpoint,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
            "User-Agent": "qdev-fleet-bootstrap-validation",
        },
    )
    if not isinstance(body, dict) or not isinstance(body.get("jobs"), list):
        raise BootstrapValidationError("GitHub jobs response is invalid")
    jobs = [job for job in body["jobs"] if isinstance(job, dict)]
    if len(jobs) != len(body["jobs"]):
        raise BootstrapValidationError("GitHub jobs response contains invalid entries")
    return jobs


def resolve_job_id(repository: str, run_id: int, *, expected_name: str) -> int:
    """Resolve exactly one numeric job ID from the current run.

    A profile label is never accepted as a job identity.  The API response is
    also checked against the current source SHA and run before the ID enters
    the request fingerprint.
    """

    if not _SAFE_JOB_NAME.fullmatch(expected_name):
        raise BootstrapValidationError("bootstrap job name is invalid")
    source_sha = _source_sha()
    jobs = _job_list(repository, run_id)
    matching = [job for job in jobs if job.get("name") == expected_name]
    if len(matching) != 1:
        raise BootstrapValidationError("current bootstrap job is not uniquely discoverable")
    job = matching[0]
    job_id = job.get("id")
    if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 1:
        raise BootstrapValidationError("GitHub returned an invalid numeric job ID")
    if (
        str(job.get("run_id")) != str(run_id)
        or job.get("head_sha") != source_sha
        or job.get("status") not in {"queued", "in_progress", "completed"}
    ):
        raise BootstrapValidationError("GitHub job identity does not match this attempt")
    if job.get("status") == "completed" and job.get("conclusion") != "success":
        raise BootstrapValidationError("completed bootstrap job did not succeed")
    supplied = os.environ.get("BOOTSTRAP_JOB_ID", "").strip()
    if supplied and _positive_int(supplied, "BOOTSTRAP_JOB_ID") != job_id:
        raise BootstrapValidationError("supplied job ID does not match GitHub API")
    return job_id


def build_request(policy: FleetBootstrapPolicy) -> FleetBootstrapRequest:
    repository = _required("GITHUB_REPOSITORY")
    if repository != policy.identity.repository:
        raise BootstrapValidationError("workflow repository is not allowlisted")
    run_id = _positive_int(_required("GITHUB_RUN_ID"), "GITHUB_RUN_ID")
    attempt = _positive_int(
        os.environ.get("GITHUB_RUN_ATTEMPT", "1"), "GITHUB_RUN_ATTEMPT"
    )
    expected_job_name = _required("BOOTSTRAP_JOB_NAME")
    job_id = resolve_job_id(repository, run_id, expected_name=expected_job_name)
    source_sha = _source_sha()
    raw: dict[str, Any] = {
        "schema": REQUEST_SCHEMA,
        "action": _required("BOOTSTRAP_ACTION"),
        "source_sha": source_sha,
        "run_id": run_id,
        "job_id": job_id,
        "attempt": attempt,
        "claim_ttl_seconds": _positive_int(
            os.environ.get("BOOTSTRAP_CLAIM_TTL_SECONDS", "900"),
            "BOOTSTRAP_CLAIM_TTL_SECONDS",
        ),
        "controller_revision": source_sha,
        "controller_release_digest": controller_release_digest(ROOT),
        "release_lane": os.environ.get("BOOTSTRAP_RELEASE_LANE") or None,
        "worker_name": os.environ.get("BOOTSTRAP_WORKER_NAME") or None,
    }
    try:
        request = FleetBootstrapRequest.model_validate(raw)
    except ValidationError as error:
        raise BootstrapValidationError("bootstrap request fields are invalid") from error
    policy.validate(request)
    return request


def validate() -> dict[str, str]:
    policy_path = Path(
        os.environ.get("FLEET_BOOTSTRAP_POLICY", str(ROOT / "config/fleet-bootstrap.yml"))
    )
    release_lanes_path = Path(
        os.environ.get("FLEET_RELEASE_LANES", ROOT / "config/release-lanes.yml")
    )
    try:
        policy = FleetBootstrapPolicy(policy_path, release_lanes_path)
        request = build_request(policy)
        audience = policy.identity.audience
        claims = GitHubActionsArtifactOIDCVerifier(audience=audience).verify_and_decode(
            _oidc_token(audience),
            repository=policy.identity.repository,
            sha=request.source_sha,
            run_id=request.run_id,
        )
        policy.validate_oidc_claims(claims, request)
        idempotency_key = _required("BOOTSTRAP_IDEMPOTENCY_KEY")
        if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise BootstrapValidationError("bootstrap idempotency key is invalid")
        store_path = Path(
            os.environ.get(
                "BOOTSTRAP_OPERATION_STATE",
                str(ROOT / ".fleet-bootstrap-operation.json"),
            )
        )
        record = BootstrapOperationStore(store_path).begin(idempotency_key, request)
    except (FleetBootstrapError, GitHubActionsOIDCError) as error:
        raise BootstrapValidationError("bootstrap request failed closed") from error
    return {
        "status": "validated",
        "operation_status": record.status,
        "request_fingerprint": bootstrap_request_fingerprint(request),
        "idempotency_key": record.idempotency_key,
    }


def main() -> int:
    try:
        result = validate()
    except BootstrapValidationError as error:
        print(f"fleet_bootstrap_validation_failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
