#!/usr/bin/env python3
"""Validate one signed GitHub Actions request for fleet bootstrap.

It binds the current workflow attempt to the numeric GitHub job and to an
immutable controller artifact digest. The controller still independently
verifies the OIDC identity, mints the short-lived operation directive and
performs only the allowlisted transition through a fixed privileged adapter.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from qdev_runner.fleet_bootstrap import (
    REQUEST_SCHEMA,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    bootstrap_request_fingerprint,
)
from qdev_runner.github_oidc import GitHubActionsArtifactOIDCVerifier, GitHubActionsOIDCError
from qdev_runner.operator import run as operator_run

ROOT = Path(__file__).resolve().parents[1]
_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SAFE_JOB_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._:/()\-]{0,127}$")
_GITHUB_API_ORIGIN = "https://api.github.com"
_OIDC_MINT_HOST = re.compile(
    r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+actions\.githubusercontent\.com$"
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


def _https_url(name: str, value: str, *, allowed_host: str | None = None) -> str:
    if "\\" in value or any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in value):
        raise BootstrapValidationError(f"{name} must be an HTTPS URL")
    try:
        parsed = urllib.parse.urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise BootstrapValidationError(f"{name} must be an HTTPS URL") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
    ):
        raise BootstrapValidationError(f"{name} must be an HTTPS URL")
    if allowed_host is not None and parsed.hostname != allowed_host:
        raise BootstrapValidationError(f"{name} host is not allowlisted")
    return value


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never resend a workflow bearer to a redirect target, even on the same origin."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


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
        # Callers validate the initial URL; disabling redirects preserves that
        # origin boundary for both the Actions runtime bearer and GITHUB_TOKEN.
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(request, timeout=timeout) as response:  # noqa: S310
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
    )
    parsed = urllib.parse.urlsplit(endpoint)
    # The mint endpoint is regional, unlike the fixed JWT issuer. GitHub's
    # runner supplies a host under *.actions.githubusercontent.com.
    if not _OIDC_MINT_HOST.fullmatch(parsed.hostname or ""):
        raise BootstrapValidationError("ACTIONS_ID_TOKEN_REQUEST_URL host is not allowlisted")
    token = _required("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
    if not audience or len(audience) > 256:
        raise BootstrapValidationError("OIDC audience is invalid")
    query = [
        (key, value)
        for key, value in urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
        if key != "audience"
    ]
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
    endpoint = _https_url(
        "GITHUB_API_URL",
        os.environ.get("GITHUB_API_URL", _GITHUB_API_ORIGIN),
        allowed_host="api.github.com",
    )
    parsed = urllib.parse.urlsplit(endpoint)
    if parsed.path not in {"", "/"} or parsed.query:
        raise BootstrapValidationError("GITHUB_API_URL must be the GitHub API origin")
    return _GITHUB_API_ORIGIN


def _job_list(repository: str, run_id: int, attempt: int) -> list[dict[str, Any]]:
    token = _required("GITHUB_TOKEN")
    endpoint = (
        f"{_github_api_base()}/repos/{urllib.parse.quote(repository, safe='/')}"
        f"/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"
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


def resolve_job_id(repository: str, run_id: int, *, attempt: int, expected_name: str) -> int:
    """Resolve exactly one running numeric job ID from the current attempt.

    A profile label is never accepted as a job identity.  The API response is
    also checked against the current source SHA, run and attempt before the ID
    enters the request fingerprint.
    """

    if not _SAFE_JOB_NAME.fullmatch(expected_name):
        raise BootstrapValidationError("bootstrap job name is invalid")
    source_sha = _source_sha()
    jobs = _job_list(repository, run_id, attempt)
    matching = [job for job in jobs if job.get("name") == expected_name]
    if len(matching) != 1:
        raise BootstrapValidationError("current bootstrap job is not uniquely discoverable")
    job = matching[0]
    job_id = job.get("id")
    if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 1:
        raise BootstrapValidationError("GitHub returned an invalid numeric job ID")
    if (
        type(job.get("run_id")) is not int
        or job["run_id"] != run_id
        or type(job.get("run_attempt")) is not int
        or job["run_attempt"] != attempt
        or job.get("head_sha") != source_sha
        or job.get("status") != "in_progress"
        or job.get("conclusion") is not None
    ):
        raise BootstrapValidationError("GitHub job identity does not match this attempt")
    supplied = os.environ.get("BOOTSTRAP_JOB_ID", "").strip()
    if supplied and _positive_int(supplied, "BOOTSTRAP_JOB_ID") != job_id:
        raise BootstrapValidationError("supplied job ID does not match GitHub API")
    return job_id


def build_request(policy: FleetBootstrapPolicy) -> FleetBootstrapRequest:
    repository = _required("GITHUB_REPOSITORY")
    if repository != policy.identity.repository:
        raise BootstrapValidationError("workflow repository is not allowlisted")
    run_id = _positive_int(_required("GITHUB_RUN_ID"), "GITHUB_RUN_ID")
    attempt = _positive_int(_required("GITHUB_RUN_ATTEMPT"), "GITHUB_RUN_ATTEMPT")
    expected_job_name = _required("BOOTSTRAP_JOB_NAME")
    job_id = resolve_job_id(repository, run_id, attempt=attempt, expected_name=expected_job_name)
    action = _required("BOOTSTRAP_ACTION")
    candidate_raw = os.environ.get("BOOTSTRAP_CONTROLLER_CANDIDATE_RECEIPT", "").strip()
    candidate: object = None
    if action == "activate-controller":
        if not candidate_raw or len(candidate_raw.encode("utf-8")) > 16_384:
            raise BootstrapValidationError("controller candidate receipt is required")
        try:
            candidate = json.loads(candidate_raw)
        except json.JSONDecodeError as error:
            raise BootstrapValidationError("controller candidate receipt is invalid") from error
    elif candidate_raw:
        raise BootstrapValidationError("controller candidate receipt is out of scope")
    raw: dict[str, Any] = {
        "schema": REQUEST_SCHEMA,
        "action": action,
        "source_sha": _source_sha(),
        "run_id": run_id,
        "job_id": job_id,
        "attempt": attempt,
        "claim_ttl_seconds": _positive_int(
            os.environ.get("BOOTSTRAP_CLAIM_TTL_SECONDS", "900"),
            "BOOTSTRAP_CLAIM_TTL_SECONDS",
        ),
        "controller_revision": _required("BOOTSTRAP_CONTROLLER_REVISION").lower(),
        "controller_release_digest": _required("BOOTSTRAP_CONTROLLER_RELEASE_DIGEST").lower(),
        "controller_candidate_receipt": candidate,
        "release_lane": os.environ.get("BOOTSTRAP_RELEASE_LANE") or None,
        "worker_name": os.environ.get("BOOTSTRAP_WORKER_NAME") or None,
    }
    try:
        request = FleetBootstrapRequest.model_validate(raw)
    except ValidationError as error:
        raise BootstrapValidationError("bootstrap request fields are invalid") from error
    policy.validate(request)
    return request


def _validated_operation() -> tuple[FleetBootstrapRequest, str, str]:
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
        token = _oidc_token(audience)
        claims = GitHubActionsArtifactOIDCVerifier(audience=audience).verify_and_decode(
            token,
            repository=policy.identity.repository,
            sha=request.source_sha,
            run_id=request.run_id,
        )
        policy.validate_oidc_claims(claims, request)
        idempotency_key = _required("BOOTSTRAP_IDEMPOTENCY_KEY")
        if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
            raise BootstrapValidationError("bootstrap idempotency key is invalid")
    except (FleetBootstrapError, GitHubActionsOIDCError) as error:
        raise BootstrapValidationError("bootstrap request failed closed") from error
    return request, idempotency_key, token


def validate() -> dict[str, str]:
    request, idempotency_key, _ = _validated_operation()
    return {
        "status": "validated",
        "request_fingerprint": bootstrap_request_fingerprint(request),
        "idempotency_key": idempotency_key,
    }


def execute() -> dict[str, str]:
    """Validate once, then submit that exact identity to the controller."""

    request, idempotency_key, oidc_token = _validated_operation()
    descriptor, temporary = tempfile.mkstemp(prefix="qdev-fleet-bootstrap-", suffix=".json")
    request_path = Path(temporary)
    previous_token = os.environ.get("QDEV_BOOTSTRAP_OIDC_TOKEN")
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(
                request.model_dump(mode="json", by_alias=True),
                stream,
                ensure_ascii=True,
                sort_keys=True,
                separators=(",", ":"),
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.environ["QDEV_BOOTSTRAP_OIDC_TOKEN"] = oidc_token
        receipt = operator_run(
            [
                "fleet-bootstrap",
                "--request",
                str(request_path),
                "--idempotency-key",
                idempotency_key,
                "--timeout-seconds",
                "120",
            ]
        )
    except (OSError, RuntimeError, ValueError) as error:
        raise BootstrapValidationError("controller bootstrap execution failed closed") from error
    finally:
        request_path.unlink(missing_ok=True)
        if previous_token is None:
            os.environ.pop("QDEV_BOOTSTRAP_OIDC_TOKEN", None)
        else:
            os.environ["QDEV_BOOTSTRAP_OIDC_TOKEN"] = previous_token
    payload = receipt.get("payload") if isinstance(receipt, dict) else None
    if (
        not isinstance(payload, dict)
        or payload.get("kind") != "fleet-bootstrap"
        or payload.get("status") != "completed"
        or payload.get("operation_status") != "completed"
        or payload.get("action") != request.action
        or payload.get("idempotency_key") != idempotency_key
        or payload.get("request_fingerprint") != bootstrap_request_fingerprint(request)
    ):
        raise BootstrapValidationError("controller did not complete the exact bootstrap request")
    receipt_digest = hashlib.sha256(
        json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "status": "completed",
        "action": request.action,
        "request_fingerprint": bootstrap_request_fingerprint(request),
        "idempotency_key": idempotency_key,
        "controller_receipt_digest": receipt_digest,
    }


def main() -> int:
    try:
        result = execute()
    except BootstrapValidationError as error:
        print(f"fleet_bootstrap_validation_failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
