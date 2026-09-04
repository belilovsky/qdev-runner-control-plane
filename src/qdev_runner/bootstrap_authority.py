"""OIDC admission and signed directives for the existing bootstrap boundary.

The directive uses the existing operator signing key; it is not a newly
minted CA certificate. The privileged adapter must verify it independently.
Tokens and decoded JWT claims are never persisted in operation journals.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import time
from dataclasses import dataclass
from typing import Any

from .fleet_bootstrap import (
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    bootstrap_request_fingerprint,
)
from .github import GitHubAppClient
from .github_oidc import GitHubActionsArtifactOIDCVerifier
from .store import Store

SCHEMA = "qdev-fleet-bootstrap-directive-v1"


def _timestamp(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise FleetBootstrapError("bootstrap lifetime is invalid")
    return float(value)


def _signature(payload: dict[str, Any], signing_key: str) -> str:
    if not signing_key:
        raise FleetBootstrapError("bootstrap signing identity is unavailable")
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hmac.new(signing_key.encode(), encoded.encode(), hashlib.sha256).hexdigest()


@dataclass(frozen=True)
class VerifiedBootstrapOperation:
    request: FleetBootstrapRequest
    idempotency_key: str
    fence: str
    directive: dict[str, Any]


def verify_directive(
    directive: dict[str, Any], *, policy: FleetBootstrapPolicy, signing_key: str,
) -> VerifiedBootstrapOperation:
    return _verify_directive(directive, policy=policy, signing_key=signing_key, active=True)


def _verify_directive(
    directive: dict[str, Any], *, policy: FleetBootstrapPolicy, signing_key: str, active: bool,
) -> VerifiedBootstrapOperation:
    if not isinstance(directive, dict) or set(directive) != {"payload", "signature"}:
        raise FleetBootstrapError("bootstrap directive is invalid")
    payload, signature = directive["payload"], directive["signature"]
    if not isinstance(payload, dict) or set(payload) != {
        "schema", "request", "idempotency_key", "fence", "issued_at", "expires_at",
    } or not isinstance(signature, str):
        raise FleetBootstrapError("bootstrap directive is invalid")
    if not hmac.compare_digest(signature, _signature(payload, signing_key)):
        raise FleetBootstrapError("bootstrap directive signature is invalid")
    request = FleetBootstrapRequest.model_validate(payload["request"])
    policy.validate(request)
    key = payload["idempotency_key"]
    if not isinstance(key, str):
        raise FleetBootstrapError("bootstrap directive operation key is invalid")
    BootstrapOperationStore._validate_key(key)  # noqa: SLF001
    issued, expires = _timestamp(payload["issued_at"]), _timestamp(payload["expires_at"])
    now = time.time()
    if (
        issued > now or not 0 < expires - issued <= request.claim_ttl_seconds
        or (active and now >= expires)
    ):
        raise FleetBootstrapError("bootstrap directive is expired or not active")
    fence = hashlib.sha256(f"{key}:{bootstrap_request_fingerprint(request)}".encode()).hexdigest()
    if payload["schema"] != SCHEMA or payload["fence"] != fence:
        raise FleetBootstrapError("bootstrap directive binding is invalid")
    return VerifiedBootstrapOperation(request, key, fence, directive)


def renew_bootstrap_operation(
    original: dict[str, Any], fresh: VerifiedBootstrapOperation, *,
    policy: FleetBootstrapPolicy, signing_key: str,
) -> VerifiedBootstrapOperation:
    """Fresh admission can reconcile the same intent, never change its original fence.

    The original directive is read from the controller-owned immutable journal.
    Its signature and complete binding remain mandatory even after expiry. Only
    the run/job/attempt and shorter-lived authorization may change; the original
    source and operational target stay pinned. The fresh attempt must separately
    pass GitHub OIDC and active job admission before reaching this function.
    """
    previous = _verify_directive(original, policy=policy, signing_key=signing_key, active=False)
    fresh = verify_directive(fresh.directive, policy=policy, signing_key=signing_key)
    ignored = {"run_id", "job_id", "attempt", "claim_ttl_seconds"}
    if (
        previous.idempotency_key != fresh.idempotency_key
        or previous.request.model_dump(exclude=ignored) != fresh.request.model_dump(exclude=ignored)
    ):
        raise FleetBootstrapError("bootstrap reconciliation intent changed")
    issued = fresh.directive["payload"]["issued_at"]
    payload = {
        **previous.directive["payload"], "issued_at": issued,
        "expires_at": min(
            fresh.directive["payload"]["expires_at"], issued + previous.request.claim_ttl_seconds,
        ),
    }
    return verify_directive(
        {"payload": payload, "signature": _signature(payload, signing_key)},
        policy=policy, signing_key=signing_key,
    )


def authorize_bootstrap(
    *, token: str, request: FleetBootstrapRequest, idempotency_key: str,
    policy: FleetBootstrapPolicy, verifier: GitHubActionsArtifactOIDCVerifier,
    github: GitHubAppClient, controller_store: Store, signing_key: str,
) -> VerifiedBootstrapOperation:
    policy.validate(request)
    BootstrapOperationStore._validate_key(idempotency_key)  # noqa: SLF001
    claims = verifier.verify_and_decode(
        token, repository=policy.identity.repository, sha=request.source_sha, run_id=request.run_id,
    )
    policy.validate_oidc_claims(claims, request)
    now = time.time()
    issued, expires = _timestamp(claims.get("iat")), _timestamp(claims.get("exp"))
    if (
        not issued <= now < expires
        or not 0 < expires - issued <= policy.identity.max_claim_ttl_seconds
        or claims.get("event_name") != "workflow_dispatch"
    ):
        raise FleetBootstrapError("bootstrap OIDC lifetime or event is invalid")
    # Installation identity comes from an authenticated webhook record, never
    # from request JSON. A missing record is an admission gap, not an approval.
    row = controller_store.job(request.job_id)
    if not row or (
        row["repository"] != policy.identity.repository or row["head_sha"] != request.source_sha
        or row["run_id"] != request.run_id or row["status"] not in {"claimed", "running"}
    ):
        raise FleetBootstrapError("bootstrap controller job identity is unavailable")
    installation = int(row["installation_id"])
    job = github.workflow_job(installation, policy.identity.repository, request.job_id)
    run = github.workflow_run(installation, policy.identity.repository, request.run_id)
    if (
        job.get("id") != request.job_id or job.get("run_id") != request.run_id
        or job.get("run_attempt") != request.attempt or job.get("head_sha") != request.source_sha
        or job.get("status") != "in_progress" or job.get("name") != "fleet-bootstrap-execute"
        or run.get("id") != request.run_id or run.get("run_attempt") != request.attempt
        or run.get("head_sha") != request.source_sha
        or run.get("head_branch") != policy.identity.branch
        or run.get("path") != policy.identity.workflow or run.get("event") != "workflow_dispatch"
        or run.get("status") != "in_progress"
    ):
        raise FleetBootstrapError("bootstrap GitHub job attempt does not match")
    payload = {
        "schema": SCHEMA, "request": request.model_dump(mode="json", by_alias=True),
        "idempotency_key": idempotency_key,
        "fence": hashlib.sha256(
            f"{idempotency_key}:{bootstrap_request_fingerprint(request)}".encode()
        ).hexdigest(),
        "issued_at": now, "expires_at": min(expires, now + request.claim_ttl_seconds),
    }
    return verify_directive(
        {"payload": payload, "signature": _signature(payload, signing_key)},
        policy=policy, signing_key=signing_key,
    )
