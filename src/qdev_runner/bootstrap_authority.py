"""OIDC admission and signed directives for the existing bootstrap boundary.

The directive uses the existing operator signing key; it is not a newly
minted CA certificate. The privileged adapter must verify it independently.
Tokens and decoded JWT claims are never persisted in operation journals.
"""

from __future__ import annotations

import hashlib
import hmac
import io
import json
import math
import tarfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .controller_image_candidate import WORKFLOW as CANDIDATE_WORKFLOW
from .controller_image_candidate import CandidateReceiptError
from .controller_image_candidate import verify as verify_candidate_receipt
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
CANDIDATE_PROVENANCE_SCHEMA = "qdev-controller-candidate-provenance-v1"
QUIESCENCE_SCHEMA = "qdev-fleet-quiescence-v1"
QUIESCENCE_TTL_SECONDS = 60


def _timestamp(value: object) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
        raise FleetBootstrapError("bootstrap lifetime is invalid")
    return float(value)


def _signature(payload: dict[str, Any], signing_key: str) -> str:
    if not signing_key:
        raise FleetBootstrapError("bootstrap signing identity is unavailable")
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hmac.new(signing_key.encode(), encoded.encode(), hashlib.sha256).hexdigest()


def _digest(payload: dict[str, Any]) -> str:
    encoded = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(encoded.encode()).hexdigest()


def _verify_candidate_provenance(
    provenance: object,
    request: FleetBootstrapRequest,
    *,
    repository: str,
    branch: str,
) -> dict[str, Any] | None:
    """Verify controller-signed evidence for the already completed image build."""

    if request.action != "activate-controller":
        if provenance is not None:
            raise FleetBootstrapError("bootstrap candidate provenance is out of scope")
        return None
    if not isinstance(provenance, dict) or set(provenance) != {
        "schema",
        "repository",
        "workflow",
        "workflow_ref",
        "source_revision",
        "bundle_digest",
        "image_digest",
        "candidate_receipt_digest",
        "candidate_artifact_digest",
        "run_id",
        "run_attempt",
        "job_id",
        "job_name",
        "run_conclusion",
        "job_conclusion",
        "verified_at",
        "provenance_digest",
    }:
        raise FleetBootstrapError("bootstrap candidate provenance is invalid")
    unsigned = {key: value for key, value in provenance.items() if key != "provenance_digest"}
    candidate = verify_candidate_receipt(request.controller_candidate_receipt)
    if (
        provenance.get("schema") != CANDIDATE_PROVENANCE_SCHEMA
        or provenance.get("repository") != repository
        or provenance.get("workflow") != CANDIDATE_WORKFLOW
        or provenance.get("workflow_ref") != f"{CANDIDATE_WORKFLOW}@refs/heads/{branch}"
        or provenance.get("source_revision") != request.controller_revision
        or provenance.get("bundle_digest") != candidate["bundle_digest"]
        or provenance.get("image_digest") != request.controller_release_digest
        or provenance.get("candidate_receipt_digest") != candidate["receipt_digest"]
        or not isinstance(provenance.get("candidate_artifact_digest"), str)
        or len(provenance["candidate_artifact_digest"]) != 64
        or any(
            character not in "0123456789abcdef"
            for character in provenance["candidate_artifact_digest"]
        )
        or provenance.get("run_id") != int(candidate["run_id"])
        or provenance.get("run_attempt") != candidate["run_attempt"]
        or type(provenance.get("job_id")) is not int
        or provenance["job_id"] < 1
        or provenance.get("job_name") != candidate["job"]
        or provenance.get("run_conclusion") != "success"
        or provenance.get("job_conclusion") != "success"
        or not math.isfinite(_timestamp(provenance.get("verified_at")))
        or provenance.get("provenance_digest") != _digest(unsigned)
    ):
        raise FleetBootstrapError("bootstrap candidate provenance binding is invalid")
    return dict(provenance)


def _candidate_artifact(
    *,
    artifact_root: Path,
    repository: str,
    source_revision: str,
    job_id: int,
    run_attempt: int,
    expected_receipt: dict[str, Any],
) -> str:
    """Read the completed job's immutable receipt from controller-owned storage."""

    try:
        owner, repo = repository.split("/", 1)
    except ValueError as error:
        raise FleetBootstrapError("bootstrap candidate repository is invalid") from error
    name = f"controller-image-candidate-{source_revision}-{run_attempt}.tar.gz"
    archive = artifact_root / owner / repo / source_revision / str(job_id) / name
    if archive.is_symlink() or not archive.is_file():
        raise FleetBootstrapError("bootstrap candidate artifact is unavailable")
    try:
        body = archive.read_bytes()
    except OSError as error:
        raise FleetBootstrapError("bootstrap candidate artifact is unreadable") from error
    if not body or len(body) > 1024 * 1024:
        raise FleetBootstrapError("bootstrap candidate artifact size is invalid")
    try:
        with tarfile.open(fileobj=io.BytesIO(body), mode="r:gz") as bundle:
            members = bundle.getmembers()
            if (
                len(members) != 1
                or not members[0].isfile()
                or Path(members[0].name).name != "controller-image-candidate-receipt.json"
                or members[0].size < 2
                or members[0].size > 64 * 1024
            ):
                raise FleetBootstrapError("bootstrap candidate artifact shape is invalid")
            extracted = bundle.extractfile(members[0])
            if extracted is None:
                raise FleetBootstrapError("bootstrap candidate receipt is unavailable")
            archived_receipt = verify_candidate_receipt(json.loads(extracted.read()))
    except (
        tarfile.TarError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        CandidateReceiptError,
    ) as error:
        raise FleetBootstrapError("bootstrap candidate artifact is invalid") from error
    if archived_receipt != expected_receipt:
        raise FleetBootstrapError("bootstrap candidate artifact receipt does not match")
    return hashlib.sha256(body).hexdigest()


def _candidate_provenance(
    request: FleetBootstrapRequest,
    *,
    github: GitHubAppClient,
    installation: int,
    repository: str,
    branch: str,
    artifact_root: Path,
    now: float,
) -> dict[str, Any] | None:
    if request.action != "activate-controller":
        return None
    candidate = verify_candidate_receipt(request.controller_candidate_receipt)
    run_id = int(candidate["run_id"])
    attempt = int(candidate["run_attempt"])
    run = github.workflow_run(installation, repository, run_id)
    jobs = github.workflow_jobs(installation, repository, run_id, attempt)
    matches = [job for job in jobs if job.get("name") == candidate["job"]]
    if len(matches) != 1:
        raise FleetBootstrapError("bootstrap candidate job is not uniquely verifiable")
    job = matches[0]
    job_id = job.get("id")
    if (
        run.get("id") != run_id
        or run.get("run_attempt") != attempt
        or run.get("head_sha") != request.controller_revision
        or run.get("head_branch") != branch
        or run.get("path") != CANDIDATE_WORKFLOW
        or run.get("event") != "workflow_dispatch"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or type(job_id) is not int
        or job_id < 1
        or job.get("run_id") != run_id
        or job.get("run_attempt") != attempt
        or job.get("head_sha") != request.controller_revision
        or job.get("status") != "completed"
        or job.get("conclusion") != "success"
    ):
        raise FleetBootstrapError("bootstrap candidate GitHub provenance does not match")
    candidate_artifact_digest = _candidate_artifact(
        artifact_root=artifact_root,
        repository=repository,
        source_revision=request.controller_revision,
        job_id=job_id,
        run_attempt=attempt,
        expected_receipt=candidate,
    )
    payload = {
        "schema": CANDIDATE_PROVENANCE_SCHEMA,
        "repository": repository,
        "workflow": CANDIDATE_WORKFLOW,
        "workflow_ref": f"{CANDIDATE_WORKFLOW}@refs/heads/{branch}",
        "source_revision": request.controller_revision,
        "bundle_digest": candidate["bundle_digest"],
        "image_digest": request.controller_release_digest,
        "candidate_receipt_digest": candidate["receipt_digest"],
        "candidate_artifact_digest": candidate_artifact_digest,
        "run_id": run_id,
        "run_attempt": attempt,
        "job_id": job_id,
        "job_name": candidate["job"],
        "run_conclusion": "success",
        "job_conclusion": "success",
        "verified_at": now,
    }
    return {**payload, "provenance_digest": _digest(payload)}


@dataclass(frozen=True)
class VerifiedBootstrapOperation:
    request: FleetBootstrapRequest
    idempotency_key: str
    fence: str
    directive: dict[str, Any]


def create_quiescence_receipt(
    operation: VerifiedBootstrapOperation,
    *,
    target_id: str,
    state_revision: str,
    active_jobs: int,
    signing_key: str,
) -> dict[str, Any]:
    """Sign a short-lived controller scheduler observation for root execution."""

    if (
        not target_id
        or len(state_revision) != 64
        or any(character not in "0123456789abcdef" for character in state_revision)
        or type(active_jobs) is not int
        or active_jobs < 0
    ):
        raise FleetBootstrapError("bootstrap quiescence state is invalid")
    now = time.time()
    operation_expiry = _timestamp(operation.directive["payload"]["expires_at"])
    payload = {
        "schema": QUIESCENCE_SCHEMA,
        "operation_fence": operation.fence,
        "target_id": target_id,
        "state_revision": state_revision,
        "active_jobs": active_jobs,
        "issued_at": now,
        "expires_at": min(operation_expiry, now + QUIESCENCE_TTL_SECONDS),
    }
    return {"payload": payload, "signature": _signature(payload, signing_key)}


def verify_quiescence_receipt(
    receipt: object,
    *,
    operation: VerifiedBootstrapOperation,
    target_id: str,
    signing_key: str,
) -> dict[str, Any]:
    """Verify a quiescence observation and bind it to one signed operation."""

    if not isinstance(receipt, dict) or set(receipt) != {"payload", "signature"}:
        raise FleetBootstrapError("bootstrap quiescence receipt is invalid")
    payload = receipt.get("payload")
    signature = receipt.get("signature")
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "schema",
            "operation_fence",
            "target_id",
            "state_revision",
            "active_jobs",
            "issued_at",
            "expires_at",
        }
        or not isinstance(signature, str)
    ):
        raise FleetBootstrapError("bootstrap quiescence receipt is invalid")
    if not hmac.compare_digest(signature, _signature(payload, signing_key)):
        raise FleetBootstrapError("bootstrap quiescence signature is invalid")
    issued = _timestamp(payload["issued_at"])
    expires = _timestamp(payload["expires_at"])
    now = time.time()
    state_revision = payload.get("state_revision")
    active_jobs = payload.get("active_jobs")
    if (
        payload.get("schema") != QUIESCENCE_SCHEMA
        or payload.get("operation_fence") != operation.fence
        or payload.get("target_id") != target_id
        or not isinstance(state_revision, str)
        or len(state_revision) != 64
        or any(character not in "0123456789abcdef" for character in state_revision)
        or type(active_jobs) is not int
        or active_jobs != 0
        or issued > now
        or now >= expires
        or not 0 < expires - issued <= QUIESCENCE_TTL_SECONDS
        or expires > _timestamp(operation.directive["payload"]["expires_at"])
    ):
        raise FleetBootstrapError("bootstrap quiescence binding is invalid")
    return dict(payload)


def verify_directive(
    directive: dict[str, Any],
    *,
    policy: FleetBootstrapPolicy,
    signing_key: str,
) -> VerifiedBootstrapOperation:
    return _verify_directive(directive, policy=policy, signing_key=signing_key, active=True)


def _verify_directive(
    directive: dict[str, Any],
    *,
    policy: FleetBootstrapPolicy,
    signing_key: str,
    active: bool,
) -> VerifiedBootstrapOperation:
    if not isinstance(directive, dict) or set(directive) != {"payload", "signature"}:
        raise FleetBootstrapError("bootstrap directive is invalid")
    payload, signature = directive["payload"], directive["signature"]
    if (
        not isinstance(payload, dict)
        or set(payload)
        != {
            "schema",
            "request",
            "idempotency_key",
            "fence",
            "issued_at",
            "expires_at",
            "candidate_provenance",
        }
        or not isinstance(signature, str)
    ):
        raise FleetBootstrapError("bootstrap directive is invalid")
    if not hmac.compare_digest(signature, _signature(payload, signing_key)):
        raise FleetBootstrapError("bootstrap directive signature is invalid")
    request = FleetBootstrapRequest.model_validate(payload["request"])
    policy.validate(request)
    _verify_candidate_provenance(
        payload["candidate_provenance"],
        request,
        repository=policy.identity.repository,
        branch=policy.identity.branch,
    )
    key = payload["idempotency_key"]
    if not isinstance(key, str):
        raise FleetBootstrapError("bootstrap directive operation key is invalid")
    BootstrapOperationStore._validate_key(key)  # noqa: SLF001
    issued, expires = _timestamp(payload["issued_at"]), _timestamp(payload["expires_at"])
    now = time.time()
    if (
        issued > now
        or not 0 < expires - issued <= request.claim_ttl_seconds
        or (active and now >= expires)
    ):
        raise FleetBootstrapError("bootstrap directive is expired or not active")
    fence = hashlib.sha256(f"{key}:{bootstrap_request_fingerprint(request)}".encode()).hexdigest()
    if payload["schema"] != SCHEMA or payload["fence"] != fence:
        raise FleetBootstrapError("bootstrap directive binding is invalid")
    return VerifiedBootstrapOperation(request, key, fence, directive)


def renew_bootstrap_operation(
    original: dict[str, Any],
    fresh: VerifiedBootstrapOperation,
    *,
    policy: FleetBootstrapPolicy,
    signing_key: str,
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
    if previous.idempotency_key != fresh.idempotency_key or previous.request.model_dump(
        exclude=ignored
    ) != fresh.request.model_dump(exclude=ignored):
        raise FleetBootstrapError("bootstrap reconciliation intent changed")
    issued = fresh.directive["payload"]["issued_at"]
    payload = {
        **previous.directive["payload"],
        "issued_at": issued,
        "expires_at": min(
            fresh.directive["payload"]["expires_at"],
            issued + previous.request.claim_ttl_seconds,
        ),
    }
    return verify_directive(
        {"payload": payload, "signature": _signature(payload, signing_key)},
        policy=policy,
        signing_key=signing_key,
    )


def authorize_bootstrap(
    *,
    token: str,
    request: FleetBootstrapRequest,
    idempotency_key: str,
    policy: FleetBootstrapPolicy,
    verifier: GitHubActionsArtifactOIDCVerifier,
    github: GitHubAppClient,
    controller_store: Store,
    artifact_root: Path,
    signing_key: str,
) -> VerifiedBootstrapOperation:
    policy.validate(request)
    BootstrapOperationStore._validate_key(idempotency_key)  # noqa: SLF001
    claims = verifier.verify_and_decode(
        token,
        repository=policy.identity.repository,
        sha=request.source_sha,
        run_id=request.run_id,
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
        row["repository"] != policy.identity.repository
        or row["head_sha"] != request.source_sha
        or row["run_id"] != request.run_id
        or row["status"] not in {"claimed", "running"}
    ):
        raise FleetBootstrapError("bootstrap controller job identity is unavailable")
    installation = int(row["installation_id"])
    job = github.workflow_job(installation, policy.identity.repository, request.job_id)
    run = github.workflow_run(installation, policy.identity.repository, request.run_id)
    if (
        job.get("id") != request.job_id
        or job.get("run_id") != request.run_id
        or job.get("run_attempt") != request.attempt
        or job.get("head_sha") != request.source_sha
        or job.get("status") != "in_progress"
        or job.get("name") != "fleet-bootstrap-execute"
        or run.get("id") != request.run_id
        or run.get("run_attempt") != request.attempt
        or run.get("head_sha") != request.source_sha
        or run.get("head_branch") != policy.identity.branch
        or run.get("path") != policy.identity.workflow
        or run.get("event") != "workflow_dispatch"
        or run.get("status") != "in_progress"
    ):
        raise FleetBootstrapError("bootstrap GitHub job attempt does not match")
    candidate_provenance = _candidate_provenance(
        request,
        github=github,
        installation=installation,
        repository=policy.identity.repository,
        branch=policy.identity.branch,
        artifact_root=artifact_root,
        now=now,
    )
    payload = {
        "schema": SCHEMA,
        "request": request.model_dump(mode="json", by_alias=True),
        "idempotency_key": idempotency_key,
        "fence": hashlib.sha256(
            f"{idempotency_key}:{bootstrap_request_fingerprint(request)}".encode()
        ).hexdigest(),
        "issued_at": now,
        "expires_at": min(expires, now + request.claim_ttl_seconds),
        "candidate_provenance": candidate_provenance,
    }
    return verify_directive(
        {"payload": payload, "signature": _signature(payload, signing_key)},
        policy=policy,
        signing_key=signing_key,
    )
