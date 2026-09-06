"""Controller-owned, product-specific immutable release lanes.

This module deliberately sits outside the GitHub Actions worker queue.  A
release lane admits an already-built artifact only after a fresh mTLS host-agent
preflight proves capacity, lock availability and a distinct verified rollback.
The host agent later returns its own runtime receipt after it has checked and
promoted the exact immutable tuple.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError

if TYPE_CHECKING:
    from .github import GitHubAppClient

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_SEGMENT = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}$")
_ARTIFACT_REPOSITORY = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}$")
_CANONICAL_REPOSITORY = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,38}/[a-z0-9][a-z0-9_.-]{0,99}$")
_ARTIFACT_PREFIX = re.compile(r"^(?:[a-z0-9][a-z0-9.-]{0,62}/)?[a-z0-9][a-z0-9._/-]{1,191}$")
_NATIVE_ADAPTER = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}-v[1-9][0-9]*$")
_CI_SCOPE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$")
_RUNNER_PROFILES = frozenset({"qdev-ci", "qdev-ci-docker", "qdev-ci-browser"})

REQUEST_SCHEMA = "qdev-controller-release-request-v1"
RECEIPT_SCHEMA = "qdev-controller-release-receipt-v1"
HOST_HEARTBEAT_SCHEMA = "qdev-release-host-agent-heartbeat-v1"
RUNTIME_RECEIPT_SCHEMA = "qdev-controller-release-runtime-receipt-v1"
ROLLBACK_RECEIPT_SCHEMA = "qdev-controller-release-rollback-receipt-v1"
CONTROLLER_CLAIM_SCHEMA = "qdev-controller-release-claim-v3"
HOST_DISPATCH_CLAIM_SCHEMA = "qdev-controller-host-dispatch-claim-v2"
OPERATION_JOURNAL_SCHEMA = "qdev-controller-release-operation-v3"
_JOURNAL_GENESIS = "0" * 64
_CONTROLLER_CLAIM_MAX_TTL_SECONDS = 300
_CONTROLLER_CLAIM_CLOCK_SKEW_SECONDS = 30
_DISPATCH_CLAIM_MAX_TTL_SECONDS = 300
_RELEASE_LEASE_DEFAULT_TTL_SECONDS = 3600
_RELEASE_LEASE_MAX_TTL_SECONDS = 86400
LEGACY_COMPATIBILITY_LANES = frozenset(
    {
        "qdev-release-qaz-tours",
        "qdev-release-qaz-fund",
        "qdev-release-qaz-events",
        "qdev-release-qmt",
        # QazGeo is an existing managed-production lane.  Keep its exact
        # legacy shape until its source-bound v2 profile is separately
        # admitted; never infer a partial v2 binding from the old record.
        "qdev-release-qazgeo",
    }
)
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
QMT_CANDIDATE_EVIDENCE_SCHEMA = "qdev-qmt-candidate-evidence-v1"


class ReleaseLaneError(RuntimeError):
    """A release lane policy or durable state is invalid."""


class ReleaseAdmissionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_name: str = Field(alias="schema")
    release_lane: str
    project_id: str
    placement: str
    source_sha: str
    artifact_digest: str
    artifact_ref: str
    candidate_receipt: dict[str, Any]
    # A controller-issued claim is optional for the published legacy lanes and
    # mandatory whenever the deployment edge is configured with a claim key.
    # Keeping it in the typed request prevents callers from smuggling an
    # unvalidated claim through an arbitrary JSON field.
    controller_claim: dict[str, Any] | None = None
    controller_claim_signature: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class HostHeartbeatRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_name: str = Field(alias="schema")
    release_lane: str
    project_id: str
    placement: str
    state: str
    release_lock: str
    capacity_free_gib: float = Field(ge=0)
    active_release: dict[str, Any]
    rollback: dict[str, Any]
    bootstrap: bool = False


@dataclass(frozen=True)
class ReleaseLane:
    name: str
    project_id: str
    placement: str
    client_mtls_identity: str
    host_agent_mtls_identity: str
    minimum_free_gib: float
    heartbeat_ttl_seconds: int
    artifact_repository: str
    canonical_repository: str | None
    artifact_ref_prefix: str
    native_host_adapter: str
    runtime_endpoints: tuple[str, ...]
    rollback_reference: str
    required_readiness: tuple[str, ...]


class ReleaseLanePolicy:
    def __init__(self, path: Path) -> None:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ReleaseLaneError("release lane policy is unavailable") from exc
        if not isinstance(document, dict) or set(document) != {"schema_version", "lanes"}:
            raise ReleaseLaneError("release lane policy shape is invalid")
        schema_version = document["schema_version"]
        if schema_version not in {"qdev-release-lanes-v1", "qdev-release-lanes-v2"}:
            raise ReleaseLaneError("release lane policy schema is invalid")
        raw_lanes = document["lanes"]
        if not isinstance(raw_lanes, dict) or not raw_lanes:
            raise ReleaseLaneError("release lane policy has no lanes")
        lanes: dict[str, ReleaseLane] = {}
        for name, raw in raw_lanes.items():
            if not isinstance(name, str) or not _SEGMENT.fullmatch(name):
                raise ReleaseLaneError("release lane name is invalid")
            if not isinstance(raw, dict):
                raise ReleaseLaneError("release lane entry is invalid")
            legacy_expected = {
                "project_id",
                "placement",
                "client_mtls_identity",
                "host_agent_mtls_identity",
                "minimum_free_gib",
                "heartbeat_ttl_seconds",
                "artifact_repository",
            }
            v2_expected = legacy_expected | {
                "canonical_repository",
                "artifact_ref_prefix",
                "native_host_adapter",
                "runtime_endpoints",
                "rollback_reference",
                "required_readiness",
            }
            # A v2 policy may retain a pre-existing lane whose source binding
            # has not yet been verified. Treat only the exact legacy shape as
            # compatibility data; new Admin Platform lanes must be complete v2
            # records and cannot silently lose their bindings.
            is_legacy_entry = set(raw) == legacy_expected
            expected = legacy_expected if schema_version == "qdev-release-lanes-v1" else v2_expected
            if schema_version == "qdev-release-lanes-v2" and is_legacy_entry:
                if name not in LEGACY_COMPATIBILITY_LANES:
                    raise ReleaseLaneError(
                        "legacy release lane is not an explicit compatibility lane"
                    )
                expected = legacy_expected
            if set(raw) != expected:
                raise ReleaseLaneError("release lane fields are invalid")
            try:
                minimum_free_gib = float(raw["minimum_free_gib"])
                heartbeat_ttl_seconds = int(raw["heartbeat_ttl_seconds"])
            except (TypeError, ValueError) as exc:
                raise ReleaseLaneError("release lane capacity fields are invalid") from exc
            values = (
                raw["project_id"],
                raw["placement"],
                raw["client_mtls_identity"],
                raw["host_agent_mtls_identity"],
                raw["artifact_repository"],
            )
            if (
                not all(isinstance(value, str) and value for value in values)
                or minimum_free_gib < 1
                or not 30 <= heartbeat_ttl_seconds <= 900
                or not _ARTIFACT_REPOSITORY.fullmatch(str(raw["artifact_repository"]))
            ):
                raise ReleaseLaneError("release lane values are invalid")
            if schema_version == "qdev-release-lanes-v1" or is_legacy_entry:
                canonical_repository: str | None = None
                artifact_ref_prefix = f"registry.ci.qdev.run/{raw['artifact_repository']}"
                native_host_adapter = "legacy-compose-v1"
                runtime_endpoints: tuple[str, ...] = ()
                rollback_reference = "legacy-controller-state"
                required_readiness = ("qazgeo",)
            else:
                raw_endpoints = raw["runtime_endpoints"]
                raw_readiness = raw["required_readiness"]
                if (
                    not isinstance(raw["canonical_repository"], str)
                    or not _CANONICAL_REPOSITORY.fullmatch(raw["canonical_repository"])
                    or not isinstance(raw["artifact_ref_prefix"], str)
                    or not _ARTIFACT_PREFIX.fullmatch(raw["artifact_ref_prefix"])
                    or not isinstance(raw["native_host_adapter"], str)
                    or not _NATIVE_ADAPTER.fullmatch(raw["native_host_adapter"])
                    or not isinstance(raw_endpoints, list)
                    or not raw_endpoints
                    or not all(
                        isinstance(endpoint, str)
                        and endpoint.startswith("https://")
                        and "#" not in endpoint
                        for endpoint in raw_endpoints
                    )
                    or not isinstance(raw["rollback_reference"], str)
                    or not raw["rollback_reference"].strip()
                    or not isinstance(raw_readiness, list)
                    or not raw_readiness
                    or len(raw_readiness) != len(set(raw_readiness))
                    or not all(
                        isinstance(item, str) and _SEGMENT.fullmatch(item) for item in raw_readiness
                    )
                ):
                    raise ReleaseLaneError("release lane v2 values are invalid")
                canonical_repository = raw["canonical_repository"]
                artifact_ref_prefix = raw["artifact_ref_prefix"]
                native_host_adapter = raw["native_host_adapter"]
                runtime_endpoints = tuple(raw_endpoints)
                rollback_reference = raw["rollback_reference"].strip()
                required_readiness = tuple(raw_readiness)
                if name == "qdev-release-total" and (
                    canonical_repository != "belilovsky/total-kz"
                    or any("total.kz" in endpoint for endpoint in runtime_endpoints)
                ):
                    raise ReleaseLaneError("Total lane must bind only total.qdev.run")
            lanes[name] = ReleaseLane(
                name=name,
                project_id=str(raw["project_id"]),
                placement=str(raw["placement"]),
                client_mtls_identity=str(raw["client_mtls_identity"]),
                host_agent_mtls_identity=str(raw["host_agent_mtls_identity"]),
                minimum_free_gib=minimum_free_gib,
                heartbeat_ttl_seconds=heartbeat_ttl_seconds,
                artifact_repository=str(raw["artifact_repository"]),
                canonical_repository=canonical_repository,
                artifact_ref_prefix=artifact_ref_prefix,
                native_host_adapter=native_host_adapter,
                runtime_endpoints=runtime_endpoints,
                rollback_reference=rollback_reference,
                required_readiness=required_readiness,
            )
        self._lanes = lanes

    def lane(self, name: str) -> ReleaseLane:
        lane = self._lanes.get(name)
        if lane is None:
            raise ReleaseLaneError("release lane is not allowlisted")
        return lane

    def lane_for_host(self, placement: str, release_lane: str | None = None) -> ReleaseLane:
        if release_lane is not None:
            lane = self.lane(release_lane)
            if lane.placement != placement:
                raise ReleaseLaneError("release lane does not match host placement")
            return lane
        matches = [lane for lane in self._lanes.values() if lane.placement == placement]
        if len(matches) != 1:
            raise ReleaseLaneError("release lane must be explicit for shared placement")
        return matches[0]

    def lane_for_placement(self, placement: str) -> ReleaseLane:
        """Compatibility lookup for deployments with a unique host placement."""
        return self.lane_for_host(placement)


def _is_sha(value: object) -> bool:
    return isinstance(value, str) and _SHA.fullmatch(value) is not None


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _DIGEST.fullmatch(value) is not None


def _is_lane_artifact_ref(value: object, digest: str, lane: ReleaseLane) -> bool:
    return value == f"{lane.artifact_ref_prefix}@{digest}"


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _fsync_directory(path: Path) -> None:
    """Persist a rename or newly-created append target in its parent directory."""
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _dispatch_key(value: str | bytes | None) -> bytes:
    if isinstance(value, str):
        raw = value.encode("utf-8")
    elif isinstance(value, bytes):
        raw = value
    else:
        raise ReleaseLaneError("managed host dispatch key is unavailable")
    if not 32 <= len(raw) <= 4096:
        raise ReleaseLaneError("managed host dispatch key length is invalid")
    return raw


def validate_candidate(request: ReleaseAdmissionRequest, lane: ReleaseLane) -> None:
    if request.schema_name != REQUEST_SCHEMA:
        raise ReleaseLaneError("release request schema is invalid")
    if request.release_lane != lane.name:
        raise ReleaseLaneError("release lane does not match request")
    if request.project_id != lane.project_id or request.placement != lane.placement:
        raise ReleaseLaneError("release identity does not match allowlisted lane")
    if not _is_sha(request.source_sha) or not _is_digest(request.artifact_digest):
        raise ReleaseLaneError("release immutable tuple is invalid")
    if not _is_lane_artifact_ref(request.artifact_ref, request.artifact_digest, lane):
        raise ReleaseLaneError(
            "release artifact reference is not immutable or does not match digest"
        )
    receipt = request.candidate_receipt
    base_fields = {
        "schema",
        "status",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
    }
    optional_fields = {
        "artifact_type",
        "artifact_uri",
        "archive_sha256",
        "payload_sha256",
        "ci_receipt_uri",
        "source_receipt_uri",
        "repository",
        "workflow",
        "job",
        "run_id",
        "job_id",
        "attempt",
        "runner_profile",
        "release_version",
        "migration_receipt_digest",
        "contract_digest",
    }
    if (
        not isinstance(receipt, dict)
        or not base_fields.issubset(receipt)
        or set(receipt) - (base_fields | optional_fields)
        or receipt.get("schema") != "qdev-release-candidate-receipt-v1"
        or receipt.get("status") != "passed"
        or receipt.get("source_sha") != request.source_sha
        or receipt.get("artifact_digest") != request.artifact_digest
        or receipt.get("artifact_ref") != request.artifact_ref
    ):
        raise ReleaseLaneError("completed candidate receipt does not bind immutable release tuple")
    artifact_type = receipt.get("artifact_type", "oci")
    if artifact_type not in {"oci", "http-archive"}:
        raise ReleaseLaneError("candidate artifact type is invalid")
    artifact_uri = receipt.get("artifact_uri")
    if artifact_type == "http-archive":
        if (
            not isinstance(artifact_uri, str)
            or not artifact_uri.startswith("https://")
            or "#" in artifact_uri
        ):
            raise ReleaseLaneError("HTTP archive artifact URI must be HTTPS")
        for field in ("archive_sha256", "payload_sha256"):
            if not isinstance(receipt.get(field), str) or not _HEX64.fullmatch(receipt[field]):
                raise ReleaseLaneError("HTTP archive checksums are incomplete")
    else:
        if any(field in receipt for field in ("archive_sha256", "payload_sha256")):
            raise ReleaseLaneError("OCI candidate must not carry archive checksums")
        if artifact_uri is not None and (
            not isinstance(artifact_uri, str) or not artifact_uri.startswith("https://")
        ):
            raise ReleaseLaneError("OCI artifact URI must be HTTPS when supplied")
    if lane.canonical_repository is not None:
        scope_fields = {
            "repository",
            "workflow",
            "job",
            "run_id",
            "job_id",
            "attempt",
            "runner_profile",
        }
        if not scope_fields.issubset(receipt):
            raise ReleaseLaneError("managed candidate receipt is missing CI claim scope")
        if receipt.get("repository") != lane.canonical_repository:
            raise ReleaseLaneError("candidate repository does not match managed lane")
        for field in ("run_id", "job_id", "attempt"):
            value = receipt.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
                raise ReleaseLaneError("candidate CI numeric identity is invalid")
        for field in ("workflow", "job"):
            value = receipt.get(field)
            if not isinstance(value, str) or not _CI_SCOPE_VALUE.fullmatch(value):
                raise ReleaseLaneError("candidate CI scope value is invalid")
        if receipt.get("runner_profile") not in _RUNNER_PROFILES:
            raise ReleaseLaneError("candidate runner profile is not allowlisted")
    qmt_fields = {"release_version", "migration_receipt_digest", "contract_digest"}
    if lane.project_id == "kaztilshi":
        if not qmt_fields.issubset(receipt):
            raise ReleaseLaneError("QMT candidate receipt is missing release evidence")
        if receipt.get("release_version") != "4.4.2":
            raise ReleaseLaneError("QMT candidate release version is not allowlisted")
        if not _is_digest(receipt.get("migration_receipt_digest")):
            raise ReleaseLaneError("QMT migration receipt digest is invalid")
        if not isinstance(receipt.get("contract_digest"), str) or not _HEX64.fullmatch(
            receipt["contract_digest"]
        ):
            raise ReleaseLaneError("QMT contract digest is invalid")
    elif qmt_fields.intersection(receipt):
        raise ReleaseLaneError("QMT release evidence is not valid for this lane")


def candidate_evidence(job: dict[str, Any], lane: ReleaseLane) -> dict[str, Any]:
    """Return metadata-only candidate evidence covered by the host dispatch claim."""
    receipt = job.get("candidate_receipt")
    if not isinstance(receipt, dict):
        raise ReleaseLaneError("release job has no candidate receipt")
    evidence: dict[str, Any] = {
        "schema": "qdev-release-candidate-evidence-v1",
        "candidate_receipt_sha256": hashlib.sha256(_canonical_bytes(receipt)).hexdigest(),
    }
    if lane.project_id == "kaztilshi":
        evidence = {
            "schema": QMT_CANDIDATE_EVIDENCE_SCHEMA,
            "candidate_receipt_sha256": evidence["candidate_receipt_sha256"],
            "release_version": receipt.get("release_version"),
            "migration_receipt_digest": receipt.get("migration_receipt_digest"),
            "contract_digest": receipt.get("contract_digest"),
        }
    return evidence


def controller_claim_payload(
    request: ReleaseAdmissionRequest,
    lane: ReleaseLane,
    *,
    issued_at: int | None = None,
    expires_at: int | None = None,
    nonce: str | None = None,
) -> dict[str, Any]:
    """Return the canonical fields covered by a controller-signed claim."""
    receipt = request.candidate_receipt
    existing = request.controller_claim
    if isinstance(existing, dict):
        if issued_at is None:
            issued_at = existing.get("issued_at")
        if expires_at is None:
            expires_at = existing.get("expires_at")
        if nonce is None:
            nonce = existing.get("nonce")
    if issued_at is None:
        issued_at = int(time.time())
    if expires_at is None:
        expires_at = issued_at + 120
    if nonce is None:
        nonce = secrets.token_urlsafe(32)
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= issued_at
        or expires_at - issued_at > _CONTROLLER_CLAIM_MAX_TTL_SECONDS
        or not isinstance(nonce, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce)
    ):
        raise ReleaseLaneError("controller claim lifetime or nonce is invalid")
    scope = {
        "repository": receipt.get("repository"),
        "workflow": receipt.get("workflow"),
        "job": receipt.get("job"),
        "exact_sha": request.source_sha,
        "run_id": receipt.get("run_id"),
        "job_id": receipt.get("job_id"),
        "attempt": receipt.get("attempt"),
        "runner_profile": receipt.get("runner_profile"),
    }
    return {
        "schema": CONTROLLER_CLAIM_SCHEMA,
        "release_lane": lane.name,
        "project_id": lane.project_id,
        "placement": lane.placement,
        "source_sha": request.source_sha,
        "artifact_digest": request.artifact_digest,
        "artifact_ref": request.artifact_ref,
        "scope": scope,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
    }


def validate_controller_claim(
    request: ReleaseAdmissionRequest,
    lane: ReleaseLane,
    *,
    signing_key: str | bytes | None,
    now: float | None = None,
) -> None:
    """Validate a bounded claim, if the controller is configured to require one.

    The key is read only from controller process configuration.  It is never
    accepted in the request, so a product cannot self-authorise a release.
    """
    if signing_key is None:
        if lane.canonical_repository is not None:
            raise ReleaseLaneError("controller claim key is unavailable for managed lane")
        return
    claim = request.controller_claim
    signature = request.controller_claim_signature
    if not isinstance(claim, dict):
        raise ReleaseLaneError("controller-signed claim is missing or malformed")
    issued_at = claim.get("issued_at")
    expires_at = claim.get("expires_at")
    nonce = claim.get("nonce")
    expected = controller_claim_payload(
        request,
        lane,
        issued_at=issued_at if isinstance(issued_at, int) else None,
        expires_at=expires_at if isinstance(expires_at, int) else None,
        nonce=nonce if isinstance(nonce, str) else None,
    )
    if not isinstance(claim, dict) or set(claim) != set(expected):
        raise ReleaseLaneError("controller-signed claim is missing or malformed")
    if claim != expected or not isinstance(signature, str):
        raise ReleaseLaneError("controller-signed claim does not bind release tuple")
    scope = claim.get("scope")
    if not isinstance(scope, dict) or set(scope) != {
        "repository",
        "workflow",
        "job",
        "exact_sha",
        "run_id",
        "job_id",
        "attempt",
        "runner_profile",
    }:
        raise ReleaseLaneError("controller-signed claim scope is invalid")
    current = int(time.time() if now is None else now)
    if lane.canonical_repository is not None and (
        scope.get("repository") != lane.canonical_repository
        or scope.get("exact_sha") != request.source_sha
        or any(
            not isinstance(scope.get(field), int)
            or isinstance(scope.get(field), bool)
            or scope[field] <= 0
            for field in ("run_id", "job_id", "attempt")
        )
        or scope.get("runner_profile") not in _RUNNER_PROFILES
        or any(
            not isinstance(scope.get(field), str) or not _CI_SCOPE_VALUE.fullmatch(scope[field])
            for field in ("workflow", "job")
        )
    ):
        raise ReleaseLaneError("controller-signed claim scope is invalid")
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= issued_at
        or expires_at - issued_at > _CONTROLLER_CLAIM_MAX_TTL_SECONDS
        or issued_at > current + _CONTROLLER_CLAIM_CLOCK_SKEW_SECONDS
        or expires_at <= current
        or not isinstance(nonce, str)
        or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce)
    ):
        raise ReleaseLaneError("controller-signed claim is expired or not yet valid")
    canonical = _canonical_bytes(claim)
    calculated = hmac.new(_dispatch_key(signing_key), canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated, signature):
        raise ReleaseLaneError("controller-signed claim signature is invalid")


def host_dispatch_claim_payload(
    job: dict[str, Any],
    lane: ReleaseLane,
    *,
    host_identity: str,
    issued_at: int,
    expires_at: int,
    nonce: str,
) -> dict[str, Any]:
    """Build the exact controller-to-host claim for one managed operation."""
    receipt = job.get("candidate_receipt")
    if not isinstance(receipt, dict):
        raise ReleaseLaneError("release job has no candidate CI identity")
    if host_identity != lane.host_agent_mtls_identity:
        raise ReleaseLaneError("host dispatch identity does not match managed lane")
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= issued_at
        or expires_at - issued_at > _DISPATCH_CLAIM_MAX_TTL_SECONDS
    ):
        raise ReleaseLaneError("host dispatch claim lifetime is invalid")
    if not isinstance(nonce, str) or not re.fullmatch(r"[A-Za-z0-9_-]{32,128}", nonce):
        raise ReleaseLaneError("host dispatch nonce is invalid")
    run_id = receipt.get("run_id")
    job_id = receipt.get("job_id")
    attempt = receipt.get("attempt")
    artifact_digest = job.get("artifact_digest")
    artifact_ref = job.get("artifact_ref")
    claim: dict[str, Any] = {
        "schema": HOST_DISPATCH_CLAIM_SCHEMA,
        "repository": receipt.get("repository"),
        "workflow": receipt.get("workflow"),
        "job": receipt.get("job"),
        "exact_sha": job.get("source_sha"),
        "run_id": run_id,
        "job_id": job_id,
        "attempt": attempt,
        "runner_profile": receipt.get("runner_profile"),
        "host_identity": host_identity,
        "release_id": job.get("release_id"),
        "release_lane": lane.name,
        "project_id": lane.project_id,
        "placement": lane.placement,
        "artifact_digest": artifact_digest,
        "artifact_ref": artifact_ref,
        "lease_id": job.get("lease_id"),
        "fence": job.get("fence"),
        "lease_expires_at": job.get("lease_expires_at"),
        "rollback_anchor": job.get("rollback_anchor"),
        "candidate_evidence": candidate_evidence(job, lane),
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
    }
    if (
        claim["repository"] != lane.canonical_repository
        or not _is_sha(claim["exact_sha"])
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value <= 0
            for value in (run_id, job_id, attempt)
        )
        or claim["runner_profile"] not in _RUNNER_PROFILES
        or any(
            not isinstance(claim.get(field), str) or not _CI_SCOPE_VALUE.fullmatch(claim[field])
            for field in ("workflow", "job")
        )
        or not isinstance(artifact_digest, str)
        or not _is_digest(artifact_digest)
        or not _is_lane_artifact_ref(artifact_ref, artifact_digest, lane)
        or not isinstance(claim["release_id"], str)
        or not isinstance(claim["lease_id"], str)
        or not isinstance(claim["fence"], str)
        or not isinstance(claim["lease_expires_at"], int)
        or isinstance(claim["lease_expires_at"], bool)
        or expires_at > claim["lease_expires_at"]
        or not isinstance(claim["rollback_anchor"], dict)
        or set(claim["rollback_anchor"]) != {"source_sha", "artifact_digest", "artifact_ref"}
        or not _is_sha(claim["rollback_anchor"].get("source_sha"))
        or not _is_digest(claim["rollback_anchor"].get("artifact_digest"))
        or not _is_lane_artifact_ref(
            claim["rollback_anchor"].get("artifact_ref"),
            claim["rollback_anchor"]["artifact_digest"],
            lane,
        )
        or not isinstance(claim["candidate_evidence"], dict)
    ):
        raise ReleaseLaneError("host dispatch claim cannot bind the managed job")
    return claim


def sign_host_dispatch_claim(claim: dict[str, Any], *, signing_key: str | bytes | None) -> str:
    """Sign a dispatch claim with a key supplied only by fixed controller config."""
    return hmac.new(_dispatch_key(signing_key), _canonical_bytes(claim), hashlib.sha256).hexdigest()


def validate_host_heartbeat(request: HostHeartbeatRequest, lane: ReleaseLane) -> None:
    if (
        request.schema_name != HOST_HEARTBEAT_SCHEMA
        or request.release_lane != lane.name
        or request.project_id != lane.project_id
        or request.placement != lane.placement
    ):
        raise ReleaseLaneError("host-agent identity does not match allowlisted lane")
    if request.state != "ready" or request.release_lock != "available":
        raise ReleaseLaneError("host-agent is not ready for a release")
    active = request.active_release
    rollback = request.rollback
    active_valid = (
        isinstance(active, dict)
        and set(active) == {"source_sha", "artifact_digest", "artifact_ref"}
        and _is_sha(active.get("source_sha"))
        and _is_digest(active.get("artifact_digest"))
        and _is_lane_artifact_ref(active.get("artifact_ref"), active["artifact_digest"], lane)
    )
    rollback_valid = (
        isinstance(rollback, dict)
        and set(rollback) == {"verified", "source_sha", "artifact_digest", "artifact_ref"}
        and rollback.get("verified") is True
        and _is_sha(rollback.get("source_sha"))
        and _is_digest(rollback.get("artifact_digest"))
        and _is_lane_artifact_ref(rollback.get("artifact_ref"), rollback["artifact_digest"], lane)
    )
    if not active_valid or not rollback_valid:
        raise ReleaseLaneError("host-agent rollback proof is invalid")
    same_tuple = (
        active.get("source_sha"),
        active.get("artifact_digest"),
        active.get("artifact_ref"),
    ) == (
        rollback.get("source_sha"),
        rollback.get("artifact_digest"),
        rollback.get("artifact_ref"),
    )
    if not request.bootstrap and same_tuple:
        raise ReleaseLaneError("host-agent rollback must be a distinct immutable tuple")
    if request.bootstrap and not same_tuple:
        raise ReleaseLaneError("bootstrap heartbeat must use the current release as its anchor")


def validate_runtime_receipt(
    receipt: dict[str, Any],
    *,
    lane: ReleaseLane,
    source_sha: str,
    artifact_digest: str,
    artifact_ref: str,
    rollback_anchor: dict[str, Any] | None = None,
) -> None:
    expected = {
        "schema",
        "status",
        "project",
        "release_lane",
        "placement",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
        "health",
        "readiness",
        "rollback",
    }
    if not expected.issubset(receipt) or set(receipt) - (
        expected | {"runtime_identity", "dependency_identity", "artifact_provenance"}
    ):
        raise ReleaseLaneError("runtime receipt fields are invalid")
    if (
        receipt.get("schema") != RUNTIME_RECEIPT_SCHEMA
        or receipt.get("status") != "verified"
        or receipt.get("project") != lane.project_id
        or receipt.get("release_lane") != lane.name
        or receipt.get("placement") != lane.placement
        or receipt.get("source_sha") != source_sha
        or receipt.get("artifact_digest") != artifact_digest
        or receipt.get("artifact_ref") != artifact_ref
        or receipt.get("health") != "ok"
    ):
        raise ReleaseLaneError("runtime receipt does not bind verified release tuple")
    evidence_fields = {"runtime_identity", "dependency_identity", "artifact_provenance"}
    if lane.canonical_repository is not None and not evidence_fields.issubset(receipt):
        raise ReleaseLaneError("runtime identity evidence is required for managed release lanes")
    if evidence_fields.intersection(receipt):
        if not evidence_fields.issubset(receipt):
            raise ReleaseLaneError("runtime identity evidence is incomplete")
        runtime_identity = receipt["runtime_identity"]
        if (
            not isinstance(runtime_identity, dict)
            or set(runtime_identity)
            != {"source_sha", "artifact_digest", "artifact_ref", "measured"}
            or runtime_identity.get("source_sha") != source_sha
            or runtime_identity.get("artifact_digest") != artifact_digest
            or runtime_identity.get("artifact_ref") != artifact_ref
            or runtime_identity.get("measured") is not True
        ):
            raise ReleaseLaneError("runtime receipt does not contain measured identity")
        dependency_identity = receipt["dependency_identity"]
        if (
            not isinstance(dependency_identity, dict)
            or not dependency_identity
            or any(
                not isinstance(value, str) or not value.strip()
                for value in dependency_identity.values()
            )
        ):
            raise ReleaseLaneError("runtime dependency identity is invalid")
        _validate_runtime_provenance(receipt, lane, installed_only=True)
    readiness = receipt.get("readiness")
    rollback = receipt.get("rollback")
    rollback_tuple = (
        {key: rollback.get(key) for key in ("source_sha", "artifact_digest", "artifact_ref")}
        if isinstance(rollback, dict)
        else None
    )
    if (
        not isinstance(readiness, dict)
        or any(
            readiness.get(name) not in ({"ok", "degraded"} if name == "qazgeo" else {"ok"})
            for name in lane.required_readiness
        )
        or not isinstance(rollback, dict)
        or rollback.get("verified") is not True
        or not _is_sha(rollback.get("source_sha"))
        or rollback.get("source_sha") == source_sha
        or not _is_digest(rollback.get("artifact_digest"))
        or not _is_lane_artifact_ref(
            rollback.get("artifact_ref"), rollback["artifact_digest"], lane
        )
    ):
        raise ReleaseLaneError("runtime receipt readiness or rollback proof is invalid")
    if rollback_anchor is not None and rollback_tuple != rollback_anchor:
        raise ReleaseLaneError("runtime receipt rollback does not match frozen anchor")


def validate_native_runtime_receipt(
    receipt: dict[str, Any],
    *,
    lane: ReleaseLane,
    source_sha: str,
    artifact_digest: str,
    artifact_ref: str,
) -> None:
    """Validate product-native identity and runtime evidence for release or rollback."""
    base = {
        "schema",
        "project_id",
        "native_host_adapter",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
        "readiness",
    }
    evidence = {"runtime_identity", "dependency_identity", "artifact_provenance"}
    if (
        not isinstance(receipt, dict)
        or not base.issubset(receipt)
        or set(receipt) - base - evidence
        or receipt.get("schema") != "qdev-admin-platform-native-receipt-v1"
        or receipt.get("project_id") != lane.project_id
        or receipt.get("native_host_adapter") != lane.native_host_adapter
        or receipt.get("source_sha") != source_sha
        or receipt.get("artifact_digest") != artifact_digest
        or receipt.get("artifact_ref") != artifact_ref
    ):
        raise ReleaseLaneError("native runtime receipt does not bind release tuple")
    readiness = receipt.get("readiness")
    if not isinstance(readiness, dict) or any(
        readiness.get(name) != "ok" for name in lane.required_readiness
    ):
        raise ReleaseLaneError("native runtime readiness is incomplete")
    if lane.canonical_repository is not None and not evidence.issubset(receipt):
        raise ReleaseLaneError("native runtime evidence is required for managed release lanes")
    if evidence.intersection(receipt):
        if not evidence.issubset(receipt):
            raise ReleaseLaneError("native runtime evidence is incomplete")
        runtime_identity = receipt["runtime_identity"]
        if (
            not isinstance(runtime_identity, dict)
            or set(runtime_identity)
            != {"source_sha", "artifact_digest", "artifact_ref", "measured"}
            or runtime_identity.get("measured") is not True
            or runtime_identity.get("source_sha") != source_sha
            or runtime_identity.get("artifact_digest") != artifact_digest
            or runtime_identity.get("artifact_ref") != artifact_ref
        ):
            raise ReleaseLaneError("native runtime identity is not measured")
        dependencies = receipt["dependency_identity"]
        if (
            not isinstance(dependencies, dict)
            or not dependencies
            or any(
                not isinstance(value, str) or not value.strip() for value in dependencies.values()
            )
        ):
            raise ReleaseLaneError("native dependency identity is incomplete")
        _validate_runtime_provenance(receipt, lane)


def _validate_runtime_provenance(
    receipt: dict[str, Any],
    lane: ReleaseLane,
    *,
    installed_only: bool = False,
) -> None:
    if lane.project_id == "id-qdev-run":
        from qdev_runner.idp_file_runtime import (
            ADAPTER,
            ARTIFACT_PREFIX,
            REPOSITORY,
            IdPObservationError,
            validate_runtime_evidence,
        )

        if (lane.canonical_repository, lane.native_host_adapter, lane.artifact_ref_prefix) != (
            REPOSITORY,
            ADAPTER,
            ARTIFACT_PREFIX,
        ):
            raise ReleaseLaneError("IdP native adapter scope is invalid")
        try:
            validate_runtime_evidence(receipt, installed_only=installed_only)
        except IdPObservationError:
            raise ReleaseLaneError("IdP runtime provenance is invalid") from None
        return
    _validate_artifact_provenance(receipt["artifact_provenance"], lane)


def _validate_artifact_provenance(provenance: object, lane: ReleaseLane) -> None:
    if lane.project_id == "kaztilshi":
        expected = {
            "candidate_receipt_sha256",
            "migration_receipt_digest",
            "contract_digest",
        }
        if not isinstance(provenance, dict) or set(provenance) != expected:
            raise ReleaseLaneError("QMT artifact provenance is incomplete")
        if not _HEX64.fullmatch(str(provenance.get("candidate_receipt_sha256", ""))):
            raise ReleaseLaneError("QMT candidate receipt binding is invalid")
        if not _is_digest(provenance.get("migration_receipt_digest")):
            raise ReleaseLaneError("QMT migration receipt binding is invalid")
        if not _HEX64.fullmatch(str(provenance.get("contract_digest", ""))):
            raise ReleaseLaneError("QMT contract binding is invalid")
        return
    expected = {"qak_wheel_sha256", "avds_artifact_sha256", "avds_source_sha"}
    if not isinstance(provenance, dict) or set(provenance) != expected:
        raise ReleaseLaneError("runtime artifact provenance is invalid")
    if any(
        not isinstance(provenance.get(field), str) or not _HEX64.fullmatch(provenance[field])
        for field in ("qak_wheel_sha256", "avds_artifact_sha256")
    ) or not _is_sha(provenance.get("avds_source_sha")):
        raise ReleaseLaneError("runtime artifact provenance is invalid")


class ReleaseStore:
    """Small controller-owned durable queue for an independent release lane."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.agents_root = root / "agents"
        self.jobs_root = root / "jobs"
        self.locks_root = root / "locks"
        self.operations_root = root / "operations"
        for path in (
            self.root,
            self.agents_root,
            self.jobs_root,
            self.locks_root,
            self.operations_root,
        ):
            path.mkdir(parents=True, exist_ok=True)
            path.chmod(0o700)

    @staticmethod
    def _safe_name(value: str) -> str:
        if not _SEGMENT.fullmatch(value):
            raise ReleaseLaneError("release state path is invalid")
        return value

    @staticmethod
    def _read(path: Path) -> dict[str, Any] | None:
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return None
        return value if isinstance(value, dict) else None

    @staticmethod
    def _write(path: Path, value: dict[str, Any]) -> None:
        temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(value, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            _fsync_directory(path.parent)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _agent_path(self, lane_name: str) -> Path:
        return self.agents_root / f"{self._safe_name(lane_name)}.json"

    def _job_path(self, lane_name: str) -> Path:
        return self.jobs_root / f"{self._safe_name(lane_name)}.json"

    def _previous_path(self, lane_name: str) -> Path:
        return self.jobs_root / f"{self._safe_name(lane_name)}.previous.json"

    def _operation_path(self, lane_name: str) -> Path:
        return self.operations_root / f"{self._safe_name(lane_name)}.jsonl"

    def _legacy_operation_path(self, lane_name: str) -> Path:
        return self.operations_root / f"{self._safe_name(lane_name)}.json"

    def _operation_events_unlocked(self, lane: ReleaseLane) -> list[dict[str, Any]]:
        path = self._operation_path(lane.name)
        legacy = self._legacy_operation_path(lane.name)
        if path.is_symlink():
            raise ReleaseLaneError("release operation journal must not be a symlink")
        if not path.exists() and legacy.exists():
            raise ReleaseLaneError("legacy replaceable release journal requires explicit migration")
        try:
            raw = path.read_bytes()
        except FileNotFoundError:
            return []
        except OSError as exc:
            raise ReleaseLaneError("release operation journal is unavailable") from exc
        if raw and not raw.endswith(b"\n"):
            raise ReleaseLaneError("release operation journal has a partial record")
        events: list[dict[str, Any]] = []
        previous = _JOURNAL_GENESIS
        for expected_seq, line in enumerate(raw.splitlines(), start=1):
            try:
                event = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ReleaseLaneError("release operation journal is not JSONL") from exc
            if (
                not isinstance(event, dict)
                or event.get("schema") != OPERATION_JOURNAL_SCHEMA
                or event.get("journal_seq") != expected_seq
                or event.get("previous_event_sha256") != previous
                or event.get("release_lane") != lane.name
                or event.get("project_id") != lane.project_id
                or event.get("placement") != lane.placement
                or not isinstance(event.get("event_sha256"), str)
                or not _HEX64.fullmatch(event["event_sha256"])
            ):
                raise ReleaseLaneError("release operation journal chain is invalid")
            snapshot = event.get("job_snapshot")
            if (
                not isinstance(snapshot, dict)
                or snapshot.get("journal_seq") != expected_seq
                or any(
                    event.get(field) != snapshot.get(field)
                    for field in (
                        "release_lane",
                        "project_id",
                        "placement",
                        "release_id",
                        "lease_id",
                        "fence",
                        "operation_seq",
                    )
                )
            ):
                raise ReleaseLaneError("release operation journal snapshot is invalid")
            unsigned = dict(event)
            claimed_hash = unsigned.pop("event_sha256")
            calculated_hash = hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
            if not hmac.compare_digest(calculated_hash, claimed_hash):
                raise ReleaseLaneError("release operation journal hash is invalid")
            previous = claimed_hash
            events.append(event)
        return events

    def _append_operation_unlocked(
        self,
        lane: ReleaseLane,
        job: dict[str, Any],
        phase: str,
        *,
        recorded_at: float | None = None,
        **fields: Any,
    ) -> dict[str, Any]:
        events = self._operation_events_unlocked(lane)
        protected = {
            "schema",
            "journal_seq",
            "previous_event_sha256",
            "event_sha256",
            "release_lane",
            "project_id",
            "placement",
            "release_id",
            "lease_id",
            "fence",
            "operation_seq",
            "phase",
            "recorded_at",
            "job_snapshot",
        }
        if protected.intersection(fields):
            raise ReleaseLaneError("release operation journal fields conflict")
        journal_seq = len(events) + 1
        job["journal_seq"] = journal_seq
        snapshot = json.loads(_canonical_bytes(job))
        event: dict[str, Any] = {
            "schema": OPERATION_JOURNAL_SCHEMA,
            "journal_seq": journal_seq,
            "previous_event_sha256": (events[-1]["event_sha256"] if events else _JOURNAL_GENESIS),
            "release_lane": lane.name,
            "project_id": lane.project_id,
            "placement": lane.placement,
            "release_id": job.get("release_id"),
            "lease_id": job.get("lease_id"),
            "fence": job.get("fence"),
            "operation_seq": job.get("operation_seq"),
            "phase": phase,
            "recorded_at": time.time() if recorded_at is None else recorded_at,
            "job_snapshot": snapshot,
            **fields,
        }
        event["event_sha256"] = hashlib.sha256(_canonical_bytes(event)).hexdigest()
        path = self._operation_path(lane.name)
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
            with os.fdopen(descriptor, "ab") as stream:
                stream.write(_canonical_bytes(event) + b"\n")
                stream.flush()
                os.fsync(stream.fileno())
            _fsync_directory(path.parent)
        except OSError as exc:
            raise ReleaseLaneError("release operation journal append failed") from exc
        return event

    def operation_events(self, lane: ReleaseLane) -> list[dict[str, Any]]:
        """Return a verified copy of the append-only operation history."""
        with self._lock(lane.name):
            return self._operation_events_unlocked(lane)

    @contextmanager
    def _lock(self, name: str) -> Iterator[None]:
        path = self.locks_root / f"{self._safe_name(name)}.lock"
        with path.open("a+", encoding="utf-8") as stream:
            os.chmod(path, 0o600)
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

    def _job_unlocked(self, lane: ReleaseLane) -> dict[str, Any] | None:
        """Return the journal-authoritative job and repair a stale snapshot.

        The JSON job file is only a replaceable lookup snapshot.  Every state
        transition is first fsynced to the hash-chained journal with the full
        resulting job, so a crash between the append and snapshot rename can
        be reconciled without repeating a release operation.
        """
        events = self._operation_events_unlocked(lane)
        disk = self._read(self._job_path(lane.name))
        if not events:
            if disk is not None and lane.canonical_repository is not None:
                raise ReleaseLaneError(
                    "managed release snapshot has no durable journal; "
                    "explicit migration is required"
                )
            return disk
        latest = events[-1]["job_snapshot"]
        if not isinstance(latest, dict):  # guarded while reading the journal
            raise ReleaseLaneError("release operation journal snapshot is invalid")
        if disk is None:
            self._write(self._job_path(lane.name), latest)
            return latest
        disk_seq = disk.get("journal_seq")
        latest_seq = latest.get("journal_seq")
        if (
            not isinstance(disk_seq, int)
            or isinstance(disk_seq, bool)
            or not isinstance(latest_seq, int)
            or isinstance(latest_seq, bool)
        ):
            raise ReleaseLaneError("release job snapshot sequence is invalid")
        if disk_seq < latest_seq:
            self._write(self._job_path(lane.name), latest)
            return latest
        if disk_seq > latest_seq:
            raise ReleaseLaneError("release job snapshot is ahead of durable journal")
        if not hmac.compare_digest(_canonical_bytes(disk), _canonical_bytes(latest)):
            raise ReleaseLaneError("release job snapshot diverges from durable journal")
        return disk

    def _active_job_unlocked(self, lane: ReleaseLane) -> dict[str, Any] | None:
        job = self._job_unlocked(lane)
        if job is None or job.get("status") not in {"accepted", "dispatched"}:
            return None
        return job

    @staticmethod
    def _heartbeat_request(record: dict[str, Any]) -> HostHeartbeatRequest:
        payload = {
            key: value
            for key, value in record.items()
            if key not in {"mtls_identity", "received_at"}
        }
        try:
            return HostHeartbeatRequest.model_validate(payload)
        except ValidationError as exc:
            raise ReleaseLaneError("persisted host-agent heartbeat is invalid") from exc

    def _fresh_agent_unlocked(
        self, lane: ReleaseLane, *, now: float | None = None
    ) -> dict[str, Any] | None:
        record = self._read(self._agent_path(lane.name))
        if record is None:
            return None
        if record.get("mtls_identity") != lane.host_agent_mtls_identity:
            raise ReleaseLaneError("persisted host-agent identity is invalid")
        request = self._heartbeat_request(record)
        validate_host_heartbeat(request, lane)
        received_at = record.get("received_at")
        if not isinstance(received_at, (int, float)) or isinstance(received_at, bool):
            raise ReleaseLaneError("persisted host-agent heartbeat timestamp is invalid")
        current = time.time() if now is None else now
        age = current - float(received_at)
        if age < -_CONTROLLER_CLAIM_CLOCK_SKEW_SECONDS:
            raise ReleaseLaneError("persisted host-agent heartbeat is from the future")
        if age > lane.heartbeat_ttl_seconds:
            return None
        return record

    @staticmethod
    def _ensure_live_lease(
        job: dict[str, Any], lane: ReleaseLane, *, now: float | None = None
    ) -> None:
        if lane.canonical_repository is None:
            return
        expires_at = job.get("lease_expires_at")
        if (
            not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or expires_at <= int(time.time() if now is None else now)
        ):
            raise ReleaseLaneError("managed release lease is expired or invalid")

    @staticmethod
    def _managed_claim_metadata(
        request: ReleaseAdmissionRequest,
        lane: ReleaseLane,
        *,
        now: float,
    ) -> tuple[str, str]:
        claim = request.controller_claim
        signature = request.controller_claim_signature
        if not isinstance(claim, dict) or not isinstance(signature, str):
            raise ReleaseLaneError("controller-signed claim is required for managed lane")
        issued_at = claim.get("issued_at")
        expires_at = claim.get("expires_at")
        nonce = claim.get("nonce")
        expected = controller_claim_payload(
            request,
            lane,
            issued_at=issued_at if isinstance(issued_at, int) else None,
            expires_at=expires_at if isinstance(expires_at, int) else None,
            nonce=nonce if isinstance(nonce, str) else None,
        )
        current = int(now)
        if (
            claim != expected
            or not _HEX64.fullmatch(signature)
            or not isinstance(issued_at, int)
            or isinstance(issued_at, bool)
            or not isinstance(expires_at, int)
            or isinstance(expires_at, bool)
            or issued_at > current + _CONTROLLER_CLAIM_CLOCK_SKEW_SECONDS
            or expires_at <= current
            or not isinstance(nonce, str)
        ):
            raise ReleaseLaneError("controller-signed claim is expired or malformed")
        return nonce, hashlib.sha256(_canonical_bytes(claim)).hexdigest()

    def _claim_nonce_used_unlocked(
        self, lane: ReleaseLane, *, nonce: str, release_id: str | None = None
    ) -> bool:
        for event in self._operation_events_unlocked(lane):
            snapshot = event["job_snapshot"]
            if snapshot.get("controller_claim_nonce") == nonce and (
                release_id is None or snapshot.get("release_id") != release_id
            ):
                return True
        return False

    def record_heartbeat(
        self,
        lane: ReleaseLane,
        request: HostHeartbeatRequest,
        *,
        identity: str,
        now: float | None = None,
    ) -> dict[str, Any]:
        if identity != lane.host_agent_mtls_identity:
            raise ReleaseLaneError("host-agent mTLS identity does not match managed lane")
        validate_host_heartbeat(request, lane)
        record = request.model_dump(mode="json", by_alias=True)
        record["mtls_identity"] = identity
        record["received_at"] = time.time() if now is None else now
        with self._lock(lane.name):
            previous = self._read(self._agent_path(lane.name))
            if previous is None:
                if lane.canonical_repository is not None and not request.bootstrap:
                    raise ReleaseLaneError(
                        "first managed host-agent heartbeat must establish a bootstrap anchor"
                    )
            else:
                if previous.get("mtls_identity") != lane.host_agent_mtls_identity:
                    raise ReleaseLaneError("persisted host-agent identity is invalid")
                previous_request = self._heartbeat_request(previous)
                validate_host_heartbeat(previous_request, lane)
                previous_active = {
                    key: previous_request.active_release[key]
                    for key in ("source_sha", "artifact_digest", "artifact_ref")
                }
                current_active = {
                    key: request.active_release[key]
                    for key in ("source_sha", "artifact_digest", "artifact_ref")
                }
                current_rollback = {
                    key: request.rollback[key]
                    for key in ("source_sha", "artifact_digest", "artifact_ref")
                }
                if previous_request.bootstrap:
                    if request.bootstrap and current_active != previous_active:
                        raise ReleaseLaneError("bootstrap anchor cannot change")
                    if not request.bootstrap and current_rollback != previous_active:
                        raise ReleaseLaneError(
                            "first managed heartbeat must retain the bootstrap anchor"
                        )
                elif request.bootstrap:
                    raise ReleaseLaneError("managed host-agent cannot return to bootstrap")
            self._write(self._agent_path(lane.name), record)
        return record

    def fresh_agent(self, lane: ReleaseLane, *, now: float | None = None) -> dict[str, Any] | None:
        with self._lock(lane.name):
            return self._fresh_agent_unlocked(lane, now=now)

    def active_job(self, lane: ReleaseLane) -> dict[str, Any] | None:
        with self._lock(lane.name):
            return self._active_job_unlocked(lane)

    def admit(
        self,
        request: ReleaseAdmissionRequest,
        lane: ReleaseLane,
        *,
        now: int | None = None,
        lease_ttl_seconds: int = _RELEASE_LEASE_DEFAULT_TTL_SECONDS,
    ) -> tuple[dict[str, Any], bool]:
        validate_candidate(request, lane)
        current_time = int(time.time() if now is None else now)
        if lane.canonical_repository is not None and (
            not isinstance(lease_ttl_seconds, int)
            or isinstance(lease_ttl_seconds, bool)
            or not 60 <= lease_ttl_seconds <= _RELEASE_LEASE_MAX_TTL_SECONDS
        ):
            raise ReleaseLaneError("managed release lease TTL is invalid")
        with self._lock(lane.name):
            existing = self._active_job_unlocked(lane)
            tuple_fields = ("source_sha", "artifact_digest", "artifact_ref")
            claim_nonce: str | None = None
            claim_sha256: str | None = None
            rollback_anchor: dict[str, Any] | None = None
            if lane.canonical_repository is not None:
                claim_nonce, claim_sha256 = self._managed_claim_metadata(
                    request, lane, now=float(current_time)
                )
                agent = self._fresh_agent_unlocked(lane, now=float(current_time))
                if agent is None:
                    raise ReleaseLaneError("managed release host-agent heartbeat is stale")
                if float(agent.get("capacity_free_gib", -1)) < lane.minimum_free_gib:
                    raise ReleaseLaneError("managed release host-agent capacity is insufficient")
                rollback_anchor = {key: agent["active_release"][key] for key in tuple_fields}
                if rollback_anchor == {key: getattr(request, key) for key in tuple_fields}:
                    raise ReleaseLaneError("managed candidate must differ from rollback anchor")
            if existing is not None:
                if (
                    all(existing.get(name) == getattr(request, name) for name in tuple_fields)
                    and existing.get("candidate_receipt") == request.candidate_receipt
                    and (
                        lane.canonical_repository is None
                        or (
                            existing.get("controller_claim_nonce") == claim_nonce
                            and existing.get("controller_claim_sha256") == claim_sha256
                        )
                    )
                ):
                    return existing, True
                raise ReleaseLaneError("release lane already has an active immutable tuple")
            if claim_nonce is not None and self._claim_nonce_used_unlocked(lane, nonce=claim_nonce):
                raise ReleaseLaneError("controller-signed claim nonce was already consumed")
            current = self._job_unlocked(lane)
            if current is not None and current.get("status") == "verified":
                self._write(self._previous_path(lane.name), current)
            job = {
                "release_id": secrets.token_urlsafe(18),
                "lease_id": secrets.token_urlsafe(18),
                "fence": secrets.token_hex(12),
                "operation_seq": int((current or {}).get("operation_seq", 0)) + 1
                if isinstance(current, dict)
                else 1,
                "release_lane": lane.name,
                "project_id": lane.project_id,
                "placement": lane.placement,
                "source_sha": request.source_sha,
                "artifact_digest": request.artifact_digest,
                "artifact_ref": request.artifact_ref,
                "candidate_receipt": request.candidate_receipt,
                "status": "accepted",
                "operation_phase": "accepted",
                "accepted_at": float(current_time),
            }
            if lane.canonical_repository is not None:
                job.update(
                    {
                        "lease_issued_at": current_time,
                        "lease_expires_at": current_time + lease_ttl_seconds,
                        "rollback_anchor": rollback_anchor,
                        "controller_claim_nonce": claim_nonce,
                        "controller_claim_sha256": claim_sha256,
                    }
                )
            self._append_operation_unlocked(
                lane,
                job,
                "accepted",
                recorded_at=float(current_time),
                candidate_receipt_sha256=hashlib.sha256(
                    _canonical_bytes(request.candidate_receipt)
                ).hexdigest(),
            )
            self._write(self._job_path(lane.name), job)
            return job, False

    def next_job(
        self,
        lane: ReleaseLane,
        *,
        host_identity: str | None = None,
        dispatch_signing_key: str | bytes | None = None,
        now: float | None = None,
        claim_ttl_seconds: int = 120,
    ) -> dict[str, Any] | None:
        with self._lock(lane.name):
            job = self._active_job_unlocked(lane)
            if job is None:
                return None
            if lane.canonical_repository is None:
                if job["status"] == "accepted":
                    job["status"] = "dispatched"
                    job["dispatched_at"] = time.time() if now is None else now
                    self._append_operation_unlocked(
                        lane, job, "dispatched", recorded_at=job["dispatched_at"]
                    )
                    self._write(self._job_path(lane.name), job)
                return job
            if host_identity != lane.host_agent_mtls_identity:
                raise ReleaseLaneError("managed release dispatch host identity is invalid")
            self._ensure_live_lease(job, lane, now=now)
            key = _dispatch_key(dispatch_signing_key)
            if (
                not isinstance(claim_ttl_seconds, int)
                or isinstance(claim_ttl_seconds, bool)
                or not 30 <= claim_ttl_seconds <= _DISPATCH_CLAIM_MAX_TTL_SECONDS
            ):
                raise ReleaseLaneError("managed host dispatch claim TTL is invalid")
            issued_at = int(time.time() if now is None else now)
            current_claim = job.get("dispatch_claim")
            current_signature = job.get("dispatch_claim_signature")
            if current_claim is not None or current_signature is not None:
                if not isinstance(current_claim, dict) or not isinstance(current_signature, str):
                    raise ReleaseLaneError("persisted host dispatch claim is invalid")
                current_issued_at = current_claim.get("issued_at")
                current_expires_at = current_claim.get("expires_at")
                current_nonce = current_claim.get("nonce")
                if (
                    not isinstance(current_issued_at, int)
                    or isinstance(current_issued_at, bool)
                    or not isinstance(current_expires_at, int)
                    or isinstance(current_expires_at, bool)
                    or not isinstance(current_nonce, str)
                ):
                    raise ReleaseLaneError("persisted host dispatch claim is invalid")
                expected = host_dispatch_claim_payload(
                    job,
                    lane,
                    host_identity=host_identity,
                    issued_at=current_issued_at,
                    expires_at=current_expires_at,
                    nonce=current_nonce,
                )
                expected_signature = hmac.new(
                    key, _canonical_bytes(expected), hashlib.sha256
                ).hexdigest()
                if current_claim != expected or not hmac.compare_digest(
                    expected_signature, current_signature
                ):
                    raise ReleaseLaneError("persisted host dispatch claim is invalid")
                if current_expires_at > issued_at:
                    return job
            elif job["status"] == "dispatched":
                raise ReleaseLaneError("dispatched managed job has no signed host claim")
            dispatch_expires_at = min(issued_at + claim_ttl_seconds, int(job["lease_expires_at"]))
            if dispatch_expires_at <= issued_at:
                raise ReleaseLaneError("managed release lease cannot cover a dispatch claim")
            claim = host_dispatch_claim_payload(
                job,
                lane,
                host_identity=host_identity,
                issued_at=issued_at,
                expires_at=dispatch_expires_at,
                nonce=secrets.token_urlsafe(32),
            )
            signature = hmac.new(key, _canonical_bytes(claim), hashlib.sha256).hexdigest()
            phase = "dispatched" if job["status"] == "accepted" else "dispatch_reissued"
            if job["status"] == "accepted":
                job["status"] = "dispatched"
                job["dispatched_at"] = issued_at
            job["operation_phase"] = phase
            job["dispatch_claim"] = claim
            job["dispatch_claim_signature"] = signature
            self._append_operation_unlocked(
                lane,
                job,
                phase,
                recorded_at=float(issued_at),
                host_identity=host_identity,
                dispatch_nonce=claim["nonce"],
                dispatch_expires_at=claim["expires_at"],
                dispatch_claim_sha256=hashlib.sha256(_canonical_bytes(claim)).hexdigest(),
            )
            self._write(self._job_path(lane.name), job)
            return job

    def authorize_idp_file_apply(
        self,
        lane: ReleaseLane,
        release_id: str,
        raw_native: bytes,
        *,
        lease_id: str | None,
        fence: str | None,
        signing_key: str | bytes,
        github: GitHubAppClient,
        artifact_root: Path,
        clock: Callable[[], float] = time.time,
    ) -> dict[str, Any]:
        """Authorize only a current dispatch; never admit/reissue/consume it.

        The private handler authenticates the fixed release-host identity before
        entering here. No caller can choose a collector, key or candidate. Do
        not hold the lane lock across provider I/O: revocation must remain live.
        """
        from datetime import datetime

        from .file_apply_authorization import authorization_payload, canonical_bytes
        from .idp_file_evidence import observe_idp_ci
        from .idp_file_issuer import (
            check_storage,
            parse_native,
            previous_observation,
            verify_native_dispatch,
        )

        native = parse_native(raw_native, lane)

        def current() -> dict[str, Any]:
            check_storage(self.root, lane)
            job = self._job_unlocked(lane)
            if (
                job is None
                or job.get("release_id") != release_id
                or job.get("status") != "dispatched"
                or not lease_id
                or not fence
                or job.get("lease_id") != lease_id
                or job.get("fence") != fence
            ):
                raise ReleaseLaneError("IdP release dispatch or fence is not current")
            self._ensure_live_lease(job, lane, now=clock())
            if job.get("idp_file_transaction") not in (None, native.get("transaction")):
                raise ReleaseLaneError("IdP dispatch is bound to another native transaction")
            return job

        check_storage(self.root, lane)
        with self._lock(lane.name):
            job = current()
            prior = previous_observation(
                self._operation_events_unlocked(lane),
                lane,
                job["rollback_anchor"],
            )
            binding_bytes = verify_native_dispatch(
                native,
                job,
                lane,
                signing_key=signing_key,
                now=clock(),
                previous=prior,
            )
            frozen_job = canonical_bytes(job)

        ci = observe_idp_ci(
            binding_bytes,
            github=github,
            artifact_root=artifact_root,
            clock=clock,
        )

        with self._lock(lane.name):
            job = current()
            if canonical_bytes(job) != frozen_job:
                raise ReleaseLaneError("IdP dispatch changed during provider observation")
            verified_at = clock()
            if not (
                datetime.fromisoformat(ci["observed_at"]).timestamp()
                <= verified_at
                < datetime.fromisoformat(ci["expires_at"]).timestamp()
            ):
                raise ReleaseLaneError("IdP provider observation expired before authorization")
            verify_native_dispatch(
                native,
                job,
                lane,
                signing_key=signing_key,
                now=verified_at,
                previous=prior,
            )
            envelope = authorization_payload(binding_bytes, job["dispatch_claim"])
            signature = sign_host_dispatch_claim(envelope, signing_key=signing_key)
            observation = {
                "schema": "qdev-controller-idp-file-authorization-observation-v1",
                "observed_at": verified_at,
                "expires_at": job["dispatch_claim"]["expires_at"],
                "release_lane": lane.name,
                "host_identity": lane.host_agent_mtls_identity,
                "native_origin": "configured_release_host_mtls",
                "native_observation": native,
                "native_observation_sha256": hashlib.sha256(raw_native).hexdigest(),
                "prior_observation_sha256": (
                    None if prior is None else hashlib.sha256(canonical_bytes(prior)).hexdigest()
                ),
                "ci": ci,
                "authorization": envelope,
                "authorization_signature": signature,
                "acceptance": "not_run",
            }
            # The existing journal is the durable boundary, including a lost
            # HTTP response or snapshot write. Retry records a separate fresh
            # observation; it cannot overwrite history or extend dispatch TTL.
            job["idp_file_transaction"] = native["transaction"]
            event = self._append_operation_unlocked(
                lane,
                job,
                "idp_file_authorized",
                recorded_at=verified_at,
                idp_file_authorization=observation,
            )
            self._write(self._job_path(lane.name), job)
            return {
                "schema": "qdev-controller-idp-file-authorization-receipt-v1",
                "authorization": envelope,
                "authorization_signature": signature,
                "dispatch_claim": job["dispatch_claim"],
                "dispatch_claim_signature": job["dispatch_claim_signature"],
                "candidate_receipt": job["candidate_receipt"],
                "journal_seq": event["journal_seq"],
                "journal_event_sha256": event["event_sha256"],
                "acceptance": "not_run",
            }

    def complete(
        self,
        lane: ReleaseLane,
        release_id: str,
        receipt: dict[str, Any],
        *,
        lease_id: str | None = None,
        fence: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        with self._lock(lane.name):
            job = self._job_unlocked(lane)
            if job is None or job.get("release_id") != release_id:
                raise ReleaseLaneError("release job is not active")
            if lane.canonical_repository is not None and not lease_id:
                raise ReleaseLaneError("managed release lease is required")
            if lane.canonical_repository is not None and not fence:
                raise ReleaseLaneError("managed release fence is required")
            if lease_id is not None and lease_id != job.get("lease_id"):
                raise ReleaseLaneError("release lease does not match job")
            if fence is not None and fence != job.get("fence"):
                raise ReleaseLaneError("release fence does not match job")
            if job.get("status") == "verified":
                if job.get("runtime_receipt") == receipt:
                    return job
                raise ReleaseLaneError("release job was already completed with another receipt")
            if job.get("status") not in {"accepted", "dispatched"}:
                raise ReleaseLaneError("release job is not active")
            self._ensure_live_lease(job, lane, now=now)
            validate_runtime_receipt(
                receipt,
                lane=lane,
                source_sha=str(job["source_sha"]),
                artifact_digest=str(job["artifact_digest"]),
                artifact_ref=str(job["artifact_ref"]),
                rollback_anchor=job.get("rollback_anchor"),
            )
            job["status"] = "verified"
            job["verified_at"] = time.time() if now is None else now
            job["runtime_receipt"] = receipt
            job["operation_phase"] = "verified"
            self._append_operation_unlocked(
                lane,
                job,
                "verified",
                runtime_receipt_sha256=hashlib.sha256(_canonical_bytes(receipt)).hexdigest(),
            )
            self._write(self._job_path(lane.name), job)
            return job

    def rollback(
        self,
        lane: ReleaseLane,
        release_id: str,
        receipt: dict[str, Any],
        *,
        lease_id: str | None = None,
        fence: str | None = None,
        now: float | None = None,
    ) -> dict[str, Any]:
        """Record an idempotent native rollback acknowledgement."""
        with self._lock(lane.name):
            job = self._job_unlocked(lane)
            if job is None or job.get("release_id") != release_id:
                raise ReleaseLaneError("release job is not found")
            if lane.canonical_repository is not None and not lease_id:
                raise ReleaseLaneError("managed rollback lease is required")
            if lane.canonical_repository is not None and not fence:
                raise ReleaseLaneError("managed rollback fence is required")
            if lease_id is not None and lease_id != job.get("lease_id"):
                raise ReleaseLaneError("release lease does not match job")
            if fence is not None and fence != job.get("fence"):
                raise ReleaseLaneError("release fence does not match job")
            if job.get("status") == "rolled_back":
                if job.get("rollback_receipt") == receipt:
                    return job
                raise ReleaseLaneError("release rollback already has another receipt")
            if job.get("status") not in {"accepted", "dispatched"}:
                raise ReleaseLaneError("release job cannot be rolled back")
            self._ensure_live_lease(job, lane, now=now)
            required_receipt = {
                "schema",
                "status",
                "project_id",
                "release_lane",
                "placement",
                "release_id",
                "failed_release",
                "restored_release",
                "native_receipt",
            }
            if (
                not isinstance(receipt, dict)
                or set(receipt) != required_receipt
                or receipt.get("schema") != ROLLBACK_RECEIPT_SCHEMA
                or receipt.get("status") != "rolled_back"
                or receipt.get("release_id") != release_id
                or receipt.get("project_id") != lane.project_id
                or receipt.get("release_lane") != lane.name
                or receipt.get("placement") != lane.placement
                or not isinstance(receipt.get("failed_release"), dict)
                or not isinstance(receipt.get("restored_release"), dict)
                or not isinstance(receipt.get("native_receipt"), dict)
            ):
                raise ReleaseLaneError("rollback receipt is invalid")
            failed = receipt["failed_release"]
            failed_tuple = {
                key: failed.get(key) for key in ("source_sha", "artifact_digest", "artifact_ref")
            }
            if failed_tuple != {
                key: job.get(key) for key in ("source_sha", "artifact_digest", "artifact_ref")
            }:
                raise ReleaseLaneError("rollback receipt does not bind failed release")
            restored = receipt["restored_release"]
            _release_tuple = {
                key: restored.get(key) for key in ("source_sha", "artifact_digest", "artifact_ref")
            }
            if not _is_sha(_release_tuple["source_sha"]) or not _is_digest(
                _release_tuple["artifact_digest"]
            ):
                raise ReleaseLaneError("rollback release identity is invalid")
            if not _is_lane_artifact_ref(
                restored.get("artifact_ref"), restored["artifact_digest"], lane
            ):
                raise ReleaseLaneError("rollback artifact identity is invalid")
            if _release_tuple == failed_tuple:
                raise ReleaseLaneError("rollback must restore a different immutable release")
            if lane.canonical_repository is not None and _release_tuple != job.get(
                "rollback_anchor"
            ):
                raise ReleaseLaneError("rollback does not restore the frozen release anchor")
            native = receipt["native_receipt"]
            validate_native_runtime_receipt(
                native,
                lane=lane,
                source_sha=restored["source_sha"],
                artifact_digest=restored["artifact_digest"],
                artifact_ref=restored["artifact_ref"],
            )
            job["status"] = "rolled_back"
            job["rollback_receipt"] = receipt
            job["rolled_back_at"] = time.time() if now is None else now
            job["operation_phase"] = "rolled_back"
            self._append_operation_unlocked(
                lane,
                job,
                "rolled_back",
                rollback_receipt_sha256=hashlib.sha256(_canonical_bytes(receipt)).hexdigest(),
            )
            self._write(self._job_path(lane.name), job)
            return job

    def job(self, lane: ReleaseLane, release_id: str) -> dict[str, Any] | None:
        with self._lock(lane.name):
            job = self._job_unlocked(lane)
            if job is None or job.get("release_id") != release_id:
                return None
            return job


def admission_receipt(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "accepted",
        "release_id": job["release_id"],
        "release_lane": job["release_lane"],
        "project_id": job["project_id"],
        "placement": job["placement"],
        "source_sha": job["source_sha"],
        "artifact_digest": job["artifact_digest"],
        "artifact_ref": job["artifact_ref"],
    }
