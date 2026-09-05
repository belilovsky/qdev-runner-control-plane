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
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field

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
        "attempt",
        "runner_profile",
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
    elif artifact_uri is not None and (
        not isinstance(artifact_uri, str) or not artifact_uri.startswith("https://")
    ):
        raise ReleaseLaneError("OCI artifact URI must be HTTPS when supplied")
    if lane.canonical_repository is not None:
        scope_fields = {"repository", "workflow", "job", "attempt", "runner_profile"}
        if not scope_fields.issubset(receipt):
            raise ReleaseLaneError("managed candidate receipt is missing CI claim scope")
        if receipt.get("repository") != lane.canonical_repository:
            raise ReleaseLaneError("candidate repository does not match managed lane")
        for field in ("workflow", "job"):
            if not isinstance(receipt.get(field), str) or not _CI_SCOPE_VALUE.fullmatch(
                receipt[field]
            ):
                raise ReleaseLaneError("candidate CI scope value is invalid")
        attempt = receipt.get("attempt")
        if not isinstance(attempt, int) or isinstance(attempt, bool) or attempt <= 0:
            raise ReleaseLaneError("candidate CI attempt is invalid")
        if receipt.get("runner_profile") not in _RUNNER_PROFILES:
            raise ReleaseLaneError("candidate runner profile is not allowlisted")


def controller_claim_payload(request: ReleaseAdmissionRequest, lane: ReleaseLane) -> dict[str, Any]:
    """Return the canonical fields covered by a controller-signed claim."""
    receipt = request.candidate_receipt
    scope = {
        "repository": receipt.get("repository"),
        "exact_sha": request.source_sha,
        "workflow": receipt.get("workflow"),
        "job": receipt.get("job"),
        "attempt": receipt.get("attempt"),
        "runner_profile": receipt.get("runner_profile"),
    }
    return {
        "schema": "qdev-controller-release-claim-v1",
        "release_lane": lane.name,
        "project_id": lane.project_id,
        "placement": lane.placement,
        "source_sha": request.source_sha,
        "artifact_digest": request.artifact_digest,
        "artifact_ref": request.artifact_ref,
        "scope": scope,
    }


def validate_controller_claim(
    request: ReleaseAdmissionRequest,
    lane: ReleaseLane,
    *,
    signing_key: str | None,
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
    expected = controller_claim_payload(request, lane)
    if not isinstance(claim, dict) or set(claim) != set(expected):
        raise ReleaseLaneError("controller-signed claim is missing or malformed")
    if claim != expected or not isinstance(signature, str):
        raise ReleaseLaneError("controller-signed claim does not bind release tuple")
    scope = claim.get("scope")
    if not isinstance(scope, dict) or set(scope) != {
        "repository",
        "exact_sha",
        "workflow",
        "job",
        "attempt",
        "runner_profile",
    }:
        raise ReleaseLaneError("controller-signed claim scope is invalid")
    if lane.canonical_repository is not None and (
        scope.get("repository") != lane.canonical_repository
        or scope.get("exact_sha") != request.source_sha
        or not isinstance(scope.get("workflow"), str)
        or not _CI_SCOPE_VALUE.fullmatch(scope["workflow"])
        or not isinstance(scope.get("job"), str)
        or not _CI_SCOPE_VALUE.fullmatch(scope["job"])
        or not isinstance(scope.get("attempt"), int)
        or isinstance(scope.get("attempt"), bool)
        or scope["attempt"] <= 0
        or scope.get("runner_profile") not in _RUNNER_PROFILES
    ):
        raise ReleaseLaneError("controller-signed claim scope is invalid")
    canonical = json.dumps(claim, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    calculated = hmac.new(signing_key.encode(), canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated, signature):
        raise ReleaseLaneError("controller-signed claim signature is invalid")


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


def validate_product_container_proof(proof: dict[str, Any], lane: ReleaseLane) -> None:
    services_by_project = {
        "qaz-fund": {"api", "worker"},
        "qaz-events": {"app"},
        "kaztilshi": {"kaztilshi"},
    }
    services = proof.get("services")
    if (
        not _is_digest(proof.get("image_id"))
        or not isinstance(services, dict)
        or set(services) != services_by_project.get(lane.project_id)
        or any(value != proof["image_id"] for value in services.values())
    ):
        raise ReleaseLaneError("actual product container image is not proven")


def validate_product_provenance(receipt: dict[str, Any], lane: ReleaseLane) -> None:
    identity = receipt["runtime_identity"]
    validate_product_container_proof(identity, lane)
    if set(identity) != {
        "source_sha",
        "artifact_digest",
        "artifact_ref",
        "measured",
        "image_id",
        "services",
    }:
        raise ReleaseLaneError("product measured identity fields are invalid")
    dependency = receipt["dependency_identity"]
    checksum = dependency.get("compose_config_sha256")
    if (
        set(dependency) != {"compose_config_sha256"}
        or not isinstance(checksum, str)
        or not _HEX64.fullmatch(checksum)
    ):
        raise ReleaseLaneError("product configuration digest is invalid")
    expected = {
        "schema": "qdev-product-oci-provenance-v1",
        **{key: receipt[key] for key in ("source_sha", "artifact_digest", "artifact_ref")},
        "image_id": identity["image_id"],
        "config_sha256": checksum,
    }
    if receipt["artifact_provenance"] != expected:
        raise ReleaseLaneError("product OCI provenance does not bind measured identity")


def validate_runtime_receipt(
    receipt: dict[str, Any],
    *,
    lane: ReleaseLane,
    source_sha: str,
    artifact_digest: str,
    artifact_ref: str,
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
            or runtime_identity.get("source_sha") != source_sha
            or runtime_identity.get("artifact_digest") != artifact_digest
            or runtime_identity.get("artifact_ref") != artifact_ref
            or runtime_identity.get("measured") is not True
        ):
            raise ReleaseLaneError("runtime receipt does not contain measured identity")
        dependency_identity = receipt["dependency_identity"]
        if not isinstance(dependency_identity, dict) or any(
            not isinstance(value, str) or not value.strip()
            for value in dependency_identity.values()
        ):
            raise ReleaseLaneError("runtime dependency identity is invalid")
        provenance = receipt["artifact_provenance"]
        if not isinstance(provenance, dict):
            raise ReleaseLaneError("runtime artifact provenance is invalid")
        if lane.native_host_adapter == "product-compose-v2":
            validate_product_provenance(receipt, lane)
        else:
            for field in ("qak_wheel_sha256", "avds_artifact_sha256"):
                if not isinstance(provenance.get(field), str) or not _HEX64.fullmatch(
                    provenance[field]
                ):
                    raise ReleaseLaneError("runtime artifact provenance checksum is invalid")
            if not isinstance(provenance.get("avds_source_sha"), str) or not _SHA.fullmatch(
                provenance["avds_source_sha"]
            ):
                raise ReleaseLaneError("runtime AVDS source binding is invalid")
    readiness = receipt.get("readiness")
    rollback = receipt.get("rollback")
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


class ReleaseStore:
    """Small controller-owned durable queue for an independent release lane."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.agents_root = root / "agents"
        self.jobs_root = root / "jobs"
        self.locks_root = root / "locks"
        self.operations_root = root / "operations"
        self.enrolments_root = root / "enrolments"
        for path in (
            self.root,
            self.agents_root,
            self.jobs_root,
            self.locks_root,
            self.operations_root,
            self.enrolments_root,
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
        except FileNotFoundError:
            return None
        except (OSError, json.JSONDecodeError) as exc:
            raise ReleaseLaneError("release state cannot be verified") from exc
        if not isinstance(value, dict):
            raise ReleaseLaneError("release state is not an object")
        return value

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
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        finally:
            if temporary.exists():
                temporary.unlink()

    def _agent_path(self, lane_name: str) -> Path:
        return self.agents_root / f"{self._safe_name(lane_name)}.json"

    def _job_path(self, lane_name: str) -> Path:
        return self.jobs_root / f"{self._safe_name(lane_name)}.json"

    def _previous_path(self, lane_name: str) -> Path:
        return self.jobs_root / f"{self._safe_name(lane_name)}.previous.json"

    def _history_path(self, lane_name: str, release_id: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9_-]{3,128}", release_id):
            raise ReleaseLaneError("release history identifier is invalid")
        identity = hashlib.sha256(release_id.encode()).hexdigest()
        return self.jobs_root / (f"{self._safe_name(lane_name)}.{identity}.terminal.json")

    def _operation_path(self, lane_name: str) -> Path:
        return self.operations_root / f"{self._safe_name(lane_name)}.json"

    def _enrolment_path(self, lane_name: str, operation_fence: str) -> Path:
        if not re.fullmatch(r"[A-Za-z0-9._:-]{24,128}", operation_fence):
            raise ReleaseLaneError("host enrolment fence is invalid")
        identity = hashlib.sha256(operation_fence.encode("utf-8")).hexdigest()
        return self.enrolments_root / f"{self._safe_name(lane_name)}.{identity}.json"

    def record_enrolment_ack(
        self, lane: ReleaseLane, operation_fence: str, acknowledgement: dict[str, Any]
    ) -> dict[str, Any]:
        """Persist one immutable mTLS challenge acknowledgement."""

        path = self._enrolment_path(lane.name, operation_fence)
        with self._lock(lane.name):
            current = self._read(path)
            if current is not None:
                if current != acknowledgement:
                    raise ReleaseLaneError("host enrolment acknowledgement cannot be replaced")
                return current
            self._write(path, acknowledgement)
        return acknowledgement

    def enrolment_ack(self, lane: ReleaseLane, operation_fence: str) -> dict[str, Any] | None:
        """Return the immutable acknowledgement for an exact operation fence."""

        with self._lock(lane.name):
            return self._read(self._enrolment_path(lane.name, operation_fence))

    def _sync_operation(self, lane: ReleaseLane, job: dict[str, Any]) -> None:
        # The job is authoritative. Retrying an acknowledgement repairs this
        # projection if the process died between the two durable writes.
        self._write(
            self._operation_path(lane.name),
            {
                "schema": "qdev-controller-release-operation-v1",
                **{
                    key: job.get(key)
                    for key in ("release_id", "lease_id", "fence", "operation_seq")
                },
                "phase": job["status"],
                "updated_at": time.time(),
            },
        )

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

    def _active_job_unlocked(self, lane: ReleaseLane) -> dict[str, Any] | None:
        job = self._read(self._job_path(lane.name))
        if job is None or job.get("status") not in {"accepted", "dispatched"}:
            return None
        return job

    def record_heartbeat(
        self, lane: ReleaseLane, request: HostHeartbeatRequest, *, identity: str
    ) -> dict[str, Any]:
        record = request.model_dump(mode="json", by_alias=True)
        record["mtls_identity"] = identity
        record["received_at"] = time.time()
        with self._lock(lane.name):
            self._write(self._agent_path(lane.name), record)
        return record

    def fresh_agent(self, lane: ReleaseLane) -> dict[str, Any] | None:
        record = self._read(self._agent_path(lane.name))
        if record is None or record.get("mtls_identity") != lane.host_agent_mtls_identity:
            return None
        received_at = record.get("received_at")
        if not isinstance(received_at, (int, float)):
            return None
        if time.time() - float(received_at) > lane.heartbeat_ttl_seconds:
            return None
        return record

    def active_job(self, lane: ReleaseLane) -> dict[str, Any] | None:
        with self._lock(lane.name):
            return self._active_job_unlocked(lane)

    def admit(
        self, request: ReleaseAdmissionRequest, lane: ReleaseLane
    ) -> tuple[dict[str, Any], bool]:
        with self._lock(lane.name):
            existing = self._active_job_unlocked(lane)
            tuple_fields = ("source_sha", "artifact_digest", "artifact_ref")
            if existing is not None:
                if all(existing.get(name) == getattr(request, name) for name in tuple_fields):
                    return existing, True
                raise ReleaseLaneError("release lane already has an active immutable tuple")
            current = self._read(self._job_path(lane.name))
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
                "accepted_at": time.time(),
            }
            if lane.native_host_adapter == "product-compose-v2":
                agent = self.fresh_agent(lane)
                if agent is None:
                    raise ReleaseLaneError("product release requires a fresh rollback anchor")
                validate_host_heartbeat(
                    HostHeartbeatRequest.model_validate(
                        {
                            key: value
                            for key, value in agent.items()
                            if key not in {"mtls_identity", "received_at"}
                        }
                    ),
                    lane,
                )
                if current is not None:
                    terminal = current.get("status")
                    if terminal == "verified":
                        anchor = {key: current[key] for key in tuple_fields}
                        finished_at = current["verified_at"]
                    elif terminal == "rolled_back":
                        restored = current["rollback_receipt"]["restored_release"]
                        anchor = {key: restored[key] for key in tuple_fields}
                        finished_at = current["rolled_back_at"]
                    else:
                        raise ReleaseLaneError("previous product operation is not terminal")
                    if agent["received_at"] <= finished_at or agent["active_release"] != anchor:
                        raise ReleaseLaneError("host has not reconciled the previous release")
                job["previous_release"] = agent["active_release"]
            if current is not None:
                self._write(self._history_path(lane.name, current["release_id"]), current)
                if current.get("status") == "verified":
                    self._write(self._previous_path(lane.name), current)
            self._write(
                self._operation_path(lane.name),
                {
                    "schema": "qdev-controller-release-operation-v1",
                    "release_id": job["release_id"],
                    "lease_id": job["lease_id"],
                    "fence": job["fence"],
                    "operation_seq": job["operation_seq"],
                    "phase": "accepted",
                    "updated_at": time.time(),
                },
            )
            self._write(self._job_path(lane.name), job)
            return job, False

    def next_job(self, lane: ReleaseLane) -> dict[str, Any] | None:
        with self._lock(lane.name):
            job = self._active_job_unlocked(lane)
            if job is None:
                return None
            if job["status"] == "accepted":
                job["status"] = "dispatched"
                job["dispatched_at"] = time.time()
                self._write(self._job_path(lane.name), job)
            return job

    def complete(
        self,
        lane: ReleaseLane,
        release_id: str,
        receipt: dict[str, Any],
        *,
        lease_id: str | None = None,
        fence: str | None = None,
    ) -> dict[str, Any]:
        with self._lock(lane.name):
            job = self._read(self._job_path(lane.name))
            historical = False
            if job is None or job.get("release_id") != release_id:
                job = self._read(self._history_path(lane.name, release_id))
                historical = True
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
                    if not historical:
                        self._sync_operation(lane, job)
                    return job
                raise ReleaseLaneError("release job was already completed with another receipt")
            if job.get("status") not in {"accepted", "dispatched"}:
                raise ReleaseLaneError("release job is not active")
            validate_runtime_receipt(
                receipt,
                lane=lane,
                source_sha=str(job["source_sha"]),
                artifact_digest=str(job["artifact_digest"]),
                artifact_ref=str(job["artifact_ref"]),
            )
            if lane.native_host_adapter == "product-compose-v2" and {
                key: receipt["rollback"].get(key)
                for key in ("source_sha", "artifact_digest", "artifact_ref")
            } != job.get("previous_release"):
                raise ReleaseLaneError("runtime rollback differs from admitted anchor")
            job["status"] = "verified"
            job["verified_at"] = time.time()
            job["runtime_receipt"] = receipt
            job["operation_phase"] = "verified"
            self._write(self._job_path(lane.name), job)
            self._write(
                self._operation_path(lane.name),
                {
                    "schema": "qdev-controller-release-operation-v1",
                    "release_id": job["release_id"],
                    "lease_id": job.get("lease_id"),
                    "fence": job.get("fence"),
                    "operation_seq": job.get("operation_seq"),
                    "phase": "verified",
                    "updated_at": time.time(),
                },
            )
            return job

    def rollback(
        self,
        lane: ReleaseLane,
        release_id: str,
        receipt: dict[str, Any],
        *,
        lease_id: str | None = None,
        fence: str | None = None,
    ) -> dict[str, Any]:
        """Record an idempotent native rollback acknowledgement."""
        with self._lock(lane.name):
            job = self._read(self._job_path(lane.name))
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
                    self._sync_operation(lane, job)
                    return job
                raise ReleaseLaneError("release rollback already has another receipt")
            allowed_states = {"accepted", "dispatched"}
            if lane.native_host_adapter == "product-compose-v2":
                allowed_states.add("verified")
            if job.get("status") not in allowed_states:
                raise ReleaseLaneError("release job cannot be rolled back")
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
            if lane.native_host_adapter == "product-compose-v2" and (
                _release_tuple != job.get("previous_release")
            ):
                raise ReleaseLaneError("rollback must restore the admitted previous release")
            native = receipt["native_receipt"]
            if (
                native.get("schema") != "qdev-admin-platform-native-receipt-v1"
                or native.get("project_id") != lane.project_id
                or native.get("native_host_adapter") != lane.native_host_adapter
                or native.get("source_sha") != restored["source_sha"]
                or native.get("artifact_digest") != restored["artifact_digest"]
                or native.get("artifact_ref") != restored["artifact_ref"]
            ):
                raise ReleaseLaneError("rollback native identity is not proven")
            if lane.native_host_adapter == "product-compose-v2":
                validate_product_container_proof(native, lane)
                if (
                    not isinstance(native.get("config_sha256"), str)
                    or not _HEX64.fullmatch(native["config_sha256"])
                    or not isinstance(native.get("readiness"), dict)
                    or any(native["readiness"].get(key) != "ok" for key in lane.required_readiness)
                ):
                    raise ReleaseLaneError("restored configuration or readiness is not proven")
            job["status"] = "rolled_back"
            job["rollback_receipt"] = receipt
            job["rolled_back_at"] = time.time()
            self._write(self._job_path(lane.name), job)
            self._write(
                self._operation_path(lane.name),
                {
                    "schema": "qdev-controller-release-operation-v1",
                    "release_id": release_id,
                    "lease_id": job.get("lease_id"),
                    "fence": job.get("fence"),
                    "operation_seq": job.get("operation_seq"),
                    "phase": "rolled_back",
                    "updated_at": time.time(),
                },
            )
            return job

    def job(self, lane: ReleaseLane, release_id: str) -> dict[str, Any] | None:
        with self._lock(lane.name):
            job = self._read(self._job_path(lane.name))
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
