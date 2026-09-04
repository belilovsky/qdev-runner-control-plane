"""Controller-owned, product-specific immutable release lanes.

This module deliberately sits outside the GitHub Actions worker queue.  A
release lane admits an already-built artifact only after a fresh mTLS host-agent
preflight proves capacity, lock availability and a distinct verified rollback.
The host agent later returns its own runtime receipt after it has checked and
promoted the exact immutable tuple.
"""

from __future__ import annotations

import fcntl
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
_ARTIFACT_PREFIX = re.compile(
    r"^(?:[a-z0-9][a-z0-9.-]{0,62}/)?[a-z0-9][a-z0-9._/-]{1,191}$"
)
_NATIVE_ADAPTER = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}-v[1-9][0-9]*$")

REQUEST_SCHEMA = "qdev-controller-release-request-v1"
RECEIPT_SCHEMA = "qdev-controller-release-receipt-v1"
HOST_HEARTBEAT_SCHEMA = "qdev-release-host-agent-heartbeat-v1"
RUNTIME_RECEIPT_SCHEMA = "qdev-controller-release-runtime-receipt-v1"


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
                        isinstance(item, str) and _SEGMENT.fullmatch(item)
                        for item in raw_readiness
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

    def lane_for_placement(self, placement: str) -> ReleaseLane:
        matches = [lane for lane in self._lanes.values() if lane.placement == placement]
        if len(matches) != 1:
            raise ReleaseLaneError("release placement is not uniquely allowlisted")
        return matches[0]


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
    if (
        not isinstance(receipt, dict)
        or set(receipt)
        != {
            "schema",
            "status",
            "source_sha",
            "artifact_digest",
            "artifact_ref",
        }
        or receipt.get("schema") != "qdev-release-candidate-receipt-v1"
        or receipt.get("status") != "passed"
        or receipt.get("source_sha") != request.source_sha
        or receipt.get("artifact_digest") != request.artifact_digest
        or receipt.get("artifact_ref") != request.artifact_ref
    ):
        raise ReleaseLaneError("completed candidate receipt does not bind immutable release tuple")


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
    if (
        not isinstance(active, dict)
        or set(active) != {"source_sha", "artifact_digest", "artifact_ref"}
        or not isinstance(rollback, dict)
        or set(rollback) != {"verified", "source_sha", "artifact_digest", "artifact_ref"}
        or not _is_sha(active.get("source_sha"))
        or not _is_digest(active.get("artifact_digest"))
        or not _is_lane_artifact_ref(active.get("artifact_ref"), active["artifact_digest"], lane)
        or rollback.get("verified") is not True
        or not _is_sha(rollback.get("source_sha"))
        or not _is_digest(rollback.get("artifact_digest"))
        or not _is_lane_artifact_ref(
            rollback.get("artifact_ref"), rollback["artifact_digest"], lane
        )
        or (
            rollback.get("source_sha"),
            rollback.get("artifact_digest"),
            rollback.get("artifact_ref"),
        )
        == (
            active.get("source_sha"),
            active.get("artifact_digest"),
            active.get("artifact_ref"),
        )
    ):
        raise ReleaseLaneError("host-agent rollback proof is invalid")


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
    if set(receipt) != expected:
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
        for path in (self.root, self.agents_root, self.jobs_root, self.locks_root):
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
        finally:
            if temporary.exists():
                temporary.unlink()

    def _agent_path(self, placement: str) -> Path:
        return self.agents_root / f"{self._safe_name(placement)}.json"

    def _job_path(self, lane_name: str) -> Path:
        return self.jobs_root / f"{self._safe_name(lane_name)}.json"

    def _previous_path(self, lane_name: str) -> Path:
        return self.jobs_root / f"{self._safe_name(lane_name)}.previous.json"

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
        with self._lock(lane.placement):
            self._write(self._agent_path(lane.placement), record)
        return record

    def fresh_agent(self, lane: ReleaseLane) -> dict[str, Any] | None:
        record = self._read(self._agent_path(lane.placement))
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
            if current is not None and current.get("status") == "verified":
                self._write(self._previous_path(lane.name), current)
            job = {
                "release_id": secrets.token_urlsafe(18),
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
        self, lane: ReleaseLane, release_id: str, receipt: dict[str, Any]
    ) -> dict[str, Any]:
        with self._lock(lane.name):
            job = self._active_job_unlocked(lane)
            if job is None or job.get("release_id") != release_id:
                raise ReleaseLaneError("release job is not active")
            validate_runtime_receipt(
                receipt,
                lane=lane,
                source_sha=str(job["source_sha"]),
                artifact_digest=str(job["artifact_digest"]),
                artifact_ref=str(job["artifact_ref"]),
            )
            job["status"] = "verified"
            job["verified_at"] = time.time()
            job["runtime_receipt"] = receipt
            self._write(self._job_path(lane.name), job)
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
