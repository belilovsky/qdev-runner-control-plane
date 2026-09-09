"""Fail-closed policy for the one-time fleet bootstrap control operation.

The policy deliberately authorizes *intent* only.  A controller process must
separately validate the GitHub Actions OIDC token and use the existing QDev CA
to mint the short-lived mTLS claim consumed by the root-owned lifecycle agent.
Keeping those roles separate prevents a repository workflow from choosing a
host, image, compose file, worker, or arbitrary controller revision.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TextIO

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .release_lane import ReleaseLane, ReleaseLanePolicy

POLICY_SCHEMA = "qdev-fleet-bootstrap-policy-v2"
REQUEST_SCHEMA = "qdev-fleet-bootstrap-request-v2"
ALLOWED_ACTIONS = frozenset({"activate-controller", "enrol-host-agent", "restore-existing-worker"})

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$")
_WORKER = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}$")
_TARGET_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,254}$")
_SERVICE_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,254}\.service$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SENSITIVE_RESULT_KEY = re.compile(
    r"(?:token|secret|private|password|credential|cookie|pin|claim)", re.IGNORECASE
)


class FleetBootstrapError(RuntimeError):
    """The bootstrap policy or request cannot be trusted."""


@dataclass(frozen=True)
class BootstrapIdentity:
    repository: str
    branch: str
    workflow: str
    audience: str
    max_claim_ttl_seconds: int


@dataclass(frozen=True)
class ControllerActivation:
    mode: str
    envelope_schema: str
    public_key_binding: str
    max_envelope_ttl_seconds: int


@dataclass(frozen=True)
class WorkerRecoveryTarget:
    """The controller-owned identity of one existing worker service.

    ``host_binding`` is intentionally a registry reference rather than a
    hostname.  The privileged controller resolves it against its registered
    host/service inventory; a workflow can never select an arbitrary host.
    """

    worker_name: str
    target_id: str
    service_unit: str
    host_binding: str
    labels: tuple[str, ...]


class FleetBootstrapRequest(BaseModel):
    """The controller-facing, non-secret bootstrap request envelope."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_name: str = Field(alias="schema")
    action: Literal["activate-controller", "enrol-host-agent", "restore-existing-worker"]
    source_sha: str
    run_id: int = Field(ge=1)
    job_id: int = Field(ge=1)
    attempt: int = Field(ge=1)
    claim_ttl_seconds: int = Field(ge=1)
    controller_revision: str | None = None
    controller_release_digest: str | None = None
    controller_image_digest: str | None = None
    controller_internal_image_digest: str | None = None
    activation_envelope_digest: str | None = None
    release_lane: str | None = None
    worker_name: str | None = None

    @model_validator(mode="after")
    def validate_action_shape(self) -> FleetBootstrapRequest:
        # v2 callers may omit the internal image only for the legacy
        # single-image deployment.  Normalize it before fingerprints, durable
        # storage and adapter dispatch so new receipts always bind both images.
        if (
            self.action in {"activate-controller", "enrol-host-agent"}
            and self.controller_internal_image_digest is None
            and self.controller_image_digest is not None
        ):
            object.__setattr__(
                self, "controller_internal_image_digest", self.controller_image_digest
            )
        if self.action == "activate-controller":
            if (
                self.release_lane is not None
                or self.worker_name is not None
                or self.controller_revision is None
                or self.controller_release_digest is None
                or self.controller_image_digest is None
                or self.controller_internal_image_digest is None
                or self.activation_envelope_digest is None
            ):
                raise ValueError("controller activation cannot name a lane or worker")
        elif self.action == "enrol-host-agent":
            if (
                self.release_lane is None
                or self.worker_name is not None
                or self.controller_revision is None
                or self.controller_release_digest is None
                or self.controller_image_digest is None
                or self.controller_internal_image_digest is None
                or self.activation_envelope_digest is None
            ):
                raise ValueError("host-agent enrolment must name exactly one release lane")
        elif (
            self.release_lane is not None
            or self.worker_name is None
            or self.controller_revision is not None
            or self.controller_release_digest is not None
            or self.controller_image_digest is not None
            or self.controller_internal_image_digest is not None
            or self.activation_envelope_digest is not None
        ):
            raise ValueError(
                "worker restoration must name exactly one worker and no activation tuple"
            )
        return self


class FleetBootstrapPolicy:
    """Strict allowlist for the controller bootstrap transition."""

    def __init__(self, path: Path, release_lanes_path: Path) -> None:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise FleetBootstrapError("fleet bootstrap policy is unavailable") from exc
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "bootstrap",
            "activation",
            "enrolment",
            "workers",
            "worker_targets",
        }:
            raise FleetBootstrapError("fleet bootstrap policy shape is invalid")
        if document["schema_version"] != POLICY_SCHEMA:
            raise FleetBootstrapError("fleet bootstrap policy schema is invalid")
        self.identity = self._identity(document["bootstrap"])
        self.activation = self._activation(document["activation"])
        self._release_lanes = ReleaseLanePolicy(release_lanes_path)
        self._allowed_lanes = self._parse_lanes(document["enrolment"], self._release_lanes)
        self._allowed_workers = self._parse_workers(document["workers"])
        self._worker_targets = self._parse_worker_targets(document["worker_targets"])

    @staticmethod
    def _identity(raw: object) -> BootstrapIdentity:
        if not isinstance(raw, dict) or set(raw) != {
            "repository",
            "branch",
            "workflow",
            "audience",
            "max_claim_ttl_seconds",
        }:
            raise FleetBootstrapError("bootstrap identity is invalid")
        repository = raw["repository"]
        branch = raw["branch"]
        workflow = raw["workflow"]
        audience = raw["audience"]
        ttl = raw["max_claim_ttl_seconds"]
        if (
            not isinstance(repository, str)
            or repository.count("/") != 1
            or not all(part for part in repository.split("/"))
            or not isinstance(branch, str)
            or not _BRANCH.fullmatch(branch)
            or not isinstance(workflow, str)
            or not _WORKFLOW_PATH.fullmatch(workflow)
            or not isinstance(audience, str)
            or not audience
            or isinstance(ttl, bool)
            or not isinstance(ttl, int)
            or not 60 <= ttl <= 900
        ):
            raise FleetBootstrapError("bootstrap identity values are invalid")
        return BootstrapIdentity(repository, branch, workflow, audience, ttl)

    @staticmethod
    def _activation(raw: object) -> ControllerActivation:
        expected = {
            "mode",
            "envelope_schema",
            "public_key_binding",
            "max_envelope_ttl_seconds",
        }
        if not isinstance(raw, dict) or set(raw) != expected:
            raise FleetBootstrapError("bootstrap activation policy is invalid")
        ttl = raw["max_envelope_ttl_seconds"]
        if (
            raw["mode"] != "signed-external-envelope"
            or raw["envelope_schema"] != "qdev-controller-activation-envelope-v1"
            or raw["public_key_binding"] != "controller-registry"
            or isinstance(ttl, bool)
            or not isinstance(ttl, int)
            or not 60 <= ttl <= 1800
        ):
            raise FleetBootstrapError("bootstrap activation values are invalid")
        return ControllerActivation(
            mode=str(raw["mode"]),
            envelope_schema=str(raw["envelope_schema"]),
            public_key_binding=str(raw["public_key_binding"]),
            max_envelope_ttl_seconds=ttl,
        )

    @staticmethod
    def _parse_lanes(raw: object, policy: ReleaseLanePolicy) -> frozenset[str]:
        if not isinstance(raw, dict) or set(raw) != {"lanes"}:
            raise FleetBootstrapError("bootstrap enrolment policy is invalid")
        values = raw["lanes"]
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) for value in values)
            or len(values) != len(set(values))
        ):
            raise FleetBootstrapError("bootstrap enrolment lanes are invalid")
        try:
            for name in values:
                policy.lane(name)
        except Exception as exc:
            raise FleetBootstrapError("bootstrap enrolment lane is not registered") from exc
        return frozenset(values)

    def release_lane(self, name: str) -> ReleaseLane:
        """Return one enrolment-allowlisted immutable release lane.

        Keeping this lookup on the parsed bootstrap policy prevents a
        privileged executor from reopening a different registry file after
        the request has been admitted.
        """

        if name not in self._allowed_lanes:
            raise FleetBootstrapError("bootstrap release lane is not allowlisted")
        try:
            return self._release_lanes.lane(name)
        except Exception as exc:
            raise FleetBootstrapError("bootstrap release lane is unavailable") from exc

    @staticmethod
    def _parse_workers(raw: object) -> frozenset[str]:
        if (
            not isinstance(raw, list)
            or not raw
            or not all(isinstance(value, str) and _WORKER.fullmatch(value) for value in raw)
            or len(raw) != len(set(raw))
        ):
            raise FleetBootstrapError("bootstrap workers are invalid")
        return frozenset(raw)

    @staticmethod
    def _parse_worker_targets(raw: object) -> dict[str, WorkerRecoveryTarget]:
        if not isinstance(raw, list) or not raw:
            raise FleetBootstrapError("bootstrap worker target mapping is invalid")
        targets: dict[str, WorkerRecoveryTarget] = {}
        seen_target_ids: set[str] = set()
        seen_services: set[str] = set()
        for entry in raw:
            if not isinstance(entry, dict) or set(entry) != {
                "worker_name",
                "target_id",
                "service_unit",
                "host_binding",
                "labels",
            }:
                raise FleetBootstrapError("bootstrap worker target mapping is invalid")
            worker_name = entry["worker_name"]
            target_id = entry["target_id"]
            service_unit = entry["service_unit"]
            host_binding = entry["host_binding"]
            labels = entry["labels"]
            if (
                not isinstance(worker_name, str)
                or not _WORKER.fullmatch(worker_name)
                or worker_name in targets
                or not isinstance(target_id, str)
                or not _TARGET_ID.fullmatch(target_id)
                or target_id in seen_target_ids
                or not isinstance(service_unit, str)
                or not _SERVICE_UNIT.fullmatch(service_unit)
                or service_unit in seen_services
                or host_binding != "controller-registry"
                or not isinstance(labels, list)
                or not labels
                or not all(isinstance(label, str) and label for label in labels)
                or len(labels) != len(set(labels))
                or not {"self-hosted", "Linux", "X64"}.issubset(labels)
            ):
                raise FleetBootstrapError("bootstrap worker target mapping is invalid")
            targets[worker_name] = WorkerRecoveryTarget(
                worker_name=worker_name,
                target_id=target_id,
                service_unit=service_unit,
                host_binding=host_binding,
                labels=tuple(labels),
            )
            seen_target_ids.add(target_id)
            seen_services.add(service_unit)
        return targets

    def worker_target(self, worker_name: str) -> WorkerRecoveryTarget | None:
        """Return the exact registered target for an existing worker name."""

        return self._worker_targets.get(worker_name)

    def validate(self, request: FleetBootstrapRequest) -> None:
        if request.schema_name != REQUEST_SCHEMA:
            raise FleetBootstrapError("bootstrap request schema is invalid")
        if not _SHA.fullmatch(request.source_sha):
            raise FleetBootstrapError("bootstrap source SHA is invalid")
        if request.claim_ttl_seconds > self.identity.max_claim_ttl_seconds:
            raise FleetBootstrapError("bootstrap claim TTL exceeds policy")
        if request.action in {"activate-controller", "enrol-host-agent"} and (
            request.controller_revision is None
            or request.controller_revision != request.source_sha
            or _SHA.fullmatch(request.controller_revision) is None
            or request.controller_release_digest is None
            or _DIGEST.fullmatch(request.controller_release_digest) is None
            or request.controller_image_digest is None
            or _DIGEST.fullmatch(request.controller_image_digest) is None
            or request.controller_internal_image_digest is None
            or _DIGEST.fullmatch(request.controller_internal_image_digest) is None
            or request.activation_envelope_digest is None
            or _DIGEST.fullmatch(request.activation_envelope_digest) is None
        ):
            raise FleetBootstrapError(
                "bootstrap activation must bind the workflow source, release, image, "
                "and signed envelope"
            )
        if request.action == "enrol-host-agent" and request.release_lane not in self._allowed_lanes:
            raise FleetBootstrapError("bootstrap release lane is not allowlisted")
        if (
            request.action == "restore-existing-worker"
            and request.worker_name not in self._worker_targets
        ):
            raise FleetBootstrapError("bootstrap worker is not allowlisted")

    def validate_oidc_claims(self, claims: dict[str, Any], request: FleetBootstrapRequest) -> None:
        """Bind the OIDC claim to one immutable workflow attempt.

        The JWT signature and standard temporal checks are performed by the
        GitHub OIDC verifier before this policy method is called.  This method
        supplies the controller-specific repository, workflow, branch, SHA,
        run, job-attempt and audience binding.
        """
        expected_workflow_ref = (
            f"{self.identity.repository}/{self.identity.workflow}@refs/heads/{self.identity.branch}"
        )
        attempt = claims.get("run_attempt")
        if isinstance(attempt, bool) or str(attempt) != str(request.attempt):
            raise FleetBootstrapError("bootstrap OIDC attempt is invalid")
        if (
            claims.get("repository") != self.identity.repository
            or claims.get("ref") != f"refs/heads/{self.identity.branch}"
            or claims.get("sha") != request.source_sha
            or str(claims.get("run_id")) != str(request.run_id)
            or claims.get("workflow_ref") != expected_workflow_ref
        ):
            raise FleetBootstrapError("bootstrap OIDC scope is invalid")
        # GitHub emits ``job_workflow_ref`` for reusable workflows.  A normal
        # workflow does not have that claim, so requiring it unconditionally
        # would make the signed bootstrap workflow impossible to run.  When
        # GitHub does provide it, bind it to the same immutable workflow ref.
        job_workflow_ref = claims.get("job_workflow_ref")
        if job_workflow_ref is not None and job_workflow_ref != expected_workflow_ref:
            raise FleetBootstrapError("bootstrap OIDC scope is invalid")


def validate_github_bootstrap_observation(
    policy: FleetBootstrapPolicy,
    request: FleetBootstrapRequest,
    run: dict[str, Any],
    jobs: list[dict[str, Any]],
) -> None:
    """Bind one bootstrap request to the GitHub App's observed job attempt.

    A valid Actions OIDC token proves which workflow made a request, but it
    does not carry the numeric GitHub job identifier.  The broker therefore
    observes the exact run and its attempt through the GitHub App before it
    lets the root-owned dispatcher see the request.  This deliberately accepts
    only the two controller bootstrap actions: worker restoration remains a
    separate controller-managed lifecycle operation.

    The function is pure so that the HTTP ingress cannot mistake a partial or
    caller-supplied observation for provider evidence.
    """

    if request.action not in {"activate-controller", "enrol-host-agent"}:
        raise FleetBootstrapError("bootstrap ingress action is not allowed")

    expected_ref = f"refs/heads/{policy.identity.branch}"

    def require_exact_int(value: object, expected: int) -> bool:
        return type(value) is int and value == expected

    def require_pending_or_successful(record: dict[str, Any], *, kind: str) -> None:
        status = record.get("status")
        if status not in {"queued", "in_progress", "completed"}:
            raise FleetBootstrapError(f"GitHub bootstrap {kind} status is incomplete")
        if status == "completed" and record.get("conclusion") != "success":
            raise FleetBootstrapError(f"GitHub bootstrap {kind} did not succeed")

    repository = run.get("repository")
    if (
        not isinstance(repository, dict)
        or repository.get("full_name") != policy.identity.repository
    ):
        raise FleetBootstrapError("GitHub bootstrap repository is invalid")
    # GitHub's workflow-dispatch run representation currently leaves ``ref``
    # null even when the dispatch originates from the protected default branch.
    # The independently observed head branch, exact immutable SHA, OIDC claim
    # and workflow path remain mandatory; accepting any other ref is not.
    observed_ref = run.get("ref")
    if observed_ref is None:
        observed_ref = expected_ref
    if (
        not require_exact_int(run.get("id"), request.run_id)
        or not require_exact_int(run.get("run_attempt"), request.attempt)
        or run.get("head_sha") != request.source_sha
        or run.get("event") != "workflow_dispatch"
        or run.get("path") != policy.identity.workflow
        or observed_ref != expected_ref
        or run.get("head_branch") != policy.identity.branch
    ):
        raise FleetBootstrapError("GitHub bootstrap run identity is invalid")
    require_pending_or_successful(run, kind="run")

    if not isinstance(jobs, list) or not jobs or any(not isinstance(job, dict) for job in jobs):
        raise FleetBootstrapError("GitHub bootstrap jobs are incomplete")
    observed_jobs = [job for job in jobs if require_exact_int(job.get("id"), request.job_id)]
    if len(observed_jobs) != 1:
        raise FleetBootstrapError("GitHub bootstrap job identity is ambiguous")
    job = observed_jobs[0]
    if (
        not require_exact_int(job.get("run_id"), request.run_id)
        or not require_exact_int(job.get("run_attempt"), request.attempt)
        or job.get("head_sha") != request.source_sha
        or job.get("head_branch") != policy.identity.branch
    ):
        raise FleetBootstrapError("GitHub bootstrap job identity is invalid")
    require_pending_or_successful(job, kind="job")


def bootstrap_request_fingerprint(request: FleetBootstrapRequest) -> str:
    """Return the stable digest used to make one bootstrap request idempotent."""

    payload = request.model_dump(mode="json", by_alias=True, exclude_none=False)
    canonical = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def bootstrap_ingress_operation_key(
    policy: FleetBootstrapPolicy, request: FleetBootstrapRequest
) -> str:
    """Derive the one durable ingress operation identity from verified facts.

    The GitHub workflow may provide an opaque correlation value, but it must
    never choose the file/key used to deduplicate a privileged operation.  The
    broker derives that key after binding the request to the policy and the
    exact GitHub run/job/attempt/SHA tuple.  A changed activation tuple for
    the same authenticated operation therefore reaches the same durable
    record and is rejected by its request-fingerprint check.
    """

    if request.action not in {"activate-controller", "enrol-host-agent"}:
        raise FleetBootstrapError("bootstrap ingress action is not allowed")
    policy.validate(request)
    payload = {
        "schema": "qdev-fleet-bootstrap-ingress-operation-key-v1",
        "repository": policy.identity.repository,
        "workflow": policy.identity.workflow,
        "branch": policy.identity.branch,
        "source_sha": request.source_sha,
        "run_id": request.run_id,
        "job_id": request.job_id,
        "attempt": request.attempt,
        "action": request.action,
    }
    canonical = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")
    return "github-" + hashlib.sha256(canonical).hexdigest()


def bootstrap_request_fingerprints(request: FleetBootstrapRequest) -> frozenset[str]:
    """Return current and wire-compatible legacy fingerprints for one request.

    The dual-image field was added to the v2 request without changing its
    schema.  Existing durable operation/spool records may therefore bind the
    exact legacy JSON where that optional field was null.  Accept that digest
    only when validation proved this is the legacy single-image shape; all new
    records continue to use the normalized dual-image fingerprint.
    """

    fingerprints = {bootstrap_request_fingerprint(request)}
    if (
        request.action in {"activate-controller", "enrol-host-agent"}
        and request.controller_image_digest is not None
        and request.controller_internal_image_digest == request.controller_image_digest
    ):
        payload = request.model_dump(mode="json", by_alias=True, exclude_none=False)
        payload["controller_internal_image_digest"] = None
        canonical = json.dumps(
            payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        fingerprints.add(hashlib.sha256(canonical).hexdigest())
    return frozenset(fingerprints)


@dataclass(frozen=True)
class BootstrapOperationRecord:
    """Durable, non-secret state for one bootstrap operation."""

    idempotency_key: str
    request_fingerprint: str
    status: Literal["pending", "completed"]
    result: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema": "qdev-fleet-bootstrap-operation-v1",
            "idempotency_key": self.idempotency_key,
            "request_fingerprint": self.request_fingerprint,
            "status": self.status,
        }
        if self.result is not None:
            value["result"] = self.result
        return value


class BootstrapOperationStore:
    """Atomically persist one-shot bootstrap state and reject parameter drift.

    The store is deliberately separate from privileged controller execution.
    It contains only the non-secret request digest and a caller-supplied,
    schema-light operation result.  Callers must pass an explicit durable path
    owned by the controller; the workflow uses an ephemeral path only for
    request validation.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.lock_path = path.with_name(f".{path.name}.lock")

    @staticmethod
    def _validate_key(value: str) -> None:
        if not _IDEMPOTENCY_KEY.fullmatch(value):
            raise FleetBootstrapError("bootstrap idempotency key is invalid")

    @staticmethod
    def _validate_result(result: dict[str, Any]) -> None:
        if not isinstance(result, dict) or any(
            not isinstance(key, str) or _SENSITIVE_RESULT_KEY.search(key) for key in result
        ):
            raise FleetBootstrapError("bootstrap operation result is not safe to persist")
        for value in result.values():
            if value is not None and not isinstance(value, (str, int, float, bool)):
                raise FleetBootstrapError("bootstrap operation result is not safe to persist")

    def _read_unlocked(self) -> BootstrapOperationRecord | None:
        if not self.path.exists():
            return None
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise FleetBootstrapError("bootstrap operation state is unreadable") from exc
        if not isinstance(raw, dict) or raw.get("schema") != "qdev-fleet-bootstrap-operation-v1":
            raise FleetBootstrapError("bootstrap operation state schema is invalid")
        key = raw.get("idempotency_key")
        fingerprint = raw.get("request_fingerprint")
        status = raw.get("status")
        result = raw.get("result")
        if (
            not isinstance(key, str)
            or not _IDEMPOTENCY_KEY.fullmatch(key)
            or not isinstance(fingerprint, str)
            or not re.fullmatch(r"[0-9a-f]{64}", fingerprint)
            or status not in {"pending", "completed"}
            or (result is not None and not isinstance(result, dict))
        ):
            raise FleetBootstrapError("bootstrap operation state is invalid")
        if result is not None:
            self._validate_result(result)
        return BootstrapOperationRecord(key, fingerprint, status, result)

    def _write_unlocked(self, record: BootstrapOperationRecord) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            record.as_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")
        )
        fd, temporary = tempfile.mkstemp(
            prefix=f".{self.path.name}.", dir=self.path.parent, text=True
        )
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
        except OSError as exc:
            with suppress(OSError):
                os.unlink(temporary)
            raise FleetBootstrapError("bootstrap operation state cannot be written") from exc

    def _locked(self) -> TextIO:
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        handle = self.lock_path.open("a+", encoding="utf-8")
        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
        return handle

    def begin(
        self, idempotency_key: str, request: FleetBootstrapRequest
    ) -> BootstrapOperationRecord:
        self._validate_key(idempotency_key)
        fingerprint = bootstrap_request_fingerprint(request)
        with self._locked() as lock:
            try:
                existing = self._read_unlocked()
                if existing is not None:
                    if existing.idempotency_key != idempotency_key:
                        raise FleetBootstrapError("bootstrap operation state key mismatch")
                    if existing.request_fingerprint not in bootstrap_request_fingerprints(request):
                        raise FleetBootstrapError(
                            "bootstrap idempotency key was reused with different parameters"
                        )
                    return existing
                record = BootstrapOperationRecord(idempotency_key, fingerprint, "pending")
                self._write_unlocked(record)
                return record
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def complete(
        self,
        idempotency_key: str,
        request: FleetBootstrapRequest,
        result: dict[str, Any],
    ) -> BootstrapOperationRecord:
        self._validate_key(idempotency_key)
        self._validate_result(result)
        with self._locked() as lock:
            try:
                existing = self._read_unlocked()
                if existing is None:
                    raise FleetBootstrapError("bootstrap operation has not been started")
                if (
                    existing.idempotency_key != idempotency_key
                    or existing.request_fingerprint not in bootstrap_request_fingerprints(request)
                ):
                    raise FleetBootstrapError("bootstrap operation parameters do not match")
                if existing.status == "completed":
                    if existing.result != result:
                        raise FleetBootstrapError("bootstrap operation result cannot be changed")
                    return existing
                record = BootstrapOperationRecord(
                    idempotency_key, existing.request_fingerprint, "completed", dict(result)
                )
                self._write_unlocked(record)
                return record
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
