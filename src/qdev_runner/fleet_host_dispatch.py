"""Durable root-host dispatch for policy-bound fleet bootstrap mutations.

The broker can publish only a typed bootstrap request into an unprivileged
spool.  A root-owned systemd service claims the request, reloads the
root-owned bootstrap and release-lane policies, derives the registered target,
and invokes one fixed adapter.  No executable, command, URL, hostname, service
unit, or timeout crosses the broker/root boundary.

The ``started`` marker is intentionally durable.  If the dispatcher restarts
after that marker but before a result is committed, it records ``unknown`` and
requires reconciliation instead of replaying a possibly completed mutation.
"""

from __future__ import annotations

import json
import os
import re
import stat
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Literal, cast

from .fleet_bootstrap import (
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    bootstrap_request_fingerprint,
)
from .fleet_bootstrap_executor import (
    BOOTSTRAP_EXECUTION_RECEIPT_SCHEMA,
    _adapter_path,
    _bootstrap_adapter_path,
    _bootstrap_target,
    _invoke_adapter,
    _invoke_bootstrap_adapter,
)

DISPATCH_REQUEST_SCHEMA = "qdev-fleet-host-dispatch-request-v1"
DISPATCH_RESULT_SCHEMA = "qdev-fleet-host-dispatch-result-v1"
STARTED_SCHEMA = "qdev-fleet-host-dispatch-started-v1"

DEFAULT_ACTIVATION_ADAPTER = Path("/usr/local/sbin/qdev-controller-activate")
DEFAULT_ENROLMENT_ADAPTER = Path("/usr/local/sbin/qdev-release-host-agent-enrol")
DEFAULT_RECOVERY_ADAPTER = Path("/usr/local/sbin/qdev-fleet-worker-recovery")
DEFAULT_CONTROLLER_STATUS = Path(
    "/var/lib/qdev-runner/controller-status/controller-release.json"
)

_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_FINGERPRINT = re.compile(r"^[0-9a-f]{64}$")
_ERROR_CODE = re.compile(r"^[a-z][a-z0-9_]{2,127}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_MAX_FILE_BYTES = 64 * 1024
_ACTIONS = frozenset(
    {"activate-controller", "enrol-host-agent", "restore-existing-worker"}
)

DispatchStatus = Literal["queued", "completed", "failed", "unknown", "access_blocked"]
OperationStatus = Literal["pending", "completed", "unknown"]
BootstrapAction = Literal[
    "activate-controller", "enrol-host-agent", "restore-existing-worker"
]


class FleetHostDispatchError(FleetBootstrapError):
    """The host-dispatch spool or one of its immutable records is unsafe."""


def _canonical(value: dict[str, Any]) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n"
    ).encode("utf-8")


def _validate_key(value: str) -> None:
    if not _KEY.fullmatch(value):
        raise FleetHostDispatchError("fleet host dispatch idempotency key is invalid")


def _validate_directory(
    path: Path,
    *,
    expected_uid: int | None = None,
    expected_gid: int | None = None,
    expected_mode: int | None = None,
) -> None:
    try:
        metadata = path.lstat()
    except OSError as exc:
        raise FleetHostDispatchError("fleet host dispatch bridge is unavailable") from exc
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise FleetHostDispatchError("fleet host dispatch directory is unsafe")
    if expected_uid is not None and metadata.st_uid != expected_uid:
        raise FleetHostDispatchError("fleet host dispatch directory owner is unsafe")
    if expected_gid is not None and metadata.st_gid != expected_gid:
        raise FleetHostDispatchError("fleet host dispatch directory group is unsafe")
    if expected_mode is not None and stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise FleetHostDispatchError("fleet host dispatch directory permissions are unsafe")


def _validate_policy_file(path: Path, *, expected_uid: int) -> None:
    """Require a policy file and its containing directory to be root-controlled.

    The dispatcher deliberately validates these paths for every request before
    ``FleetBootstrapPolicy`` reopens them.  A non-writable parent makes that
    second open safe from an unprivileged rename race without accepting policy
    bytes through the broker-controlled spool.
    """

    if not path.is_absolute():
        raise FleetHostDispatchError("fleet host dispatch policy path is unsafe")
    try:
        parent = path.parent.lstat()
    except OSError as exc:
        raise FleetHostDispatchError("fleet host dispatch policy is unavailable") from exc
    if (
        not stat.S_ISDIR(parent.st_mode)
        or stat.S_ISLNK(parent.st_mode)
        or parent.st_uid != expected_uid
        or stat.S_IMODE(parent.st_mode) & 0o022
    ):
        raise FleetHostDispatchError("fleet host dispatch policy directory is unsafe")
    payload = _read_regular(path, expected_uid=expected_uid)
    if not payload:
        raise FleetHostDispatchError("fleet host dispatch policy is empty")


def _read_regular(
    path: Path,
    *,
    expected_uid: int | None = None,
    reject_group_write: bool = True,
) -> bytes:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise FleetHostDispatchError("fleet host dispatch record is unreadable") from exc
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink < 1:
            raise FleetHostDispatchError("fleet host dispatch record is unsafe")
        if expected_uid is not None and metadata.st_uid != expected_uid:
            raise FleetHostDispatchError("fleet host dispatch record owner is unsafe")
        if reject_group_write and stat.S_IMODE(metadata.st_mode) & 0o022:
            raise FleetHostDispatchError("fleet host dispatch record permissions are unsafe")
        if metadata.st_size > _MAX_FILE_BYTES:
            raise FleetHostDispatchError("fleet host dispatch record is too large")
        chunks: list[bytes] = []
        remaining = _MAX_FILE_BYTES + 1
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 8192))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)
        if len(payload) > _MAX_FILE_BYTES:
            raise FleetHostDispatchError("fleet host dispatch record is too large")
        return payload
    finally:
        os.close(fd)


def _decode_object(payload: bytes, *, label: str) -> dict[str, Any]:
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FleetHostDispatchError(f"fleet host dispatch {label} is invalid") from exc
    if not isinstance(value, dict):
        raise FleetHostDispatchError(f"fleet host dispatch {label} is invalid")
    return value


def verified_controller_runtime_anchor(
    path: Path,
    *,
    expected_uid: int,
) -> tuple[str, str]:
    """Read one root-controlled, measured controller runtime identity.

    The caller cannot supply the rollback anchor.  The root dispatcher derives
    it immediately before the mutation marker, while the fixed activation
    adapter independently rereads the same status for compare-and-swap.
    """

    _validate_policy_file(path, expected_uid=expected_uid)
    raw = _decode_object(
        _read_regular(path, expected_uid=expected_uid),
        label="controller runtime status",
    )
    schema = raw.get("schema")
    legacy_keys = {
        "schema",
        "state",
        "revision",
        "release_digest",
        "activated_at",
    }
    measured_keys = legacy_keys | {"runtime_identity", "dependency_identity"}
    expected_keys = (
        legacy_keys
        if schema == "qdev-controller-release-status-v1"
        else measured_keys
    )
    if (
        schema
        not in {"qdev-controller-release-status-v1", "qdev-controller-release-status-v2"}
        or set(raw) != expected_keys
    ):
        raise FleetHostDispatchError(
            "fleet host dispatch controller runtime status shape is invalid"
        )
    revision = raw.get("revision")
    release_digest = raw.get("release_digest")
    if (
        schema == "qdev-controller-release-status-v1"
        and isinstance(release_digest, str)
        and re.fullmatch(r"[0-9a-f]{64}", release_digest)
    ):
        release_digest = f"sha256:{release_digest}"
    activated_at = raw.get("activated_at")
    try:
        activated = (
            datetime.fromisoformat(activated_at.replace("Z", "+00:00"))
            if isinstance(activated_at, str)
            else None
        )
    except ValueError:
        activated = None
    if (
        raw.get("state") != "active"
        or not isinstance(revision, str)
        or not _SHA.fullmatch(revision)
        or not isinstance(release_digest, str)
        or not _DIGEST.fullmatch(release_digest)
        or activated is None
        or activated.tzinfo is None
        or activated.utcoffset() is None
    ):
        raise FleetHostDispatchError(
            "fleet host dispatch controller runtime identity is invalid"
        )
    # A root-owned v1 receipt is a bounded migration anchor.  It carries no
    # measured runtime/dependency claims, so only its exact legacy shape can
    # authorize the one-way activation that publishes a v2 receipt.
    if schema == "qdev-controller-release-status-v1":
        return revision, release_digest
    runtime_identity = raw.get("runtime_identity")
    dependency_identity = raw.get("dependency_identity")
    if (
        not isinstance(runtime_identity, dict)
        or set(runtime_identity)
        != {
            "source_revision",
            "source_digest",
            "public_image_id",
            "internal_image_id",
        }
        or runtime_identity.get("source_revision") != revision
        or not isinstance(dependency_identity, dict)
        or set(dependency_identity)
        != {
            "requirements_digest",
            "public_installed_digest",
            "internal_installed_digest",
        }
    ):
        raise FleetHostDispatchError(
            "fleet host dispatch controller runtime identity is invalid"
        )
    measured_digests = (
        runtime_identity.get("source_digest"),
        runtime_identity.get("public_image_id"),
        runtime_identity.get("internal_image_id"),
        dependency_identity.get("requirements_digest"),
        dependency_identity.get("public_installed_digest"),
        dependency_identity.get("internal_installed_digest"),
    )
    if any(
        not isinstance(value, str) or not _DIGEST.fullmatch(value)
        for value in measured_digests
    ):
        raise FleetHostDispatchError(
            "fleet host dispatch controller runtime measurements are invalid"
        )
    if (
        dependency_identity["public_installed_digest"]
        != dependency_identity["internal_installed_digest"]
    ):
        raise FleetHostDispatchError(
            "fleet host dispatch controller dependency identity is inconsistent"
        )
    return revision, release_digest


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _publish_immutable(
    path: Path,
    payload: bytes,
    *,
    mode: int,
    uid: int | None = None,
    gid: int | None = None,
) -> bool:
    """Publish bytes without replacing an existing record.

    Returns ``True`` for the creator and ``False`` for an identical winner.
    A different existing record is always treated as fingerprint drift.
    """

    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        if uid is not None or gid is not None:
            os.fchown(fd, -1 if uid is None else uid, -1 if gid is None else gid)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
            created = True
            _fsync_directory(path.parent)
        except FileExistsError:
            created = False
            if _read_regular(path) != payload:
                raise FleetHostDispatchError(
                    "fleet host dispatch idempotency key has fingerprint drift"
                ) from None
        return created
    except OSError as exc:
        raise FleetHostDispatchError("fleet host dispatch record cannot be published") from exc
    finally:
        with suppress(OSError):
            os.close(fd)
        with suppress(OSError):
            temporary.unlink()


def _remove_regular(path: Path, *, expected_uid: int | None = None) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        raise FleetHostDispatchError("fleet host dispatch record cannot be removed") from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (expected_uid is not None and metadata.st_uid != expected_uid)
    ):
        raise FleetHostDispatchError("fleet host dispatch record is unsafe")
    try:
        path.unlink()
        _fsync_directory(path.parent)
    except OSError as exc:
        raise FleetHostDispatchError("fleet host dispatch record cannot be removed") from exc


def _validate_safe_result(value: object) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise FleetHostDispatchError("fleet host dispatch result payload is invalid")
    BootstrapOperationStore._validate_result(value)  # noqa: SLF001
    return dict(value)


@dataclass(frozen=True)
class DispatchEnvelope:
    idempotency_key: str
    request_fingerprint: str
    request: FleetBootstrapRequest
    active_jobs: int | None

    @classmethod
    def parse(cls, payload: bytes, *, expected_key: str) -> DispatchEnvelope:
        raw = _decode_object(payload, label="request")
        if set(raw) != {
            "schema",
            "idempotency_key",
            "request_fingerprint",
            "request",
            "active_jobs",
        }:
            raise FleetHostDispatchError("fleet host dispatch request shape is invalid")
        key = raw.get("idempotency_key")
        fingerprint = raw.get("request_fingerprint")
        if raw.get("schema") != DISPATCH_REQUEST_SCHEMA or not isinstance(key, str):
            raise FleetHostDispatchError("fleet host dispatch request identity is invalid")
        _validate_key(key)
        if key != expected_key or not isinstance(fingerprint, str) or not _FINGERPRINT.fullmatch(
            fingerprint
        ):
            raise FleetHostDispatchError("fleet host dispatch request identity is invalid")
        try:
            request = FleetBootstrapRequest.model_validate(raw.get("request"))
        except Exception as exc:
            raise FleetHostDispatchError(
                "fleet host dispatch bootstrap request is invalid"
            ) from exc
        if bootstrap_request_fingerprint(request) != fingerprint:
            raise FleetHostDispatchError("fleet host dispatch request fingerprint is invalid")
        active_jobs = raw.get("active_jobs")
        if request.action == "restore-existing-worker":
            if (
                isinstance(active_jobs, bool)
                or not isinstance(active_jobs, int)
                or active_jobs != 0
            ):
                raise FleetHostDispatchError(
                    "fleet host recovery dispatch requires zero observed active jobs"
                )
        elif active_jobs is not None:
            raise FleetHostDispatchError(
                "fleet host dispatch active-jobs field does not match action"
            )
        return cls(key, fingerprint, request, active_jobs)

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": DISPATCH_REQUEST_SCHEMA,
            "idempotency_key": self.idempotency_key,
            "request_fingerprint": self.request_fingerprint,
            "request": self.request.model_dump(
                mode="json", by_alias=True, exclude_none=False
            ),
            "active_jobs": self.active_jobs,
        }


@dataclass(frozen=True)
class DispatchResult:
    idempotency_key: str
    request_fingerprint: str
    action: BootstrapAction
    status: Literal["completed", "failed", "unknown"]
    error_code: str | None
    result: dict[str, Any] | None

    @classmethod
    def parse(cls, payload: bytes, *, expected_key: str) -> DispatchResult:
        raw = _decode_object(payload, label="result")
        if set(raw) != {
            "schema",
            "idempotency_key",
            "request_fingerprint",
            "action",
            "status",
            "error_code",
            "result",
        }:
            raise FleetHostDispatchError("fleet host dispatch result shape is invalid")
        key = raw.get("idempotency_key")
        fingerprint = raw.get("request_fingerprint")
        action = raw.get("action")
        status_value = raw.get("status")
        error_code = raw.get("error_code")
        result_value = raw.get("result")
        if (
            raw.get("schema") != DISPATCH_RESULT_SCHEMA
            or not isinstance(key, str)
            or key != expected_key
            or not isinstance(fingerprint, str)
            or not _FINGERPRINT.fullmatch(fingerprint)
            or action not in _ACTIONS
            or status_value not in {"completed", "failed", "unknown"}
        ):
            raise FleetHostDispatchError("fleet host dispatch result identity is invalid")
        if status_value == "completed":
            if error_code is not None:
                raise FleetHostDispatchError("completed fleet host result has an error")
            result = _validate_safe_result(result_value)
        else:
            if (
                not isinstance(error_code, str)
                or not _ERROR_CODE.fullmatch(error_code)
                or result_value is not None
            ):
                raise FleetHostDispatchError("fleet host dispatch failure is invalid")
            result = None
        return cls(
            key,
            fingerprint,
            cast(BootstrapAction, action),
            cast(Literal["completed", "failed", "unknown"], status_value),
            error_code,
            result,
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": DISPATCH_RESULT_SCHEMA,
            "idempotency_key": self.idempotency_key,
            "request_fingerprint": self.request_fingerprint,
            "action": self.action,
            "status": self.status,
            "error_code": self.error_code,
            "result": self.result,
        }


@dataclass(frozen=True)
class HostDispatchObservation:
    status: DispatchStatus
    operation_status: OperationStatus
    action: BootstrapAction
    idempotency_key: str
    request_fingerprint: str
    controller_revision: str
    controller_release_digest: str
    release_lane: str | None = None
    host_agent_mtls_identity: str | None = None
    worker_name: str | None = None
    target_id: str | None = None
    service_unit: str | None = None
    error_code: str | None = None
    result: dict[str, Any] | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": BOOTSTRAP_EXECUTION_RECEIPT_SCHEMA,
            "status": self.status,
            "operation_status": self.operation_status,
            "action": self.action,
            "idempotency_key": self.idempotency_key,
            "request_fingerprint": self.request_fingerprint,
            "controller_revision": self.controller_revision,
            "controller_release_digest": self.controller_release_digest,
            "release_lane": self.release_lane,
            "host_agent_mtls_identity": self.host_agent_mtls_identity,
            "error_code": self.error_code,
            "result": self.result,
        }


class FleetHostDispatchSpool:
    """Broker-side publisher/observer for the narrow host bridge."""

    def __init__(
        self,
        request_root: Path,
        result_root: Path,
        *,
        runtime_uid: int | None = None,
        runtime_gid: int | None = None,
        result_uid: int = 0,
    ) -> None:
        self.request_root = request_root
        self.result_root = result_root
        self.runtime_uid = os.geteuid() if runtime_uid is None else runtime_uid
        self.runtime_gid = os.getegid() if runtime_gid is None else runtime_gid
        self.result_uid = result_uid

    def _observation(
        self,
        *,
        policy: FleetBootstrapPolicy,
        envelope: DispatchEnvelope,
        status: DispatchStatus,
        operation_status: OperationStatus,
        error_code: str | None = None,
        result: dict[str, Any] | None = None,
    ) -> HostDispatchObservation:
        request = envelope.request
        lane = None
        worker_target = None
        if request.action == "enrol-host-agent" and request.release_lane is not None:
            lane = policy.release_lane(request.release_lane)
        elif request.action == "restore-existing-worker" and request.worker_name is not None:
            worker_target = policy.worker_target(request.worker_name)
        return HostDispatchObservation(
            status=status,
            operation_status=operation_status,
            action=request.action,
            idempotency_key=envelope.idempotency_key,
            request_fingerprint=envelope.request_fingerprint,
            controller_revision=request.controller_revision,
            controller_release_digest=request.controller_release_digest,
            release_lane=lane.name if lane else None,
            host_agent_mtls_identity=lane.host_agent_mtls_identity if lane else None,
            worker_name=request.worker_name,
            target_id=worker_target.target_id if worker_target else None,
            service_unit=worker_target.service_unit if worker_target else None,
            error_code=error_code,
            result=result,
        )

    def submit(
        self,
        *,
        policy: FleetBootstrapPolicy,
        store: BootstrapOperationStore,
        request: FleetBootstrapRequest,
        idempotency_key: str,
        active_jobs: int | None = None,
    ) -> HostDispatchObservation:
        policy.validate(request)
        _validate_key(idempotency_key)
        if request.action == "restore-existing-worker" and active_jobs != 0:
            if isinstance(active_jobs, bool) or not isinstance(active_jobs, int) or active_jobs < 0:
                raise FleetHostDispatchError("active work observation is invalid")
            fingerprint = bootstrap_request_fingerprint(request)
            envelope = DispatchEnvelope(idempotency_key, fingerprint, request, active_jobs)
            store.begin(idempotency_key, request)
            return self._observation(
                policy=policy,
                envelope=envelope,
                status="access_blocked",
                operation_status="pending",
                error_code="active_work",
            )
        if request.action != "restore-existing-worker" and active_jobs is not None:
            raise FleetHostDispatchError("active work observation does not match action")

        record = store.begin(idempotency_key, request)
        fingerprint = bootstrap_request_fingerprint(request)
        envelope = DispatchEnvelope(idempotency_key, fingerprint, request, active_jobs)
        if record.status == "completed":
            return self._observation(
                policy=policy,
                envelope=envelope,
                status="completed",
                operation_status="completed",
                result=record.result,
            )

        try:
            _validate_directory(
                self.request_root,
                expected_uid=self.runtime_uid,
                expected_gid=self.runtime_gid,
                expected_mode=0o700,
            )
            _validate_directory(
                self.result_root,
                expected_uid=self.result_uid,
                expected_gid=self.runtime_gid,
                expected_mode=0o750,
            )
        except FleetHostDispatchError:
            return self._observation(
                policy=policy,
                envelope=envelope,
                status="access_blocked",
                operation_status="pending",
                error_code="host_dispatch_unavailable",
            )

        result_path = self.result_root / f"{idempotency_key}.json"
        if result_path.exists() or result_path.is_symlink():
            result_record = DispatchResult.parse(
                _read_regular(result_path, expected_uid=self.result_uid),
                expected_key=idempotency_key,
            )
            if (
                result_record.request_fingerprint != fingerprint
                or result_record.action != request.action
            ):
                raise FleetHostDispatchError(
                    "fleet host dispatch result does not match request"
                )
            if result_record.status == "completed":
                assert result_record.result is not None
                completed = store.complete(
                    idempotency_key, request, result_record.result
                )
                return self._observation(
                    policy=policy,
                    envelope=envelope,
                    status="completed",
                    operation_status="completed",
                    result=completed.result,
                )
            return self._observation(
                policy=policy,
                envelope=envelope,
                status=result_record.status,
                operation_status=(
                    "unknown" if result_record.status == "unknown" else "pending"
                ),
                error_code=result_record.error_code,
            )

        request_path = self.request_root / f"{idempotency_key}.json"
        _publish_immutable(request_path, _canonical(envelope.as_dict()), mode=0o600)
        return self._observation(
            policy=policy,
            envelope=envelope,
            status="queued",
            operation_status="pending",
        )


class FleetHostDispatcher:
    """Root-side dispatcher with fixed policy, spool, and adapter locations."""

    def __init__(
        self,
        *,
        request_root: Path,
        processing_root: Path,
        result_root: Path,
        policy_path: Path,
        release_lanes_path: Path,
        activation_adapter: Path = DEFAULT_ACTIVATION_ADAPTER,
        enrolment_adapter: Path = DEFAULT_ENROLMENT_ADAPTER,
        recovery_adapter: Path = DEFAULT_RECOVERY_ADAPTER,
        controller_status_path: Path = DEFAULT_CONTROLLER_STATUS,
        adapter_timeout_seconds: float = 120.0,
        runtime_uid: int = 9020,
        runtime_gid: int = 9020,
        root_uid: int = 0,
        root_gid: int = 0,
    ) -> None:
        self.request_root = request_root
        self.processing_root = processing_root
        self.result_root = result_root
        self.policy_path = policy_path
        self.release_lanes_path = release_lanes_path
        self.activation_adapter = activation_adapter
        self.enrolment_adapter = enrolment_adapter
        self.recovery_adapter = recovery_adapter
        self.controller_status_path = controller_status_path
        self.adapter_timeout_seconds = adapter_timeout_seconds
        self.runtime_uid = runtime_uid
        self.runtime_gid = runtime_gid
        self.root_uid = root_uid
        self.root_gid = root_gid

    def _validate_roots(self) -> None:
        _validate_directory(
            self.request_root,
            expected_uid=self.runtime_uid,
            expected_gid=self.runtime_gid,
            expected_mode=0o700,
        )
        _validate_directory(
            self.processing_root,
            expected_uid=self.root_uid,
            expected_gid=self.root_gid,
            expected_mode=0o700,
        )
        _validate_directory(
            self.result_root,
            expected_uid=self.root_uid,
            expected_gid=self.runtime_gid,
            expected_mode=0o750,
        )

    def _claim(self, key: str) -> tuple[Path, DispatchEnvelope]:
        incoming = self.request_root / f"{key}.json"
        processing = self.processing_root / f"{key}.request.json"
        payload = _read_regular(incoming, expected_uid=self.runtime_uid)
        envelope = DispatchEnvelope.parse(payload, expected_key=key)
        _publish_immutable(
            processing,
            _canonical(envelope.as_dict()),
            mode=0o600,
            uid=self.root_uid,
            gid=self.root_gid,
        )
        _remove_regular(incoming, expected_uid=self.runtime_uid)
        return processing, envelope

    def _read_processing(self, key: str) -> tuple[Path, DispatchEnvelope]:
        processing = self.processing_root / f"{key}.request.json"
        payload = _read_regular(processing, expected_uid=self.root_uid)
        return processing, DispatchEnvelope.parse(payload, expected_key=key)

    def _read_result(self, key: str) -> DispatchResult | None:
        path = self.result_root / f"{key}.json"
        if not path.exists() and not path.is_symlink():
            return None
        return DispatchResult.parse(
            _read_regular(path, expected_uid=self.root_uid), expected_key=key
        )

    def _publish_result(self, result: DispatchResult) -> None:
        _publish_immutable(
            self.result_root / f"{result.idempotency_key}.json",
            _canonical(result.as_dict()),
            mode=0o640,
            uid=self.root_uid,
            gid=self.runtime_gid,
        )

    def _started_path(self, key: str) -> Path:
        return self.processing_root / f"{key}.started.json"

    def _mark_started(self, envelope: DispatchEnvelope) -> bool:
        payload = _canonical(
            {
                "schema": STARTED_SCHEMA,
                "idempotency_key": envelope.idempotency_key,
                "request_fingerprint": envelope.request_fingerprint,
                "action": envelope.request.action,
            }
        )
        return _publish_immutable(
            self._started_path(envelope.idempotency_key),
            payload,
            mode=0o600,
            uid=self.root_uid,
            gid=self.root_gid,
        )

    def _validate_started(self, envelope: DispatchEnvelope) -> None:
        raw = _decode_object(
            _read_regular(
                self._started_path(envelope.idempotency_key),
                expected_uid=self.root_uid,
            ),
            label="started marker",
        )
        if raw != {
            "schema": STARTED_SCHEMA,
            "idempotency_key": envelope.idempotency_key,
            "request_fingerprint": envelope.request_fingerprint,
            "action": envelope.request.action,
        }:
            raise FleetHostDispatchError("fleet host dispatch started marker is invalid")

    def _cleanup(self, processing: Path, key: str) -> None:
        _remove_regular(processing, expected_uid=self.root_uid)
        _remove_regular(self._started_path(key), expected_uid=self.root_uid)
        incoming = self.request_root / f"{key}.json"
        if incoming.exists() or incoming.is_symlink():
            payload = _read_regular(incoming, expected_uid=self.runtime_uid)
            DispatchEnvelope.parse(payload, expected_key=key)
            _remove_regular(incoming, expected_uid=self.runtime_uid)

    def _unknown(self, envelope: DispatchEnvelope) -> DispatchResult:
        result = DispatchResult(
            envelope.idempotency_key,
            envelope.request_fingerprint,
            envelope.request.action,
            "unknown",
            "operation_outcome_unknown_reconciliation_required",
            None,
        )
        self._publish_result(result)
        return result

    def _execute(
        self, policy: FleetBootstrapPolicy, envelope: DispatchEnvelope
    ) -> DispatchResult:
        request = envelope.request
        if request.action in {"activate-controller", "enrol-host-agent"}:
            action = cast(
                Literal["activate-controller", "enrol-host-agent"], request.action
            )
            adapter = (
                self.activation_adapter
                if action == "activate-controller"
                else self.enrolment_adapter
            )
            adapter_path = _bootstrap_adapter_path(adapter, action=action)
            if adapter_path is None:
                return DispatchResult(
                    envelope.idempotency_key,
                    envelope.request_fingerprint,
                    action,
                    "failed",
                    "host_adapter_unavailable",
                    None,
                )
            controller_runtime = None
            if action == "activate-controller":
                controller_runtime = verified_controller_runtime_anchor(
                    self.controller_status_path,
                    expected_uid=self.root_uid,
                )
            target, lane = _bootstrap_target(
                policy=policy,
                request=request,
                controller_runtime=controller_runtime,
            )
            if not self._mark_started(envelope):
                return self._unknown(envelope)
            adapter_status, adapter_result = _invoke_bootstrap_adapter(
                adapter_path,
                request=request,
                target=target,
                lane=lane,
                timeout_seconds=self.adapter_timeout_seconds,
            )
            if adapter_status not in {"completed", "already_completed"}:
                if adapter_status == "access_blocked":
                    return DispatchResult(
                        envelope.idempotency_key,
                        envelope.request_fingerprint,
                        action,
                        "failed",
                        "host_adapter_access_blocked",
                        None,
                    )
                return self._unknown(envelope)
            completion: dict[str, Any] = {
                "action": action,
                "controller_revision": request.controller_revision,
                "controller_release_digest": request.controller_release_digest,
                "adapter_status": adapter_status,
            }
            if lane is not None:
                completion.update(
                    {
                        "release_lane": lane.name,
                        "project_id": lane.project_id,
                        "placement": lane.placement,
                        "host_agent_mtls_identity": lane.host_agent_mtls_identity,
                        "native_host_adapter": lane.native_host_adapter,
                    }
                )
            if adapter_result:
                completion.update(adapter_result)
            _validate_safe_result(completion)
            return DispatchResult(
                envelope.idempotency_key,
                envelope.request_fingerprint,
                action,
                "completed",
                None,
                completion,
            )

        assert request.action == "restore-existing-worker"
        assert request.worker_name is not None
        assert envelope.active_jobs == 0
        recovery_target = policy.worker_target(request.worker_name)
        if recovery_target is None:
            raise FleetHostDispatchError("fleet host recovery target is unavailable")
        adapter_path = _adapter_path(self.recovery_adapter)
        if adapter_path is None:
            return DispatchResult(
                envelope.idempotency_key,
                envelope.request_fingerprint,
                "restore-existing-worker",
                "failed",
                "host_adapter_unavailable",
                None,
            )
        if not self._mark_started(envelope):
            return self._unknown(envelope)
        adapter_status, adapter_result = _invoke_adapter(
            adapter_path,
            request=request,
            target=recovery_target,
            active_jobs=0,
            timeout_seconds=self.adapter_timeout_seconds,
        )
        if adapter_status not in {"completed", "already_completed"}:
            if adapter_status in {"access_blocked", "active_work", "target_unregistered"}:
                return DispatchResult(
                    envelope.idempotency_key,
                    envelope.request_fingerprint,
                    "restore-existing-worker",
                    "failed",
                    "host_adapter_access_blocked",
                    None,
                )
            return self._unknown(envelope)
        completion = {
            "action": "restore-existing-worker",
            "worker_name": recovery_target.worker_name,
            "target_id": recovery_target.target_id,
            "service_unit": recovery_target.service_unit,
            "host_binding": recovery_target.host_binding,
            "adapter_status": adapter_status,
            "active_jobs": 0,
        }
        if adapter_result:
            completion.update(adapter_result)
        _validate_safe_result(completion)
        return DispatchResult(
            envelope.idempotency_key,
            envelope.request_fingerprint,
            "restore-existing-worker",
            "completed",
            None,
            completion,
        )

    def _dispatch_processing(self, key: str) -> DispatchResult:
        processing, envelope = self._read_processing(key)
        existing = self._read_result(key)
        if existing is not None:
            if (
                existing.request_fingerprint != envelope.request_fingerprint
                or existing.action != envelope.request.action
            ):
                raise FleetHostDispatchError(
                    "fleet host dispatch completed result has fingerprint drift"
                )
            self._cleanup(processing, key)
            return existing
        # A marker present before this invocation means a previous process may
        # have crossed the mutation boundary.  Never invoke the adapter again.
        if self._started_path(key).exists() or self._started_path(key).is_symlink():
            self._validate_started(envelope)
            result = self._unknown(envelope)
        else:
            _validate_policy_file(self.policy_path, expected_uid=self.root_uid)
            _validate_policy_file(self.release_lanes_path, expected_uid=self.root_uid)
            policy = FleetBootstrapPolicy(self.policy_path, self.release_lanes_path)
            policy.validate(envelope.request)
            result = self._execute(policy, envelope)
            self._publish_result(result)
        self._cleanup(processing, key)
        return result

    @staticmethod
    def _processing_key(path: Path) -> str:
        suffix = ".request.json"
        if not path.name.endswith(suffix):
            raise FleetHostDispatchError("fleet host processing spool contains an unsafe name")
        key = path.name[: -len(suffix)]
        _validate_key(key)
        return key

    @staticmethod
    def _incoming_key(path: Path) -> str:
        if not path.name.endswith(".json") or path.name.startswith("."):
            raise FleetHostDispatchError("fleet host request spool contains an unsafe name")
        key = path.name[:-5]
        _validate_key(key)
        return key

    def drain(self) -> list[DispatchResult]:
        self._validate_roots()
        results: list[DispatchResult] = []
        processing_entries = sorted(self.processing_root.iterdir(), key=lambda item: item.name)
        for path in processing_entries:
            if path.name.endswith(".started.json") or path.name.startswith("."):
                continue
            results.append(self._dispatch_processing(self._processing_key(path)))
        incoming_entries = sorted(self.request_root.iterdir(), key=lambda item: item.name)
        for path in incoming_entries:
            if path.name.startswith("."):
                continue
            key = self._incoming_key(path)
            processing, envelope = self._claim(key)
            existing = self._read_result(key)
            if existing is not None:
                if (
                    existing.request_fingerprint != envelope.request_fingerprint
                    or existing.action != envelope.request.action
                ):
                    raise FleetHostDispatchError(
                        "fleet host dispatch duplicate has fingerprint drift"
                    )
                self._cleanup(processing, key)
                results.append(existing)
            else:
                results.append(self._dispatch_processing(key))
        return results
