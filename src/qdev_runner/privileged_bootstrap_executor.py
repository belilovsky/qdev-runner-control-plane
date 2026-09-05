"""Root-owned executor for the narrowly allowlisted fleet bootstrap boundary.

The broker is deliberately unprivileged.  It can submit only a controller-
signed directive over a local Unix socket.  This process independently
verifies that directive and derives the exact target and native executable
from root-owned policy before performing one idempotent transition.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import socket
import stat
import struct
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, cast

from .bootstrap_authority import verify_directive, verify_quiescence_receipt
from .fleet_bootstrap import (
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
)
from .fleet_bootstrap_executor import (
    RECOVERY_RESULT_SCHEMA,
    _adapter_path,
    _safe_adapter_result,
)
from .fleet_bootstrap_operation_executor import RESULT_SCHEMA as OPERATION_RESULT_SCHEMA
from .host_enrolment_challenge import (
    HostEnrolmentChallenge,
    verify_host_enrolment_ack,
)
from .privileged_bootstrap_client import DEFAULT_SOCKET, MAX_MESSAGE_BYTES

REQUEST_SCHEMAS = frozenset(
    {
        "qdev-fleet-bootstrap-adapter-request-v1",
        "qdev-fleet-worker-recovery-request-v2",
    }
)
GENERIC_STATUSES = frozenset({"completed", "already_completed", "access_blocked", "failed"})
RECOVERY_STATUSES = frozenset(
    {"completed", "already_completed", "access_blocked", "target_unregistered", "failed"}
)
DEFAULT_STATE_ROOT = Path("/var/lib/qdev-runner/bootstrap-privileged")
DEFAULT_POLICY = Path("/etc/qdev-runner/fleet-bootstrap.yml")
DEFAULT_RELEASE_LANES = Path("/etc/qdev-runner/release-lanes.yml")
DEFAULT_SIGNING_KEY_FILE = Path("/etc/qdev-runner/bootstrap-directive.key")
DEFAULT_RUNTIME_RELEASE_ROOT = Path("/opt/qdev-runner-bootstrap/current")
DEFAULT_RUNTIME_IDENTITY_FILE = Path("/run/qdev-runner-bootstrap/executor-identity.json")
DEFAULT_BROKER_UID = 9020
DEFAULT_BROKER_GID = 9020
RESULT_SCHEMA = OPERATION_RESULT_SCHEMA

_NATIVE_HELPERS = {
    "activate-controller": Path(
        "/opt/qdev-runner-bootstrap/current/venv/bin/qdev-controller-activation-adapter"
    ),
    "enrol-host-agent": Path(
        "/opt/qdev-runner-bootstrap/current/venv/bin/qdev-host-agent-enrolment-adapter"
    ),
    "restore-existing-worker": Path(
        "/opt/qdev-runner-bootstrap/current/venv/bin/qdev-fleet-worker-recovery-native"
    ),
}


class PrivilegedExecutorError(RuntimeError):
    """A request cannot safely cross the privileged boundary."""


@dataclass(frozen=True)
class ExecutorConfig:
    policy_path: Path = DEFAULT_POLICY
    release_lanes_path: Path = DEFAULT_RELEASE_LANES
    state_root: Path = DEFAULT_STATE_ROOT
    socket_path: Path = DEFAULT_SOCKET
    broker_uid: int = DEFAULT_BROKER_UID
    broker_gid: int = DEFAULT_BROKER_GID
    timeout_seconds: float = 120
    runtime_release_root: Path = DEFAULT_RUNTIME_RELEASE_ROOT
    runtime_identity_file: Path = DEFAULT_RUNTIME_IDENTITY_FILE


def _read_signing_key(path: Path) -> str:
    """Read the shared directive key without inheriting the broker environment."""

    if not path.is_absolute() or path.is_symlink():
        raise PrivilegedExecutorError("bootstrap signing key path is unsafe")
    try:
        metadata = path.stat()
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or metadata.st_size < 32
            or metadata.st_size > 4096
        ):
            raise PrivilegedExecutorError("bootstrap signing key file is unsafe")
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise PrivilegedExecutorError("bootstrap signing key is unavailable") from error
    if len(value.encode("utf-8")) < 32:
        raise PrivilegedExecutorError("bootstrap signing key is unavailable")
    return value


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _read_json(data: bytes) -> dict[str, Any]:
    if not data or len(data) > MAX_MESSAGE_BYTES:
        raise PrivilegedExecutorError("bootstrap request is empty or too large")
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PrivilegedExecutorError("bootstrap request is not JSON") from error
    if not isinstance(value, dict):
        raise PrivilegedExecutorError("bootstrap request is not an object")
    return value


def _write(path: Path, value: dict[str, Any]) -> None:
    encoded = _canonical(value) + b"\n"
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _private_root(path: Path) -> None:
    path.mkdir(parents=True, mode=0o700, exist_ok=True)
    metadata = path.lstat()
    if (
        path.is_symlink()
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
        or not stat.S_ISDIR(metadata.st_mode)
    ):
        raise PrivilegedExecutorError("bootstrap state root is unsafe")


def _trusted_identity_file(path: Path) -> str:
    try:
        metadata = path.lstat()
        if (
            path.is_symlink()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise PrivilegedExecutorError("bootstrap runtime identity input is unsafe")
        value = path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError) as error:
        raise PrivilegedExecutorError("bootstrap runtime identity input is unavailable") from error
    return value


def _process_start_ticks(path: Path) -> int:
    try:
        value = path.read_text(encoding="utf-8")
        fields = value[value.rindex(") ") + 2 :].split()
        start_ticks = int(fields[19])
    except (OSError, UnicodeError, ValueError, IndexError) as error:
        raise PrivilegedExecutorError("bootstrap process identity is unavailable") from error
    if start_ticks < 1:
        raise PrivilegedExecutorError("bootstrap process identity is invalid")
    return start_ticks


def _runtime_identity(
    release_root: Path,
    *,
    package_path: Path | None = None,
    process_id: int | None = None,
    boot_id_path: Path = Path("/proc/sys/kernel/random/boot_id"),
    process_stat_path: Path = Path("/proc/self/stat"),
) -> dict[str, Any]:
    try:
        resolved = release_root.resolve(strict=True)
        metadata = resolved.lstat()
    except OSError as error:
        raise PrivilegedExecutorError("bootstrap runtime release is unavailable") from error
    if (
        resolved.is_symlink()
        or not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise PrivilegedExecutorError("bootstrap runtime release is unsafe")
    revision = _trusted_identity_file(resolved / "source-revision")
    bundle_digest = _trusted_identity_file(resolved / "bundle-digest")
    if not re.fullmatch(r"[0-9a-f]{40}", revision) or not re.fullmatch(
        r"[0-9a-f]{64}", bundle_digest
    ):
        raise PrivilegedExecutorError("bootstrap runtime release identity is invalid")
    package = (package_path or Path(__file__)).resolve(strict=True)
    if not package.is_relative_to(resolved):
        raise PrivilegedExecutorError("bootstrap runtime package is outside its release")
    try:
        boot_id = boot_id_path.read_text(encoding="ascii").strip().lower()
    except (OSError, UnicodeError) as error:
        raise PrivilegedExecutorError("bootstrap boot identity is unavailable") from error
    if not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id):
        raise PrivilegedExecutorError("bootstrap boot identity is invalid")
    pid = process_id if process_id is not None else os.getpid()
    if type(pid) is not int or pid < 1:
        raise PrivilegedExecutorError("bootstrap process identity is invalid")
    return {
        "schema": "qdev-bootstrap-executor-runtime-identity-v1",
        "source_revision": revision,
        "bundle_digest": bundle_digest,
        "pid": pid,
        "boot_id": boot_id,
        "process_start_ticks": _process_start_ticks(process_stat_path),
        "release_root": str(resolved),
        "package_path": str(package),
    }


def _target(policy: FleetBootstrapPolicy, request: FleetBootstrapRequest) -> dict[str, Any]:
    if request.action == "activate-controller":
        target_id = f"controller:{request.controller_revision}"
        return {
            "target_id": target_id,
            "revision": request.controller_revision,
            "release_digest": request.controller_release_digest,
            "artifact_ref": policy.controller_artifact_ref(request),
            "rollback_revision": policy.activation.rollback_revision,
            "rollback_release_digest": policy.activation.rollback_release_digest,
        }
    if request.action == "enrol-host-agent" and request.release_lane is not None:
        lane = policy.release_lane(request.release_lane)
        return {
            "target_id": f"release-lane:{lane.name}",
            "release_lane": lane.name,
            "project_id": lane.project_id,
            "placement": lane.placement,
            "client_mtls_identity": lane.client_mtls_identity,
            "host_agent_mtls_identity": lane.host_agent_mtls_identity,
            "artifact_ref_prefix": lane.artifact_ref_prefix,
            "native_host_adapter": lane.native_host_adapter,
            "runtime_endpoints": list(lane.runtime_endpoints),
            "rollback_reference": lane.rollback_reference,
            "required_readiness": list(lane.required_readiness),
        }
    if request.action == "restore-existing-worker" and request.worker_name is not None:
        worker = policy.worker_target(request.worker_name)
        if worker is None:
            raise PrivilegedExecutorError("bootstrap worker target is not registered")
        return {
            "worker_name": worker.worker_name,
            "target_id": worker.target_id,
            "service_unit": worker.service_unit,
            "host_binding": worker.host_binding,
            "labels": list(worker.labels),
            "certificate_fingerprint_sha256": worker.certificate_fingerprint_sha256,
        }
    raise PrivilegedExecutorError("bootstrap action is unsupported")


def _validate_envelope(
    envelope: dict[str, Any], *, policy: FleetBootstrapPolicy, signing_key: str
) -> tuple[FleetBootstrapRequest, str, dict[str, Any], int | None]:
    if set(envelope) != {"schema", "operation", "request", "target", "active_jobs", "quiescence"}:
        raise PrivilegedExecutorError("bootstrap envelope shape is invalid")
    schema = envelope.get("schema")
    if schema not in REQUEST_SCHEMAS:
        raise PrivilegedExecutorError("bootstrap envelope schema is invalid")
    operation = envelope.get("operation")
    if not isinstance(operation, dict):
        raise PrivilegedExecutorError("bootstrap directive is missing")
    try:
        verified = verify_directive(operation, policy=policy, signing_key=signing_key)
        request = FleetBootstrapRequest.model_validate(envelope.get("request"))
    except (FleetBootstrapError, ValueError, TypeError) as error:
        raise PrivilegedExecutorError("bootstrap authority is invalid") from error
    if request != verified.request:
        raise PrivilegedExecutorError("bootstrap request differs from signed authority")
    expected_schema = (
        "qdev-fleet-worker-recovery-request-v2"
        if request.action == "restore-existing-worker"
        else "qdev-fleet-bootstrap-adapter-request-v1"
    )
    if schema != expected_schema:
        raise PrivilegedExecutorError("bootstrap schema does not match action")
    expected_target = _target(policy, request)
    if envelope.get("target") != expected_target:
        raise PrivilegedExecutorError("bootstrap target differs from policy")
    active_jobs = envelope.get("active_jobs")
    if request.action in {"activate-controller", "restore-existing-worker"}:
        if type(active_jobs) is not int or active_jobs != 0:
            raise PrivilegedExecutorError("bootstrap operation is not quiescent")
        try:
            quiescence = verify_quiescence_receipt(
                envelope.get("quiescence"),
                operation=verified,
                target_id=str(expected_target["target_id"]),
                signing_key=signing_key,
            )
        except FleetBootstrapError as error:
            raise PrivilegedExecutorError("bootstrap quiescence authority is invalid") from error
        if quiescence["active_jobs"] != active_jobs:
            raise PrivilegedExecutorError("bootstrap quiescence count differs")
    elif active_jobs is not None or envelope.get("quiescence") is not None:
        raise PrivilegedExecutorError("host enrolment quiescence field is invalid")
    return request, verified.fence, expected_target, active_jobs


def _result_identity(
    request: FleetBootstrapRequest, target: dict[str, Any], active_jobs: int | None
) -> dict[str, Any]:
    base: dict[str, Any] = {
        "action": request.action,
        "request": request.model_dump(mode="json", by_alias=True),
        "target": target,
        "active_jobs": active_jobs,
    }
    return base


def _blocked_result(
    request: FleetBootstrapRequest,
    target: dict[str, Any],
    active_jobs: int | None,
    fence: str,
    error_code: str,
) -> dict[str, Any]:
    if request.action == "restore-existing-worker":
        return {
            "schema": RECOVERY_RESULT_SCHEMA,
            "status": "access_blocked",
            "worker_name": request.worker_name,
            "target_id": target["target_id"],
            "service_unit": target["service_unit"],
            "active_jobs": active_jobs,
            "result": {"error_code": error_code},
            "operation_fence": fence,
        }
    return {
        "schema": RESULT_SCHEMA,
        "status": "access_blocked",
        "action": request.action,
        "target_id": target["target_id"],
        "result": {"error_code": error_code},
        "operation_fence": fence,
    }


def _validate_native_result(
    raw: object,
    *,
    request: FleetBootstrapRequest,
    target: dict[str, Any],
    active_jobs: int | None,
    fence: str,
    signing_key: str,
    require_current_enrolment_ack: bool = True,
) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise PrivilegedExecutorError("native bootstrap result is not an object")
    if request.action == "restore-existing-worker":
        expected_keys = {
            "schema",
            "status",
            "worker_name",
            "target_id",
            "service_unit",
            "active_jobs",
            "result",
            "operation_fence",
        }
        if (
            set(raw) != expected_keys
            or raw.get("schema") != RECOVERY_RESULT_SCHEMA
            or raw.get("status") not in RECOVERY_STATUSES
            or raw.get("worker_name") != request.worker_name
            or raw.get("target_id") != target["target_id"]
            or raw.get("service_unit") != target["service_unit"]
            or raw.get("active_jobs") != active_jobs
            or raw.get("operation_fence") != fence
        ):
            raise PrivilegedExecutorError("native bootstrap result identity mismatch")
    else:
        if (
            set(raw)
            != {
                "schema",
                "status",
                "action",
                "target_id",
                "result",
                "operation_fence",
            }
            or raw.get("schema") != RESULT_SCHEMA
            or raw.get("status") not in GENERIC_STATUSES
            or raw.get("action") != request.action
            or raw.get("target_id") != target["target_id"]
            or raw.get("operation_fence") != fence
        ):
            raise PrivilegedExecutorError("native bootstrap result identity mismatch")
    if request.action == "enrol-host-agent" and raw.get("status") in {
        "completed",
        "already_completed",
    }:
        result = raw.get("result")
        expected_result_keys = {
            "release_lane",
            "host_agent_identity",
            "certificate_fingerprint_sha256",
            "service_status",
            "enrolment_ack",
        }
        if (
            not isinstance(result, dict)
            or set(result) != expected_result_keys
            or result.get("release_lane") != target["release_lane"]
            or result.get("host_agent_identity") != target["host_agent_mtls_identity"]
            or result.get("service_status") != "active"
        ):
            raise PrivilegedExecutorError("host enrolment result identity mismatch")
        scalar_result = dict(result)
        scalar_result.pop("enrolment_ack", None)
        if _safe_adapter_result(scalar_result) is None:
            raise PrivilegedExecutorError("native bootstrap result contains unsafe data")
        acknowledgement = result.get("enrolment_ack")
        nonce = acknowledgement.get("nonce") if isinstance(acknowledgement, dict) else None
        try:
            challenge = HostEnrolmentChallenge.model_validate(
                {
                    "schema": "qdev-host-enrolment-challenge-v1",
                    "release_lane": target["release_lane"],
                    "project_id": target["project_id"],
                    "placement": target["placement"],
                    "controller_revision": request.controller_revision,
                    "operation_fence": fence,
                    "certificate_fingerprint_sha256": result.get("certificate_fingerprint_sha256"),
                    "nonce": nonce,
                }
            )
            verify_host_enrolment_ack(
                acknowledgement,
                request=challenge,
                expected_mtls_identity=target["host_agent_mtls_identity"],
                signing_key=signing_key,
                require_current=require_current_enrolment_ack,
            )
        except (TypeError, ValueError) as error:
            raise PrivilegedExecutorError("host enrolment acknowledgement is invalid") from error
    elif _safe_adapter_result(raw.get("result")) is None:
        raise PrivilegedExecutorError("native bootstrap result contains unsafe data")
    return dict(raw)


def _invoke_native(
    helper: Path,
    envelope: dict[str, Any],
    *,
    request: FleetBootstrapRequest,
    target: dict[str, Any],
    active_jobs: int | None,
    fence: str,
    signing_key: str,
    timeout_seconds: float,
) -> dict[str, Any]:
    native_envelope = dict(envelope)
    native_envelope.pop("quiescence", None)
    try:
        completed = subprocess.run(  # noqa: S603
            [str(helper)],
            input=_canonical(native_envelope),
            capture_output=True,
            check=False,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PrivilegedExecutorError("native bootstrap adapter unavailable") from error
    if completed.returncode != 0 or len(completed.stdout) > MAX_MESSAGE_BYTES:
        raise PrivilegedExecutorError("native bootstrap adapter failed")
    try:
        raw = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PrivilegedExecutorError("native bootstrap result is invalid") from error
    return _validate_native_result(
        raw,
        request=request,
        target=target,
        active_jobs=active_jobs,
        fence=fence,
        signing_key=signing_key,
    )


def execute_envelope(
    envelope: dict[str, Any],
    *,
    policy: FleetBootstrapPolicy,
    signing_key: str,
    state_root: Path = DEFAULT_STATE_ROOT,
    helper_paths: dict[str, Path] | None = None,
    timeout_seconds: float = 120,
) -> dict[str, Any]:
    """Execute or replay one exact policy-derived privileged operation."""

    request, fence, target, active_jobs = _validate_envelope(
        envelope, policy=policy, signing_key=signing_key
    )
    helpers = helper_paths or _NATIVE_HELPERS
    if set(helpers) != set(_NATIVE_HELPERS):
        raise PrivilegedExecutorError("native bootstrap helper set is invalid")
    _private_root(state_root)
    lock_path = state_root / ".lock"
    with lock_path.open("a+b") as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        path = state_root / f"{fence}.json"
        identity = _result_identity(request, target, active_jobs)
        identity_digest = hashlib.sha256(_canonical(identity)).hexdigest()
        if path.exists():
            try:
                recorded = json.loads(path.read_bytes())
            except (OSError, json.JSONDecodeError) as error:
                raise PrivilegedExecutorError("bootstrap journal is unreadable") from error
            if (
                not isinstance(recorded, dict)
                or recorded.get("identity_digest") != identity_digest
                or recorded.get("fence") != fence
            ):
                raise PrivilegedExecutorError("bootstrap fence was reused with changed intent")
            result = recorded.get("result")
            if recorded.get("phase") == "completed" and isinstance(result, dict):
                validated = _validate_native_result(
                    result,
                    request=request,
                    target=target,
                    active_jobs=active_jobs,
                    fence=fence,
                    signing_key=signing_key,
                    require_current_enrolment_ack=False,
                )
                # Only a native success is final. Access/capacity failures are
                # deliberately retryable with the same immutable intent; a
                # changed intent is still rejected by identity_digest above.
                if validated.get("status") in {"completed", "already_completed"}:
                    return validated
        _write(
            path,
            {
                "schema": "qdev-privileged-bootstrap-journal-v1",
                "fence": fence,
                "identity_digest": identity_digest,
                "phase": "applying",
                "result": None,
            },
        )
        helper = _adapter_path(helpers[request.action])
        if helper is None:
            result = _blocked_result(
                request, target, active_jobs, fence, "native_adapter_unavailable"
            )
        else:
            result = _invoke_native(
                helper,
                envelope,
                request=request,
                target=target,
                active_jobs=active_jobs,
                fence=fence,
                signing_key=signing_key,
                timeout_seconds=timeout_seconds,
            )
        terminal = result.get("status") in {"completed", "already_completed"}
        _write(
            path,
            {
                "schema": "qdev-privileged-bootstrap-journal-v1",
                "fence": fence,
                "identity_digest": identity_digest,
                "phase": "completed" if terminal else "retryable",
                "result": result,
            },
        )
        return result


def _peer_uid(connection: socket.socket) -> int:
    try:
        peer_credentials = cast(int, socket.__dict__["SO_PEERCRED"])
        credentials = connection.getsockopt(socket.SOL_SOCKET, peer_credentials, 12)
    except (AttributeError, OSError) as error:
        raise PrivilegedExecutorError("peer credentials are unavailable") from error
    _pid, uid, _gid = struct.unpack("3i", credentials)
    return cast(int, uid)


def _receive(connection: socket.socket) -> bytes:
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = connection.recv(min(65536, MAX_MESSAGE_BYTES + 1 - total))
        if not chunk:
            break
        chunks.append(chunk)
        total += len(chunk)
        if total > MAX_MESSAGE_BYTES:
            raise PrivilegedExecutorError("bootstrap request is too large")
    return b"".join(chunks)


def _serve_connection(
    connection: socket.socket,
    *,
    config: ExecutorConfig,
    policy: FleetBootstrapPolicy,
    signing_key: str,
) -> None:
    if _peer_uid(connection) != config.broker_uid:
        raise PrivilegedExecutorError("bootstrap peer is not the broker identity")
    envelope = _read_json(_receive(connection))
    result = execute_envelope(
        envelope,
        policy=policy,
        signing_key=signing_key,
        state_root=config.state_root,
        timeout_seconds=config.timeout_seconds,
    )
    encoded = _canonical(result)
    if len(encoded) > MAX_MESSAGE_BYTES:
        raise PrivilegedExecutorError("bootstrap result is too large")
    connection.sendall(encoded)


def serve(config: ExecutorConfig, *, signing_key: str) -> None:
    if os.geteuid() != 0:
        raise PrivilegedExecutorError("privileged bootstrap executor requires root")
    if not signing_key:
        raise PrivilegedExecutorError("bootstrap signing identity is unavailable")
    policy = FleetBootstrapPolicy(config.policy_path, config.release_lanes_path)
    runtime_identity = _runtime_identity(config.runtime_release_root)
    _private_root(config.state_root)
    parent = config.socket_path.parent
    parent.mkdir(parents=True, mode=0o750, exist_ok=True)
    metadata = parent.lstat()
    if parent.is_symlink() or metadata.st_uid != 0 or metadata.st_mode & 0o027:
        raise PrivilegedExecutorError("bootstrap socket directory is unsafe")
    if config.socket_path.exists() or config.socket_path.is_symlink():
        metadata = config.socket_path.lstat()
        if not stat.S_ISSOCK(metadata.st_mode) or metadata.st_uid != 0:
            raise PrivilegedExecutorError("bootstrap socket path is unsafe")
        config.socket_path.unlink()
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(config.socket_path))
        os.chown(config.socket_path, 0, config.broker_gid)
        os.chmod(config.socket_path, 0o660)
        server.listen(16)
        _write(config.runtime_identity_file, runtime_identity)
        try:
            while True:
                connection, _ = server.accept()
                with connection, contextlib.suppress(PrivilegedExecutorError, OSError):
                    _serve_connection(
                        connection,
                        config=config,
                        policy=policy,
                        signing_key=signing_key,
                    )
        finally:
            config.socket_path.unlink(missing_ok=True)
            try:
                recorded = json.loads(config.runtime_identity_file.read_text(encoding="utf-8"))
            except (OSError, UnicodeError, json.JSONDecodeError):
                recorded = None
            if isinstance(recorded, dict) and recorded.get("pid") == os.getpid():
                config.runtime_identity_file.unlink(missing_ok=True)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--socket", type=Path, default=DEFAULT_SOCKET)
    parser.add_argument("--state-root", type=Path, default=DEFAULT_STATE_ROOT)
    parser.add_argument("--signing-key-file", type=Path, default=DEFAULT_SIGNING_KEY_FILE)
    parser.add_argument("--runtime-release-root", type=Path, default=DEFAULT_RUNTIME_RELEASE_ROOT)
    parser.add_argument("--runtime-identity-file", type=Path, default=DEFAULT_RUNTIME_IDENTITY_FILE)
    args = parser.parse_args()
    config = ExecutorConfig(
        policy_path=Path(os.environ.get("QDEV_FLEET_BOOTSTRAP_POLICY", DEFAULT_POLICY)),
        release_lanes_path=Path(os.environ.get("QDEV_RELEASE_LANES", DEFAULT_RELEASE_LANES)),
        state_root=args.state_root,
        socket_path=args.socket,
        broker_uid=int(os.environ.get("QDEV_CONTROLLER_RUNTIME_UID", DEFAULT_BROKER_UID)),
        broker_gid=int(os.environ.get("QDEV_CONTROLLER_RUNTIME_GID", DEFAULT_BROKER_GID)),
        runtime_release_root=args.runtime_release_root,
        runtime_identity_file=args.runtime_identity_file,
    )
    try:
        serve(config, signing_key=_read_signing_key(args.signing_key_file))
    except (PrivilegedExecutorError, FleetBootstrapError, OSError, ValueError):
        print("privileged_bootstrap_executor_failed")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
