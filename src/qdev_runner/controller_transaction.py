"""Durable native controller activation/rollback; no product or queue operations.

This private host journal is recovery evidence, NOT a signed release receipt.
The caller must first supply the separately verified release/activation claim.
Secrets stay in the existing configuration store and are never serialized here.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import tempfile
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .controller_release_bundle import BundleError
from .controller_release_bundle import verify as verify_bundle

_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_CONTROLLER_IMAGE_REPOSITORY = "registry.ci.qdev.run/qdev-runner-control-plane"
_SERVICES = ("broker-public", "broker-internal")
_CONFIGS = (
    "repos.json",
    "profiles.yml",
    "release-lanes.yml",
    "managed-registry.yml",
    "admin-platform-ledger.yml",
    "managed-release-ledger.yml",
    "fleet-bootstrap.yml",
    "controller-release.json",
)
_TERMINAL = {"accepted", "rolled_back"}


class TransactionError(RuntimeError):
    """Fail closed without exposing command output or private configuration."""


@dataclass(frozen=True)
class Paths:
    releases: Path = Path("/opt/qdev-runner-control-plane/releases")
    current: Path = Path("/opt/qdev-runner-control-plane/current")
    config: Path = Path("/etc/qdev-runner")
    state: Path = Path("/var/lib/qdev-runner/controller-activations")
    owner_uid: int = 0


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".controller-", dir=path.parent)
    try:
        os.fchmod(descriptor, mode)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        Path(temporary).unlink(missing_ok=True)


def _json(path: Path, value: dict[str, Any]) -> None:
    _write(path, json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def _read(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_bytes())
    if not isinstance(value, dict):
        raise TransactionError("invalid durable activation state")
    return value


def _run(
    argv: list[str],
    *,
    timeout: int = 180,
    pass_fds: tuple[int, ...] = (),
    env: dict[str, str] | None = None,
) -> str:
    try:
        result = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            pass_fds=pass_fds,
            env=env,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TransactionError("native controller operation unavailable") from error
    if result.returncode:
        raise TransactionError("native controller operation failed")
    return result.stdout


def _inspect(argv: list[str]) -> dict[str, Any]:
    values = json.loads(_run(["docker", *argv]))
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise TransactionError("container identity unavailable")
    return values[0]


def _images() -> dict[str, dict[str, str]]:
    result = {}
    for service in _SERVICES:
        container = _inspect(["inspect", f"qdev-runner-{service}"])
        image_id, reference = container.get("Image"), container.get("Config", {}).get("Image")
        if (
            not isinstance(image_id, str)
            or not _DIGEST.fullmatch(image_id)
            or not isinstance(reference, str)
            or not reference
            or reference.startswith("-")
            or container.get("State", {}).get("Running") is not True
            or _inspect(["image", "inspect", image_id]).get("Id") != image_id
        ):
            raise TransactionError("running controller image is not recoverable")
        result[service] = {"id": image_id, "reference": reference}
    return result


def _health(expected: dict[str, Any]) -> None:
    body = json.loads(
        _run(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--max-time",
                "15",
                "https://ci.qdev.run/health",
            ],
            timeout=20,
        )
    )
    if not isinstance(body, dict):
        raise TransactionError("controller health response is invalid")
    observed = body.get("controller_release", {})
    if (
        body.get("ok") is not True
        or observed.get("state") != "active"
        or observed.get("revision") != expected.get("revision")
        or observed.get("release_digest") != expected.get("release_digest")
        or (
            expected.get("artifact_digest") is not None
            and observed.get("artifact_digest") != expected.get("artifact_digest")
        )
    ):
        raise TransactionError("controller health/release identity mismatch")


def _safe_owned_path(path: Path, *, root: Path, owner_uid: int, regular: bool = False) -> None:
    """Reject symlink or writable-path substitution before privileged execution."""
    lexical_root = Path(os.path.abspath(root))
    lexical = Path(os.path.abspath(path))
    if lexical != lexical_root and lexical_root not in lexical.parents:
        raise TransactionError("privileged path is outside its registered root")
    current = lexical
    while True:
        metadata = current.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise TransactionError("privileged path contains a symbolic link")
        if current == lexical_root:
            break
        current = current.parent
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    if resolved != resolved_root and resolved_root not in resolved.parents:
        raise TransactionError("privileged path is outside its registered root")
    current = resolved
    while True:
        metadata = current.lstat()
        if metadata.st_uid != owner_uid or metadata.st_mode & 0o022:
            raise TransactionError("privileged path ownership or permissions are unsafe")
        if current == resolved_root:
            break
        current = current.parent
    metadata = resolved.lstat()
    if regular and not stat.S_ISREG(metadata.st_mode):
        raise TransactionError("privileged executable is not a regular file")


def _release(path: Path, paths: Paths, *, require_native: bool = False) -> Path:
    resolved = path.resolve(strict=True)
    if resolved.parent != paths.releases.resolve(strict=True):
        raise TransactionError("controller release is outside the registered root")
    _safe_owned_path(resolved, root=paths.releases, owner_uid=paths.owner_uid)
    required = ["deploy/compose.yml"]
    if require_native:
        required.append("scripts/activate_controller_release_native.sh")
    for relative in required:
        _safe_owned_path(
            resolved / relative,
            root=resolved,
            owner_uid=paths.owner_uid,
            regular=True,
        )
    return resolved


def _file(path: Path) -> bytes:
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise TransactionError("configuration is not a regular file")
    return path.read_bytes()


def _private_directory(path: Path, owner_uid: int) -> None:
    metadata = path.lstat()
    if path.is_symlink() or metadata.st_uid != owner_uid or metadata.st_mode & 0o077:
        raise TransactionError("controller transaction directory is not private")


def _validate_operation(paths: Paths, operation: dict[str, Any]) -> None:
    """Treat even root-private recovery state as untrusted structured input."""
    required = {
        "schema",
        "id",
        "phase",
        "candidate",
        "previous",
        "previous_status",
        "images",
        "configs",
        "identity_permissions",
    }
    if (
        set(operation) != required
        or operation.get("schema") != "qdev-controller-activation-transaction-v1"
    ):
        raise TransactionError("invalid durable activation state")
    identity = operation.get("id")
    if not isinstance(identity, str) or not re.fullmatch(r"[0-9a-f]{32}", identity):
        raise TransactionError("invalid durable activation identity")
    if operation.get("phase") not in {"prepared", "applying"}:
        raise TransactionError("invalid pending activation phase")
    candidate = operation.get("candidate")
    previous = operation.get("previous")
    if not isinstance(candidate, str) or not isinstance(previous, str):
        raise TransactionError("invalid durable release paths")
    _release(Path(candidate), paths, require_native=True)
    _release(Path(previous), paths)
    status = operation.get("previous_status")
    if (
        not isinstance(status, dict)
        or status.get("state") != "active"
        or not isinstance(status.get("revision"), str)
        or not _SHA.fullmatch(status["revision"])
        or not isinstance(status.get("release_digest"), str)
        or not re.fullmatch(r"[0-9a-f]{64}", status["release_digest"])
    ):
        raise TransactionError("invalid previous controller release tuple")
    configs = operation.get("configs")
    if not isinstance(configs, dict) or set(configs) != set(_CONFIGS):
        raise TransactionError("invalid rollback configuration inventory")
    for record in configs.values():
        if not isinstance(record, dict) or not isinstance(record.get("present"), bool):
            raise TransactionError("invalid rollback configuration tuple")
        if not record["present"]:
            if record != {"present": False}:
                raise TransactionError("invalid absent configuration tuple")
            continue
        if (
            set(record) != {"present", "sha256", "mode", "uid", "gid"}
            or not isinstance(record.get("sha256"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", record["sha256"])
            or not isinstance(record.get("mode"), int)
            or not 0 <= record["mode"] <= 0o7777
            or not isinstance(record.get("uid"), int)
            or record["uid"] < 0
            or not isinstance(record.get("gid"), int)
            or record["gid"] < 0
        ):
            raise TransactionError("invalid rollback configuration tuple")
    images = operation.get("images")
    if not isinstance(images, dict) or set(images) != set(_SERVICES):
        raise TransactionError("invalid rollback image inventory")
    for service, image in images.items():
        if (
            not isinstance(image, dict)
            or set(image) != {"id", "reference", "pin"}
            or not _DIGEST.fullmatch(str(image.get("id", "")))
            or not isinstance(image.get("reference"), str)
            or not image["reference"]
            or image["reference"].startswith("-")
            or image.get("pin") != f"qdev-controller-retained-{service}:{identity}"
        ):
            raise TransactionError("invalid rollback image tuple")
    expected_permissions = {
        "mtls/operator",
        "mtls/operator/ca.pem",
        "mtls/operator/operator-cert.pem",
        "mtls/operator/operator-key.pem",
    }
    permissions = operation.get("identity_permissions")
    if not isinstance(permissions, list) or len(permissions) != len(expected_permissions):
        raise TransactionError("invalid operator identity inventory")
    names: set[str] = set()
    for item in permissions:
        if (
            not isinstance(item, dict)
            or set(item) != {"name", "mode", "uid", "gid"}
            or not isinstance(item.get("name"), str)
            or not isinstance(item.get("mode"), int)
            or not 0 <= item["mode"] <= 0o7777
            or not isinstance(item.get("uid"), int)
            or item["uid"] < 0
            or not isinstance(item.get("gid"), int)
            or item["gid"] < 0
        ):
            raise TransactionError("invalid operator identity tuple")
        names.add(item["name"])
    if names != expected_permissions:
        raise TransactionError("invalid operator identity inventory")


def prepare(paths: Paths, candidate: Path) -> dict[str, Any]:
    """Persist rollback images/config before invoking any activation helper."""
    paths.state.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private_directory(paths.state, paths.owner_uid)
    candidate = _release(candidate, paths, require_native=True)
    previous = _release(paths.current, paths)
    status = _read(paths.config / "controller-release.json")
    revision, digest = status.get("revision"), status.get("release_digest")
    if (
        not isinstance(revision, str)
        or not _SHA.fullmatch(revision)
        or not isinstance(digest, str)
        or not re.fullmatch(r"[0-9a-f]{64}", digest)
    ):
        raise TransactionError("previous controller release tuple is incomplete")
    _health(status)
    images = _images()
    identity = uuid.uuid4().hex
    checkpoint = paths.state / identity
    checkpoint.mkdir(mode=0o700)
    scratch_paths: list[Path] = []
    image_pins: list[str] = []
    pointer = paths.current.parent / f".rollback-{identity}"
    try:
        records: dict[str, Any] = {}
        for name in _CONFIGS:
            source = paths.config / name
            if not source.exists() and not source.is_symlink():
                records[name] = {"present": False}
                continue
            data = _file(source)
            metadata = source.stat()
            _write(checkpoint / name, data)
            # Restore scratch is preallocated on the destination filesystem. ENOSPC
            # after activation cannot prevent replacement of the old configuration.
            scratch = paths.config / f".rollback-{identity}-{name}"
            _write(scratch, data, mode=stat.S_IMODE(metadata.st_mode))
            scratch_paths.append(scratch)
            os.chown(scratch, metadata.st_uid, metadata.st_gid)
            records[name] = {
                "present": True,
                "sha256": hashlib.sha256(data).hexdigest(),
                "mode": stat.S_IMODE(metadata.st_mode),
                "uid": metadata.st_uid,
                "gid": metadata.st_gid,
            }
        # Existing credentials are neither copied nor read. Only their permissions
        # are saved because the legacy native helper adjusts them during activation.
        identity_permissions = []
        identity_root = paths.config / "mtls/operator"
        identity_items = (
            identity_root,
            *(
                identity_root / n
                for n in (
                    "ca.pem",
                    "operator-cert.pem",
                    "operator-key.pem",
                )
            ),
        )
        for index, item in enumerate(identity_items):
            metadata = item.lstat()
            if (
                item.is_symlink()
                or (index == 0 and not stat.S_ISDIR(metadata.st_mode))
                or (index > 0 and not stat.S_ISREG(metadata.st_mode))
            ):
                raise TransactionError("operator identity metadata is unsafe")
            identity_permissions.append(
                {
                    "name": str(item.relative_to(paths.config)),
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "uid": metadata.st_uid,
                    "gid": metadata.st_gid,
                }
            )
        for service, image in images.items():
            pin = f"qdev-controller-retained-{service}:{identity}"
            _run(["docker", "image", "tag", image["id"], pin])
            image_pins.append(pin)
            image["pin"] = pin
        # A preallocated symlink also makes pointer restoration allocation-light.
        pointer.symlink_to(previous)
        _sync_directory(pointer.parent)
        record = {
            "schema": "qdev-controller-activation-transaction-v1",
            "id": identity,
            "phase": "prepared",
            "candidate": str(candidate),
            "previous": str(previous),
            "previous_status": status,
            "images": images,
            "configs": records,
            "identity_permissions": identity_permissions,
        }
        _validate_operation(paths, record)
        _json(checkpoint / "snapshot.json", record)
        _json(paths.state / "current.json", record)
        return record
    except BaseException:
        # Once current.json binds this identity, recovery owns every retained
        # artifact. Before that point preparation has not changed live runtime.
        # An unreadable journal is deliberately treated as potentially durable:
        # deleting the rollback tuple in that state would turn an I/O fault into
        # an unrecoverable prepared transaction.
        cleanup_allowed = False
        try:
            current = _read(paths.state / "current.json")
        except FileNotFoundError:
            cleanup_allowed = True
        except (TransactionError, OSError, ValueError):
            cleanup_allowed = False
        else:
            cleanup_allowed = current.get("id") != identity
        if cleanup_allowed:
            if pointer.is_symlink() and pointer.resolve(strict=False) == previous:
                pointer.unlink()
            for scratch in scratch_paths:
                if scratch.exists() and not scratch.is_symlink():
                    scratch.unlink()
            for pin in image_pins:
                with contextlib.suppress(TransactionError):
                    _run(["docker", "image", "rm", pin])
            for name in (*_CONFIGS, "snapshot.json", "result.json"):
                item = checkpoint / name
                if item.exists() and not item.is_symlink():
                    item.unlink()
            with contextlib.suppress(OSError):
                checkpoint.rmdir()
        raise


def _verify_configs(paths: Paths, operation: dict[str, Any]) -> None:
    for name, record in operation["configs"].items():
        target = paths.config / name
        if record["present"]:
            metadata = target.stat()
            if (
                hashlib.sha256(_file(target)).hexdigest() != record["sha256"]
                or stat.S_IMODE(metadata.st_mode) != record["mode"]
                or metadata.st_uid != record["uid"]
                or metadata.st_gid != record["gid"]
            ):
                raise TransactionError("restored configuration digest mismatch")
        elif target.exists() or target.is_symlink():
            raise TransactionError("unexpected restored configuration")


def rollback(paths: Paths, operation: dict[str, Any]) -> None:
    """Idempotently restore the old tuple, including interrupted restores.

    The pre-mutation journal remains pending if even the final write fails.
    A later invocation re-verifies physical rollback before recording success.
    """
    _validate_operation(paths, operation)
    identity = operation["id"]
    previous = _release(Path(operation["previous"]), paths)
    for image in operation["images"].values():
        if _inspect(["image", "inspect", image["id"]]).get("Id") != image["id"]:
            raise TransactionError("retained controller image missing")
    for name, record in operation["configs"].items():
        target = paths.config / name
        if not record["present"]:
            target.unlink(missing_ok=True)
            continue
        scratch = paths.config / f".rollback-{identity}-{name}"
        if scratch.exists():
            if hashlib.sha256(_file(scratch)).hexdigest() != record["sha256"]:
                raise TransactionError("rollback configuration was modified")
            os.replace(scratch, target)
        elif hashlib.sha256(_file(target)).hexdigest() != record["sha256"]:
            raise TransactionError("rollback configuration scratch is unavailable")
    _sync_directory(paths.config)
    for metadata in operation["identity_permissions"]:
        item = paths.config / metadata["name"]
        item_metadata = item.lstat()
        is_directory = metadata["name"] == "mtls/operator"
        if (
            item.is_symlink()
            or (is_directory and not stat.S_ISDIR(item_metadata.st_mode))
            or (not is_directory and not stat.S_ISREG(item_metadata.st_mode))
        ):
            raise TransactionError("operator identity metadata is unsafe")
        os.chown(item, metadata["uid"], metadata["gid"])
        os.chmod(item, metadata["mode"])
    pointer = paths.current.parent / f".rollback-{identity}"
    if pointer.is_symlink():
        if pointer.resolve(strict=True) != previous:
            raise TransactionError("rollback release pointer mismatch")
        os.replace(pointer, paths.current)
        _sync_directory(paths.current.parent)
    elif paths.current.resolve(strict=True) != previous:
        raise TransactionError("rollback release pointer unavailable")
    for image in operation["images"].values():
        _run(["docker", "image", "tag", image["id"], image["reference"]])
    rollback_env = {
        **os.environ,
        "QDEV_CONTROLLER_BROKER_PUBLIC_IMAGE": operation["images"]["broker-public"]["pin"],
        "QDEV_CONTROLLER_BROKER_INTERNAL_IMAGE": operation["images"]["broker-internal"]["pin"],
    }
    _run(
        [
            "docker",
            "compose",
            "-p",
            "qdev-runner",
            "-f",
            str(previous / "deploy/compose.yml"),
            "up",
            "-d",
            "--force-recreate",
            "--no-build",
            "--no-deps",
            *_SERVICES,
        ],
        env=rollback_env,
    )
    deadline = time.monotonic() + 45
    while True:
        try:
            actual = _images()
            for service, image in operation["images"].items():
                if actual[service]["id"] != image["id"]:
                    raise TransactionError("rollback started the wrong controller image")
            _verify_configs(paths, operation)
            _health(operation["previous_status"])
            break
        except TransactionError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(1)
    result = {**operation, "phase": "rolled_back"}
    _json(paths.state / identity / "result.json", result)
    _json(paths.state / "current.json", result)


def activate(
    paths: Paths,
    candidate: Path,
    *,
    expected_revision: str,
    expected_artifact_digest: str,
    expected_release_digest: str,
    expected_previous_revision: str,
    expected_previous_artifact_digest: str,
    candidate_image_ref: str,
) -> dict[str, Any]:
    # A persistent host lock covers the native child, snapshot and recovery.
    paths.state.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private_directory(paths.state, paths.owner_uid)
    lock_path = paths.state / ".lock"
    if lock_path.exists() and (
        lock_path.is_symlink() or not stat.S_ISREG(lock_path.lstat().st_mode)
    ):
        raise TransactionError("controller transaction lock is unsafe")
    with lock_path.open("a+b") as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            pending = _read(paths.state / "current.json")
        except FileNotFoundError:
            pending = None
        if pending is not None and pending.get("phase") not in _TERMINAL:
            _validate_operation(paths, pending)
            rollback(paths, pending)
        candidate = _release(candidate, paths, require_native=True)
        if (
            not _SHA.fullmatch(expected_revision)
            or not _DIGEST.fullmatch(expected_artifact_digest)
            or not re.fullmatch(r"[0-9a-f]{64}", expected_release_digest)
            or not _SHA.fullmatch(expected_previous_revision)
            or not _DIGEST.fullmatch(expected_previous_artifact_digest)
            or candidate_image_ref != f"{_CONTROLLER_IMAGE_REPOSITORY}@{expected_artifact_digest}"
        ):
            raise TransactionError("verified controller release tuple is invalid")
        current_status = _read(paths.config / "controller-release.json")
        if (
            current_status.get("revision") != expected_previous_revision
            or current_status.get("artifact_digest") != expected_previous_artifact_digest
        ):
            raise TransactionError("controller release compare-and-swap rejected")
        try:
            verify_bundle(
                candidate,
                source_revision=expected_revision,
                expected_digest=expected_release_digest,
            )
        except (BundleError, OSError, ValueError) as error:
            raise TransactionError("controller release bundle verification failed") from error
        operation = prepare(paths, candidate)
        operation["phase"] = "applying"
        _json(paths.state / "current.json", operation)
        try:
            # The inherited lock prevents a replacement controller process from
            # entering recovery while the fixed native child still runs.
            os.set_inheritable(lock.fileno(), True)
            _run(
                [str(candidate / "scripts/activate_controller_release_native.sh"), str(candidate)],
                timeout=900,
                pass_fds=(lock.fileno(),),
                env={
                    **os.environ,
                    "QDEV_CONTROLLER_RELEASE_REVISION": expected_revision,
                    "QDEV_CONTROLLER_ARTIFACT_DIGEST": expected_artifact_digest,
                    "QDEV_CONTROLLER_RELEASE_DIGEST": expected_release_digest,
                    "QDEV_CONTROLLER_NO_BUILD": "true",
                    "QDEV_CONTROLLER_BROKER_PUBLIC_IMAGE": candidate_image_ref,
                    "QDEV_CONTROLLER_BROKER_INTERNAL_IMAGE": candidate_image_ref,
                },
            )
            status = _read(paths.config / "controller-release.json")
            if (
                status.get("revision") != expected_revision
                or status.get("artifact_digest") != expected_artifact_digest
                or status.get("release_digest") != expected_release_digest
            ):
                raise TransactionError("candidate controller source mismatch")
            _health(status)
            active_images = _images()
            if any(image["reference"] != candidate_image_ref for image in active_images.values()):
                raise TransactionError(
                    "candidate controller is not running the exact immutable image"
                )
            result = {
                **operation,
                "phase": "accepted",
                "active_status": status,
                "active_images": active_images,
            }
            # Keep all checkpoint images/configs. Retention pruning is NOT an
            # EXIT handler and requires a later separately verified operation.
            _json(paths.state / operation["id"] / "result.json", result)
            _json(paths.state / "current.json", result)
            return result
        except BaseException:
            rollback(paths, operation)
            raise


def rollback_accepted(paths: Paths, identity: str) -> None:
    """Rollback only the currently active, retained transaction checkpoint."""
    if not re.fullmatch(r"[0-9a-f]{32}", identity):
        raise TransactionError("invalid controller transaction identity")
    paths.state.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private_directory(paths.state, paths.owner_uid)
    lock_path = paths.state / ".lock"
    if lock_path.exists() and (
        lock_path.is_symlink() or not stat.S_ISREG(lock_path.lstat().st_mode)
    ):
        raise TransactionError("controller transaction lock is unsafe")
    with lock_path.open("a+b") as lock:
        os.fchmod(lock.fileno(), 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        current = _read(paths.state / "current.json")
        if current.get("phase") != "accepted" or current.get("id") != identity:
            raise TransactionError("rollback transaction is not the active accepted release")
        checkpoint = paths.state / identity
        _private_directory(checkpoint, paths.owner_uid)
        operation = _read(checkpoint / "snapshot.json")
        if operation.get("id") != identity:
            raise TransactionError("rollback checkpoint identity mismatch")
        rollback(paths, operation)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("release", type=Path, nargs="?")
    parser.add_argument("--rollback", metavar="TRANSACTION_ID")
    args = parser.parse_args()
    try:
        if os.geteuid() != 0:
            raise TransactionError("native controller activation requires root")
        if (args.release is None) == (args.rollback is None):
            raise TransactionError("select exactly one controller operation")
        if args.rollback is not None:
            rollback_accepted(Paths(), args.rollback)
        else:
            revision = os.environ.get("QDEV_CONTROLLER_RELEASE_REVISION", "")
            artifact_digest = os.environ.get("QDEV_CONTROLLER_ARTIFACT_DIGEST", "")
            release_digest = os.environ.get("QDEV_CONTROLLER_RELEASE_DIGEST", "")
            previous_revision = os.environ.get(
                "QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION", ""
            )
            previous_artifact_digest = os.environ.get(
                "QDEV_CONTROLLER_EXPECTED_CURRENT_ARTIFACT_DIGEST", ""
            )
            candidate_image_ref = os.environ.get("QDEV_CONTROLLER_CANDIDATE_IMAGE", "")
            activate(
                Paths(),
                args.release,
                expected_revision=revision,
                expected_artifact_digest=artifact_digest,
                expected_release_digest=release_digest,
                expected_previous_revision=previous_revision,
                expected_previous_artifact_digest=previous_artifact_digest,
                candidate_image_ref=candidate_image_ref,
            )
    except (TransactionError, OSError, ValueError, KeyError, TypeError):
        print("controller_operation_failed; durable recovery state retained")
        return 1
    print("controller_operation_verified; durable rollback retained")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
