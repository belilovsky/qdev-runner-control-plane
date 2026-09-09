"""Prepare and publish the root-owned assets consumed by controller activation.

The fleet adapter intentionally accepts only fixed spool paths.  This module
turns a reconciled artifact and an offline-signed envelope into those paths
without a manual copy step.  It also captures the current status and effective
configuration under the lifecycle lock before an unsigned envelope is issued.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import stat
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .controller_activation import (
    ENVELOPE_SCHEMA,
    MAX_ENVELOPE_TTL,
    ControllerActivationError,
    ControllerReleaseStatus,
    ControllerTuple,
    MeasuredControllerReleaseStatus,
    fingerprint_release_tree,
    load_activation_public_key,
    load_and_verify_envelope,
    verify_controller_artifact_manifest,
)
from .controller_recovery_artifact import (
    ControllerRecoveryArtifactError,
    candidate_config_digest,
    verify_current_snapshot,
)
from .controller_release import ControllerReleaseIdentityError, controller_release_digest

_SHA = re.compile(r"^[0-9a-f]{40}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
ACTIVATION_LIFECYCLE_LOCK = Path("/run/lock/qdev-controller-activation.lock")

_DESCRIPTOR_FIELDS = (
    "image_archive",
    "sbom",
    "security_scans",
    "source_scan",
    "image_scan",
    "provenance",
    "claim_receipt",
)


class ControllerActivationAssetsError(RuntimeError):
    """A fixed-target activation asset operation could not be proven safe."""


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _parse_time(value: object, *, label: str) -> datetime:
    if not isinstance(value, str):
        raise ControllerActivationAssetsError(f"{label} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ControllerActivationAssetsError(f"{label} is invalid") from exc
    if parsed.tzinfo is None:
        raise ControllerActivationAssetsError(f"{label} is invalid")
    return parsed.astimezone(UTC)


def _safe_regular_bytes(
    path: Path,
    *,
    label: str,
    require_root_owner: bool,
    mode_mask: int = 0o022,
) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (require_root_owner and metadata.st_uid != 0)
            or stat.S_IMODE(metadata.st_mode) & mode_mask
        ):
            raise ControllerActivationAssetsError(f"{label} is unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read()
    except OSError as exc:
        raise ControllerActivationAssetsError(f"{label} is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _safe_directory(path: Path, *, label: str, require_root_owner: bool) -> Path:
    try:
        metadata = path.lstat()
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise ControllerActivationAssetsError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or (require_root_owner and metadata.st_uid != 0)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or resolved != path.absolute()
    ):
        raise ControllerActivationAssetsError(f"{label} is unsafe")
    return resolved


def _ensure_directory(
    path: Path,
    *,
    label: str,
    require_root_owner: bool,
    mode: int = 0o700,
) -> Path:
    try:
        path.mkdir(mode=mode, parents=False, exist_ok=False)
    except FileExistsError:
        pass
    except OSError as exc:
        raise ControllerActivationAssetsError(f"{label} cannot be created") from exc
    try:
        metadata = path.lstat()
        if require_root_owner and metadata.st_uid != 0:
            raise ControllerActivationAssetsError(f"{label} is not root-owned")
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
            raise ControllerActivationAssetsError(f"{label} is unsafe")
        if stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ControllerActivationAssetsError(f"{label} permissions are unsafe")
        if stat.S_IMODE(metadata.st_mode) != mode:
            os.chmod(path, mode)
    except OSError as exc:
        raise ControllerActivationAssetsError(f"{label} cannot be verified") from exc
    return path


def _fsync_directory(path: Path) -> None:
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        os.fsync(descriptor)
    except OSError as exc:
        raise ControllerActivationAssetsError(
            "activation asset directory cannot be synced"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _publish_bytes(
    path: Path,
    payload: bytes,
    *,
    label: str,
    require_root_owner: bool,
    allow_existing_same: bool,
) -> bool:
    """Publish one root-only file without replacing an existing target.

    ``os.link`` is the commit primitive: it atomically fails if another process
    published the name first.  A byte-identical existing target is accepted
    only for the idempotent staging path.
    """

    parent = _safe_directory(
        path.parent, label=f"{label} directory", require_root_owner=require_root_owner
    )
    temporary = parent / f".{path.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o600,
        )
        os.fchmod(descriptor, 0o600)
        if require_root_owner:
            os.fchown(descriptor, 0, 0)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as exc:
            existing = _safe_regular_bytes(
                path,
                label=label,
                require_root_owner=require_root_owner,
            )
            if not allow_existing_same or existing != payload:
                raise ControllerActivationAssetsError(f"refusing to replace {label}") from exc
            return False
        _fsync_directory(parent)
        return True
    except OSError as exc:
        raise ControllerActivationAssetsError(f"{label} cannot be published") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ControllerActivationAssetsError(f"{label} temporary cleanup failed") from exc


@contextmanager
def activation_lifecycle_lock(path: Path, *, require_root_owner: bool = True) -> Iterator[None]:
    """Acquire the existing nonblocking controller activation lifecycle lock."""

    _safe_directory(
        path.parent,
        label="controller activation lock directory",
        require_root_owner=require_root_owner,
    )
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (require_root_owner and metadata.st_uid != 0)
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise ControllerActivationAssetsError("controller activation lock is unsafe")
        os.fchmod(descriptor, 0o600)
        if require_root_owner:
            os.fchown(descriptor, 0, 0)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ControllerActivationAssetsError(
                "another controller activation is active"
            ) from exc
        yield
    except OSError as exc:
        raise ControllerActivationAssetsError("controller activation lock is unavailable") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _status_from_snapshot(
    status_path: Path,
    *,
    transaction_id: str,
    current_config_digest: str,
    require_root_owner: bool,
) -> ControllerReleaseStatus:
    raw = _safe_regular_bytes(
        status_path,
        label="current controller status",
        require_root_owner=require_root_owner,
    )
    try:
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerActivationAssetsError("current controller status is invalid") from exc
    try:
        if isinstance(document, dict) and document.get("schema") in {
            "qdev-controller-activation-status-v1",
            "qdev-controller-activation-status-v2",
        }:
            status = ControllerReleaseStatus.parse(document)
        else:
            measured = MeasuredControllerReleaseStatus.parse(document)
            current = ControllerTuple(
                measured.revision,
                measured.public_image_digest,
                current_config_digest,
                measured.internal_image_digest,
            )
            return ControllerReleaseStatus(
                generation=0,
                current=current,
                previous=None,
                transaction_id=f"bootstrap:{transaction_id}",
                activated_at=measured.activated_at,
            )
    except ControllerActivationError as exc:
        raise ControllerActivationAssetsError(str(exc)) from exc
    return status


def _canonical_status_digest(status: ControllerReleaseStatus) -> str:
    return hashlib.sha256(_canonical(status.mapping()) + b"\n").hexdigest()


def issue_unsigned_activation_envelope(
    *,
    release_root: Path,
    source_sha: str,
    artifact_manifest: Path,
    current_status_path: Path,
    current_config_root: Path,
    transaction_id: str,
    ttl_seconds: int,
    now: datetime | None = None,
    require_root_owner: bool = True,
) -> dict[str, object]:
    """Generate one unsigned envelope from a freshly captured current snapshot."""

    if not _SHA.fullmatch(source_sha):
        raise ControllerActivationAssetsError("candidate source SHA is invalid")
    if not _IDENTIFIER.fullmatch(transaction_id):
        raise ControllerActivationAssetsError("activation transaction ID is invalid")
    if (
        isinstance(ttl_seconds, bool)
        or not isinstance(ttl_seconds, int)
        or not 1 <= ttl_seconds <= int(MAX_ENVELOPE_TTL.total_seconds())
    ):
        raise ControllerActivationAssetsError("activation envelope TTL is invalid")
    observed_at = (now or datetime.now(UTC)).astimezone(UTC).replace(microsecond=0)
    try:
        artifact = verify_controller_artifact_manifest(
            artifact_manifest,
            require_root_owner=require_root_owner,
            now=observed_at,
        )
        release_digest = controller_release_digest(release_root).removeprefix("sha256:")
        config_digest = candidate_config_digest(release_root)
        entrypoint_digest = fingerprint_release_tree(
            release_root,
            require_root_owner=require_root_owner,
        )
        current_config_digest = candidate_config_digest(current_config_root)
    except (
        ControllerActivationError,
        ControllerReleaseIdentityError,
        ControllerRecoveryArtifactError,
    ) as exc:
        raise ControllerActivationAssetsError(str(exc)) from exc
    if artifact.source_sha != source_sha:
        raise ControllerActivationAssetsError("artifact source SHA does not match exact release")
    if artifact.policy_bundle_digest != config_digest:
        raise ControllerActivationAssetsError("artifact policy digest does not match exact release")
    if artifact.entrypoint_reconciliation_digest != entrypoint_digest:
        raise ControllerActivationAssetsError(
            "artifact entrypoint digest does not match exact release"
        )
    status = _status_from_snapshot(
        current_status_path,
        transaction_id=transaction_id,
        current_config_digest=current_config_digest,
        require_root_owner=require_root_owner,
    )
    expires_at = observed_at + timedelta(seconds=ttl_seconds)
    identity_expiry = artifact.workflow_identity.get("expires_at")
    if identity_expiry is not None:
        expires_at = min(expires_at, _parse_time(identity_expiry, label="artifact identity expiry"))
    if expires_at <= observed_at:
        raise ControllerActivationAssetsError("reconciled artifact identity has expired")
    unsigned: dict[str, object] = {
        "schema": ENVELOPE_SCHEMA,
        "transaction_id": transaction_id,
        "issued_at": _format_time(observed_at),
        "expires_at": _format_time(expires_at),
        "expected_generation": status.generation,
        "expected_current": status.current.mapping(),
        "expected_current_status_digest": _canonical_status_digest(status),
        "expected_current_config_digest": current_config_digest,
        "candidate": ControllerTuple(
            source_sha,
            artifact.image_digest,
            artifact.policy_bundle_digest,
            artifact.image_digest,
        ).mapping(),
        "candidate_release_digest": release_digest,
        "candidate_config_digest": config_digest,
        "artifact_manifest_digest": artifact.manifest_digest,
        "entrypoint_reconciliation_digest": entrypoint_digest,
    }
    try:
        verify_current_snapshot(
            unsigned,
            current_status_path=current_status_path,
            current_config_root=current_config_root,
        )
    except ControllerRecoveryArtifactError as exc:
        raise ControllerActivationAssetsError(str(exc)) from exc
    return unsigned


def snapshot_current_material(
    *,
    status_path: Path,
    current_config_files: Mapping[str, Path],
    snapshot_root: Path,
    transaction_id: str,
    require_root_owner: bool = True,
) -> tuple[Path, Path]:
    """Create a no-overwrite snapshot used by both issue and offline signing."""

    if not _IDENTIFIER.fullmatch(transaction_id):
        raise ControllerActivationAssetsError("activation transaction ID is invalid")
    _safe_directory(
        snapshot_root, label="activation snapshot root", require_root_owner=require_root_owner
    )
    transaction_root = snapshot_root / transaction_id
    try:
        transaction_root.mkdir(mode=0o700)
    except FileExistsError as exc:
        raise ControllerActivationAssetsError(
            "activation transaction snapshot already exists"
        ) from exc
    except OSError as exc:
        raise ControllerActivationAssetsError(
            "activation transaction snapshot cannot be created"
        ) from exc
    try:
        if require_root_owner:
            os.chown(transaction_root, 0, 0)
        os.chmod(transaction_root, 0o700)
        config_root = _ensure_directory(
            transaction_root / "current-config",
            label="activation current-config snapshot",
            require_root_owner=require_root_owner,
        )
        inventory = _ensure_directory(
            config_root / "inventory",
            label="activation inventory snapshot",
            require_root_owner=require_root_owner,
        )
        config = _ensure_directory(
            config_root / "config",
            label="activation configuration snapshot",
            require_root_owner=require_root_owner,
        )
        status = _safe_regular_bytes(
            status_path,
            label="current controller status",
            require_root_owner=require_root_owner,
        )
        _publish_bytes(
            transaction_root / "status.json",
            status,
            label="activation status snapshot",
            require_root_owner=require_root_owner,
            allow_existing_same=False,
        )
        expected_names = {
            "repos.json",
            "profiles.yml",
            "release-lanes.yml",
            "managed-registry.yml",
            "fleet-bootstrap.yml",
            "managed-release-ledger.yml",
        }
        if set(current_config_files) != expected_names:
            raise ControllerActivationAssetsError("current configuration mapping is incomplete")
        for logical_name, source in sorted(current_config_files.items()):
            payload = _safe_regular_bytes(
                source,
                label=f"current controller configuration {logical_name}",
                require_root_owner=require_root_owner,
            )
            destination = (
                inventory / logical_name if logical_name == "repos.json" else config / logical_name
            )
            _publish_bytes(
                destination,
                payload,
                label=f"activation configuration snapshot {logical_name}",
                require_root_owner=require_root_owner,
                allow_existing_same=False,
            )
        _fsync_directory(inventory)
        _fsync_directory(config)
        _fsync_directory(config_root)
        _fsync_directory(transaction_root)
    except BaseException:
        # The deliberately retained incomplete directory makes a retry with the
        # same transaction fail closed; it is never referenced by an unsigned
        # envelope because that file is published only after this function.
        raise
    return transaction_root / "status.json", config_root


def snapshot_and_issue_unsigned_activation_envelope(
    *,
    release_root: Path,
    source_sha: str,
    artifact_manifest: Path,
    assets_root: Path,
    current_status_path: Path,
    current_config_files: Mapping[str, Path],
    transaction_id: str,
    ttl_seconds: int,
    now: datetime | None = None,
    require_root_owner: bool = True,
) -> dict[str, object]:
    """Snapshot live inputs and atomically publish one unsigned envelope.

    The caller must hold :func:`activation_lifecycle_lock`.  The snapshot and
    unsigned output names are transaction-scoped and can never be replaced.
    """

    _safe_directory(
        assets_root,
        label="activation assets root",
        require_root_owner=require_root_owner,
    )
    snapshots = _ensure_directory(
        assets_root / "snapshots",
        label="activation snapshot spool",
        require_root_owner=require_root_owner,
    )
    unsigned_root = _ensure_directory(
        assets_root / "unsigned",
        label="unsigned activation spool",
        require_root_owner=require_root_owner,
    )
    _ensure_directory(
        assets_root / "signed",
        label="signed activation spool",
        require_root_owner=require_root_owner,
    )
    snapshot_status, snapshot_config_root = snapshot_current_material(
        status_path=current_status_path,
        current_config_files=current_config_files,
        snapshot_root=snapshots,
        transaction_id=transaction_id,
        require_root_owner=require_root_owner,
    )
    unsigned = issue_unsigned_activation_envelope(
        release_root=release_root,
        source_sha=source_sha,
        artifact_manifest=artifact_manifest,
        current_status_path=snapshot_status,
        current_config_root=snapshot_config_root,
        transaction_id=transaction_id,
        ttl_seconds=ttl_seconds,
        now=now,
        require_root_owner=require_root_owner,
    )
    unsigned_path = unsigned_root / f"{transaction_id}.json"
    _publish_bytes(
        unsigned_path,
        _canonical(unsigned) + b"\n",
        label="unsigned activation envelope",
        require_root_owner=require_root_owner,
        allow_existing_same=False,
    )
    _fsync_directory(unsigned_root)
    return {
        "status": "issued",
        "transaction_id": transaction_id,
        "unsigned_envelope": str(unsigned_path),
        "snapshot_status": str(snapshot_status),
        "snapshot_config_root": str(snapshot_config_root),
        "expires_at": unsigned["expires_at"],
        "expected_generation": unsigned["expected_generation"],
        "expected_current": unsigned["expected_current"],
        "candidate": unsigned["candidate"],
    }


def _verify_trust_binding(
    *,
    activation_public_key: Path,
    admission_public_key: Path,
    trust_binding: Path,
    require_root_owner: bool,
) -> Any:
    activation = _safe_regular_bytes(
        activation_public_key,
        label="activation public key",
        require_root_owner=require_root_owner,
    )
    admission = _safe_regular_bytes(
        admission_public_key,
        label="admission public key",
        require_root_owner=require_root_owner,
    )
    raw_binding = _safe_regular_bytes(
        trust_binding,
        label="activation trust binding",
        require_root_owner=require_root_owner,
    )
    try:
        binding = json.loads(raw_binding.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerActivationAssetsError("activation trust binding is invalid") from exc
    expected = {
        "schema": "qdev-controller-activation-trust-binding-v1",
        "binding": "controller-registry",
        "authority": "controller-admission",
        "source_path": str(admission_public_key),
        "source_sha256": "sha256:" + hashlib.sha256(admission).hexdigest(),
        "activation_public_key_path": str(activation_public_key),
        "activation_public_key_sha256": "sha256:" + hashlib.sha256(activation).hexdigest(),
    }
    if not isinstance(binding, dict) or binding != expected or activation != admission:
        raise ControllerActivationAssetsError("activation trust binding is invalid")
    try:
        return load_activation_public_key(
            activation_public_key,
            require_root_owner=require_root_owner,
        )
    except ControllerActivationError as exc:
        raise ControllerActivationAssetsError(str(exc)) from exc


def _artifact_members(
    path: Path,
    *,
    expected_manifest_digest: str,
    require_root_owner: bool,
) -> dict[str, bytes]:
    raw = _safe_regular_bytes(
        path,
        label="controller artifact manifest",
        require_root_owner=require_root_owner,
    )
    try:
        manifest = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerActivationAssetsError("controller artifact manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise ControllerActivationAssetsError("controller artifact manifest is invalid")
    actual_manifest_digest = hashlib.sha256(raw).hexdigest()
    if actual_manifest_digest != expected_manifest_digest:
        raise ControllerActivationAssetsError(
            "controller artifact manifest changed after verification"
        )
    members = {f"manifest:{actual_manifest_digest}.json": raw}
    for field in _DESCRIPTOR_FIELDS:
        descriptor = manifest.get(field)
        if descriptor is None and field == "claim_receipt":
            continue
        if not isinstance(descriptor, dict) or set(descriptor) != {"path", "sha256", "size"}:
            raise ControllerActivationAssetsError("controller artifact descriptor is invalid")
        name = descriptor["path"]
        expected_digest = descriptor["sha256"]
        expected_size = descriptor["size"]
        if (
            not isinstance(name, str)
            or Path(name).name != name
            or not name
            or not isinstance(expected_digest, str)
            or not _HEX_DIGEST.fullmatch(expected_digest)
            or isinstance(expected_size, bool)
            or not isinstance(expected_size, int)
            or expected_size < 0
        ):
            raise ControllerActivationAssetsError("controller artifact descriptor is invalid")
        payload = _safe_regular_bytes(
            path.parent / name,
            label=f"controller artifact member {name}",
            require_root_owner=require_root_owner,
        )
        if len(payload) != expected_size or hashlib.sha256(payload).hexdigest() != expected_digest:
            raise ControllerActivationAssetsError(
                "controller artifact member does not match manifest"
            )
        members[name] = payload
    return members


def stage_activation_assets(
    *,
    release_root: Path,
    source_sha: str,
    artifact_manifest: Path,
    signed_envelope: Path,
    assets_root: Path,
    activation_public_key: Path,
    admission_public_key: Path,
    trust_binding: Path,
    now: datetime | None = None,
    require_root_owner: bool = True,
) -> dict[str, object]:
    """Stage verified assets and publish the envelope last as the commit point."""

    if not _SHA.fullmatch(source_sha):
        raise ControllerActivationAssetsError("candidate source SHA is invalid")
    observed_at = (now or datetime.now(UTC)).astimezone(UTC)
    _safe_directory(
        assets_root, label="activation assets root", require_root_owner=require_root_owner
    )
    public_key = _verify_trust_binding(
        activation_public_key=activation_public_key,
        admission_public_key=admission_public_key,
        trust_binding=trust_binding,
        require_root_owner=require_root_owner,
    )
    try:
        envelope = load_and_verify_envelope(
            signed_envelope,
            public_key=public_key,
            now=observed_at,
        )
        artifact = verify_controller_artifact_manifest(
            artifact_manifest,
            require_root_owner=require_root_owner,
            now=observed_at,
        )
        release_digest = controller_release_digest(release_root).removeprefix("sha256:")
        config_digest = candidate_config_digest(release_root)
        entrypoint_digest = fingerprint_release_tree(
            release_root,
            require_root_owner=require_root_owner,
        )
    except (
        ControllerActivationError,
        ControllerReleaseIdentityError,
        ControllerRecoveryArtifactError,
    ) as exc:
        raise ControllerActivationAssetsError(str(exc)) from exc
    if (
        artifact.source_sha != source_sha
        or envelope.candidate.source_sha != source_sha
        or envelope.candidate.public_image_digest != artifact.image_digest
        or envelope.candidate.effective_internal_image_digest != artifact.image_digest
        or envelope.candidate.policy_bundle_digest != artifact.policy_bundle_digest
        or envelope.artifact_manifest_digest != artifact.manifest_digest
        or envelope.candidate_release_digest != release_digest
        or envelope.candidate_config_digest != config_digest
        or envelope.entrypoint_reconciliation_digest != entrypoint_digest
        or artifact.policy_bundle_digest != config_digest
        or artifact.entrypoint_reconciliation_digest != entrypoint_digest
    ):
        raise ControllerActivationAssetsError(
            "signed envelope is not bound to exact candidate assets"
        )
    members = _artifact_members(
        artifact_manifest,
        expected_manifest_digest=artifact.manifest_digest,
        require_root_owner=require_root_owner,
    )
    raw_envelope = _safe_regular_bytes(
        signed_envelope,
        label="signed activation envelope",
        require_root_owner=require_root_owner,
    )
    try:
        envelope_document = json.loads(raw_envelope.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ControllerActivationAssetsError("signed activation envelope is invalid") from exc
    if not isinstance(envelope_document, dict):
        raise ControllerActivationAssetsError("signed activation envelope is invalid")
    envelope_bytes = _canonical(envelope_document) + b"\n"
    if hashlib.sha256(_canonical(envelope_document)).hexdigest() != envelope.digest:
        raise ControllerActivationAssetsError("signed activation envelope digest is invalid")
    artifacts = _ensure_directory(
        assets_root / "artifacts",
        label="activation artifact spool",
        require_root_owner=require_root_owner,
    )
    envelopes = _ensure_directory(
        assets_root / "envelopes",
        label="activation envelope spool",
        require_root_owner=require_root_owner,
    )
    # Every verified artifact keeps the producer's original member names, so
    # they must live below a manifest-addressed directory.  Flattening these
    # files into the shared spool made a second valid release collide with the
    # active release's ``controller-image.tar`` and scan reports.  The bundle
    # directory is both immutable and the manifest's required sibling root.
    bundle = _ensure_directory(
        artifacts / artifact.manifest_digest,
        label="activation artifact bundle",
        require_root_owner=require_root_owner,
    )
    for name, payload in sorted(members.items()):
        target = bundle / ("manifest.json" if name.startswith("manifest:") else name)
        _publish_bytes(
            target,
            payload,
            label=f"activation artifact {target.name}",
            require_root_owner=require_root_owner,
            allow_existing_same=True,
        )
    _fsync_directory(bundle)
    _fsync_directory(artifacts)
    envelope_path = envelopes / f"{envelope.digest}.json"
    published = _publish_bytes(
        envelope_path,
        envelope_bytes,
        label="activation envelope",
        require_root_owner=require_root_owner,
        allow_existing_same=True,
    )
    _fsync_directory(envelopes)
    return {
        "status": "staged" if published else "already_staged",
        "transaction_id": envelope.transaction_id,
        "activation_envelope": str(envelope_path),
        "activation_envelope_digest": "sha256:" + envelope.digest,
        "artifact_manifest": str(bundle / "manifest.json"),
        "artifact_manifest_digest": "sha256:" + artifact.manifest_digest,
        "source_sha": source_sha,
        "controller_release_digest": "sha256:" + release_digest,
        "controller_image_digest": "sha256:" + artifact.image_digest,
        "controller_internal_image_digest": "sha256:" + artifact.image_digest,
        "controller_policy_bundle_digest": "sha256:" + artifact.policy_bundle_digest,
        "workflow_run_id": artifact.workflow_identity["run_id"],
        "workflow_job_id": artifact.workflow_identity["job_id"],
        "workflow_attempt": artifact.workflow_identity["attempt"],
    }


def _sha256_hex(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _replace_root_owned_bytes(
    path: Path, payload: bytes, *, label: str, require_root_owner: bool
) -> None:
    """Atomically replace one fixed root executable after its bytes are bound.

    The caller holds the lifecycle lock.  This intentionally has no caller-selected
    destination: it is used only to repair the installed activation adapter before
    the normal signed activation path can update itself.
    """

    parent = _safe_directory(
        path.parent, label=f"{label} directory", require_root_owner=require_root_owner
    )
    temporary = parent / f".{path.name}.{os.getpid()}.{os.urandom(8).hex()}.tmp"
    descriptor = -1
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            0o700,
        )
        os.fchmod(descriptor, 0o700)
        if require_root_owner:
            os.fchown(descriptor, 0, 0)
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            view = view[written:]
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, path)
        _fsync_directory(parent)
    except OSError as exc:
        raise ControllerActivationAssetsError(f"{label} cannot be replaced") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
        except OSError as exc:
            raise ControllerActivationAssetsError(f"{label} temporary cleanup failed") from exc


def repair_installed_activation_adapter(
    *,
    release_root: Path,
    source_sha: str,
    artifact_manifest: Path,
    transaction_id: str,
    installed_adapter: Path,
    expected_installed_sha256: str,
    expected_candidate_sha256: str,
    repairs_root: Path,
    now: datetime | None = None,
    require_root_owner: bool = True,
    lifecycle_lock_path: Path = ACTIVATION_LIFECYCLE_LOCK,
) -> dict[str, object]:
    """Repair the fixed adapter from a reconciled controller release.

    This is a narrowly-scoped bootstrap bridge.  It verifies the same hosted
    recovery artifact inputs as activation, accepts only a clean exact release,
    backs up the measured installed adapter by digest, and atomically replaces
    that one fixed executable.  It never activates a release or touches queue,
    service, or policy state.
    """

    if not _SHA.fullmatch(source_sha):
        raise ControllerActivationAssetsError("candidate source SHA is invalid")
    if not _IDENTIFIER.fullmatch(transaction_id):
        raise ControllerActivationAssetsError("adapter repair transaction ID is invalid")
    if not _HEX_DIGEST.fullmatch(expected_installed_sha256):
        raise ControllerActivationAssetsError("expected installed adapter digest is invalid")
    if not _HEX_DIGEST.fullmatch(expected_candidate_sha256):
        raise ControllerActivationAssetsError("expected candidate adapter digest is invalid")
    release = _safe_directory(
        release_root, label="controller repair release", require_root_owner=require_root_owner
    )
    if release.name != source_sha:
        raise ControllerActivationAssetsError("repair release is not bound to its source SHA")
    candidate_adapter = release / "scripts" / "qdev_controller_activation_adapter.py"
    _safe_directory(
        candidate_adapter.parent,
        label="candidate activation adapter directory",
        require_root_owner=require_root_owner,
    )
    candidate_bytes = _safe_regular_bytes(
        candidate_adapter,
        label="candidate activation adapter",
        require_root_owner=require_root_owner,
    )
    if _sha256_hex(candidate_bytes) != expected_candidate_sha256:
        raise ControllerActivationAssetsError("candidate activation adapter digest does not match")
    try:
        artifact = verify_controller_artifact_manifest(
            artifact_manifest,
            require_root_owner=require_root_owner,
            now=(now or datetime.now(UTC)).astimezone(UTC),
        )
        policy_digest = candidate_config_digest(release)
        entrypoint_digest = fingerprint_release_tree(release, require_root_owner=require_root_owner)
    except (ControllerActivationError, ControllerRecoveryArtifactError) as exc:
        raise ControllerActivationAssetsError(str(exc)) from exc
    if (
        artifact.source_sha != source_sha
        or artifact.policy_bundle_digest != policy_digest
        or artifact.entrypoint_reconciliation_digest != entrypoint_digest
    ):
        raise ControllerActivationAssetsError("recovery artifact does not bind candidate adapter")

    observed_at = _format_time(now or datetime.now(UTC))
    with activation_lifecycle_lock(lifecycle_lock_path, require_root_owner=require_root_owner):
        installed_bytes = _safe_regular_bytes(
            installed_adapter,
            label="installed activation adapter",
            require_root_owner=require_root_owner,
        )
        installed_digest = _sha256_hex(installed_bytes)
        if installed_digest != expected_installed_sha256:
            if installed_digest == expected_candidate_sha256:
                raise ControllerActivationAssetsError(
                    "activation adapter is already repaired; reconcile its existing receipt"
                )
            raise ControllerActivationAssetsError("installed activation adapter digest changed")
        root = _ensure_directory(
            repairs_root,
            label="activation adapter repair root",
            require_root_owner=require_root_owner,
        )
        backups = _ensure_directory(
            root / "backups",
            label="activation adapter repair backups",
            require_root_owner=require_root_owner,
        )
        receipts = _ensure_directory(
            root / "receipts",
            label="activation adapter repair receipts",
            require_root_owner=require_root_owner,
        )
        _publish_bytes(
            backups / f"{installed_digest}.py",
            installed_bytes,
            label="activation adapter rollback backup",
            require_root_owner=require_root_owner,
            allow_existing_same=True,
        )
        _replace_root_owned_bytes(
            installed_adapter,
            candidate_bytes,
            label="installed activation adapter",
            require_root_owner=require_root_owner,
        )
        verified = _safe_regular_bytes(
            installed_adapter,
            label="installed activation adapter",
            require_root_owner=require_root_owner,
        )
        if _sha256_hex(verified) != expected_candidate_sha256:
            raise ControllerActivationAssetsError(
                "installed activation adapter digest is not durable"
            )
        receipt: dict[str, object] = {
            "schema": "qdev-controller-activation-adapter-repair-v1",
            "status": "completed",
            "transaction_id": transaction_id,
            "source_sha": source_sha,
            "artifact_manifest_digest": artifact.manifest_digest,
            "policy_bundle_digest": policy_digest,
            "entrypoint_reconciliation_digest": entrypoint_digest,
            "installed_adapter": str(installed_adapter),
            "rollback_adapter_sha256": installed_digest,
            "candidate_adapter_sha256": expected_candidate_sha256,
            "observed_at": observed_at,
        }
        _publish_bytes(
            receipts / f"{transaction_id}.json",
            _canonical(receipt) + b"\n",
            label="activation adapter repair receipt",
            require_root_owner=require_root_owner,
            allow_existing_same=True,
        )
    return receipt
