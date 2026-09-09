"""Fail-closed state machine for controller release activation.

The shell activation entrypoint owns the host-wide lifecycle lock and the
physical compose/configuration transaction.  This module owns the durable
identity transaction: it verifies a signed, short-lived envelope and performs
compare-and-swap checks immediately before a flip, commit, or rollback.
"""

from __future__ import annotations

import base64
import fcntl
import hashlib
import json
import os
import re
import stat
import tempfile
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

STATUS_SCHEMA = "qdev-controller-activation-status-v2"
LEGACY_ACTIVATION_STATUS_SCHEMA = "qdev-controller-activation-status-v1"
MEASURED_STATUS_SCHEMA = "qdev-controller-release-status-v2"
LEGACY_STATUS_SCHEMA = "qdev-controller-release-status-v1"
ENVELOPE_SCHEMA = "qdev-controller-activation-envelope-v1"
TRANSACTION_SCHEMA = "qdev-controller-activation-transaction-v1"
ARTIFACT_MANIFEST_SCHEMA = "qdev-controller-activation-artifact-v1"
ARTIFACT_PROVENANCE_SCHEMA = "qdev-controller-artifact-provenance-v1"
ENTRYPOINT_RECONCILIATION_SCHEMA = "qdev-controller-entrypoint-reconciliation-v1"
CONTROLLER_REPOSITORY = "belilovsky/qdev-runner-control-plane"
MAX_ENVELOPE_TTL = timedelta(minutes=30)
MAX_CLOCK_SKEW = timedelta(seconds=60)

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_TRANSACTION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")

_PROCESS_LOCKS_GUARD = threading.Lock()
_PROCESS_LOCKS: dict[str, threading.RLock] = {}

ActivationReservationState = Literal[
    "new",
    "pending-before-mutation",
    "pending-mutating",
    "pending-config-transition",
    "pending-config-installed",
    "pending-candidate-active",
    "committed",
    "finalized",
    "rolled-back",
]


class ControllerActivationError(ValueError):
    """Raised when an activation cannot safely advance."""


@dataclass(frozen=True)
class VerifiedControllerArtifact:
    """Exact prebuilt controller artifact bound by the signed envelope."""

    manifest_digest: str
    source_sha: str
    image_digest: str
    policy_bundle_digest: str
    entrypoint_reconciliation_digest: str
    image_archive: Path
    image_archive_digest: str
    image_unpacked_size: int
    sbom_digest: str
    source_scan_digest: str
    image_scan_digest: str
    claim_receipt: Path | None
    claim_receipt_digest: str | None
    workflow_identity: dict[str, object]
    provenance_digest: str


def _canonical(value: Mapping[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def _parse_time(value: object, field: str) -> datetime:
    if not isinstance(value, str):
        raise ControllerActivationError(f"activation envelope {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ControllerActivationError(f"activation envelope {field} is invalid") from error
    if parsed.tzinfo is None:
        raise ControllerActivationError(f"activation envelope {field} is invalid")
    return parsed.astimezone(UTC)


def _format_time(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _require_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ControllerActivationError(f"controller {field} is invalid")
    return value


def _require_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or _DIGEST.fullmatch(value) is None:
        raise ControllerActivationError(f"controller {field} digest is invalid")
    return value


@dataclass(frozen=True)
class ControllerTuple:
    source_sha: str
    image_digest: str
    policy_bundle_digest: str
    internal_image_digest: str | None = None

    def __post_init__(self) -> None:
        if self.internal_image_digest is None:
            object.__setattr__(self, "internal_image_digest", self.image_digest)

    @property
    def public_image_digest(self) -> str:
        return self.image_digest

    @property
    def effective_internal_image_digest(self) -> str:
        return self.internal_image_digest or self.image_digest

    @classmethod
    def parse(cls, value: object, *, field: str) -> ControllerTuple:
        if not isinstance(value, dict):
            raise ControllerActivationError(f"controller {field} tuple is invalid")
        legacy_fields = {"source_sha", "image_digest", "policy_bundle_digest"}
        current_fields = {
            "source_sha",
            "public_image_digest",
            "internal_image_digest",
            "policy_bundle_digest",
        }
        if set(value) == legacy_fields:
            public_image_digest = value["image_digest"]
            internal_image_digest = public_image_digest
        elif set(value) == current_fields:
            public_image_digest = value["public_image_digest"]
            internal_image_digest = value["internal_image_digest"]
        else:
            raise ControllerActivationError(f"controller {field} tuple is invalid")
        source_sha = value["source_sha"]
        policy_bundle_digest = value["policy_bundle_digest"]
        if not isinstance(source_sha, str) or _SHA.fullmatch(source_sha) is None:
            raise ControllerActivationError(f"controller {field} source SHA is invalid")
        if (
            not isinstance(public_image_digest, str)
            or _DIGEST.fullmatch(public_image_digest) is None
            or not isinstance(internal_image_digest, str)
            or _DIGEST.fullmatch(internal_image_digest) is None
        ):
            raise ControllerActivationError(f"controller {field} image digests are invalid")
        if (
            not isinstance(policy_bundle_digest, str)
            or _DIGEST.fullmatch(policy_bundle_digest) is None
        ):
            raise ControllerActivationError(f"controller {field} policy bundle digest is invalid")
        return cls(
            source_sha,
            public_image_digest,
            policy_bundle_digest,
            internal_image_digest,
        )

    def mapping(self) -> dict[str, str]:
        return {
            "source_sha": self.source_sha,
            "public_image_digest": self.public_image_digest,
            "internal_image_digest": self.effective_internal_image_digest,
            "policy_bundle_digest": self.policy_bundle_digest,
        }

    def matches_images(self, public_digest: str, internal_digest: str | None = None) -> bool:
        observed_internal = internal_digest or public_digest
        return (
            public_digest == self.public_image_digest
            and observed_internal == self.effective_internal_image_digest
        )


@dataclass(frozen=True)
class ActivationEnvelope:
    transaction_id: str
    issued_at: datetime
    expires_at: datetime
    expected_generation: int
    expected_current: ControllerTuple
    expected_current_status_digest: str
    expected_current_config_digest: str
    candidate: ControllerTuple
    candidate_release_digest: str
    candidate_config_digest: str
    artifact_manifest_digest: str
    entrypoint_reconciliation_digest: str
    signature: str
    digest: str

    @classmethod
    def verify(
        cls,
        document: object,
        *,
        public_key: Ed25519PublicKey,
        now: datetime | None = None,
        allow_expired_for_rollback: bool = False,
    ) -> ActivationEnvelope:
        if not isinstance(document, dict) or set(document) != {
            "schema",
            "transaction_id",
            "issued_at",
            "expires_at",
            "expected_generation",
            "expected_current",
            "expected_current_status_digest",
            "expected_current_config_digest",
            "candidate",
            "candidate_release_digest",
            "candidate_config_digest",
            "artifact_manifest_digest",
            "entrypoint_reconciliation_digest",
            "signature",
        }:
            raise ControllerActivationError("activation envelope shape is invalid")
        if document["schema"] != ENVELOPE_SCHEMA:
            raise ControllerActivationError("activation envelope schema is invalid")
        transaction_id = document["transaction_id"]
        signature = document["signature"]
        if not isinstance(transaction_id, str) or _TRANSACTION_ID.fullmatch(transaction_id) is None:
            raise ControllerActivationError("activation transaction ID is invalid")
        if not isinstance(signature, str) or _SIGNATURE.fullmatch(signature) is None:
            raise ControllerActivationError("activation envelope signature is invalid")
        unsigned = dict(document)
        del unsigned["signature"]
        try:
            signature_bytes = base64.urlsafe_b64decode(f"{signature}==")
            public_key.verify(signature_bytes, _canonical(unsigned))
        except (InvalidSignature, ValueError) as error:
            raise ControllerActivationError("activation envelope signature is invalid") from error
        canonical_signature = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")
        if len(signature_bytes) != 64 or canonical_signature != signature:
            raise ControllerActivationError("activation envelope signature is invalid")

        issued_at = _parse_time(document["issued_at"], "issued_at")
        expires_at = _parse_time(document["expires_at"], "expires_at")
        observed_at = (now or datetime.now(UTC)).astimezone(UTC)
        if issued_at > observed_at + MAX_CLOCK_SKEW:
            raise ControllerActivationError("activation envelope is not yet valid")
        if expires_at <= observed_at and not allow_expired_for_rollback:
            raise ControllerActivationError("activation envelope has expired")
        if expires_at <= issued_at or expires_at - issued_at > MAX_ENVELOPE_TTL:
            raise ControllerActivationError("activation envelope TTL is invalid")

        expected_generation = _require_int(document["expected_generation"], "expected generation")
        expected_current = ControllerTuple.parse(
            document["expected_current"], field="expected current"
        )
        expected_current_status_digest = _require_digest(
            document["expected_current_status_digest"], "expected current status"
        )
        expected_current_config_digest = _require_digest(
            document["expected_current_config_digest"], "expected current config"
        )
        candidate = ControllerTuple.parse(document["candidate"], field="candidate")
        candidate_release_digest = _require_digest(
            document["candidate_release_digest"], "candidate release"
        )
        candidate_config_digest = _require_digest(
            document["candidate_config_digest"], "candidate config"
        )
        artifact_manifest_digest = _require_digest(
            document["artifact_manifest_digest"], "artifact manifest"
        )
        entrypoint_reconciliation_digest = _require_digest(
            document["entrypoint_reconciliation_digest"],
            "entrypoint reconciliation",
        )
        if candidate == expected_current:
            raise ControllerActivationError("activation candidate must change the current tuple")
        return cls(
            transaction_id=transaction_id,
            issued_at=issued_at,
            expires_at=expires_at,
            expected_generation=expected_generation,
            expected_current=expected_current,
            expected_current_status_digest=expected_current_status_digest,
            expected_current_config_digest=expected_current_config_digest,
            candidate=candidate,
            candidate_release_digest=candidate_release_digest,
            candidate_config_digest=candidate_config_digest,
            artifact_manifest_digest=artifact_manifest_digest,
            entrypoint_reconciliation_digest=entrypoint_reconciliation_digest,
            signature=signature,
            digest=hashlib.sha256(_canonical(document)).hexdigest(),
        )


@dataclass(frozen=True)
class ControllerReleaseStatus:
    generation: int
    current: ControllerTuple
    previous: tuple[int, ControllerTuple] | None
    transaction_id: str
    activated_at: datetime

    @classmethod
    def parse(cls, value: object) -> ControllerReleaseStatus:
        legacy_required = {
            "schema",
            "state",
            "generation",
            "source_sha",
            "image_digest",
            "policy_bundle_digest",
            "previous",
            "transaction_id",
            "activated_at",
        }
        current_required = (legacy_required - {"image_digest"}) | {
            "public_image_digest",
            "internal_image_digest",
        }
        if not isinstance(value, dict) or set(value) not in {
            frozenset(legacy_required),
            frozenset(current_required),
        }:
            raise ControllerActivationError("controller release status shape is invalid")
        is_legacy = set(value) == legacy_required
        expected_schema = LEGACY_ACTIVATION_STATUS_SCHEMA if is_legacy else STATUS_SCHEMA
        if value["schema"] != expected_schema or value["state"] != "active":
            raise ControllerActivationError("controller activation status is not active")
        generation = _require_int(value["generation"], "release generation")
        current_value = {
            "source_sha": value["source_sha"],
            "policy_bundle_digest": value["policy_bundle_digest"],
        }
        if is_legacy:
            current_value["image_digest"] = value["image_digest"]
        else:
            current_value["public_image_digest"] = value["public_image_digest"]
            current_value["internal_image_digest"] = value["internal_image_digest"]
        current = ControllerTuple.parse(current_value, field="release status")
        transaction_id = value["transaction_id"]
        if not isinstance(transaction_id, str) or _TRANSACTION_ID.fullmatch(transaction_id) is None:
            raise ControllerActivationError("controller status transaction ID is invalid")
        activated_at = _parse_time(value["activated_at"], "activated_at")

        previous_raw = value["previous"]
        previous: tuple[int, ControllerTuple] | None = None
        if previous_raw is not None:
            legacy_previous_fields = {
                "generation",
                "source_sha",
                "image_digest",
                "policy_bundle_digest",
            }
            current_previous_fields = (legacy_previous_fields - {"image_digest"}) | {
                "public_image_digest",
                "internal_image_digest",
            }
            if not isinstance(previous_raw, dict) or set(previous_raw) not in {
                frozenset(legacy_previous_fields),
                frozenset(current_previous_fields),
            }:
                raise ControllerActivationError("controller previous tuple is invalid")
            previous_generation = _require_int(previous_raw["generation"], "previous generation")
            if previous_generation >= generation:
                raise ControllerActivationError("controller previous generation is invalid")
            previous = (
                previous_generation,
                ControllerTuple.parse(
                    {key: value for key, value in previous_raw.items() if key != "generation"},
                    field="previous",
                ),
            )
        return cls(generation, current, previous, transaction_id, activated_at)

    def mapping(self) -> dict[str, Any]:
        previous: dict[str, Any] | None = None
        if self.previous is not None:
            previous_generation, previous_tuple = self.previous
            previous = {"generation": previous_generation, **previous_tuple.mapping()}
        return {
            "schema": STATUS_SCHEMA,
            "state": "active",
            "generation": self.generation,
            **self.current.mapping(),
            "previous": previous,
            "transaction_id": self.transaction_id,
            "activated_at": _format_time(self.activated_at),
        }


@dataclass(frozen=True)
class MeasuredControllerReleaseStatus:
    """Runtime identity emitted by the mature controller release payload.

    ``release_digest`` identifies the activated source tree.  It is deliberately
    independent from the policy bundle digest carried by the signed activation
    envelope and durable activation state.
    """

    revision: str
    release_digest: str
    activated_at: datetime
    source_digest: str
    public_image_digest: str
    internal_image_digest: str
    requirements_digest: str
    public_installed_digest: str
    internal_installed_digest: str

    @classmethod
    def parse(cls, value: object) -> MeasuredControllerReleaseStatus:
        required = {
            "schema",
            "state",
            "revision",
            "release_digest",
            "activated_at",
            "runtime_identity",
            "dependency_identity",
        }
        if not isinstance(value, dict) or set(value) != required:
            raise ControllerActivationError("measured controller status shape is invalid")
        if value["schema"] != MEASURED_STATUS_SCHEMA or value["state"] != "active":
            raise ControllerActivationError("measured controller status is not active v2")
        revision = value["revision"]
        if not isinstance(revision, str) or _SHA.fullmatch(revision) is None:
            raise ControllerActivationError("measured controller revision is invalid")
        release_digest = _require_prefixed_digest(
            value["release_digest"], "measured controller release"
        )
        activated_at = _parse_time(value["activated_at"], "activated_at")
        runtime = value["runtime_identity"]
        dependencies = value["dependency_identity"]
        if not isinstance(runtime, dict) or set(runtime) != {
            "source_revision",
            "source_digest",
            "public_image_id",
            "internal_image_id",
        }:
            raise ControllerActivationError("measured controller runtime identity is invalid")
        if runtime["source_revision"] != revision:
            raise ControllerActivationError("measured controller source revision is inconsistent")
        source_digest = _require_prefixed_digest(
            runtime["source_digest"], "measured controller source"
        )
        public_image = _require_prefixed_digest(
            runtime["public_image_id"], "measured public controller image"
        )
        internal_image = _require_prefixed_digest(
            runtime["internal_image_id"], "measured internal controller image"
        )
        if not isinstance(dependencies, dict) or set(dependencies) != {
            "requirements_digest",
            "public_installed_digest",
            "internal_installed_digest",
        }:
            raise ControllerActivationError("measured controller dependency identity is invalid")
        requirements = _require_prefixed_digest(
            dependencies["requirements_digest"], "measured controller requirements"
        )
        public_installed = _require_prefixed_digest(
            dependencies["public_installed_digest"], "measured public dependencies"
        )
        internal_installed = _require_prefixed_digest(
            dependencies["internal_installed_digest"], "measured internal dependencies"
        )
        if public_installed != internal_installed:
            raise ControllerActivationError("measured controller dependencies disagree")
        return cls(
            revision=revision,
            release_digest=release_digest,
            activated_at=activated_at,
            source_digest=source_digest,
            public_image_digest=public_image,
            internal_image_digest=internal_image,
            requirements_digest=requirements,
            public_installed_digest=public_installed,
            internal_installed_digest=internal_installed,
        )


@dataclass(frozen=True)
class LegacyMeasuredControllerReleaseStatus:
    """Runtime identity emitted by an immutable historical controller payload."""

    revision: str
    release_digest: str
    activated_at: datetime

    @classmethod
    def parse(cls, value: object) -> LegacyMeasuredControllerReleaseStatus:
        required = {"schema", "state", "revision", "release_digest", "activated_at"}
        if not isinstance(value, dict) or set(value) != required:
            raise ControllerActivationError("legacy measured controller status shape is invalid")
        if value["schema"] != LEGACY_STATUS_SCHEMA or value["state"] != "active":
            raise ControllerActivationError("legacy measured controller status is not active v1")
        revision = value["revision"]
        if not isinstance(revision, str) or _SHA.fullmatch(revision) is None:
            raise ControllerActivationError("legacy measured controller revision is invalid")
        release_value = value["release_digest"]
        if isinstance(release_value, str) and release_value.startswith("sha256:"):
            release_digest = _require_prefixed_digest(
                release_value, "legacy measured controller release"
            )
        else:
            release_digest = _require_digest(release_value, "legacy measured controller release")
        activated_at = _parse_time(value["activated_at"], "activated_at")
        return cls(revision, release_digest, activated_at)


def _require_prefixed_digest(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        raise ControllerActivationError(f"{field} digest is invalid")
    return _require_digest(value.removeprefix("sha256:"), field)


class ActivationStateStore:
    """Atomic controller release status and pending-transaction store."""

    def __init__(self, status_path: Path) -> None:
        self.status_path = status_path
        self.lock_path = status_path.with_suffix(f"{status_path.suffix}.lock")
        self.transaction_path = status_path.with_suffix(f"{status_path.suffix}.transaction")
        lock_key = os.path.abspath(self.lock_path)
        with _PROCESS_LOCKS_GUARD:
            self._process_lock = _PROCESS_LOCKS.setdefault(lock_key, threading.RLock())

    @contextmanager
    def _locked(self) -> Iterator[None]:
        # flock()/lockf() ownership is process-scoped on supported Unix hosts,
        # so threads in one process need an additional keyed mutex.  The file
        # lock remains the cross-process authority.
        with self._process_lock:
            self.status_path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(
                self.lock_path,
                os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
                0o600,
            )
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_mode & 0o022
                ):
                    raise ControllerActivationError("controller activation lock is unsafe")
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

    @staticmethod
    def _read_bytes(path: Path) -> bytes:
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
            try:
                metadata = os.fstat(descriptor)
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_uid != os.geteuid()
                    or metadata.st_mode & 0o022
                ):
                    raise ControllerActivationError(f"controller state is unsafe: {path.name}")
                with os.fdopen(descriptor, "rb") as handle:
                    descriptor = -1
                    return handle.read()
            finally:
                if descriptor >= 0:
                    os.close(descriptor)
        except OSError as error:
            raise ControllerActivationError(
                f"controller state is unavailable: {path.name}"
            ) from error

    @classmethod
    def _read_json_with_digest(cls, path: Path) -> tuple[object, str]:
        raw = cls._read_bytes(path)
        try:
            value = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ControllerActivationError(
                f"controller state is unavailable: {path.name}"
            ) from error
        return value, hashlib.sha256(raw).hexdigest()

    @classmethod
    def _read_json(cls, path: Path) -> object:
        return cls._read_json_with_digest(path)[0]

    @staticmethod
    def _atomic_write(path: Path, value: Mapping[str, Any], *, mode: int) -> None:
        descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, mode)
            with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                json.dump(value, handle, sort_keys=True, separators=(",", ":"))
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, path)
            directory_fd = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            with suppress(FileNotFoundError):
                temporary.unlink()

    @staticmethod
    def _atomic_unlink(path: Path) -> None:
        """Durably remove an exact regular state file without following links."""

        try:
            metadata = path.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise ControllerActivationError(
                f"controller state is unavailable: {path.name}"
            ) from error
        if (
            not stat.S_ISREG(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o022
        ):
            raise ControllerActivationError(f"controller state is unsafe: {path.name}")
        try:
            path.unlink()
            directory_fd = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except OSError as error:
            raise ControllerActivationError(
                f"controller state could not be removed: {path.name}"
            ) from error

    def read_status(self) -> ControllerReleaseStatus:
        with self._locked():
            return ControllerReleaseStatus.parse(self._read_json(self.status_path))

    def recovery_state(
        self,
        envelope: ActivationEnvelope,
        *,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
        allow_config_transition: bool = False,
    ) -> ActivationReservationState:
        """Classify an existing exact transaction without reserving or evicting it."""

        with self._locked():
            raw_status, status_digest = self._read_json_with_digest(self.status_path)
            status = ControllerReleaseStatus.parse(raw_status)
            transaction = self._assert_transaction(envelope)
            observed = (
                observed_image_digest,
                observed_internal_image_digest or observed_image_digest,
                observed_config_digest,
            )
            if (
                status.generation == envelope.expected_generation + 2
                and status.current == envelope.expected_current
                and status.previous == (envelope.expected_generation + 1, envelope.candidate)
                and status.transaction_id == f"rollback:{envelope.transaction_id}"
            ):
                if observed != (
                    envelope.expected_current.public_image_digest,
                    envelope.expected_current.effective_internal_image_digest,
                    envelope.expected_current_config_digest,
                ):
                    raise ControllerActivationError(
                        "controller recovery runtime does not match rolled-back transaction"
                    )
                return "rolled-back"
            if (
                status.generation == envelope.expected_generation + 1
                and status.current == envelope.candidate
                and status.previous == (envelope.expected_generation, envelope.expected_current)
                and status.transaction_id == envelope.transaction_id
            ):
                committed_digest = transaction["committed_status_digest"]
                if committed_digest is None:
                    raise ControllerActivationError(
                        "controller recovery committed status fingerprint is unavailable"
                    )
                self._assert_status_digest(status_digest, committed_digest)
                if observed == (
                    envelope.candidate.public_image_digest,
                    envelope.candidate.effective_internal_image_digest,
                    envelope.candidate_config_digest,
                ):
                    return "committed"
                trusted_images = observed[0] in {
                    envelope.expected_current.public_image_digest,
                    envelope.candidate.public_image_digest,
                } and observed[1] in {
                    envelope.expected_current.effective_internal_image_digest,
                    envelope.candidate.effective_internal_image_digest,
                }
                if allow_config_transition and trusted_images:
                    return "pending-mutating"
                raise ControllerActivationError(
                    "controller recovery runtime does not match committed transaction"
                )
            self._assert_expected(status, envelope)
            self._assert_status_digest(status_digest, transaction["reserved_status_digest"])
            states: dict[tuple[str, str, str], ActivationReservationState] = {
                (
                    envelope.expected_current.public_image_digest,
                    envelope.expected_current.effective_internal_image_digest,
                    envelope.expected_current_config_digest,
                ): "pending-before-mutation",
                (
                    envelope.expected_current.public_image_digest,
                    envelope.expected_current.effective_internal_image_digest,
                    envelope.candidate_config_digest,
                ): "pending-config-installed",
                (
                    envelope.candidate.public_image_digest,
                    envelope.candidate.effective_internal_image_digest,
                    envelope.candidate_config_digest,
                ): "pending-candidate-active",
            }
            state = states.get(observed)
            trusted_images = observed[0] in {
                envelope.expected_current.public_image_digest,
                envelope.candidate.public_image_digest,
            } and observed[1] in {
                envelope.expected_current.effective_internal_image_digest,
                envelope.candidate.effective_internal_image_digest,
            }
            if state is None and allow_config_transition and trusted_images:
                # The trusted host payload validates every live configuration
                # file against either its durable pre-activation snapshot or
                # the exact source-bound candidate before authorizing physical
                # rollback. This state only bridges recovery classification
                # across a SIGKILL between atomic per-file installs.
                state = "pending-mutating"
            if state is None:
                raise ControllerActivationError(
                    "controller recovery runtime is foreign to exact transaction"
                )
            return state

    def bootstrap_from_measured(
        self,
        envelope: ActivationEnvelope,
        *,
        measured_status_path: Path,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
    ) -> ControllerReleaseStatus:
        """Create generation zero from exact signed mature-runtime evidence once."""

        with self._locked():
            if self.status_path.exists() or self.status_path.is_symlink():
                raise ControllerActivationError("controller activation status already exists")
            if self.transaction_path.exists() or self.transaction_path.is_symlink():
                raise ControllerActivationError(
                    "measured controller status cannot bootstrap with a transaction"
                )
            if envelope.expected_generation != 0:
                raise ControllerActivationError(
                    "measured controller status may bootstrap only generation zero"
                )
            _require_digest(observed_image_digest, "observed image")
            if observed_internal_image_digest is not None:
                _require_digest(observed_internal_image_digest, "observed internal image")
            _require_digest(observed_config_digest, "observed config")
            raw, _measured_digest = self._read_json_with_digest(measured_status_path)
            measured = MeasuredControllerReleaseStatus.parse(raw)
            if measured.revision != envelope.expected_current.source_sha:
                raise ControllerActivationError(
                    "measured controller revision does not match signed current tuple"
                )
            if not envelope.expected_current.matches_images(
                measured.public_image_digest,
                measured.internal_image_digest,
            ):
                raise ControllerActivationError(
                    "measured controller images do not match signed current tuple"
                )
            if (
                observed_image_digest != measured.public_image_digest
                or (observed_internal_image_digest or observed_image_digest)
                != measured.internal_image_digest
            ):
                raise ControllerActivationError(
                    "running controller images do not match measured status"
                )
            if observed_config_digest != envelope.expected_current_config_digest:
                raise ControllerActivationError(
                    "running controller config does not match signed current config"
                )
            status = ControllerReleaseStatus(
                generation=0,
                current=envelope.expected_current,
                previous=None,
                transaction_id=f"bootstrap:{envelope.transaction_id}",
                activated_at=measured.activated_at,
            )
            status_digest = hashlib.sha256(_canonical(status.mapping()) + b"\n").hexdigest()
            self._assert_status_digest(
                status_digest,
                envelope.expected_current_status_digest,
            )
            self._atomic_write(self.status_path, status.mapping(), mode=0o644)
            return status

    @staticmethod
    def _assert_expected(
        status: ControllerReleaseStatus,
        envelope: ActivationEnvelope,
    ) -> None:
        if status.generation != envelope.expected_generation:
            raise ControllerActivationError("controller activation generation CAS failed")
        if status.current != envelope.expected_current:
            raise ControllerActivationError("controller activation current tuple CAS failed")

    @staticmethod
    def _transaction_mapping(
        envelope: ActivationEnvelope,
        *,
        reserved_status_digest: str,
        committed_status_digest: str | None = None,
        committed_activated_at: datetime | None = None,
    ) -> dict[str, Any]:
        if (committed_status_digest is None) != (committed_activated_at is None):
            raise ControllerActivationError(
                "controller committed transaction metadata is incomplete"
            )
        return {
            "schema": TRANSACTION_SCHEMA,
            "transaction_id": envelope.transaction_id,
            "envelope_digest": envelope.digest,
            "expected_generation": envelope.expected_generation,
            "expected_current": envelope.expected_current.mapping(),
            "expected_current_status_digest": envelope.expected_current_status_digest,
            "expected_current_config_digest": envelope.expected_current_config_digest,
            "candidate": envelope.candidate.mapping(),
            "candidate_release_digest": envelope.candidate_release_digest,
            "candidate_config_digest": envelope.candidate_config_digest,
            "artifact_manifest_digest": envelope.artifact_manifest_digest,
            "entrypoint_reconciliation_digest": (envelope.entrypoint_reconciliation_digest),
            "reserved_status_digest": reserved_status_digest,
            "committed_status_digest": committed_status_digest,
            "committed_activated_at": (
                None if committed_activated_at is None else _format_time(committed_activated_at)
            ),
            "expires_at": _format_time(envelope.expires_at),
        }

    @staticmethod
    def _transaction_fields() -> set[str]:
        return {
            "schema",
            "transaction_id",
            "envelope_digest",
            "expected_generation",
            "expected_current",
            "expected_current_status_digest",
            "expected_current_config_digest",
            "candidate",
            "candidate_release_digest",
            "candidate_config_digest",
            "artifact_manifest_digest",
            "entrypoint_reconciliation_digest",
            "reserved_status_digest",
            "committed_status_digest",
            "committed_activated_at",
            "expires_at",
        }

    def _assert_transaction(self, envelope: ActivationEnvelope) -> dict[str, Any]:
        raw = self._read_json(self.transaction_path)
        if not isinstance(raw, dict) or set(raw) != self._transaction_fields():
            raise ControllerActivationError("controller activation transaction ownership failed")
        reserved_status_digest = _require_digest(
            raw.get("reserved_status_digest"), "reserved status"
        )
        committed_status_digest_raw = raw.get("committed_status_digest")
        committed_status_digest = (
            None
            if committed_status_digest_raw is None
            else _require_digest(committed_status_digest_raw, "committed status")
        )
        committed_activated_at_raw = raw.get("committed_activated_at")
        committed_activated_at = (
            None
            if committed_activated_at_raw is None
            else _parse_time(committed_activated_at_raw, "committed_activated_at")
        )
        expected = self._transaction_mapping(
            envelope,
            reserved_status_digest=reserved_status_digest,
            committed_status_digest=committed_status_digest,
            committed_activated_at=committed_activated_at,
        )
        if raw != expected:
            raise ControllerActivationError("controller activation transaction ownership failed")
        return expected

    @staticmethod
    def _assert_status_digest(
        observed: str,
        expected: str,
    ) -> None:
        if observed != expected:
            raise ControllerActivationError("controller activation status fingerprint CAS failed")

    def _migrate_legacy(
        self,
        raw: object,
        envelope: ActivationEnvelope,
        *,
        observed_image_digest: str | None,
        observed_internal_image_digest: str | None,
        observed_status_digest: str,
    ) -> ControllerReleaseStatus:
        if (
            not isinstance(raw, dict)
            or set(raw) != {"schema", "state", "revision", "release_digest", "activated_at"}
            or raw.get("schema") != LEGACY_STATUS_SCHEMA
            or raw.get("state") != "active"
            or raw.get("revision") != envelope.expected_current.source_sha
            or (
                not isinstance(raw.get("release_digest"), str)
                or _DIGEST.fullmatch(raw["release_digest"]) is None
            )
            or not envelope.expected_current.matches_images(
                observed_image_digest or "",
                observed_internal_image_digest,
            )
            or observed_status_digest != envelope.expected_current_status_digest
            or envelope.expected_generation != 0
        ):
            raise ControllerActivationError("legacy controller status import is not exact")
        activated_at = _parse_time(raw.get("activated_at"), "activated_at")
        migrated = ControllerReleaseStatus(
            generation=0,
            current=envelope.expected_current,
            previous=None,
            transaction_id=f"legacy:{envelope.transaction_id}",
            activated_at=activated_at,
        )
        return migrated

    def reserve(
        self,
        envelope: ActivationEnvelope,
        *,
        allow_legacy_import: bool = False,
        legacy_status_path: Path | None = None,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
        allow_config_transition: bool = False,
        now: datetime | None = None,
    ) -> ActivationReservationState:
        """Reserve a transaction and report its exact durable/runtime state."""
        observed_at = (now or datetime.now(UTC)).astimezone(UTC)
        with self._locked():
            _require_digest(observed_image_digest, "observed image")
            if observed_internal_image_digest is not None:
                _require_digest(observed_internal_image_digest, "observed internal image")
            _require_digest(observed_config_digest, "observed config")
            migrated_legacy = False
            if self.status_path.exists() or self.status_path.is_symlink():
                raw_status, status_digest = self._read_json_with_digest(self.status_path)
                try:
                    status = ControllerReleaseStatus.parse(raw_status)
                except ControllerActivationError:
                    if not allow_legacy_import or legacy_status_path is not None:
                        raise
                    if self.transaction_path.exists():
                        raise ControllerActivationError(
                            "legacy controller status cannot be imported with a transaction"
                        ) from None
                    if observed_config_digest != envelope.expected_current_config_digest:
                        raise ControllerActivationError(
                            "running controller config does not match active status"
                        ) from None
                    status = self._migrate_legacy(
                        raw_status,
                        envelope,
                        observed_image_digest=observed_image_digest,
                        observed_internal_image_digest=observed_internal_image_digest,
                        observed_status_digest=status_digest,
                    )
                    migrated_legacy = True
            else:
                if not allow_legacy_import or legacy_status_path is None:
                    raise ControllerActivationError("controller status is unavailable")
                if self.transaction_path.exists():
                    raise ControllerActivationError(
                        "legacy controller status cannot be imported with a transaction"
                    )
                if observed_config_digest != envelope.expected_current_config_digest:
                    raise ControllerActivationError(
                        "running controller config does not match active status"
                    )
                raw_status, status_digest = self._read_json_with_digest(legacy_status_path)
                status = self._migrate_legacy(
                    raw_status,
                    envelope,
                    observed_image_digest=observed_image_digest,
                    observed_internal_image_digest=observed_internal_image_digest,
                    observed_status_digest=status_digest,
                )
                migrated_legacy = True

            if (
                status.generation == envelope.expected_generation + 2
                and status.current == envelope.expected_current
                and status.previous == (envelope.expected_generation + 1, envelope.candidate)
                and status.transaction_id == f"rollback:{envelope.transaction_id}"
            ):
                if (
                    not envelope.expected_current.matches_images(
                        observed_image_digest,
                        observed_internal_image_digest,
                    )
                    or observed_config_digest != envelope.expected_current_config_digest
                ):
                    raise ControllerActivationError(
                        "running controller runtime does not match rolled-back transaction"
                    )
                if self.transaction_path.exists():
                    self._assert_transaction(envelope)
                return "rolled-back"

            if (
                status.transaction_id == envelope.transaction_id
                and status.generation == envelope.expected_generation + 1
                and status.current == envelope.candidate
            ):
                if self.transaction_path.exists():
                    transaction = self._assert_transaction(envelope)
                    committed_status_digest = transaction["committed_status_digest"]
                    if committed_status_digest is None:
                        raise ControllerActivationError(
                            "controller committed replay fingerprint is unavailable"
                        )
                    self._assert_status_digest(status_digest, committed_status_digest)
                    observed = (
                        observed_image_digest,
                        observed_internal_image_digest or observed_image_digest,
                        observed_config_digest,
                    )
                    if observed == (
                        envelope.candidate.public_image_digest,
                        envelope.candidate.effective_internal_image_digest,
                        envelope.candidate_config_digest,
                    ):
                        return "committed"
                    trusted_images = observed[0] in {
                        envelope.expected_current.public_image_digest,
                        envelope.candidate.public_image_digest,
                    } and observed[1] in {
                        envelope.expected_current.effective_internal_image_digest,
                        envelope.candidate.effective_internal_image_digest,
                    }
                    if allow_config_transition and trusted_images:
                        return "pending-mutating"
                    raise ControllerActivationError(
                        "running controller runtime does not match committed transaction"
                    )
                if (
                    not envelope.candidate.matches_images(
                        observed_image_digest,
                        observed_internal_image_digest,
                    )
                    or observed_config_digest != envelope.candidate_config_digest
                ):
                    raise ControllerActivationError(
                        "running controller runtime does not match committed status"
                    )
                return "finalized"
            self._assert_expected(status, envelope)
            reserved_status_digest = status_digest
            if not migrated_legacy:
                self._assert_status_digest(
                    status_digest,
                    envelope.expected_current_status_digest,
                )

            if self.transaction_path.exists():
                raw_transaction = self._read_json(self.transaction_path)
                if (
                    isinstance(raw_transaction, dict)
                    and set(raw_transaction) == self._transaction_fields()
                ):
                    transaction_status_digest = raw_transaction.get("reserved_status_digest")
                    expected = self._transaction_mapping(
                        envelope,
                        reserved_status_digest=_require_digest(
                            transaction_status_digest, "reserved status"
                        ),
                        committed_status_digest=(
                            None
                            if raw_transaction.get("committed_status_digest") is None
                            else _require_digest(
                                raw_transaction.get("committed_status_digest"),
                                "committed status",
                            )
                        ),
                        committed_activated_at=(
                            None
                            if raw_transaction.get("committed_activated_at") is None
                            else _parse_time(
                                raw_transaction.get("committed_activated_at"),
                                "committed_activated_at",
                            )
                        ),
                    )
                else:
                    expected = None
                if raw_transaction == expected:
                    if not isinstance(raw_transaction, dict):
                        raise ControllerActivationError(
                            "controller activation transaction is invalid"
                        )
                    replay_states: dict[tuple[str, str, str], ActivationReservationState] = {
                        (
                            status.current.public_image_digest,
                            status.current.effective_internal_image_digest,
                            envelope.expected_current_config_digest,
                        ): "pending-before-mutation",
                        (
                            status.current.public_image_digest,
                            status.current.effective_internal_image_digest,
                            envelope.candidate_config_digest,
                        ): "pending-config-installed",
                        (
                            envelope.candidate.public_image_digest,
                            envelope.candidate.effective_internal_image_digest,
                            envelope.candidate_config_digest,
                        ): "pending-candidate-active",
                    }
                    replay_state = replay_states.get(
                        (
                            observed_image_digest,
                            observed_internal_image_digest or observed_image_digest,
                            observed_config_digest,
                        )
                    )
                    if replay_state is None and allow_config_transition:
                        observed_public = observed_image_digest
                        observed_internal = observed_internal_image_digest or observed_image_digest
                        trusted_images = observed_public in {
                            envelope.expected_current.public_image_digest,
                            envelope.candidate.public_image_digest,
                        } and observed_internal in {
                            envelope.expected_current.effective_internal_image_digest,
                            envelope.candidate.effective_internal_image_digest,
                        }
                        if trusted_images:
                            replay_state = "pending-mutating"
                    if replay_state is None:
                        raise ControllerActivationError(
                            "running controller image/config does not match reserved transaction"
                        )
                    self._assert_status_digest(
                        status_digest,
                        _require_digest(
                            raw_transaction.get("reserved_status_digest"),
                            "reserved status",
                        ),
                    )
                    return replay_state
                if (
                    not isinstance(raw_transaction, dict)
                    or set(raw_transaction) != self._transaction_fields()
                ):
                    raise ControllerActivationError("controller activation transaction is invalid")
                if raw_transaction.get("schema") != TRANSACTION_SCHEMA:
                    raise ControllerActivationError("controller activation transaction is invalid")
                expires_at = _parse_time(raw_transaction.get("expires_at"), "expires_at")
                if expires_at > observed_at:
                    raise ControllerActivationError("another controller activation owns the lock")
                # Expired transactions may be evicted only while their expected
                # current tuple and generation are still active.
                stale_expected = ControllerTuple.parse(
                    raw_transaction.get("expected_current"), field="stale expected current"
                )
                stale_generation = _require_int(
                    raw_transaction.get("expected_generation"), "stale expected generation"
                )
                stale_status_digest = _require_digest(
                    raw_transaction.get("reserved_status_digest"), "stale reserved status"
                )
                stale_config_digest = _require_digest(
                    raw_transaction.get("expected_current_config_digest"),
                    "stale expected current config",
                )
                if status.current != stale_expected or status.generation != stale_generation:
                    raise ControllerActivationError(
                        "expired controller transaction cannot be safely evicted"
                    )
                self._assert_status_digest(status_digest, stale_status_digest)
                if not stale_expected.matches_images(
                    observed_image_digest,
                    observed_internal_image_digest,
                ):
                    raise ControllerActivationError(
                        "expired controller transaction cannot be safely evicted while "
                        "its expected image is not running"
                    )
                if observed_config_digest != stale_config_digest:
                    raise ControllerActivationError(
                        "expired controller transaction cannot be safely evicted while "
                        "its expected config is not active"
                    )
                self._atomic_unlink(self.transaction_path)

            if not status.current.matches_images(
                observed_image_digest,
                observed_internal_image_digest,
            ):
                raise ControllerActivationError(
                    "running controller images do not match active status"
                )
            if observed_config_digest != envelope.expected_current_config_digest:
                raise ControllerActivationError(
                    "running controller config does not match active status"
                )
            if migrated_legacy:
                self._atomic_write(self.status_path, status.mapping(), mode=0o644)
                _, reserved_status_digest = self._read_json_with_digest(self.status_path)

            self._atomic_write(
                self.transaction_path,
                self._transaction_mapping(
                    envelope,
                    reserved_status_digest=reserved_status_digest,
                ),
                mode=0o600,
            )
            return "new"

    def assert_current(
        self,
        envelope: ActivationEnvelope,
        *,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
        candidate_config: bool = False,
    ) -> None:
        with self._locked():
            raw_status, status_digest = self._read_json_with_digest(self.status_path)
            status = ControllerReleaseStatus.parse(raw_status)
            transaction = self._assert_transaction(envelope)
            self._assert_expected(status, envelope)
            self._assert_status_digest(status_digest, transaction["reserved_status_digest"])
            if not envelope.expected_current.matches_images(
                observed_image_digest,
                observed_internal_image_digest,
            ):
                raise ControllerActivationError("controller activation running images CAS failed")
            expected_config = (
                envelope.candidate_config_digest
                if candidate_config
                else envelope.expected_current_config_digest
            )
            if observed_config_digest != expected_config:
                raise ControllerActivationError(
                    "controller activation config fingerprint CAS failed"
                )

    def authorize_rollback(
        self,
        envelope: ActivationEnvelope,
        *,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
        rollback_config_digest: str,
        allow_config_transition: bool = False,
    ) -> None:
        """Authorize physical rollback only for the reserving transaction."""
        with self._locked():
            raw_status, status_digest = self._read_json_with_digest(self.status_path)
            status = ControllerReleaseStatus.parse(raw_status)
            transaction = self._assert_transaction(envelope)
            pending = (
                status.generation == envelope.expected_generation
                and status.current == envelope.expected_current
            )
            committed = (
                status.generation == envelope.expected_generation + 1
                and status.current == envelope.candidate
                and status.previous == (envelope.expected_generation, envelope.expected_current)
                and status.transaction_id == envelope.transaction_id
            )
            if not pending and not committed:
                raise ControllerActivationError("controller activation generation CAS failed")
            if pending:
                self._assert_status_digest(status_digest, transaction["reserved_status_digest"])
            else:
                committed_status_digest = transaction["committed_status_digest"]
                if committed_status_digest is None:
                    raise ControllerActivationError(
                        "controller rollback committed status fingerprint is unavailable"
                    )
                self._assert_status_digest(status_digest, committed_status_digest)
            observed_images = (
                observed_image_digest,
                observed_internal_image_digest or observed_image_digest,
            )
            _require_digest(observed_config_digest, "observed config")
            permitted_observations = {
                (
                    envelope.expected_current.public_image_digest,
                    envelope.expected_current.effective_internal_image_digest,
                    envelope.expected_current_config_digest,
                ),
                # The candidate config is installed before the compose flip, so
                # a failed flip can legitimately leave the old image on the new
                # config.  No other mixed tuple is accepted.
                (
                    envelope.expected_current.public_image_digest,
                    envelope.expected_current.effective_internal_image_digest,
                    envelope.candidate_config_digest,
                ),
                (
                    envelope.candidate.public_image_digest,
                    envelope.candidate.effective_internal_image_digest,
                    envelope.candidate_config_digest,
                ),
            }
            transition_is_permitted = allow_config_transition and (
                observed_images[0]
                in {
                    envelope.expected_current.public_image_digest,
                    envelope.candidate.public_image_digest,
                }
                and observed_images[1]
                in {
                    envelope.expected_current.effective_internal_image_digest,
                    envelope.candidate.effective_internal_image_digest,
                }
            )
            if (
                *observed_images,
                observed_config_digest,
            ) not in permitted_observations and not transition_is_permitted:
                raise ControllerActivationError("controller rollback running config is foreign")
            if rollback_config_digest != envelope.expected_current_config_digest:
                raise ControllerActivationError("controller rollback config snapshot is foreign")

    def abort(
        self,
        envelope: ActivationEnvelope,
        *,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
    ) -> None:
        with self._locked():
            raw_status, status_digest = self._read_json_with_digest(self.status_path)
            status = ControllerReleaseStatus.parse(raw_status)
            transaction = self._assert_transaction(envelope)
            self._assert_expected(status, envelope)
            self._assert_status_digest(status_digest, transaction["reserved_status_digest"])
            if not envelope.expected_current.matches_images(
                observed_image_digest,
                observed_internal_image_digest,
            ):
                raise ControllerActivationError("controller abort running images CAS failed")
            if observed_config_digest != envelope.expected_current_config_digest:
                raise ControllerActivationError("controller abort config fingerprint CAS failed")
            self._atomic_unlink(self.transaction_path)

    def commit(
        self,
        envelope: ActivationEnvelope,
        *,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
        activated_at: datetime | None = None,
    ) -> ControllerReleaseStatus:
        with self._locked():
            status = ControllerReleaseStatus.parse(self._read_json(self.status_path))
            if (
                status.transaction_id == envelope.transaction_id
                and status.generation == envelope.expected_generation + 1
                and status.current == envelope.candidate
            ):
                if not envelope.candidate.matches_images(
                    observed_image_digest,
                    observed_internal_image_digest,
                ):
                    raise ControllerActivationError("controller commit running images CAS failed")
                if observed_config_digest != envelope.candidate_config_digest:
                    raise ControllerActivationError(
                        "controller commit config fingerprint CAS failed"
                    )
                if self.transaction_path.exists():
                    raw_transaction = self._assert_transaction(envelope)
                    committed_digest = raw_transaction["committed_status_digest"]
                    if committed_digest is None:
                        raise ControllerActivationError(
                            "controller commit status fingerprint is unavailable"
                        )
                    _, status_digest = self._read_json_with_digest(self.status_path)
                    self._assert_status_digest(status_digest, committed_digest)
                return status
            transaction = self._assert_transaction(envelope)
            self._assert_expected(status, envelope)
            _, status_digest = self._read_json_with_digest(self.status_path)
            self._assert_status_digest(status_digest, transaction["reserved_status_digest"])
            if not envelope.candidate.matches_images(
                observed_image_digest,
                observed_internal_image_digest,
            ):
                raise ControllerActivationError("controller commit running images CAS failed")
            if observed_config_digest != envelope.candidate_config_digest:
                raise ControllerActivationError("controller commit config fingerprint CAS failed")
            committed_status_digest = transaction["committed_status_digest"]
            committed_activated_at_raw = transaction["committed_activated_at"]
            if committed_status_digest is None:
                committed_activated_at = (activated_at or datetime.now(UTC)).astimezone(UTC)
                committed = ControllerReleaseStatus(
                    generation=status.generation + 1,
                    current=envelope.candidate,
                    previous=(status.generation, status.current),
                    transaction_id=envelope.transaction_id,
                    activated_at=committed_activated_at,
                )
                committed_status_digest = hashlib.sha256(
                    _canonical(committed.mapping()) + b"\n"
                ).hexdigest()
                # Persist the exact future status fingerprint before exposing
                # the corresponding status. A crash after this write can only
                # replay the same status bytes.
                self._atomic_write(
                    self.transaction_path,
                    self._transaction_mapping(
                        envelope,
                        reserved_status_digest=transaction["reserved_status_digest"],
                        committed_status_digest=committed_status_digest,
                        committed_activated_at=committed_activated_at,
                    ),
                    mode=0o600,
                )
            else:
                if not isinstance(committed_activated_at_raw, str):
                    raise ControllerActivationError("controller commit timestamp is unavailable")
                committed_activated_at = _parse_time(
                    committed_activated_at_raw, "committed_activated_at"
                )
                committed = ControllerReleaseStatus(
                    generation=status.generation + 1,
                    current=envelope.candidate,
                    previous=(status.generation, status.current),
                    transaction_id=envelope.transaction_id,
                    activated_at=committed_activated_at,
                )
                calculated_digest = hashlib.sha256(
                    _canonical(committed.mapping()) + b"\n"
                ).hexdigest()
                self._assert_status_digest(calculated_digest, committed_status_digest)
            self._atomic_write(self.status_path, committed.mapping(), mode=0o644)
            _, observed_committed_digest = self._read_json_with_digest(self.status_path)
            self._assert_status_digest(observed_committed_digest, committed_status_digest)
            return committed

    def finalize(self, envelope: ActivationEnvelope) -> ControllerReleaseStatus:
        """Close a committed transaction after public status-v2 proves it."""
        with self._locked():
            raw_status, status_digest = self._read_json_with_digest(self.status_path)
            status = ControllerReleaseStatus.parse(raw_status)
            expected = (
                status.generation == envelope.expected_generation + 1
                and status.current == envelope.candidate
                and status.previous == (envelope.expected_generation, envelope.expected_current)
                and status.transaction_id == envelope.transaction_id
            )
            if not expected:
                raise ControllerActivationError("controller finalize status CAS failed")
            if self.transaction_path.exists():
                transaction = self._assert_transaction(envelope)
                committed_status_digest = transaction["committed_status_digest"]
                if committed_status_digest is None:
                    raise ControllerActivationError(
                        "controller finalize committed status fingerprint is unavailable"
                    )
                self._assert_status_digest(status_digest, committed_status_digest)
                self._atomic_unlink(self.transaction_path)
            return status

    def finalize_measured(
        self,
        envelope: ActivationEnvelope,
        *,
        measured_status: MeasuredControllerReleaseStatus,
        public_status: MeasuredControllerReleaseStatus,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
    ) -> ControllerReleaseStatus:
        """Finalize only after local and public measured runtime identities agree."""

        _require_digest(observed_image_digest, "observed image")
        _require_digest(observed_config_digest, "observed config")
        if measured_status != public_status:
            raise ControllerActivationError(
                "public measured controller status does not match durable runtime status"
            )
        if measured_status.revision != envelope.candidate.source_sha:
            raise ControllerActivationError(
                "measured controller revision does not prove activation candidate"
            )
        if measured_status.release_digest != envelope.candidate_release_digest:
            raise ControllerActivationError(
                "measured controller release does not prove activation candidate"
            )
        if not envelope.candidate.matches_images(
            measured_status.public_image_digest,
            measured_status.internal_image_digest,
        ):
            raise ControllerActivationError(
                "measured controller images do not prove activation candidate"
            )
        if not envelope.candidate.matches_images(
            observed_image_digest,
            observed_internal_image_digest,
        ):
            raise ControllerActivationError("controller finalize running images CAS failed")
        if observed_config_digest != envelope.candidate_config_digest:
            raise ControllerActivationError("controller finalize config fingerprint CAS failed")
        return self.finalize(envelope)

    def finalize_historical(
        self,
        envelope: ActivationEnvelope,
        *,
        measured_status: LegacyMeasuredControllerReleaseStatus,
        public_status: LegacyMeasuredControllerReleaseStatus,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
    ) -> ControllerReleaseStatus:
        """Finalize an exact historical v1 candidate without executing its code."""

        _require_digest(observed_image_digest, "observed image")
        _require_digest(observed_config_digest, "observed config")
        if measured_status != public_status:
            raise ControllerActivationError(
                "public legacy controller status does not match durable runtime status"
            )
        if measured_status.revision != envelope.candidate.source_sha:
            raise ControllerActivationError(
                "legacy controller revision does not prove activation candidate"
            )
        if measured_status.release_digest != envelope.candidate_release_digest:
            raise ControllerActivationError(
                "legacy controller release does not prove activation candidate"
            )
        if not envelope.candidate.matches_images(
            observed_image_digest,
            observed_internal_image_digest,
        ):
            raise ControllerActivationError("controller finalize running images CAS failed")
        if observed_config_digest != envelope.candidate_config_digest:
            raise ControllerActivationError("controller finalize config fingerprint CAS failed")
        return self.finalize(envelope)

    def complete_rollback(
        self,
        envelope: ActivationEnvelope,
        *,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
        activated_at: datetime | None = None,
    ) -> ControllerReleaseStatus:
        """Close rollback, preserving monotonic generation after a committed flip."""
        with self._locked():
            _require_digest(observed_image_digest, "observed rollback image")
            if observed_internal_image_digest is not None:
                _require_digest(observed_internal_image_digest, "observed rollback internal image")
            _require_digest(observed_config_digest, "observed rollback config")
            raw_status, status_digest = self._read_json_with_digest(self.status_path)
            status = ControllerReleaseStatus.parse(raw_status)
            rollback_transaction_id = f"rollback:{envelope.transaction_id}"
            if (
                status.generation == envelope.expected_generation + 2
                and status.current == envelope.expected_current
                and status.previous == (envelope.expected_generation + 1, envelope.candidate)
                and status.transaction_id == rollback_transaction_id
            ):
                if not envelope.expected_current.matches_images(
                    observed_image_digest,
                    observed_internal_image_digest,
                ):
                    raise ControllerActivationError("controller rollback terminal image CAS failed")
                if observed_config_digest != envelope.expected_current_config_digest:
                    raise ControllerActivationError(
                        "controller rollback terminal config CAS failed"
                    )
                if self.transaction_path.exists():
                    self._assert_transaction(envelope)
                    self._atomic_unlink(self.transaction_path)
                return status
            self._assert_transaction(envelope)
            if not envelope.expected_current.matches_images(
                observed_image_digest,
                observed_internal_image_digest,
            ):
                raise ControllerActivationError("controller rollback image restore CAS failed")
            if observed_config_digest != envelope.expected_current_config_digest:
                raise ControllerActivationError("controller rollback config restore CAS failed")
            if (
                status.generation == envelope.expected_generation
                and status.current == envelope.expected_current
            ):
                self._atomic_unlink(self.transaction_path)
                return status
            if not (
                status.generation == envelope.expected_generation + 1
                and status.current == envelope.candidate
                and status.previous == (envelope.expected_generation, envelope.expected_current)
                and status.transaction_id == envelope.transaction_id
            ):
                raise ControllerActivationError("controller rollback status CAS failed")
            committed_status_digest = self._assert_transaction(envelope)["committed_status_digest"]
            if committed_status_digest is None:
                raise ControllerActivationError(
                    "controller rollback committed status fingerprint is unavailable"
                )
            self._assert_status_digest(status_digest, committed_status_digest)
            rolled_back = ControllerReleaseStatus(
                generation=status.generation + 1,
                current=envelope.expected_current,
                previous=(status.generation, status.current),
                transaction_id=rollback_transaction_id,
                activated_at=(activated_at or datetime.now(UTC)).astimezone(UTC),
            )
            self._atomic_write(self.status_path, rolled_back.mapping(), mode=0o644)
            self._atomic_unlink(self.transaction_path)
            return rolled_back

    def verify_rollback_terminal(
        self,
        envelope: ActivationEnvelope,
        *,
        observed_image_digest: str,
        observed_internal_image_digest: str | None = None,
        observed_config_digest: str,
    ) -> ControllerReleaseStatus:
        """Prove that recovery terminated on the envelope's previous tuple."""

        with self._locked():
            _require_digest(observed_image_digest, "observed rollback image")
            if observed_internal_image_digest is not None:
                _require_digest(observed_internal_image_digest, "observed rollback internal image")
            _require_digest(observed_config_digest, "observed rollback config")
            raw_status, status_digest = self._read_json_with_digest(self.status_path)
            status = ControllerReleaseStatus.parse(raw_status)
            if not envelope.expected_current.matches_images(
                observed_image_digest,
                observed_internal_image_digest,
            ):
                raise ControllerActivationError("controller rollback terminal image CAS failed")
            if observed_config_digest != envelope.expected_current_config_digest:
                raise ControllerActivationError("controller rollback terminal config CAS failed")
            if (
                status.generation == envelope.expected_generation
                and status.current == envelope.expected_current
            ):
                self._assert_status_digest(status_digest, envelope.expected_current_status_digest)
                return status
            if not (
                status.generation == envelope.expected_generation + 2
                and status.current == envelope.expected_current
                and status.previous == (envelope.expected_generation + 1, envelope.candidate)
                and status.transaction_id == f"rollback:{envelope.transaction_id}"
            ):
                raise ControllerActivationError(
                    "controller rollback terminal status does not match signed transaction"
                )
            return status


def load_activation_public_key(
    path: Path,
    *,
    require_root_owner: bool = True,
) -> Ed25519PublicKey:
    """Load a non-symlinked, root-owned Ed25519 public verification key."""
    try:
        raw = _read_regular_bytes(
            path,
            description="activation public key",
            require_root_owner=require_root_owner,
        )
        key = serialization.load_pem_public_key(raw)
    except (TypeError, ValueError) as error:
        raise ControllerActivationError("activation public key is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise ControllerActivationError("activation public key is not Ed25519")
    return key


def load_and_verify_envelope(
    path: Path,
    *,
    public_key: Ed25519PublicKey,
    now: datetime | None = None,
    allow_expired_for_rollback: bool = False,
) -> ActivationEnvelope:
    try:
        raw = _read_regular_bytes(
            path,
            description="activation envelope",
            require_root_owner=True,
        )
        document = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControllerActivationError("activation envelope is unavailable") from error
    return ActivationEnvelope.verify(
        document,
        public_key=public_key,
        now=now,
        allow_expired_for_rollback=allow_expired_for_rollback,
    )


def _read_regular_bytes(
    path: Path,
    *,
    description: str,
    require_root_owner: bool,
    mode_mask: int = 0o022,
) -> bytes:
    """Read a trusted regular file without following or racing a symlink."""
    descriptor = -1
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ControllerActivationError(f"{description} path is unsafe")
        if require_root_owner and metadata.st_uid != 0:
            raise ControllerActivationError(f"{description} is not root-owned")
        if metadata.st_mode & mode_mask:
            raise ControllerActivationError(f"{description} permissions are unsafe")
        with os.fdopen(descriptor, "rb") as handle:
            descriptor = -1
            return handle.read()
    except OSError as error:
        raise ControllerActivationError(f"{description} is unavailable") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def fingerprint_config_files(
    files: Mapping[str, Path],
    *,
    require_root_owner: bool = True,
) -> str:
    """Fingerprint the exact activation-controlled effective configuration.

    Logical names are included in the digest so swapping two equal-looking
    destinations cannot preserve the fingerprint.  Callers must supply the
    same logical destination set for the current and candidate snapshots.
    """

    if not files:
        raise ControllerActivationError("controller config fingerprint is empty")
    records: dict[str, dict[str, object]] = {}
    for logical_name, path in files.items():
        if (
            not isinstance(logical_name, str)
            or not logical_name
            or logical_name.startswith("/")
            or ".." in Path(logical_name).parts
            or logical_name in records
        ):
            raise ControllerActivationError("controller config logical name is invalid")
        raw = _read_regular_bytes(
            path,
            description=f"controller config {logical_name}",
            require_root_owner=require_root_owner,
        )
        records[logical_name] = {
            "sha256": hashlib.sha256(raw).hexdigest(),
            "size": len(raw),
        }
    return hashlib.sha256(_canonical(records)).hexdigest()


def fingerprint_release_tree(
    root: Path,
    *,
    require_root_owner: bool = True,
) -> str:
    """Fingerprint every directory and regular file in an executable release tree.

    Activation executes scripts and Compose definitions from ``root``.  A
    signed image manifest alone therefore cannot authorize those host-side
    bytes.  The digest includes relative paths, modes, sizes and file hashes;
    links and special files fail closed.  Ownership and write-permission
    checks make the traversal stable against non-root replacement while the
    host-wide activation lock is held.
    """

    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise ControllerActivationError("controller release tree is unavailable") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        raise ControllerActivationError("controller release tree root is unsafe")
    if require_root_owner and root_metadata.st_uid != 0:
        raise ControllerActivationError("controller release tree is not root-owned")
    if root_metadata.st_mode & 0o022:
        raise ControllerActivationError("controller release tree permissions are unsafe")

    entries: list[dict[str, object]] = [
        {
            "path": ".",
            "kind": "directory",
            "mode": stat.S_IMODE(root_metadata.st_mode),
        }
    ]

    def walk(directory: Path, relative_directory: Path) -> None:
        try:
            children = sorted(os.scandir(directory), key=lambda entry: entry.name)
        except OSError as error:
            raise ControllerActivationError("controller release tree is unavailable") from error
        for child in children:
            relative = relative_directory / child.name
            relative_text = relative.as_posix()
            # ``.git`` is checkout transport metadata, not executable release
            # material. Its contents differ between GitHub Actions and a
            # root-owned host checkout, so including it would make an otherwise
            # identical release impossible to reconcile.
            if relative_directory == Path() and child.name == ".git":
                continue
            if (
                not child.name
                or child.name in {".", ".."}
                or relative.is_absolute()
                or ".." in relative.parts
            ):
                raise ControllerActivationError("controller release tree path is invalid")
            # CPython creates this derived interpreter cache while release
            # tooling imports the activation modules. It is not executable
            # release material and must not bind a signed tree to one host's
            # bytecode policy. Its directory still has to meet the ownership
            # and permission checks; links and arbitrary ``.pyc`` files fail
            # closed below.
            if child.name == "__pycache__" and child.is_dir(follow_symlinks=False):
                try:
                    cache_metadata = child.stat(follow_symlinks=False)
                except OSError as error:
                    raise ControllerActivationError(
                        f"controller release tree entry is unavailable: {relative_text}"
                    ) from error
                if require_root_owner and cache_metadata.st_uid != 0:
                    raise ControllerActivationError(
                        f"controller release tree entry is not root-owned: {relative_text}"
                    )
                if cache_metadata.st_mode & 0o022:
                    raise ControllerActivationError(
                        f"controller release tree entry permissions are unsafe: {relative_text}"
                    )
                continue
            try:
                metadata = child.stat(follow_symlinks=False)
            except OSError as error:
                raise ControllerActivationError(
                    f"controller release tree entry is unavailable: {relative_text}"
                ) from error
            if require_root_owner and metadata.st_uid != 0:
                raise ControllerActivationError(
                    f"controller release tree entry is not root-owned: {relative_text}"
                )
            if metadata.st_mode & 0o022:
                raise ControllerActivationError(
                    f"controller release tree entry permissions are unsafe: {relative_text}"
                )
            if stat.S_ISDIR(metadata.st_mode):
                entries.append(
                    {
                        "path": relative_text,
                        "kind": "directory",
                        "mode": stat.S_IMODE(metadata.st_mode),
                    }
                )
                walk(Path(child.path), relative)
                continue
            if not stat.S_ISREG(metadata.st_mode) or child.is_symlink():
                raise ControllerActivationError(
                    f"controller release tree entry is unsafe: {relative_text}"
                )
            raw = _read_regular_bytes(
                Path(child.path),
                description=f"controller release tree entry {relative_text}",
                require_root_owner=require_root_owner,
            )
            entries.append(
                {
                    "path": relative_text,
                    "kind": "file",
                    "mode": stat.S_IMODE(metadata.st_mode),
                    "size": len(raw),
                    "sha256": hashlib.sha256(raw).hexdigest(),
                }
            )

    walk(root, Path())
    if len(entries) == 1:
        raise ControllerActivationError("controller release tree is empty")
    document: dict[str, Any] = {
        "schema": ENTRYPOINT_RECONCILIATION_SCHEMA,
        "entries": entries,
    }
    return hashlib.sha256(_canonical(document)).hexdigest()


def _artifact_member(
    manifest_directory: Path,
    value: object,
    *,
    field: str,
    require_root_owner: bool,
) -> tuple[Path, bytes, str]:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size"}:
        raise ControllerActivationError(f"controller artifact {field} descriptor is invalid")
    relative_path = value["path"]
    expected_digest = value["sha256"]
    expected_size = value["size"]
    if (
        not isinstance(relative_path, str)
        or not relative_path
        or Path(relative_path).name != relative_path
        or relative_path in {".", ".."}
    ):
        raise ControllerActivationError(f"controller artifact {field} path is invalid")
    _require_digest(expected_digest, f"artifact {field}")
    if not isinstance(expected_size, int) or isinstance(expected_size, bool) or expected_size < 1:
        raise ControllerActivationError(f"controller artifact {field} size is invalid")
    path = manifest_directory / relative_path
    raw = _read_regular_bytes(
        path,
        description=f"controller artifact {field}",
        require_root_owner=require_root_owner,
    )
    observed_digest = hashlib.sha256(raw).hexdigest()
    if len(raw) != expected_size or observed_digest != expected_digest:
        raise ControllerActivationError(f"controller artifact {field} bytes do not match manifest")
    return path, raw, observed_digest


def _trivy_actionable_findings(report: object) -> int:
    """Count high/critical vulnerabilities and every detected secret."""

    if (
        not isinstance(report, dict)
        or not isinstance(report.get("SchemaVersion"), int)
        or not isinstance(report.get("ArtifactName"), str)
        or not isinstance(report.get("ArtifactType"), str)
        or not isinstance(report.get("Trivy"), dict)
        or not isinstance(report["Trivy"].get("Version"), str)
    ):
        raise ControllerActivationError("controller artifact Trivy report is invalid")
    if "Results" not in report:
        return 0
    results = report["Results"]
    if not isinstance(results, list):
        raise ControllerActivationError("controller artifact Trivy report is invalid")
    total = 0
    for result in results:
        if not isinstance(result, dict):
            raise ControllerActivationError("controller artifact Trivy result is invalid")
        vulnerabilities = result.get("Vulnerabilities")
        secrets = result.get("Secrets")
        if vulnerabilities is None:
            vulnerabilities = []
        if secrets is None:
            secrets = []
        if not isinstance(vulnerabilities, list) or not isinstance(secrets, list):
            raise ControllerActivationError("controller artifact Trivy findings are invalid")
        for finding in vulnerabilities:
            if not isinstance(finding, dict) or finding.get("Severity") not in {"HIGH", "CRITICAL"}:
                raise ControllerActivationError(
                    "controller artifact Trivy vulnerability is invalid"
                )
            total += 1
        if not all(isinstance(secret, dict) for secret in secrets):
            raise ControllerActivationError("controller artifact Trivy secret is invalid")
        total += len(secrets)
    return total


def verify_controller_artifact_manifest(
    path: Path,
    *,
    expected_manifest_digest: str | None = None,
    require_root_owner: bool = True,
    now: datetime | None = None,
) -> VerifiedControllerArtifact:
    """Verify an import-only image archive, SPDX SBOM and provenance receipt.

    This deliberately does not call the GitHub OIDC token a byte signature.
    OIDC identity reconciliation happens server-side before the external
    operator signs an activation envelope; that envelope binds the digest of
    this fully verified manifest.
    """

    raw_manifest = _read_regular_bytes(
        path,
        description="controller artifact manifest",
        require_root_owner=require_root_owner,
    )
    manifest_digest = hashlib.sha256(raw_manifest).hexdigest()
    if expected_manifest_digest is not None:
        _require_digest(expected_manifest_digest, "expected artifact manifest")
        if manifest_digest != expected_manifest_digest:
            raise ControllerActivationError(
                "controller artifact manifest does not match signed digest"
            )
    try:
        document = json.loads(raw_manifest.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControllerActivationError("controller artifact manifest is invalid") from error
    required = {
        "schema",
        "repository",
        "source_sha",
        "image_digest",
        "policy_bundle_digest",
        "entrypoint_reconciliation_digest",
        "image_unpacked_size",
        "image_archive",
        "sbom",
        "security_scans",
        "source_scan",
        "image_scan",
        "provenance",
    }
    if not isinstance(document, dict) or set(document) not in {
        frozenset(required),
        frozenset(required | {"claim_receipt"}),
    }:
        raise ControllerActivationError("controller artifact manifest shape is invalid")
    if (
        document["schema"] != ARTIFACT_MANIFEST_SCHEMA
        or document["repository"] != CONTROLLER_REPOSITORY
    ):
        raise ControllerActivationError("controller artifact manifest identity is invalid")
    source_sha = document["source_sha"]
    image_digest = document["image_digest"]
    policy_bundle_digest = document["policy_bundle_digest"]
    entrypoint_reconciliation_digest = document["entrypoint_reconciliation_digest"]
    image_unpacked_size = document["image_unpacked_size"]
    if not isinstance(source_sha, str) or _SHA.fullmatch(source_sha) is None:
        raise ControllerActivationError("controller artifact source SHA is invalid")
    _require_digest(image_digest, "artifact image")
    _require_digest(policy_bundle_digest, "artifact policy bundle")
    _require_digest(entrypoint_reconciliation_digest, "artifact entrypoint reconciliation")
    if (
        not isinstance(image_unpacked_size, int)
        or isinstance(image_unpacked_size, bool)
        or image_unpacked_size < 1
    ):
        raise ControllerActivationError("controller artifact unpacked image size is invalid")

    image_archive, _, image_archive_digest = _artifact_member(
        path.parent,
        document["image_archive"],
        field="image archive",
        require_root_owner=require_root_owner,
    )
    _, sbom_raw, sbom_digest = _artifact_member(
        path.parent,
        document["sbom"],
        field="SBOM",
        require_root_owner=require_root_owner,
    )
    _, security_scans_raw, security_scans_digest = _artifact_member(
        path.parent,
        document["security_scans"],
        field="security scans",
        require_root_owner=require_root_owner,
    )
    _, source_scan_raw, source_scan_digest = _artifact_member(
        path.parent,
        document["source_scan"],
        field="source Trivy scan",
        require_root_owner=require_root_owner,
    )
    _, image_scan_raw, image_scan_digest = _artifact_member(
        path.parent,
        document["image_scan"],
        field="image Trivy scan",
        require_root_owner=require_root_owner,
    )
    claim_receipt_path: Path | None = None
    claim_receipt_raw: bytes | None = None
    claim_receipt_digest: str | None = None
    if "claim_receipt" in document:
        claim_receipt_path, claim_receipt_raw, claim_receipt_digest = _artifact_member(
            path.parent,
            document["claim_receipt"],
            field="controller claim receipt",
            require_root_owner=require_root_owner,
        )
    _, provenance_raw, provenance_digest = _artifact_member(
        path.parent,
        document["provenance"],
        field="provenance",
        require_root_owner=require_root_owner,
    )

    try:
        sbom = json.loads(sbom_raw.decode("utf-8"))
        security_scans = json.loads(security_scans_raw.decode("utf-8"))
        source_scan = json.loads(source_scan_raw.decode("utf-8"))
        image_scan = json.loads(image_scan_raw.decode("utf-8"))
        provenance = json.loads(provenance_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControllerActivationError("controller artifact evidence is invalid") from error
    if not isinstance(sbom, dict) or sbom.get("spdxVersion") != "SPDX-2.3":
        raise ControllerActivationError("controller artifact SBOM is not SPDX 2.3")
    if (
        not isinstance(security_scans, dict)
        or security_scans.get("schema") != "qdev-controller-security-scans-v1"
        or security_scans.get("status") != "passed"
        or security_scans.get("source_high_critical") != 0
        or security_scans.get("image_high_critical") != 0
        or security_scans.get("source_report_sha256") != source_scan_digest
        or security_scans.get("image_report_sha256") != image_scan_digest
        or _trivy_actionable_findings(source_scan) != 0
        or _trivy_actionable_findings(image_scan) != 0
    ):
        raise ControllerActivationError("controller artifact security scans did not pass")
    provenance_fields = {
        "schema",
        "repository",
        "source_sha",
        "image_digest",
        "policy_bundle_digest",
        "entrypoint_reconciliation_digest",
        "image_unpacked_size",
        "image_archive_sha256",
        "sbom_sha256",
        "security_scans_sha256",
        "source_scan_sha256",
        "image_scan_sha256",
        "workflow_identity",
    }
    if not isinstance(provenance, dict) or set(provenance) not in {
        frozenset(provenance_fields),
        frozenset(provenance_fields | {"claim_receipt_sha256"}),
    }:
        raise ControllerActivationError("controller artifact provenance shape is invalid")
    workflow_identity = provenance.get("workflow_identity")
    normal_identity_fields = {
        "issuer",
        "subject",
        "workflow_ref",
        "event",
        "ref",
        "run_id",
        "job_id",
        "attempt",
        "reconciled_at",
    }
    recovery_identity_fields = normal_identity_fields | {
        "head_sha",
        "job_name",
        "labels",
        "owner_recovery",
        "execution_lane",
        "expected_sha",
        "admission_nonce",
        "idempotency_key",
        "issued_at",
        "expires_at",
        "conclusion",
    }
    hosted_identity_fields = recovery_identity_fields - {"admission_nonce"}
    if not isinstance(workflow_identity, dict) or set(workflow_identity) not in {
        frozenset(normal_identity_fields),
        frozenset(recovery_identity_fields),
        frozenset(hosted_identity_fields),
    }:
        raise ControllerActivationError("controller artifact workflow identity is invalid")
    common_identity_invalid = (
        not isinstance(workflow_identity.get("subject"), str)
        or not isinstance(workflow_identity.get("workflow_ref"), str)
        or not workflow_identity["workflow_ref"].startswith(
            f"{CONTROLLER_REPOSITORY}/.github/workflows/"
        )
        or not isinstance(workflow_identity.get("reconciled_at"), str)
        or any(
            not isinstance(workflow_identity.get(field), int)
            or isinstance(workflow_identity.get(field), bool)
            or workflow_identity[field] < 1
            for field in ("run_id", "job_id", "attempt")
        )
    )
    if common_identity_invalid:
        raise ControllerActivationError("controller artifact workflow identity is invalid")
    reconciled_at = _parse_time(workflow_identity["reconciled_at"], "workflow reconciled_at")
    if set(workflow_identity) == normal_identity_fields:
        if claim_receipt_raw is not None or "claim_receipt_sha256" in provenance:
            raise ControllerActivationError(
                "normal controller artifact must not contain a recovery claim receipt"
            )
        if (
            workflow_identity.get("issuer") != "https://token.actions.githubusercontent.com"
            or workflow_identity.get("event") != "push"
            or workflow_identity.get("ref") != "refs/heads/main"
            or not workflow_identity["subject"].startswith(
                f"repo:{CONTROLLER_REPOSITORY}:ref:refs/heads/main"
            )
        ):
            raise ControllerActivationError("controller artifact workflow identity is invalid")
    elif set(workflow_identity) == hosted_identity_fields:
        issued_at = _parse_time(workflow_identity.get("issued_at"), "recovery build issued_at")
        expires_at = _parse_time(workflow_identity.get("expires_at"), "recovery build expires_at")
        observed_at = (now or datetime.now(UTC)).astimezone(UTC)
        run_id = workflow_identity["run_id"]
        job_id = workflow_identity["job_id"]
        attempt = workflow_identity["attempt"]
        recovery_build_identities = {
            (
                ("ubuntu-latest",),
                "github-hosted-recovery-build",
                "hosted-recovery",
            ),
            (
                ("self-hosted", "Linux", "X64", "qdev-ci-docker"),
                "self-hosted-recovery-build",
                "self-hosted-recovery",
            ),
        }
        identity_tuple = (
            tuple(workflow_identity.get("labels", [])),
            workflow_identity.get("execution_lane"),
            str(workflow_identity.get("idempotency_key", "")).split(":", 1)[0],
        )
        if (
            claim_receipt_raw is not None
            or "claim_receipt_sha256" in provenance
            or workflow_identity.get("issuer") != "https://api.github.com"
            or workflow_identity.get("event") != "workflow_dispatch"
            or workflow_identity.get("ref") != "refs/heads/main"
            or workflow_identity.get("head_sha") != source_sha
            or workflow_identity.get("expected_sha") != source_sha
            or workflow_identity.get("job_name") != "controller-recovery-build"
            or workflow_identity.get("conclusion") != "success"
            or workflow_identity.get("owner_recovery") is not True
            or identity_tuple not in recovery_build_identities
            or workflow_identity["subject"] != f"repo:{CONTROLLER_REPOSITORY}:ref:refs/heads/main"
            or workflow_identity["workflow_ref"]
            != (
                f"{CONTROLLER_REPOSITORY}/.github/workflows/"
                "controller-recovery-build.yml@refs/heads/main"
            )
            or workflow_identity.get("idempotency_key")
            != f"{identity_tuple[2]}:{run_id}:{job_id}:{attempt}"
            or expires_at <= issued_at
            or expires_at - issued_at > MAX_ENVELOPE_TTL
            or reconciled_at != issued_at
            or issued_at > observed_at + MAX_CLOCK_SKEW
            or expires_at <= observed_at
        ):
            raise ControllerActivationError("controller recovery build identity is invalid")
    else:
        if claim_receipt_raw is None or claim_receipt_digest is None:
            raise ControllerActivationError(
                "controller recovery artifact claim receipt is unavailable"
            )
        try:
            claim_receipt = json.loads(claim_receipt_raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ControllerActivationError(
                "controller recovery artifact claim receipt is invalid"
            ) from error
        if not isinstance(claim_receipt, dict):
            raise ControllerActivationError("controller recovery artifact claim receipt is invalid")
        claim_payload = claim_receipt.get("payload")
        claim_receipt_id = claim_receipt.get("receipt_id")
        claim_tuple = (
            claim_payload.get("immutable_tuple") if isinstance(claim_payload, dict) else None
        )
        claim_scope = claim_payload.get("claim_scope") if isinstance(claim_payload, dict) else None
        claim_jobs = claim_scope.get("jobs") if isinstance(claim_scope, dict) else None
        claim_job = claim_jobs[0] if isinstance(claim_jobs, list) and len(claim_jobs) == 1 else None
        claim_expires_at = _parse_time(
            claim_scope.get("expires_at") if isinstance(claim_scope, dict) else None,
            "recovery claim scope expires_at",
        )
        canonical_claim_digest = (
            hashlib.sha256(_canonical(claim_payload)).hexdigest()
            if isinstance(claim_payload, dict)
            else ""
        )
        issued_at = _parse_time(workflow_identity.get("issued_at"), "recovery issued_at")
        expires_at = _parse_time(workflow_identity.get("expires_at"), "recovery expires_at")
        observed_at = (now or datetime.now(UTC)).astimezone(UTC)
        labels = workflow_identity.get("labels")
        run_id = workflow_identity.get("run_id")
        attempt = workflow_identity.get("attempt")
        expected_labels = {
            "self-hosted",
            "Linux",
            "X64",
            "qdev-ci",
            f"qdev-job-{run_id}-{attempt}-smoke",
        }
        ref = workflow_identity.get("ref")
        if (
            set(claim_receipt)
            != {"schema", "receipt_id", "payload", "digest", "enforcement", "signature"}
            or claim_receipt.get("schema") != "qdev-controller-receipt-v2"
            or claim_receipt.get("enforcement") != "enforced"
            or not isinstance(claim_receipt_id, str)
            or _DIGEST.fullmatch(claim_receipt_id) is None
            or claim_receipt.get("digest") != claim_receipt_id
            or canonical_claim_digest != claim_receipt_id
            or not isinstance(claim_receipt.get("signature"), str)
            or not isinstance(claim_payload, dict)
            or claim_payload.get("kind") != "fifo-claim-scope-issued"
            or claim_payload.get("operator_session") != "verified"
            or claim_payload.get("admission_ledger") != "admin-platform"
            or claim_payload.get("admin_platform_ledger_entry") != "controller"
            or claim_payload.get("managed_release_ledger_entry") is not None
            or claim_payload.get("managed_registry_entry") is not None
            or not isinstance(claim_tuple, dict)
            or claim_tuple.get("repository") != CONTROLLER_REPOSITORY
            or claim_tuple.get("run_id") != workflow_identity.get("run_id")
            or claim_tuple.get("job_id") != workflow_identity.get("job_id")
            or claim_tuple.get("attempt") != workflow_identity.get("attempt")
            or claim_tuple.get("exact_sha") != source_sha
            or claim_tuple.get("profile") != "qdev-ci"
            or not isinstance(claim_scope, dict)
            or claim_scope.get("schema") != "claim-scope-v2"
            or claim_scope.get("runner") != claim_tuple.get("runner")
            or claim_scope.get("host") != claim_tuple.get("host")
            or not isinstance(claim_job, dict)
            or claim_job.get("repository") != CONTROLLER_REPOSITORY
            or claim_job.get("run_id") != workflow_identity.get("run_id")
            or claim_job.get("job_id") != workflow_identity.get("job_id")
            or claim_job.get("attempt") != workflow_identity.get("attempt")
            or claim_job.get("exact_sha") != source_sha
            or claim_job.get("profile") != "qdev-ci"
            or workflow_identity.get("admission_nonce") != f"controller-claim:{claim_receipt_id}"
            or provenance.get("claim_receipt_sha256") != claim_receipt_digest
            or claim_expires_at <= observed_at
            or workflow_identity.get("issuer") != "https://api.github.com"
            or workflow_identity.get("event") != "workflow_dispatch"
            or not isinstance(ref, str)
            or not ref.startswith("refs/heads/")
            or workflow_identity.get("head_sha") != source_sha
            or workflow_identity.get("expected_sha") != source_sha
            or workflow_identity.get("job_name") != "runner-smoke"
            or workflow_identity.get("conclusion") != "success"
            or workflow_identity.get("owner_recovery") is not True
            or workflow_identity.get("execution_lane") != "recovery"
            or workflow_identity["subject"] != f"repo:{CONTROLLER_REPOSITORY}:ref:{ref}"
            or workflow_identity["workflow_ref"]
            != f"{CONTROLLER_REPOSITORY}/.github/workflows/runner-smoke.yml@{ref}"
            or not isinstance(labels, list)
            or not all(isinstance(label, str) for label in labels)
            or len(labels) != len(set(labels))
            or set(labels) != expected_labels
            or not isinstance(workflow_identity.get("admission_nonce"), str)
            or _IDENTIFIER.fullmatch(workflow_identity["admission_nonce"]) is None
            or not isinstance(workflow_identity.get("idempotency_key"), str)
            or _IDENTIFIER.fullmatch(workflow_identity["idempotency_key"]) is None
            or expires_at <= issued_at
            or expires_at - issued_at > MAX_ENVELOPE_TTL
            or reconciled_at < issued_at
            or reconciled_at > expires_at
            or issued_at > observed_at + MAX_CLOCK_SKEW
            or expires_at <= observed_at
        ):
            raise ControllerActivationError("controller recovery workflow identity is invalid")
    expected_provenance: dict[str, object] = {
        "schema": ARTIFACT_PROVENANCE_SCHEMA,
        "repository": CONTROLLER_REPOSITORY,
        "source_sha": source_sha,
        "image_digest": image_digest,
        "policy_bundle_digest": policy_bundle_digest,
        "entrypoint_reconciliation_digest": entrypoint_reconciliation_digest,
        "image_unpacked_size": image_unpacked_size,
        "image_archive_sha256": image_archive_digest,
        "sbom_sha256": sbom_digest,
        "security_scans_sha256": security_scans_digest,
        "source_scan_sha256": source_scan_digest,
        "image_scan_sha256": image_scan_digest,
        "workflow_identity": workflow_identity,
    }
    if claim_receipt_digest is not None:
        expected_provenance["claim_receipt_sha256"] = claim_receipt_digest
    if provenance != expected_provenance:
        raise ControllerActivationError("controller artifact provenance binding is invalid")
    return VerifiedControllerArtifact(
        manifest_digest=manifest_digest,
        source_sha=source_sha,
        image_digest=image_digest,
        policy_bundle_digest=policy_bundle_digest,
        entrypoint_reconciliation_digest=entrypoint_reconciliation_digest,
        image_archive=image_archive,
        image_archive_digest=image_archive_digest,
        image_unpacked_size=image_unpacked_size,
        sbom_digest=sbom_digest,
        source_scan_digest=source_scan_digest,
        image_scan_digest=image_scan_digest,
        claim_receipt=claim_receipt_path,
        claim_receipt_digest=claim_receipt_digest,
        workflow_identity=workflow_identity,
        provenance_digest=provenance_digest,
    )
