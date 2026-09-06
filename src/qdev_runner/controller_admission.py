"""Sign and verify exact-source controller admission receipts.

The private signing key belongs to the controller host. Product hosts receive
only a public key and fail closed unless every repository, workflow, job and
controller binding matches the release candidate they are about to accept.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import sqlite3
import stat
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "qdev-ci-controller-admission/v1"
ALGORITHM = "Ed25519"
MAX_VALIDITY = timedelta(hours=24)

_SHA = re.compile(r"^[0-9a-f]{40}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_REF = re.compile(r"^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_KEY_ID = re.compile(r"^sha256:[0-9a-f]{64}$")
_DIGEST = _KEY_ID
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

_REPLAY_TABLE_SQL = """
CREATE TABLE consumed_receipts (
    fingerprint TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    admission_id TEXT NOT NULL,
    claim_id TEXT NOT NULL,
    functional_source_sha TEXT NOT NULL,
    consumer TEXT NOT NULL,
    consumed_at TEXT NOT NULL,
    UNIQUE (admission_id),
    UNIQUE (claim_id)
)
"""

_TOP_LEVEL_FIELDS = frozenset({"schema", "payload", "signature"})
_PAYLOAD_FIELDS = frozenset(
    {
        "repository",
        "protected_ref",
        "functional_source_sha",
        "evidence",
        "workflow",
        "required_jobs",
        "controller_revision",
        "admission",
        "issued_at",
        "expires_at",
    }
)
_EVIDENCE_FIELDS = frozenset(
    {"release_payload_sha256", "controller_contract_sha256", "release_lock_sha256"}
)
_REPOSITORY_FIELDS = frozenset({"id", "full_name"})
_WORKFLOW_FIELDS = frozenset({"run_id", "run_attempt"})
_JOB_FIELDS = frozenset({"name", "controller_profile", "job_id", "conclusion"})
_ADMISSION_FIELDS = frozenset({"id", "claim_id"})
_SIGNATURE_FIELDS = frozenset({"algorithm", "key_id", "payload_sha256", "value"})


class ControllerAdmissionError(ValueError):
    """Raised when an admission receipt is malformed, stale or untrusted."""


def _mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ControllerAdmissionError(f"{field} must be an object")
    return value


def _exact_fields(value: Mapping[str, object], fields: frozenset[str], label: str) -> None:
    actual = frozenset(value)
    if actual != fields:
        missing = sorted(fields - actual)
        extra = sorted(actual - fields)
        detail = []
        if missing:
            detail.append("missing " + ", ".join(missing))
        if extra:
            detail.append("unexpected " + ", ".join(extra))
        raise ControllerAdmissionError(f"{label} has invalid fields: {'; '.join(detail)}")


def _positive_integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise ControllerAdmissionError(f"{field} must be a positive integer")
    return value


def _matched_text(value: object, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ControllerAdmissionError(f"{field} is invalid")
    return value


def _timestamp(value: object, field: str) -> datetime:
    text = _matched_text(value, _TIME, field)
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise ControllerAdmissionError(f"{field} is invalid") from error


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ControllerAdmissionError(f"JSON contains duplicate key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise ControllerAdmissionError(f"JSON constant is not permitted: {value}")


def load_json_strict(path: Path) -> object:
    """Load one JSON document while rejecting duplicate keys and invalid constants."""

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except ControllerAdmissionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ControllerAdmissionError(f"cannot load JSON from {path}") from error


def canonical_payload(payload: object) -> bytes:
    """Return the stable bytes covered by the Ed25519 signature."""

    try:
        return json.dumps(
            payload,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ControllerAdmissionError("payload cannot be represented as canonical JSON") from error


def payload_digest(payload: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_payload(payload)).hexdigest()


def public_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _read_trusted_key_file(
    path: Path,
    *,
    label: str,
    owner_only: bool,
) -> bytes:
    """Read one regular, non-symlink key through the verified descriptor."""

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ControllerAdmissionError(f"{label} is unavailable or invalid") from error
    try:
        status = os.fstat(descriptor)
        mode = stat.S_IMODE(status.st_mode)
        allowed_owners = {os.geteuid(), 0}
        if not stat.S_ISREG(status.st_mode) or status.st_uid not in allowed_owners:
            raise ControllerAdmissionError(f"{label} must be a trusted regular file")
        if owner_only:
            if mode & 0o077:
                raise ControllerAdmissionError(f"{label} must be owner-only")
        elif mode & 0o022:
            raise ControllerAdmissionError(f"{label} must not be group/world writable")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    except OSError as error:
        raise ControllerAdmissionError(f"{label} is unavailable or invalid") from error
    finally:
        os.close(descriptor)


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(
            _read_trusted_key_file(
                path,
                label="admission private key",
                owner_only=True,
            ),
            password=None,
        )
    except ControllerAdmissionError:
        raise
    except ValueError as error:
        raise ControllerAdmissionError("admission private key is unavailable or invalid") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise ControllerAdmissionError("admission private key is not Ed25519")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(
            _read_trusted_key_file(
                path,
                label="admission public key",
                owner_only=False,
            )
        )
    except ControllerAdmissionError:
        raise
    except ValueError as error:
        raise ControllerAdmissionError("admission public key is unavailable or invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise ControllerAdmissionError("admission public key is not Ed25519")
    return key


def initialize_keypair(private_key_path: Path, public_key_path: Path) -> str:
    """Create a host-local keypair without overwriting either destination."""

    if (
        private_key_path.exists()
        or private_key_path.is_symlink()
        or public_key_path.exists()
        or public_key_path.is_symlink()
    ):
        raise ControllerAdmissionError("admission key path already exists")
    private_key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    public_key_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    key = Ed25519PrivateKey.generate()
    private_bytes = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    public_bytes = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    descriptor = os.open(private_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(private_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        public_descriptor = os.open(public_key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
        with os.fdopen(public_descriptor, "wb") as stream:
            stream.write(public_bytes)
            stream.flush()
            os.fsync(stream.fileno())
    except Exception:
        private_key_path.unlink(missing_ok=True)
        public_key_path.unlink(missing_ok=True)
        raise
    return public_key_id(key.public_key())


def validate_payload(payload: object) -> dict[str, Any]:
    """Validate every source, workflow, controller and expiry binding."""

    value = _mapping(payload, "payload")
    _exact_fields(value, _PAYLOAD_FIELDS, "payload")

    repository = _mapping(value["repository"], "payload.repository")
    _exact_fields(repository, _REPOSITORY_FIELDS, "payload.repository")
    _positive_integer(repository["id"], "payload.repository.id")
    _matched_text(repository["full_name"], _REPOSITORY, "payload.repository.full_name")
    _matched_text(value["protected_ref"], _REF, "payload.protected_ref")
    _matched_text(value["functional_source_sha"], _SHA, "payload.functional_source_sha")
    evidence = _mapping(value["evidence"], "payload.evidence")
    _exact_fields(evidence, _EVIDENCE_FIELDS, "payload.evidence")
    for field in sorted(_EVIDENCE_FIELDS):
        _matched_text(evidence[field], _DIGEST, f"payload.evidence.{field}")

    workflow = _mapping(value["workflow"], "payload.workflow")
    _exact_fields(workflow, _WORKFLOW_FIELDS, "payload.workflow")
    _positive_integer(workflow["run_id"], "payload.workflow.run_id")
    _positive_integer(workflow["run_attempt"], "payload.workflow.run_attempt")

    jobs = value["required_jobs"]
    if not isinstance(jobs, list) or not 1 <= len(jobs) <= 32:
        raise ControllerAdmissionError("payload.required_jobs must contain 1 to 32 jobs")
    names: set[str] = set()
    job_ids: set[int] = set()
    for index, raw_job in enumerate(jobs):
        job = _mapping(raw_job, f"payload.required_jobs[{index}]")
        _exact_fields(job, _JOB_FIELDS, f"payload.required_jobs[{index}]")
        name = _matched_text(job["name"], _IDENTIFIER, f"payload.required_jobs[{index}].name")
        profile = _matched_text(
            job["controller_profile"],
            _PROFILE,
            f"payload.required_jobs[{index}].controller_profile",
        )
        job_id = _positive_integer(job["job_id"], f"payload.required_jobs[{index}].job_id")
        if name in names or job_id in job_ids:
            raise ControllerAdmissionError("payload.required_jobs contains a duplicate job")
        if profile not in {"qdev-ci", "qdev-ci-docker", "qdev-ci-browser"}:
            raise ControllerAdmissionError(
                "payload.required_jobs contains an unknown controller profile"
            )
        if job["conclusion"] != "success":
            raise ControllerAdmissionError("every required job must have conclusion success")
        names.add(name)
        job_ids.add(job_id)

    _matched_text(value["controller_revision"], _SHA, "payload.controller_revision")
    admission = _mapping(value["admission"], "payload.admission")
    _exact_fields(admission, _ADMISSION_FIELDS, "payload.admission")
    _matched_text(admission["id"], _IDENTIFIER, "payload.admission.id")
    _matched_text(admission["claim_id"], _IDENTIFIER, "payload.admission.claim_id")

    issued_at = _timestamp(value["issued_at"], "payload.issued_at")
    expires_at = _timestamp(value["expires_at"], "payload.expires_at")
    if expires_at <= issued_at:
        raise ControllerAdmissionError("payload.expires_at must be after issued_at")
    if expires_at - issued_at > MAX_VALIDITY:
        raise ControllerAdmissionError("admission receipt validity exceeds 24 hours")
    return value


def _validate_observation_window(
    payload: Mapping[str, object],
    *,
    now: datetime,
    clock_skew: timedelta = timedelta(seconds=60),
) -> None:
    observed = now.astimezone(UTC)
    issued_at = _timestamp(payload["issued_at"], "payload.issued_at")
    expires_at = _timestamp(payload["expires_at"], "payload.expires_at")
    if issued_at > observed + clock_skew:
        raise ControllerAdmissionError("receipt is not yet valid")
    if expires_at <= observed:
        raise ControllerAdmissionError("receipt has expired")


def sign_payload(
    payload: object,
    private_key_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Create a signed envelope for one already-complete admission payload."""

    validated = validate_payload(payload)
    if now is not None:
        _validate_observation_window(validated, now=now)
    key = _load_private_key(private_key_path)
    raw = canonical_payload(validated)
    signature = base64.urlsafe_b64encode(key.sign(raw)).rstrip(b"=").decode("ascii")
    return {
        "schema": SCHEMA,
        "payload": validated,
        "signature": {
            "algorithm": ALGORITHM,
            "key_id": public_key_id(key.public_key()),
            "payload_sha256": payload_digest(validated),
            "value": signature,
        },
    }


def _expected_jobs(
    value: Sequence[str] | None,
) -> tuple[dict[str, str] | None, dict[str, int] | None]:
    if value is None:
        return None, None
    expected: dict[str, str] = {}
    expected_ids: dict[str, int] = {}
    all_have_ids = True
    for item in value:
        name, separator, binding = item.partition("=")
        profile, id_separator, job_id_text = binding.partition(":")
        if not separator or not _IDENTIFIER.fullmatch(name) or not _PROFILE.fullmatch(profile):
            raise ControllerAdmissionError("expected job must use NAME=CONTROLLER_PROFILE[:JOB_ID]")
        if name in expected:
            raise ControllerAdmissionError("expected jobs contain a duplicate name")
        expected[name] = profile
        if id_separator:
            try:
                job_id = int(job_id_text)
            except ValueError as error:
                raise ControllerAdmissionError(
                    "expected job ID must be a positive integer"
                ) from error
            expected_ids[name] = _positive_integer(job_id, "expected job ID")
        else:
            all_have_ids = False
    if not expected:
        raise ControllerAdmissionError("at least one expected job is required")
    if expected_ids and not all_have_ids:
        raise ControllerAdmissionError("expected jobs must either all include job IDs or none do")
    return expected, expected_ids if all_have_ids else None


def verify_receipt(
    receipt: object,
    public_key_path: Path,
    *,
    now: datetime | None = None,
    expected_repository_id: int | None = None,
    expected_repository: str | None = None,
    expected_ref: str | None = None,
    expected_sha: str | None = None,
    expected_evidence: Mapping[str, str] | None = None,
    expected_controller_revision: str | None = None,
    expected_admission_id: str | None = None,
    expected_claim_id: str | None = None,
    expected_jobs: Mapping[str, str] | None = None,
    expected_workflow_run_id: int | None = None,
    expected_workflow_run_attempt: int | None = None,
    expected_job_ids: Mapping[str, int] | None = None,
    clock_skew: timedelta = timedelta(seconds=60),
) -> dict[str, Any]:
    """Verify a receipt and optional exact release expectations."""

    envelope = _mapping(receipt, "receipt")
    _exact_fields(envelope, _TOP_LEVEL_FIELDS, "receipt")
    if envelope["schema"] != SCHEMA:
        raise ControllerAdmissionError(f"receipt.schema must be {SCHEMA}")
    payload = validate_payload(envelope["payload"])
    signature = _mapping(envelope["signature"], "receipt.signature")
    _exact_fields(signature, _SIGNATURE_FIELDS, "receipt.signature")
    if signature["algorithm"] != ALGORITHM:
        raise ControllerAdmissionError("receipt.signature.algorithm must be Ed25519")
    _matched_text(signature["key_id"], _KEY_ID, "receipt.signature.key_id")
    _matched_text(signature["payload_sha256"], _DIGEST, "receipt.signature.payload_sha256")
    encoded_signature = _matched_text(signature["value"], _SIGNATURE, "receipt.signature.value")

    public_key = _load_public_key(public_key_path)
    if signature["key_id"] != public_key_id(public_key):
        raise ControllerAdmissionError("receipt was signed by an unknown admission key")
    raw = canonical_payload(payload)
    if signature["payload_sha256"] != "sha256:" + hashlib.sha256(raw).hexdigest():
        raise ControllerAdmissionError("receipt payload digest does not match")
    try:
        raw_signature = base64.urlsafe_b64decode(encoded_signature + "==")
        public_key.verify(raw_signature, raw)
    except (InvalidSignature, ValueError) as error:
        raise ControllerAdmissionError("receipt signature verification failed") from error

    _validate_observation_window(
        payload,
        now=now or datetime.now(UTC),
        clock_skew=clock_skew,
    )

    repository = _mapping(payload["repository"], "payload.repository")
    workflow = _mapping(payload["workflow"], "payload.workflow")
    workflow_jobs = _mapping_jobs(payload["required_jobs"])
    workflow_job_ids = _mapping_job_ids(payload["required_jobs"])
    evidence = _mapping(payload["evidence"], "payload.evidence")
    admission = _mapping(payload["admission"], "payload.admission")
    exact_expectations: tuple[tuple[str, object, object | None], ...] = (
        ("repository id", repository["id"], expected_repository_id),
        ("repository", repository["full_name"], expected_repository),
        ("protected ref", payload["protected_ref"], expected_ref),
        ("functional source SHA", payload["functional_source_sha"], expected_sha),
        ("admission id", admission["id"], expected_admission_id),
        ("claim id", admission["claim_id"], expected_claim_id),
        ("controller revision", payload["controller_revision"], expected_controller_revision),
        ("workflow run id", workflow["run_id"], expected_workflow_run_id),
        ("workflow run attempt", workflow["run_attempt"], expected_workflow_run_attempt),
    )
    for label, actual, expected in exact_expectations:
        if expected is not None and actual != expected:
            raise ControllerAdmissionError(f"receipt {label} does not match expected value")
    if expected_jobs is not None and workflow_jobs != dict(expected_jobs):
        raise ControllerAdmissionError(
            "receipt required jobs do not match expected job/profile mapping"
        )
    if expected_job_ids is not None and workflow_job_ids != dict(expected_job_ids):
        raise ControllerAdmissionError(
            "receipt required job IDs do not match expected job/ID mapping"
        )
    if expected_evidence is not None and evidence != dict(expected_evidence):
        raise ControllerAdmissionError(
            "receipt evidence digests do not match expected release files"
        )
    return payload


def _mapping_jobs(value: object) -> dict[str, str]:
    if not isinstance(value, list):
        raise ControllerAdmissionError("payload.required_jobs must be a list")
    return {str(job["name"]): str(job["controller_profile"]) for job in value}


def _mapping_job_ids(value: object) -> dict[str, int]:
    if not isinstance(value, list):
        raise ControllerAdmissionError("payload.required_jobs must be a list")
    return {str(job["name"]): int(job["job_id"]) for job in value}


def _validate_replay_store_schema(connection: sqlite3.Connection) -> None:
    schema_row = connection.execute(
        "SELECT type, sql FROM sqlite_master WHERE name = 'consumed_receipts'"
    ).fetchone()
    expected_sql = " ".join(_REPLAY_TABLE_SQL.upper().split())
    if (
        schema_row is None
        or schema_row[0] != "table"
        or not isinstance(schema_row[1], str)
        or " ".join(schema_row[1].upper().split()) != expected_sql
    ):
        raise ControllerAdmissionError("receipt replay store schema is invalid")

    columns = connection.execute("PRAGMA table_info(consumed_receipts)").fetchall()
    expected_columns = [
        ("fingerprint", "TEXT", 0, 1),
        ("key_id", "TEXT", 1, 0),
        ("admission_id", "TEXT", 1, 0),
        ("claim_id", "TEXT", 1, 0),
        ("functional_source_sha", "TEXT", 1, 0),
        ("consumer", "TEXT", 1, 0),
        ("consumed_at", "TEXT", 1, 0),
    ]
    actual_columns = [
        (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5])) for row in columns
    ]
    if actual_columns != expected_columns:
        raise ControllerAdmissionError("receipt replay store schema is invalid")

    unique_columns: set[tuple[str, ...]] = set()
    for index in connection.execute("PRAGMA index_list(consumed_receipts)").fetchall():
        if int(index[2]) != 1 or int(index[4]) != 0:
            continue
        index_name = str(index[1]).replace('"', '""')
        rows = connection.execute(f'PRAGMA index_info("{index_name}")').fetchall()
        unique_columns.add(tuple(str(row[2]) for row in rows))
    required_unique_columns = {
        ("fingerprint",),
        ("admission_id",),
        ("claim_id",),
    }
    if unique_columns != required_unique_columns:
        raise ControllerAdmissionError("receipt replay store uniqueness is invalid")

    triggers = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'consumed_receipts'"
    ).fetchall()
    if triggers:
        raise ControllerAdmissionError("receipt replay store must not contain triggers")


def _consume_verified_receipt(
    receipt: object,
    replay_store_path: Path,
    *,
    consumer: str,
    consumed_at: datetime | None = None,
) -> None:
    """Atomically record one verified receipt before a state-changing action."""

    envelope = _mapping(receipt, "receipt")
    payload = _mapping(envelope.get("payload"), "receipt.payload")
    signature = _mapping(envelope.get("signature"), "receipt.signature")
    consumer_value = _matched_text(consumer, _IDENTIFIER, "consumer")
    key_id = _matched_text(signature.get("key_id"), _KEY_ID, "receipt.signature.key_id")
    signature_value = _matched_text(
        signature.get("value"),
        _SIGNATURE,
        "receipt.signature.value",
    )
    admission = _mapping(payload.get("admission"), "receipt.payload.admission")
    admission_id = _matched_text(admission.get("id"), _IDENTIFIER, "admission.id")
    claim_id = _matched_text(admission.get("claim_id"), _IDENTIFIER, "admission.claim_id")
    functional_source_sha = _matched_text(
        payload.get("functional_source_sha"),
        _SHA,
        "functional_source_sha",
    )
    fingerprint = hashlib.sha256(f"{key_id}:{signature_value}".encode()).hexdigest()
    observed = (consumed_at or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    try:
        replay_store_path.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        parent_status = replay_store_path.parent.stat()
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or parent_status.st_uid not in {os.geteuid(), 0}
            or parent_status.st_mode & 0o022
        ):
            raise ControllerAdmissionError("receipt replay store directory is not owner-controlled")
        if replay_store_path.is_symlink():
            raise ControllerAdmissionError("receipt replay store must not be a symlink")
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(replay_store_path, flags, 0o600)
        try:
            file_status = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_status.st_mode)
                or file_status.st_uid not in {os.geteuid(), 0}
                or stat.S_IMODE(file_status.st_mode) & 0o077
            ):
                raise ControllerAdmissionError(
                    "receipt replay store is not an owner-controlled file"
                )
            with sqlite3.connect(replay_store_path, timeout=5) as connection:
                path_status = replay_store_path.lstat()
                if not stat.S_ISREG(path_status.st_mode) or (
                    path_status.st_dev,
                    path_status.st_ino,
                ) != (file_status.st_dev, file_status.st_ino):
                    raise ControllerAdmissionError(
                        "receipt replay store changed while it was opened"
                    )
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                table_exists = connection.execute(
                    "SELECT 1 FROM sqlite_master WHERE name = 'consumed_receipts'"
                ).fetchone()
                if table_exists is None:
                    connection.execute(_REPLAY_TABLE_SQL)
                _validate_replay_store_schema(connection)
                identity = (
                    fingerprint,
                    key_id,
                    admission_id,
                    claim_id,
                    functional_source_sha,
                    consumer_value,
                )
                try:
                    inserted = connection.execute(
                        """
                        INSERT INTO consumed_receipts (
                            fingerprint,
                            key_id,
                            admission_id,
                            claim_id,
                            functional_source_sha,
                            consumer,
                            consumed_at
                        ) VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (*identity, observed),
                    )
                except sqlite3.IntegrityError as error:
                    existing = connection.execute(
                        """
                        SELECT fingerprint, key_id, admission_id, claim_id,
                               functional_source_sha, consumer
                        FROM consumed_receipts
                        WHERE fingerprint = ? OR admission_id = ? OR claim_id = ?
                        """,
                        (fingerprint, admission_id, claim_id),
                    ).fetchall()
                    if existing != [identity]:
                        raise ControllerAdmissionError(
                            "receipt has already been consumed"
                        ) from error
                else:
                    if inserted.rowcount != 1 or connection.execute(
                        "SELECT changes()"
                    ).fetchone() != (1,):
                        raise ControllerAdmissionError("receipt has already been consumed")
        finally:
            os.close(descriptor)
    except ControllerAdmissionError:
        raise
    except (OSError, sqlite3.Error) as error:
        raise ControllerAdmissionError("receipt replay store is unavailable") from error


def verify_and_consume_receipt(
    receipt: object,
    public_key_path: Path,
    replay_store_path: Path,
    *,
    consumer: str,
    now: datetime | None = None,
    expected_repository_id: int | None = None,
    expected_repository: str | None = None,
    expected_ref: str | None = None,
    expected_sha: str | None = None,
    expected_evidence: Mapping[str, str] | None = None,
    expected_controller_revision: str | None = None,
    expected_admission_id: str | None = None,
    expected_claim_id: str | None = None,
    expected_jobs: Mapping[str, str] | None = None,
    expected_workflow_run_id: int | None = None,
    expected_workflow_run_attempt: int | None = None,
    expected_job_ids: Mapping[str, int] | None = None,
    clock_skew: timedelta = timedelta(seconds=60),
) -> dict[str, Any]:
    """Verify exact bindings and atomically consume a release admission receipt."""

    required_expectations = {
        "expected_repository_id": expected_repository_id,
        "expected_repository": expected_repository,
        "expected_ref": expected_ref,
        "expected_sha": expected_sha,
        "expected_evidence": expected_evidence,
        "expected_controller_revision": expected_controller_revision,
        "expected_admission_id": expected_admission_id,
        "expected_claim_id": expected_claim_id,
        "expected_jobs": expected_jobs,
        "expected_workflow_run_id": expected_workflow_run_id,
        "expected_workflow_run_attempt": expected_workflow_run_attempt,
        "expected_job_ids": expected_job_ids,
    }
    missing = [name for name, value in required_expectations.items() if value is None]
    if missing:
        raise ControllerAdmissionError(
            "receipt consumption requires exact expectations: " + ", ".join(missing)
        )
    assert expected_jobs is not None
    assert expected_job_ids is not None
    if not expected_jobs or set(expected_jobs) != set(expected_job_ids):
        raise ControllerAdmissionError(
            "receipt consumption requires matching non-empty job profile and ID expectations"
        )

    payload = verify_receipt(
        receipt,
        public_key_path,
        now=now,
        expected_repository_id=expected_repository_id,
        expected_repository=expected_repository,
        expected_ref=expected_ref,
        expected_sha=expected_sha,
        expected_evidence=expected_evidence,
        expected_controller_revision=expected_controller_revision,
        expected_admission_id=expected_admission_id,
        expected_claim_id=expected_claim_id,
        expected_jobs=expected_jobs,
        expected_workflow_run_id=expected_workflow_run_id,
        expected_workflow_run_attempt=expected_workflow_run_attempt,
        expected_job_ids=expected_job_ids,
        clock_skew=clock_skew,
    )
    _consume_verified_receipt(
        receipt,
        replay_store_path,
        consumer=consumer,
        consumed_at=now,
    )
    return payload


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(canonical_payload(value) + b"\n")
    os.replace(temporary, path)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Issue and verify QDev controller admission receipts"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    generate = subparsers.add_parser("generate-keypair")
    generate.add_argument("--private-key", required=True, type=Path)
    generate.add_argument("--public-key", required=True, type=Path)

    sign = subparsers.add_parser("sign")
    sign.add_argument("--payload", required=True, type=Path)
    sign.add_argument("--private-key", required=True, type=Path)
    sign.add_argument("--output", required=True, type=Path)

    verify = subparsers.add_parser("verify")
    verify.add_argument("--receipt", required=True, type=Path)
    verify.add_argument("--public-key", required=True, type=Path)
    verify.add_argument("--repository-id", type=int)
    verify.add_argument("--repository")
    verify.add_argument("--protected-ref")
    verify.add_argument("--functional-source-sha")
    verify.add_argument("--release-payload-sha256")
    verify.add_argument("--controller-contract-sha256")
    verify.add_argument("--release-lock-sha256")
    verify.add_argument("--controller-revision")
    verify.add_argument("--admission-id")
    verify.add_argument("--claim-id")
    verify.add_argument("--workflow-run-id", type=int)
    verify.add_argument("--workflow-run-attempt", type=int)
    verify.add_argument("--require-job", action="append")
    verify.add_argument("--consume-ledger", type=Path)
    verify.add_argument("--consumer")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "generate-keypair":
            key_id = initialize_keypair(args.private_key, args.public_key)
            result: object = {"state": "created", "key_id": key_id}
        elif args.command == "sign":
            result = sign_payload(
                load_json_strict(args.payload),
                args.private_key,
                now=datetime.now(UTC),
            )
            _write_json(args.output, result)
            result = {
                "state": "signed",
                "receipt": str(args.output),
                "key_id": result["signature"]["key_id"],
            }
        else:
            receipt = load_json_strict(args.receipt)
            expected_jobs, expected_job_ids = _expected_jobs(args.require_job)
            expected_evidence = None
            evidence_values = (
                args.release_payload_sha256,
                args.controller_contract_sha256,
                args.release_lock_sha256,
            )
            if any(value is not None for value in evidence_values):
                if not all(value is not None for value in evidence_values):
                    raise ControllerAdmissionError(
                        "all three evidence digests must be provided together"
                    )
                expected_evidence = {
                    "release_payload_sha256": args.release_payload_sha256,
                    "controller_contract_sha256": args.controller_contract_sha256,
                    "release_lock_sha256": args.release_lock_sha256,
                }
            if (args.consume_ledger is None) != (args.consumer is None):
                raise ControllerAdmissionError(
                    "--consume-ledger and --consumer must be provided together"
                )
            if args.consume_ledger is not None:
                payload = verify_and_consume_receipt(
                    receipt,
                    args.public_key,
                    args.consume_ledger,
                    consumer=args.consumer,
                    expected_repository_id=args.repository_id,
                    expected_repository=args.repository,
                    expected_ref=args.protected_ref,
                    expected_sha=args.functional_source_sha,
                    expected_evidence=expected_evidence,
                    expected_controller_revision=args.controller_revision,
                    expected_admission_id=args.admission_id,
                    expected_claim_id=args.claim_id,
                    expected_jobs=expected_jobs,
                    expected_workflow_run_id=args.workflow_run_id,
                    expected_workflow_run_attempt=args.workflow_run_attempt,
                    expected_job_ids=expected_job_ids,
                )
            else:
                payload = verify_receipt(
                    receipt,
                    args.public_key,
                    expected_repository_id=args.repository_id,
                    expected_repository=args.repository,
                    expected_ref=args.protected_ref,
                    expected_sha=args.functional_source_sha,
                    expected_evidence=expected_evidence,
                    expected_controller_revision=args.controller_revision,
                    expected_admission_id=args.admission_id,
                    expected_claim_id=args.claim_id,
                    expected_jobs=expected_jobs,
                    expected_workflow_run_id=args.workflow_run_id,
                    expected_workflow_run_attempt=args.workflow_run_attempt,
                    expected_job_ids=expected_job_ids,
                )
            result = {
                "state": "verified",
                "functional_source_sha": payload["functional_source_sha"],
                "workflow_run_id": payload["workflow"]["run_id"],
            }
    except ControllerAdmissionError as error:
        print(f"controller admission rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ControllerAdmissionError",
    "SCHEMA",
    "canonical_payload",
    "initialize_keypair",
    "load_json_strict",
    "main",
    "payload_digest",
    "public_key_id",
    "sign_payload",
    "validate_payload",
    "verify_and_consume_receipt",
    "verify_receipt",
]
