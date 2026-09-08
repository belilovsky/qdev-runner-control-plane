"""Issue and verify Ed25519 provenance for completed QazPipe water runs.

This is deliberately a dedicated receipt family.  It shares the controller's
canonical Ed25519 conventions with admission receipts, but it does not accept
or interpret image provenance, HMAC evidence, or admission payloads.
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
from urllib.parse import urlparse

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

SCHEMA = "qdev-qazpipe-water-provenance/v1"
ALGORITHM = "Ed25519"
MAX_VALIDITY = timedelta(hours=24)

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_REPOSITORY = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_REF = re.compile(r"^refs/heads/[A-Za-z0-9][A-Za-z0-9._/-]{0,254}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_WORKFLOW_NAME = re.compile(r"^[A-Za-z0-9._/-][A-Za-z0-9._:/-]{0,255}$")
_PROFILE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")
_TIME = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")
_URI = re.compile(r"^\S{1,2048}$")

_TOP_LEVEL_FIELDS = frozenset({"schema", "payload", "signature"})
_PAYLOAD_FIELDS = frozenset(
    {
        "repository",
        "protected_ref",
        "source_sha",
        "collector",
        "workflow",
        "artifact",
        "result",
        "controller_revision",
        "receipt",
        "issued_at",
        "expires_at",
    }
)
_REPOSITORY_FIELDS = frozenset({"id", "full_name"})
_COLLECTOR_FIELDS = frozenset({"id"})
_WORKFLOW_FIELDS = frozenset({"name", "run_id", "run_attempt", "job_id", "profile"})
_ARTIFACT_FIELDS = frozenset({"uri", "sha256", "size_bytes"})
_RESULT_FIELDS = frozenset(
    {
        "water_run_id",
        "state",
        "query_plan_sha256",
        "expected_query_count",
        "completed_query_count",
        "manifest_sha256",
        "records_sha256",
        "record_count",
        "source_observed_at",
        "started_at",
        "completed_at",
    }
)
_RECEIPT_FIELDS = frozenset({"id", "claim_id"})
_SIGNATURE_FIELDS = frozenset({"algorithm", "key_id", "payload_sha256", "value"})
_REPLAY_TABLE = "consumed_qazpipe_water_provenance"
_REPLAY_TABLE_SQL = f"""
CREATE TABLE {_REPLAY_TABLE} (
    envelope_sha256 TEXT PRIMARY KEY,
    key_id TEXT NOT NULL,
    receipt_id TEXT NOT NULL UNIQUE,
    claim_id TEXT NOT NULL UNIQUE,
    water_run_id TEXT NOT NULL,
    source_sha TEXT NOT NULL,
    artifact_sha256 TEXT NOT NULL,
    records_sha256 TEXT NOT NULL,
    consumer TEXT NOT NULL,
    consumed_at TEXT NOT NULL
)
"""
_REPLAY_INSERT_SQL = """
INSERT INTO consumed_qazpipe_water_provenance (
    envelope_sha256, key_id, receipt_id, claim_id, water_run_id,
    source_sha, artifact_sha256, records_sha256, consumer, consumed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
"""


class QazPipeWaterProvenanceError(ValueError):
    """Raised when a QazPipe water provenance receipt is invalid or unsafe."""


def _mapping(value: object, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QazPipeWaterProvenanceError(f"{field} must be an object")
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
        raise QazPipeWaterProvenanceError(f"{label} has invalid fields: {'; '.join(detail)}")


def _positive_integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise QazPipeWaterProvenanceError(f"{field} must be a positive integer")
    return value


def _nonnegative_integer(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise QazPipeWaterProvenanceError(f"{field} must be a non-negative integer")
    return value


def _matched_text(value: object, pattern: re.Pattern[str], field: str) -> str:
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise QazPipeWaterProvenanceError(f"{field} is invalid")
    return value


def _timestamp(value: object, field: str) -> datetime:
    text = _matched_text(value, _TIME, field)
    try:
        return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError as error:
        raise QazPipeWaterProvenanceError(f"{field} is invalid") from error


def _uri(value: object, field: str) -> str:
    text = _matched_text(value, _URI, field)
    parsed = urlparse(text)
    if not parsed.scheme or parsed.username is not None or parsed.password is not None:
        raise QazPipeWaterProvenanceError(f"{field} is invalid")
    return text


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise QazPipeWaterProvenanceError(f"JSON contains duplicate key: {key}")
        value[key] = item
    return value


def _reject_constant(value: str) -> None:
    raise QazPipeWaterProvenanceError(f"JSON constant is not permitted: {value}")


def load_json_strict(path: Path) -> object:
    """Load a JSON document while rejecting ambiguous duplicate keys and constants."""

    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except QazPipeWaterProvenanceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise QazPipeWaterProvenanceError(f"cannot load JSON from {path}") from error


def canonical_payload(value: object) -> bytes:
    """Return the stable JSON bytes covered by an Ed25519 signature or digest."""

    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise QazPipeWaterProvenanceError(
            "value cannot be represented as canonical JSON"
        ) from error


def payload_digest(payload: object) -> str:
    """Return the canonical SHA-256 payload digest with its algorithm prefix."""

    return "sha256:" + hashlib.sha256(canonical_payload(payload)).hexdigest()


def envelope_digest(receipt: object) -> str:
    """Return the canonical SHA-256 digest QazLake retains for this envelope."""

    return "sha256:" + hashlib.sha256(canonical_payload(receipt)).hexdigest()


def public_key_id(key: Ed25519PublicKey) -> str:
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def _read_key_file(path: Path, *, label: str, owner_only: bool) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise QazPipeWaterProvenanceError(f"{label} is unavailable or invalid") from error
    try:
        status = os.fstat(descriptor)
        mode = stat.S_IMODE(status.st_mode)
        if not stat.S_ISREG(status.st_mode) or status.st_uid not in {os.geteuid(), 0}:
            raise QazPipeWaterProvenanceError(f"{label} must be a trusted regular file")
        if owner_only:
            if mode & 0o077:
                raise QazPipeWaterProvenanceError(f"{label} must be owner-only")
        elif mode & 0o022:
            raise QazPipeWaterProvenanceError(f"{label} must not be group/world writable")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            return stream.read()
    except OSError as error:
        raise QazPipeWaterProvenanceError(f"{label} is unavailable or invalid") from error
    finally:
        os.close(descriptor)


def _load_private_key(path: Path) -> Ed25519PrivateKey:
    try:
        key = serialization.load_pem_private_key(
            _read_key_file(path, label="water provenance private key", owner_only=True),
            password=None,
        )
    except QazPipeWaterProvenanceError:
        raise
    except ValueError as error:
        raise QazPipeWaterProvenanceError("water provenance private key is invalid") from error
    if not isinstance(key, Ed25519PrivateKey):
        raise QazPipeWaterProvenanceError("water provenance private key is not Ed25519")
    return key


def _load_public_key(path: Path) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(
            _read_key_file(path, label="water provenance public key", owner_only=False)
        )
    except QazPipeWaterProvenanceError:
        raise
    except ValueError as error:
        raise QazPipeWaterProvenanceError("water provenance public key is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise QazPipeWaterProvenanceError("water provenance public key is not Ed25519")
    return key


def initialize_keypair(private_key_path: Path, public_key_path: Path) -> str:
    """Create an Ed25519 keypair without overwriting either destination."""

    if (
        private_key_path.exists()
        or private_key_path.is_symlink()
        or public_key_path.exists()
        or public_key_path.is_symlink()
    ):
        raise QazPipeWaterProvenanceError("water provenance key path already exists")
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
    try:
        private_descriptor = os.open(
            private_key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        with os.fdopen(private_descriptor, "wb") as stream:
            stream.write(private_bytes)
            stream.flush()
            os.fsync(stream.fileno())
        public_descriptor = os.open(
            public_key_path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0),
            0o644,
        )
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
    """Validate the complete, fixed QazPipe water provenance payload."""

    value = _mapping(payload, "payload")
    _exact_fields(value, _PAYLOAD_FIELDS, "payload")

    repository = _mapping(value["repository"], "payload.repository")
    _exact_fields(repository, _REPOSITORY_FIELDS, "payload.repository")
    _positive_integer(repository["id"], "payload.repository.id")
    _matched_text(repository["full_name"], _REPOSITORY, "payload.repository.full_name")
    _matched_text(value["protected_ref"], _REF, "payload.protected_ref")
    _matched_text(value["source_sha"], _SHA, "payload.source_sha")

    collector = _mapping(value["collector"], "payload.collector")
    _exact_fields(collector, _COLLECTOR_FIELDS, "payload.collector")
    if collector["id"] != "geo-003":
        raise QazPipeWaterProvenanceError("payload.collector.id must be geo-003")

    workflow = _mapping(value["workflow"], "payload.workflow")
    _exact_fields(workflow, _WORKFLOW_FIELDS, "payload.workflow")
    _matched_text(workflow["name"], _WORKFLOW_NAME, "payload.workflow.name")
    _positive_integer(workflow["run_id"], "payload.workflow.run_id")
    _positive_integer(workflow["run_attempt"], "payload.workflow.run_attempt")
    _positive_integer(workflow["job_id"], "payload.workflow.job_id")
    _matched_text(workflow["profile"], _PROFILE, "payload.workflow.profile")

    artifact = _mapping(value["artifact"], "payload.artifact")
    _exact_fields(artifact, _ARTIFACT_FIELDS, "payload.artifact")
    _uri(artifact["uri"], "payload.artifact.uri")
    _matched_text(artifact["sha256"], _DIGEST, "payload.artifact.sha256")
    _positive_integer(artifact["size_bytes"], "payload.artifact.size_bytes")

    result = _mapping(value["result"], "payload.result")
    _exact_fields(result, _RESULT_FIELDS, "payload.result")
    _matched_text(result["water_run_id"], _IDENTIFIER, "payload.result.water_run_id")
    if result["state"] != "complete":
        raise QazPipeWaterProvenanceError("payload.result.state must be complete")
    _matched_text(result["query_plan_sha256"], _DIGEST, "payload.result.query_plan_sha256")
    expected_queries = _positive_integer(
        result["expected_query_count"], "payload.result.expected_query_count"
    )
    completed_queries = _positive_integer(
        result["completed_query_count"], "payload.result.completed_query_count"
    )
    if completed_queries != expected_queries:
        raise QazPipeWaterProvenanceError(
            "payload.result.completed_query_count must equal expected_query_count"
        )
    _matched_text(result["manifest_sha256"], _DIGEST, "payload.result.manifest_sha256")
    _matched_text(result["records_sha256"], _DIGEST, "payload.result.records_sha256")
    _nonnegative_integer(result["record_count"], "payload.result.record_count")
    source_observed_at = _timestamp(
        result["source_observed_at"], "payload.result.source_observed_at"
    )
    started_at = _timestamp(result["started_at"], "payload.result.started_at")
    completed_at = _timestamp(result["completed_at"], "payload.result.completed_at")
    if source_observed_at > completed_at:
        raise QazPipeWaterProvenanceError(
            "payload.result.source_observed_at must not be after completed_at"
        )
    if started_at > completed_at:
        raise QazPipeWaterProvenanceError(
            "payload.result.started_at must not be after completed_at"
        )

    _matched_text(value["controller_revision"], _SHA, "payload.controller_revision")
    receipt = _mapping(value["receipt"], "payload.receipt")
    _exact_fields(receipt, _RECEIPT_FIELDS, "payload.receipt")
    _matched_text(receipt["id"], _IDENTIFIER, "payload.receipt.id")
    _matched_text(receipt["claim_id"], _IDENTIFIER, "payload.receipt.claim_id")

    issued_at = _timestamp(value["issued_at"], "payload.issued_at")
    expires_at = _timestamp(value["expires_at"], "payload.expires_at")
    if issued_at < completed_at:
        raise QazPipeWaterProvenanceError("payload.issued_at must not be before completed_at")
    if expires_at <= issued_at:
        raise QazPipeWaterProvenanceError("payload.expires_at must be after issued_at")
    if expires_at - issued_at > MAX_VALIDITY:
        raise QazPipeWaterProvenanceError("water provenance receipt validity exceeds 24 hours")
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
        raise QazPipeWaterProvenanceError("receipt is not yet valid")
    if expires_at <= observed:
        raise QazPipeWaterProvenanceError("receipt has expired")


def sign_payload(
    payload: object,
    private_key_path: Path,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Sign one already-complete QazPipe water result with the controller key."""

    validated = validate_payload(payload)
    if now is not None:
        _validate_observation_window(validated, now=now)
    key = _load_private_key(private_key_path)
    raw = canonical_payload(validated)
    return {
        "schema": SCHEMA,
        "payload": validated,
        "signature": {
            "algorithm": ALGORITHM,
            "key_id": public_key_id(key.public_key()),
            "payload_sha256": payload_digest(validated),
            "value": base64.urlsafe_b64encode(key.sign(raw)).rstrip(b"=").decode("ascii"),
        },
    }


def _first_mismatch(actual: object, expected: object, field: str) -> str | None:
    if isinstance(expected, Mapping):
        if not isinstance(actual, Mapping):
            return field
        for key in sorted(expected):
            mismatch = _first_mismatch(actual.get(key), expected[key], f"{field}.{key}")
            if mismatch is not None:
                return mismatch
        return None
    if actual != expected:
        return field
    return None


def verify_receipt(
    receipt: object,
    trusted_key_pem: Path,
    *,
    trusted_key_id: str,
    now: datetime | None = None,
    expected_payload: Mapping[str, object] | None = None,
    expected_receipt_sha256: str | None = None,
    clock_skew: timedelta = timedelta(seconds=60),
) -> dict[str, Any]:
    """Verify one envelope against a pinned PEM/key ID and optional exact bindings."""

    envelope = _mapping(receipt, "receipt")
    _exact_fields(envelope, _TOP_LEVEL_FIELDS, "receipt")
    if envelope["schema"] != SCHEMA:
        raise QazPipeWaterProvenanceError(f"receipt.schema must be {SCHEMA}")
    payload = validate_payload(envelope["payload"])
    signature = _mapping(envelope["signature"], "receipt.signature")
    _exact_fields(signature, _SIGNATURE_FIELDS, "receipt.signature")
    if signature["algorithm"] != ALGORITHM:
        raise QazPipeWaterProvenanceError("receipt.signature.algorithm must be Ed25519")
    key_id = _matched_text(signature["key_id"], _DIGEST, "receipt.signature.key_id")
    signed_digest = _matched_text(
        signature["payload_sha256"], _DIGEST, "receipt.signature.payload_sha256"
    )
    encoded_signature = _matched_text(signature["value"], _SIGNATURE, "receipt.signature.value")
    expected_key_id = _matched_text(trusted_key_id, _DIGEST, "trusted key ID")

    public_key = _load_public_key(trusted_key_pem)
    actual_key_id = public_key_id(public_key)
    if expected_key_id != actual_key_id:
        raise QazPipeWaterProvenanceError("trusted key ID does not match trusted PEM")
    if key_id != expected_key_id:
        raise QazPipeWaterProvenanceError("receipt was signed by an untrusted water provenance key")
    raw = canonical_payload(payload)
    if signed_digest != payload_digest(payload):
        raise QazPipeWaterProvenanceError("receipt payload digest does not match")
    try:
        public_key.verify(base64.urlsafe_b64decode(encoded_signature + "=="), raw)
    except (InvalidSignature, ValueError) as error:
        raise QazPipeWaterProvenanceError("receipt signature verification failed") from error

    _validate_observation_window(payload, now=now or datetime.now(UTC), clock_skew=clock_skew)
    if expected_payload is not None:
        validated_expected = validate_payload(dict(expected_payload))
        mismatch = _first_mismatch(payload, validated_expected, "payload")
        if mismatch is not None:
            raise QazPipeWaterProvenanceError(
                f"receipt {mismatch} does not match the exact expected value"
            )
    if expected_receipt_sha256 is not None:
        expected_digest = _matched_text(
            expected_receipt_sha256, _DIGEST, "expected receipt SHA-256"
        )
        if envelope_digest(envelope) != expected_digest:
            raise QazPipeWaterProvenanceError("receipt envelope digest does not match")
    return payload


def _validate_replay_store_schema(connection: sqlite3.Connection) -> None:
    schema_row = connection.execute(
        "SELECT type, sql FROM sqlite_master WHERE name = ?", (_REPLAY_TABLE,)
    ).fetchone()
    expected_sql = " ".join(_REPLAY_TABLE_SQL.upper().split())
    if (
        schema_row is None
        or schema_row[0] != "table"
        or not isinstance(schema_row[1], str)
        or " ".join(schema_row[1].upper().split()) != expected_sql
    ):
        raise QazPipeWaterProvenanceError("water provenance replay ledger schema is invalid")

    columns = connection.execute(f"PRAGMA table_info({_REPLAY_TABLE})").fetchall()
    expected_columns = [
        ("envelope_sha256", "TEXT", 0, 1),
        ("key_id", "TEXT", 1, 0),
        ("receipt_id", "TEXT", 1, 0),
        ("claim_id", "TEXT", 1, 0),
        ("water_run_id", "TEXT", 1, 0),
        ("source_sha", "TEXT", 1, 0),
        ("artifact_sha256", "TEXT", 1, 0),
        ("records_sha256", "TEXT", 1, 0),
        ("consumer", "TEXT", 1, 0),
        ("consumed_at", "TEXT", 1, 0),
    ]
    actual_columns = [
        (str(row[1]), str(row[2]).upper(), int(row[3]), int(row[5])) for row in columns
    ]
    if actual_columns != expected_columns:
        raise QazPipeWaterProvenanceError("water provenance replay ledger schema is invalid")

    unique_columns: set[tuple[str, ...]] = set()
    for index in connection.execute(f"PRAGMA index_list({_REPLAY_TABLE})").fetchall():
        if int(index[2]) != 1 or int(index[4]) != 0:
            continue
        index_name = str(index[1]).replace('"', '""')
        rows = connection.execute(f'PRAGMA index_info("{index_name}")').fetchall()
        unique_columns.add(tuple(str(row[2]) for row in rows))
    if unique_columns != {("envelope_sha256",), ("receipt_id",), ("claim_id",)}:
        raise QazPipeWaterProvenanceError("water provenance replay ledger uniqueness is invalid")

    triggers = connection.execute(
        "SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = ?", (_REPLAY_TABLE,)
    ).fetchall()
    if triggers:
        raise QazPipeWaterProvenanceError(
            "water provenance replay ledger must not contain triggers"
        )


def _consume_verified_receipt(
    receipt: object,
    replay_ledger: Path,
    *,
    consumer: str,
    consumed_at: datetime | None = None,
) -> None:
    """Persist one verified receipt once, before QazLake changes publication state."""

    envelope = _mapping(receipt, "receipt")
    payload = _mapping(envelope["payload"], "receipt.payload")
    signature = _mapping(envelope["signature"], "receipt.signature")
    result = _mapping(payload["result"], "receipt.payload.result")
    artifact = _mapping(payload["artifact"], "receipt.payload.artifact")
    receipt_binding = _mapping(payload["receipt"], "receipt.payload.receipt")
    identity = (
        envelope_digest(envelope),
        _matched_text(signature["key_id"], _DIGEST, "receipt.signature.key_id"),
        _matched_text(receipt_binding["id"], _IDENTIFIER, "receipt.id"),
        _matched_text(receipt_binding["claim_id"], _IDENTIFIER, "receipt.claim_id"),
        _matched_text(result["water_run_id"], _IDENTIFIER, "result.water_run_id"),
        _matched_text(payload["source_sha"], _SHA, "source_sha"),
        _matched_text(artifact["sha256"], _DIGEST, "artifact.sha256"),
        _matched_text(result["records_sha256"], _DIGEST, "result.records_sha256"),
        _matched_text(consumer, _IDENTIFIER, "consumer"),
    )
    observed = (consumed_at or datetime.now(UTC)).astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    try:
        replay_ledger.parent.mkdir(parents=True, exist_ok=True, mode=0o750)
        parent_status = replay_ledger.parent.stat()
        if (
            not stat.S_ISDIR(parent_status.st_mode)
            or parent_status.st_uid not in {os.geteuid(), 0}
            or parent_status.st_mode & 0o022
        ):
            raise QazPipeWaterProvenanceError(
                "water provenance replay ledger directory is not owner-controlled"
            )
        if replay_ledger.is_symlink():
            raise QazPipeWaterProvenanceError(
                "water provenance replay ledger must not be a symlink"
            )
        descriptor = os.open(
            replay_ledger,
            os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            file_status = os.fstat(descriptor)
            if (
                not stat.S_ISREG(file_status.st_mode)
                or file_status.st_uid not in {os.geteuid(), 0}
                or stat.S_IMODE(file_status.st_mode) & 0o077
            ):
                raise QazPipeWaterProvenanceError(
                    "water provenance replay ledger is not an owner-controlled file"
                )
            with sqlite3.connect(replay_ledger, timeout=5) as connection:
                path_status = replay_ledger.lstat()
                if not stat.S_ISREG(path_status.st_mode) or (
                    path_status.st_dev,
                    path_status.st_ino,
                ) != (file_status.st_dev, file_status.st_ino):
                    raise QazPipeWaterProvenanceError(
                        "water provenance replay ledger changed while it was opened"
                    )
                connection.execute("PRAGMA trusted_schema=OFF")
                connection.execute("PRAGMA synchronous=FULL")
                connection.execute("BEGIN IMMEDIATE")
                if (
                    connection.execute(
                        "SELECT 1 FROM sqlite_master WHERE name = ?", (_REPLAY_TABLE,)
                    ).fetchone()
                    is None
                ):
                    connection.execute(_REPLAY_TABLE_SQL)
                _validate_replay_store_schema(connection)
                try:
                    inserted = connection.execute(_REPLAY_INSERT_SQL, (*identity, observed))
                except sqlite3.IntegrityError as error:
                    raise QazPipeWaterProvenanceError(
                        "water provenance receipt has already been consumed"
                    ) from error
                changes = connection.execute("SELECT changes()").fetchone()
                if inserted.rowcount != 1 or changes != (1,):
                    raise QazPipeWaterProvenanceError(
                        "water provenance receipt has already been consumed"
                    )
        finally:
            os.close(descriptor)
    except QazPipeWaterProvenanceError:
        raise
    except (OSError, sqlite3.Error) as error:
        raise QazPipeWaterProvenanceError(
            "water provenance replay ledger is unavailable"
        ) from error


def verify_and_consume_receipt(
    receipt: object,
    trusted_key_pem: Path,
    replay_ledger: Path,
    *,
    consumer: str,
    trusted_key_id: str,
    expected_payload: Mapping[str, object] | None = None,
    expected_receipt_sha256: str | None = None,
    now: datetime | None = None,
    clock_skew: timedelta = timedelta(seconds=60),
) -> dict[str, Any]:
    """Verify every QazLake binding and atomically reject any replay."""

    if expected_payload is None or expected_receipt_sha256 is None:
        raise QazPipeWaterProvenanceError(
            "water provenance consumption requires an exact payload and receipt digest"
        )
    payload = verify_receipt(
        receipt,
        trusted_key_pem,
        trusted_key_id=trusted_key_id,
        now=now,
        expected_payload=expected_payload,
        expected_receipt_sha256=expected_receipt_sha256,
        clock_skew=clock_skew,
    )
    _consume_verified_receipt(receipt, replay_ledger, consumer=consumer, consumed_at=now)
    return payload


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_bytes(canonical_payload(value) + b"\n")
    os.replace(temporary, path)


def _expected_payload_from_args(args: argparse.Namespace) -> dict[str, object]:
    return {
        "repository": {"id": args.repository_id, "full_name": args.repository_full_name},
        "protected_ref": args.protected_ref,
        "source_sha": args.source_sha,
        "collector": {"id": args.collector_id},
        "workflow": {
            "name": args.workflow_name,
            "run_id": args.workflow_run_id,
            "run_attempt": args.workflow_run_attempt,
            "job_id": args.workflow_job_id,
            "profile": args.workflow_profile,
        },
        "artifact": {
            "uri": args.artifact_uri,
            "sha256": args.artifact_sha256,
            "size_bytes": args.artifact_size_bytes,
        },
        "result": {
            "water_run_id": args.water_run_id,
            "state": args.water_state,
            "query_plan_sha256": args.query_plan_sha256,
            "expected_query_count": args.expected_query_count,
            "completed_query_count": args.completed_query_count,
            "manifest_sha256": args.manifest_sha256,
            "records_sha256": args.records_sha256,
            "record_count": args.record_count,
            "source_observed_at": args.source_observed_at,
            "started_at": args.started_at,
            "completed_at": args.completed_at,
        },
        "controller_revision": args.controller_revision,
        "receipt": {"id": args.receipt_id, "claim_id": args.claim_id},
        "issued_at": args.issued_at,
        "expires_at": args.expires_at,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Issue and verify QazPipe-to-QazLake water provenance receipts"
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
    verify.add_argument("--trusted-key-pem", required=True, type=Path)
    verify.add_argument("--trusted-key-id", required=True)
    verify.add_argument("--repository-id", required=True, type=int)
    verify.add_argument("--repository-full-name", required=True)
    verify.add_argument("--protected-ref", required=True)
    verify.add_argument("--source-sha", required=True)
    verify.add_argument("--collector-id", required=True)
    verify.add_argument("--workflow-name", required=True)
    verify.add_argument("--workflow-run-id", required=True, type=int)
    verify.add_argument("--workflow-run-attempt", required=True, type=int)
    verify.add_argument("--workflow-job-id", required=True, type=int)
    verify.add_argument("--workflow-profile", required=True)
    verify.add_argument("--artifact-uri", required=True)
    verify.add_argument("--artifact-sha256", required=True)
    verify.add_argument("--artifact-size-bytes", required=True, type=int)
    verify.add_argument("--water-run-id", required=True)
    verify.add_argument("--water-state", required=True)
    verify.add_argument("--query-plan-sha256", required=True)
    verify.add_argument("--expected-query-count", required=True, type=int)
    verify.add_argument("--completed-query-count", required=True, type=int)
    verify.add_argument("--manifest-sha256", required=True)
    verify.add_argument("--records-sha256", required=True)
    verify.add_argument("--record-count", required=True, type=int)
    verify.add_argument("--source-observed-at", required=True)
    verify.add_argument("--started-at", required=True)
    verify.add_argument("--completed-at", required=True)
    verify.add_argument("--controller-revision", required=True)
    verify.add_argument("--receipt-id", required=True)
    verify.add_argument("--claim-id", required=True)
    verify.add_argument("--issued-at", required=True)
    verify.add_argument("--expires-at", required=True)
    verify.add_argument("--expected-receipt-sha256", required=True)
    verify.add_argument("--consume-ledger", type=Path)
    verify.add_argument("--consumer")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "generate-keypair":
            result: object = {
                "state": "created",
                "key_id": initialize_keypair(args.private_key, args.public_key),
            }
        elif args.command == "sign":
            receipt = sign_payload(
                load_json_strict(args.payload), args.private_key, now=datetime.now(UTC)
            )
            _write_json(args.output, receipt)
            result = {
                "state": "signed",
                "receipt": str(args.output),
                "receipt_sha256": envelope_digest(receipt),
                "key_id": receipt["signature"]["key_id"],
            }
        else:
            if (args.consume_ledger is None) != (args.consumer is None):
                raise QazPipeWaterProvenanceError(
                    "--consume-ledger and --consumer must be provided together"
                )
            loaded_receipt = load_json_strict(args.receipt)
            expected_payload = _expected_payload_from_args(args)
            if args.consume_ledger is None:
                payload = verify_receipt(
                    loaded_receipt,
                    args.trusted_key_pem,
                    trusted_key_id=args.trusted_key_id,
                    expected_payload=expected_payload,
                    expected_receipt_sha256=args.expected_receipt_sha256,
                )
                state = "verified"
            else:
                payload = verify_and_consume_receipt(
                    loaded_receipt,
                    args.trusted_key_pem,
                    args.consume_ledger,
                    consumer=args.consumer,
                    trusted_key_id=args.trusted_key_id,
                    expected_payload=expected_payload,
                    expected_receipt_sha256=args.expected_receipt_sha256,
                )
                state = "consumed"
            result = {
                "state": state,
                "receipt_sha256": envelope_digest(loaded_receipt),
                "receipt_id": payload["receipt"]["id"],
                "claim_id": payload["receipt"]["claim_id"],
                "water_run_id": payload["result"]["water_run_id"],
                "artifact_sha256": payload["artifact"]["sha256"],
                "records_sha256": payload["result"]["records_sha256"],
            }
    except QazPipeWaterProvenanceError as error:
        print(f"QazPipe water provenance rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "ALGORITHM",
    "SCHEMA",
    "QazPipeWaterProvenanceError",
    "canonical_payload",
    "envelope_digest",
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
