from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

HARD_MIN_FREE_GIB = 4.5
HARD_MAX_DISK_USED_PCT = 95.0
MAX_OVERRIDE_SECONDS = 15 * 60
DISK_ONLY_BLOCKERS = frozenset({"disk_free_gib", "disk_used_pct"})

_WORKER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def utc_now() -> datetime:
    return datetime.now(UTC)


def format_utc(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must be timezone-aware")
    return parsed.astimezone(UTC)


def _canonical(payload: Mapping[str, Any]) -> bytes:
    return json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")


def payload_digest(payload: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def sign_payload(payload: Mapping[str, Any], key: str) -> str:
    return hmac.new(key.encode("utf-8"), _canonical(payload), hashlib.sha256).hexdigest()


_RECEIPT_PAYLOAD_FIELDS: dict[str, set[str]] = {
    "controller-release-audit": {"kind", "observed_at", "controller_release"},
    "admin-platform-audit": {
        "kind",
        "observed_at",
        "controller_release",
        "managed_registry",
        "admin_platform_ledger",
        "active_candidate",
        "admission",
    },
    "worker-audit": {"kind", "observed_at", "workers", "pending"},
    "fifo-claim-scope-issued": {
        "kind",
        "operator_session",
        "mtls_identity",
        "idempotent",
        "claim_scope",
        "immutable_tuple",
        "worker",
        "managed_registry_entry",
        "admission_ledger",
        "admin_platform_ledger_entry",
        "managed_release_ledger_entry",
    },
    "capacity-override-created": {
        "kind",
        "observed_at",
        "worker_audit",
        "operation",
        "required_free_gib",
    },
    "capacity-override-cancelled": {"kind", "observed_at", "worker_audit", "operation"},
    "stale-job-audit": {
        "kind",
        "observed_at",
        "worker_timeout_seconds",
        "provider_reconciliation_required",
        "candidates",
    },
    "stale-job-recovery": {
        "kind",
        "observed_at",
        "owner",
        "reason",
        "immutable_job",
        "provider",
        "action",
        "fifo_preserved",
    },
    "fleet-bootstrap-recovery": {
        "kind",
        "observed_at",
        "status",
        "operation_status",
        "idempotency_key",
        "request_fingerprint",
        "worker_name",
        "target_id",
        "service_unit",
        "active_jobs",
        "error_code",
        "result",
    },
}


def validate_controller_receipt_payload(payload: Mapping[str, Any]) -> dict[str, Any]:
    """Validate the v2 discriminator before a controller receipt is signed.

    Nested controller records are themselves schema-owned by the broker. This
    boundary deliberately fixes each receipt kind and its complete top-level
    payload so an arbitrary signed object can never become enforced evidence.
    """
    value = dict(payload)
    kind = str(value.get("kind"))
    expected = _RECEIPT_PAYLOAD_FIELDS.get(kind)
    if expected is None:
        raise ValueError("unsupported controller receipt kind")
    if kind == "fifo-claim-scope-issued" and value.get("idempotent") is False:
        expected = expected | {
            "replaced_expired_scope",
            "rolled_over_terminal_scope",
            "rebound_legacy_scope",
        }
    if set(value) != expected:
        raise ValueError("controller receipt payload fields are invalid")
    if kind != "fifo-claim-scope-issued" and not isinstance(value.get("observed_at"), str):
        raise ValueError("controller receipt observed_at is invalid")
    if kind == "controller-release-audit" and not isinstance(value["controller_release"], dict):
        raise ValueError("controller release payload is invalid")
    if kind == "admin-platform-audit" and (
        not isinstance(value["controller_release"], dict)
        or not isinstance(value["managed_registry"], dict)
        or not isinstance(value["admin_platform_ledger"], dict)
        or not isinstance(value["active_candidate"], str)
        or not isinstance(value["admission"], dict)
    ):
        raise ValueError("admin platform audit payload is invalid")
    if kind == "worker-audit" and (
        not isinstance(value["workers"], list)
        or not isinstance(value["pending"], int)
        or value["pending"] < 0
    ):
        raise ValueError("worker audit payload is invalid")
    if kind == "fifo-claim-scope-issued" and (
        value["operator_session"] != "verified"
        or not isinstance(value["mtls_identity"], str)
        or not isinstance(value["idempotent"], bool)
        or not isinstance(value["claim_scope"], dict)
        or not isinstance(value["immutable_tuple"], dict)
        or not isinstance(value["worker"], dict)
        or (
            value["managed_registry_entry"] is not None
            and (
                not isinstance(value["managed_registry_entry"], str)
                or not _WORKER_NAME.fullmatch(value["managed_registry_entry"])
            )
        )
        or value["admission_ledger"] not in {None, "admin-platform", "managed-production"}
        or any(
            value[field] is not None
            and (not isinstance(value[field], str) or not _WORKER_NAME.fullmatch(value[field]))
            for field in ("admin_platform_ledger_entry", "managed_release_ledger_entry")
        )
        or (
            value["managed_registry_entry"] is None
            and any(
                value[field] is not None
                for field in (
                    "admission_ledger",
                    "admin_platform_ledger_entry",
                    "managed_release_ledger_entry",
                )
            )
        )
        or (
            value["managed_registry_entry"] is not None
            and (
                (
                    value["admission_ledger"] == "admin-platform"
                    and value["admin_platform_ledger_entry"] != value["managed_registry_entry"]
                )
                or (
                    value["admission_ledger"] == "managed-production"
                    and value["managed_release_ledger_entry"] != value["managed_registry_entry"]
                )
                or (
                    value["admission_ledger"] == "admin-platform"
                    and value["managed_release_ledger_entry"] is not None
                )
                or (
                    value["admission_ledger"] == "managed-production"
                    and value["admin_platform_ledger_entry"] is not None
                )
                or value["admission_ledger"] is None
            )
        )
    ):
        raise ValueError("claim-scope payload is invalid")
    if kind.startswith("capacity-override") and not isinstance(value["worker_audit"], dict):
        raise ValueError("capacity override payload is invalid")
    if kind == "capacity-override-created" and (
        not isinstance(value["operation"], dict)
        or not isinstance(value["required_free_gib"], (int, float))
    ):
        raise ValueError("capacity override creation payload is invalid")
    if kind == "capacity-override-cancelled" and not (
        isinstance(value["operation"], dict) or value["operation"] is None
    ):
        raise ValueError("capacity override cancellation payload is invalid")
    if kind == "stale-job-audit" and (
        not isinstance(value["worker_timeout_seconds"], int)
        or not isinstance(value["provider_reconciliation_required"], bool)
        or not isinstance(value["candidates"], list)
    ):
        raise ValueError("stale-job audit payload is invalid")
    if kind == "stale-job-recovery" and (
        not isinstance(value["immutable_job"], dict)
        or not isinstance(value["provider"], dict)
        or not isinstance(value["owner"], str)
        or not isinstance(value["reason"], str)
        or not isinstance(value["action"], str)
        or value["fifo_preserved"] is not True
    ):
        raise ValueError("stale-job recovery payload is invalid")
    if kind == "fleet-bootstrap-recovery" and (
        value["status"]
        not in {"completed", "access_blocked", "active_work", "target_unregistered", "failed"}
        or value["operation_status"] not in {"pending", "completed"}
        or not isinstance(value["idempotency_key"], str)
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}", value["idempotency_key"])
        or not isinstance(value["request_fingerprint"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["request_fingerprint"])
        or not isinstance(value["worker_name"], str)
        or not _WORKER_NAME.fullmatch(value["worker_name"])
        or (value["target_id"] is not None and not isinstance(value["target_id"], str))
        or (value["service_unit"] is not None and not isinstance(value["service_unit"], str))
        or isinstance(value["active_jobs"], bool)
        or not isinstance(value["active_jobs"], int)
        or value["active_jobs"] < 0
        or (value["error_code"] is not None and not isinstance(value["error_code"], str))
        or (value["result"] is not None and not isinstance(value["result"], dict))
    ):
        raise ValueError("fleet bootstrap recovery payload is invalid")
    return value


class CapacityOverrideDirective(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["qdev-capacity-override-v1"] = Field(alias="schema")
    operation_id: str = Field(min_length=1, max_length=128)
    worker_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    repository: str = Field(min_length=1, max_length=256)
    profiles: tuple[str, ...] = Field(min_length=1)
    min_disk_free_gib: float = Field(ge=HARD_MIN_FREE_GIB)
    max_disk_used_pct: float = Field(ge=0, le=HARD_MAX_DISK_USED_PCT)
    owner: str = Field(min_length=1, max_length=200)
    reason: str = Field(min_length=1, max_length=1000)
    issued_at: str = Field(min_length=1, max_length=64)
    expires_at: str = Field(min_length=1, max_length=64)
    status: Literal["active", "cancelled"] = "active"
    cancelled_at: str | None = None
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")

    def unsigned(self) -> dict[str, Any]:
        return self.model_dump(mode="json", by_alias=True, exclude={"signature"})


def verify_capacity_override(
    payload: Mapping[str, Any],
    *,
    signing_key: str,
    worker_name: str,
    registered_profiles: tuple[str, ...],
    now: datetime | None = None,
) -> CapacityOverrideDirective:
    if not signing_key:
        raise ValueError("capacity override signing key is empty")
    try:
        directive = CapacityOverrideDirective.model_validate(payload)
    except ValidationError as exc:
        raise ValueError("invalid capacity override document") from exc
    if not hmac.compare_digest(
        directive.signature,
        sign_payload(directive.unsigned(), signing_key),
    ):
        raise ValueError("invalid capacity override signature")
    if directive.status != "active":
        raise ValueError("capacity override is not active")
    if directive.worker_name != worker_name:
        raise ValueError("capacity override worker mismatch")
    if not directive.profiles or not set(directive.profiles).issubset(registered_profiles):
        raise ValueError("capacity override profile mismatch")
    if directive.min_disk_free_gib < HARD_MIN_FREE_GIB:
        raise ValueError("capacity override violates hard free-space floor")
    if directive.max_disk_used_pct > HARD_MAX_DISK_USED_PCT:
        raise ValueError("capacity override violates hard disk-use ceiling")
    issued_at = parse_utc(directive.issued_at)
    expires_at = parse_utc(directive.expires_at)
    checked_at = now or utc_now()
    if issued_at > checked_at + timedelta(seconds=60):
        raise ValueError("capacity override was issued in the future")
    if expires_at <= checked_at:
        raise ValueError("capacity override has expired")
    if expires_at - issued_at > timedelta(seconds=MAX_OVERRIDE_SECONDS):
        raise ValueError("capacity override lifetime exceeds maximum")
    return directive


class OperationStore:
    def __init__(self, root: Path, *, worker_signing_key: str, receipt_signing_key: str) -> None:
        if not worker_signing_key or not receipt_signing_key:
            raise ValueError("operation signing keys are required")
        self.root = root
        self.worker_signing_key = worker_signing_key
        self.receipt_signing_key = receipt_signing_key
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)

    def _path(self, worker_name: str) -> Path:
        if not _WORKER_NAME.fullmatch(worker_name):
            raise ValueError("invalid worker name")
        return self.root / f"{worker_name}.json"

    def _write(self, worker_name: str, payload: Mapping[str, Any]) -> None:
        path = self._path(worker_name)
        temporary = self.root / f".{worker_name}.{secrets.token_hex(8)}.tmp"
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                json.dump(payload, stream, sort_keys=True, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if temporary.exists():
                temporary.unlink()

    def active(
        self,
        worker_name: str,
        *,
        registered_profiles: tuple[str, ...],
        now: datetime | None = None,
    ) -> CapacityOverrideDirective | None:
        path = self._path(worker_name)
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return None
        if not isinstance(payload, dict):
            return None
        try:
            return verify_capacity_override(
                payload,
                signing_key=self.worker_signing_key,
                worker_name=worker_name,
                registered_profiles=registered_profiles,
                now=now,
            )
        except ValueError:
            return None

    def create_capacity_override(
        self,
        *,
        worker_name: str,
        repository: str,
        profiles: tuple[str, ...],
        min_disk_free_gib: float,
        max_disk_used_pct: float,
        owner: str,
        reason: str,
        duration_seconds: int,
        now: datetime | None = None,
    ) -> CapacityOverrideDirective:
        if not profiles:
            raise ValueError("at least one profile is required")
        if min_disk_free_gib < HARD_MIN_FREE_GIB:
            raise ValueError("minimum free space is below the hard floor")
        if max_disk_used_pct > HARD_MAX_DISK_USED_PCT:
            raise ValueError("maximum disk use is above the hard ceiling")
        if max_disk_used_pct < 0:
            raise ValueError("maximum disk use cannot be negative")
        if not 1 <= duration_seconds <= MAX_OVERRIDE_SECONDS:
            raise ValueError("override lifetime is outside the allowed range")
        if not owner.strip() or not reason.strip():
            raise ValueError("owner and reason are required")
        issued_at = now or utc_now()
        unsigned: dict[str, Any] = {
            "schema": "qdev-capacity-override-v1",
            "operation_id": str(uuid4()),
            "worker_name": worker_name,
            "repository": repository.strip().lower(),
            "profiles": list(dict.fromkeys(profiles)),
            "min_disk_free_gib": min_disk_free_gib,
            "max_disk_used_pct": max_disk_used_pct,
            "owner": owner.strip(),
            "reason": reason.strip(),
            "issued_at": format_utc(issued_at),
            "expires_at": format_utc(issued_at + timedelta(seconds=duration_seconds)),
            "status": "active",
            "cancelled_at": None,
        }
        normalized = CapacityOverrideDirective.model_validate(
            unsigned | {"signature": "0" * 64}
        ).unsigned()
        directive = CapacityOverrideDirective.model_validate(
            normalized | {"signature": sign_payload(normalized, self.worker_signing_key)}
        )
        self._write(worker_name, directive.model_dump(mode="json", by_alias=True))
        return directive

    def cancel_capacity_override(
        self,
        worker_name: str,
        *,
        registered_profiles: tuple[str, ...],
        now: datetime | None = None,
    ) -> CapacityOverrideDirective | None:
        directive = self.active(
            worker_name,
            registered_profiles=registered_profiles,
            now=now,
        )
        if directive is None:
            return None
        unsigned = directive.unsigned() | {
            "status": "cancelled",
            "cancelled_at": format_utc(now or utc_now()),
        }
        cancelled = CapacityOverrideDirective.model_validate(
            unsigned | {"signature": sign_payload(unsigned, self.worker_signing_key)}
        )
        self._write(worker_name, cancelled.model_dump(mode="json", by_alias=True))
        return cancelled

    def receipt(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        checked_payload = validate_controller_receipt_payload(payload)
        digest = payload_digest(checked_payload)
        unsigned: dict[str, Any] = {
            "schema": "qdev-controller-receipt-v2",
            "receipt_id": digest,
            "payload": checked_payload,
            "digest": digest,
            "enforcement": "enforced",
        }
        return unsigned | {"signature": sign_payload(unsigned, self.receipt_signing_key)}
