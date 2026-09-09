from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .fleet_bootstrap_executor import BOOTSTRAP_EXECUTION_RECEIPT_SCHEMA

HARD_MIN_FREE_GIB = 4.5
# Runtime overrides remain repository-, SHA-, profile- and time-bound.  The
# absolute free-space floor plus the repository reservation is the primary
# safety invariant. Ninety percent is an absolute outer guard; a release may
# not weaken it for a large volume or through a temporary override.
HARD_MAX_DISK_USED_PCT = 90.0
MAX_OVERRIDE_SECONDS = 900
DISK_ONLY_BLOCKERS = frozenset({"disk_free_gib", "disk_used_pct"})

_WORKER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_REPOSITORY = re.compile(r"^[a-z0-9_.-]+/[a-z0-9_.-]+$")
_SOURCE_SHA = re.compile(r"^[0-9a-f]{40}$")
_PROGRAM_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_ADMIN_PLATFORM_STAGE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
_ADMIN_PLATFORM_LANES = frozenset(
    {"source", "ci", "publication", "deploy", "browser", "rollback", "observation"}
)
_ADMIN_PLATFORM_RESULT_OUTCOMES = frozenset(
    {"queued", "passed", "failed", "blocked", "auth_blocked", "not_applicable"}
)
_ADMIN_PLATFORM_TERMINAL_STATES = frozenset({"live_accepted", "rolled_back", "blocked"})
_FIFO_SKIP_REASONS = frozenset(
    {
        "active-admin-platform-controller-priority",
        "admin-platform-candidate-not-active",
        "admin-platform-candidate-tuple-not-admitted",
        "managed-production-candidate-not-active",
        "managed-production-candidate-tuple-not-admitted",
    }
)


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
    "controller-release-audit": {
        "kind",
        "observed_at",
        "controller_release",
        "controller_activation",
    },
    "admin-platform-audit": {
        "kind",
        "observed_at",
        "controller_release",
        "controller_activation",
        "managed_registry",
        "admin_platform_ledger",
        "active_candidate",
        "admission",
    },
    "worker-audit": {"kind", "observed_at", "workers", "pending"},
    "durable-queue-audit": {
        "kind",
        "observed_at",
        "pending",
        "profile_heads",
        "unclassified",
    },
    "fifo-claim-scope-issued": {
        "kind",
        "operator_session",
        "mtls_identity",
        "idempotent",
        "claim_scope",
        "immutable_tuple",
        "fifo_skipped",
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
        "immutable_tuple",
        "fifo_skipped",
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
    "failed-job-audit": {
        "kind",
        "observed_at",
        "provider_reconciliation_required",
        "candidates",
    },
    "failed-job-recovery": {
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
    "fleet-bootstrap-operation": {
        "kind",
        "observed_at",
        "execution",
    },
    "admin-platform-evidence": {
        "kind",
        "observed_at",
        "program_id",
        "stage",
        "release_id",
        "source_sha",
        "evidence_type",
        "lane",
        "outcome",
    },
    "admin-platform-state-transaction": {
        "kind",
        "observed_at",
        "transaction_id",
        "previous_ledger_sha256",
        "target_ledger_sha256",
        "receipts",
    },
    "admin-platform-ledger-link": {
        "kind",
        "observed_at",
        "previous_ledger_sha256",
        "target_ledger_sha256",
    },
    "managed-ci-registration": {
        "kind",
        "observed_at",
        "repository",
        "source_sha",
        "run_id",
        "attempt",
        "job_id",
        "profile",
        "provider",
        "idempotent",
        "backup_path",
    },
    "managed-ci-reconciliation": {
        "kind",
        "observed_at",
        "repository",
        "source_sha",
        "run_ids",
        "bindings",
        "provider",
        "idempotent",
        "backup_path",
    },
    "qazgeo-release-claim-issued": {
        "kind",
        "observed_at",
        "release_lane",
        "source_sha",
        "artifact_digest",
        "candidate_evidence_digest",
        "claim",
        "claim_signature",
        "preflight",
    },
}


def _validate_durable_queue_head(value: Any, *, require_attempt: bool = False) -> None:
    if not isinstance(value, dict) or set(value) != {
        "repository",
        "run_id",
        "job_id",
        "attempt",
        "exact_sha",
        "profile",
        "state",
        "created_at",
    }:
        raise ValueError("durable queue head is invalid")
    if (
        not isinstance(value["repository"], str)
        or not _REPOSITORY.fullmatch(value["repository"])
        or isinstance(value["run_id"], bool)
        or not isinstance(value["run_id"], int)
        or value["run_id"] <= 0
        or isinstance(value["job_id"], bool)
        or not isinstance(value["job_id"], int)
        or value["job_id"] <= 0
        or (
            value["attempt"] is not None
            and (
                isinstance(value["attempt"], bool)
                or not isinstance(value["attempt"], int)
                or value["attempt"] <= 0
            )
        )
        or (require_attempt and value["attempt"] is None)
        or not isinstance(value["exact_sha"], str)
        or not _SOURCE_SHA.fullmatch(value["exact_sha"])
        or not isinstance(value["profile"], str)
        or not _WORKER_NAME.fullmatch(value["profile"])
        or value["state"] != "pending"
        or isinstance(value["created_at"], bool)
        or not isinstance(value["created_at"], (int, float))
        or value["created_at"] <= 0
    ):
        raise ValueError("durable queue head is invalid")


def _validate_fifo_skipped(value: Any) -> None:
    if not isinstance(value, list) or len(value) > 512:
        raise ValueError("fifo skip list is invalid")
    for item in value:
        if not isinstance(item, dict) or set(item) != {
            "job_id",
            "repository",
            "run_id",
            "attempt",
            "head_sha",
            "profile",
            "managed_registry_entry",
            "reason",
        }:
            raise ValueError("fifo skip item is invalid")
        if (
            not isinstance(item["job_id"], int)
            or isinstance(item["job_id"], bool)
            or item["job_id"] <= 0
            or not isinstance(item["run_id"], int)
            or isinstance(item["run_id"], bool)
            or item["run_id"] <= 0
            or not isinstance(item["attempt"], int)
            or isinstance(item["attempt"], bool)
            or item["attempt"] <= 0
            or not isinstance(item["repository"], str)
            or not _REPOSITORY.fullmatch(item["repository"])
            or not isinstance(item["head_sha"], str)
            or not _SOURCE_SHA.fullmatch(item["head_sha"])
            or not isinstance(item["profile"], str)
            or not _WORKER_NAME.fullmatch(item["profile"])
            or (
                item["managed_registry_entry"] is not None
                and (
                    not isinstance(item["managed_registry_entry"], str)
                    or not _WORKER_NAME.fullmatch(item["managed_registry_entry"])
                )
            )
            or not isinstance(item["reason"], str)
            or item["reason"] not in _FIFO_SKIP_REASONS
        ):
            raise ValueError("fifo skip item is invalid")


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
            "repaired_managed_scope",
        }
    if set(value) != expected:
        raise ValueError("controller receipt payload fields are invalid")
    if kind != "fifo-claim-scope-issued" and not isinstance(value.get("observed_at"), str):
        raise ValueError("controller receipt observed_at is invalid")
    if kind == "controller-release-audit" and (
        not isinstance(value["controller_release"], dict)
        or not isinstance(value["controller_activation"], dict)
    ):
        raise ValueError("controller release payload is invalid")
    if kind == "admin-platform-audit" and (
        not isinstance(value["controller_release"], dict)
        or not isinstance(value["controller_activation"], dict)
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
    if kind == "durable-queue-audit" and (
        not isinstance(value["pending"], int)
        or value["pending"] < 0
        or not isinstance(value["profile_heads"], list)
        or not isinstance(value["unclassified"], list)
        or len(value["profile_heads"]) > 512
        or len(value["unclassified"]) > 512
    ):
        raise ValueError("durable queue audit payload is invalid")
    if kind == "durable-queue-audit":
        for item in value["profile_heads"]:
            _validate_durable_queue_head(item)
        if any(
            isinstance(job_id, bool) or not isinstance(job_id, int) or job_id <= 0
            for job_id in value["unclassified"]
        ):
            raise ValueError("durable queue audit unclassified jobs are invalid")
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
            and not (
                all(
                    value[field] is None
                    for field in (
                        "admission_ledger",
                        "admin_platform_ledger_entry",
                        "managed_release_ledger_entry",
                    )
                )
                or (
                    value["admission_ledger"] == "admin-platform"
                    and value["admin_platform_ledger_entry"] == "controller"
                    and value["managed_release_ledger_entry"] is None
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
    if kind == "fifo-claim-scope-issued":
        _validate_fifo_skipped(value["fifo_skipped"])
    if kind.startswith("capacity-override") and not isinstance(value["worker_audit"], dict):
        raise ValueError("capacity override payload is invalid")
    if kind == "capacity-override-created" and (
        not isinstance(value["operation"], dict)
        or not isinstance(value["required_free_gib"], (int, float))
        or not isinstance(value["immutable_tuple"], dict)
    ):
        raise ValueError("capacity override creation payload is invalid")
    if kind == "capacity-override-created":
        _validate_durable_queue_head(value["immutable_tuple"], require_attempt=True)
        _validate_fifo_skipped(value["fifo_skipped"])
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
    if kind == "failed-job-audit" and (
        not isinstance(value["provider_reconciliation_required"], bool)
        or not isinstance(value["candidates"], list)
    ):
        raise ValueError("failed-job audit payload is invalid")
    if kind == "failed-job-recovery" and (
        not isinstance(value["immutable_job"], dict)
        or not isinstance(value["provider"], dict)
        or not isinstance(value["owner"], str)
        or not isinstance(value["reason"], str)
        or not isinstance(value["action"], str)
        or value["fifo_preserved"] is not True
    ):
        raise ValueError("failed-job recovery payload is invalid")
    if kind == "fleet-bootstrap-recovery" and (
        value["status"]
        not in {
            "completed",
            "access_blocked",
            "active_work",
            "target_unregistered",
            "failed",
            "unknown",
        }
        or value["operation_status"] not in {"pending", "completed", "unknown"}
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
    if kind == "fleet-bootstrap-recovery":
        unknown = value["status"] == "unknown" or value["operation_status"] == "unknown"
        if unknown and (
            value["status"] != "unknown"
            or value["operation_status"] != "unknown"
            or value["error_code"] != "operation_outcome_unknown_reconciliation_required"
            or value["result"] is not None
        ):
            raise ValueError("fleet bootstrap unknown outcome payload is invalid")
    if kind == "fleet-bootstrap-operation":
        execution = value["execution"]
        expected_execution_fields = {
            "schema",
            "status",
            "operation_status",
            "action",
            "idempotency_key",
            "request_fingerprint",
            "controller_revision",
            "controller_release_digest",
            "controller_image_digest",
            "controller_internal_image_digest",
            "activation_envelope_digest",
            "release_lane",
            "host_agent_mtls_identity",
            "error_code",
            "result",
        }
        if not isinstance(execution, dict) or set(execution) != expected_execution_fields:
            raise ValueError("fleet bootstrap operation payload is invalid")
        status = execution.get("status")
        operation_status = execution.get("operation_status")
        action = execution.get("action")
        release_lane = execution.get("release_lane")
        host_identity = execution.get("host_agent_mtls_identity")
        error_code = execution.get("error_code")
        result = execution.get("result")
        if status == "completed":
            state_invalid = (
                operation_status != "completed"
                or error_code is not None
                or not isinstance(result, dict)
            )
        elif status == "queued":
            state_invalid = (
                operation_status != "pending" or error_code is not None or result is not None
            )
        elif status in {"access_blocked", "failed"}:
            state_invalid = (
                operation_status != "pending"
                or not isinstance(error_code, str)
                or result is not None
            )
        elif status == "unknown":
            state_invalid = (
                operation_status != "unknown"
                or error_code != "operation_outcome_unknown_reconciliation_required"
                or result is not None
            )
        else:
            state_invalid = True
        if (
            execution.get("schema") != BOOTSTRAP_EXECUTION_RECEIPT_SCHEMA
            or state_invalid
            or action not in {"activate-controller", "enrol-host-agent"}
            or not isinstance(execution.get("idempotency_key"), str)
            or not re.fullmatch(
                r"[A-Za-z0-9][A-Za-z0-9._:-]{7,127}",
                execution["idempotency_key"],
            )
            or not isinstance(execution.get("request_fingerprint"), str)
            or not re.fullmatch(r"[0-9a-f]{64}", execution["request_fingerprint"])
            or not isinstance(execution.get("controller_revision"), str)
            or not _SOURCE_SHA.fullmatch(execution["controller_revision"])
            or not isinstance(execution.get("controller_release_digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", execution["controller_release_digest"])
            or not isinstance(execution.get("controller_image_digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", execution["controller_image_digest"])
            or not isinstance(execution.get("controller_internal_image_digest"), str)
            or not re.fullmatch(
                r"sha256:[0-9a-f]{64}", execution["controller_internal_image_digest"]
            )
            or not isinstance(execution.get("activation_envelope_digest"), str)
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", execution["activation_envelope_digest"])
            or (
                action == "activate-controller"
                and any(item is not None for item in (release_lane, host_identity))
            )
            or (
                action == "enrol-host-agent"
                and (
                    not isinstance(release_lane, str)
                    or not _WORKER_NAME.fullmatch(release_lane)
                    or not isinstance(host_identity, str)
                    or not host_identity
                )
            )
        ):
            raise ValueError("fleet bootstrap operation payload is invalid")
    if kind == "admin-platform-evidence":
        evidence_type = value["evidence_type"]
        lane = value["lane"]
        outcome = value["outcome"]
        try:
            parse_utc(value["observed_at"])
        except (TypeError, ValueError) as error:
            raise ValueError("admin platform evidence observed_at is invalid") from error
        if (
            not isinstance(value["program_id"], str)
            or not _PROGRAM_ID.fullmatch(value["program_id"])
            or not isinstance(value["stage"], str)
            or not _ADMIN_PLATFORM_STAGE.fullmatch(value["stage"])
            or not isinstance(value["release_id"], str)
            or not _PROGRAM_ID.fullmatch(value["release_id"])
            or not isinstance(value["source_sha"], str)
            or not _SOURCE_SHA.fullmatch(value["source_sha"])
            or evidence_type not in {"lane_result", "attempt_terminal"}
        ):
            raise ValueError("admin platform evidence identity is invalid")
        if evidence_type == "lane_result" and (
            lane not in _ADMIN_PLATFORM_LANES or outcome not in _ADMIN_PLATFORM_RESULT_OUTCOMES
        ):
            raise ValueError("admin platform lane evidence is invalid")
        if evidence_type == "attempt_terminal" and (
            lane is not None or outcome not in _ADMIN_PLATFORM_TERMINAL_STATES
        ):
            raise ValueError("admin platform terminal evidence is invalid")
    if kind == "admin-platform-state-transaction":
        receipts = value["receipts"]
        if (
            not isinstance(value["transaction_id"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["transaction_id"])
            or not isinstance(value["previous_ledger_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["previous_ledger_sha256"])
            or not isinstance(value["target_ledger_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", value["target_ledger_sha256"])
            or not isinstance(receipts, list)
            or not 1 <= len(receipts) <= 16
        ):
            raise ValueError("admin platform state transaction is invalid")
        expected_uris: set[str] = set()
        for receipt in receipts:
            if (
                not isinstance(receipt, dict)
                or set(receipt) != {"receipt_uri", "receipt_sha256"}
                or not isinstance(receipt["receipt_uri"], str)
                or not re.fullmatch(
                    r"receipts/transactions/[0-9a-f]{64}/[0-9a-f]{64}\.json",
                    receipt["receipt_uri"],
                )
                or receipt["receipt_uri"].split("/")[2] != value["transaction_id"]
                or not isinstance(receipt["receipt_sha256"], str)
                or not re.fullmatch(r"[0-9a-f]{64}", receipt["receipt_sha256"])
                or receipt["receipt_uri"] in expected_uris
            ):
                raise ValueError("admin platform state transaction receipts are invalid")
            expected_uris.add(receipt["receipt_uri"])
    if kind == "admin-platform-ledger-link" and (
        not isinstance(value["previous_ledger_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["previous_ledger_sha256"])
        or not isinstance(value["target_ledger_sha256"], str)
        or not re.fullmatch(r"[0-9a-f]{64}", value["target_ledger_sha256"])
        or value["previous_ledger_sha256"] == value["target_ledger_sha256"]
    ):
        raise ValueError("admin platform ledger link is invalid")
    if kind in {"managed-ci-registration", "managed-ci-reconciliation"} and (
        value.get("repository") != "belilovsky/qazgeo"
        or not isinstance(value.get("source_sha"), str)
        or not _SOURCE_SHA.fullmatch(value["source_sha"])
        or not isinstance(value.get("provider"), dict)
        or not isinstance(value.get("idempotent"), bool)
        or (value.get("backup_path") is not None and not isinstance(value["backup_path"], str))
    ):
        raise ValueError("managed CI payload is invalid")
    if kind == "managed-ci-registration" and (
        not isinstance(value.get("run_id"), int)
        or isinstance(value["run_id"], bool)
        or value["run_id"] <= 0
        or not isinstance(value.get("attempt"), int)
        or isinstance(value["attempt"], bool)
        or value["attempt"] < 1
        or not isinstance(value.get("job_id"), int)
        or isinstance(value["job_id"], bool)
        or value["job_id"] <= 0
        or not isinstance(value.get("profile"), str)
        or not _WORKER_NAME.fullmatch(value["profile"])
    ):
        raise ValueError("managed CI registration payload is invalid")
    if kind == "managed-ci-reconciliation" and (
        not isinstance(value.get("run_ids"), list)
        or any(
            not isinstance(item, int) or isinstance(item, bool) or item <= 0
            for item in value["run_ids"]
        )
        or len(value["run_ids"]) != len(set(value["run_ids"]))
        or not isinstance(value.get("bindings"), list)
        or any(not isinstance(item, dict) for item in value["bindings"])
    ):
        raise ValueError("managed CI reconciliation payload is invalid")
    return value


class CapacityOverrideDirective(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, populate_by_name=True)

    schema_name: Literal["qdev-capacity-override-v2"] = Field(alias="schema")
    operation_id: str = Field(min_length=1, max_length=128)
    worker_name: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
    repository: str = Field(min_length=1, max_length=256)
    head_sha: str = Field(pattern=r"^[0-9a-f]{40}$")
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


class CapacityOverrideConflict(RuntimeError):
    """The active directive changed across an operator transaction."""


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
        self._process_lock = threading.RLock()
        self.root.mkdir(parents=True, exist_ok=True)
        self.root.chmod(0o700)

    def _path(self, worker_name: str) -> Path:
        if not _WORKER_NAME.fullmatch(worker_name):
            raise ValueError("invalid worker name")
        return self.root / f"{worker_name}.json"

    @contextmanager
    def _worker_lock(self, worker_name: str) -> Iterator[None]:
        self._path(worker_name)
        lock_path = self.root / f".{worker_name}.lock"
        with self._process_lock:
            descriptor = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)

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
        head_sha: str,
        profiles: tuple[str, ...],
        min_disk_free_gib: float,
        max_disk_used_pct: float,
        owner: str,
        reason: str,
        duration_seconds: int,
        registered_profiles: tuple[str, ...] | None = None,
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
        with self._worker_lock(worker_name):
            if (
                self.active(
                    worker_name,
                    registered_profiles=registered_profiles or profiles,
                    now=issued_at,
                )
                is not None
            ):
                raise CapacityOverrideConflict("capacity override is already active")
            unsigned: dict[str, Any] = {
                "schema": "qdev-capacity-override-v2",
                "operation_id": str(uuid4()),
                "worker_name": worker_name,
                "repository": repository.strip().lower(),
                "head_sha": head_sha.strip().lower(),
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
        expected_operation_id: str,
        registered_profiles: tuple[str, ...],
        now: datetime | None = None,
    ) -> CapacityOverrideDirective:
        if not expected_operation_id.strip():
            raise ValueError("expected operation ID is required")
        checked_at = now or utc_now()
        with self._worker_lock(worker_name):
            directive = self.active(
                worker_name,
                registered_profiles=registered_profiles,
                now=checked_at,
            )
            if directive is None:
                raise CapacityOverrideConflict("capacity override is not active")
            if not hmac.compare_digest(directive.operation_id, expected_operation_id):
                raise CapacityOverrideConflict("capacity override operation changed")
            unsigned = directive.unsigned() | {
                "status": "cancelled",
                "cancelled_at": format_utc(checked_at),
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
