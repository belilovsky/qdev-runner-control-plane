"""Cryptographic proof that a release host-agent reached the controller over mTLS."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

REQUEST_SCHEMA = "qdev-host-enrolment-challenge-v1"
ACK_SCHEMA = "qdev-host-enrolment-ack-v1"


class HostEnrolmentChallenge(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_name: Literal["qdev-host-enrolment-challenge-v1"] = Field(alias="schema")
    release_lane: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,127}$")
    project_id: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{2,127}$")
    placement: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,127}$")
    controller_revision: str = Field(pattern=r"^[0-9a-f]{40}$")
    operation_fence: str = Field(min_length=24, max_length=128)
    certificate_fingerprint_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    nonce: str = Field(pattern=r"^[0-9a-f]{32,128}$")


def _canonical(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def _unsigned_ack(
    request: HostEnrolmentChallenge,
    *,
    mtls_identity: str,
    issued_at: datetime,
    expires_at: datetime,
) -> dict[str, Any]:
    return {
        "schema": ACK_SCHEMA,
        "status": "verified",
        "release_lane": request.release_lane,
        "project_id": request.project_id,
        "placement": request.placement,
        "controller_revision": request.controller_revision,
        "operation_fence": request.operation_fence,
        "certificate_fingerprint_sha256": request.certificate_fingerprint_sha256,
        "mtls_identity": mtls_identity,
        "nonce": request.nonce,
        "issued_at": issued_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
        "expires_at": expires_at.astimezone(UTC).isoformat().replace("+00:00", "Z"),
    }


def create_host_enrolment_ack(
    request: HostEnrolmentChallenge,
    *,
    mtls_identity: str,
    signing_key: str,
    now: datetime | None = None,
) -> dict[str, Any]:
    if len(signing_key.encode("utf-8")) < 32:
        raise ValueError("host enrolment signing key is unavailable")
    issued_at = (now or datetime.now(UTC)).astimezone(UTC)
    payload = _unsigned_ack(
        request,
        mtls_identity=mtls_identity,
        issued_at=issued_at,
        expires_at=issued_at + timedelta(minutes=5),
    )
    payload["signature"] = hmac.new(
        signing_key.encode("utf-8"), _canonical(payload), hashlib.sha256
    ).hexdigest()
    return payload


def verify_host_enrolment_ack(
    value: object,
    *,
    request: HostEnrolmentChallenge,
    expected_mtls_identity: str,
    signing_key: str,
    now: datetime | None = None,
    require_current: bool = True,
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ValueError("host enrolment acknowledgement is not an object")
    expected_keys = {
        "schema",
        "status",
        "release_lane",
        "project_id",
        "placement",
        "controller_revision",
        "operation_fence",
        "certificate_fingerprint_sha256",
        "mtls_identity",
        "nonce",
        "issued_at",
        "expires_at",
        "signature",
    }
    if set(value) != expected_keys:
        raise ValueError("host enrolment acknowledgement shape is invalid")
    unsigned = dict(value)
    signature = unsigned.pop("signature", None)
    if not isinstance(signature, str) or len(signature) != 64:
        raise ValueError("host enrolment acknowledgement signature is invalid")
    expected_signature = hmac.new(
        signing_key.encode("utf-8"), _canonical(unsigned), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(signature, expected_signature):
        raise ValueError("host enrolment acknowledgement signature is invalid")
    expected = {
        "schema": ACK_SCHEMA,
        "status": "verified",
        "release_lane": request.release_lane,
        "project_id": request.project_id,
        "placement": request.placement,
        "controller_revision": request.controller_revision,
        "operation_fence": request.operation_fence,
        "certificate_fingerprint_sha256": request.certificate_fingerprint_sha256,
        "mtls_identity": expected_mtls_identity,
        "nonce": request.nonce,
    }
    if any(unsigned.get(key) != expected_value for key, expected_value in expected.items()):
        raise ValueError("host enrolment acknowledgement identity differs")
    try:
        issued_at = datetime.fromisoformat(str(unsigned["issued_at"]).replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(str(unsigned["expires_at"]).replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("host enrolment acknowledgement time is invalid") from error
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if (
        issued_at.tzinfo is None
        or expires_at.tzinfo is None
        or expires_at <= issued_at
        or expires_at - issued_at > timedelta(minutes=5)
        or (
            require_current
            and (issued_at > current + timedelta(seconds=30) or expires_at <= current)
        )
    ):
        raise ValueError("host enrolment acknowledgement is expired or invalid")
    return dict(value)
