from __future__ import annotations

import argparse
import hmac
import json
import os
import re
import ssl
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from .operations import payload_digest, sign_payload, validate_controller_receipt_payload

_WORKER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
_SCOPE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{2,127}$")
_IDEMPOTENCY_KEY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_ENDPOINT_IDENTITY = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,254}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")
OPERATOR_MTLS_IDENTITY = "qdev-fleet-operations"


def _worker_name(value: str) -> str:
    if not _WORKER_NAME.fullmatch(value):
        raise ValueError("invalid worker name")
    return value


def _scope_id(value: str) -> str:
    if not _SCOPE_ID.fullmatch(value):
        raise ValueError("invalid claim scope ID")
    return value


def _idempotency_key(value: str) -> str:
    if not _IDEMPOTENCY_KEY.fullmatch(value):
        raise ValueError("invalid idempotency key")
    return value


def _endpoint_identity(value: str, *, field: str) -> str:
    if not _ENDPOINT_IDENTITY.fullmatch(value):
        raise ValueError(f"invalid {field}")
    return value


def _certificate_sha256(value: str) -> str:
    normalized = value.lower()
    if not _SHA256.fullmatch(normalized):
        raise ValueError("invalid worker certificate SHA-256")
    return normalized


def _git_revision(value: str) -> str:
    if not _GIT_REVISION.fullmatch(value):
        raise ValueError("invalid Git source SHA")
    return value


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"required environment variable is missing: {name}")
    return value


@dataclass(frozen=True)
class OperatorSettings:
    controller_url: str
    operator_token: str
    receipt_key: str
    mtls_ca: str
    mtls_cert: str
    mtls_key: str

    @classmethod
    def from_env(cls) -> OperatorSettings:
        return cls(
            controller_url=_required("QDEV_CONTROLLER_URL").rstrip("/"),
            operator_token=_required("QDEV_OPERATOR_TOKEN"),
            receipt_key=_required("QDEV_OPERATOR_RECEIPT_KEY"),
            mtls_ca=_required("QDEV_OPERATOR_MTLS_CA"),
            mtls_cert=_required("QDEV_OPERATOR_MTLS_CERT"),
            mtls_key=_required("QDEV_OPERATOR_MTLS_KEY"),
        )


def verify_controller_receipt(
    document: Mapping[str, Any], *, receipt_key: str, allow_legacy: bool = False
) -> dict[str, Any]:
    schema = document.get("schema")
    if schema == "qdev-controller-receipt-v1":
        if not allow_legacy:
            raise ValueError(
                "legacy controller receipt is legacy_unverified and cannot be enforced"
            )
        expected_fields = {"schema", "receipt_id", "payload", "digest", "signature"}
    else:
        expected_fields = {
            "schema",
            "receipt_id",
            "payload",
            "digest",
            "enforcement",
            "signature",
        }
    if set(document) != expected_fields:
        raise ValueError("invalid controller receipt fields")
    if schema not in {"qdev-controller-receipt-v1", "qdev-controller-receipt-v2"}:
        raise ValueError("invalid controller receipt schema")
    if schema == "qdev-controller-receipt-v2" and document.get("enforcement") != "enforced":
        raise ValueError("controller receipt is not enforced")
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("invalid controller receipt payload")
    if schema == "qdev-controller-receipt-v2":
        validate_controller_receipt_payload(payload)
    digest = payload_digest(payload)
    if document.get("digest") != digest or document.get("receipt_id") != digest:
        raise ValueError("invalid controller receipt digest")
    unsigned = {
        "schema": document["schema"],
        "receipt_id": document["receipt_id"],
        "payload": payload,
        "digest": document["digest"],
    }
    if schema == "qdev-controller-receipt-v2":
        unsigned["enforcement"] = document["enforcement"]
    signature = document.get("signature")
    if not isinstance(signature, str) or not hmac.compare_digest(
        signature, sign_payload(unsigned, receipt_key)
    ):
        raise ValueError("invalid controller receipt signature")
    return dict(document)


def _tls_context(settings: OperatorSettings) -> ssl.SSLContext:
    # Preserve system roots for the public mTLS edge and extend that trust
    # store with the controller's private CA. Passing ``cafile`` directly to
    # create_default_context replaces public roots and fails at the edge.
    context = ssl.create_default_context()
    context.load_verify_locations(cafile=settings.mtls_ca)
    context.load_cert_chain(settings.mtls_cert, settings.mtls_key)
    return context


def controller_request(
    settings: OperatorSettings,
    *,
    method: str,
    path: str,
    body: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    headers = {
        "X-QDev-Operator-Token": settings.operator_token,
        "X-QDev-Operator-mTLS-Identity": OPERATOR_MTLS_IDENTITY,
    }
    with httpx.Client(
        base_url=settings.controller_url,
        headers=headers,
        verify=_tls_context(settings),
        timeout=45,
    ) as client:
        response = client.request(method, path, json=body)
        response.raise_for_status()
        document = response.json()
    if not isinstance(document, dict):
        raise ValueError("controller returned a non-object receipt")
    return verify_controller_receipt(document, receipt_key=settings.receipt_key)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="qdev-runner-operator",
        description="Perform signed, bounded controller capacity operations.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("audit", help="Read a signed worker capacity snapshot")
    commands.add_parser(
        "release-audit", help="Read a signed controller release activation snapshot"
    )
    commands.add_parser(
        "admin-platform-audit",
        help="Read the signed Admin Platform registry and ordered ledger snapshot",
    )

    create = commands.add_parser("override", help="Create one expiring disk-only override")
    create.add_argument("worker")
    create.add_argument("--repository", required=True)
    create.add_argument("--profile", action="append", required=True, dest="profiles")
    create.add_argument("--min-disk-free-gib", type=float, default=4.5)
    create.add_argument("--max-disk-used-pct", type=float, default=95.0)
    create.add_argument("--duration-seconds", type=int, default=900)
    create.add_argument("--owner", required=True)
    create.add_argument("--reason", required=True)

    cancel = commands.add_parser("cancel", help="Cancel the active override for a worker")
    cancel.add_argument("worker")

    stale_audit = commands.add_parser(
        "stale-audit", help="Read signed stale-job candidates without mutation"
    )
    stale_audit.add_argument("--timeout-seconds", type=int, default=300)

    recover_stale = commands.add_parser(
        "recover-stale", help="Reconcile one stale job with GitHub before releasing it"
    )
    recover_stale.add_argument("job_id", type=int)
    recover_stale.add_argument("--timeout-seconds", type=int, default=300)
    recover_stale.add_argument("--owner", required=True)
    recover_stale.add_argument("--reason", required=True)

    claim_scope = commands.add_parser(
        "claim-scope",
        help="Issue one FIFO-bound claim scope for an enrolled worker",
    )
    claim_scope.add_argument("job_id", type=int)
    claim_scope.add_argument("--worker", required=True)
    claim_scope.add_argument("--tier", choices=("primary", "reserve"), required=True)
    claim_scope.add_argument("--scope-id", required=True)
    claim_scope.add_argument("--host", required=True)
    claim_scope.add_argument("--runner", required=True)
    claim_scope.add_argument("--worker-certificate-sha256", required=True)
    claim_scope.add_argument("--correlation-id", required=True)
    claim_scope.add_argument("--duration-seconds", type=int, default=900)

    recover_worker = commands.add_parser(
        "recover-existing-worker",
        help="Run one controller-owned recovery for an existing enrolled worker",
    )
    recover_worker.add_argument("--request", required=True, type=Path)
    recover_worker.add_argument("--idempotency-key", required=True)
    recover_worker.add_argument("--active-jobs", required=True, type=int)
    recover_worker.add_argument("--timeout-seconds", type=float, default=120.0)
    register_ci = commands.add_parser(
        "register-ci", help="Register one verified QGeo main-push workflow job"
    )
    register_ci.add_argument("--repository", default="belilovsky/qazgeo")
    register_ci.add_argument("--source-sha", required=True)
    register_ci.add_argument("--run-id", type=int, required=True)
    register_ci.add_argument("--attempt", type=int, default=1)
    register_ci.add_argument("--job-id", type=int, required=True)

    reconcile_ci = commands.add_parser(
        "reconcile-ci", help="Reconcile all allowlisted QGeo CI jobs"
    )
    reconcile_ci.add_argument("--source-sha", required=True)
    return parser


def run(argv: Sequence[str] | None = None) -> dict[str, Any]:
    arguments = build_parser().parse_args(argv)
    settings = OperatorSettings.from_env()
    if arguments.command == "audit":
        return controller_request(settings, method="GET", path="/internal/v1/operations/workers")
    if arguments.command == "release-audit":
        return controller_request(
            settings,
            method="GET",
            path="/internal/v1/operations/controller-release",
        )
    if arguments.command == "admin-platform-audit":
        return controller_request(
            settings,
            method="GET",
            path="/internal/v1/operations/admin-platform",
        )
    if arguments.command == "override":
        worker = _worker_name(arguments.worker)
        return controller_request(
            settings,
            method="POST",
            path=f"/internal/v1/operations/workers/{worker}/capacity-override",
            body={
                "repository": arguments.repository,
                "profiles": arguments.profiles,
                "min_disk_free_gib": arguments.min_disk_free_gib,
                "max_disk_used_pct": arguments.max_disk_used_pct,
                "duration_seconds": arguments.duration_seconds,
                "owner": arguments.owner,
                "reason": arguments.reason,
            },
        )
    if arguments.command == "cancel":
        worker = _worker_name(arguments.worker)
        return controller_request(
            settings,
            method="DELETE",
            path=f"/internal/v1/operations/workers/{worker}/capacity-override",
        )
    if arguments.command == "stale-audit":
        return controller_request(
            settings,
            method="GET",
            path=(
                "/internal/v1/operations/jobs/stale"
                f"?worker_timeout_seconds={arguments.timeout_seconds}"
            ),
        )
    if arguments.command == "recover-stale":
        return controller_request(
            settings,
            method="POST",
            path=f"/internal/v1/operations/jobs/{arguments.job_id}/recover-stale",
            body={
                "worker_timeout_seconds": arguments.timeout_seconds,
                "owner": arguments.owner,
                "reason": arguments.reason,
            },
        )
    if arguments.command == "claim-scope":
        worker = _worker_name(arguments.worker)
        scope_id = _scope_id(arguments.scope_id)
        host = _endpoint_identity(arguments.host, field="host")
        runner = _endpoint_identity(arguments.runner, field="runner")
        correlation_id = _endpoint_identity(arguments.correlation_id, field="correlation ID")
        certificate_sha256 = _certificate_sha256(arguments.worker_certificate_sha256)
        return controller_request(
            settings,
            method="POST",
            path=f"/internal/v1/operations/jobs/{arguments.job_id}/claim-scope",
            body={
                "job_id": arguments.job_id,
                "worker_name": worker,
                "tier": arguments.tier,
                "scope_id": scope_id,
                "host": host,
                "runner": runner,
                "worker_certificate_sha256": certificate_sha256,
                "correlation_id": correlation_id,
                "duration_seconds": arguments.duration_seconds,
            },
        )
    if arguments.command == "recover-existing-worker":
        key = _idempotency_key(arguments.idempotency_key)
        if arguments.active_jobs < 0:
            raise ValueError("active jobs cannot be negative")
        try:
            raw = json.loads(arguments.request.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("bootstrap request file is invalid") from error
        if not isinstance(raw, dict):
            raise ValueError("bootstrap request file must contain an object")
        return controller_request(
            settings,
            method="POST",
            path="/internal/v1/operations/fleet-bootstrap/recover-existing-worker",
            body={
                "request": raw,
                "idempotency_key": key,
                "active_jobs": arguments.active_jobs,
                "timeout_seconds": arguments.timeout_seconds,
            },
        )
    if arguments.command == "register-ci":
        source_sha = _git_revision(arguments.source_sha)
        if arguments.run_id <= 0 or arguments.attempt < 1 or arguments.job_id <= 0:
            raise ValueError("invalid QGeo CI tuple")
        return controller_request(
            settings,
            method="POST",
            path="/internal/v1/operations/releases/qazgeo/ci-registration",
            body={
                "repository": arguments.repository,
                "source_sha": source_sha,
                "run_id": arguments.run_id,
                "attempt": arguments.attempt,
                "job_id": arguments.job_id,
            },
        )
    if arguments.command == "reconcile-ci":
        source_sha = _git_revision(arguments.source_sha)
        return controller_request(
            settings,
            method="POST",
            path="/internal/v1/operations/releases/qazgeo/ci-reconcile",
            body={"source_sha": source_sha},
        )
    raise AssertionError("unreachable command")


def main() -> None:
    print(json.dumps(run(), sort_keys=True, separators=(",", ":")))


def validate_receipt_file(path: Path, *, receipt_key: str) -> dict[str, Any]:
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("controller receipt file must contain an object")
    return verify_controller_receipt(document, receipt_key=receipt_key)


if __name__ == "__main__":
    main()
