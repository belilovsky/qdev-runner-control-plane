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

from .operations import payload_digest, sign_payload

_WORKER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")


def _worker_name(value: str) -> str:
    if not _WORKER_NAME.fullmatch(value):
        raise ValueError("invalid worker name")
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


def verify_controller_receipt(document: Mapping[str, Any], *, receipt_key: str) -> dict[str, Any]:
    expected_fields = {"schema", "receipt_id", "payload", "digest", "signature"}
    if set(document) != expected_fields:
        raise ValueError("invalid controller receipt fields")
    if document.get("schema") != "qdev-controller-receipt-v1":
        raise ValueError("invalid controller receipt schema")
    payload = document.get("payload")
    if not isinstance(payload, dict):
        raise ValueError("invalid controller receipt payload")
    digest = payload_digest(payload)
    if document.get("digest") != digest or document.get("receipt_id") != digest:
        raise ValueError("invalid controller receipt digest")
    unsigned = {
        "schema": document["schema"],
        "receipt_id": document["receipt_id"],
        "payload": payload,
        "digest": document["digest"],
    }
    signature = document.get("signature")
    if not isinstance(signature, str) or not hmac.compare_digest(
        signature, sign_payload(unsigned, receipt_key)
    ):
        raise ValueError("invalid controller receipt signature")
    return dict(document)


def _tls_context(settings: OperatorSettings) -> ssl.SSLContext:
    context = ssl.create_default_context(cafile=settings.mtls_ca)
    context.load_cert_chain(settings.mtls_cert, settings.mtls_key)
    return context


def controller_request(
    settings: OperatorSettings,
    *,
    method: str,
    path: str,
    body: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    with httpx.Client(
        base_url=settings.controller_url,
        headers={"X-QDev-Operator-Token": settings.operator_token},
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
