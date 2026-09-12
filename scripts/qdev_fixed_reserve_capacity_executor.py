#!/usr/bin/env python3
"""Consume one sealed reserve request through a fixed root-owned adapter.

This executable is intentionally not a generic host dispatcher.  It accepts
only the controller-generated ``mail-general-reserve`` request from the
watchdog outbox, resolves only the corresponding fixed adapter in a
root-private registry, and appends an exact capacity receipt.  The registry is
the binding point for the already-provisioned host-agent; neither an operator
nor an observation document can supply a host address, runner name, label or
command.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import stat
import subprocess
import sys
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

OUTBOX_SCHEMA = "qdev-ci-reserve-capacity-outbox-v1"
RECEIPT_SCHEMA = "qdev-ci-reserve-capacity-receipt-v1"
REGISTRY_SCHEMA = "qdev-ci-reserve-capacity-targets-v1"
INCIDENT_ID = "qdev-ci-four-vps-20260911"
HOST_ID = "mail-general-reserve"
ACTION = "activate-reserve"
REQUEST_FIELDS = {"request_id", "host_id", "action", "follow_up"}
OUTBOX_FIELDS = {"schema", "incident_id", "requests"}
RECEIPT_FIELDS = {
    "schema",
    "request_id",
    "host_id",
    "action",
    "status",
    "slots",
    "profiles",
    "max_docker_jobs",
    "audited_at",
    "audit_digest",
}
REGISTRY_FIELDS = {"schema", "targets"}
TARGET_FIELDS = {"host_id", "adapter_path"}
MAX_AUDIT_AGE_SECONDS = 300
MAX_FUTURE_SKEW_SECONDS = 120
DEFAULT_STATE_ROOT = Path("/var/lib/qdev-runner/incident-watchdog")
DEFAULT_REGISTRY = Path("/etc/qdev-runner/reserve-capacity-targets.json")
FIXED_ADAPTER = Path("/usr/local/sbin/qdev-fixed-reserve-capacity-adapter")


class ExecutorError(RuntimeError):
    """The sealed request, registry or fixed adapter is not trustworthy."""


def _private_regular(path: Path, *, owner_uid: int | None) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or (owner_uid is not None and metadata.st_uid != owner_uid)
    ):
        raise ExecutorError("private_file_permissions_invalid")


def _parse_request(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != REQUEST_FIELDS:
        raise ExecutorError("reserve_request_shape_invalid")
    expected_id = hashlib.sha256(
        f"{INCIDENT_ID}:reserve:{HOST_ID}:{ACTION}".encode()
    ).hexdigest()
    if (
        value.get("request_id") != expected_id
        or value.get("host_id") != HOST_ID
        or value.get("action") != ACTION
        or value.get("follow_up") != ["host-audit", "capacity-calculation"]
    ):
        raise ExecutorError("reserve_request_identity_invalid")
    return dict(value)


def load_request(outbox: Path, *, owner_uid: int | None) -> dict[str, Any] | None:
    """Read at most the one controller-owned reserve request."""

    _private_regular(outbox, owner_uid=owner_uid)
    try:
        document = json.loads(outbox.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExecutorError("reserve_outbox_invalid") from error
    if (
        not isinstance(document, dict)
        or set(document) != OUTBOX_FIELDS
        or document.get("schema") != OUTBOX_SCHEMA
        or document.get("incident_id") != INCIDENT_ID
        or not isinstance(document.get("requests"), list)
        or len(document["requests"]) > 1
    ):
        raise ExecutorError("reserve_outbox_invalid")
    return _parse_request(document["requests"][0]) if document["requests"] else None


def resolve_adapter(registry_path: Path, *, owner_uid: int | None) -> Path:
    """Return only the sealed adapter that private controller state permits."""

    _private_regular(registry_path, owner_uid=owner_uid)
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExecutorError("reserve_registry_invalid") from error
    if (
        not isinstance(registry, dict)
        or set(registry) != REGISTRY_FIELDS
        or registry.get("schema") != REGISTRY_SCHEMA
        or not isinstance(registry.get("targets"), dict)
        or set(registry["targets"]) != {HOST_ID}
    ):
        raise ExecutorError("reserve_registry_invalid")
    target = registry["targets"][HOST_ID]
    if (
        not isinstance(target, dict)
        or set(target) != TARGET_FIELDS
        or target.get("host_id") != HOST_ID
        or target.get("adapter_path") != str(FIXED_ADAPTER)
    ):
        raise ExecutorError("reserve_registry_identity_invalid")
    adapter = FIXED_ADAPTER
    metadata = adapter.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (owner_uid is not None and metadata.st_uid != owner_uid)
        or not os.access(adapter, os.X_OK)
    ):
        raise ExecutorError("reserve_adapter_invalid")
    return adapter


def _validate_receipt(
    value: object,
    request: Mapping[str, Any],
    *,
    now: datetime,
) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS:
        raise ExecutorError("reserve_adapter_response_invalid")
    for field in ("request_id", "host_id", "action"):
        if value.get(field) != request.get(field):
            raise ExecutorError("reserve_adapter_response_identity_invalid")
    if (
        value.get("schema") != RECEIPT_SCHEMA
        or value.get("status") not in {"admitted", "blocked"}
        or value.get("slots") != 2
        or value.get("profiles") != ["qdev-ci", "qdev-ci-browser"]
        or value.get("max_docker_jobs") != 0
        or not isinstance(value.get("audit_digest"), str)
        or len(value["audit_digest"]) != 64
        or any(character not in "0123456789abcdef" for character in value["audit_digest"])
        or not isinstance(value.get("audited_at"), str)
    ):
        raise ExecutorError("reserve_adapter_response_invalid")
    try:
        audited_at = datetime.fromisoformat(value["audited_at"].replace("Z", "+00:00"))
    except ValueError as error:
        raise ExecutorError("reserve_adapter_response_invalid") from error
    if audited_at.tzinfo is None:
        raise ExecutorError("reserve_adapter_response_invalid")
    age_seconds = (now - audited_at.astimezone(UTC)).total_seconds()
    if age_seconds > MAX_AUDIT_AGE_SECONDS or age_seconds < -MAX_FUTURE_SKEW_SECONDS:
        raise ExecutorError("reserve_adapter_audit_not_fresh")
    return dict(value)


def run_adapter(adapter: Path, request: Mapping[str, Any], *, now: datetime) -> dict[str, Any]:
    """Call the fixed adapter with no ambient user input or shell."""

    try:
        completed = subprocess.run(
            [str(adapter)],
            input=json.dumps(request, sort_keys=True, separators=(",", ":")),
            text=True,
            capture_output=True,
            timeout=600,
            check=False,
            env={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONNOUSERSITE": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExecutorError("reserve_adapter_unavailable") from error
    if completed.returncode != 0:
        raise ExecutorError("reserve_adapter_failed")
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ExecutorError("reserve_adapter_response_invalid") from error
    return _validate_receipt(response, request, now=now)


def _load_existing_receipts(path: Path, *, owner_uid: int | None) -> dict[str, dict[str, Any]]:
    if not path.exists():
        return {}
    _private_regular(path, owner_uid=owner_uid)
    receipts: dict[str, dict[str, Any]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            receipt = json.loads(line)
        except json.JSONDecodeError as error:
            raise ExecutorError("reserve_receipt_ledger_invalid") from error
        if not isinstance(receipt, dict) or not isinstance(receipt.get("request_id"), str):
            raise ExecutorError("reserve_receipt_ledger_invalid")
        existing = receipts.setdefault(receipt["request_id"], receipt)
        if existing != receipt:
            raise ExecutorError("reserve_receipt_ledger_conflict")
    return receipts


def append_receipt(
    receipts_path: Path,
    receipt: Mapping[str, Any],
    *,
    owner_uid: int | None,
) -> bool:
    """Append once, returning false for an exact replay of a prior receipt."""

    receipts_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _load_existing_receipts(receipts_path, owner_uid=owner_uid)
    previous = existing.get(str(receipt["request_id"]))
    if previous is not None:
        if previous != receipt:
            raise ExecutorError("reserve_receipt_replay_conflict")
        return False
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(receipts_path, flags, 0o600)
    try:
        if owner_uid is not None:
            os.chown(receipts_path, owner_uid, owner_uid)
        os.chmod(receipts_path, 0o600)
        _private_regular(receipts_path, owner_uid=owner_uid)
        line = json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
        os.write(descriptor, line.encode())
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return True


def execute(
    *,
    outbox: Path,
    receipts: Path,
    registry: Path,
    owner_uid: int | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    request = load_request(outbox, owner_uid=owner_uid)
    if request is None:
        return {"schema": RECEIPT_SCHEMA, "status": "idle", "receipt_written": False}
    existing = _load_existing_receipts(receipts, owner_uid=owner_uid)
    if request["request_id"] in existing:
        return {
            "schema": RECEIPT_SCHEMA,
            "status": "already_receipted",
            "receipt_written": False,
        }
    adapter = resolve_adapter(registry, owner_uid=owner_uid)
    receipt = run_adapter(adapter, request, now=now or datetime.now(UTC))
    return {
        "schema": RECEIPT_SCHEMA,
        "status": receipt["status"],
        "receipt_written": append_receipt(receipts, receipt, owner_uid=owner_uid),
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--outbox", type=Path, default=DEFAULT_STATE_ROOT / "reserve-capacity-outbox.json"
    )
    parser.add_argument(
        "--receipts", type=Path, default=DEFAULT_STATE_ROOT / "reserve-capacity-receipts.jsonl"
    )
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("reserve executor error: root_identity_required", file=sys.stderr)
        return 2
    try:
        result = execute(
            outbox=args.outbox,
            receipts=args.receipts,
            registry=args.registry,
            owner_uid=0,
        )
    except (ExecutorError, OSError) as error:
        print(f"reserve executor error: {type(error).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
