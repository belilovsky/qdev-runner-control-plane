#!/usr/bin/env python3
"""Deliver only receipt-bound QDev CI job-status notices through one fixed adapter.

The watchdog is the sole producer of the outbox and only writes a delivery
after GitHub reports that its exact job has started.  This executor is not a
message dispatcher: recipients and transport live in a root-private adapter
binding, while each call carries the immutable delivery tuple and its
``delivery_id`` as the transport idempotency key.  Explicit transient failures
may be retried; ambiguous execution is dead-lettered rather than resent.
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
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

OUTBOX_SCHEMA = "qdev-ci-incident-delivery-outbox-v1"
RECEIPT_SCHEMA = "qdev-ci-incident-delivery-receipt-v1"
REGISTRY_SCHEMA = "qdev-ci-task-delivery-targets-v1"
STATE_SCHEMA = "qdev-ci-task-delivery-executor-state-v1"
ADAPTER_RESPONSE_SCHEMA = "qdev-ci-task-delivery-adapter-response-v1"
INCIDENT_ID = "qdev-ci-four-vps-20260911"
DELIVERY_FIELDS = {
    "schema",
    "incident_id",
    "delivery_id",
    "repository",
    "run_id",
    "job_id",
    "status",
    "observed_at",
}
OUTBOX_FIELDS = {"schema", "incident_id", "deliveries"}
RECEIPT_FIELDS = {
    "schema",
    "delivery_id",
    "repository",
    "run_id",
    "job_id",
    "status",
    "delivered_at",
}
REGISTRY_FIELDS = {"schema", "adapter_path"}
STATE_FIELDS = {"schema", "deliveries"}
ENTRY_FIELDS = {"delivery", "attempts", "state", "next_attempt_at", "updated_at"}
RESPONSE_FIELDS = {"schema", "delivery_id", "outcome", "receipt"}
MAX_ATTEMPTS = 3
RETRY_DELAYS_SECONDS = (120, 300)
FIXED_ADAPTER = Path("/usr/local/sbin/qdev-fixed-task-delivery-adapter")
DEFAULT_STATE_ROOT = Path("/var/lib/qdev-runner/incident-watchdog")
DEFAULT_REGISTRY = Path("/etc/qdev-runner/task-delivery-targets.json")


class ExecutorError(RuntimeError):
    """The sealed outbox, binding or adapter response is unusable."""


def _private_regular(path: Path, *, owner_uid: int | None) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or (owner_uid is not None and metadata.st_uid != owner_uid)
    ):
        raise ExecutorError("private_file_permissions_invalid")


def _parse_timestamp(value: object, *, error: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise ExecutorError(error)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ExecutorError(error) from exc
    if parsed.tzinfo is None:
        raise ExecutorError(error)
    return parsed.astimezone(UTC)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _delivery_id(delivery: Mapping[str, Any]) -> str:
    payload = ":".join(
        (
            INCIDENT_ID,
            "job-status",
            str(delivery["repository"]),
            str(delivery["run_id"]),
            str(delivery["job_id"]),
            str(delivery["status"]),
        )
    )
    return hashlib.sha256(payload.encode()).hexdigest()


def _parse_delivery(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != DELIVERY_FIELDS:
        raise ExecutorError("delivery_shape_invalid")
    if (
        value.get("schema") != "qdev-ci-incident-watchdog-v1-job-status"
        or value.get("incident_id") != INCIDENT_ID
        or not isinstance(value.get("repository"), str)
        or not value["repository"]
        or any(character.isspace() for character in value["repository"])
        or not isinstance(value.get("run_id"), int)
        or value["run_id"] <= 0
        or not isinstance(value.get("job_id"), int)
        or value["job_id"] <= 0
        or value.get("status") not in {"in_progress", "completed", "failure", "cancelled"}
        or not isinstance(value.get("delivery_id"), str)
        or value["delivery_id"] != _delivery_id(value)
    ):
        raise ExecutorError("delivery_identity_invalid")
    _parse_timestamp(value.get("observed_at"), error="delivery_timestamp_invalid")
    return dict(value)


def load_outbox(outbox: Path, *, owner_uid: int | None) -> tuple[dict[str, Any], ...]:
    _private_regular(outbox, owner_uid=owner_uid)
    try:
        document = json.loads(outbox.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExecutorError("delivery_outbox_invalid") from error
    if (
        not isinstance(document, dict)
        or set(document) != OUTBOX_FIELDS
        or document.get("schema") != OUTBOX_SCHEMA
        or document.get("incident_id") != INCIDENT_ID
        or not isinstance(document.get("deliveries"), list)
    ):
        raise ExecutorError("delivery_outbox_invalid")
    deliveries = tuple(_parse_delivery(item) for item in document["deliveries"])
    if len({item["delivery_id"] for item in deliveries}) != len(deliveries):
        raise ExecutorError("delivery_outbox_duplicate")
    return deliveries


def resolve_adapter(registry_path: Path, *, owner_uid: int | None) -> Path:
    _private_regular(registry_path, owner_uid=owner_uid)
    try:
        registry = json.loads(registry_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExecutorError("delivery_registry_invalid") from error
    if (
        not isinstance(registry, dict)
        or set(registry) != REGISTRY_FIELDS
        or registry.get("schema") != REGISTRY_SCHEMA
        or registry.get("adapter_path") != str(FIXED_ADAPTER)
    ):
        raise ExecutorError("delivery_registry_identity_invalid")
    metadata = FIXED_ADAPTER.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or (owner_uid is not None and metadata.st_uid != owner_uid)
        or not os.access(FIXED_ADAPTER, os.X_OK)
    ):
        raise ExecutorError("delivery_adapter_invalid")
    return FIXED_ADAPTER


def _validate_receipt(value: object, delivery: Mapping[str, Any]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != RECEIPT_FIELDS:
        raise ExecutorError("delivery_receipt_invalid")
    if value.get("schema") != RECEIPT_SCHEMA:
        raise ExecutorError("delivery_receipt_invalid")
    for field in ("delivery_id", "repository", "run_id", "job_id", "status"):
        if value.get(field) != delivery.get(field):
            raise ExecutorError("delivery_receipt_identity_invalid")
    _parse_timestamp(value.get("delivered_at"), error="delivery_receipt_timestamp_invalid")
    return dict(value)


def _validate_response(
    value: object, delivery: Mapping[str, Any]
) -> tuple[str, dict[str, Any] | None]:
    if not isinstance(value, dict) or set(value) != RESPONSE_FIELDS:
        raise ExecutorError("delivery_adapter_response_invalid")
    if (
        value.get("schema") != ADAPTER_RESPONSE_SCHEMA
        or value.get("delivery_id") != delivery["delivery_id"]
        or value.get("outcome") not in {"delivered", "retryable_failure", "permanent_failure"}
    ):
        raise ExecutorError("delivery_adapter_response_invalid")
    if value["outcome"] == "delivered":
        return "delivered", _validate_receipt(value.get("receipt"), delivery)
    if value.get("receipt") is not None:
        raise ExecutorError("delivery_adapter_response_invalid")
    return str(value["outcome"]), None


def run_adapter(adapter: Path, delivery: Mapping[str, Any]) -> tuple[str, dict[str, Any] | None]:
    """Invoke the fixed binding.  A timeout is ambiguous and must not replay."""

    try:
        completed = subprocess.run(
            [str(adapter)],
            input=json.dumps(delivery, sort_keys=True, separators=(",", ":")),
            text=True,
            capture_output=True,
            timeout=120,
            check=False,
            env={
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PYTHONNOUSERSITE": "1",
            },
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ExecutorError("delivery_adapter_ambiguous") from error
    if completed.returncode != 0:
        raise ExecutorError("delivery_adapter_ambiguous")
    try:
        response = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise ExecutorError("delivery_adapter_response_invalid") from error
    return _validate_response(response, delivery)


def _load_receipts(path: Path, *, owner_uid: int | None) -> dict[str, dict[str, Any]]:
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
            raise ExecutorError("delivery_receipt_ledger_invalid") from error
        if not isinstance(receipt, dict) or not isinstance(receipt.get("delivery_id"), str):
            raise ExecutorError("delivery_receipt_ledger_invalid")
        previous = receipts.setdefault(receipt["delivery_id"], receipt)
        if previous != receipt:
            raise ExecutorError("delivery_receipt_ledger_conflict")
    return receipts


def append_receipt(
    receipts_path: Path, receipt: Mapping[str, Any], *, owner_uid: int | None
) -> bool:
    receipts_path.parent.mkdir(parents=True, exist_ok=True)
    existing = _load_receipts(receipts_path, owner_uid=owner_uid)
    previous = existing.get(str(receipt["delivery_id"]))
    if previous is not None:
        if previous != receipt:
            raise ExecutorError("delivery_receipt_replay_conflict")
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
        os.write(
            descriptor, (json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n").encode()
        )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    return True


def load_state(path: Path, *, owner_uid: int | None) -> dict[str, Any]:
    if not path.exists():
        return {"schema": STATE_SCHEMA, "deliveries": {}}
    _private_regular(path, owner_uid=owner_uid)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ExecutorError("delivery_state_invalid") from error
    if (
        not isinstance(state, dict)
        or set(state) != STATE_FIELDS
        or state.get("schema") != STATE_SCHEMA
        or not isinstance(state.get("deliveries"), dict)
    ):
        raise ExecutorError("delivery_state_invalid")
    for delivery_id, entry in state["deliveries"].items():
        if (
            not isinstance(delivery_id, str)
            or not isinstance(entry, dict)
            or set(entry) != ENTRY_FIELDS
        ):
            raise ExecutorError("delivery_state_invalid")
        delivery = _parse_delivery(entry["delivery"])
        if delivery_id != delivery["delivery_id"]:
            raise ExecutorError("delivery_state_invalid")
        if not isinstance(entry["attempts"], int) or entry["attempts"] < 0:
            raise ExecutorError("delivery_state_invalid")
        if entry["state"] not in {"retry_scheduled", "dead_letter"}:
            raise ExecutorError("delivery_state_invalid")
        _parse_timestamp(entry["next_attempt_at"], error="delivery_state_invalid")
        _parse_timestamp(entry["updated_at"], error="delivery_state_invalid")
    return state


def save_state(path: Path, state: Mapping[str, Any], *, owner_uid: int | None) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(json.dumps(state, sort_keys=True, separators=(",", ":")), encoding="utf-8")
    os.chmod(temporary, 0o600)
    if owner_uid is not None:
        os.chown(temporary, owner_uid, owner_uid)
    _private_regular(temporary, owner_uid=owner_uid)
    os.replace(temporary, path)


def _entry(
    delivery: Mapping[str, Any],
    *,
    attempts: int,
    state: str,
    next_attempt_at: datetime,
    now: datetime,
) -> dict[str, Any]:
    return {
        "delivery": dict(delivery),
        "attempts": attempts,
        "state": state,
        "next_attempt_at": _timestamp(next_attempt_at),
        "updated_at": _timestamp(now),
    }


def execute(
    *,
    outbox: Path,
    receipts: Path,
    registry: Path,
    state_path: Path,
    owner_uid: int | None,
    now: datetime | None = None,
) -> dict[str, Any]:
    current = (now or datetime.now(UTC)).astimezone(UTC)
    deliveries = load_outbox(outbox, owner_uid=owner_uid)
    existing = _load_receipts(receipts, owner_uid=owner_uid)
    state = load_state(state_path, owner_uid=owner_uid)
    entries = state["deliveries"]
    summary = {
        "delivered": 0,
        "retry_scheduled": 0,
        "dead_letter": 0,
        "already_receipted": 0,
        "idle": 0,
    }
    adapter: Path | None = None
    for delivery in sorted(deliveries, key=lambda item: item["delivery_id"]):
        delivery_id = delivery["delivery_id"]
        if delivery_id in existing:
            entries.pop(delivery_id, None)
            summary["already_receipted"] += 1
            continue
        prior = entries.get(delivery_id)
        if prior is not None:
            if prior["delivery"] != delivery:
                raise ExecutorError("delivery_state_tuple_conflict")
            if prior["state"] == "dead_letter":
                summary["dead_letter"] += 1
                continue
            if _parse_timestamp(prior["next_attempt_at"], error="delivery_state_invalid") > current:
                summary["idle"] += 1
                continue
            attempts = prior["attempts"]
        else:
            attempts = 0
        if adapter is None:
            adapter = resolve_adapter(registry, owner_uid=owner_uid)
        try:
            outcome, receipt = run_adapter(adapter, delivery)
            if outcome == "delivered":
                receipt = _validate_receipt(receipt, delivery)
        except ExecutorError:
            entries[delivery_id] = _entry(
                delivery,
                attempts=attempts + 1,
                state="dead_letter",
                next_attempt_at=current,
                now=current,
            )
            summary["dead_letter"] += 1
            continue
        if outcome == "delivered":
            assert receipt is not None
            if append_receipt(receipts, receipt, owner_uid=owner_uid):
                summary["delivered"] += 1
            else:
                summary["already_receipted"] += 1
            entries.pop(delivery_id, None)
            continue
        if outcome == "permanent_failure" or attempts + 1 >= MAX_ATTEMPTS:
            entries[delivery_id] = _entry(
                delivery,
                attempts=attempts + 1,
                state="dead_letter",
                next_attempt_at=current,
                now=current,
            )
            summary["dead_letter"] += 1
            continue
        delay = RETRY_DELAYS_SECONDS[attempts]
        entries[delivery_id] = _entry(
            delivery,
            attempts=attempts + 1,
            state="retry_scheduled",
            next_attempt_at=current + timedelta(seconds=delay),
            now=current,
        )
        summary["retry_scheduled"] += 1
    save_state(state_path, state, owner_uid=owner_uid)
    return {"schema": STATE_SCHEMA, **summary}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--outbox", type=Path, default=DEFAULT_STATE_ROOT / "job-delivery-outbox.json"
    )
    parser.add_argument(
        "--receipts", type=Path, default=DEFAULT_STATE_ROOT / "delivery-receipts.jsonl"
    )
    parser.add_argument("--registry", type=Path, default=DEFAULT_REGISTRY)
    parser.add_argument(
        "--state", type=Path, default=DEFAULT_STATE_ROOT / "task-delivery-executor-state.json"
    )
    args = parser.parse_args(argv)
    if os.geteuid() != 0:
        print("task delivery executor error: root_identity_required", file=sys.stderr)
        return 2
    try:
        print(
            json.dumps(
                execute(
                    outbox=args.outbox,
                    receipts=args.receipts,
                    registry=args.registry,
                    state_path=args.state,
                    owner_uid=0,
                ),
                sort_keys=True,
                separators=(",", ":"),
            )
        )
    except (ExecutorError, OSError) as error:
        print(f"task delivery executor error: {type(error).__name__}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
