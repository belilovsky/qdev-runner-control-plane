#!/usr/bin/env python3
"""Own and release the persistent execution gate for one QDev runner worker."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import subprocess
import tempfile
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast


@dataclass(frozen=True)
class GatePaths:
    permit: Path = Path("/etc/qdev/qdev-runner-worker.enabled")
    marker: Path = Path("/etc/qdev/qdev-runner-worker.paused")
    state: Path = Path("/etc/qdev/qdev-runner-worker-gate.json")
    lock: Path = Path("/run/lock/qdev-runner-worker-gate.lock")
    receipts: Path = Path("/var/lib/qdev-runner-worker/gate-receipts")


CommandRunner = Callable[[list[str]], None]


def now() -> datetime:
    return datetime.now(UTC)


def timestamp(value: datetime) -> str:
    return value.strftime("%Y%m%dT%H%M%SZ")


def atomic_write(path: Path, content: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.chmod(mode)
        os.replace(temporary, path)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def read_json(path: Path) -> dict[str, Any]:
    return cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def write_json(path: Path, payload: dict[str, Any], *, mode: int = 0o600) -> None:
    atomic_write(path, json.dumps(payload, indent=2, sort_keys=True) + "\n", mode=mode)


@contextmanager
def exclusive_lock(path: Path) -> Iterator[None]:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a+", encoding="utf-8") as stream:
        fcntl.flock(stream.fileno(), fcntl.LOCK_EX)
        yield


def run_command(command: list[str]) -> None:
    subprocess.run(command, check=True)  # noqa: S603


def record_receipt(paths: GatePaths, action: str, payload: dict[str, Any]) -> Path:
    observed = now()
    receipt = paths.receipts / f"{timestamp(observed)}-{action}.json"
    write_json(
        receipt,
        {
            "schema": "qdev-runner-worker-gate-receipt-v1",
            "recorded_at": observed.isoformat(),
            "action": action,
            **payload,
        },
    )
    return receipt


def acquire(
    paths: GatePaths,
    *,
    owner: str,
    reason: str,
    force_owner_transfer: bool = False,
    runner: CommandRunner = run_command,
) -> Path:
    observed = now()
    with exclusive_lock(paths.lock):
        previous = read_json(paths.state) if paths.state.exists() else None
        previous_owner = previous.get("owner") if previous else None
        if (
            previous
            and previous.get("status") == "paused"
            and previous_owner != owner
            and not force_owner_transfer
        ):
            raise RuntimeError(f"worker gate is owned by {previous_owner!r}")

        paths.permit.unlink(missing_ok=True)
        atomic_write(paths.marker, "", mode=0o644)
        state = {
            "schema": "qdev-runner-worker-gate-v1",
            "status": "paused",
            "owner": owner,
            "reason": reason,
            "acquired_at": observed.isoformat(),
            "previous_owner": previous_owner if previous_owner != owner else None,
            "forced_owner_transfer": bool(force_owner_transfer and previous_owner != owner),
        }
        write_json(paths.state, state)
        runner(["systemctl", "daemon-reload"])
        runner(["systemctl", "stop", "--no-block", "qdev-runner-worker.service"])
        return record_receipt(paths, "acquire", state)


def validate_runtime_receipt(path: Path, *, max_age_seconds: int = 900) -> dict[str, Any]:
    payload = read_json(path)
    if payload.get("schema") != "qdev-runner-worker-runtime-audit-v1":
        raise RuntimeError("unexpected worker runtime receipt schema")
    if payload.get("status") != "passed" or payload.get("errors"):
        raise RuntimeError("worker runtime audit did not pass")
    observed_at = datetime.fromisoformat(str(payload["observed_at"]))
    if observed_at.tzinfo is None:
        raise RuntimeError("worker runtime receipt has no timezone")
    age = (now() - observed_at.astimezone(UTC)).total_seconds()
    if age < -60 or age > max_age_seconds:
        raise RuntimeError(f"worker runtime receipt is stale: age={age:.0f}s")
    return payload


def release(
    paths: GatePaths,
    *,
    owner: str,
    reason: str,
    runtime_receipt: Path,
    max_age_seconds: int = 900,
    runner: CommandRunner = run_command,
) -> Path:
    audit = validate_runtime_receipt(runtime_receipt, max_age_seconds=max_age_seconds)
    observed = now()
    with exclusive_lock(paths.lock):
        if not paths.state.exists():
            raise RuntimeError("worker gate has no ownership state")
        previous = read_json(paths.state)
        if previous.get("status") != "paused":
            raise RuntimeError("worker gate is not paused")
        if previous.get("owner") != owner:
            raise RuntimeError(f"worker gate is owned by {previous.get('owner')!r}")

        permit = {
            "schema": "qdev-runner-worker-permit-v1",
            "owner": owner,
            "released_at": observed.isoformat(),
            "runtime_receipt": str(runtime_receipt),
        }
        atomic_write(paths.permit, json.dumps(permit, sort_keys=True) + "\n", mode=0o600)
        paths.marker.unlink(missing_ok=True)
        state = {
            "schema": "qdev-runner-worker-gate-v1",
            "status": "enabled",
            "owner": owner,
            "reason": reason,
            "released_at": observed.isoformat(),
            "runtime_receipt": str(runtime_receipt),
            "worker_name": audit.get("worker_name"),
            "tier": audit.get("tier"),
        }
        write_json(paths.state, state)
        runner(["systemctl", "daemon-reload"])
        runner(["systemctl", "start", "qdev-runner-worker.service"])
        return record_receipt(paths, "release", state)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)

    acquire_parser = subparsers.add_parser("acquire")
    acquire_parser.add_argument("--owner", required=True)
    acquire_parser.add_argument("--reason", required=True)
    acquire_parser.add_argument("--force-owner-transfer", action="store_true")

    release_parser = subparsers.add_parser("release")
    release_parser.add_argument("--owner", required=True)
    release_parser.add_argument("--reason", required=True)
    release_parser.add_argument("--runtime-receipt", type=Path, required=True)
    release_parser.add_argument("--max-age-seconds", type=int, default=900)

    subparsers.add_parser("status")
    return parser.parse_args()


def main() -> int:
    if os.geteuid() != 0:
        raise SystemExit("run as root")
    args = parse_args()
    paths = GatePaths()
    if args.action == "acquire":
        receipt = acquire(
            paths,
            owner=args.owner,
            reason=args.reason,
            force_owner_transfer=args.force_owner_transfer,
        )
        print(f"worker_gate=paused receipt={receipt}")
    elif args.action == "release":
        receipt = release(
            paths,
            owner=args.owner,
            reason=args.reason,
            runtime_receipt=args.runtime_receipt,
            max_age_seconds=args.max_age_seconds,
        )
        print(f"worker_gate=enabled receipt={receipt}")
    else:
        if paths.state.exists():
            print(paths.state.read_text(encoding="utf-8"), end="")
        else:
            print('{"status":"unmanaged"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
