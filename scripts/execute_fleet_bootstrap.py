#!/usr/bin/env python3
"""Run one controller-owned existing-worker recovery operation.

This entrypoint is for the privileged controller host/container only.  The
GitHub validation workflow must never run it: it has no CA/private-key access,
and this command requires a controller-observed no-active-work count plus a
controller-installed recovery adapter.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from pydantic import ValidationError

from qdev_runner.fleet_bootstrap import (
    BootstrapOperationStore,
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
)
from qdev_runner.fleet_bootstrap_executor import execute_existing_worker_recovery

ROOT = Path(__file__).resolve().parents[1]


def _request(path: Path) -> FleetBootstrapRequest:
    try:
        raw: Any = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("request must be an object")
        return FleetBootstrapRequest.model_validate(raw)
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        ValueError,
        ValidationError,
    ) as error:
        raise FleetBootstrapError("bootstrap request file is invalid") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="execute-fleet-bootstrap",
        description="Execute one controller-registered existing-worker recovery.",
    )
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--idempotency-key", required=True)
    parser.add_argument("--active-jobs", required=True, type=int)
    parser.add_argument(
        "--adapter",
        type=Path,
        help="Absolute controller-installed recovery adapter (or QDEV_FLEET_RECOVERY_EXECUTABLE).",
    )
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--operation-state", type=Path, required=True)
    parser.add_argument("--policy", type=Path, default=ROOT / "config" / "fleet-bootstrap.yml")
    parser.add_argument("--release-lanes", type=Path, default=ROOT / "config" / "release-lanes.yml")
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    return parser


def run(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        request = _request(arguments.request)
        policy = FleetBootstrapPolicy(arguments.policy, arguments.release_lanes)
        result = execute_existing_worker_recovery(
            policy=policy,
            store=BootstrapOperationStore(arguments.operation_state),
            request=request,
            idempotency_key=arguments.idempotency_key,
            active_jobs=arguments.active_jobs,
            adapter=arguments.adapter,
            timeout_seconds=arguments.timeout_seconds,
            receipt_path=arguments.receipt,
        )
    except (FleetBootstrapError, ValueError) as error:
        print(f"fleet_bootstrap_execution_failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result.as_dict(), ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if result.status == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(run())
