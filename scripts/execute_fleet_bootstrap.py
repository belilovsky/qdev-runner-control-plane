#!/usr/bin/env python3
"""Compatibility entrypoint to authenticated controller worker recovery.

Raw request JSON no longer grants local privileged execution. The normal
operator mTLS session and fresh GitHub OIDC identity are both required; the
controller supplies the target, scheduling hold, adapter and operation journal.
"""

from __future__ import annotations

import json
import sys

from qdev_runner.operator import run as operator_run


def run(argv: list[str] | None = None) -> int:
    try:
        arguments = argv if argv is not None else sys.argv[1:]
        receipt = operator_run(["fleet-bootstrap", *arguments])
    except (OSError, ValueError, RuntimeError):
        print(
            "fleet_bootstrap_execution_failed: controller authorization required", file=sys.stderr
        )
        return 1
    print(json.dumps(receipt, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0 if receipt.get("payload", {}).get("status") == "completed" else 2


if __name__ == "__main__":
    raise SystemExit(run())
