#!/usr/bin/env python3
"""Print a generated, read-only v1 compatibility projection of the ledger."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from qdev_runner.admin_platform import AdminPlatformLedger, AdminPlatformLedgerError


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "ledger",
        nargs="?",
        type=Path,
        default=Path("config/admin-platform-ledger-v2.yml"),
    )
    args = parser.parse_args()
    try:
        projection = AdminPlatformLedger(args.ledger).compatibility_snapshot_v1()
    except AdminPlatformLedgerError as error:
        parser.error(str(error))
    print(json.dumps(projection, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
