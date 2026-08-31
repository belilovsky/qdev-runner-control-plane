#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from qdev_runner.operator import validate_receipt_file  # noqa: E402


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: validate_operation_receipt.py RECEIPT.json", file=sys.stderr)
        return 2
    key = os.environ.get("QDEV_OPERATOR_RECEIPT_KEY", "").strip()
    if not key:
        print("QDEV_OPERATOR_RECEIPT_KEY is required", file=sys.stderr)
        return 2
    try:
        receipt = validate_receipt_file(Path(sys.argv[1]), receipt_key=key)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"invalid receipt: {error}", file=sys.stderr)
        return 1
    print(receipt["receipt_id"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
