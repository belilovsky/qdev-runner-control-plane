#!/usr/bin/env python3
"""Read-only or ledger-consuming QazPipe water provenance verifier for QazLake."""

# ruff: noqa: E402, I001

from __future__ import annotations

import sys
from pathlib import Path

SOURCE_ROOT = Path(__file__).resolve().parents[1] / "src"
if str(SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(SOURCE_ROOT))

from qdev_runner.qazpipe_water_provenance import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main(["verify", *sys.argv[1:]]))
