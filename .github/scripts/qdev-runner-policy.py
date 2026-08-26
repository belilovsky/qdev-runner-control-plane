#!/usr/bin/env python3
"""Run the canonical repository-local runner policy implementation."""

from __future__ import annotations

import runpy
from pathlib import Path

POLICY = Path(__file__).resolve().parents[2] / "templates/qdev-runner-policy.py"
runpy.run_path(str(POLICY), run_name="__main__")
