#!/usr/bin/env python3
"""Audit the public-safe QDev runner health contract."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

DEFAULT_URL = "https://ci.qdev.run/health"


def evaluate(
    health: dict[str, Any], *, require_primary_slot: bool, require_reserve_slot: bool
) -> list[str]:
    errors: list[str] = []
    if health.get("ok") is not True:
        errors.append("broker_not_ok")
    if health.get("schema") != "qdev-runner-health-v1":
        errors.append("unexpected_health_schema")
    for tier in ("primary", "reserve"):
        if health.get(f"{tier}_present") is not True:
            errors.append(f"{tier}_not_present")
        if health.get(f"{tier}_capacity_allowed") is not True:
            errors.append(f"{tier}_capacity_blocked")
    if require_primary_slot and int(health.get("primary_slots_available", 0)) < 1:
        errors.append("primary_slot_unavailable")
    if require_reserve_slot and int(health.get("reserve_slots_available", 0)) < 1:
        errors.append("reserve_slot_unavailable")
    return errors


def fetch(url: str, timeout: float) -> dict[str, Any]:
    if urlparse(url).scheme != "https":
        raise ValueError("health URL must use https")
    request = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": "qdev-runner-runtime-audit/1"}
    )
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        document = json.load(response)
    if not isinstance(document, dict):
        raise ValueError("health response must be a JSON object")
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default=DEFAULT_URL)
    parser.add_argument("--timeout", type=float, default=15)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--require-primary-slot", action="store_true")
    parser.add_argument("--require-reserve-slot", action="store_true")
    args = parser.parse_args()
    try:
        health = fetch(args.url, args.timeout)
        errors = evaluate(
            health,
            require_primary_slot=args.require_primary_slot,
            require_reserve_slot=args.require_reserve_slot,
        )
    except (OSError, ValueError, urllib.error.URLError) as error:
        health = {}
        errors = [f"health_fetch_failed:{type(error).__name__}"]
    receipt = {
        "schema": "qdev-runner-runtime-audit-v1",
        "observed_at": datetime.now(UTC).isoformat(),
        "url": args.url,
        "status": "passed" if not errors else "failed",
        "errors": errors,
        "health": health,
    }
    rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
