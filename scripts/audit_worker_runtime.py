#!/usr/bin/env python3
"""Audit one worker's identity and locally materialized executor images."""

from __future__ import annotations

import argparse
import json
import shlex
import subprocess
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DEFAULT_IMAGES = {
    "QDEV_RUNNER_IMAGE": "registry.ci.qdev.run/qdev/actions-runner:2.336.0-r2",
    "QDEV_RUNNER_BROWSER_IMAGE": (
        "registry.ci.qdev.run/qdev/actions-runner-browser:2.336.0-r2"
    ),
    "QDEV_RUNNER_DOCKER_IMAGE": (
        "registry.ci.qdev.run/qdev/actions-runner-buildkit:2.336.0-r2"
    ),
    "QDEV_DOCKER_SIDECAR_IMAGE": (
        "docker.io/library/docker@sha256:"
        "2a232a42256f70d78e3cc5d2b5d6b3276710a0de0596c145f627ecfae90282ac"
    ),
}
PROFILE_IMAGES = {
    "qdev-ci": ("QDEV_RUNNER_IMAGE",),
    "qdev-ci-browser": ("QDEV_RUNNER_BROWSER_IMAGE",),
    "qdev-ci-compose": ("QDEV_RUNNER_DOCKER_IMAGE", "QDEV_DOCKER_SIDECAR_IMAGE"),
    "qdev-ci-docker": ("QDEV_RUNNER_DOCKER_IMAGE", "QDEV_DOCKER_SIDECAR_IMAGE"),
}
SAFE_KEYS = {
    "QDEV_WORKER_NAME",
    "QDEV_WORKER_TIER",
    "QDEV_WORKER_PROFILES",
    "QDEV_CONTAINER_ENGINE",
    *DEFAULT_IMAGES,
}


def parse_value(value: str) -> str:
    parts = shlex.split(value, posix=True)
    if len(parts) != 1:
        raise ValueError("worker environment value must contain exactly one token")
    return parts[0]


def load_contract(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw_value = line.partition("=")
        if separator and key in SAFE_KEYS:
            values[key] = parse_value(raw_value)
    return values


def required_images(values: dict[str, str]) -> list[tuple[str, str]]:
    profiles = {
        profile.strip()
        for profile in values.get(
            "QDEV_WORKER_PROFILES", "qdev-ci,qdev-ci-browser,qdev-ci-docker"
        ).split(",")
        if profile.strip()
    }
    keys: list[str] = []
    for profile in sorted(profiles):
        keys.extend(PROFILE_IMAGES.get(profile, ()))
    return [(key, values.get(key, DEFAULT_IMAGES[key])) for key in dict.fromkeys(keys)]


def inspect_image(engine: str, reference: str) -> tuple[bool, str | None]:
    try:
        result = subprocess.run(  # noqa: S603
            [engine, "image", "inspect", "--format", "{{.Id}}", reference],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False, None
    image_id = result.stdout.strip() if result.returncode == 0 else ""
    return bool(image_id), image_id or None


def evaluate(
    values: dict[str, str],
    *,
    inspector: Callable[[str, str], tuple[bool, str | None]] = inspect_image,
) -> dict[str, Any]:
    errors: list[str] = []
    worker_name = values.get("QDEV_WORKER_NAME", "")
    tier = values.get("QDEV_WORKER_TIER", "")
    if tier not in {"primary", "reserve"}:
        errors.append("invalid_worker_tier")
    if not worker_name:
        errors.append("missing_worker_name")
    elif tier in {"primary", "reserve"} and not worker_name.endswith(f"-{tier}"):
        errors.append("worker_name_tier_mismatch")

    engine = values.get("QDEV_CONTAINER_ENGINE", "docker")
    images = []
    for key, reference in required_images(values):
        present, image_id = inspector(engine, reference)
        images.append(
            {
                "configuration": key,
                "reference": reference,
                "present": present,
                "image_id": image_id,
            }
        )
        if not present:
            errors.append(f"image_missing:{key}")
    return {
        "worker_name": worker_name or None,
        "tier": tier or None,
        "container_engine": engine,
        "images": images,
        "errors": errors,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--env-file", type=Path, default=Path("/etc/qdev-runner/worker.env"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        result = evaluate(load_contract(args.env_file))
    except (OSError, ValueError) as error:
        result = {
            "worker_name": None,
            "tier": None,
            "container_engine": None,
            "images": [],
            "errors": [f"contract_read_failed:{type(error).__name__}"],
        }
    receipt = {
        "schema": "qdev-runner-worker-runtime-audit-v1",
        "observed_at": datetime.now(UTC).isoformat(),
        "status": "passed" if not result["errors"] else "failed",
        **result,
    }
    rendered = json.dumps(receipt, indent=2, sort_keys=True) + "\n"
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    sys.stdout.write(rendered)
    return 0 if not result["errors"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
