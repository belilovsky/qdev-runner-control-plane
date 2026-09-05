"""Synthetic authenticated worker evidence, used only in isolated unit databases."""

from __future__ import annotations

import time
from typing import Any

from qdev_runner.store import Store
from qdev_runner.worker_runtime_audit import PROFILE_IMAGES


def worker_detail(
    name: str = "worker-1", profiles: tuple[str, ...] = ("qdev-ci",), *,
    tier: str = "primary", concurrency: int = 1, disk_free_gib: float = 100,
    active_ids: tuple[int, ...] = (),
) -> dict[str, Any]:
    capacity = {
        "allowed": True, "blockers": [], "disk_used_pct": 40,
        "disk_free_gib": disk_free_gib, "memory_available_gib": 8,
        "load_15": 0.5, "cpu_psi_avg10": 1, "cpus": 4,
    }
    keys = sorted({key for profile in profiles for key in PROFILE_IMAGES.get(profile, ())})
    return {
        **capacity, "tier": tier, "concurrency": concurrency,
        "active_job_ids": list(active_ids), "effective_profiles": list(profiles),
        "min_disk_free_gib": 30, "max_disk_used_pct": 85,
        "raw_capacity": dict(capacity), "baseline_capacity": dict(capacity),
        "effective_capacity": dict(capacity),
        "controller_enrollment": {
            "schema": "qdev-worker-enrollment-v1", "authenticated": True,
            "worker_name": name, "tier": tier, "profiles": list(profiles),
        },
        "runtime_audit": {
            "schema": "qdev-runner-worker-runtime-audit-v1", "status": "passed",
            "errors": [], "worker_name": name, "tier": tier, "profiles": list(profiles),
            "observed_at": time.time(), "image_release": {
                "status": "verified", "manifest_digest": "sha256:" + "a" * 64,
                "checked_artifacts": keys,
            },
            "images": [{"configuration": key, "reference": "test/image@sha256:" + "b" * 64,
                        "present": True, "image_id": "sha256:" + "c" * 64} for key in keys],
        },
    }


def seed_worker(
    store: Store, name: str = "worker-1", profiles: tuple[str, ...] = ("qdev-ci",), *,
    tier: str = "primary", concurrency: int = 1, disk_free_gib: float = 100,
    active_ids: tuple[int, ...] = (), detail: dict[str, Any] | None = None,
) -> None:
    store.heartbeat(name, profiles, len(active_ids), active_ids, detail or worker_detail(
        name, profiles, tier=tier, concurrency=concurrency, disk_free_gib=disk_free_gib,
        active_ids=active_ids,
    ))
