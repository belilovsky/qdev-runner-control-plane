"""One fail-closed worker admission decision for audit and durable scheduling.

Heartbeat authentication and enrollment are recorded by the broker, never by
the worker. Runtime inspection is produced by the authenticated worker using
the same strict image-evidence verifier as the native operator audit.
"""

from __future__ import annotations

import json
import math
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .operations import DISK_ONLY_BLOCKERS, HARD_MAX_DISK_USED_PCT, HARD_MIN_FREE_GIB
from .worker_runtime_audit import PROFILE_IMAGES

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IMAGE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")
METRICS = (
    "disk_used_pct", "disk_free_gib", "memory_available_gib", "load_15",
    "cpu_psi_avg10", "cpus",
)


def mapping(value: object) -> dict[str, Any]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return {}
    return value if isinstance(value, dict) else {}


def strings(value: object) -> tuple[str, ...]:
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError:
            return ()
    if not isinstance(value, (list, tuple)) or any(not isinstance(x, str) for x in value):
        return ()
    return tuple(value)


def number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        return float(value) if math.isfinite(value) else None
    except OverflowError:
        return None


def _timestamp(value: object) -> float | None:
    if isinstance(value, str):
        try:
            date = datetime.fromisoformat(value.replace("Z", "+00:00"))
            value = date.timestamp() if date.tzinfo is not None else None
        except (ValueError, OverflowError):
            return None
    return number(value)


def _fresh(value: object, now: float, max_age: float) -> bool:
    timestamp = _timestamp(value)
    return timestamp is not None and 0 <= now - timestamp < max_age


@dataclass(frozen=True)
class Admission:
    allowed: bool
    profiles: tuple[str, ...]
    slots: int
    blockers: tuple[str, ...]


def worker_admission(
    worker: dict[str, Any], *, now: float, durable_active: int = 0,
    max_age: float = 90, fenced: bool = False,
) -> Admission:
    """Reject incomplete/legacy evidence without interrupting existing jobs."""
    detail = mapping(worker.get("detail_json"))
    name = worker.get("name")
    tier = detail.get("tier")
    profiles = strings(worker.get("profiles_json"))
    effective_profiles = strings(detail.get("effective_profiles"))
    blockers: list[str] = []
    if not _fresh(worker.get("last_seen"), now, max_age):
        blockers.append("heartbeat_stale_or_invalid")
    enrollment = mapping(detail.get("controller_enrollment"))
    if (
        enrollment.get("schema") != "qdev-worker-enrollment-v1"
        or enrollment.get("worker_name") != name
        or enrollment.get("tier") != tier
        or enrollment.get("profiles") != list(profiles)
        or enrollment.get("authenticated") is not True
        or tier not in ("primary", "reserve")
        or not isinstance(name, str) or not name
    ):
        blockers.append("worker_identity_unenrolled")
    if (
        not profiles or set(profiles).difference(PROFILE_IMAGES)
        or len(set(profiles)) != len(profiles)
        or not effective_profiles or not set(effective_profiles).issubset(profiles)
    ):
        blockers.append("worker_profiles_invalid")
    audit = mapping(detail.get("runtime_audit"))
    release = mapping(audit.get("image_release"))
    expected_keys = {
        key for profile in profiles for key in PROFILE_IMAGES.get(profile, ())
    }
    images = audit.get("images")
    image_map = {
        image["configuration"]: image for image in images
        if isinstance(image, dict) and isinstance(image.get("configuration"), str)
    } if isinstance(images, list) else {}
    if (
        audit.get("schema") != "qdev-runner-worker-runtime-audit-v1"
        or audit.get("status") != "passed" or audit.get("errors") != []
        or audit.get("worker_name") != name or audit.get("tier") != tier
        or audit.get("profiles") != list(profiles)
        or not _fresh(audit.get("observed_at"), now, max_age)
        or release.get("status") != "verified"
        or not _DIGEST.fullmatch(str(release.get("manifest_digest", "")))
        or set(strings(release.get("checked_artifacts"))) != expected_keys
        or set(image_map) != expected_keys
        or not isinstance(images, list) or len(images) != len(expected_keys)
        or any(
            image.get("present") is not True
            or not _IMAGE.fullmatch(str(image.get("reference", "")))
            or not _DIGEST.fullmatch(str(image.get("image_id", "")))
            for image in image_map.values()
        )
    ):
        blockers.append("runtime_image_evidence_unverified")
    raw = mapping(detail.get("raw_capacity"))
    baseline = mapping(detail.get("baseline_capacity"))
    effective = mapping(detail.get("effective_capacity"))
    valid_metrics = all(
        number(capacity.get(key)) is not None and capacity[key] >= 0
        for capacity in (raw, baseline, effective) for key in METRICS
    )
    if valid_metrics:
        valid_metrics = (
            raw["cpus"] >= 1 and int(raw["cpus"]) == raw["cpus"]
            and raw["disk_used_pct"] <= 100 and raw["cpu_psi_avg10"] <= 100
            and all(raw[key] == baseline[key] == effective[key] for key in METRICS)
        )
    if not valid_metrics:
        blockers.append("resource_measurements_missing_or_invalid")
    else:
        # Memory and CPU gates cannot be lowered by an allowed bit, a disk
        # override, or a forged baseline/effective threshold.
        if raw["memory_available_gib"] < 4 or raw["load_15"] >= raw["cpus"] * 2:
            blockers.append("non_disk_capacity_blocked")
        minimum = number(detail.get("min_disk_free_gib"))
        maximum = number(detail.get("max_disk_used_pct"))
        if (
            minimum is None or maximum is None or minimum < HARD_MIN_FREE_GIB
            or not 0 < maximum <= HARD_MAX_DISK_USED_PCT
            or raw["disk_free_gib"] < minimum or raw["disk_used_pct"] >= maximum
        ):
            blockers.append("disk_capacity_blocked")
        override = detail.get("capacity_directive_id")
        if override:
            expiry = _timestamp(detail.get("capacity_directive_expires_at"))
            if expiry is None or not 0 < expiry - now <= 900:
                blockers.append("capacity_override_expired_or_invalid")
            baseline_blockers = set(strings(baseline.get("blockers")))
            if (
                not baseline_blockers or not baseline_blockers.issubset(DISK_ONLY_BLOCKERS)
                or baseline.get("allowed") is not False
            ):
                blockers.append("capacity_override_not_disk_only")
        else:
            if minimum is not None and maximum is not None and (minimum < 30 or maximum > 85):
                blockers.append("unsigned_capacity_override")
            if baseline.get("allowed") is not True or baseline.get("blockers") not in ([], ()):
                blockers.append("baseline_capacity_denied")
    if detail.get("allowed") is not True or effective.get("allowed") is not True:
        blockers.append("effective_capacity_denied")
    if effective.get("blockers") not in ([], ()):
        blockers.append("effective_capacity_blockers")
    concurrency = number(detail.get("concurrency"))
    active = number(worker.get("active_jobs"))
    active_ids = detail.get("active_job_ids")
    if (
        concurrency is None or concurrency < 1 or int(concurrency) != concurrency
        or active is None or active < 0 or int(active) != active
        or not isinstance(active_ids, list)
        or any(isinstance(x, bool) or not isinstance(x, int) or x <= 0 for x in active_ids)
        or len(set(active_ids)) != len(active_ids) or len(active_ids) != active
    ):
        blockers.append("worker_slots_unverifiable")
        slots = 0
    else:
        slots = max(0, int(concurrency) - max(int(active), durable_active))
    if fenced:
        blockers.append("worker_recovery_fenced")
    if not slots:
        blockers.append("worker_busy")
    allowed = not blockers
    return Admission(allowed, effective_profiles if allowed else (), slots if allowed else 0,
                     tuple(blockers))
