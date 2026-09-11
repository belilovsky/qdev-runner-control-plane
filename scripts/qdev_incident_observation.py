#!/usr/bin/env python3
"""Collect the aggregate observation consumed by ``qdev_incident_watchdog``.

The collector is deliberately dependency-free so it can run from the immutable
release tree as a root ``oneshot`` systemd unit.  It reads only the public
``/health`` document plus one optional aggregate internal document and writes a
single local ``observation.json``.  It never contacts runners, never reads
secrets, and never publishes anything itself.

Two of the watchdog thresholds are dwell times, not instantaneous ages:
``controller_activation`` must not stay non-``active`` for more than two
minutes, and a pending queue must not stay without an eligible slot for more
than two minutes.  Those are tracked here in a small durable ``dwell.json`` so
that a restart of the collector never resets the clock.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

SCHEMA = "qdev-ci-incident-observation-v1"
DWELL_SCHEMA = "qdev-ci-incident-dwell-v1"
INTERNAL_SCHEMA = "qdev-ci-incident-internal-observation-v1"

ACTIVATION_DWELL_KEY = "activation_not_active_since"
NO_SLOT_DWELL_KEY = "pending_without_slot_since"


class ObservationError(RuntimeError):
    """The health document or a local document is unusable."""


def _now() -> datetime:
    return datetime.now(UTC)


def _iso(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _parse_timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = f"{text[:-1]}+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _elapsed_since(stamp: Any, now: datetime) -> float | None:
    parsed = _parse_timestamp(stamp)
    if parsed is None:
        return None
    return max(0.0, (now - parsed).total_seconds())


def load_document(source: str, *, timeout: float = 20.0) -> Mapping[str, Any]:
    """Load a JSON document from an ``https`` URL or a local path."""

    if urlparse(source).scheme in ("http", "https"):
        if urlparse(source).scheme != "https":
            raise ObservationError("health endpoint must use https")
        request = urllib.request.Request(  # noqa: S310
            source, headers={"Accept": "application/json"}
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
                payload = response.read()
        except urllib.error.URLError as exc:
            raise ObservationError(f"health endpoint unreachable: {exc.reason}") from exc
        document = json.loads(payload.decode("utf-8"))
    else:
        document = json.loads(Path(source).read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise ObservationError("document must be a JSON object")
    return document


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _optional_float(value: Any) -> float | None:
    """An unmeasured value stays ``null`` instead of collapsing to zero."""

    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _load_internal(path: Path) -> Mapping[str, Any]:
    if not path.exists():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, Mapping):
        raise ObservationError("internal observation must be a JSON object")
    if document.get("schema") not in (None, INTERNAL_SCHEMA):
        raise ObservationError("internal observation has an unexpected schema")
    return document


def _load_dwell(state_root: Path) -> dict[str, Any]:
    path = state_root / "dwell.json"
    if not path.exists():
        return {"schema": DWELL_SCHEMA, ACTIVATION_DWELL_KEY: None, NO_SLOT_DWELL_KEY: None}
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != DWELL_SCHEMA:
        raise ObservationError("dwell state has an unexpected schema")
    return document


def _save_dwell(state_root: Path, document: Mapping[str, Any]) -> None:
    path = state_root / "dwell.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def _dwell_seconds(
    document: dict[str, Any],
    key: str,
    *,
    active: bool,
    now: datetime,
) -> float:
    """Seconds the *active* condition has continuously held, tracked durably."""

    if not active:
        document[key] = None
        return 0.0
    since = _parse_timestamp(document.get(key))
    if since is None or since > now:
        document[key] = _iso(now)
        return 0.0
    return max(0.0, (now - since).total_seconds())


def collect(
    health: Mapping[str, Any],
    *,
    internal: Mapping[str, Any],
    dwell: dict[str, Any],
    now: datetime | None = None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Build the observation document and the updated dwell document."""

    now = now or _now()
    activation = health.get("controller_activation") or {}
    activation_state = str(activation.get("state") or "unavailable")
    pending_jobs = _int(health.get("pending"))
    eligible_slots = _int(health.get("primary_slots_available")) + _int(
        health.get("reserve_slots_available")
    )

    activation_age = _dwell_seconds(
        dwell, ACTIVATION_DWELL_KEY, active=activation_state != "active", now=now
    )
    no_slot_age = _dwell_seconds(
        dwell,
        NO_SLOT_DWELL_KEY,
        active=pending_jobs > 0 and eligible_slots == 0,
        now=now,
    )

    fifo_head_age = health.get("oldest_pending_age_seconds")
    if fifo_head_age is None:
        fifo_head_age = internal.get("fifo_head_age_seconds", 0)

    observation = {
        "schema": SCHEMA,
        "observed_at": _iso(now),
        "activation_state": activation_state,
        "activation_age_seconds": activation_age,
        "pending_jobs": pending_jobs,
        "eligible_slots": eligible_slots,
        "no_slot_pending_seconds": no_slot_age,
        "fifo_head_age_seconds": _float(fifo_head_age),
        "worker_heartbeat_age_seconds": _float(internal.get("worker_heartbeat_age_seconds")),
        "oldest_claim_age_seconds": _float(internal.get("oldest_claim_age_seconds")),
        "disk_free_gib": _optional_float(internal.get("disk_free_gib")),
        "disk_used_pct": _optional_float(internal.get("disk_used_pct")),
        "missing_images": [str(item) for item in internal.get("missing_images", ())],
        "provider_block": (
            str(internal["provider_block"]) if internal.get("provider_block") else None
        ),
        "healthy_workers": _int(internal.get("healthy_workers")),
        "active_jobs": _int(internal.get("active_jobs")),
        "registered_reserve_hosts": [
            str(item) for item in internal.get("registered_reserve_hosts", ())
        ],
        "waiting_jobs": [
            {
                "repository": str(item["repository"]),
                "run_id": _int(item["run_id"]),
                "job_id": _int(item["job_id"]),
                "status": str(item["status"]),
                "started": bool(item["started"]),
            }
            for item in internal.get("waiting_jobs", ())
        ],
    }
    return observation, dwell


def write_observation(path: Path, observation: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(observation, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--health", default="https://ci.qdev.run/health")
    parser.add_argument(
        "--state-root", type=Path, default=Path("/var/lib/qdev-runner/incident-watchdog")
    )
    parser.add_argument("--internal", type=Path, default=None)
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args(argv)

    internal_path = args.internal or args.state_root / "internal-observation.json"
    output = args.output or args.state_root / "observation.json"
    try:
        health = load_document(args.health)
        internal = _load_internal(internal_path)
        dwell = _load_dwell(args.state_root)
        observation, dwell = collect(health, internal=internal, dwell=dwell)
        write_observation(output, observation)
        _save_dwell(args.state_root, dwell)
    except (ObservationError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"observation error: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(observation, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
