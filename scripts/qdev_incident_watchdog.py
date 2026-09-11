#!/usr/bin/env python3
"""Two-minute incident watchdog for the QDev CI control plane.

The watchdog is deliberately dependency-free: it can run straight from the
immutable release tree as a root ``oneshot`` systemd unit.  It consumes only an
aggregate observation document (activation state, queue shape, heartbeat and
claim ages, disk floor, image presence, provider block) and never reads runner
identity, repository names, SHAs or secrets into anything it publishes.

Alerting is deduplicated by ``incident_id + state_digest + audience`` so an
unchanged healthy state stays silent, a material state change is reported once,
and recovery is reported once.  Publishing only ever contains aggregate fields.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = "qdev-ci-incident-watchdog-v1"
STATE_SCHEMA = "qdev-ci-incident-watchdog-state-v1"
INCIDENT_ID = "qdev-ci-four-vps-20260911"

# Published SLO thresholds.  Every one of them is an operational contract, not
# a tunable default: keep them identical in code, docs, units and tests.
ACTIVATION_STALE_SECONDS = 120
NO_SLOT_PENDING_SECONDS = 120
FIFO_HEAD_WARN_SECONDS = 300
FIFO_HEAD_CRITICAL_SECONDS = 900
HEARTBEAT_STALE_SECONDS = 90
CLAIM_STALE_SECONDS = 300
LOOP_SECONDS = 120

OPERATOR_AUDIENCE = "qdev-fleet-operations"
TASK_AUDIENCE = "codex-tasks"
AUDIENCES = (OPERATOR_AUDIENCE, TASK_AUDIENCE)

SEVERITY_WARNING = "warning"
SEVERITY_CRITICAL = "critical"


class WatchdogError(RuntimeError):
    """The observation document or the durable ledger is unusable."""


@dataclass(frozen=True)
class WaitingJob:
    repository: str
    run_id: int
    job_id: int
    status: str
    started: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any] | WaitingJob) -> WaitingJob:
        if isinstance(value, cls):
            return value
        return cls(
            repository=str(value["repository"]),
            run_id=int(value["run_id"]),
            job_id=int(value["job_id"]),
            status=str(value["status"]),
            started=bool(value["started"]),
        )


@dataclass(frozen=True)
class Observation:
    """Aggregate control-plane state measured at one instant."""

    activation_state: str
    activation_age_seconds: float
    pending_jobs: int
    eligible_slots: int
    no_slot_pending_seconds: float
    fifo_head_age_seconds: float
    worker_heartbeat_age_seconds: float
    oldest_claim_age_seconds: float
    disk_free_gib: float | None = None
    disk_used_pct: float | None = None
    missing_images: tuple[str, ...] = ()
    provider_block: str | None = None
    healthy_workers: int = 0
    active_jobs: int = 0
    registered_reserve_hosts: tuple[str, ...] = ()
    waiting_jobs: tuple[WaitingJob, ...] = ()
    observed_at: str = field(default_factory=lambda: _now())

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> Observation:
        return cls(
            activation_state=str(value.get("activation_state", "unavailable")),
            activation_age_seconds=float(value.get("activation_age_seconds", 0)),
            pending_jobs=int(value.get("pending_jobs", 0)),
            eligible_slots=int(value.get("eligible_slots", 0)),
            no_slot_pending_seconds=float(value.get("no_slot_pending_seconds", 0)),
            fifo_head_age_seconds=float(value.get("fifo_head_age_seconds", 0)),
            worker_heartbeat_age_seconds=float(value.get("worker_heartbeat_age_seconds", 0)),
            oldest_claim_age_seconds=float(value.get("oldest_claim_age_seconds", 0)),
            disk_free_gib=_optional_float(value.get("disk_free_gib")),
            disk_used_pct=_optional_float(value.get("disk_used_pct")),
            missing_images=tuple(str(item) for item in value.get("missing_images", ())),
            provider_block=(str(value["provider_block"]) if value.get("provider_block") else None),
            healthy_workers=int(value.get("healthy_workers", 0)),
            active_jobs=int(value.get("active_jobs", 0)),
            registered_reserve_hosts=tuple(
                str(item) for item in value.get("registered_reserve_hosts", ())
            ),
            waiting_jobs=tuple(
                WaitingJob.from_mapping(item) for item in value.get("waiting_jobs", ())
            ),
            observed_at=str(value.get("observed_at") or _now()),
        )


@dataclass(frozen=True)
class Breach:
    code: str
    severity: str
    detail: str
    audience: str = OPERATOR_AUDIENCE


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _optional_float(value: Any) -> float | None:
    """Unknown measurements stay unknown: absent is never read as zero."""

    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def evaluate(
    observation: Observation,
    *,
    min_disk_free_gib: float = 4.5,
    max_disk_used_pct: float = 90.0,
) -> tuple[Breach, ...]:
    """Return every active SLO breach for one observation."""

    breaches: list[Breach] = []
    if (
        observation.activation_state != "active"
        and observation.activation_age_seconds >= ACTIVATION_STALE_SECONDS
    ):
        breaches.append(
            Breach(
                "controller_activation_not_active",
                SEVERITY_CRITICAL,
                "controller_activation has not been active beyond the two minute limit",
            )
        )
    if (
        observation.pending_jobs > 0
        and observation.eligible_slots == 0
        and observation.no_slot_pending_seconds >= NO_SLOT_PENDING_SECONDS
    ):
        breaches.append(
            Breach(
                "pending_without_eligible_slot",
                SEVERITY_CRITICAL,
                "queue has pending jobs and no eligible slot beyond the two minute limit",
            )
        )
    if observation.fifo_head_age_seconds >= FIFO_HEAD_CRITICAL_SECONDS:
        breaches.append(
            Breach(
                "fifo_head_critical",
                SEVERITY_CRITICAL,
                "FIFO head has been waiting beyond fifteen minutes",
            )
        )
    elif observation.fifo_head_age_seconds >= FIFO_HEAD_WARN_SECONDS:
        breaches.append(
            Breach(
                "fifo_head_delayed",
                SEVERITY_WARNING,
                "FIFO head has been waiting beyond five minutes",
            )
        )
    if observation.worker_heartbeat_age_seconds > HEARTBEAT_STALE_SECONDS:
        breaches.append(
            Breach(
                "worker_heartbeat_stale",
                SEVERITY_CRITICAL,
                "worker heartbeat is older than ninety seconds",
            )
        )
    if observation.oldest_claim_age_seconds > CLAIM_STALE_SECONDS:
        breaches.append(
            Breach(
                "claim_stale",
                SEVERITY_CRITICAL,
                "an unscoped claim is older than three hundred seconds",
            )
        )
    free_floor_breached = (
        observation.disk_free_gib is not None and observation.disk_free_gib < min_disk_free_gib
    )
    used_ceiling_breached = (
        observation.disk_used_pct is not None and observation.disk_used_pct > max_disk_used_pct
    )
    if free_floor_breached or used_ceiling_breached:
        breaches.append(
            Breach(
                "resource_floor_crossed",
                SEVERITY_CRITICAL,
                "host capacity crossed the published free-space or usage bound",
            )
        )
    if observation.missing_images:
        breaches.append(
            Breach(
                "immutable_image_missing",
                SEVERITY_CRITICAL,
                "an immutable runner or controller image is missing",
            )
        )
    if observation.provider_block:
        breaches.append(
            Breach(
                "provider_block",
                SEVERITY_WARNING,
                "provider or billing block is in effect",
            )
        )
    return tuple(breaches)


def state_digest(breaches: Iterable[Breach], observation: Observation) -> str:
    """Digest the aggregate state so unchanged health stays silent."""

    payload = {
        "breaches": sorted({(item.code, item.severity) for item in breaches}),
        "aggregate": {
            "activation_state": observation.activation_state,
            "pending_bucket": _bucket(observation.pending_jobs, (0, 1, 5, 20)),
            "eligible_slot_bucket": _bucket(observation.eligible_slots, (0, 1, 3, 6)),
            "fifo_head_bucket": _bucket(observation.fifo_head_age_seconds, (0, 300, 900, 3600)),
            "heartbeat_bucket": _bucket(
                observation.worker_heartbeat_age_seconds, (0, 90, 300, 3600)
            ),
            "claim_bucket": _bucket(observation.oldest_claim_age_seconds, (0, 300, 900, 3600)),
            "disk_bucket": _bucket_or_unknown(observation.disk_free_gib, (0, 4.5, 10, 30)),
            "disk_used_bucket": _bucket_or_unknown(observation.disk_used_pct, (0, 70, 85, 90)),
            "missing_image_count": len(observation.missing_images),
            "provider_block": bool(observation.provider_block),
        },
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _bucket(value: float, edges: tuple[float, ...]) -> int:
    index = 0
    for edge in edges:
        if value >= edge:
            index += 1
    return index


def _bucket_or_unknown(value: float | None, edges: tuple[float, ...]) -> int:
    return -1 if value is None else _bucket(value, edges)


def publication(
    breaches: Iterable[Breach],
    observation: Observation,
    *,
    audience: str,
) -> dict[str, Any]:
    """Build the only alert payload that may leave the host."""

    breaches = tuple(breaches)
    digest = state_digest(breaches, observation)
    audience_breaches = audience_breaches_for(breaches, audience)
    return {
        "incident_id": INCIDENT_ID,
        "schema": SCHEMA,
        "audience": audience,
        "state_digest": digest,
        "dedupe_key": hashlib.sha256(f"{INCIDENT_ID}:{digest}:{audience}".encode()).hexdigest(),
        "severity": _worst(audience_breaches),
        "codes": sorted({item.code for item in audience_breaches}),
        "observed_at": observation.observed_at,
    }


def audience_breaches_for(breaches: Iterable[Breach], audience: str) -> list[Breach]:
    """The waiting-task audience follows the whole incident, the operator does too."""

    return [item for item in breaches if audience == TASK_AUDIENCE or item.audience == audience]


def _worst(breaches: Iterable[Breach]) -> str:
    severities = {item.severity for item in breaches}
    if SEVERITY_CRITICAL in severities:
        return SEVERITY_CRITICAL
    if SEVERITY_WARNING in severities:
        return SEVERITY_WARNING
    return "healthy"


def decide(
    previous: Mapping[str, str],
    breaches: tuple[Breach, ...],
    observation: Observation,
) -> dict[str, dict[str, Any]]:
    """Return the alerts that must be sent for this transition.

    ``healthy`` and ``recovery`` kinds are only ever produced on an actual
    transition, so an unchanged healthy state publishes nothing.
    """

    decisions: dict[str, dict[str, Any]] = {}
    for audience in AUDIENCES:
        alert = publication(breaches, observation, audience=audience)
        last = previous.get(audience)
        if alert["severity"] == "healthy":
            if last is not None and last != "healthy":
                alert["kind"] = "recovery"
            else:
                continue
        elif last == alert["state_digest"]:
            continue
        elif last is None or last == "healthy":
            alert["kind"] = "start"
        else:
            alert["kind"] = "change"
        decisions[audience] = alert
    return decisions


@dataclass(frozen=True)
class ReserveDecision:
    host_id: str
    action: str
    follow_up: tuple[str, ...]

    def to_mapping(self) -> dict[str, Any]:
        return {
            "host_id": self.host_id,
            "action": self.action,
            "follow_up": list(self.follow_up),
        }


def plan_reserve(
    observation: Observation,
    *,
    already_activated: Iterable[str],
) -> ReserveDecision | None:
    """Activate at most one pre-registered reserve host, then re-audit.

    A reserve is only ever used while the healthy workers are genuinely busy:
    the head of the queue has waited past the five minute warning, nothing is
    eligible, and at least one active job is holding the fleet.
    """

    used = set(already_activated)
    available = [host for host in observation.registered_reserve_hosts if host not in used]
    if not available:
        return None
    if observation.fifo_head_age_seconds < FIFO_HEAD_WARN_SECONDS:
        return None
    if observation.eligible_slots > 0:
        return None
    if observation.worker_heartbeat_age_seconds > HEARTBEAT_STALE_SECONDS:
        return None
    if observation.healthy_workers < 1 or observation.active_jobs < 1:
        return None
    return ReserveDecision(
        host_id=sorted(available)[0],
        action="activate-reserve",
        follow_up=("host-audit", "capacity-calculation"),
    )


def status_deliveries(
    observation: Observation,
    delivered: Mapping[str, str],
) -> dict[str, dict[str, Any]]:
    """Deliver exact run/job status once a waiting job has actually started."""

    pending: dict[str, dict[str, Any]] = {}
    for job in observation.waiting_jobs:
        key = f"{job.repository}:{job.run_id}:{job.job_id}"
        if not job.started or job.status == "queued":
            # Never announce a queued job as recovered.
            continue
        if delivered.get(key) == job.status:
            continue
        pending[key] = {
            "schema": f"{SCHEMA}-job-status",
            "incident_id": INCIDENT_ID,
            "repository": job.repository,
            "run_id": job.run_id,
            "job_id": job.job_id,
            "status": job.status,
            "observed_at": observation.observed_at,
        }
    return pending


def _ledger_path(state_root: Path) -> Path:
    return state_root / "state.json"


def load_ledger(state_root: Path) -> dict[str, Any]:
    path = _ledger_path(state_root)
    if not path.exists():
        return {
            "schema": STATE_SCHEMA,
            "incident_id": INCIDENT_ID,
            "audience_digests": {},
            "activated_reserves": [],
            "delivered_jobs": {},
        }
    document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict) or document.get("schema") != STATE_SCHEMA:
        raise WatchdogError("watchdog ledger has an unexpected schema")
    return document


def save_ledger(state_root: Path, document: dict[str, Any]) -> None:
    path = _ledger_path(state_root)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(document, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def run_once(
    observation: Observation,
    *,
    state_root: Path,
    outbox: Path,
    min_disk_free_gib: float = 4.5,
    max_disk_used_pct: float = 90.0,
) -> dict[str, Any]:
    """Evaluate one observation, emit only transitions, persist the ledger."""

    ledger = load_ledger(state_root)
    breaches = evaluate(
        observation,
        min_disk_free_gib=min_disk_free_gib,
        max_disk_used_pct=max_disk_used_pct,
    )
    alerts = decide(ledger.get("audience_digests", {}), breaches, observation)
    deliveries = status_deliveries(observation, ledger.get("delivered_jobs", {}))
    reserve = plan_reserve(
        observation,
        already_activated=ledger.get("activated_reserves", []),
    )

    emitted: list[dict[str, Any]] = []
    outbox.parent.mkdir(parents=True, exist_ok=True)
    for alert in alerts.values():
        emitted.append({"record": "alert", **alert})
    for delivery in deliveries.values():
        emitted.append({"record": "job-status", **delivery})
    if reserve is not None:
        emitted.append({"record": "reserve-decision", **reserve.to_mapping()})
    if emitted:
        with outbox.open("a", encoding="utf-8") as handle:
            for record in emitted:
                handle.write(json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n")

    ledger["audience_digests"] = {
        audience: (
            "healthy"
            if not audience_breaches_for(breaches, audience)
            else publication(breaches, observation, audience=audience)["state_digest"]
        )
        for audience in AUDIENCES
    }
    if reserve is not None:
        ledger.setdefault("activated_reserves", []).append(reserve.host_id)
    ledger.setdefault("delivered_jobs", {}).update(
        {key: value["status"] for key, value in deliveries.items()}
    )
    ledger["heartbeat_at"] = observation.observed_at
    save_ledger(state_root, ledger)

    return {
        "schema": SCHEMA,
        "incident_id": INCIDENT_ID,
        "observed_at": observation.observed_at,
        "breaches": [item.code for item in breaches],
        "emitted": len(emitted),
        "silent": not emitted,
        "reserve": reserve.to_mapping() if reserve else None,
    }


def _read_observation(path: Path) -> Observation:
    if str(path) == "-":
        document = json.load(sys.stdin)
    else:
        document = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise WatchdogError("observation document must be an object")
    return Observation.from_mapping(document)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observation", type=Path, required=True)
    parser.add_argument(
        "--state-root", type=Path, default=Path("/var/lib/qdev-runner/incident-watchdog")
    )
    parser.add_argument("--outbox", type=Path, default=None)
    parser.add_argument("--min-disk-free-gib", type=float, default=4.5)
    parser.add_argument("--max-disk-used-pct", type=float, default=90.0)
    args = parser.parse_args(argv)

    outbox = args.outbox or args.state_root / "alerts.jsonl"
    try:
        observation = _read_observation(args.observation)
        summary = run_once(
            observation,
            state_root=args.state_root,
            outbox=outbox,
            min_disk_free_gib=args.min_disk_free_gib,
            max_disk_used_pct=args.max_disk_used_pct,
        )
    except (WatchdogError, OSError, ValueError, KeyError, json.JSONDecodeError) as exc:
        print(f"watchdog error: {type(exc).__name__}", file=sys.stderr)
        return 2
    print(json.dumps(summary, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
