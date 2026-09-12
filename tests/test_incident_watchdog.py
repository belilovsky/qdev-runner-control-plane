"""Incident watchdog and observation collector behaviour."""

from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]

WATCHDOG = ROOT / "scripts" / "qdev_incident_watchdog.py"
OBSERVATION = ROOT / "scripts" / "qdev_incident_observation.py"
UNIT = ROOT / "deploy" / "qdev-incident-watchdog.service"
TIMER = ROOT / "deploy" / "qdev-incident-watchdog.timer"

PUBLICATION_KEYS = {
    "incident_id",
    "schema",
    "audience",
    "state_digest",
    "dedupe_key",
    "severity",
    "codes",
    "observed_at",
}


def _load(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def watchdog():
    return _load(WATCHDOG, "qdev_incident_watchdog")


@pytest.fixture(scope="module")
def collector():
    return _load(OBSERVATION, "qdev_incident_observation")


def healthy_observation(watchdog, **overrides):
    payload = {
        "activation_state": "active",
        "activation_age_seconds": 0,
        "pending_jobs": 0,
        "eligible_slots": 6,
        "no_slot_pending_seconds": 0,
        "fifo_head_age_seconds": 0,
        "worker_heartbeat_age_seconds": 0,
        "oldest_claim_age_seconds": 0,
        "disk_free_gib": 30,
        "disk_used_pct": 60,
        "missing_images": [],
        "provider_block": None,
        "healthy_workers": 3,
        "active_jobs": 0,
        "registered_reserve_hosts": ["mail-general-reserve"],
        "waiting_jobs": [],
        "observed_at": "2026-09-11T00:00:00Z",
    }
    payload.update(overrides)
    return watchdog.Observation.from_mapping(payload)


def codes(breaches):
    return {breach.code for breach in breaches}


def test_healthy_state_has_no_breaches_and_stays_silent(watchdog, tmp_path: Path):
    observation = healthy_observation(watchdog)
    assert watchdog.evaluate(observation) == ()
    summary = watchdog.run_once(observation, state_root=tmp_path, outbox=tmp_path / "alerts.jsonl")
    assert summary["silent"] is True
    assert summary["emitted"] == 0
    assert not (tmp_path / "alerts.jsonl").exists()
    assert watchdog.decide({}, (), observation) == {}


@pytest.mark.parametrize(
    ("field", "value", "expected"),
    [
        ("activation_state", "unavailable", "controller_activation_not_active"),
        ("fifo_head_age_seconds", 900, "fifo_head_critical"),
        ("worker_heartbeat_age_seconds", 91, "worker_heartbeat_stale"),
        ("oldest_claim_age_seconds", 301, "claim_stale"),
        ("disk_free_gib", 4.4, "resource_floor_crossed"),
        ("disk_used_pct", 91, "resource_floor_crossed"),
        ("missing_images", ["sha256:deadbeef"], "immutable_image_missing"),
        ("provider_block", "payment-required", "provider_block"),
    ],
)
def test_each_contract_breach_is_detected(watchdog, field, value, expected):
    observation = healthy_observation(
        watchdog, no_slot_pending_seconds=600, activation_age_seconds=600, **{field: value}
    )
    assert expected in codes(watchdog.evaluate(observation))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("activation_state", "active"),
        ("fifo_head_age_seconds", 299),
        ("worker_heartbeat_age_seconds", 90),
        ("oldest_claim_age_seconds", 300),
        ("disk_free_gib", 4.5),
        ("disk_used_pct", 90),
    ],
)
def test_inside_the_published_bounds_is_not_a_breach(watchdog, field, value):
    observation = healthy_observation(watchdog, **{field: value})
    assert watchdog.evaluate(observation) == ()


def test_pending_job_without_slot_is_a_breach_only_after_the_limit(watchdog):
    fresh = healthy_observation(
        watchdog, pending_jobs=1, eligible_slots=0, no_slot_pending_seconds=119
    )
    stale = healthy_observation(
        watchdog, pending_jobs=1, eligible_slots=0, no_slot_pending_seconds=120
    )
    assert watchdog.evaluate(fresh) == ()
    assert "pending_without_eligible_slot" in codes(watchdog.evaluate(stale))
    with_slot = healthy_observation(
        watchdog, pending_jobs=1, eligible_slots=1, no_slot_pending_seconds=600
    )
    assert watchdog.evaluate(with_slot) == ()


def test_activation_must_be_active_within_two_minutes(watchdog):
    fresh = healthy_observation(
        watchdog, activation_state="unavailable", activation_age_seconds=119
    )
    stale = healthy_observation(
        watchdog, activation_state="unavailable", activation_age_seconds=120
    )
    assert watchdog.evaluate(fresh) == ()
    assert "controller_activation_not_active" in codes(watchdog.evaluate(stale))


def test_fifo_head_warning_then_critical(watchdog):
    warning = watchdog.evaluate(healthy_observation(watchdog, fifo_head_age_seconds=300))
    assert [(item.code, item.severity) for item in warning] == [("fifo_head_delayed", "warning")]
    critical = watchdog.evaluate(healthy_observation(watchdog, fifo_head_age_seconds=900))
    assert [(item.code, item.severity) for item in critical] == [("fifo_head_critical", "critical")]


def test_provider_block_is_a_warning_only(watchdog):
    breaches = watchdog.evaluate(healthy_observation(watchdog, provider_block="blocked"))
    assert [(item.code, item.severity) for item in breaches] == [("provider_block", "warning")]


def test_alert_publication_is_aggregate_only(watchdog):
    observation = healthy_observation(
        watchdog, activation_state="unavailable", activation_age_seconds=600
    )
    alert = watchdog.publication(
        watchdog.evaluate(observation), observation, audience="qdev-fleet-operations"
    )
    assert set(alert) == PUBLICATION_KEYS
    encoded = json.dumps(alert, sort_keys=True)
    for forbidden in (
        "belilovsky",
        "repository",
        "run_id",
        "job_id",
        "runner",
        "host",
        "token",
        "secret",
        "private",
    ):
        assert forbidden not in encoded
    assert len(alert["dedupe_key"]) == 64
    assert alert["severity"] == "critical"


def test_alert_deduplicates_start_change_and_recovery(watchdog, tmp_path: Path):
    state_root = tmp_path / "state"
    outbox = tmp_path / "alerts.jsonl"
    breached = healthy_observation(
        watchdog, activation_state="unavailable", activation_age_seconds=600
    )

    first = watchdog.run_once(breached, state_root=state_root, outbox=outbox)
    assert first["emitted"] == 2  # both audiences
    records = [json.loads(line) for line in outbox.read_text(encoding="utf-8").splitlines()]
    assert {record["kind"] for record in records} == {"start"}

    unchanged = watchdog.run_once(breached, state_root=state_root, outbox=outbox)
    assert unchanged["silent"] is True

    changed = watchdog.run_once(
        healthy_observation(
            watchdog,
            activation_state="unavailable",
            activation_age_seconds=600,
            pending_jobs=4,
            eligible_slots=0,
            no_slot_pending_seconds=600,
        ),
        state_root=state_root,
        outbox=outbox,
    )
    assert changed["emitted"] == 2
    records = [json.loads(line) for line in outbox.read_text(encoding="utf-8").splitlines()]
    assert records[-1]["kind"] == "change"

    recovered = watchdog.run_once(
        healthy_observation(watchdog), state_root=state_root, outbox=outbox
    )
    assert recovered["emitted"] == 2
    records = [json.loads(line) for line in outbox.read_text(encoding="utf-8").splitlines()]
    assert records[-1]["kind"] == "recovery"
    assert records[-1]["severity"] == "healthy"

    settled = watchdog.run_once(healthy_observation(watchdog), state_root=state_root, outbox=outbox)
    assert settled["silent"] is True


def test_task_audience_tracks_the_whole_incident(watchdog):
    observation = healthy_observation(watchdog, provider_block="blocked")
    breaches = watchdog.evaluate(observation)
    operator = watchdog.publication(breaches, observation, audience="qdev-fleet-operations")
    tasks = watchdog.publication(breaches, observation, audience="codex-tasks")
    assert operator["codes"] == ["provider_block"]
    assert tasks["codes"] == ["provider_block"]
    assert operator["dedupe_key"] != tasks["dedupe_key"]


def test_reserve_escalation_covers_only_the_sealed_reserve_host(watchdog):
    busy = healthy_observation(
        watchdog,
        pending_jobs=3,
        eligible_slots=0,
        fifo_head_age_seconds=400,
        active_jobs=2,
        registered_reserve_hosts=["mail-general-reserve"],
    )
    first = watchdog.plan_reserve(busy, already_requested=[])
    assert first is not None
    assert first.host_id == "mail-general-reserve"
    assert first.action == "activate-reserve"
    assert first.follow_up == ("host-audit", "capacity-calculation")
    assert watchdog.plan_reserve(busy, already_requested=["mail-general-reserve"]) is None


def test_unsealed_reserve_is_alerted_and_never_selected(watchdog):
    busy = healthy_observation(
        watchdog,
        pending_jobs=3,
        eligible_slots=0,
        fifo_head_age_seconds=400,
        active_jobs=2,
        registered_reserve_hosts=["mail-general-reserve", "unapproved-reserve"],
    )
    assert "unsealed_reserve_observed" in codes(watchdog.evaluate(busy))
    assert watchdog.plan_reserve(busy, already_requested=[]) is None


@pytest.mark.parametrize(
    "overrides",
    [
        {"fifo_head_age_seconds": 299},
        {"eligible_slots": 1},
        {"worker_heartbeat_age_seconds": 91},
        {"healthy_workers": 0},
        {"active_jobs": 0},
        {"registered_reserve_hosts": []},
    ],
)
def test_reserve_escalation_is_denied_outside_its_contract(watchdog, overrides):
    busy = {
        "pending_jobs": 3,
        "eligible_slots": 0,
        "fifo_head_age_seconds": 400,
        "active_jobs": 2,
        "worker_heartbeat_age_seconds": 0,
        "healthy_workers": 3,
        "registered_reserve_hosts": ["mail-general-reserve"],
    }
    busy.update(overrides)
    assert (
        watchdog.plan_reserve(healthy_observation(watchdog, **busy), already_requested=[]) is None
    )


def test_reserve_decision_is_recorded_once(watchdog, tmp_path: Path):
    state_root = tmp_path / "state"
    outbox = tmp_path / "alerts.jsonl"
    busy = healthy_observation(
        watchdog,
        pending_jobs=3,
        eligible_slots=0,
        fifo_head_age_seconds=400,
        active_jobs=1,
        registered_reserve_hosts=["mail-general-reserve"],
    )
    first = watchdog.run_once(busy, state_root=state_root, outbox=outbox)
    assert first["reserve"] == {
        "host_id": "mail-general-reserve",
        "action": "activate-reserve",
        "follow_up": ["host-audit", "capacity-calculation"],
    }
    ledger = json.loads((state_root / "state.json").read_text(encoding="utf-8"))
    assert ledger["activated_reserves"] == []
    assert ledger["pending_reserve_requests"] == {
        "mail-general-reserve": {
            "host_id": "mail-general-reserve",
            "action": "activate-reserve",
            "follow_up": ["host-audit", "capacity-calculation"],
        }
    }
    records = [json.loads(line) for line in outbox.read_text(encoding="utf-8").splitlines()]
    assert records[-1]["record"] == "reserve-decision"
    second = watchdog.run_once(busy, state_root=state_root, outbox=outbox)
    assert second["reserve"] is None
    assert len(
        [json.loads(line) for line in outbox.read_text(encoding="utf-8").splitlines()]
    ) == len(records)


def test_waiting_jobs_are_only_reported_once_they_started(watchdog):
    observation = healthy_observation(
        watchdog,
        waiting_jobs=[
            watchdog.WaitingJob("belilovsky/qazlake", 11, 22, "queued", False),
            watchdog.WaitingJob("belilovsky/qazlake", 11, 23, "queued", True),
            watchdog.WaitingJob("belilovsky/qazlake", 12, 24, "in_progress", True),
        ],
    )
    deliveries = watchdog.status_deliveries(observation, {})
    assert len(deliveries) == 1
    delivery = next(iter(deliveries.values()))
    assert delivery["status"] == "in_progress"
    assert len(delivery["delivery_id"]) == 64
    assert watchdog.status_deliveries(observation, {delivery["delivery_id"]: {}}) == {}


def test_waiting_job_status_change_is_delivered_again(watchdog):
    first = healthy_observation(
        watchdog,
        waiting_jobs=[watchdog.WaitingJob("belilovsky/qazlake", 11, 23, "in_progress", True)],
    )
    second = healthy_observation(
        watchdog,
        waiting_jobs=[watchdog.WaitingJob("belilovsky/qazlake", 11, 23, "completed", True)],
    )
    first_delivery = next(iter(watchdog.status_deliveries(first, {}).values()))
    acknowledged = {first_delivery["delivery_id"]: {}}
    pending = watchdog.status_deliveries(second, acknowledged)
    assert len(pending) == 1
    assert next(iter(pending.values()))["status"] == "completed"
    assert watchdog.status_deliveries(first, acknowledged) == {}


def _receipt_for(watchdog, delivery, *, delivered_at="2026-09-11T00:01:00Z"):
    return {
        "schema": watchdog.DELIVERY_RECEIPT_SCHEMA,
        "delivery_id": delivery["delivery_id"],
        "repository": delivery["repository"],
        "run_id": delivery["run_id"],
        "job_id": delivery["job_id"],
        "status": delivery["status"],
        "delivered_at": delivered_at,
    }


def test_job_delivery_remains_pending_until_a_matching_receipt(watchdog, tmp_path: Path):
    state_root = tmp_path / "state"
    outbox = tmp_path / "alerts.jsonl"
    observation = healthy_observation(
        watchdog,
        waiting_jobs=[watchdog.WaitingJob("belilovsky/qazlake", 11, 23, "in_progress", True)],
    )

    first = watchdog.run_once(observation, state_root=state_root, outbox=outbox)
    assert first["emitted"] == 1
    assert first["pending_job_deliveries"] == 1
    ledger = json.loads((state_root / "state.json").read_text(encoding="utf-8"))
    assert ledger["acknowledged_job_deliveries"] == {}
    assert len(ledger["pending_job_deliveries"]) == 1

    delivery_spool = state_root / "job-delivery-outbox.json"
    spool = json.loads(delivery_spool.read_text(encoding="utf-8"))
    assert spool["schema"] == watchdog.DELIVERY_OUTBOX_SCHEMA
    assert len(spool["deliveries"]) == 1
    assert stat.S_IMODE(delivery_spool.stat().st_mode) == 0o600
    delivery = spool["deliveries"][0]

    retry = watchdog.run_once(observation, state_root=state_root, outbox=outbox)
    assert retry["emitted"] == 0
    assert retry["pending_job_deliveries"] == 1

    receipt_path = state_root / "delivery-receipts.jsonl"
    receipt_path.write_text(json.dumps(_receipt_for(watchdog, delivery)) + "\n", encoding="utf-8")
    os.chmod(receipt_path, 0o600)
    reconciled = watchdog.run_once(observation, state_root=state_root, outbox=outbox)
    assert reconciled["delivery_receipts_reconciled"] == 1
    assert reconciled["pending_job_deliveries"] == 0
    ledger = json.loads((state_root / "state.json").read_text(encoding="utf-8"))
    assert delivery["delivery_id"] in ledger["acknowledged_job_deliveries"]

    after_receipt = watchdog.run_once(observation, state_root=state_root, outbox=outbox)
    assert after_receipt["emitted"] == 0
    assert after_receipt["pending_job_deliveries"] == 0


def test_delivery_receipt_mismatch_fails_closed_without_acknowledging(watchdog, tmp_path: Path):
    state_root = tmp_path / "state"
    observation = healthy_observation(
        watchdog,
        waiting_jobs=[watchdog.WaitingJob("belilovsky/qazlake", 11, 23, "in_progress", True)],
    )
    watchdog.run_once(observation, state_root=state_root, outbox=tmp_path / "alerts.jsonl")
    delivery = json.loads(
        (state_root / "job-delivery-outbox.json").read_text(encoding="utf-8")
    )["deliveries"][0]
    receipt = _receipt_for(watchdog, delivery)
    receipt["status"] = "completed"
    receipt_path = state_root / "delivery-receipts.jsonl"
    receipt_path.write_text(json.dumps(receipt) + "\n", encoding="utf-8")
    os.chmod(receipt_path, 0o600)

    with pytest.raises(watchdog.WatchdogError):
        watchdog.run_once(observation, state_root=state_root, outbox=tmp_path / "alerts.jsonl")
    ledger = json.loads((state_root / "state.json").read_text(encoding="utf-8"))
    assert delivery["delivery_id"] in ledger["pending_job_deliveries"]
    assert ledger["acknowledged_job_deliveries"] == {}


def test_legacy_delivery_ledger_is_reissued_for_receipt_bound_delivery(watchdog, tmp_path: Path):
    state_root = tmp_path / "state"
    state_root.mkdir()
    (state_root / "state.json").write_text(
        json.dumps(
            {
                "schema": watchdog.LEGACY_STATE_SCHEMA,
                "incident_id": watchdog.INCIDENT_ID,
                "audience_digests": {},
                "activated_reserves": [],
                "delivered_jobs": {"belilovsky/qazlake:11:23": "in_progress"},
            }
        ),
        encoding="utf-8",
    )
    observation = healthy_observation(
        watchdog,
        waiting_jobs=[watchdog.WaitingJob("belilovsky/qazlake", 11, 23, "in_progress", True)],
    )

    summary = watchdog.run_once(
        observation,
        state_root=state_root,
        outbox=tmp_path / "alerts.jsonl",
    )
    assert summary["emitted"] == 1
    assert summary["pending_job_deliveries"] == 1
    assert watchdog.load_ledger(state_root)["schema"] == watchdog.STATE_SCHEMA


def test_ledger_is_owner_only_and_corruption_fails_closed(watchdog, tmp_path: Path):
    state_root = tmp_path / "state"
    watchdog.run_once(
        healthy_observation(watchdog), state_root=state_root, outbox=tmp_path / "a.jsonl"
    )
    path = state_root / "state.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.write_text("[]", encoding="utf-8")
    with pytest.raises(watchdog.WatchdogError):
        watchdog.load_ledger(state_root)


def test_cli_emits_a_json_summary_and_fails_closed(watchdog, tmp_path: Path, capsys):
    observation_path = tmp_path / "observation.json"
    observation_path.write_text(
        json.dumps(
            {
                "activation_state": "unavailable",
                "activation_age_seconds": 900,
                "observed_at": "2026-09-11T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    exit_code = watchdog.main(
        [
            "--observation",
            str(observation_path),
            "--state-root",
            str(tmp_path / "state"),
        ]
    )
    assert exit_code == 0
    summary = json.loads(capsys.readouterr().out)
    assert summary["breaches"] == ["controller_activation_not_active"]

    missing = watchdog.main(
        [
            "--observation",
            str(tmp_path / "absent.json"),
            "--state-root",
            str(tmp_path / "s"),
        ]
    )
    assert missing == 2


def test_watchdog_has_no_third_party_imports():
    source = WATCHDOG.read_text(encoding="utf-8")
    assert "import yaml" not in source
    assert "import pydantic" not in source
    assert "from qdev_runner" not in source


def test_watchdog_units_run_every_two_minutes_as_a_root_oneshot():
    service = UNIT.read_text(encoding="utf-8")
    timer = TIMER.read_text(encoding="utf-8")
    for directive in (
        "Type=oneshot",
        "User=root",
        "UMask=0027",
        "NoNewPrivileges=true",
        "PrivateTmp=true",
        "ProtectHome=true",
        "ProtectSystem=full",
        "ReadWritePaths=/var/lib/qdev-runner",
        "qdev_incident_observation.py",
        "qdev_incident_watchdog.py",
    ):
        assert directive in service
    assert "OnUnitActiveSec=120" in timer
    assert "Unit=qdev-incident-watchdog.service" in timer


def test_collector_derives_dwell_times_from_the_health_document(collector):
    health = {
        "controller_activation": {"state": "unavailable"},
        "pending": 2,
        "primary_slots_available": 0,
        "reserve_slots_available": 0,
    }
    dwell = {
        "schema": collector.DWELL_SCHEMA,
        "activation_not_active_since": None,
        "pending_without_slot_since": None,
    }
    started = datetime(2026, 9, 11, 0, 0, tzinfo=UTC)
    first, dwell = collector.collect(health, internal={}, dwell=dwell, now=started)
    assert first["activation_age_seconds"] == 0.0
    assert first["no_slot_pending_seconds"] == 0.0
    assert dwell["activation_not_active_since"] is not None

    later, dwell = collector.collect(
        health, internal={}, dwell=dwell, now=started + timedelta(minutes=3)
    )
    assert later["activation_age_seconds"] == 180.0
    assert later["no_slot_pending_seconds"] == 180.0
    assert later["eligible_slots"] == 0

    recovered, dwell = collector.collect(
        {"controller_activation": {"state": "active"}, "pending": 0},
        internal={},
        dwell=dwell,
        now=started + timedelta(minutes=4),
    )
    assert recovered["activation_age_seconds"] == 0.0
    assert dwell["activation_not_active_since"] is None
    assert dwell["pending_without_slot_since"] is None


def test_collector_merges_the_aggregate_internal_document(collector):
    health = {
        "controller_activation": {"state": "active"},
        "pending": 1,
        "primary_slots_available": 2,
        "reserve_slots_available": 4,
        "oldest_pending_age_seconds": 42,
    }
    internal = {
        "schema": collector.INTERNAL_SCHEMA,
        "worker_heartbeat_age_seconds": 12,
        "oldest_claim_age_seconds": 30,
        "disk_free_gib": 31.5,
        "disk_used_pct": 64.5,
        "missing_images": ["sha256:abc"],
        "provider_block": "blocked",
        "healthy_workers": 3,
        "active_jobs": 1,
        "registered_reserve_hosts": ["mail-general-reserve"],
        "waiting_jobs": [
            {
                "repository": "belilovsky/qazlake",
                "run_id": 1,
                "job_id": 2,
                "status": "queued",
                "started": False,
            }
        ],
    }
    observation, _ = collector.collect(health, internal=internal, dwell={})
    assert observation["eligible_slots"] == 6
    assert observation["pending_jobs"] == 1
    assert observation["fifo_head_age_seconds"] == 42
    assert observation["disk_free_gib"] == 31.5
    assert observation["missing_images"] == ["sha256:abc"]
    assert observation["provider_block"] == "blocked"
    assert observation["waiting_jobs"][0]["job_id"] == 2


def test_collector_fifo_age_falls_back_to_the_internal_document(collector):
    observation, _ = collector.collect(
        {"controller_activation": {"state": "active"}, "pending": 1},
        internal={"fifo_head_age_seconds": 77},
        dwell={},
    )
    assert observation["fifo_head_age_seconds"] == 77.0


def test_collector_reads_a_local_health_path_and_writes_owner_only_output(
    collector, tmp_path: Path
):
    health_path = tmp_path / "health.json"
    health_path.write_text(
        json.dumps({"controller_activation": {"state": "active"}, "pending": 0}),
        encoding="utf-8",
    )
    observation = collector.collect(
        collector.load_document(str(health_path)), internal={}, dwell={}
    )[0]
    output = tmp_path / "state" / "observation.json"
    collector.write_observation(output, observation)
    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    assert json.loads(output.read_text(encoding="utf-8"))["schema"] == collector.SCHEMA


def test_collector_output_escalates_after_the_dwell_limit(watchdog, collector, tmp_path: Path):
    state_root = tmp_path / "state"
    health_path = tmp_path / "health.json"
    health_path.write_text(
        json.dumps({"controller_activation": {"state": "unavailable"}, "pending": 0}),
        encoding="utf-8",
    )
    assert collector.main(["--health", str(health_path), "--state-root", str(state_root)]) == 0
    fresh = collector.load_document(str(state_root / "observation.json"))
    assert watchdog.evaluate(watchdog.Observation.from_mapping(fresh)) == ()

    dwell = json.loads((state_root / "dwell.json").read_text(encoding="utf-8"))
    dwell["activation_not_active_since"] = (
        (datetime.now(UTC) - timedelta(minutes=10)).isoformat().replace("+00:00", "Z")
    )
    (state_root / "dwell.json").write_text(json.dumps(dwell), encoding="utf-8")
    assert collector.main(["--health", str(health_path), "--state-root", str(state_root)]) == 0
    stale = collector.load_document(str(state_root / "observation.json"))
    assert "controller_activation_not_active" in codes(
        watchdog.evaluate(watchdog.Observation.from_mapping(stale))
    )
