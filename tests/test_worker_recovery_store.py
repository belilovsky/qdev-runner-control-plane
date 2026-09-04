from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import time
from pathlib import Path
from typing import Any

import pytest

from qdev_runner.models import QueuedJob
from qdev_runner.store import Store

WORKER = "qdev-platform-ci-187"
REPOSITORY = "belilovsky/platform-portal"
LABELS = ("self-hosted", "Linux", "X64", "qdev-platform-ci")
PROOF_KEY = "provider-proof-key"
RECONCILIATION_KEY = "native-reconciliation-key"
ACCEPTANCE_KEY = "recovery-acceptance-key"
PROVIDER_RECONCILIATION_DIGEST = "sha256:" + "0" * 64


def _provider_proof(*, observed_at: float | None = None, active_jobs: int = 0) -> dict[str, Any]:
    return Store.issue_worker_provider_idle_proof(
        key=PROOF_KEY,
        worker_name=WORKER,
        repository=REPOSITORY,
        labels=LABELS,
        provider_runner_id=187,
        provider_status="offline",
        provider_busy=False,
        active_jobs=active_jobs,
        provider_reconciliation_digest=PROVIDER_RECONCILIATION_DIGEST,
        observed_at=observed_at,
    )


def _begin_arguments(**overrides: Any) -> dict[str, Any]:
    now = time.time()
    values: dict[str, Any] = {
        "worker_name": WORKER,
        "idempotency_key": "recovery-platform-0001",
        "fingerprint": "a" * 64,
        "repository": REPOSITORY,
        "labels": LABELS,
        "provider_idle_proof": _provider_proof(observed_at=now),
        "provider_proof_key": PROOF_KEY,
        "recovery_action": "restore_saved_configuration",
        "operator_certificate_sha256": "b" * 64,
        "expected_agent_certificate_sha256": "c" * 64,
        "interface_version": "qdev-worker-recovery-v1",
        "interface_digest": "d" * 64,
        "controller_revision": "e" * 40,
        "controller_release_digest": "f" * 64,
        "controller_receipt_id": "1" * 64,
        "controller_observed_at": now,
        "request_nonce": "nonce-platform-0001",
        "requested_at": now,
    }
    values.update(overrides)
    return values


def _queued_job() -> QueuedJob:
    return QueuedJob(
        delivery_id="offline-recovery-durable-job",
        job_id=8123,
        run_id=9912,
        repository=REPOSITORY,
        repository_id=1,
        installation_id=2,
        labels=LABELS,
        head_sha="9" * 40,
        head_branch="main",
        payload={"workflow_job": {"run_attempt": 1}},
    )


def _heartbeat(store: Store, *, observed_active: int = 0) -> None:
    store.heartbeat(
        WORKER,
        ("qdev-platform-ci",),
        observed_active,
        (),
        {"tier": "primary", "allowed": True, "concurrency": 1},
    )


def _acceptance_proof(
    recovery: dict[str, Any],
    *,
    provider_runner_id: int | None = None,
    prior_provider_runner_disposition: str = "same",
    matching_runner_count: int = 1,
    labels: tuple[str, ...] | None = None,
    canary_runner_id: int | None = None,
    canary_completed_at: float | None = None,
    observed_at: float | None = None,
) -> dict[str, Any]:
    worker_name = str(recovery["worker_name"])
    repository = str(recovery["repository"])
    permanent_labels = (
        tuple(json.loads(str(recovery["labels_json"]))) if labels is None else labels
    )
    prior_runner_id = int(recovery["provider_runner_id"])
    resulting_runner_id = (
        prior_runner_id if provider_runner_id is None else provider_runner_id
    )
    now = time.time()
    completed_at = (
        max(float(recovery["native_finalized_at"]), now - 0.001)
        if canary_completed_at is None
        else canary_completed_at
    )
    provider_observed_at = now if observed_at is None else observed_at
    workflow = (
        ".github/workflows/runner-smoke.yml"
        if worker_name == WORKER
        else ".github/workflows/self-hosted-recovery.yml"
    )
    return Store.issue_worker_recovery_acceptance_proof(
        key=ACCEPTANCE_KEY,
        operation_id=str(recovery["operation_id"]),
        worker_name=worker_name,
        repository=repository,
        labels=permanent_labels,
        prior_provider_runner_id=prior_runner_id,
        prior_provider_runner_disposition=prior_provider_runner_disposition,
        provider_runner_id=resulting_runner_id,
        matching_runner_count=matching_runner_count,
        provider_status="online",
        provider_busy=False,
        active_jobs=0,
        provider_reconciliation_digest="sha256:" + "7" * 64,
        canary_repository=repository,
        canary_workflow=workflow,
        canary_ref="refs/heads/main",
        canary_head_sha="8" * 40,
        canary_run_id=500,
        canary_run_attempt=1,
        canary_job_id=501,
        canary_runner_id=(
            resulting_runner_id if canary_runner_id is None else canary_runner_id
        ),
        canary_runner_name=worker_name,
        canary_status="completed",
        canary_conclusion="success",
        canary_completed_at=completed_at,
        observed_at=provider_observed_at,
    )


def test_legacy_worker_recovery_schema_migrates_before_new_indexes(
    tmp_path: Path,
) -> None:
    database = tmp_path / "broker.db"
    with sqlite3.connect(database) as connection:
        connection.execute(
            "CREATE TABLE worker_recoveries ("
            "idempotency_key TEXT PRIMARY KEY, worker_name TEXT NOT NULL, "
            "request_fingerprint TEXT NOT NULL, "
            "state TEXT NOT NULL CHECK(state IN "
            "('prepared','invoking','completed','released')), "
            "created_at REAL NOT NULL, invoked_at REAL, updated_at REAL NOT NULL)"
        )
        connection.execute(
            "INSERT INTO worker_recoveries VALUES(?,?,?,?,?,?,?)",
            (
                "legacy-recovery-0001",
                WORKER,
                "9" * 64,
                "released",
                1.0,
                None,
                2.0,
            ),
        )

    store = Store(database)
    migrated = store.worker_recovery_by_idempotency_key("legacy-recovery-0001")

    assert migrated is not None
    assert migrated["operation_id"] == hashlib.sha256(
        f"legacy-recovery-0001\0{WORKER}\0{'9' * 64}".encode()
    ).hexdigest()
    with store.connect() as connection:
        indexes = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA index_list(worker_recoveries)"
            ).fetchall()
        }
        tables = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert "worker_recovery_controller_receipt_idx" in indexes
    assert "worker_recovery_request_nonce_idx" in indexes
    assert "worker_recovery_outcomes" in tables
    assert "worker_recovery_acceptances" in tables


def test_offline_worker_can_be_fenced_only_with_signed_provider_and_durable_idle_proof(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")

    admitted = store.begin_worker_recovery(**_begin_arguments())

    assert admitted["state"] == "prepared"
    assert admitted["provider_runner_id"] == 187
    assert admitted["provider_observed_at"] > 0
    assert store.health()["workers"] == []
    lookup = store.worker_recovery(admitted["operation_id"])
    assert lookup is not None
    assert lookup["state"] == "prepared"


def test_offline_recovery_rejects_provider_work_and_durable_claims(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    with pytest.raises(ValueError, match="provider idle proof"):
        store.begin_worker_recovery(
            **_begin_arguments(provider_idle_proof=_provider_proof(active_jobs=1))
        )

    store.enqueue(_queued_job())
    _heartbeat(store)
    assert store.claim(WORKER, ("qdev-platform-ci",)) is not None
    with store.connect() as connection:
        connection.execute("DELETE FROM workers WHERE name=?", (WORKER,))
    with pytest.raises(ValueError, match="durable active work"):
        store.begin_worker_recovery(**_begin_arguments())


def test_pre_recovery_proof_is_offline_only_and_strictly_typed(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    with pytest.raises(ValueError, match="provider idle proof"):
        Store.issue_worker_provider_idle_proof(
            key=PROOF_KEY,
            worker_name=WORKER,
            repository=REPOSITORY,
            labels=LABELS,
            provider_runner_id=187,
            provider_status="online",
            provider_busy=False,
            active_jobs=0,
            provider_reconciliation_digest=PROVIDER_RECONCILIATION_DIGEST,
        )
    with pytest.raises(ValueError, match="operation identity"):
        store.worker_recovery(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="idempotency key"):
        store.worker_recovery_by_idempotency_key(None)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="not registered"):
        store.prepared_worker_recovery("arbitrary-runner")
    with pytest.raises(ValueError, match="operation identity"):
        store.worker_recovery_outcomes(None)  # type: ignore[arg-type]


def test_recovery_authority_and_live_controller_tuple_are_single_use(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    arguments = _begin_arguments()
    first = store.begin_worker_recovery(**arguments)
    replay = store.begin_worker_recovery(**arguments)
    assert replay["operation_id"] == first["operation_id"]
    assert replay["consumed_at"] == first["consumed_at"]

    changed = dict(arguments)
    changed["controller_revision"] = "2" * 40
    with pytest.raises(ValueError, match="bound to another request"):
        store.begin_worker_recovery(**changed)

    second = _begin_arguments(
        worker_name="qdev-qazstack-01",
        idempotency_key="recovery-qazstack-0001",
        fingerprint="2" * 64,
        repository="belilovsky/qazstack",
        labels=("self-hosted", "Linux", "X64", "qdev-ci"),
        recovery_action="replace_existing_registration",
        request_nonce="nonce-qazstack-0001",
    )
    second["provider_idle_proof"] = Store.issue_worker_provider_idle_proof(
        key=PROOF_KEY,
        worker_name=second["worker_name"],
        repository=second["repository"],
        labels=second["labels"],
        provider_runner_id=153,
        provider_status="offline",
        provider_busy=False,
        active_jobs=0,
        provider_reconciliation_digest=PROVIDER_RECONCILIATION_DIGEST,
    )
    with pytest.raises(ValueError, match="authority was already consumed"):
        store.begin_worker_recovery(**second)


def test_exact_terminal_request_replay_does_not_reopen_freshness_window(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    arguments = _begin_arguments()
    admitted = store.begin_worker_recovery(**arguments)
    store.advance_worker_recovery(
        admitted["idempotency_key"], expected="prepared", state="invoking"
    )
    store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        agent_certificate_sha256="c" * 64,
        outcome="not_applied",
        outcome_digest="sha256:" + "2" * 64,
        reconciliation_key=RECONCILIATION_KEY,
    )

    arguments["controller_observed_at"] = float(arguments["controller_observed_at"])
    arguments["requested_at"] = float(arguments["requested_at"])
    replay = store.begin_worker_recovery(**arguments, proof_max_age_seconds=0.0)
    assert replay["state"] == "released"
    assert replay["operation_id"] == admitted["operation_id"]
    lookup = store.worker_recovery_by_idempotency_key(
        admitted["idempotency_key"]
    )
    assert lookup is not None
    assert lookup["operation_id"] == admitted["operation_id"]
    assert lookup["state"] == "released"

    with pytest.raises(ValueError, match="idempotency key"):
        store.worker_recovery_by_idempotency_key("bad")


def test_stale_or_tampered_proofs_cannot_start_a_new_fence(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    stale = _provider_proof(observed_at=time.time() - 600)
    with pytest.raises(ValueError, match="stale"):
        store.begin_worker_recovery(**_begin_arguments(provider_idle_proof=stale))

    tampered = _provider_proof()
    tampered["active_jobs"] = 0
    tampered["provider_runner_id"] = 999
    with pytest.raises(ValueError, match="provider idle proof"):
        store.begin_worker_recovery(**_begin_arguments(provider_idle_proof=tampered))

    old_request = _begin_arguments(
        controller_observed_at=time.time() - 600,
        requested_at=time.time() - 600,
    )
    with pytest.raises(ValueError, match="not fresh"):
        store.begin_worker_recovery(**old_request)


def test_recovery_evidence_must_still_be_fresh_when_agent_invocation_starts(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    admitted = store.begin_worker_recovery(**_begin_arguments())
    with store.connect() as connection:
        connection.execute(
            "UPDATE worker_recoveries SET controller_observed_at=?,requested_at=?,"
            "provider_observed_at=? WHERE operation_id=?",
            (
                time.time() - 600,
                time.time() - 600,
                time.time() - 600,
                admitted["operation_id"],
            ),
        )
    with pytest.raises(ValueError, match="expired before invocation"):
        store.advance_worker_recovery(
            admitted["idempotency_key"], expected="prepared", state="invoking"
        )
    current = store.worker_recovery(admitted["operation_id"])
    assert current is not None
    assert current["state"] == "prepared"


def test_recovery_rejects_unregistered_target_and_unbound_provider_reconciliation(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    arbitrary = _begin_arguments(repository="belilovsky/other")
    with pytest.raises(ValueError, match="provider idle proof"):
        Store.issue_worker_provider_idle_proof(
            key=PROOF_KEY,
            worker_name=WORKER,
            repository="belilovsky/other",
            labels=LABELS,
            provider_runner_id=187,
            provider_status="offline",
            provider_busy=False,
            active_jobs=0,
            provider_reconciliation_digest=PROVIDER_RECONCILIATION_DIGEST,
        )
    with pytest.raises(ValueError, match="not registered"):
        store.begin_worker_recovery(**arbitrary)

    tampered = _provider_proof()
    tampered["provider_reconciliation_digest"] = "sha256:" + "9" * 64
    with pytest.raises(ValueError, match="provider idle proof"):
        store.begin_worker_recovery(
            **_begin_arguments(provider_idle_proof=tampered)
        )


def test_ambiguous_observation_stays_fenced_then_exact_terminal_outcome_completes(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    admitted = store.begin_worker_recovery(**_begin_arguments())
    invoking = store.advance_worker_recovery(
        admitted["idempotency_key"], expected="prepared", state="invoking"
    )
    assert invoking["state"] == "invoking"
    observed_at = time.time()
    ambiguous = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        agent_certificate_sha256="c" * 64,
        outcome="ambiguous",
        outcome_digest="sha256:" + "3" * 64,
        reconciliation_key=RECONCILIATION_KEY,
        observed_at=observed_at,
    )
    assert ambiguous["state"] == "invoking"
    assert store.health()["workers"] == []

    replay = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        agent_certificate_sha256="c" * 64,
        outcome="ambiguous",
        outcome_digest="sha256:" + "3" * 64,
        reconciliation_key=RECONCILIATION_KEY,
        observed_at=observed_at - 600,
    )
    assert replay["reconciliation_receipt_digest"] == ambiguous[
        "reconciliation_receipt_digest"
    ]

    completed = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        agent_certificate_sha256="c" * 64,
        outcome="completed",
        outcome_digest="sha256:" + "4" * 64,
        reconciliation_key=RECONCILIATION_KEY,
    )
    assert completed["state"] == "completed"
    assert completed["native_outcome"] == "completed"
    assert len(store.worker_recovery_outcomes(admitted["operation_id"])) == 2
    with pytest.raises(ValueError, match="acceptance proof is required"):
        store.advance_worker_recovery(
            admitted["idempotency_key"], expected="completed", state="released"
        )
    acceptance = _acceptance_proof(completed)
    released = store.advance_worker_recovery(
        admitted["idempotency_key"],
        expected="completed",
        state="released",
        acceptance_proof=acceptance,
        acceptance_proof_key=ACCEPTANCE_KEY,
    )
    assert released["state"] == "released"
    assert released["native_outcome"] == "completed"
    assert released["accepted_provider_runner_id"] == 187
    assert released["acceptance_proof_digest"] == acceptance["digest"]
    assert store.health()["workers"] == []
    replay = store.advance_worker_recovery(
        admitted["idempotency_key"],
        expected="completed",
        state="released",
        acceptance_proof=acceptance,
        acceptance_proof_key=ACCEPTANCE_KEY,
        proof_max_age_seconds=0,
    )
    assert replay == released
    with store.connect() as connection:
        acceptance_count = connection.execute(
            "SELECT COUNT(*) FROM worker_recovery_acceptances WHERE operation_id=?",
            (admitted["operation_id"],),
        ).fetchone()[0]
    assert acceptance_count == 1


def test_completed_state_cannot_bypass_signed_native_reconciliation(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    admitted = store.begin_worker_recovery(**_begin_arguments())
    store.advance_worker_recovery(
        admitted["idempotency_key"], expected="prepared", state="invoking"
    )

    with pytest.raises(ValueError, match="invalid worker recovery transition"):
        store.advance_worker_recovery(
            admitted["idempotency_key"], expected="invoking", state="completed"
        )

    current = store.worker_recovery(admitted["operation_id"])
    assert current is not None
    assert current["state"] == "invoking"
    assert current["native_outcome"] is None


def test_not_applied_is_only_failure_outcome_that_releases_fence(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    admitted = store.begin_worker_recovery(**_begin_arguments())
    store.advance_worker_recovery(
        admitted["idempotency_key"], expected="prepared", state="invoking"
    )

    failed = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        agent_certificate_sha256="c" * 64,
        outcome="failed",
        outcome_digest="sha256:" + "5" * 64,
        reconciliation_key=RECONCILIATION_KEY,
    )
    assert failed["state"] == "invoking"

    released = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        agent_certificate_sha256="c" * 64,
        outcome="not_applied",
        outcome_digest="sha256:" + "6" * 64,
        reconciliation_key=RECONCILIATION_KEY,
    )
    assert released["state"] == "released"


def test_reconciliation_is_bound_to_expected_agent_and_signed(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    admitted = store.begin_worker_recovery(**_begin_arguments())
    store.advance_worker_recovery(
        admitted["idempotency_key"], expected="prepared", state="invoking"
    )
    with pytest.raises(ValueError, match="does not match"):
        store.reconcile_worker_recovery(
            operation_id=admitted["operation_id"],
            worker_name=WORKER,
            request_fingerprint="a" * 64,
            agent_certificate_sha256="7" * 64,
            outcome="completed",
            outcome_digest="sha256:" + "8" * 64,
            reconciliation_key=RECONCILIATION_KEY,
        )

    observed_at = time.time()
    outcome = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        agent_certificate_sha256="c" * 64,
        outcome="ambiguous",
        outcome_digest="sha256:" + "8" * 64,
        reconciliation_key=RECONCILIATION_KEY,
        observed_at=observed_at,
    )
    payload = {
        "schema": "qdev-worker-recovery-native-outcome-v1",
        "operation_id": admitted["operation_id"],
        "worker_name": WORKER,
        "request_digest": "a" * 64,
        "agent_certificate_sha256": "c" * 64,
        "provider_reconciliation_digest": PROVIDER_RECONCILIATION_DIGEST,
        "outcome": "ambiguous",
        "outcome_digest": "sha256:" + "8" * 64,
        "observed_at": observed_at,
    }
    canonical = json.dumps(
        payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode()
    assert hmac.compare_digest(
        outcome["reconciliation_signature"],
        hmac.new(RECONCILIATION_KEY.encode(), canonical, hashlib.sha256).hexdigest(),
    )
    stored_outcomes = store.worker_recovery_outcomes(admitted["operation_id"])
    assert len(stored_outcomes) == 1
    assert (
        stored_outcomes[0]["provider_reconciliation_digest"]
        == PROVIDER_RECONCILIATION_DIGEST
    )


def test_native_outcome_cannot_predate_adapter_invocation(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    admitted = store.begin_worker_recovery(**_begin_arguments())
    invoking = store.advance_worker_recovery(
        admitted["idempotency_key"], expected="prepared", state="invoking"
    )
    with pytest.raises(ValueError, match="predates adapter invocation"):
        store.reconcile_worker_recovery(
            operation_id=admitted["operation_id"],
            worker_name=WORKER,
            request_fingerprint="a" * 64,
            agent_certificate_sha256="c" * 64,
            outcome="completed",
            outcome_digest="sha256:" + "9" * 64,
            reconciliation_key=RECONCILIATION_KEY,
            observed_at=float(invoking["invoked_at"]) - 0.001,
        )
    current = store.worker_recovery(admitted["operation_id"])
    assert current is not None
    assert current["state"] == "invoking"
    assert store.worker_recovery_outcomes(admitted["operation_id"]) == []


def test_acceptance_rejects_wrong_workflow_labels_and_platform_id_rotation(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    admitted = store.begin_worker_recovery(**_begin_arguments())
    store.advance_worker_recovery(
        admitted["idempotency_key"], expected="prepared", state="invoking"
    )
    completed = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        agent_certificate_sha256="c" * 64,
        outcome="completed",
        outcome_digest="sha256:" + "a" * 64,
        reconciliation_key=RECONCILIATION_KEY,
    )

    wrong_workflow = {
        field: value
        for field, value in _acceptance_proof(completed).items()
        if field not in {"digest", "signature", "schema"}
    }
    wrong_workflow["canary_workflow"] = ".github/workflows/other.yml"
    with pytest.raises(ValueError, match="acceptance proof"):
        Store.issue_worker_recovery_acceptance_proof(
            key=ACCEPTANCE_KEY, **wrong_workflow
        )
    with pytest.raises(ValueError, match="acceptance proof"):
        _acceptance_proof(
            completed,
            labels=LABELS + ("temporary-smoke",),
        )
    with pytest.raises(ValueError, match="acceptance proof"):
        _acceptance_proof(
            completed,
            provider_runner_id=188,
            prior_provider_runner_disposition="absent",
        )
    current = store.worker_recovery(admitted["operation_id"])
    assert current is not None
    assert current["state"] == "completed"


def test_qazstack_same_name_replace_accepts_unique_new_provider_id(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    now = time.time()
    labels = ("self-hosted", "Linux", "X64", "qdev-ci")
    arguments = _begin_arguments(
        worker_name="qdev-qazstack-01",
        idempotency_key="recovery-qazstack-0002",
        fingerprint="2" * 64,
        repository="belilovsky/qazstack",
        labels=labels,
        recovery_action="replace_existing_registration",
        request_nonce="nonce-qazstack-0002",
        controller_observed_at=now,
        requested_at=now,
    )
    arguments["provider_idle_proof"] = Store.issue_worker_provider_idle_proof(
        key=PROOF_KEY,
        worker_name="qdev-qazstack-01",
        repository="belilovsky/qazstack",
        labels=labels,
        provider_runner_id=21,
        provider_status="offline",
        provider_busy=False,
        active_jobs=0,
        provider_reconciliation_digest="sha256:" + "b" * 64,
        observed_at=now,
    )
    admitted = store.begin_worker_recovery(**arguments)
    store.advance_worker_recovery(
        admitted["idempotency_key"], expected="prepared", state="invoking"
    )
    completed = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name="qdev-qazstack-01",
        request_fingerprint="2" * 64,
        agent_certificate_sha256="c" * 64,
        outcome="completed",
        outcome_digest="sha256:" + "c" * 64,
        reconciliation_key=RECONCILIATION_KEY,
    )
    acceptance = _acceptance_proof(
        completed,
        provider_runner_id=22,
        prior_provider_runner_disposition="absent",
    )
    released = store.advance_worker_recovery(
        admitted["idempotency_key"],
        expected="completed",
        state="released",
        acceptance_proof=acceptance,
        acceptance_proof_key=ACCEPTANCE_KEY,
    )
    assert released["state"] == "released"
    assert released["provider_runner_id"] == 21
    assert released["accepted_provider_runner_id"] == 22
