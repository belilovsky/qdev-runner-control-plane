from __future__ import annotations

import hashlib
import hmac
import json
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
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
POLICY_DIGEST = "sha256:" + "2" * 64
AGENT_RELEASE_DIGEST = "sha256:" + "3" * 64


def _provider_observation(
    *,
    worker_name: str = WORKER,
    repository: str = REPOSITORY,
    labels: tuple[str, ...] = LABELS,
    provider_runner_id: int = 187,
    provider_status: str = "offline",
    provider_busy: bool = False,
    active_jobs: int = 0,
    canary: dict[str, Any] | None = None,
    other_runners: tuple[dict[str, Any], ...] = (),
) -> dict[str, Any]:
    runners = [
        {
            "id": provider_runner_id,
            "name": worker_name,
            "status": provider_status,
            "busy": provider_busy,
            "labels": list(labels),
        },
        *other_runners,
    ]
    observation: dict[str, Any] = {
        "schema": (
            "qdev-worker-provider-observation-v1"
            if canary is None
            else "qdev-worker-recovery-provider-observation-v1"
        ),
        "repository": repository,
        "runners": {"total_count": len(runners), "items": runners},
        "active_target_jobs": {
            "total_count": active_jobs,
            "items": [{"id": index + 1} for index in range(active_jobs)],
        },
    }
    if canary is not None:
        observation["canary"] = canary
    return observation


def _provider_absence_observation(
    *,
    worker_name: str,
    repository: str,
    active_jobs: int = 0,
) -> dict[str, Any]:
    return {
        "schema": "qdev-worker-provider-absence-observation-v1",
        "repository": repository,
        "worker_name": worker_name,
        "runners": {"total_count": 0, "items": []},
        "active_target_jobs": {
            "total_count": active_jobs,
            "items": [{"id": index + 1} for index in range(active_jobs)],
        },
    }


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
        provider_observation=_provider_observation(active_jobs=active_jobs),
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
        "interface_version": "qdev-worker-recovery-v3",
        "interface_digest": "d" * 64,
        "controller_revision": "e" * 40,
        "controller_release_digest": "f" * 64,
        "policy_digest": POLICY_DIGEST,
        "agent_release_digest": AGENT_RELEASE_DIGEST,
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
    permanent_labels = tuple(json.loads(str(recovery["labels_json"]))) if labels is None else labels
    raw_prior_runner_id = recovery["provider_runner_id"]
    prior_runner_id = None if raw_prior_runner_id is None else int(raw_prior_runner_id)
    if provider_runner_id is None and prior_runner_id is None:
        raise ValueError("provider_runner_id is required when the prior runner is absent")
    resulting_runner_id = prior_runner_id if provider_runner_id is None else provider_runner_id
    assert resulting_runner_id is not None
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
    operation_id = str(recovery["operation_id"])
    temporary_label = f"qdev-job-recovery-{operation_id}"
    dispatch_correlation = f"qdev-recovery-{operation_id}"
    canary_observation = {
        "repository": repository,
        "workflow": workflow,
        "ref": "refs/heads/main",
        "head_sha": "8" * 40,
        "dispatch_correlation": dispatch_correlation,
        "temporary_label": temporary_label,
        "dispatch_observed_label": temporary_label,
        "run_observed_label": temporary_label,
        "baseline_run_id": 499,
        "run_id": 500,
        "run_attempt": 1,
        "job_id": 501,
        "job_labels": [*permanent_labels, temporary_label],
        "job_runner_id": resulting_runner_id,
        "job_runner_name": worker_name,
        "status": "completed",
        "conclusion": "success",
        "completed_at": completed_at,
    }
    return Store.issue_worker_recovery_acceptance_proof(
        key=ACCEPTANCE_KEY,
        operation_id=operation_id,
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
        provider_observation=_provider_observation(
            worker_name=worker_name,
            repository=repository,
            labels=permanent_labels,
            provider_runner_id=resulting_runner_id,
            provider_status="online",
            canary=canary_observation,
        ),
        canary_repository=repository,
        canary_workflow=workflow,
        canary_ref="refs/heads/main",
        canary_head_sha="8" * 40,
        canary_dispatch_correlation=dispatch_correlation,
        canary_temporary_label=temporary_label,
        canary_dispatch_observed_label=temporary_label,
        canary_run_observed_label=temporary_label,
        canary_baseline_run_id=499,
        canary_run_id=500,
        canary_run_attempt=1,
        canary_job_id=501,
        canary_job_labels=permanent_labels + (temporary_label,),
        canary_job_runner_id=resulting_runner_id,
        canary_job_runner_name=worker_name,
        canary_runner_id=(resulting_runner_id if canary_runner_id is None else canary_runner_id),
        canary_runner_name=worker_name,
        canary_status="completed",
        canary_conclusion="success",
        canary_completed_at=completed_at,
        observed_at=provider_observed_at,
    )


def _complete_canary(
    store: Store,
    recovery: dict[str, Any],
    *,
    provider_runner_id: int | None = None,
) -> dict[str, Any]:
    worker_name = str(recovery["worker_name"])
    repository = str(recovery["repository"])
    raw_runner_id = recovery["provider_runner_id"]
    if provider_runner_id is None and raw_runner_id is None:
        raise ValueError("provider_runner_id is required when the prior runner is absent")
    runner_id = int(raw_runner_id) if provider_runner_id is None else provider_runner_id
    assert runner_id is not None
    workflow = (
        ".github/workflows/runner-smoke.yml"
        if worker_name == WORKER
        else ".github/workflows/self-hosted-recovery.yml"
    )
    canary, replay = store.create_worker_recovery_canary_intent(
        operation_id=str(recovery["operation_id"]),
        repository=repository,
        workflow=workflow,
        ref="refs/heads/main",
        head_sha="8" * 40,
        baseline_run_id=499,
        provider_runner_id=runner_id,
        provider_runner_name=worker_name,
    )
    assert replay is False
    canary, permitted = store.claim_worker_recovery_canary_dispatch(
        operation_id=str(recovery["operation_id"]),
        expected_revision=int(canary["revision"]),
    )
    assert permitted is True
    correlation = str(canary["dispatch_correlation"])
    temporary_label = str(canary["temporary_label"])
    steps: tuple[tuple[str, dict[str, Any]], ...] = (
        (
            "dispatched",
            {
                "dispatch_correlation": correlation,
                "observed_temporary_label": temporary_label,
            },
        ),
        (
            "run_observed",
            {
                "dispatch_correlation": correlation,
                "observed_temporary_label": temporary_label,
                "run_id": 500,
                "run_attempt": 1,
            },
        ),
        ("labels_pending", {}),
        ("labels_applied", {}),
        (
            "job_observed",
            {
                "dispatch_correlation": correlation,
                "observed_temporary_label": temporary_label,
                "job_id": 501,
                "job_labels": tuple(json.loads(str(recovery["labels_json"]))) + (temporary_label,),
                "job_runner_id": runner_id,
                "job_runner_name": worker_name,
                "run_status": "in_progress",
            },
        ),
        (
            "completed",
            {
                "run_status": "completed",
                "conclusion": "success",
            },
        ),
        ("cleanup_pending", {}),
        ("cleaned", {}),
    )
    for phase, observation in steps:
        if phase == "completed":
            observation["completed_at"] = max(
                time.time(),
                float(recovery["native_finalized_at"]),
                float(canary["dispatched_at"]),
            )
        canary, replay = store.transition_worker_recovery_canary(
            operation_id=str(recovery["operation_id"]),
            expected_revision=int(canary["revision"]),
            expected_phase=str(canary["phase"]),
            phase=phase,
            **observation,
        )
        assert replay is False
    return canary


def _completed_recovery(store: Store) -> dict[str, Any]:
    admitted = store.begin_worker_recovery(**_begin_arguments())
    store.advance_worker_recovery(
        admitted["idempotency_key"], expected="prepared", state="invoking"
    )
    return store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="completed",
        outcome_digest="sha256:" + "4" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
        reconciliation_key=RECONCILIATION_KEY,
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
    assert (
        migrated["operation_id"]
        == hashlib.sha256(f"legacy-recovery-0001\0{WORKER}\0{'9' * 64}".encode()).hexdigest()
    )
    with store.connect() as connection:
        indexes = {
            str(row["name"])
            for row in connection.execute("PRAGMA index_list(worker_recoveries)").fetchall()
        }
        tables = {
            str(row["name"])
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
        recovery_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(worker_recoveries)").fetchall()
        }
        outcome_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(worker_recovery_outcomes)").fetchall()
        }
        acceptance_columns = {
            str(row["name"])
            for row in connection.execute(
                "PRAGMA table_info(worker_recovery_acceptances)"
            ).fetchall()
        }
        canary_columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(worker_recovery_canaries)").fetchall()
        }
    assert "worker_recovery_controller_receipt_idx" in indexes
    assert "worker_recovery_request_nonce_idx" in indexes
    assert "worker_recovery_outcomes" in tables
    assert "worker_recovery_acceptances" in tables
    assert "worker_recovery_canaries" in tables
    assert "worker_recovery_canary_events" in tables
    assert {
        "provider_observation_json",
        "provider_reconciliation_digest",
        "policy_digest",
        "agent_release_digest",
        "superseded_by_operation_id",
        "superseded_at",
        "supersede_reason",
    } <= recovery_columns
    assert {
        "provider_reconciliation_digest",
        "recovery_action",
        "request_nonce",
        "policy_digest",
        "agent_release_digest",
    } <= outcome_columns
    assert "provider_observation_json" in acceptance_columns
    assert {
        "dispatch_correlation",
        "temporary_label",
        "dispatch_observed_label",
        "run_observed_label",
        "job_labels_json",
        "job_runner_id",
        "job_runner_name",
        "dispatched_at",
    } <= canary_columns


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


def test_saved_platform_pre_recovery_proof_accepts_exact_online_idle() -> None:
    proof = Store.issue_worker_provider_idle_proof(
        key=PROOF_KEY,
        worker_name=WORKER,
        repository=REPOSITORY,
        labels=LABELS,
        provider_runner_id=187,
        provider_status="online",
        provider_busy=False,
        active_jobs=0,
        provider_observation=_provider_observation(provider_status="online"),
    )
    verified = Store.verify_worker_provider_idle_proof(
        proof,
        key=PROOF_KEY,
        worker_name=WORKER,
        repository=REPOSITORY,
        labels=LABELS,
        max_age_seconds=60,
    )
    assert verified["provider_status"] == "online"


def test_pre_recovery_proof_remains_strictly_typed(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    with pytest.raises(ValueError, match="provider idle proof"):
        Store.issue_worker_provider_idle_proof(
            key=PROOF_KEY,
            worker_name=WORKER,
            repository=REPOSITORY,
            labels=LABELS,
            provider_runner_id=187,
            provider_status="online",
            provider_busy=True,
            active_jobs=0,
            provider_observation=_provider_observation(
                provider_status="online", provider_busy=True
            ),
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
        provider_observation=_provider_observation(
            worker_name=str(second["worker_name"]),
            repository=str(second["repository"]),
            labels=second["labels"],
            provider_runner_id=153,
        ),
    )
    with pytest.raises(ValueError, match="authority was already consumed"):
        store.begin_worker_recovery(**second)


def test_stale_prepared_recovery_is_atomically_superseded_before_invocation(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    first = store.begin_worker_recovery(**_begin_arguments())
    second_arguments = _begin_arguments(
        idempotency_key="recovery-platform-0002",
        fingerprint="2" * 64,
        controller_revision="3" * 40,
        controller_release_digest="4" * 64,
        controller_receipt_id="5" * 64,
        request_nonce="nonce-platform-0002",
        supersede_prepared_operation_id=first["operation_id"],
    )

    second = store.begin_worker_recovery(**second_arguments)

    superseded = store.worker_recovery(first["operation_id"])
    assert superseded is not None
    assert superseded["state"] == "released"
    assert superseded["native_outcome"] is None
    assert superseded["superseded_by_operation_id"] == second["operation_id"]
    assert superseded["superseded_at"] is not None
    assert superseded["supersede_reason"] == "controller_release_changed_before_invocation"
    assert second["state"] == "prepared"
    active = store.prepared_worker_recovery(WORKER)
    assert active is not None
    assert active["operation_id"] == second["operation_id"]


def test_prepared_supersede_rolls_back_if_new_authority_cannot_be_admitted(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    first_arguments = _begin_arguments()
    first = store.begin_worker_recovery(**first_arguments)
    second_arguments = _begin_arguments(
        idempotency_key="recovery-platform-0002",
        fingerprint="2" * 64,
        controller_revision="3" * 40,
        controller_release_digest="4" * 64,
        controller_receipt_id="5" * 64,
        request_nonce=first_arguments["request_nonce"],
        supersede_prepared_operation_id=first["operation_id"],
    )

    with pytest.raises(ValueError, match="authority was already consumed"):
        store.begin_worker_recovery(**second_arguments)

    unchanged = store.worker_recovery(first["operation_id"])
    assert unchanged is not None
    assert unchanged["state"] == "prepared"
    assert unchanged["native_outcome"] is None
    assert unchanged["superseded_by_operation_id"] is None


def test_invoked_recovery_cannot_be_superseded(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    first = store.begin_worker_recovery(**_begin_arguments())
    store.advance_worker_recovery(first["idempotency_key"], expected="prepared", state="invoking")

    with pytest.raises(ValueError, match="cannot be superseded"):
        store.begin_worker_recovery(
            **_begin_arguments(
                idempotency_key="recovery-platform-0002",
                fingerprint="2" * 64,
                controller_revision="3" * 40,
                controller_release_digest="4" * 64,
                controller_receipt_id="5" * 64,
                request_nonce="nonce-platform-0002",
                supersede_prepared_operation_id=first["operation_id"],
            )
        )


def test_completed_recovery_cannot_be_superseded(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    first = store.begin_worker_recovery(**_begin_arguments())
    with sqlite3.connect(tmp_path / "broker.db") as connection:
        connection.execute(
            "UPDATE worker_recoveries SET state='completed' WHERE operation_id=?",
            (first["operation_id"],),
        )

    with pytest.raises(ValueError, match="cannot be superseded"):
        store.begin_worker_recovery(
            **_begin_arguments(
                idempotency_key="recovery-platform-0002",
                fingerprint="2" * 64,
                controller_revision="3" * 40,
                controller_release_digest="4" * 64,
                controller_receipt_id="5" * 64,
                request_nonce="nonce-platform-0002",
                supersede_prepared_operation_id=first["operation_id"],
            )
        )


@pytest.mark.parametrize(
    ("statement", "value"),
    [
        ("UPDATE worker_recoveries SET invoked_at=? WHERE operation_id=?", 1.0),
        ("UPDATE worker_recoveries SET native_outcome=? WHERE operation_id=?", "completed"),
        (
            "UPDATE worker_recoveries SET native_outcome_digest=? WHERE operation_id=?",
            "sha256:" + "1" * 64,
        ),
        ("UPDATE worker_recoveries SET native_outcome_signature=? WHERE operation_id=?", "1" * 64),
        ("UPDATE worker_recoveries SET agent_identity=? WHERE operation_id=?", "agent"),
        ("UPDATE worker_recoveries SET agent_certificate_sha256=? WHERE operation_id=?", "2" * 64),
        ("UPDATE worker_recoveries SET reconciled_at=? WHERE operation_id=?", 1.0),
        ("UPDATE worker_recoveries SET native_outcome_observed_at=? WHERE operation_id=?", 1.0),
        ("UPDATE worker_recoveries SET native_finalized_at=? WHERE operation_id=?", 1.0),
        ("UPDATE worker_recoveries SET accepted_provider_runner_id=? WHERE operation_id=?", 187),
        (
            "UPDATE worker_recoveries SET acceptance_proof_digest=? WHERE operation_id=?",
            "sha256:" + "3" * 64,
        ),
        (
            "UPDATE worker_recoveries SET acceptance_proof_signature=? WHERE operation_id=?",
            "3" * 64,
        ),
        (
            "UPDATE worker_recoveries SET acceptance_reconciliation_digest=? WHERE operation_id=?",
            "sha256:" + "4" * 64,
        ),
        ("UPDATE worker_recoveries SET acceptance_observed_at=? WHERE operation_id=?", 1.0),
        ("UPDATE worker_recoveries SET canary_repository=? WHERE operation_id=?", REPOSITORY),
        ("UPDATE worker_recoveries SET canary_workflow=? WHERE operation_id=?", "ci.yml"),
        ("UPDATE worker_recoveries SET canary_ref=? WHERE operation_id=?", "main"),
        ("UPDATE worker_recoveries SET canary_run_id=? WHERE operation_id=?", 1),
        ("UPDATE worker_recoveries SET canary_job_id=? WHERE operation_id=?", 1),
        ("UPDATE worker_recoveries SET canary_attempt=? WHERE operation_id=?", 1),
        ("UPDATE worker_recoveries SET canary_head_sha=? WHERE operation_id=?", "5" * 40),
        ("UPDATE worker_recoveries SET canary_runner_id=? WHERE operation_id=?", 187),
        ("UPDATE worker_recoveries SET canary_status=? WHERE operation_id=?", "completed"),
        ("UPDATE worker_recoveries SET canary_conclusion=? WHERE operation_id=?", "success"),
        ("UPDATE worker_recoveries SET canary_completed_at=? WHERE operation_id=?", 1.0),
        ("UPDATE worker_recoveries SET released_at=? WHERE operation_id=?", 1.0),
        (
            "UPDATE worker_recoveries SET superseded_by_operation_id=? WHERE operation_id=?",
            "6" * 64,
        ),
        ("UPDATE worker_recoveries SET superseded_at=? WHERE operation_id=?", 1.0),
        ("UPDATE worker_recoveries SET supersede_reason=? WHERE operation_id=?", "unexpected"),
    ],
)
def test_any_execution_or_terminal_marker_blocks_prepared_supersede(
    tmp_path: Path, statement: str, value: object
) -> None:
    database = tmp_path / "broker.db"
    store = Store(database)
    first = store.begin_worker_recovery(**_begin_arguments())
    with sqlite3.connect(database) as connection:
        connection.execute(statement, (value, first["operation_id"]))

    with pytest.raises(ValueError, match="cannot be superseded"):
        store.begin_worker_recovery(
            **_begin_arguments(
                idempotency_key="recovery-platform-0002",
                fingerprint="2" * 64,
                controller_revision="3" * 40,
                controller_release_digest="4" * 64,
                controller_receipt_id="5" * 64,
                request_nonce="nonce-platform-0002",
                supersede_prepared_operation_id=first["operation_id"],
            )
        )
    unchanged = store.worker_recovery(first["operation_id"])
    assert unchanged is not None
    assert unchanged["state"] == "prepared"


@pytest.mark.parametrize("ledger", ["outcome", "acceptance", "canary"])
def test_any_append_only_ledger_blocks_prepared_supersede(
    tmp_path: Path, ledger: str
) -> None:
    database = tmp_path / "broker.db"
    store = Store(database)
    first = store.begin_worker_recovery(**_begin_arguments())
    operation_id = first["operation_id"]
    with sqlite3.connect(database) as connection:
        if ledger == "outcome":
            connection.execute(
                "INSERT INTO worker_recovery_outcomes VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    "sha256:" + "1" * 64,
                    operation_id,
                    WORKER,
                    first["request_fingerprint"],
                    "2" * 64,
                    "sha256:" + "3" * 64,
                    "recover_existing_worker",
                    first["request_nonce"],
                    first["policy_digest"],
                    first["agent_release_digest"],
                    "ambiguous",
                    "sha256:" + "4" * 64,
                    "5" * 64,
                    1.0,
                    1.0,
                ),
            )
        elif ledger == "acceptance":
            connection.execute(
                "INSERT INTO worker_recovery_acceptances VALUES("
                + ",".join("?" for _ in range(25))
                + ")",
                (
                    "sha256:" + "1" * 64,
                    operation_id,
                    WORKER,
                    REPOSITORY,
                    json.dumps(list(LABELS), separators=(",", ":")),
                    None,
                    "absent",
                    187,
                    1,
                    "sha256:" + "2" * 64,
                    "{}",
                    1.0,
                    REPOSITORY,
                    "ci.yml",
                    "main",
                    "3" * 40,
                    1,
                    1,
                    1,
                    187,
                    "completed",
                    "success",
                    1.0,
                    "4" * 64,
                    1.0,
                ),
            )
        else:
            connection.execute(
                "INSERT INTO worker_recovery_canaries("
                "operation_id,worker_name,repository,workflow,ref,head_sha,"
                "baseline_run_id,provider_runner_id,provider_runner_name,"
                "dispatch_correlation,temporary_label,temporary_labels_json,"
                "intent_digest,phase,revision,last_event_digest,created_at,updated_at"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    operation_id,
                    WORKER,
                    REPOSITORY,
                    "ci.yml",
                    "main",
                    "3" * 40,
                    0,
                    187,
                    WORKER,
                    "correlation-ledger",
                    "temporary-label",
                    "[]",
                    "sha256:" + "4" * 64,
                    "dispatch_intent",
                    1,
                    "sha256:" + "5" * 64,
                    1.0,
                    1.0,
                ),
            )

    with pytest.raises(ValueError, match="cannot be superseded"):
        store.begin_worker_recovery(
            **_begin_arguments(
                idempotency_key="recovery-platform-0002",
                fingerprint="2" * 64,
                controller_revision="3" * 40,
                controller_release_digest="4" * 64,
                controller_receipt_id="5" * 64,
                request_nonce="nonce-platform-0002",
                supersede_prepared_operation_id=operation_id,
            )
        )
    unchanged = store.worker_recovery(operation_id)
    assert unchanged is not None
    assert unchanged["state"] == "prepared"


def test_released_recovery_cannot_be_superseded_by_stale_compare_and_swap(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    first = store.begin_worker_recovery(**_begin_arguments())
    store.advance_worker_recovery(first["idempotency_key"], expected="prepared", state="released")

    with pytest.raises(ValueError, match="cannot be superseded"):
        store.begin_worker_recovery(
            **_begin_arguments(
                idempotency_key="recovery-platform-0002",
                fingerprint="2" * 64,
                controller_revision="3" * 40,
                controller_release_digest="4" * 64,
                controller_receipt_id="5" * 64,
                request_nonce="nonce-platform-0002",
                supersede_prepared_operation_id=first["operation_id"],
            )
        )

    released = store.worker_recovery(first["operation_id"])
    assert released is not None
    assert released["state"] == "released"
    assert store.prepared_worker_recovery(WORKER) is None


def test_supersede_then_claim_old_operation_fails_and_new_operation_can_claim(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    first = store.begin_worker_recovery(**_begin_arguments())
    second = store.begin_worker_recovery(
        **_begin_arguments(
            idempotency_key="recovery-platform-0002",
            fingerprint="2" * 64,
            controller_revision="3" * 40,
            controller_release_digest="4" * 64,
            controller_receipt_id="5" * 64,
            request_nonce="nonce-platform-0002",
            supersede_prepared_operation_id=first["operation_id"],
        )
    )

    with pytest.raises(ValueError, match="transaction changed"):
        store.advance_worker_recovery(
            first["idempotency_key"], expected="prepared", state="invoking"
        )
    claimed = store.advance_worker_recovery(
        second["idempotency_key"], expected="prepared", state="invoking"
    )
    assert claimed["operation_id"] == second["operation_id"]
    assert claimed["state"] == "invoking"


def test_only_one_parallel_prepare_can_supersede_the_same_predecessor(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    first = store.begin_worker_recovery(**_begin_arguments())
    candidates = [
        _begin_arguments(
            idempotency_key=f"recovery-platform-000{index}",
            fingerprint=str(index) * 64,
            controller_revision=str(index + 1) * 40,
            controller_release_digest=str(index + 2) * 64,
            controller_receipt_id=str(index + 3) * 64,
            request_nonce=f"nonce-platform-000{index}",
            supersede_prepared_operation_id=first["operation_id"],
        )
        for index in (2, 3)
    ]

    def attempt(arguments: dict[str, Any]) -> tuple[str, str]:
        try:
            row = store.begin_worker_recovery(**arguments)
        except ValueError as error:
            return ("rejected", str(error))
        return ("prepared", str(row["operation_id"]))

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(attempt, candidates))

    assert sorted(result[0] for result in results) == ["prepared", "rejected"]
    rejected = next(result for result in results if result[0] == "rejected")
    assert rejected[1] == "worker recovery transaction cannot be superseded"
    active = store.prepared_worker_recovery(WORKER)
    assert active is not None
    winner = next(result[1] for result in results if result[0] == "prepared")
    assert active["operation_id"] == winner
    old = store.worker_recovery(first["operation_id"])
    assert old is not None
    assert old["superseded_by_operation_id"] == winner


def test_claim_and_supersede_race_has_exactly_one_winner(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    first = store.begin_worker_recovery(**_begin_arguments())
    barrier = threading.Barrier(2)

    def claim() -> tuple[str, str]:
        barrier.wait()
        try:
            row = store.advance_worker_recovery(
                first["idempotency_key"], expected="prepared", state="invoking"
            )
        except ValueError as error:
            return "claim-rejected", str(error)
        return "claimed", str(row["operation_id"])

    def supersede() -> tuple[str, str]:
        barrier.wait()
        try:
            row = store.begin_worker_recovery(
                **_begin_arguments(
                    idempotency_key="recovery-platform-0002",
                    fingerprint="2" * 64,
                    controller_revision="3" * 40,
                    controller_release_digest="4" * 64,
                    controller_receipt_id="5" * 64,
                    request_nonce="nonce-platform-0002",
                    supersede_prepared_operation_id=first["operation_id"],
                )
            )
        except ValueError as error:
            return "supersede-rejected", str(error)
        return "superseded", str(row["operation_id"])

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = (executor.submit(claim), executor.submit(supersede))
        results = [future.result() for future in futures]

    outcomes = {result[0] for result in results}
    assert outcomes in (
        {"claimed", "supersede-rejected"},
        {"claim-rejected", "superseded"},
    )
    old = store.worker_recovery(first["operation_id"])
    assert old is not None
    if "claimed" in outcomes:
        assert old["state"] == "invoking"
        assert old["superseded_by_operation_id"] is None
    else:
        assert old["state"] == "released"
        assert old["superseded_by_operation_id"] is not None


@pytest.mark.parametrize(
    ("revision", "release_digest"),
    [("1" * 40, "4" * 64), ("3" * 40, "2" * 64)],
)
def test_revision_or_digest_change_independently_allows_prepared_supersede(
    tmp_path: Path, revision: str, release_digest: str
) -> None:
    store = Store(tmp_path / "broker.db")
    first = store.begin_worker_recovery(**_begin_arguments())
    second = store.begin_worker_recovery(
        **_begin_arguments(
            idempotency_key="recovery-platform-0002",
            fingerprint="2" * 64,
            controller_revision=revision,
            controller_release_digest=release_digest,
            controller_receipt_id="5" * 64,
            request_nonce="nonce-platform-0002",
            supersede_prepared_operation_id=first["operation_id"],
        )
    )
    assert second["state"] == "prepared"


def test_controller_release_can_return_to_an_older_tuple_through_supersede_chain(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    first = store.begin_worker_recovery(**_begin_arguments())
    second = store.begin_worker_recovery(
        **_begin_arguments(
            idempotency_key="recovery-platform-0002",
            fingerprint="2" * 64,
            controller_revision="3" * 40,
            controller_release_digest="4" * 64,
            controller_receipt_id="5" * 64,
            request_nonce="nonce-platform-0002",
            supersede_prepared_operation_id=first["operation_id"],
        )
    )
    third = store.begin_worker_recovery(
        **_begin_arguments(
            idempotency_key="recovery-platform-0003",
            fingerprint="3" * 64,
            controller_receipt_id="6" * 64,
            request_nonce="nonce-platform-0003",
            supersede_prepared_operation_id=second["operation_id"],
        )
    )

    assert third["controller_revision"] == "e" * 40
    assert third["controller_release_digest"] == "f" * 64
    active = store.prepared_worker_recovery(WORKER)
    assert active is not None
    assert active["operation_id"] == third["operation_id"]


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
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="not_applied",
        outcome_digest="sha256:" + "2" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
        reconciliation_key=RECONCILIATION_KEY,
    )

    arguments["controller_observed_at"] = float(arguments["controller_observed_at"])
    arguments["requested_at"] = float(arguments["requested_at"])
    replay = store.begin_worker_recovery(**arguments, proof_max_age_seconds=0.0)
    assert replay["state"] == "released"
    assert replay["operation_id"] == admitted["operation_id"]
    lookup = store.worker_recovery_by_idempotency_key(admitted["idempotency_key"])
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
            provider_observation=_provider_observation(repository="belilovsky/other"),
        )
    with pytest.raises(ValueError, match="not registered"):
        store.begin_worker_recovery(**arbitrary)

    tampered = _provider_proof()
    tampered["provider_reconciliation_digest"] = "sha256:" + "9" * 64
    forged_payload = {
        field: value for field, value in tampered.items() if field not in {"digest", "signature"}
    }
    canonical = json.dumps(
        forged_payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode()
    tampered["digest"] = "sha256:" + hashlib.sha256(canonical).hexdigest()
    tampered["signature"] = hmac.new(PROOF_KEY.encode(), canonical, hashlib.sha256).hexdigest()
    with pytest.raises(ValueError, match="provider idle proof"):
        store.begin_worker_recovery(**_begin_arguments(provider_idle_proof=tampered))


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
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="ambiguous",
        outcome_digest="sha256:" + "3" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
        reconciliation_key=RECONCILIATION_KEY,
        observed_at=observed_at,
    )
    assert ambiguous["state"] == "invoking"
    assert store.health()["workers"] == []

    replay = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="ambiguous",
        outcome_digest="sha256:" + "3" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
        reconciliation_key=RECONCILIATION_KEY,
        observed_at=observed_at - 600,
    )
    assert replay["reconciliation_receipt_digest"] == ambiguous["reconciliation_receipt_digest"]

    completed = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="completed",
        outcome_digest="sha256:" + "4" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
        reconciliation_key=RECONCILIATION_KEY,
    )
    assert completed["state"] == "completed"
    assert completed["native_outcome"] == "completed"
    assert len(store.worker_recovery_outcomes(admitted["operation_id"])) == 2
    with pytest.raises(ValueError, match="acceptance proof is required"):
        store.advance_worker_recovery(
            admitted["idempotency_key"], expected="completed", state="released"
        )
    canary = _complete_canary(store, completed)
    acceptance = _acceptance_proof(completed, canary_completed_at=float(canary["completed_at"]))
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
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="failed",
        outcome_digest="sha256:" + "5" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
        reconciliation_key=RECONCILIATION_KEY,
    )
    assert failed["state"] == "invoking"

    released = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="not_applied",
        outcome_digest="sha256:" + "6" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
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
            recovery_action=str(admitted["recovery_action"]),
            request_nonce=str(admitted["request_nonce"]),
            provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
            agent_certificate_sha256="7" * 64,
            outcome="completed",
            outcome_digest="sha256:" + "8" * 64,
            agent_release_digest=str(admitted["agent_release_digest"]),
            reconciliation_key=RECONCILIATION_KEY,
        )

    observed_at = time.time()
    outcome = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name=WORKER,
        request_fingerprint="a" * 64,
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="ambiguous",
        outcome_digest="sha256:" + "8" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
        reconciliation_key=RECONCILIATION_KEY,
        observed_at=observed_at,
    )
    payload = {
        "schema": "qdev-worker-recovery-native-outcome-v1",
        "operation_id": admitted["operation_id"],
        "worker_name": WORKER,
        "request_digest": "a" * 64,
        "agent_certificate_sha256": "c" * 64,
        "provider_reconciliation_digest": admitted["provider_reconciliation_digest"],
        "recovery_action": admitted["recovery_action"],
        "request_nonce": admitted["request_nonce"],
        "policy_digest": admitted["policy_digest"],
        "agent_release_digest": admitted["agent_release_digest"],
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
        == admitted["provider_reconciliation_digest"]
    )
    assert stored_outcomes[0]["policy_digest"] == POLICY_DIGEST
    assert stored_outcomes[0]["agent_release_digest"] == AGENT_RELEASE_DIGEST


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
            recovery_action=str(admitted["recovery_action"]),
            request_nonce=str(admitted["request_nonce"]),
            provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
            agent_certificate_sha256="c" * 64,
            outcome="completed",
            outcome_digest="sha256:" + "9" * 64,
            agent_release_digest=str(admitted["agent_release_digest"]),
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
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="completed",
        outcome_digest="sha256:" + "a" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
        reconciliation_key=RECONCILIATION_KEY,
    )

    wrong_workflow = {
        field: value
        for field, value in _acceptance_proof(completed).items()
        if field
        not in {
            "digest",
            "signature",
            "schema",
            "provider_reconciliation_digest",
        }
    }
    wrong_workflow["canary_workflow"] = ".github/workflows/other.yml"
    with pytest.raises(ValueError, match="acceptance proof"):
        Store.issue_worker_recovery_acceptance_proof(key=ACCEPTANCE_KEY, **wrong_workflow)
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
        provider_observation=_provider_observation(
            worker_name="qdev-qazstack-01",
            repository="belilovsky/qazstack",
            labels=labels,
            provider_runner_id=21,
        ),
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
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="completed",
        outcome_digest="sha256:" + "c" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
        reconciliation_key=RECONCILIATION_KEY,
    )
    acceptance = _acceptance_proof(
        completed,
        provider_runner_id=22,
        prior_provider_runner_disposition="absent",
        canary_completed_at=float(
            _complete_canary(store, completed, provider_runner_id=22)["completed_at"]
        ),
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


def test_qazstack_absent_provider_registration_accepts_fresh_runner(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    now = time.time()
    labels = ("self-hosted", "Linux", "X64", "qdev-ci")
    arguments = _begin_arguments(
        worker_name="qdev-qazstack-01",
        idempotency_key="recovery-qazstack-absent-0001",
        fingerprint="3" * 64,
        repository="belilovsky/qazstack",
        labels=labels,
        recovery_action="replace_existing_registration",
        request_nonce="nonce-qazstack-absent-0001",
        controller_observed_at=now,
        requested_at=now,
    )
    arguments["provider_idle_proof"] = Store.issue_worker_provider_idle_proof(
        key=PROOF_KEY,
        worker_name="qdev-qazstack-01",
        repository="belilovsky/qazstack",
        labels=labels,
        provider_runner_id=None,
        provider_status=None,
        provider_busy=None,
        active_jobs=0,
        provider_observation=_provider_absence_observation(
            worker_name="qdev-qazstack-01",
            repository="belilovsky/qazstack",
        ),
        observed_at=now,
    )
    admitted = store.begin_worker_recovery(**arguments)
    assert admitted["provider_runner_id"] is None

    store.advance_worker_recovery(
        admitted["idempotency_key"], expected="prepared", state="invoking"
    )
    completed = store.reconcile_worker_recovery(
        operation_id=admitted["operation_id"],
        worker_name="qdev-qazstack-01",
        request_fingerprint="3" * 64,
        recovery_action=str(admitted["recovery_action"]),
        request_nonce=str(admitted["request_nonce"]),
        provider_reconciliation_digest=str(admitted["provider_reconciliation_digest"]),
        agent_certificate_sha256="c" * 64,
        outcome="completed",
        outcome_digest="sha256:" + "d" * 64,
        agent_release_digest=str(admitted["agent_release_digest"]),
        reconciliation_key=RECONCILIATION_KEY,
    )
    acceptance = _acceptance_proof(
        completed,
        provider_runner_id=22,
        prior_provider_runner_disposition="absent",
        canary_completed_at=float(
            _complete_canary(store, completed, provider_runner_id=22)["completed_at"]
        ),
    )
    released = store.advance_worker_recovery(
        admitted["idempotency_key"],
        expected="completed",
        state="released",
        acceptance_proof=acceptance,
        acceptance_proof_key=ACCEPTANCE_KEY,
    )
    assert released["state"] == "released"
    assert released["provider_runner_id"] is None
    assert released["accepted_provider_runner_id"] == 22


def test_canary_intent_is_exact_secret_free_and_replay_safe(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    recovery = _completed_recovery(store)
    arguments = {
        "operation_id": recovery["operation_id"],
        "repository": REPOSITORY,
        "workflow": ".github/workflows/runner-smoke.yml",
        "ref": "refs/heads/main",
        "head_sha": "8" * 40,
        "baseline_run_id": 499,
        "provider_runner_id": 187,
        "provider_runner_name": WORKER,
    }

    intent, replay = store.create_worker_recovery_canary_intent(**arguments)

    assert replay is False
    assert intent["phase"] == "dispatch_intent"
    assert intent["revision"] == 1
    assert intent["repository"] == REPOSITORY
    assert intent["workflow"] == ".github/workflows/runner-smoke.yml"
    assert intent["ref"] == "refs/heads/main"
    assert intent["head_sha"] == "8" * 40
    assert intent["baseline_run_id"] == 499
    assert intent["provider_runner_id"] == 187
    assert intent["provider_runner_name"] == WORKER
    expected_label = f"qdev-job-recovery-{recovery['operation_id']}"
    expected_correlation = f"qdev-recovery-{recovery['operation_id']}"
    assert intent["dispatch_correlation"] == expected_correlation
    assert intent["temporary_label"] == expected_label
    assert intent["temporary_labels"] == (expected_label,)
    events = store.worker_recovery_canary_events(recovery["operation_id"])
    assert len(events) == 1
    assert events[0]["event"]["phase"] == "dispatch_intent"
    assert set(events[0]["event"]) == {
        "schema",
        "operation_id",
        "revision",
        "from_phase",
        "phase",
        "intent_digest",
        "worker_name",
        "repository",
        "workflow",
        "ref",
        "head_sha",
        "baseline_run_id",
        "provider_runner_id",
        "provider_runner_name",
        "dispatch_correlation",
        "temporary_label",
        "temporary_labels",
        "dispatch_observed_label",
        "run_observed_label",
        "run_id",
        "run_attempt",
        "job_id",
        "job_labels",
        "job_runner_id",
        "job_runner_name",
        "run_status",
        "conclusion",
        "dispatched_at",
        "completed_at",
        "cleaned_at",
        "accepted_at",
        "recorded_at",
    }
    with store.connect() as connection:
        column_names = {
            str(row["name"]).lower()
            for table in (
                "worker_recovery_canaries",
                "worker_recovery_canary_events",
            )
            for row in connection.execute(f"PRAGMA table_info({table})").fetchall()
        }
        event_json = str(
            connection.execute("SELECT event_json FROM worker_recovery_canary_events").fetchone()[0]
        ).lower()
    assert not column_names.intersection(
        {"token", "registration_token", "secret", "credential", "provider_response"}
    )
    assert all(
        marker not in event_json
        for marker in ("registration_token", "credential", "provider_response")
    )

    claimed, permitted = store.claim_worker_recovery_canary_dispatch(
        operation_id=recovery["operation_id"], expected_revision=1
    )
    assert permitted is True
    exact_replay, replay = store.create_worker_recovery_canary_intent(**arguments)
    assert replay is True
    assert exact_replay == claimed
    assert len(store.worker_recovery_canary_events(recovery["operation_id"])) == 2

    with pytest.raises(ValueError, match="another intent"):
        store.create_worker_recovery_canary_intent(**(arguments | {"head_sha": "7" * 40}))


def test_canary_dispatch_and_cas_replays_fail_closed_on_ambiguity(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    recovery = _completed_recovery(store)
    intent, _ = store.create_worker_recovery_canary_intent(
        operation_id=recovery["operation_id"],
        repository=REPOSITORY,
        workflow=".github/workflows/runner-smoke.yml",
        ref="refs/heads/main",
        head_sha="8" * 40,
        baseline_run_id=499,
        provider_runner_id=187,
        provider_runner_name=WORKER,
    )

    claimed, permitted = store.claim_worker_recovery_canary_dispatch(
        operation_id=recovery["operation_id"],
        expected_revision=int(intent["revision"]),
    )
    replayed, permitted_again = store.claim_worker_recovery_canary_dispatch(
        operation_id=recovery["operation_id"],
        expected_revision=int(intent["revision"]),
    )
    assert permitted is True
    assert permitted_again is False
    assert replayed == claimed
    correlation = str(claimed["dispatch_correlation"])
    temporary_label = str(claimed["temporary_label"])

    dispatched, replay = store.transition_worker_recovery_canary(
        operation_id=recovery["operation_id"],
        expected_revision=2,
        expected_phase="dispatching",
        phase="dispatched",
        dispatch_correlation=correlation,
        observed_temporary_label=temporary_label,
    )
    assert replay is False
    replayed_dispatch, replay = store.transition_worker_recovery_canary(
        operation_id=recovery["operation_id"],
        expected_revision=2,
        expected_phase="dispatching",
        phase="dispatched",
        dispatch_correlation=correlation,
        observed_temporary_label=temporary_label,
    )
    assert replay is True
    assert replayed_dispatch == dispatched
    with pytest.raises(ValueError, match="ambiguous"):
        store.transition_worker_recovery_canary(
            operation_id=recovery["operation_id"],
            expected_revision=2,
            expected_phase="dispatching",
            phase="run_observed",
            dispatch_correlation=correlation,
            observed_temporary_label=temporary_label,
            run_id=500,
            run_attempt=1,
        )
    current = store.worker_recovery_canary(recovery["operation_id"])
    assert current == dispatched
    assert len(store.worker_recovery_canary_events(recovery["operation_id"])) == 3

    ambiguous, replay = store.transition_worker_recovery_canary(
        operation_id=recovery["operation_id"],
        expected_revision=3,
        expected_phase="dispatched",
        phase="ambiguous",
    )
    assert replay is False
    assert ambiguous["phase"] == "ambiguous"
    with pytest.raises(ValueError, match="invalid worker recovery canary transition"):
        store.transition_worker_recovery_canary(
            operation_id=recovery["operation_id"],
            expected_revision=4,
            expected_phase="ambiguous",
            phase="run_observed",
            dispatch_correlation=correlation,
            observed_temporary_label=temporary_label,
            run_id=500,
            run_attempt=1,
        )


def test_canary_lifecycle_acceptance_is_atomic_append_only_and_idempotent(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    recovery = _completed_recovery(store)
    cleaned = _complete_canary(store, recovery)
    expected_phases = [
        "dispatch_intent",
        "dispatching",
        "dispatched",
        "run_observed",
        "labels_pending",
        "labels_applied",
        "job_observed",
        "completed",
        "cleanup_pending",
        "cleaned",
    ]
    events = store.worker_recovery_canary_events(recovery["operation_id"])
    assert [event["phase"] for event in events] == expected_phases
    assert [event["revision"] for event in events] == list(range(1, 11))
    assert cleaned["run_id"] == 500
    assert cleaned["run_attempt"] == 1
    assert cleaned["job_id"] == 501
    assert cleaned["run_status"] == "completed"
    assert cleaned["conclusion"] == "success"
    assert cleaned["completed_at"] <= cleaned["cleaned_at"]

    with store.connect() as connection:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute(
                "UPDATE worker_recovery_canary_events SET phase='accepted' "
                "WHERE operation_id=? AND revision=1",
                (recovery["operation_id"],),
            )
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute(
                "DELETE FROM worker_recovery_canary_events WHERE operation_id=?",
                (recovery["operation_id"],),
            )

    acceptance = _acceptance_proof(recovery, canary_completed_at=float(cleaned["completed_at"]))
    released = store.advance_worker_recovery(
        recovery["idempotency_key"],
        expected="completed",
        state="released",
        acceptance_proof=acceptance,
        acceptance_proof_key=ACCEPTANCE_KEY,
    )
    assert released["state"] == "released"
    accepted = store.worker_recovery_canary(recovery["operation_id"])
    assert accepted is not None
    assert accepted["phase"] == "accepted"
    assert accepted["revision"] == 11
    assert accepted["accepted_at"] is not None
    assert len(store.worker_recovery_canary_events(recovery["operation_id"])) == 11

    replay = store.advance_worker_recovery(
        recovery["idempotency_key"],
        expected="completed",
        state="released",
        acceptance_proof=acceptance,
        acceptance_proof_key=ACCEPTANCE_KEY,
        proof_max_age_seconds=0,
    )
    assert replay == released
    assert len(store.worker_recovery_canary_events(recovery["operation_id"])) == 11


def test_acceptance_without_cleaned_durable_canary_keeps_recovery_fenced(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    recovery = _completed_recovery(store)
    acceptance = _acceptance_proof(recovery)

    with pytest.raises(ValueError, match="durable proof is missing"):
        store.advance_worker_recovery(
            recovery["idempotency_key"],
            expected="completed",
            state="released",
            acceptance_proof=acceptance,
            acceptance_proof_key=ACCEPTANCE_KEY,
        )

    current = store.worker_recovery(recovery["operation_id"])
    assert current is not None
    assert current["state"] == "completed"
    with store.connect() as connection:
        acceptance_count = connection.execute(
            "SELECT COUNT(*) FROM worker_recovery_acceptances WHERE operation_id=?",
            (recovery["operation_id"],),
        ).fetchone()[0]
    assert acceptance_count == 0


def test_canary_observations_are_exact_and_invalid_progress_does_not_commit(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    recovery = _completed_recovery(store)
    intent, _ = store.create_worker_recovery_canary_intent(
        operation_id=recovery["operation_id"],
        repository=REPOSITORY,
        workflow=".github/workflows/runner-smoke.yml",
        ref="refs/heads/main",
        head_sha="8" * 40,
        baseline_run_id=499,
        provider_runner_id=187,
        provider_runner_name=WORKER,
    )
    claimed, _ = store.claim_worker_recovery_canary_dispatch(
        operation_id=recovery["operation_id"],
        expected_revision=int(intent["revision"]),
    )
    correlation = str(claimed["dispatch_correlation"])
    temporary_label = str(claimed["temporary_label"])
    with pytest.raises(ValueError, match="provider binding is invalid"):
        store.transition_worker_recovery_canary(
            operation_id=recovery["operation_id"],
            expected_revision=int(claimed["revision"]),
            expected_phase="dispatching",
            phase="dispatched",
            dispatch_correlation=correlation,
            observed_temporary_label="qdev-job-recovery-canary",
        )
    dispatched, _ = store.transition_worker_recovery_canary(
        operation_id=recovery["operation_id"],
        expected_revision=int(claimed["revision"]),
        expected_phase="dispatching",
        phase="dispatched",
        dispatch_correlation=correlation,
        observed_temporary_label=temporary_label,
    )
    with pytest.raises(ValueError, match="provider binding is invalid"):
        store.transition_worker_recovery_canary(
            operation_id=recovery["operation_id"],
            expected_revision=int(dispatched["revision"]),
            expected_phase="dispatched",
            phase="run_observed",
            dispatch_correlation=correlation,
            observed_temporary_label=f"qdev-job-recovery-{'0' * 64}",
            run_id=500,
            run_attempt=1,
        )
    with pytest.raises(ValueError, match="run observation is invalid"):
        store.transition_worker_recovery_canary(
            operation_id=recovery["operation_id"],
            expected_revision=int(dispatched["revision"]),
            expected_phase="dispatched",
            phase="run_observed",
            dispatch_correlation=correlation,
            observed_temporary_label=temporary_label,
            run_id=499,
            run_attempt=1,
        )
    run_observed, _ = store.transition_worker_recovery_canary(
        operation_id=recovery["operation_id"],
        expected_revision=int(dispatched["revision"]),
        expected_phase="dispatched",
        phase="run_observed",
        dispatch_correlation=correlation,
        observed_temporary_label=temporary_label,
        run_id=500,
        run_attempt=1,
    )
    labels_pending, _ = store.transition_worker_recovery_canary(
        operation_id=recovery["operation_id"],
        expected_revision=int(run_observed["revision"]),
        expected_phase="run_observed",
        phase="labels_pending",
    )
    labels_applied, _ = store.transition_worker_recovery_canary(
        operation_id=recovery["operation_id"],
        expected_revision=int(labels_pending["revision"]),
        expected_phase="labels_pending",
        phase="labels_applied",
    )
    with pytest.raises(ValueError, match="job observation is invalid"):
        store.transition_worker_recovery_canary(
            operation_id=recovery["operation_id"],
            expected_revision=int(labels_applied["revision"]),
            expected_phase="labels_applied",
            phase="job_observed",
            dispatch_correlation=correlation,
            observed_temporary_label=temporary_label,
            job_id=501,
            job_labels=LABELS + (f"qdev-job-recovery-{'0' * 64}",),
            job_runner_id=187,
            job_runner_name=WORKER,
            run_status="in_progress",
        )
    job_observed, _ = store.transition_worker_recovery_canary(
        operation_id=recovery["operation_id"],
        expected_revision=int(labels_applied["revision"]),
        expected_phase="labels_applied",
        phase="job_observed",
        dispatch_correlation=correlation,
        observed_temporary_label=temporary_label,
        job_id=501,
        job_labels=LABELS + (temporary_label,),
        job_runner_id=187,
        job_runner_name=WORKER,
        run_status="in_progress",
    )
    completion = {
        "operation_id": recovery["operation_id"],
        "expected_revision": int(job_observed["revision"]),
        "expected_phase": "job_observed",
        "phase": "completed",
        "run_status": "completed",
        "conclusion": "success",
    }
    with pytest.raises(ValueError, match="timestamp is required"):
        store.transition_worker_recovery_canary(**completion)
    with pytest.raises(ValueError, match="completion is invalid"):
        store.transition_worker_recovery_canary(
            **completion,
            completed_at=float(job_observed["dispatched_at"]) - 0.001,
        )
    with pytest.raises(ValueError, match="completion is invalid"):
        store.transition_worker_recovery_canary(
            **completion,
            completed_at=time.time() + 600,
        )
    completed, _ = store.transition_worker_recovery_canary(
        **completion,
        completed_at=max(
            time.time(),
            float(recovery["native_finalized_at"]),
            float(job_observed["dispatched_at"]),
        ),
    )
    current = store.worker_recovery_canary(recovery["operation_id"])
    assert current == completed
    assert current["completed_at"] is not None
    assert len(store.worker_recovery_canary_events(recovery["operation_id"])) == 8
