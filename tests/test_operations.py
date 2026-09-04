from __future__ import annotations

import json
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qdev_runner.operations import (
    HARD_MAX_DISK_USED_PCT,
    HARD_MIN_FREE_GIB,
    CapacityOverrideConflict,
    OperationStore,
    payload_digest,
    sign_payload,
    validate_controller_receipt_payload,
    verify_capacity_override,
)
from qdev_runner.operator import validate_receipt_file, verify_controller_receipt


@pytest.fixture
def operation_store(tmp_path: Path) -> OperationStore:
    return OperationStore(
        tmp_path / "operations",
        worker_signing_key="worker-signing-key",
        receipt_signing_key="receipt-signing-key",
    )


def test_capacity_override_is_signed_scoped_expiring_and_cancellable(
    operation_store: OperationStore,
) -> None:
    now = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    directive = operation_store.create_capacity_override(
        worker_name="srv1879763-light-primary",
        repository="belilovsky/qazshield",
        head_sha="a" * 40,
        profiles=("qdev-ci", "qdev-ci-docker", "qdev-ci"),
        min_disk_free_gib=HARD_MIN_FREE_GIB,
        max_disk_used_pct=HARD_MAX_DISK_USED_PCT,
        owner="qdev-fleet-operations",
        reason="bounded capacity recovery for existing FIFO jobs",
        duration_seconds=600,
        now=now,
    )

    assert directive.profiles == ("qdev-ci", "qdev-ci-docker")
    assert directive.head_sha == "a" * 40
    assert (
        operation_store.active(
            "srv1879763-light-primary",
            registered_profiles=("qdev-ci", "qdev-ci-docker", "qdev-ci-browser"),
            now=now + timedelta(minutes=1),
        )
        == directive
    )
    assert (
        operation_store.active(
            "srv1879763-light-primary",
            registered_profiles=("qdev-ci", "qdev-ci-docker", "qdev-ci-browser"),
            now=now + timedelta(minutes=11),
        )
        is None
    )

    cancelled = operation_store.cancel_capacity_override(
        "srv1879763-light-primary",
        expected_operation_id=directive.operation_id,
        registered_profiles=("qdev-ci", "qdev-ci-docker", "qdev-ci-browser"),
        now=now + timedelta(minutes=2),
    )
    assert cancelled.status == "cancelled"
    assert (
        operation_store.active(
            "srv1879763-light-primary",
            registered_profiles=("qdev-ci", "qdev-ci-docker", "qdev-ci-browser"),
            now=now + timedelta(minutes=3),
        )
        is None
    )


def test_capacity_override_cancel_is_compare_and_swap(
    operation_store: OperationStore,
) -> None:
    now = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    directive = operation_store.create_capacity_override(
        worker_name="srv1879763-light-primary",
        repository="belilovsky/qazshield",
        head_sha="a" * 40,
        profiles=("qdev-ci",),
        min_disk_free_gib=HARD_MIN_FREE_GIB,
        max_disk_used_pct=HARD_MAX_DISK_USED_PCT,
        owner="qdev-fleet-operations",
        reason="compare-and-swap regression",
        duration_seconds=600,
        now=now,
    )

    with pytest.raises(CapacityOverrideConflict, match="operation changed"):
        operation_store.cancel_capacity_override(
            "srv1879763-light-primary",
            expected_operation_id="foreign-operation",
            registered_profiles=("qdev-ci", "qdev-ci-docker"),
            now=now + timedelta(minutes=1),
        )

    assert (
        operation_store.active(
            "srv1879763-light-primary",
            registered_profiles=("qdev-ci", "qdev-ci-docker"),
            now=now + timedelta(minutes=1),
        )
        == directive
    )


def test_concurrent_capacity_override_create_has_one_winner(
    operation_store: OperationStore,
) -> None:
    now = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    barrier = threading.Barrier(2)

    def create(repository: str) -> str:
        barrier.wait(timeout=5)
        try:
            directive = operation_store.create_capacity_override(
                worker_name="srv1879763-light-primary",
                repository=repository,
                head_sha="a" * 40,
                profiles=("qdev-ci",),
                min_disk_free_gib=HARD_MIN_FREE_GIB,
                max_disk_used_pct=HARD_MAX_DISK_USED_PCT,
                owner="qdev-fleet-operations",
                reason="concurrent create regression",
                duration_seconds=600,
                registered_profiles=("qdev-ci", "qdev-ci-docker"),
                now=now,
            )
        except CapacityOverrideConflict:
            return "conflict"
        return directive.repository

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(
            executor.map(
                create,
                ("belilovsky/qazshield", "belilovsky/qazgeo"),
            )
        )

    assert results.count("conflict") == 1
    winner = next(result for result in results if result != "conflict")
    active = operation_store.active(
        "srv1879763-light-primary",
        registered_profiles=("qdev-ci", "qdev-ci-docker"),
        now=now + timedelta(seconds=1),
    )
    assert active is not None
    assert active.repository == winner


def test_capacity_override_rejects_tamper_profile_mismatch_and_expiry(
    operation_store: OperationStore,
) -> None:
    now = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    directive = operation_store.create_capacity_override(
        worker_name="srv1879763-light-primary",
        repository="belilovsky/qazshield",
        head_sha="a" * 40,
        profiles=("qdev-ci-docker",),
        min_disk_free_gib=HARD_MIN_FREE_GIB,
        max_disk_used_pct=HARD_MAX_DISK_USED_PCT,
        owner="qdev-fleet-operations",
        reason="one bounded recovery",
        duration_seconds=60,
        now=now,
    )
    payload = directive.model_dump(mode="json", by_alias=True)

    with pytest.raises(ValueError, match="signature"):
        verify_capacity_override(
            payload | {"reason": "tampered"},
            signing_key="worker-signing-key",
            worker_name="srv1879763-light-primary",
            registered_profiles=("qdev-ci-docker",),
            now=now,
        )
    with pytest.raises(ValueError, match="profile mismatch"):
        verify_capacity_override(
            payload,
            signing_key="worker-signing-key",
            worker_name="srv1879763-light-primary",
            registered_profiles=("qdev-ci",),
            now=now,
        )
    with pytest.raises(ValueError, match="expired"):
        verify_capacity_override(
            payload,
            signing_key="worker-signing-key",
            worker_name="srv1879763-light-primary",
            registered_profiles=("qdev-ci-docker",),
            now=now + timedelta(seconds=61),
        )


def test_controller_receipt_is_deterministic_and_tamper_evident(
    operation_store: OperationStore, tmp_path: Path
) -> None:
    payload = {
        "kind": "worker-audit",
        "observed_at": "2026-08-31T08:00:00Z",
        "workers": [],
        "pending": 0,
    }
    first = operation_store.receipt(payload)
    second = operation_store.receipt(payload)
    assert first == second
    assert verify_controller_receipt(first, receipt_key="receipt-signing-key") == first

    path = tmp_path / "receipt.json"
    path.write_text(json.dumps(first), encoding="utf-8")
    assert validate_receipt_file(path, receipt_key="receipt-signing-key") == first
    with pytest.raises(ValueError, match="digest"):
        verify_controller_receipt(
            first | {"payload": payload | {"pending": 1}},
            receipt_key="receipt-signing-key",
        )


def test_controller_receipt_v1_is_legacy_unverified_and_v2_rejects_unknown_payload(
    operation_store: OperationStore,
) -> None:
    payload = {
        "kind": "worker-audit",
        "observed_at": "2026-08-31T08:00:00Z",
        "workers": [],
        "pending": 0,
    }
    with pytest.raises(ValueError, match="fields"):
        operation_store.receipt(payload | {"unexpected": True})

    digest = payload_digest(payload)
    legacy_unsigned = {
        "schema": "qdev-controller-receipt-v1",
        "receipt_id": digest,
        "payload": payload,
        "digest": digest,
    }
    legacy = legacy_unsigned | {"signature": sign_payload(legacy_unsigned, "receipt-signing-key")}
    with pytest.raises(ValueError, match="legacy_unverified"):
        verify_controller_receipt(legacy, receipt_key="receipt-signing-key")
    assert (
        verify_controller_receipt(legacy, receipt_key="receipt-signing-key", allow_legacy=True)
        == legacy
    )


def test_capacity_override_receipt_requires_full_immutable_fifo_tuple() -> None:
    payload = {
        "kind": "capacity-override-created",
        "observed_at": "2026-08-31T08:00:00Z",
        "worker_audit": {},
        "operation": {},
        "required_free_gib": 8.0,
        "immutable_tuple": {
            "repository": "belilovsky/qazshield",
            "run_id": 84_000_000_042,
            "job_id": 42,
            "attempt": 1,
            "exact_sha": "a" * 40,
            "profile": "qdev-ci-docker",
            "state": "pending",
            "created_at": 1_777_777_777.0,
        },
    }
    assert validate_controller_receipt_payload(payload) == payload

    with pytest.raises(ValueError, match="durable queue head"):
        validate_controller_receipt_payload(
            payload | {"immutable_tuple": payload["immutable_tuple"] | {"attempt": None}}
        )


def test_fifo_receipt_rejects_unclassified_skip_rows() -> None:
    payload = {
        "kind": "fifo-claim-scope-issued",
        "operator_session": "verified",
        "mtls_identity": "qdev-fleet-operations",
        "idempotent": False,
        "replaced_expired_scope": False,
        "rolled_over_terminal_scope": False,
        "rebound_legacy_scope": False,
        "claim_scope": {},
        "immutable_tuple": {},
        "fifo_skipped": [
            {
                "job_id": 41,
                "repository": "belilovsky/qazposter",
                "run_id": 84000000041,
                "head_sha": "a" * 40,
                "profile": "qdev-ci-docker",
                "managed_registry_entry": "qazposter",
                "reason": "manual-bypass",
            }
        ],
        "managed_registry_entry": None,
        "admission_ledger": None,
        "admin_platform_ledger_entry": None,
        "managed_release_ledger_entry": None,
        "worker": {},
    }
    with pytest.raises(ValueError, match="fifo skip item"):
        validate_controller_receipt_payload(payload)


def test_fifo_receipt_rejects_unhashable_skip_reason() -> None:
    payload = {
        "kind": "fifo-claim-scope-issued",
        "operator_session": "verified",
        "mtls_identity": "qdev-fleet-operations",
        "idempotent": False,
        "replaced_expired_scope": False,
        "rolled_over_terminal_scope": False,
        "rebound_legacy_scope": False,
        "claim_scope": {},
        "immutable_tuple": {},
        "fifo_skipped": [
            {
                "job_id": 41,
                "repository": "belilovsky/qazposter",
                "run_id": 84000000041,
                "head_sha": "a" * 40,
                "profile": "qdev-ci-docker",
                "managed_registry_entry": "qazposter",
                "reason": [],
            }
        ],
        "managed_registry_entry": None,
        "admission_ledger": None,
        "admin_platform_ledger_entry": None,
        "managed_release_ledger_entry": None,
        "worker": {},
    }
    with pytest.raises(ValueError, match="fifo skip item"):
        validate_controller_receipt_payload(payload)


def test_operation_store_requires_keys_and_enforces_hard_floor(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="signing keys"):
        OperationStore(tmp_path / "empty", worker_signing_key="", receipt_signing_key="x")
    store = OperationStore(
        tmp_path / "operations",
        worker_signing_key="worker-signing-key",
        receipt_signing_key="receipt-signing-key",
    )
    with pytest.raises(ValueError, match="hard floor"):
        store.create_capacity_override(
            worker_name="worker-primary",
            repository="belilovsky/qazshield",
            head_sha="a" * 40,
            profiles=("qdev-ci",),
            min_disk_free_gib=HARD_MIN_FREE_GIB - 0.1,
            max_disk_used_pct=HARD_MAX_DISK_USED_PCT,
            owner="owner",
            reason="reason",
            duration_seconds=60,
        )
    with pytest.raises(ValueError, match="hard ceiling"):
        store.create_capacity_override(
            worker_name="worker-primary",
            repository="belilovsky/qazgeo",
            head_sha="a" * 40,
            profiles=("qdev-ci-docker",),
            min_disk_free_gib=HARD_MIN_FREE_GIB,
            max_disk_used_pct=HARD_MAX_DISK_USED_PCT + 0.1,
            owner="owner",
            reason="reason",
            duration_seconds=60,
        )
