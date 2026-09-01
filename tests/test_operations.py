from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qdev_runner.operations import (
    HARD_MAX_DISK_USED_PCT,
    HARD_MIN_FREE_GIB,
    OperationStore,
    payload_digest,
    sign_payload,
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
        profiles=("qdev-ci", "qdev-ci-docker", "qdev-ci"),
        min_disk_free_gib=HARD_MIN_FREE_GIB,
        max_disk_used_pct=HARD_MAX_DISK_USED_PCT,
        owner="qdev-fleet-operations",
        reason="bounded capacity recovery for existing FIFO jobs",
        duration_seconds=600,
        now=now,
    )

    assert directive.profiles == ("qdev-ci", "qdev-ci-docker")
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
        registered_profiles=("qdev-ci", "qdev-ci-docker", "qdev-ci-browser"),
        now=now + timedelta(minutes=2),
    )
    assert cancelled is not None
    assert cancelled.status == "cancelled"
    assert (
        operation_store.active(
            "srv1879763-light-primary",
            registered_profiles=("qdev-ci", "qdev-ci-docker", "qdev-ci-browser"),
            now=now + timedelta(minutes=3),
        )
        is None
    )


def test_capacity_override_rejects_tamper_profile_mismatch_and_expiry(
    operation_store: OperationStore,
) -> None:
    now = datetime(2026, 8, 31, 8, 0, tzinfo=UTC)
    directive = operation_store.create_capacity_override(
        worker_name="srv1879763-light-primary",
        repository="belilovsky/qazshield",
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
    legacy = legacy_unsigned | {
        "signature": sign_payload(legacy_unsigned, "receipt-signing-key")
    }
    with pytest.raises(ValueError, match="legacy_unverified"):
        verify_controller_receipt(legacy, receipt_key="receipt-signing-key")
    assert (
        verify_controller_receipt(
            legacy, receipt_key="receipt-signing-key", allow_legacy=True
        )
        == legacy
    )


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
            profiles=("qdev-ci",),
            min_disk_free_gib=HARD_MIN_FREE_GIB - 0.1,
            max_disk_used_pct=HARD_MAX_DISK_USED_PCT,
            owner="owner",
            reason="reason",
            duration_seconds=60,
        )
