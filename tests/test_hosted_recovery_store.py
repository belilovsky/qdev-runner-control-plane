from __future__ import annotations

from pathlib import Path

import pytest

from qdev_runner.store import Store


def _create_subject(store: Store, **overrides: object) -> dict[str, object]:
    values: dict[str, object] = {
        "job_id": 981,
        "repository": "belilovsky/qdev-runner-control-plane",
        "repository_id": 44,
        "installation_id": 55,
        "source_sha": "a" * 40,
        "run_id": 982,
        "attempt": 1,
        "head_branch": "main",
        "job_name": "controller-recovery-build",
        "labels": ("ubuntu-latest",),
        "delivery_id": "delivery-00000001",
    }
    values.update(overrides)
    return store.create_hosted_recovery_subject(**values)  # type: ignore[arg-type]


def _store_subject(
    store: Store,
    *,
    job_id: int = 981,
    now: float = 100.0,
) -> tuple[dict[str, object], dict[str, object]]:
    lease = store.begin_hosted_recovery_upload(job_id, 30, now=now)
    assert lease is not None
    stored = store.finalize_hosted_recovery_upload(
        job_id,
        str(lease["upload_lease_id"]),
        int(lease["upload_fence"]),
        "b" * 64,
        "c" * 64,
        4096,
        str(lease["archive_storage_key"]),
        "sha256:" + "d" * 64,
        now=now + 1,
    )
    assert stored is not None
    return lease, stored


def test_hosted_recovery_subject_is_immutable_and_isolated(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")

    created = _create_subject(store)
    replay = _create_subject(store, delivery_id="delivery-00000002")

    assert created["state"] == "pending"
    assert replay["subject_id"] == created["subject_id"]
    assert replay["delivery_id"] == "delivery-00000001"
    assert created["archive_storage_key"] == "hosted-controller-recovery:981"
    assert created["labels"] == ["ubuntu-latest"]
    assert store.job(981) is None

    with store.connect() as connection:
        columns = {
            str(row["name"])
            for row in connection.execute("PRAGMA table_info(hosted_recovery_subjects)").fetchall()
        }
        foreign_keys = connection.execute(
            "PRAGMA foreign_key_list(hosted_recovery_subjects)"
        ).fetchall()
    assert "path" not in columns
    assert "url" not in columns
    assert foreign_keys == []

    with pytest.raises(ValueError, match="immutable"):
        _create_subject(store, source_sha="e" * 40)
    with pytest.raises(ValueError, match="static workflow"):
        _create_subject(store, job_id=982, labels=("self-hosted",))


def test_hosted_recovery_upload_uses_a_fenced_store_derived_key(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    _create_subject(store)

    first_lease = store.begin_hosted_recovery_upload(981, 5, now=100)
    assert first_lease is not None
    assert store.begin_hosted_recovery_upload(981, 5, now=101) is None

    reclaimed_lease = store.begin_hosted_recovery_upload(981, 5, now=105)
    assert reclaimed_lease is not None
    assert reclaimed_lease["upload_lease_id"] != first_lease["upload_lease_id"]
    assert reclaimed_lease["upload_fence"] == first_lease["upload_fence"] + 1

    assert (
        store.finalize_hosted_recovery_upload(
            981,
            str(first_lease["upload_lease_id"]),
            int(first_lease["upload_fence"]),
            "b" * 64,
            "c" * 64,
            4096,
            str(first_lease["archive_storage_key"]),
            "d" * 64,
            now=105.5,
        )
        is None
    )
    assert (
        store.abort_hosted_recovery_upload(
            981,
            str(first_lease["upload_lease_id"]),
            int(first_lease["upload_fence"]),
            now=105.5,
        )
        is None
    )
    with pytest.raises(ValueError, match="Store-derived"):
        store.finalize_hosted_recovery_upload(
            981,
            str(reclaimed_lease["upload_lease_id"]),
            int(reclaimed_lease["upload_fence"]),
            "b" * 64,
            "c" * 64,
            4096,
            "caller-selected-location",
            "d" * 64,
            now=105.5,
        )

    stored = store.finalize_hosted_recovery_upload(
        981,
        str(reclaimed_lease["upload_lease_id"]),
        int(reclaimed_lease["upload_fence"]),
        "b" * 64,
        "c" * 64,
        4096,
        str(reclaimed_lease["archive_storage_key"]),
        "sha256:" + "d" * 64,
        now=105.5,
    )
    assert stored is not None
    assert stored["state"] == "stored"
    assert stored["archive_sha256"] == "c" * 64
    assert store.hosted_recovery_subject(receipt_id="b" * 64) == stored

    replay = store.finalize_hosted_recovery_upload(
        981,
        str(reclaimed_lease["upload_lease_id"]),
        int(reclaimed_lease["upload_fence"]),
        "b" * 64,
        "c" * 64,
        4096,
        str(reclaimed_lease["archive_storage_key"]),
        "sha256:" + "d" * 64,
        now=106,
    )
    assert replay == stored


def test_hosted_recovery_verification_requires_successful_provider_completion(
    tmp_path: Path,
) -> None:
    store = Store(tmp_path / "broker.db")
    _create_subject(store)
    _, stored = _store_subject(store)

    assert store.mark_hosted_recovery_verified("b" * 64, "e" * 64, verified_at=120) is None
    completed = store.complete_hosted_recovery_subject(981, "success", completed_at=121)
    assert completed is not None
    assert completed["provider_conclusion"] == "success"
    assert store.complete_hosted_recovery_subject(981, "success", completed_at=122) == completed

    verified = store.mark_hosted_recovery_verified("b" * 64, "e" * 64, verified_at=123)
    assert verified is not None
    assert verified["state"] == "verified"
    assert verified["verification_digest"] == "e" * 64
    assert store.mark_hosted_recovery_verified("b" * 64, "e" * 64, verified_at=124) == verified
    with pytest.raises(ValueError, match="immutable"):
        store.mark_hosted_recovery_verified("b" * 64, "f" * 64, verified_at=125)
    with pytest.raises(ValueError, match="immutable"):
        store.complete_hosted_recovery_subject(981, "failure", completed_at=126)
    assert stored["state"] == "stored"


def test_failed_provider_conclusion_fences_an_active_upload(tmp_path: Path) -> None:
    store = Store(tmp_path / "broker.db")
    _create_subject(store)
    lease = store.begin_hosted_recovery_upload(981, 30, now=100)
    assert lease is not None

    failed = store.complete_hosted_recovery_subject(981, "failure", completed_at=101)
    assert failed is not None
    assert failed["state"] == "pending"
    assert failed["upload_fence"] == lease["upload_fence"] + 1
    assert store.begin_hosted_recovery_upload(981, 30, now=102) is None
    assert (
        store.finalize_hosted_recovery_upload(
            981,
            str(lease["upload_lease_id"]),
            int(lease["upload_fence"]),
            "b" * 64,
            "c" * 64,
            4096,
            str(lease["archive_storage_key"]),
            "d" * 64,
            now=102,
        )
        is None
    )


def test_hosted_recovery_subject_table_is_added_to_existing_database(tmp_path: Path) -> None:
    database = tmp_path / "broker.db"
    store = Store(database)
    with store.connect() as connection:
        connection.execute("DROP TABLE hosted_recovery_subjects")

    migrated = Store(database)
    with migrated.connect() as connection:
        row = connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='hosted_recovery_subjects'"
        ).fetchone()
    assert row is not None
