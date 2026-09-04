from __future__ import annotations

import importlib.util
import json
import sqlite3
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
OLD_SHA, NEW_SHA = "1" * 40, "2" * 40
OLD_DIGEST, NEW_DIGEST = "3" * 64, "4" * 64
OLD_IMAGE, NEW_IMAGE, FOREIGN_IMAGE = ("sha256:" + char * 64 for char in "567")


@pytest.fixture
def native(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> ModuleType:
    monkeypatch.setattr(sys, "dont_write_bytecode", True)
    for name in ("controller_release_guard", "release_controller_exact"):
        spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name + ".py"))
        assert spec and spec.loader
        module = importlib.util.module_from_spec(spec)
        monkeypatch.setitem(sys.modules, name, module)
        spec.loader.exec_module(module)
    for name, value in {
        "ROOT": tmp_path / "native",
        "CONFIG": tmp_path / "config",
        "STATUS": tmp_path / "config/controller-release.json",
        "TRANSACTIONS": tmp_path / "transactions",
        "DATABASE": tmp_path / "broker.db",
    }.items():
        monkeypatch.setattr(module, name, value)
    module.CONFIG.mkdir()
    (module.ROOT / "releases/old").mkdir(parents=True)
    (module.ROOT / "releases/new").mkdir()
    (module.ROOT / "current").symlink_to(module.ROOT / "releases/old")
    return module


def binding(native: ModuleType) -> dict[str, str]:
    return {
        "release": str(native.ROOT / "releases/new"),
        "revision": NEW_SHA,
        "digest": NEW_DIGEST,
        "expected_revision": OLD_SHA,
        "expected_digest": OLD_DIGEST,
    }


def status(native: ModuleType, *, new: bool = False) -> None:
    native.atomic_json(
        native.STATUS,
        {
            "state": "active",
            "revision": NEW_SHA if new else OLD_SHA,
            "release_digest": NEW_DIGEST if new else OLD_DIGEST,
        },
    )


def test_idempotency_key_cannot_change_source(native: ModuleType, tmp_path: Path) -> None:
    first = native.load_transaction(tmp_path, binding(native))
    assert first == native.load_transaction(tmp_path, binding(native))
    assert first["phase"] == "prepared"
    assert (tmp_path / "transaction.json").stat().st_mode & 0o777 == 0o600
    with pytest.raises(ValueError, match="idempotency"):
        native.load_transaction(tmp_path, binding(native) | {"revision": OLD_SHA})


@pytest.mark.parametrize("state", ["completed", "activating", "verifying"])
def test_resume_completed_activation_never_redeploys(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    state: str,
) -> None:
    record = {"binding": binding(native), "phase": state, "candidate_image": NEW_IMAGE}
    accepted: list[Any] = []
    monkeypatch.setattr(native, "accept", lambda *_: accepted.append(True))
    monkeypatch.setattr(native, "current_matches", lambda *_: True)
    monkeypatch.setattr(native, "images", lambda: dict.fromkeys(native.SERVICES, NEW_IMAGE))
    monkeypatch.setattr(native, "run", lambda *_a, **_k: pytest.fail("must not redeploy"))
    assert native.reconcile(tmp_path, record) is True
    assert accepted == [True]


def test_partial_activation_rolls_back_once(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    record = {"binding": binding(native), "phase": "activating", "candidate_image": NEW_IMAGE}
    restored: list[Any] = []
    monkeypatch.setattr(native, "current_matches", lambda *_: True)
    monkeypatch.setattr(
        native, "images", lambda: {"broker-public": NEW_IMAGE, "broker-internal": OLD_IMAGE}
    )
    monkeypatch.setattr(native, "restore", lambda *_: restored.append(True))
    monkeypatch.setattr(native, "accept", lambda *_: pytest.fail("partial runtime cannot pass"))
    with pytest.raises(ValueError, match="interrupted activation restored"):
        native.reconcile(tmp_path, record)
    assert restored == [True]


@pytest.mark.parametrize("state", ["rolled-back", "unknown"])
def test_terminal_or_unknown_transaction_never_deploys(
    native: ModuleType, tmp_path: Path, state: str
) -> None:
    with pytest.raises(ValueError):
        native.reconcile(tmp_path, {"phase": state})


@pytest.mark.parametrize("mutation", ["foreign-image", "foreign-revision"])
def test_rollback_refuses_parallel_runtime_changes(native: ModuleType, mutation: str) -> None:
    status(native)
    record = {
        "binding": binding(native),
        "previous_images": dict.fromkeys(native.SERVICES, OLD_IMAGE),
        "candidate_image": NEW_IMAGE,
    }
    actual = dict.fromkeys(native.SERVICES, NEW_IMAGE)
    assert native.rollback_permitted(record, actual)
    if mutation == "foreign-image":
        actual["broker-internal"] = FOREIGN_IMAGE
    else:
        native.atomic_json(
            native.STATUS, {"state": "active", "revision": "a" * 40, "release_digest": OLD_DIGEST}
        )
    assert not native.rollback_permitted(record, actual)


def test_configuration_change_rejects_activation_and_rollback(native: ModuleType) -> None:
    record = {
        "binding": binding(native),
        "previous_configuration": dict.fromkeys(native.CONFIG_FILES),
    }
    native.verify_configuration(record, previous_only=True)
    (native.CONFIG / "profiles.yml").write_text("foreign change\n")
    with pytest.raises(ValueError, match="foreign configuration"):
        native.verify_configuration(record, previous_only=True)
    with pytest.raises(ValueError, match="foreign configuration"):
        native.verify_configuration(record)


def test_snapshot_and_rollback_preserve_actual_image_ids_without_repeated_recreate(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    directory = tmp_path / "release-transaction"
    directory.mkdir()
    status(native)
    (native.CONFIG / "profiles.yml").write_text("old profile\n")
    image_state = dict.fromkeys(native.SERVICES, OLD_IMAGE)
    commands: list[list[str]] = []

    def run(command: list[str], **_kwargs: Any) -> str:
        commands.append(command)
        if command[:2] == ["docker", "compose"]:
            image_state.update(dict.fromkeys(native.SERVICES, OLD_IMAGE))
        return ""

    monkeypatch.setattr(native, "run", run)
    monkeypatch.setattr(native, "images", lambda: dict(image_state))
    monkeypatch.setattr(native, "signed_audits", lambda *_a, **_kw: {})
    record = native.load_transaction(directory, binding(native))
    native.snapshot(directory, record)
    assert record["previous_images"] == dict.fromkeys(native.SERVICES, OLD_IMAGE)
    assert (
        json.loads((directory / "rollback-compose.json").read_text())["services"]["broker-public"][
            "image"
        ]
        == OLD_IMAGE
    )
    record["candidate_image"] = NEW_IMAGE
    image_state.update(dict.fromkeys(native.SERVICES, NEW_IMAGE))
    status(native, new=True)
    native.phase(directory, record, "verifying")
    native.restore(directory, record)
    assert record["phase"] == "rolled-back"
    assert (native.CONFIG / "profiles.yml").read_text() == "old profile\n"
    recreates = [command for command in commands if "--force-recreate" in command]
    assert len(recreates) == 1 and "--no-build" in recreates[0]
    native.restore(directory, record)
    assert len([command for command in commands if "--force-recreate" in command]) == 1
    assert (directory / "configuration/controller-release.json").exists()


@pytest.mark.parametrize("mutation", ["stale", "future", "unenforced", "legacy", "no-timezone"])
def test_signed_audit_rejects_invalid_envelope(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    mutation: str,
) -> None:
    now = datetime.now(UTC)
    when = now - timedelta(seconds=300) if mutation == "stale" else now
    if mutation == "future":
        when = now + timedelta(seconds=300)
    observed = (
        when.replace(tzinfo=None).isoformat() if mutation == "no-timezone" else when.isoformat()
    )
    receipt = {
        "schema": "legacy" if mutation == "legacy" else "qdev-controller-receipt-v2",
        "enforcement": "unenforced" if mutation == "unenforced" else "enforced",
        "payload": {"observed_at": observed},
    }
    monkeypatch.setattr(native, "run", lambda *_a, **_kw: json.dumps(receipt))
    with pytest.raises(ValueError):
        native.signed_audits(tmp_path)


def test_source_runtime_audit_mismatch_cannot_complete(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    record = {"binding": binding(native), "candidate_image": NEW_IMAGE, "phase": "verifying"}
    status(native, new=True)
    (native.ROOT / "current").unlink()
    (native.ROOT / "current").symlink_to(native.ROOT / "releases/new")
    monkeypatch.setattr(native, "verify_artifact", lambda *_: NEW_DIGEST)
    monkeypatch.setattr(native, "images", lambda: dict.fromkeys(native.SERVICES, NEW_IMAGE))
    monkeypatch.setattr(
        native,
        "signed_audits",
        lambda *_: {"release-audit": {"payload": {"controller_release": {"revision": OLD_SHA}}}},
    )
    with pytest.raises(ValueError, match="signed release audit"):
        native.accept(tmp_path, record)
    assert record["phase"] == "verifying"


@pytest.mark.parametrize("destructive", [False, True])
def test_migration_preflight_uses_only_copy_and_checks_original_rows(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    destructive: bool,
) -> None:
    with sqlite3.connect(native.DATABASE) as connection:
        connection.execute("CREATE TABLE jobs (id INTEGER PRIMARY KEY, status TEXT)")
        connection.execute("INSERT INTO jobs VALUES (1, 'running')")
    commands: list[list[str]] = []

    def run(command: list[str], **_kwargs: Any) -> str:
        commands.append(command)
        assert "--read-only" in command and command[command.index("--network") + 1] == "none"
        assert str(native.DATABASE) not in command
        copy = tmp_path / "migration/migration.sqlite3"
        with sqlite3.connect(copy) as connection:
            if len(commands) == 1:
                connection.execute("ALTER TABLE jobs ADD COLUMN claim_scope_id TEXT")
                if destructive:
                    connection.execute("UPDATE jobs SET status='pending'")
        return "migration_compatibility_ok"

    monkeypatch.setattr(native, "run", run)
    if destructive:
        with pytest.raises(ValueError, match="queue data"):
            native.migration_preflight(tmp_path, NEW_IMAGE, OLD_IMAGE)
    else:
        native.migration_preflight(tmp_path, NEW_IMAGE, OLD_IMAGE)
        assert len(commands) == 2
        assert OLD_IMAGE in commands[1]
    with sqlite3.connect(native.DATABASE) as connection:
        assert connection.execute("SELECT * FROM jobs").fetchall() == [(1, "running")]
        assert len(connection.execute("PRAGMA table_info(jobs)").fetchall()) == 2


def test_release_stops_before_build_when_current_revision_changed(
    native: ModuleType,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    status(native, new=True)
    monkeypatch.setattr(native, "verify_artifact", lambda *_: NEW_DIGEST)
    monkeypatch.setattr(
        native, "run", lambda *_a, **_kw: pytest.fail("no build or mutation permitted")
    )
    with pytest.raises(ValueError, match="runtime changed"):
        native.execute(tmp_path, {"binding": binding(native), "phase": "prepared"})
