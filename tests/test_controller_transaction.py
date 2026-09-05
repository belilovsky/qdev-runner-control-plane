from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Any, cast

import pytest

from qdev_runner import controller_transaction as transaction

REVISION_OLD = "1" * 40
REVISION_NEW = "2" * 40
DIGEST_OLD = "3" * 64
DIGEST_NEW = "4" * 64
ARTIFACT_NEW = "sha256:" + "7" * 64
ARTIFACT_OLD = "sha256:" + "8" * 64
IMAGE_REF_NEW = "registry.ci.qdev.run/qdev-runner-control-plane@" + ARTIFACT_NEW
IMAGE_PUBLIC = "sha256:" + "5" * 64
IMAGE_INTERNAL = "sha256:" + "6" * 64


def _write(path: Path, value: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(value)
    path.chmod(mode)


def _release(root: Path, name: str, *, native: bool) -> Path:
    release = root / name
    _write(release / "deploy/compose.yml", b"services: {}\n", 0o644)
    if native:
        _write(
            release / "scripts/activate_controller_release_native.sh",
            b"#!/usr/bin/env bash\nexit 0\n",
            0o755,
        )
    return release


def _fixture(tmp_path: Path) -> tuple[transaction.Paths, Path, Path]:
    releases = tmp_path / "releases"
    releases.mkdir(mode=0o755)
    previous = _release(releases, REVISION_OLD, native=False)
    candidate = _release(releases, REVISION_NEW, native=True)
    current = tmp_path / "current"
    current.symlink_to(previous)
    config = tmp_path / "config"
    config.mkdir(mode=0o700)
    for index, name in enumerate(transaction._CONFIGS):
        _write(config / name, f"old-{index}".encode())
    status = {
        "schema": "qdev-controller-release-status-v1",
        "state": "active",
        "revision": REVISION_OLD,
        "artifact_digest": ARTIFACT_OLD,
        "release_digest": DIGEST_OLD,
    }
    _write(config / "controller-release.json", json.dumps(status).encode())
    identity = config / "mtls/operator"
    identity.mkdir(parents=True, mode=0o750)
    for name in ("ca.pem", "operator-cert.pem", "operator-key.pem"):
        _write(identity / name, b"opaque", 0o640)
    state = tmp_path / "state"
    return transaction.Paths(releases, current, config, state, os.getuid()), previous, candidate


def _old_images() -> dict[str, dict[str, str]]:
    return {
        "broker-public": {"id": IMAGE_PUBLIC, "reference": "controller-public:old"},
        "broker-internal": {"id": IMAGE_INTERNAL, "reference": "controller-internal:old"},
    }


def test_prepare_and_rollback_restore_exact_previous_tuple(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, previous, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_inspect", lambda argv: {"Id": argv[-1]})
    monkeypatch.setattr(transaction, "_run", lambda argv, **kwargs: "")
    original = {name: (paths.config / name).read_bytes() for name in transaction._CONFIGS}

    operation = transaction.prepare(paths, candidate)
    assert operation["previous"] == str(previous)
    assert operation["previous_status"]["revision"] == REVISION_OLD
    assert operation["images"]["broker-public"]["id"] == IMAGE_PUBLIC

    paths.current.unlink()
    paths.current.symlink_to(candidate)
    for name in transaction._CONFIGS:
        _write(paths.config / name, b"candidate")

    transaction.rollback(paths, operation)

    assert paths.current.resolve() == previous
    for name in transaction._CONFIGS:
        assert (paths.config / name).read_bytes() == original[name]
    result = json.loads((paths.state / "current.json").read_text())
    assert result["phase"] == "rolled_back"
    assert (paths.state / operation["id"] / "snapshot.json").is_file()


def test_rollback_retries_health_without_accepting_candidate_requirements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    calls: list[dict[str, Any]] = []

    def health(expected: dict[str, Any]) -> None:
        calls.append(expected)
        if len(calls) == 2:
            raise transaction.TransactionError("starting")

    monkeypatch.setattr(transaction, "_health", health)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_inspect", lambda argv: {"Id": argv[-1]})
    monkeypatch.setattr(transaction, "_run", lambda argv, **kwargs: "")
    monkeypatch.setattr(time, "sleep", lambda seconds: None)

    operation = transaction.prepare(paths, candidate)
    transaction.rollback(paths, operation)

    assert calls[-1]["revision"] == REVISION_OLD
    assert calls[-1]["release_digest"] == DIGEST_OLD
    assert len(calls) == 3


def test_activate_failure_recovers_and_retains_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, previous, candidate = _fixture(tmp_path)
    runtime = {"images": _old_images(), "fail_native": True}
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", lambda: runtime["images"])
    monkeypatch.setattr(transaction, "_inspect", lambda argv: {"Id": argv[-1]})
    monkeypatch.setattr(transaction, "verify_bundle", lambda *args, **kwargs: {})

    native_env: dict[str, str] = {}

    def run(argv: list[str], **kwargs: object) -> str:
        if argv[0].endswith("activate_controller_release_native.sh"):
            native_env.update(cast(dict[str, str], kwargs["env"]))
            paths.current.unlink()
            paths.current.symlink_to(candidate)
            _write(paths.config / "profiles.yml", b"candidate")
            raise transaction.TransactionError("candidate failed")
        return ""

    monkeypatch.setattr(transaction, "_run", run)
    with pytest.raises(transaction.TransactionError):
        transaction.activate(
            paths,
            candidate,
            expected_revision=REVISION_NEW,
            expected_artifact_digest=ARTIFACT_NEW,
            expected_release_digest=DIGEST_NEW,
            expected_previous_revision=REVISION_OLD,
            expected_previous_artifact_digest=ARTIFACT_OLD,
            candidate_image_ref=IMAGE_REF_NEW,
        )

    assert paths.current.resolve() == previous
    assert (paths.config / "profiles.yml").read_bytes() == b"old-1"
    assert native_env["QDEV_CONTROLLER_NO_BUILD"] == "true"
    assert native_env["QDEV_CONTROLLER_BROKER_PUBLIC_IMAGE"] == IMAGE_REF_NEW
    assert native_env["QDEV_CONTROLLER_BROKER_INTERNAL_IMAGE"] == IMAGE_REF_NEW
    result = json.loads((paths.state / "current.json").read_text())
    assert result["phase"] == "rolled_back"
    assert (paths.state / result["id"] / "snapshot.json").is_file()


@pytest.mark.parametrize(
    "image_ref",
    [
        "registry.ci.qdev.run/qdev-runner-control-plane:latest",
        "registry.ci.qdev.run/other@" + ARTIFACT_NEW,
        "registry.ci.qdev.run/qdev-runner-control-plane@sha256:" + "8" * 64,
    ],
)
def test_activate_rejects_unbound_candidate_image_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, image_ref: str
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_inspect", lambda argv: {"Id": argv[-1]})
    monkeypatch.setattr(transaction, "_run", lambda argv, **kwargs: "")
    monkeypatch.setattr(transaction, "verify_bundle", lambda *args, **kwargs: {})

    with pytest.raises(transaction.TransactionError, match="release tuple"):
        transaction.activate(
            paths,
            candidate,
            expected_revision=REVISION_NEW,
            expected_artifact_digest=ARTIFACT_NEW,
            expected_release_digest=DIGEST_NEW,
            expected_previous_revision=REVISION_OLD,
            expected_previous_artifact_digest=ARTIFACT_OLD,
            candidate_image_ref=image_ref,
        )


def test_activate_compare_and_swap_rejects_stale_previous_tuple_before_prepare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "verify_bundle", lambda *args, **kwargs: {})
    prepared: list[Path] = []

    def prepare(paths_arg: transaction.Paths, candidate_arg: Path) -> dict[str, Any]:
        prepared.append(candidate_arg)
        raise AssertionError("stale activation must not prepare a rollback checkpoint")

    monkeypatch.setattr(transaction, "prepare", prepare)
    with pytest.raises(transaction.TransactionError, match="compare-and-swap"):
        transaction.activate(
            paths,
            candidate,
            expected_revision=REVISION_NEW,
            expected_artifact_digest=ARTIFACT_NEW,
            expected_release_digest=DIGEST_NEW,
            expected_previous_revision="9" * 40,
            expected_previous_artifact_digest=ARTIFACT_OLD,
            candidate_image_ref=IMAGE_REF_NEW,
        )

    assert prepared == []
    assert not (paths.state / "current.json").exists()


def test_activate_rejects_mismatched_release_digest_and_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, previous, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_inspect", lambda argv: {"Id": argv[-1]})
    monkeypatch.setattr(transaction, "verify_bundle", lambda *args, **kwargs: {})

    def run(argv: list[str], **kwargs: object) -> str:
        if argv[0].endswith("activate_controller_release_native.sh"):
            paths.current.unlink()
            paths.current.symlink_to(candidate)
            status = {
                "state": "active",
                "revision": REVISION_NEW,
                "artifact_digest": ARTIFACT_NEW,
                "release_digest": "9" * 64,
            }
            _write(paths.config / "controller-release.json", json.dumps(status).encode())
        return ""

    monkeypatch.setattr(transaction, "_run", run)
    with pytest.raises(transaction.TransactionError):
        transaction.activate(
            paths,
            candidate,
            expected_revision=REVISION_NEW,
            expected_artifact_digest=ARTIFACT_NEW,
            expected_release_digest=DIGEST_NEW,
            expected_previous_revision=REVISION_OLD,
            expected_previous_artifact_digest=ARTIFACT_OLD,
            candidate_image_ref=IMAGE_REF_NEW,
        )
    assert paths.current.resolve() == previous


def test_activate_accepts_only_the_exact_candidate_runtime_reference(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    runtime = {"images": _old_images()}
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", lambda: runtime["images"])
    monkeypatch.setattr(transaction, "_inspect", lambda argv: {"Id": argv[-1]})
    monkeypatch.setattr(transaction, "verify_bundle", lambda *args, **kwargs: {})

    def run(argv: list[str], **kwargs: object) -> str:
        if argv[0].endswith("activate_controller_release_native.sh"):
            paths.current.unlink()
            paths.current.symlink_to(candidate)
            status = {
                "state": "active",
                "revision": REVISION_NEW,
                "artifact_digest": ARTIFACT_NEW,
                "release_digest": DIGEST_NEW,
            }
            _write(paths.config / "controller-release.json", json.dumps(status).encode())
            runtime["images"] = {
                service: {"id": image["id"], "reference": IMAGE_REF_NEW}
                for service, image in _old_images().items()
            }
        return ""

    monkeypatch.setattr(transaction, "_run", run)
    result = transaction.activate(
        paths,
        candidate,
        expected_revision=REVISION_NEW,
        expected_artifact_digest=ARTIFACT_NEW,
        expected_release_digest=DIGEST_NEW,
        expected_previous_revision=REVISION_OLD,
        expected_previous_artifact_digest=ARTIFACT_OLD,
        candidate_image_ref=IMAGE_REF_NEW,
    )

    assert result["phase"] == "accepted"
    assert result["active_images"]["broker-public"]["reference"] == IMAGE_REF_NEW
    assert paths.current.resolve() == candidate
    assert json.loads((paths.state / "current.json").read_text())["phase"] == "accepted"


def test_activate_rolls_back_when_runtime_reference_is_not_exact(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, previous, candidate = _fixture(tmp_path)
    runtime = {"images": _old_images()}
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", lambda: runtime["images"])
    monkeypatch.setattr(transaction, "_inspect", lambda argv: {"Id": argv[-1]})
    monkeypatch.setattr(transaction, "verify_bundle", lambda *args, **kwargs: {})

    def run(argv: list[str], **kwargs: object) -> str:
        if argv[0].endswith("activate_controller_release_native.sh"):
            paths.current.unlink()
            paths.current.symlink_to(candidate)
            status = {
                "state": "active",
                "revision": REVISION_NEW,
                "artifact_digest": ARTIFACT_NEW,
                "release_digest": DIGEST_NEW,
            }
            _write(paths.config / "controller-release.json", json.dumps(status).encode())
            runtime["images"] = {
                service: {
                    "id": image["id"],
                    "reference": "registry.ci.qdev.run/qdev-runner-control-plane:mutable",
                }
                for service, image in _old_images().items()
            }
        return ""

    monkeypatch.setattr(transaction, "_run", run)

    with pytest.raises(transaction.TransactionError, match="exact immutable image"):
        transaction.activate(
            paths,
            candidate,
            expected_revision=REVISION_NEW,
            expected_artifact_digest=ARTIFACT_NEW,
            expected_release_digest=DIGEST_NEW,
            expected_previous_revision=REVISION_OLD,
            expected_previous_artifact_digest=ARTIFACT_OLD,
            candidate_image_ref=IMAGE_REF_NEW,
        )

    assert paths.current.resolve() == previous
    assert json.loads((paths.state / "current.json").read_text())["phase"] == "rolled_back"


def test_pending_operation_is_recovered_before_new_prepare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    paths.state.mkdir(mode=0o700)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_inspect", lambda argv: {"Id": argv[-1]})
    monkeypatch.setattr(transaction, "_run", lambda argv, **kwargs: "")
    monkeypatch.setattr(transaction, "verify_bundle", lambda *args, **kwargs: {})
    pending = transaction.prepare(paths, candidate)
    pending["phase"] = "applying"
    transaction._json(paths.state / "current.json", pending)
    recovered: list[str] = []
    real_rollback = transaction.rollback

    def rollback(paths_arg: transaction.Paths, operation: dict[str, Any]) -> None:
        recovered.append(operation["id"])
        real_rollback(paths_arg, operation)

    def stop_prepare(paths_arg: transaction.Paths, candidate_arg: Path) -> dict[str, Any]:
        raise transaction.TransactionError("stop")

    monkeypatch.setattr(transaction, "rollback", rollback)
    monkeypatch.setattr(transaction, "prepare", stop_prepare)
    with pytest.raises(transaction.TransactionError, match="stop"):
        transaction.activate(
            paths,
            candidate,
            expected_revision=REVISION_NEW,
            expected_artifact_digest=ARTIFACT_NEW,
            expected_release_digest=DIGEST_NEW,
            expected_previous_revision=REVISION_OLD,
            expected_previous_artifact_digest=ARTIFACT_OLD,
            candidate_image_ref=IMAGE_REF_NEW,
        )
    assert recovered == [pending["id"]]


def test_tampered_state_and_writable_candidate_are_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_run", lambda argv, **kwargs: "")
    operation = transaction.prepare(paths, candidate)
    operation["configs"]["../../outside"] = {"present": False}
    with pytest.raises(transaction.TransactionError, match="inventory"):
        transaction.rollback(paths, operation)

    candidate.chmod(0o777)
    with pytest.raises(transaction.TransactionError, match="permissions"):
        transaction.prepare(paths, candidate)


def test_snapshot_contains_only_metadata_not_identity_material(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_run", lambda argv, **kwargs: "")
    operation = transaction.prepare(paths, candidate)
    snapshot = (paths.state / operation["id"] / "snapshot.json").read_bytes()
    assert b"opaque" not in snapshot
    assert hashlib.sha256(snapshot).hexdigest()


def test_operator_rollback_accepts_only_current_accepted_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, previous, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_inspect", lambda argv: {"Id": argv[-1]})
    monkeypatch.setattr(transaction, "_run", lambda argv, **kwargs: "")
    operation = transaction.prepare(paths, candidate)
    accepted = {
        **operation,
        "phase": "accepted",
        "active_status": {
            "state": "active",
            "revision": REVISION_NEW,
            "release_digest": DIGEST_NEW,
        },
        "active_images": _old_images(),
    }
    transaction._json(paths.state / "current.json", accepted)
    paths.current.unlink()
    paths.current.symlink_to(candidate)
    _write(paths.config / "profiles.yml", b"candidate")

    transaction.rollback_accepted(paths, operation["id"])

    assert paths.current.resolve() == previous
    assert (paths.config / "profiles.yml").read_bytes() == b"old-1"
    assert json.loads((paths.state / "current.json").read_text())["phase"] == "rolled_back"


def test_operator_rollback_rejects_noncurrent_checkpoint(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_run", lambda argv, **kwargs: "")
    operation = transaction.prepare(paths, candidate)
    transaction._json(
        paths.state / "current.json",
        {
            **operation,
            "id": "a" * 32,
            "phase": "accepted",
        },
    )

    with pytest.raises(transaction.TransactionError, match="not the active"):
        transaction.rollback_accepted(paths, operation["id"])


def test_prepare_rejects_nonregular_operator_identity_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    key = paths.config / "mtls/operator/operator-key.pem"
    key.unlink()
    key.mkdir()

    with pytest.raises(transaction.TransactionError, match="identity metadata"):
        transaction.prepare(paths, candidate)


def test_tampered_snapshot_tuple_is_rejected_before_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_run", lambda argv, **kwargs: "")
    operation = transaction.prepare(paths, candidate)
    operation["configs"]["profiles.yml"]["uid"] = -1

    with pytest.raises(transaction.TransactionError, match="configuration tuple"):
        transaction.rollback(paths, operation)


def test_prepare_failure_before_durable_journal_removes_exact_temporary_artifacts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    tag_calls = 0

    def run(argv: list[str], **kwargs: object) -> str:
        nonlocal tag_calls
        if argv[:3] == ["docker", "image", "tag"]:
            tag_calls += 1
            if tag_calls == 2:
                raise transaction.TransactionError("tag failed")
        return ""

    monkeypatch.setattr(transaction, "_run", run)
    with pytest.raises(transaction.TransactionError, match="tag failed"):
        transaction.prepare(paths, candidate)

    assert not (paths.state / "current.json").exists()
    assert not list(paths.state.glob("[0-9a-f]" * 32))
    assert not list(paths.config.glob(".rollback-*"))
    assert not list(paths.current.parent.glob(".rollback-*"))


def test_prepare_preserves_rollback_tuple_when_durable_journal_is_unreadable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, previous, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    removed_images: list[str] = []

    def run(argv: list[str], **kwargs: object) -> str:
        if argv[:3] == ["docker", "image", "rm"]:
            removed_images.append(argv[-1])
        return ""

    monkeypatch.setattr(transaction, "_run", run)
    real_json = transaction._json
    real_read = transaction._read
    journal_written = False

    def failing_json(path: Path, value: dict[str, Any]) -> None:
        nonlocal journal_written
        real_json(path, value)
        if path == paths.state / "current.json":
            journal_written = True
            raise OSError("post-write durability acknowledgement failed")

    def unreadable_journal(path: Path) -> dict[str, Any]:
        if journal_written and path == paths.state / "current.json":
            raise OSError("journal read failed")
        return real_read(path)

    monkeypatch.setattr(transaction, "_json", failing_json)
    monkeypatch.setattr(transaction, "_read", unreadable_journal)

    with pytest.raises(OSError, match="post-write"):
        transaction.prepare(paths, candidate)

    assert (paths.state / "current.json").exists()
    durable = json.loads((paths.state / "current.json").read_text())
    identity = durable["id"]
    assert (paths.state / identity / "snapshot.json").exists()
    assert (paths.current.parent / f".rollback-{identity}").resolve() == previous
    assert list(paths.config.glob(f".rollback-{identity}-*"))
    assert removed_images == []


def test_candidate_with_symlinked_native_helper_is_rejected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    helper = candidate / "scripts/activate_controller_release_native.sh"
    target = candidate / "scripts/native-real.sh"
    helper.rename(target)
    helper.symlink_to(target.name)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)

    with pytest.raises(transaction.TransactionError, match="symbolic link"):
        transaction.prepare(paths, candidate)


def test_rollback_rejects_replaced_operator_identity_type(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths, _, candidate = _fixture(tmp_path)
    monkeypatch.setattr(transaction, "_health", lambda expected: None)
    monkeypatch.setattr(transaction, "_images", _old_images)
    monkeypatch.setattr(transaction, "_inspect", lambda argv: {"Id": argv[-1]})
    monkeypatch.setattr(transaction, "_run", lambda argv, **kwargs: "")
    operation = transaction.prepare(paths, candidate)
    key = paths.config / "mtls/operator/operator-key.pem"
    key.unlink()
    key.mkdir()

    with pytest.raises(transaction.TransactionError, match="identity metadata"):
        transaction.rollback(paths, operation)
