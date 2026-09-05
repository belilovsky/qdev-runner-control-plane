import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qmt_native_release_adapter.py"
SPEC = importlib.util.spec_from_file_location("qmt_native_release_adapter", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ADAPTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADAPTER
SPEC.loader.exec_module(ADAPTER)


def _release(marker: str) -> dict[str, str]:
    digest = "sha256:" + marker * 64
    return {
        "source_sha": marker * 40,
        "artifact_digest": digest,
        "artifact_ref": f"{ADAPTER.IMAGE_PREFIX}@{digest}",
    }


def _candidate(marker: str = "b") -> dict[str, Any]:
    return {
        "release": _release(marker),
        "evidence": {
            "version": "4.4.2",
            "artifact_provenance": {
                "candidate_receipt_sha256": "c" * 64,
                "migration_receipt_digest": "sha256:" + "d" * 64,
                "contract_digest": "e" * 64,
            },
        },
    }


def _legacy() -> dict[str, Any]:
    return {
        "release": _release("a"),
        "evidence": {
            "version": "4.4.1",
            "artifact_provenance": {"legacy_runtime_receipt_sha256": "f" * 64},
        },
    }


def _paths(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setattr(ADAPTER, "ROOT", tmp_path)
    monkeypatch.setattr(ADAPTER, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(ADAPTER, "TRANSACTION_FILE", tmp_path / "transaction.json")
    monkeypatch.setattr(ADAPTER, "OVERLAY_FILE", tmp_path / "compose.yml")
    monkeypatch.setattr(ADAPTER, "METADATA_FILE", tmp_path / "metadata.json")


def test_candidate_metadata_binds_all_signed_evidence() -> None:
    document = ADAPTER.metadata_document(_candidate())

    assert document == {
        "schema_version": "kaztilshi-runtime-release-v1",
        "project_id": "kaztilshi",
        "source_revision": "b" * 40,
        "image_digest": "sha256:" + "b" * 64,
        "migration_receipt_digest": "sha256:" + "d" * 64,
        "release_receipt_digest": "sha256:" + "c" * 64,
        "contract_digest": "e" * 64,
    }


def test_legacy_record_is_only_allowed_before_442() -> None:
    assert ADAPTER.validate_record(_legacy())["evidence"]["version"] == "4.4.1"
    invalid = _legacy()
    invalid["evidence"]["version"] = "4.4.2"
    with pytest.raises(ADAPTER.AdapterError, match="provenance"):
        ADAPTER.validate_record(invalid)


def test_current_legacy_runtime_is_enrolled_by_registry_digest(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _paths(monkeypatch, tmp_path)
    image_id = "sha256:" + "1" * 64
    registry_digest = "sha256:" + "a" * 64
    registry_ref = f"{ADAPTER.IMAGE_PREFIX}@{registry_digest}"
    commands: list[list[str]] = []

    def docker_json(*arguments: str) -> Any:
        if arguments == ("inspect", ADAPTER.CONTAINER):
            return [{"Image": image_id, "State": {"Running": True}, "Config": {"Image": "mutable"}}]
        raise AssertionError(arguments)

    def inspect(reference: str) -> dict[str, Any]:
        if reference == image_id:
            return {
                "Id": image_id,
                "Size": 100,
                "Config": {
                    "Labels": {
                        "org.opencontainers.image.revision": ADAPTER.LEGACY_SOURCE_SHA
                    }
                },
                "RepoDigests": [],
            }
        assert reference == f"{ADAPTER.IMAGE_PREFIX}:rollback-{ADAPTER.LEGACY_SOURCE_SHA}"
        return {
            "Id": image_id,
            "Size": 100,
            "Config": {
                "Labels": {"org.opencontainers.image.revision": ADAPTER.LEGACY_SOURCE_SHA}
            },
            "RepoDigests": [registry_ref],
        }

    monkeypatch.setattr(ADAPTER, "docker_json", docker_json)
    monkeypatch.setattr(ADAPTER, "image_inspect", inspect)
    monkeypatch.setattr(ADAPTER, "ensure_capacity", lambda required, **_: None)
    monkeypatch.setattr(ADAPTER, "run", lambda command: commands.append(command) or "")
    monkeypatch.setattr(
        ADAPTER,
        "http_json",
        lambda origin, path: {
            "version": ADAPTER.LEGACY_VERSION,
            "source_revision": ADAPTER.LEGACY_SOURCE_SHA,
            "runtime_revision": ADAPTER.LEGACY_SOURCE_SHA,
        },
    )
    monkeypatch.setattr(ADAPTER, "prove_runtime", lambda record: ADAPTER.receipt(record))

    receipt = ADAPTER.enroll_current_runtime()

    state = ADAPTER.read_state()
    assert receipt["artifact_ref"] == registry_ref
    assert state["active"] == state["rollback"]
    assert state["active"]["release"]["artifact_digest"] == registry_digest
    assert [command[1] for command in commands] == ["tag", "push"]


def test_enrollment_refuses_existing_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _paths(monkeypatch, tmp_path)
    ADAPTER.write_state(_legacy(), _legacy())

    with pytest.raises(ADAPTER.AdapterError, match="already enrolled"):
        ADAPTER.enroll_current_runtime()


def test_release_commits_candidate_and_retains_exact_previous_tuple(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _paths(monkeypatch, tmp_path)
    previous = _legacy()
    candidate = _candidate()
    ADAPTER.write_state(previous, previous)
    mutations: list[str] = []
    monkeypatch.setattr(ADAPTER, "run", lambda command: mutations.append(command[-1]) or "")
    monkeypatch.setattr(ADAPTER, "required_capacity", lambda new, old: 1)
    monkeypatch.setattr(ADAPTER, "ensure_capacity", lambda required, **_: None)
    monkeypatch.setattr(
        ADAPTER, "compose_up", lambda record: mutations.append(record["release"]["source_sha"])
    )
    monkeypatch.setattr(ADAPTER, "prove_runtime", lambda record: ADAPTER.receipt(record))

    result = ADAPTER.do_release(candidate)

    state = ADAPTER.read_state()
    assert result["source_sha"] == candidate["release"]["source_sha"]
    assert state["active"] == candidate
    assert state["rollback"] == previous
    assert not ADAPTER.TRANSACTION_FILE.exists()
    assert candidate["release"]["source_sha"] in mutations


def test_release_failure_restores_previous_tuple_and_state(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _paths(monkeypatch, tmp_path)
    previous = _legacy()
    candidate = _candidate()
    ADAPTER.write_state(previous, previous)
    starts: list[str] = []
    monkeypatch.setattr(ADAPTER, "run", lambda command: "")
    monkeypatch.setattr(ADAPTER, "required_capacity", lambda new, old: 1)
    monkeypatch.setattr(ADAPTER, "ensure_capacity", lambda required, **_: None)
    monkeypatch.setattr(
        ADAPTER, "compose_up", lambda record: starts.append(record["release"]["source_sha"])
    )

    def prove(record: dict[str, Any]) -> dict[str, Any]:
        if record["release"] == candidate["release"]:
            raise ADAPTER.AdapterError("candidate identity mismatch")
        return ADAPTER.receipt(record)

    monkeypatch.setattr(ADAPTER, "prove_runtime", prove)

    with pytest.raises(ADAPTER.AdapterError, match="previous QMT runtime was restored"):
        ADAPTER.do_release(candidate)

    state = ADAPTER.read_state()
    assert state["active"] == previous
    assert state["rollback"] == previous
    assert starts == [candidate["release"]["source_sha"], previous["release"]["source_sha"]]
    assert not ADAPTER.TRANSACTION_FILE.exists()


def test_interrupted_transaction_is_rolled_back_before_new_work(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _paths(monkeypatch, tmp_path)
    previous = _legacy()
    candidate = _candidate()
    ADAPTER.write_state(previous, previous)
    ADAPTER.atomic_json(
        ADAPTER.TRANSACTION_FILE,
        {"schema": ADAPTER.TRANSACTION_SCHEMA, "previous": previous, "candidate": candidate},
    )
    monkeypatch.setattr(ADAPTER, "compose_up", lambda record: None)
    monkeypatch.setattr(ADAPTER, "prove_runtime", lambda record: ADAPTER.receipt(record))

    recovered = ADAPTER.recover_interrupted(ADAPTER.read_state())

    assert recovered["active"] == previous
    assert not ADAPTER.TRANSACTION_FILE.exists()
