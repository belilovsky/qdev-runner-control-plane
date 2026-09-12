import importlib.util
import json
import stat
import sys
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qazpolit_native_release_adapter.py"
SPEC = importlib.util.spec_from_file_location("qazpolit_native_release_adapter", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ADAPTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADAPTER
SPEC.loader.exec_module(ADAPTER)

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


def _release(source: str = SHA, digest: str = DIGEST) -> dict[str, str]:
    return {
        "source_sha": source,
        "artifact_digest": digest,
        "artifact_ref": f"{ADAPTER.IMAGE_PREFIX}@{digest}",
    }


def _provenance() -> dict[str, object]:
    return {
        "archive_sha256": "c" * 64,
        "payload_sha256": "d" * 64,
        "archive_size_bytes": 1,
    }


def _archive(path: Path, *, symlink: bool = False) -> None:
    with zipfile.ZipFile(path, "w") as archive:
        for name in sorted(ADAPTER.REQUIRED_ARCHIVE_FILES):
            member = zipfile.ZipInfo(name)
            if symlink and name == "provenance.json":
                member.external_attr = (stat.S_IFLNK | 0o777) << 16
            archive.writestr(member, "{}")


def test_extract_refuses_symlink_member(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    archive = tmp_path / "candidate.zip"
    _archive(archive, symlink=True)
    monkeypatch.setattr(ADAPTER, "EXTRACTED_ROOT", tmp_path / "extracted")

    with pytest.raises(ADAPTER.AdapterError, match="symlink"):
        ADAPTER.extract_archive(archive, SHA, _provenance())


def test_release_provenance_requires_exact_qazpolit_image_prefix(tmp_path: Path) -> None:
    (tmp_path / "source-sha.txt").write_text(SHA + "\n", encoding="utf-8")
    (tmp_path / "provenance.json").write_text(
        json.dumps(
            {
                "schema": "qazpolit.release-provenance.v1",
                "source_sha": SHA,
                "image_digest": DIGEST,
                "image_ref": f"registry.example.invalid/qazpolit@{DIGEST}",
                "postgres": {
                    "image_ref": "registry.ci.qdev.run/qazpolit-postgres@sha256:" + "e" * 64
                },
                "release_id": "release-1",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(ADAPTER.AdapterError, match="inconsistent"):
        ADAPTER.release_provenance(tmp_path, SHA)


def test_bind_operator_runtime_allows_only_fixed_operator_inputs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    operator = tmp_path / "operator"
    data = operator / "data"
    data.mkdir(parents=True)
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    overlay = tmp_path / "overlay.env"
    overlay.write_text("X=1\n", encoding="utf-8")
    monkeypatch.setattr(ADAPTER, "OPERATOR_ROOT", operator)

    ADAPTER.bind_operator_runtime(worktree, overlay)
    assert (worktree / ".env").resolve() == overlay.resolve()
    assert (worktree / "data").resolve() == data.resolve()

    (worktree / ".env").unlink()
    (worktree / ".env").write_text("untrusted\n", encoding="utf-8")
    with pytest.raises(ADAPTER.AdapterError, match="mutable runtime material"):
        ADAPTER.bind_operator_runtime(worktree, overlay)


def test_candidate_failure_restores_legacy_release_and_clears_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    previous = {
        "release": _release(),
        "provenance": {"legacy_runtime_receipt_sha256": "f" * 64},
        "deployment": {
            "worktree": "/opt/qazpolit",
            "overlay": "/opt/qazpolit/.env",
            "release_id": "legacy-release",
        },
    }
    candidate = _release("c" * 40, "sha256:" + "d" * 64)
    transaction = tmp_path / "transaction.json"
    worktree = tmp_path / "worktree"
    worktree.mkdir()
    overlay = tmp_path / "overlay.env"
    overlay.write_text("X=1\n", encoding="utf-8")
    attempted: list[dict[str, object]] = []
    monkeypatch.setattr(ADAPTER, "TRANSACTION_FILE", transaction)
    monkeypatch.setattr(ADAPTER, "STATE_FILE", tmp_path / "state.json")
    monkeypatch.setattr(ADAPTER, "ROOT", tmp_path)
    monkeypatch.setattr(
        ADAPTER,
        "current_state",
        lambda: {"schema": ADAPTER.STATE_SCHEMA, "active": previous, "rollback": previous},
    )
    monkeypatch.setattr(ADAPTER, "checked_archive", lambda *_: tmp_path / "candidate.zip")
    monkeypatch.setattr(ADAPTER, "extract_archive", lambda *_: tmp_path / "extracted")
    monkeypatch.setattr(
        ADAPTER,
        "release_provenance",
        lambda *_: {
            "app_image": candidate["artifact_ref"],
            "app_digest": candidate["artifact_digest"],
            "db_image": "registry.ci.qdev.run/qazpolit-postgres@sha256:" + "e" * 64,
            "release_id": "candidate-release",
        },
    )
    monkeypatch.setattr(ADAPTER, "prepare_worktree", lambda *_: worktree)
    monkeypatch.setattr(ADAPTER.shutil, "disk_usage", lambda *_: SimpleNamespace(free=10**12))
    monkeypatch.setattr(ADAPTER, "run", lambda *_args, **_kwargs: "")
    monkeypatch.setattr(ADAPTER, "write_overlay", lambda *_: overlay)
    monkeypatch.setattr(ADAPTER, "bind_operator_runtime", lambda *_: None)

    def fail_candidate(record: dict[str, object]) -> None:
        attempted.append(record)
        if record["release"] == candidate:
            raise ADAPTER.AdapterError("candidate runtime failed")

    monkeypatch.setattr(ADAPTER, "deploy_record", fail_candidate)
    arguments = SimpleNamespace(
        source_sha=candidate["source_sha"],
        artifact_digest=candidate["artifact_digest"],
        artifact_ref=candidate["artifact_ref"],
        private_archive_sha256="c" * 64,
        private_payload_sha256="d" * 64,
        private_archive_size_bytes=1,
    )

    with pytest.raises(ADAPTER.AdapterError, match="candidate runtime failed"):
        ADAPTER.release(arguments)
    assert attempted == [
        {
            "release": candidate,
            "provenance": _provenance(),
            "deployment": {
                "worktree": str(worktree),
                "overlay": str(overlay),
                "release_id": "candidate-release",
            },
        },
        previous,
    ]
    assert not transaction.exists()
