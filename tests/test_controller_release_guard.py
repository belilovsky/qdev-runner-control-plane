from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "release_guard", ROOT / "scripts/controller_release_guard.py"
)
assert SPEC and SPEC.loader
GUARD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(GUARD)
SHA = "1" * 40
DIGEST = "2" * 64


def artifact(tmp_path: Path) -> str:
    import hashlib

    (tmp_path / "broker.py").write_text("pass\n")
    payload = {
        "schema": GUARD.SCHEMA,
        "revision": SHA,
        "files": {
            "broker.py": {"sha256": hashlib.sha256(b"pass\n").hexdigest(), "executable": False}
        },
    }
    bound = GUARD.digest(payload)
    (tmp_path / GUARD.MANIFEST).write_text(json.dumps({**payload, "digest": bound}))
    return str(bound)


def test_exact_source_artifact_is_accepted(tmp_path: Path) -> None:
    bound = artifact(tmp_path)
    assert GUARD.verify_artifact(tmp_path, SHA, bound) == bound


@pytest.mark.parametrize("mutation", ["source", "extra", "missing", "mode", "symlink"])
def test_modified_artifact_is_rejected(tmp_path: Path, mutation: str) -> None:
    bound = artifact(tmp_path)
    source = tmp_path / "broker.py"
    if mutation == "source":
        source.write_text("different\n")
    elif mutation == "extra":
        (tmp_path / "unbound.py").write_text("pass\n")
    elif mutation == "missing":
        source.unlink()
    elif mutation == "mode":
        source.chmod(0o755)
    else:
        source.unlink()
        source.symlink_to(ROOT / "README.md")
    with pytest.raises(ValueError):
        GUARD.verify_artifact(tmp_path, SHA, bound)


def test_other_revision_or_digest_is_rejected(tmp_path: Path) -> None:
    bound = artifact(tmp_path)
    with pytest.raises(ValueError):
        GUARD.verify_artifact(tmp_path, "3" * 40, bound)
    with pytest.raises(ValueError):
        GUARD.verify_artifact(tmp_path, SHA, DIGEST)


def test_runtime_compare_and_swap_detects_parallel_release(tmp_path: Path) -> None:
    status = tmp_path / "status.json"
    status.write_text(json.dumps({"state": "active", "revision": SHA, "release_digest": DIGEST}))
    GUARD.check_current(status, SHA, DIGEST)
    status.write_text(
        json.dumps({"state": "active", "revision": "3" * 40, "release_digest": DIGEST})
    )
    with pytest.raises(ValueError, match="runtime changed"):
        GUARD.check_current(status, SHA, DIGEST)


@pytest.mark.parametrize("path", ["../outside", "/outside", "a/../b", ".git/config", "a//b"])
def test_untrusted_manifest_paths_fail_closed(path: str) -> None:
    with pytest.raises(ValueError):
        GUARD.validate_path(path)
