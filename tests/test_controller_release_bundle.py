from __future__ import annotations

import json
from pathlib import Path

import pytest

from qdev_runner import controller_release_bundle as bundle

REVISION = "a" * 40


def _source(tmp_path: Path) -> Path:
    root = tmp_path / "source"
    for name in bundle._FILES:
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{name}\n", encoding="utf-8")
    for name in bundle._TREES:
        path = root / name / "entry.txt"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{name}\n", encoding="utf-8")
    return root


def test_build_is_deterministic_and_verifiable(tmp_path: Path) -> None:
    source = _source(tmp_path)
    first = bundle.build(source, tmp_path / "first", REVISION)
    second = bundle.build(source, tmp_path / "second", REVISION)

    assert first == second
    assert first["bundle_digest"] == bundle.verify(tmp_path / "first")["bundle_digest"]
    assert json.loads((tmp_path / "first" / bundle.MANIFEST).read_text(encoding="utf-8")) == first


def test_build_binds_external_offline_wheelhouse(tmp_path: Path) -> None:
    source = _source(tmp_path)
    wheelhouse = tmp_path / "external-wheelhouse"
    wheelhouse.mkdir()
    (wheelhouse / "dependency-1.0-py3-none-any.whl").write_bytes(b"wheel")
    destination = tmp_path / "bundle"

    manifest = bundle.build(source, destination, REVISION, wheelhouse=wheelhouse)

    assert "wheelhouse/dependency-1.0-py3-none-any.whl" in manifest["files"]
    (destination / "wheelhouse/dependency-1.0-py3-none-any.whl").write_bytes(b"changed")
    with pytest.raises(bundle.BundleError, match="contents"):
        bundle.verify(destination)


def test_build_excludes_generated_python_metadata(tmp_path: Path) -> None:
    source = _source(tmp_path)
    generated = source / "src/qdev_runner_control_plane.egg-info/PKG-INFO"
    generated.parent.mkdir(parents=True)
    generated.write_text("generated\n", encoding="utf-8")
    cached = source / "src/qdev_runner/__pycache__/module.pyc"
    cached.parent.mkdir(parents=True)
    cached.write_bytes(b"generated")

    manifest = bundle.build(source, tmp_path / "bundle", REVISION)

    assert not any("egg-info" in path for path in manifest["files"])
    assert not any("__pycache__" in path for path in manifest["files"])


def test_verify_rejects_modified_or_undeclared_content(tmp_path: Path) -> None:
    source = _source(tmp_path)
    destination = tmp_path / "bundle"
    manifest = bundle.build(source, destination, REVISION)
    (destination / "config/entry.txt").write_text("changed\n", encoding="utf-8")
    with pytest.raises(bundle.BundleError, match="contents"):
        bundle.verify(destination, expected_digest=manifest["bundle_digest"])

    destination = tmp_path / "bundle-extra"
    bundle.build(source, destination, REVISION)
    (destination / "scripts/extra.txt").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(bundle.BundleError, match="contents|undeclared"):
        bundle.verify(destination)


def test_build_rejects_symlink_and_existing_destination(tmp_path: Path) -> None:
    source = _source(tmp_path)
    (source / "scripts/entry.txt").unlink()
    (source / "scripts/entry.txt").symlink_to(source / "README.md")
    with pytest.raises(bundle.BundleError, match="regular file"):
        bundle.build(source, tmp_path / "bundle", REVISION)

    source = _source(tmp_path / "again")
    destination = tmp_path / "existing"
    destination.mkdir()
    with pytest.raises(bundle.BundleError, match="must not exist"):
        bundle.build(source, destination, REVISION)


def test_verify_rejects_wrong_identity(tmp_path: Path) -> None:
    source = _source(tmp_path)
    destination = tmp_path / "bundle"
    manifest = bundle.build(source, destination, REVISION)
    with pytest.raises(bundle.BundleError, match="source revision mismatch"):
        bundle.verify(destination, source_revision="b" * 40)
    with pytest.raises(bundle.BundleError, match="bundle digest mismatch"):
        bundle.verify(destination, expected_digest="c" * 64)
    assert len(manifest["bundle_digest"]) == 64
