from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def material(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    path = ROOT / "scripts/controller_activation_material.py"
    spec = importlib.util.spec_from_file_location("controller_activation_material", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, "_safe_directory", lambda path, mode=None: None)
    monkeypatch.setattr(module, "_safe_regular", lambda path, mode_mask=0o022: path.lstat())
    monkeypatch.setattr(module.os, "chown", lambda *args: None)
    return module


def _prepare(material: ModuleType, tmp_path: Path) -> tuple[Path, dict[str, object]]:
    root = tmp_path / "transactions"
    root.mkdir(mode=0o700)
    release = tmp_path / "release"
    release.mkdir()
    configuration = tmp_path / "etc" / "profiles.yml"
    configuration.parent.mkdir()
    configuration.write_text("old-profile\n", encoding="utf-8")
    os.chmod(configuration, 0o640)
    absent = tmp_path / "etc" / "new.yml"
    args = argparse.Namespace(
        root=root,
        transaction_id="activation-1",
        envelope_digest="a" * 64,
        release_path=str(release),
        previous_release_path="/opt/qdev/releases/" + "1" * 40,
        previous_public_image="sha256:" + "2" * 64,
        previous_public_ref="registry.example/public@sha256:" + "2" * 64,
        previous_internal_image="sha256:" + "3" * 64,
        previous_internal_ref="registry.example/internal@sha256:" + "3" * 64,
        rollback_public_ref="rollback-public:test",
        rollback_internal_ref="rollback-internal:test",
        dispatcher_enabled="enabled",
        dispatcher_active="active",
        snapshot=[f"configuration={configuration}", f"configuration={absent}"],
    )
    value = material.prepare(args)
    return root / f"activation-1-{'a' * 64}", value


def test_material_restores_exact_files_and_publishes_bound_anchor(
    material: ModuleType, tmp_path: Path
) -> None:
    directory, value = _prepare(material, tmp_path)
    snapshots = value["snapshots"]
    assert isinstance(snapshots, list)
    present = Path(snapshots[0]["destination"])
    absent = Path(snapshots[1]["destination"])
    present.write_text("candidate-profile\n", encoding="utf-8")
    absent.write_text("candidate-only\n", encoding="utf-8")

    material.restore(argparse.Namespace(directory=directory, group=["configuration"]))
    assert present.read_text(encoding="utf-8") == "old-profile\n"
    assert present.stat().st_mode & 0o777 == 0o640
    assert not absent.exists()

    extracted = tmp_path / "extracted.json"
    material.extract(
        argparse.Namespace(
            directory=directory,
            destination=str(present),
            output=extracted,
        )
    )
    assert extracted.read_text(encoding="utf-8") == "old-profile\n"

    revision = "4" * 40
    anchor = {
        "schema": "qdev-controller-rollback-anchor-v1",
        "revision": revision,
        "release_digest": "sha256:" + "5" * 64,
        "release_path": value["previous_release_path"],
        "public_image_id": value["previous_public_image"],
        "internal_image_id": value["previous_internal_image"],
        "public_image_ref": value["previous_public_ref"],
        "internal_image_ref": value["previous_internal_ref"],
        "public_saved_ref": f"qdev-runner-controller-anchor-public:{revision}",
        "internal_saved_ref": f"qdev-runner-controller-anchor-internal:{revision}",
        "recorded_at": "2026-09-05T12:00:00Z",
    }
    source = tmp_path / "anchor.json"
    source.write_text(json.dumps(anchor) + "\n", encoding="utf-8")
    os.chmod(source, 0o600)
    material.stage_anchor(argparse.Namespace(directory=directory, source=source))
    destination = tmp_path / "state" / "rollback-anchor.json"
    destination.parent.mkdir()
    material.publish_anchor(argparse.Namespace(directory=directory, destination=destination))
    assert json.loads(destination.read_text(encoding="utf-8")) == anchor

    material.finish(argparse.Namespace(directory=directory, outcome="finalized"))
    assert not directory.exists()


def test_material_rejects_tampered_snapshot(material: ModuleType, tmp_path: Path) -> None:
    directory, value = _prepare(material, tmp_path)
    snapshots = value["snapshots"]
    assert isinstance(snapshots, list)
    backup = directory / snapshots[0]["backup"]
    backup.write_text("tampered\n", encoding="utf-8")
    with pytest.raises(material.MaterialError, match="snapshot digest mismatch"):
        material.restore(argparse.Namespace(directory=directory, group=["configuration"]))


def test_material_rejects_anchor_not_bound_to_preserved_runtime(
    material: ModuleType, tmp_path: Path
) -> None:
    directory, value = _prepare(material, tmp_path)
    revision = "4" * 40
    anchor = {
        "schema": "qdev-controller-rollback-anchor-v1",
        "revision": revision,
        "release_digest": "sha256:" + "5" * 64,
        "release_path": value["previous_release_path"],
        "public_image_id": "sha256:" + "9" * 64,
        "internal_image_id": value["previous_internal_image"],
        "public_image_ref": value["previous_public_ref"],
        "internal_image_ref": value["previous_internal_ref"],
        "public_saved_ref": f"qdev-runner-controller-anchor-public:{revision}",
        "internal_saved_ref": f"qdev-runner-controller-anchor-internal:{revision}",
        "recorded_at": "2026-09-05T12:00:00Z",
    }
    source = tmp_path / "bad-anchor.json"
    source.write_text(json.dumps(anchor) + "\n", encoding="utf-8")
    with pytest.raises(material.MaterialError, match="preserved runtime material"):
        material.stage_anchor(argparse.Namespace(directory=directory, source=source))


def test_material_refuses_to_remove_tree_containing_symlink(
    material: ModuleType, tmp_path: Path
) -> None:
    directory, _ = _prepare(material, tmp_path)
    (directory / "unsafe-link").symlink_to(tmp_path / "outside")
    with pytest.raises(material.MaterialError, match="unsafe symlink"):
        material.finish(argparse.Namespace(directory=directory, outcome="rolled-back"))
    assert directory.exists()


def test_material_installs_and_flips_release_projection_atomically(
    material: ModuleType, tmp_path: Path
) -> None:
    directory, value = _prepare(material, tmp_path)
    release = Path(value["release_path"])
    source = release / "profiles.yml"
    source.write_text("candidate\n", encoding="utf-8")
    destination = tmp_path / "etc" / "installed.yml"

    material.install_file(
        argparse.Namespace(
            directory=directory,
            source=source,
            destination=destination,
            mode=0o640,
            uid=os.getuid(),
            gid=os.getgid(),
        )
    )
    assert destination.read_text(encoding="utf-8") == "candidate\n"
    assert destination.stat().st_mode & 0o777 == 0o640

    releases = tmp_path / "releases"
    releases.mkdir()
    target = releases / ("4" * 40)
    target.mkdir()
    link = releases / "current"
    material.activate_link(argparse.Namespace(directory=directory, link=link, target=target))
    assert link.is_symlink()
    assert link.resolve() == target.resolve()


def test_material_rejects_install_source_outside_signed_release(
    material: ModuleType, tmp_path: Path
) -> None:
    directory, _ = _prepare(material, tmp_path)
    outside = tmp_path / "outside"
    outside.write_text("forged\n", encoding="utf-8")
    with pytest.raises(material.MaterialError, match="outside the signed release"):
        material.install_file(
            argparse.Namespace(
                directory=directory,
                source=outside,
                destination=tmp_path / "etc" / "forged",
                mode=0o644,
                uid=os.getuid(),
                gid=os.getgid(),
            )
        )


@pytest.mark.parametrize(
    "stage",
    [
        "after-staging-directory",
        "after-files-directory",
        "after-snapshot-0",
        "after-manifest",
        "before-rename",
    ],
)
def test_prepare_crash_before_publish_never_exposes_partial_canonical_material(
    material: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stage: str
) -> None:
    def fail_at(observed: str) -> None:
        if observed == stage:
            raise RuntimeError("simulated process interruption")

    monkeypatch.setattr(material, "_prepare_fault", fail_at)
    with pytest.raises(RuntimeError, match="simulated process interruption"):
        _prepare(material, tmp_path)
    canonical = tmp_path / "transactions" / f"activation-1-{'a' * 64}"
    assert not canonical.exists()
    assert not list((tmp_path / "transactions").glob(".*.prepare.*"))


def test_prepare_crash_after_publish_leaves_complete_recoverable_material(
    material: ModuleType, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def fail_at(observed: str) -> None:
        if observed == "after-rename":
            raise RuntimeError("simulated process interruption")

    monkeypatch.setattr(material, "_prepare_fault", fail_at)
    with pytest.raises(RuntimeError, match="simulated process interruption"):
        _prepare(material, tmp_path)
    canonical = tmp_path / "transactions" / f"activation-1-{'a' * 64}"
    value = material._load(canonical)
    assert value["phase"] == "prepared"
    assert len(value["snapshots"]) == 2
