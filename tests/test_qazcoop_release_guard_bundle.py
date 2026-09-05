from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import stat
import subprocess
from pathlib import Path
from types import ModuleType

import pytest

from qdev_runner.controller_admission import initialize_keypair


def _script(name: str) -> ModuleType:
    path = Path(__file__).parents[1] / "scripts" / name
    spec = importlib.util.spec_from_file_location(name.removesuffix(".py"), path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _git(repository: Path, *arguments: str) -> str:
    return subprocess.run(  # noqa: S603
        ["/usr/bin/git", *arguments],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _source_repository(tmp_path: Path, builder: ModuleType) -> tuple[Path, str]:
    repository = tmp_path / "controller"
    repository.mkdir()
    _git(repository, "init")
    _git(repository, "config", "user.email", "controller@example.invalid")
    _git(repository, "config", "user.name", "Controller Test")
    for relative, _destination, mode in builder.REPOSITORY_FILES.values():
        target = repository / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        if relative.endswith(".json"):
            target.write_text("{}\n", encoding="utf-8")
        elif mode & 0o111:
            target.write_text("#!/usr/bin/env python3\n", encoding="utf-8")
            target.chmod(mode)
        else:
            target.write_text("# exact committed source\n", encoding="utf-8")
    build_source = repository / "scripts/build_qazcoop_release_guard_bundle.py"
    build_source.parent.mkdir(parents=True, exist_ok=True)
    build_source.write_text("# bundle builder source binding\n", encoding="utf-8")
    _git(repository, "add", ".")
    _git(repository, "commit", "-m", "controller source")
    return repository, _git(repository, "rev-parse", "HEAD")


def _bundle(tmp_path: Path) -> tuple[Path, ModuleType]:
    builder = _script("build_qazcoop_release_guard_bundle.py")
    installer = _script("install_qazcoop_release_guard.py")
    repository, revision = _source_repository(tmp_path, builder)
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    initialize_keypair(private, public)
    output = tmp_path / "bundle"
    builder.build_bundle(repository, revision, private, public, output)
    return output, installer


def _rewrite_manifest_digest(bundle: Path, name: str, relative: Path) -> None:
    manifest_path = bundle / "bundle.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][name] = "sha256:" + hashlib.sha256(
        (bundle / relative).read_bytes()
    ).hexdigest()
    manifest_path.write_text(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )


def test_builder_exports_exact_bundle_with_signed_key_canary(tmp_path: Path) -> None:
    bundle, installer = _bundle(tmp_path)

    manifest = installer.validate_bundle(bundle)

    assert manifest["contract"] == "qazcoop-release-guard-trust-bundle/v1"
    assert set(manifest["files"]) == set(installer.EXPECTED_FILES)


def test_bundle_validation_rejects_unmanifested_python(tmp_path: Path) -> None:
    bundle, installer = _bundle(tmp_path)
    (bundle / "lib/sitecustomize.py").write_text("raise RuntimeError\n", encoding="utf-8")

    with pytest.raises(ValueError, match="filesystem inventory is not exact"):
        installer.validate_bundle(bundle)


def test_bundle_validation_rejects_malformed_public_key(tmp_path: Path) -> None:
    bundle, installer = _bundle(tmp_path)
    public = bundle / installer.EXPECTED_FILES["public.pem"]
    public.write_text("not a public key\n", encoding="utf-8")
    _rewrite_manifest_digest(bundle, "public.pem", installer.EXPECTED_FILES["public.pem"])

    with pytest.raises(ValueError, match="public key is invalid"):
        installer.validate_bundle(bundle)


def test_bundle_validation_rejects_resigned_manifest_with_tampered_canary(
    tmp_path: Path,
) -> None:
    bundle, installer = _bundle(tmp_path)
    canary = bundle / installer.EXPECTED_FILES["key-canary.json"]
    value = json.loads(canary.read_text(encoding="utf-8"))
    value["payload"]["controller_revision"] = "0" * 40
    canary.write_text(
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    _rewrite_manifest_digest(bundle, "key-canary.json", installer.EXPECTED_FILES["key-canary.json"])

    with pytest.raises(ValueError, match="key canary payload is invalid"):
        installer.validate_bundle(bundle)


def test_bundle_validation_rejects_manifest_rewrite_for_changed_guard_file(
    tmp_path: Path,
) -> None:
    bundle, installer = _bundle(tmp_path)
    guard = bundle / installer.EXPECTED_FILES["controller_admission.py"]
    guard.write_text("changed\n", encoding="utf-8")
    _rewrite_manifest_digest(
        bundle,
        "controller_admission.py",
        installer.EXPECTED_FILES["controller_admission.py"],
    )

    with pytest.raises(ValueError, match="key canary payload is invalid"):
        installer.validate_bundle(bundle)


def test_builder_rejects_dirty_tracked_source(tmp_path: Path) -> None:
    builder = _script("build_qazcoop_release_guard_bundle.py")
    repository, revision = _source_repository(tmp_path, builder)
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    initialize_keypair(private, public)
    first_source = next(iter(builder.REPOSITORY_FILES.values()))[0]
    (repository / first_source).write_text("changed\n", encoding="utf-8")

    with pytest.raises(ValueError, match="worktree must be clean"):
        builder.build_bundle(repository, revision, private, public, tmp_path / "bundle")


def test_preinstalled_guard_must_match_exact_inventory_and_digests(tmp_path: Path) -> None:
    bundle, installer = _bundle(tmp_path)
    manifest = installer.validate_bundle(bundle)
    installed = tmp_path / "installed"
    for relative, mode in installer.VERSION_FILES.items():
        destination = installed / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        source_name = next(
            name for name, source_relative in installer.EXPECTED_FILES.items()
            if source_relative == relative
        )
        destination.write_bytes((bundle / installer.EXPECTED_FILES[source_name]).read_bytes())
        destination.chmod(mode)
    for directory in (
        installed,
        installed / "lib",
        installed / "lib/qdev_runner",
        installed / "bin",
    ):
        directory.chmod(0o750)

    installer._validate_installed_version(
        installed,
        manifest,
        gid=installed.stat().st_gid,
        uid=installed.stat().st_uid,
    )

    changed = installed / installer.EXPECTED_FILES["controller_admission.py"]
    changed.write_text("changed\n", encoding="utf-8")
    changed.chmod(stat.S_IMODE(installer.VERSION_FILES[changed.relative_to(installed)]))
    with pytest.raises(ValueError, match="digest mismatch"):
        installer._validate_installed_version(
            installed,
            manifest,
            gid=installed.stat().st_gid,
            uid=installed.stat().st_uid,
        )


def test_backup_state_id_binds_hook_and_launcher(tmp_path: Path) -> None:
    _bundle_path, installer = _bundle(tmp_path)
    hook = tmp_path / "update"
    launcher = tmp_path / "launcher"
    hook.write_text("same hook\n", encoding="utf-8")
    launcher.write_text("first launcher\n", encoding="utf-8")
    first = installer._backup_state_id(hook, launcher)
    launcher.write_text("second launcher\n", encoding="utf-8")

    assert installer._backup_state_id(hook, launcher) != first


def test_restore_replaces_managed_file_atomically(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _bundle_path, installer = _bundle(tmp_path)
    destination = tmp_path / "update"
    backup = tmp_path / "backup"
    destination.write_text("new\n", encoding="utf-8")
    backup.write_text("old\n", encoding="utf-8")
    observed_existing_destination = False
    replace = installer.os.replace

    def checked_replace(source: Path, target: Path) -> None:
        nonlocal observed_existing_destination
        observed_existing_destination = target.exists()
        replace(source, target)

    monkeypatch.setattr(installer.os, "replace", checked_replace)
    monkeypatch.setattr(installer.os, "fchown", lambda *_args: None)
    installer._restore_file(destination, backup)

    assert observed_existing_destination is True
    assert destination.read_text(encoding="utf-8") == "old\n"


def test_copy_fixed_rejects_precreated_symlink(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _bundle_path, installer = _bundle(tmp_path)
    source = tmp_path / "source"
    target = tmp_path / "target"
    destination = tmp_path / "staged"
    source.write_text("guard\n", encoding="utf-8")
    target.write_text("protected\n", encoding="utf-8")
    destination.symlink_to(target)
    monkeypatch.setattr(installer.os, "fchown", lambda *_args: None)

    with pytest.raises(FileExistsError):
        installer._copy_fixed(source, destination, mode=0o750, gid=os.getgid())

    assert target.read_text(encoding="utf-8") == "protected\n"


def test_staged_paths_are_not_pid_predictable(tmp_path: Path) -> None:
    _bundle_path, installer = _bundle(tmp_path)
    destination = tmp_path / "update"

    first = installer._staged_path(destination, "new")
    second = installer._staged_path(destination, "new")

    assert first != second
    assert f".{os.getpid()}." not in first.name


def test_safe_root_directory_rejects_existing_symlink(tmp_path: Path) -> None:
    _bundle_path, installer = _bundle(tmp_path)
    target = tmp_path / "target"
    target.mkdir()
    link = tmp_path / "release"
    link.symlink_to(target, target_is_directory=True)

    with pytest.raises(ValueError, match="managed directory is unsafe"):
        installer._safe_root_directory(link, mode=0o750)
