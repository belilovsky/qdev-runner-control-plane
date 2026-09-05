#!/usr/bin/env python3
"""Install one root-owned QazCoop release guard bundle on its product host."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

EXPECTED_REPOSITORY = Path("/opt/qazcoop.git")
EXPECTED_FILES = {
    "public.pem": Path("trust/public.pem"),
    "admission.schema.json": Path("trust/admission.schema.json"),
    "controller_admission.py": Path("lib/qdev_runner/controller_admission.py"),
    "qazcoop_release_guard.py": Path("lib/qdev_runner/qazcoop_release_guard.py"),
    "qdev-controller-verify-admission": Path("bin/qdev-controller-verify-admission"),
    "qazcoop-update": Path("bin/qazcoop-update"),
}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def strict_json(path: Path) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise ValueError(f"bundle contains duplicate key {key}")
            value[key] = item
        return value

    def constant(value: str) -> None:
        raise ValueError(f"bundle contains forbidden constant {value}")

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=pairs,
        parse_constant=constant,
    )
    if not isinstance(value, dict):
        raise ValueError("bundle manifest must be an object")
    return value


def require_owner_controlled(path: Path, *, executable: bool = False) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"bundle file is unavailable: {path.name}")
    info = path.stat()
    if info.st_uid not in {0, os.geteuid()} or stat.S_IMODE(info.st_mode) & 0o022:
        raise ValueError(f"bundle file is not owner controlled: {path.name}")
    if executable and not stat.S_IMODE(info.st_mode) & 0o111:
        raise ValueError(f"bundle file is not executable: {path.name}")


def validate_bundle(bundle: Path) -> dict[str, Any]:
    if bundle.is_symlink() or not bundle.is_dir():
        raise ValueError("bundle directory is unavailable")
    manifest_path = bundle / "bundle.json"
    require_owner_controlled(manifest_path)
    manifest = strict_json(manifest_path)
    if set(manifest) != {"contract", "controller_revision", "repository", "files"}:
        raise ValueError("bundle manifest fields are invalid")
    if manifest["contract"] != "qazcoop-release-guard-trust-bundle/v1":
        raise ValueError("bundle contract is invalid")
    revision = manifest["controller_revision"]
    if not isinstance(revision, str) or SHA.fullmatch(revision) is None:
        raise ValueError("bundle controller revision is invalid")
    if manifest["repository"] != {
        "id": 1_357_887_516,
        "full_name": "belilovsky/qazcoop",
        "protected_ref": "refs/heads/codex/qazcoop-mvp",
    }:
        raise ValueError("bundle repository identity is invalid")
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != set(EXPECTED_FILES):
        raise ValueError("bundle file inventory is invalid")
    for name, relative in EXPECTED_FILES.items():
        path = bundle / relative
        executable = name in {"qazcoop-update", "qdev-controller-verify-admission"}
        require_owner_controlled(path, executable=executable)
        expected = files[name]
        if not isinstance(expected, str) or DIGEST.fullmatch(expected) is None:
            raise ValueError(f"bundle digest is invalid: {name}")
        if digest(path) != expected:
            raise ValueError(f"bundle digest mismatch: {name}")
    return manifest


def install_bundle(candidate: Path, bundle: Path) -> str:
    if os.geteuid() != 0:
        raise PermissionError("run as root")
    candidate = candidate.resolve(strict=True)
    if candidate != EXPECTED_REPOSITORY or not (candidate / "HEAD").is_file():
        raise ValueError("candidate repository is not the QazCoop production bare repository")
    if subprocess.run(
        ["/usr/bin/git", "rev-parse", "--is-bare-repository"],
        cwd=candidate,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip() != "true":
        raise ValueError("candidate repository must be bare")
    manifest = validate_bundle(bundle)
    revision = str(manifest["controller_revision"])
    version_root = Path("/usr/local/lib/qazcoop-release-guard") / revision
    if version_root.exists() or version_root.is_symlink():
        raise ValueError("guard revision is already installed")
    version_root.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    temporary = Path(tempfile.mkdtemp(prefix=f".{revision}.", dir=version_root.parent))
    try:
        shutil.copytree(bundle / "lib", temporary / "lib", dirs_exist_ok=True)
        shutil.copytree(bundle / "bin", temporary / "bin", dirs_exist_ok=True)
        for path in temporary.rglob("*"):
            if path.is_file():
                path.chmod(0o755 if path.parent.name == "bin" else 0o644)
        os.replace(temporary, version_root)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise

    trust_parent = Path("/etc/qazcoop")
    trust_parent.mkdir(parents=True, exist_ok=True, mode=0o750)
    trust_tmp = Path(tempfile.mkdtemp(prefix=".release-controller.", dir=trust_parent))
    old_trust = trust_parent / ".release-controller.previous"
    trust_root = trust_parent / "release-controller"
    launcher = Path("/usr/local/sbin/qdev-controller-verify-admission")
    hook = candidate / "hooks/update"
    backups = Path(tempfile.mkdtemp(prefix=".qazcoop-release-guard-backup.", dir="/tmp"))
    previous_files: dict[Path, Path] = {}
    try:
        shutil.copyfile(bundle / "bundle.json", trust_tmp / "bundle.json")
        shutil.copyfile(bundle / "trust/public.pem", trust_tmp / "public.pem")
        shutil.copyfile(bundle / "trust/admission.schema.json", trust_tmp / "admission.schema.json")
        for path in trust_tmp.iterdir():
            path.chmod(0o644)
        trust_tmp.chmod(0o750)
        if old_trust.exists():
            shutil.rmtree(old_trust)
        if trust_root.exists():
            os.replace(trust_root, old_trust)
        os.replace(trust_tmp, trust_root)
        Path("/var/lib/qazcoop/release/admissions").mkdir(parents=True, exist_ok=True, mode=0o750)
        Path("/var/lib/qazcoop/release").chmod(0o750)
        for name, destination in (("launcher", launcher), ("hook", hook)):
            if destination.exists() or destination.is_symlink():
                if destination.is_symlink() or not destination.is_file():
                    raise ValueError(f"existing {name} is not a regular file")
                backup = backups / name
                shutil.copyfile(destination, backup)
                backup.chmod(stat.S_IMODE(destination.stat().st_mode))
                previous_files[destination] = backup
        for source, destination in (
            (bundle / EXPECTED_FILES["qdev-controller-verify-admission"], launcher),
            (bundle / EXPECTED_FILES["qazcoop-update"], hook),
        ):
            staged = destination.with_name(f".{destination.name}.{os.getpid()}.new")
            shutil.copyfile(source, staged)
            staged.chmod(0o755)
            os.replace(staged, destination)
        subprocess.run([str(launcher), "--help"], check=True, capture_output=True)
        if old_trust.exists():
            shutil.rmtree(old_trust)
    except Exception:
        if trust_root.exists():
            shutil.rmtree(trust_root)
        if old_trust.exists():
            os.replace(old_trust, trust_root)
        for destination in (launcher, hook):
            previous_backup = previous_files.get(destination)
            if previous_backup is not None:
                os.replace(previous_backup, destination)
            else:
                destination.unlink(missing_ok=True)
        shutil.rmtree(version_root, ignore_errors=True)
        raise
    finally:
        shutil.rmtree(trust_tmp, ignore_errors=True)
        shutil.rmtree(backups, ignore_errors=True)
    return revision


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate-repository", type=Path, required=True)
    parser.add_argument("--controller-bundle", type=Path, required=True)
    args = parser.parse_args()
    revision = install_bundle(
        args.candidate_repository,
        args.controller_bundle.resolve(strict=True),
    )
    print(f"qazcoop_release_guard_installed={revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
