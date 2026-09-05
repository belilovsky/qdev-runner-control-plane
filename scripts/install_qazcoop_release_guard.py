#!/usr/bin/env python3
"""Install one root-owned QazCoop release guard bundle on its product host."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

EXPECTED_REPOSITORY = Path("/opt/qazcoop.git")
EXPECTED_REPOSITORY_ID = 1_357_887_516
EXPECTED_REPOSITORY_NAME = "belilovsky/qazcoop"
EXPECTED_REF = "refs/heads/codex/qazcoop-mvp"
LEGACY_HOOK_SHA256 = "ce9a0963eb84aa7c9775cfd73bce78d76195fc38a83463c99200eeb47fa593f2"
HOOK_MARKER = b"# QAZCOOP_RELEASE_GUARD_MANAGED_V1\n"
LAUNCHER_MARKER = b"# QAZCOOP_RELEASE_GUARD_LAUNCHER_MANAGED_V1\n"
EXPECTED_FILES = {
    "public.pem": Path("trust/public.pem"),
    "admission.schema.json": Path("trust/admission.schema.json"),
    "key-canary.json": Path("trust/key-canary.json"),
    "controller_admission.py": Path("lib/qdev_runner/controller_admission.py"),
    "qazcoop_release_guard.py": Path("lib/qdev_runner/qazcoop_release_guard.py"),
    "qdev_runner.__init__.py": Path("lib/qdev_runner/__init__.py"),
    "qdev-controller-verify-admission": Path("bin/qdev-controller-verify-admission"),
    "qazcoop-update": Path("bin/qazcoop-update"),
}
EXPECTED_DIRECTORIES = {
    Path("."),
    Path("trust"),
    Path("lib"),
    Path("lib/qdev_runner"),
    Path("bin"),
}
VERSION_FILES = {
    EXPECTED_FILES["controller_admission.py"]: 0o640,
    EXPECTED_FILES["qazcoop_release_guard.py"]: 0o640,
    EXPECTED_FILES["qdev_runner.__init__.py"]: 0o640,
    EXPECTED_FILES["qdev-controller-verify-admission"]: 0o750,
    EXPECTED_FILES["qazcoop-update"]: 0o750,
}
VERSION_DIRECTORIES = {Path("."), Path("lib"), Path("lib/qdev_runner"), Path("bin")}
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
SHA = re.compile(r"^[0-9a-f]{40}$")
SIGNATURE = re.compile(r"^[A-Za-z0-9_-]{86}$")


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def strict_json(path: Path) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise ValueError(f"JSON contains duplicate key {key}")
            value[key] = item
        return value

    def constant(value: str) -> None:
        raise ValueError(f"JSON contains forbidden constant {value}")

    try:
        value = json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=pairs,
            parse_constant=constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"cannot read strict JSON: {path.name}") from error
    if not isinstance(value, dict):
        raise ValueError(f"JSON must contain an object: {path.name}")
    return value


def _require_owner_controlled(path: Path, *, directory: bool = False) -> os.stat_result:
    status = path.lstat()
    expected_type = stat.S_ISDIR if directory else stat.S_ISREG
    if not expected_type(status.st_mode):
        raise ValueError(f"bundle entry has an invalid type: {path.name}")
    if status.st_uid not in {0, os.geteuid()} or stat.S_IMODE(status.st_mode) & 0o022:
        raise ValueError(f"bundle entry is not owner controlled: {path.name}")
    return status


def _exact_inventory(bundle: Path) -> None:
    _require_owner_controlled(bundle, directory=True)
    files: set[Path] = set()
    directories: set[Path] = {Path(".")}
    for root, names, filenames in os.walk(bundle, topdown=True, followlinks=False):
        root_path = Path(root)
        relative_root = root_path.relative_to(bundle)
        relative_root = relative_root if relative_root.parts else Path(".")
        _require_owner_controlled(root_path, directory=True)
        directories.add(relative_root)
        for name in names:
            candidate = root_path / name
            _require_owner_controlled(candidate, directory=True)
            directories.add(candidate.relative_to(bundle))
        for name in filenames:
            candidate = root_path / name
            _require_owner_controlled(candidate)
            files.add(candidate.relative_to(bundle))
    expected_files = {Path("bundle.json"), *EXPECTED_FILES.values()}
    if files != expected_files or directories != EXPECTED_DIRECTORIES:
        raise ValueError("bundle filesystem inventory is not exact")


def _public_key(path: Path) -> tuple[Ed25519PublicKey, str]:
    try:
        key = serialization.load_pem_public_key(path.read_bytes())
    except (OSError, ValueError) as error:
        raise ValueError("bundle public key is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("bundle public key must be Ed25519")
    raw = key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return key, "sha256:" + hashlib.sha256(raw).hexdigest()


def _verify_key_canary(bundle: Path, revision: str) -> None:
    key, key_id = _public_key(bundle / EXPECTED_FILES["public.pem"])
    canary = strict_json(bundle / EXPECTED_FILES["key-canary.json"])
    if set(canary) != {"payload", "signature"}:
        raise ValueError("bundle key canary fields are invalid")
    payload = canary["payload"]
    signature = canary["signature"]
    expected_payload = {
        "contract": "qazcoop-release-guard-key-canary/v1",
        "controller_revision": revision,
        "files": {
            name: digest(bundle / relative)
            for name, relative in sorted(EXPECTED_FILES.items())
            if name != "key-canary.json"
        },
        "public_key_id": key_id,
        "repository": {
            "id": EXPECTED_REPOSITORY_ID,
            "full_name": EXPECTED_REPOSITORY_NAME,
        },
    }
    if payload != expected_payload or not isinstance(signature, dict):
        raise ValueError("bundle key canary payload is invalid")
    if set(signature) != {"algorithm", "key_id", "value"}:
        raise ValueError("bundle key canary signature fields are invalid")
    value = signature["value"]
    if (
        signature["algorithm"] != "Ed25519"
        or signature["key_id"] != key_id
        or not isinstance(value, str)
        or SIGNATURE.fullmatch(value) is None
    ):
        raise ValueError("bundle key canary signature metadata is invalid")
    try:
        raw_signature = base64.urlsafe_b64decode(value + "==")
        key.verify(raw_signature, canonical(payload))
    except (ValueError, InvalidSignature) as error:
        raise ValueError("bundle key canary signature is invalid") from error


def validate_bundle(bundle: Path) -> dict[str, Any]:
    _exact_inventory(bundle)
    manifest = strict_json(bundle / "bundle.json")
    if set(manifest) != {"contract", "controller_revision", "repository", "files"}:
        raise ValueError("bundle manifest fields are invalid")
    if manifest["contract"] != "qazcoop-release-guard-trust-bundle/v1":
        raise ValueError("bundle contract is invalid")
    revision = manifest["controller_revision"]
    if not isinstance(revision, str) or SHA.fullmatch(revision) is None:
        raise ValueError("bundle controller revision is invalid")
    if manifest["repository"] != {
        "id": EXPECTED_REPOSITORY_ID,
        "full_name": EXPECTED_REPOSITORY_NAME,
        "protected_ref": EXPECTED_REF,
    }:
        raise ValueError("bundle repository identity is invalid")
    files = manifest["files"]
    if not isinstance(files, dict) or set(files) != set(EXPECTED_FILES):
        raise ValueError("bundle file inventory is invalid")
    for name, relative in EXPECTED_FILES.items():
        path = bundle / relative
        mode = stat.S_IMODE(path.lstat().st_mode)
        executable = name in {"qazcoop-update", "qdev-controller-verify-admission"}
        if executable != bool(mode & 0o111):
            raise ValueError(f"bundle executable mode is invalid: {name}")
        expected = files[name]
        if not isinstance(expected, str) or DIGEST.fullmatch(expected) is None:
            raise ValueError(f"bundle digest is invalid: {name}")
        if digest(path) != expected:
            raise ValueError(f"bundle digest mismatch: {name}")
    _verify_key_canary(bundle, revision)
    return manifest


def _managed_file(path: Path, marker: bytes, *, allow_legacy_hook: bool = False) -> str | None:
    if not path.exists() and not path.is_symlink():
        return None
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"existing managed path is not a regular file: {path}")
    content = path.read_bytes()
    if marker in content.splitlines(keepends=True)[:3]:
        return digest(path).removeprefix("sha256:")[:16]
    observed = hashlib.sha256(content).hexdigest()
    if allow_legacy_hook and observed == LEGACY_HOOK_SHA256:
        return "legacy-ce9a0963eb84"
    raise ValueError(f"refusing to replace unmanaged file: {path}")


def _copy_fixed(
    source: Path, destination: Path, *, mode: int, gid: int, uid: int = 0
) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    descriptor = os.open(destination, flags, 0o600)
    try:
        with source.open("rb") as source_handle, os.fdopen(
            descriptor, "wb", closefd=False
        ) as destination_handle:
            shutil.copyfileobj(source_handle, destination_handle)
            destination_handle.flush()
            os.fsync(destination_handle.fileno())
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    finally:
        os.close(descriptor)


def _staged_path(destination: Path, operation: str) -> Path:
    return destination.with_name(
        f".{destination.name}.{secrets.token_hex(16)}.{operation}"
    )


def _safe_root_directory(path: Path, *, mode: int, gid: int = 0) -> None:
    if path.exists() or path.is_symlink():
        status = path.lstat()
        if (
            not stat.S_ISDIR(status.st_mode)
            or stat.S_ISLNK(status.st_mode)
            or status.st_uid != 0
            or stat.S_IMODE(status.st_mode) & 0o022
        ):
            raise ValueError(f"managed directory is unsafe: {path}")
    else:
        path.mkdir(mode=mode)
    os.chown(path, 0, gid)
    path.chmod(mode)


def _validate_root_directory(path: Path) -> None:
    status = path.lstat()
    if (
        not stat.S_ISDIR(status.st_mode)
        or stat.S_ISLNK(status.st_mode)
        or status.st_uid != 0
        or stat.S_IMODE(status.st_mode) & 0o022
    ):
        raise ValueError(f"managed parent directory is unsafe: {path}")


def _validate_directory_chain(path: Path, anchor: Path, *, uid: int = 0) -> None:
    if path != anchor and anchor not in path.parents:
        raise ValueError("managed directory chain is outside its trust anchor")
    current = path
    while True:
        status = current.lstat()
        if (
            not stat.S_ISDIR(status.st_mode)
            or stat.S_ISLNK(status.st_mode)
            or status.st_uid != uid
            or stat.S_IMODE(status.st_mode) & 0o022
        ):
            raise ValueError(f"managed directory chain is unsafe: {current}")
        if current == anchor:
            return
        current = current.parent


def _validate_installed_version(
    version_root: Path,
    manifest: dict[str, Any],
    *,
    gid: int,
    uid: int = 0,
) -> None:
    files: set[Path] = set()
    directories: set[Path] = {Path(".")}
    for root, names, filenames in os.walk(version_root, topdown=True, followlinks=False):
        root_path = Path(root)
        relative_root = root_path.relative_to(version_root)
        relative_root = relative_root if relative_root.parts else Path(".")
        status = root_path.lstat()
        if (
            not stat.S_ISDIR(status.st_mode)
            or stat.S_ISLNK(status.st_mode)
            or status.st_uid != uid
            or status.st_gid != gid
            or stat.S_IMODE(status.st_mode) != 0o750
        ):
            raise ValueError(f"installed guard directory metadata is invalid: {relative_root}")
        directories.add(relative_root)
        for name in names:
            path = root_path / name
            child_status = path.lstat()
            if not stat.S_ISDIR(child_status.st_mode) or stat.S_ISLNK(child_status.st_mode):
                raise ValueError(f"installed guard directory type is invalid: {path}")
            directories.add(path.relative_to(version_root))
        for name in filenames:
            path = root_path / name
            relative = path.relative_to(version_root)
            child_status = path.lstat()
            if (
                not stat.S_ISREG(child_status.st_mode)
                or stat.S_ISLNK(child_status.st_mode)
                or child_status.st_uid != uid
                or child_status.st_gid != gid
                or child_status.st_nlink != 1
                or stat.S_IMODE(child_status.st_mode) != VERSION_FILES.get(relative)
            ):
                raise ValueError(f"installed guard file metadata is invalid: {relative}")
            files.add(relative)
    if files != set(VERSION_FILES) or directories != VERSION_DIRECTORIES:
        raise ValueError("installed guard filesystem inventory is not exact")
    manifest_files = manifest["files"]
    for name, relative in EXPECTED_FILES.items():
        if relative not in VERSION_FILES:
            continue
        if digest(version_root / relative) != manifest_files[name]:
            raise ValueError(f"installed guard digest mismatch: {name}")


def _identity_can_traverse(path: Path, uid: int, gid: int) -> bool:
    if uid == 0:
        return True
    status = path.stat()
    mode = stat.S_IMODE(status.st_mode)
    if uid == status.st_uid:
        return bool(mode & stat.S_IXUSR)
    if gid == status.st_gid:
        return bool(mode & stat.S_IXGRP)
    return bool(mode & stat.S_IXOTH)


def _backup_managed_file(source: Path, destination: Path, *, gid: int) -> None:
    if destination.exists() or destination.is_symlink():
        if destination.is_symlink() or not destination.is_file():
            raise ValueError(f"managed backup path is invalid: {destination}")
        status = destination.stat()
        if (
            status.st_uid != 0
            or stat.S_IMODE(status.st_mode) & 0o022
            or status.st_nlink != 1
            or digest(destination) != digest(source)
        ):
            raise ValueError(f"managed backup does not match current file: {destination}")
        return
    _copy_fixed(
        source,
        destination,
        mode=stat.S_IMODE(source.stat().st_mode),
        gid=gid,
    )


def _restore_file(destination: Path, backup: Path | None) -> None:
    if backup is None:
        destination.unlink(missing_ok=True)
        return
    staged = _staged_path(destination, "restore")
    try:
        status = backup.stat()
        _copy_fixed(
            backup,
            staged,
            mode=stat.S_IMODE(status.st_mode),
            gid=status.st_gid,
            uid=status.st_uid,
        )
        os.replace(staged, destination)
    finally:
        staged.unlink(missing_ok=True)


def _backup_state_id(hook: Path, launcher: Path) -> str:
    state = {
        "hook": digest(hook) if hook.exists() else None,
        "launcher": digest(launcher) if launcher.exists() else None,
    }
    return "sha256-" + hashlib.sha256(canonical(state)).hexdigest()


def _run_as_identity(command: list[str], uid: int, gid: int) -> None:
    prefix: list[str] = []
    if (uid, gid) != (os.geteuid(), os.getegid()):
        prefix = [
            "/usr/bin/setpriv",
            f"--reuid={uid}",
            f"--regid={gid}",
            "--clear-groups",
        ]
    subprocess.run([*prefix, *command], check=True, capture_output=True, text=True)


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
    candidate_status = candidate.stat()
    receive_uid, receive_gid = candidate_status.st_uid, candidate_status.st_gid
    version_root = Path("/usr/local/lib/qazcoop-release-guard") / revision
    trust_parent = Path("/etc/qazcoop")
    trust_root = trust_parent / "release-controller"
    launcher = Path("/usr/local/sbin/qdev-controller-verify-admission")
    hook = candidate / "hooks/update"
    # The hook's directory cannot be protected if a less-trusted owner can
    # rename an ancestor after validation. The production bare repository and
    # its /opt anchor are root-controlled; root compromise is outside this
    # host-local guard's trust boundary.
    _validate_directory_chain(hook.parent, Path("/opt"))
    _validate_directory_chain(launcher.parent, Path("/usr"))
    _managed_file(hook, HOOK_MARKER, allow_legacy_hook=True)
    _managed_file(launcher, LAUNCHER_MARKER)
    version_preexisting = version_root.exists() or version_root.is_symlink()
    if version_preexisting:
        if version_root.is_symlink() or not version_root.is_dir():
            raise ValueError("installed guard revision path is invalid")
        _validate_installed_version(version_root, manifest, gid=receive_gid)

    backup_id = _backup_state_id(hook, launcher)
    backup_root = trust_parent / "release-controller-backups" / backup_id
    transaction_old_trust = trust_parent / f".release-controller.previous.{os.getpid()}"
    version_parent = version_root.parent
    version_tmp: Path | None = None
    trust_tmp: Path | None = None
    hook_backup: Path | None = None
    launcher_backup: Path | None = None
    trust_moved = False
    installed_trust = False
    installed_hook = False
    installed_launcher = False

    try:
        if not trust_parent.exists():
            trust_parent.mkdir(parents=True, mode=0o750)
            os.chown(trust_parent, 0, 0)
        _validate_root_directory(trust_parent)
        if not _identity_can_traverse(trust_parent, receive_uid, receive_gid):
            raise ValueError("repository receive identity cannot traverse /etc/qazcoop")
        backup_parent = backup_root.parent
        if not backup_parent.exists():
            backup_parent.mkdir(mode=0o750)
        _safe_root_directory(backup_parent, mode=0o750, gid=receive_gid)
        if not backup_root.exists():
            backup_root.mkdir(mode=0o750)
        _safe_root_directory(backup_root, mode=0o750, gid=receive_gid)
        if hook.exists():
            hook_backup = backup_root / "update"
            _backup_managed_file(hook, hook_backup, gid=receive_gid)
        if launcher.exists():
            launcher_backup = backup_root / "qdev-controller-verify-admission"
            _backup_managed_file(launcher, launcher_backup, gid=receive_gid)

        if not version_parent.exists():
            version_parent.mkdir(parents=True, mode=0o755)
        _safe_root_directory(version_parent, mode=0o755)
        # The launcher imports executable Python from this tree. Validate every
        # ancestor back to /usr after creation so /usr/local or /usr/local/lib
        # cannot be replaced by a less-trusted user between install and use.
        _validate_directory_chain(version_parent, Path("/usr"))
        if not version_preexisting:
            version_tmp = Path(tempfile.mkdtemp(prefix=f".{revision}.", dir=version_parent))
            for directory in (version_tmp / "lib/qdev_runner", version_tmp / "bin"):
                directory.mkdir(parents=True, exist_ok=True)
                os.chown(directory, 0, receive_gid)
                directory.chmod(0o750)
            for name in (
                "controller_admission.py",
                "qazcoop_release_guard.py",
                "qdev_runner.__init__.py",
            ):
                _copy_fixed(
                    bundle / EXPECTED_FILES[name],
                    version_tmp / EXPECTED_FILES[name],
                    mode=0o640,
                    gid=receive_gid,
                )
            for name in ("qdev-controller-verify-admission", "qazcoop-update"):
                _copy_fixed(
                    bundle / EXPECTED_FILES[name],
                    version_tmp / EXPECTED_FILES[name],
                    mode=0o750,
                    gid=receive_gid,
                )
            os.chown(version_tmp / "lib", 0, receive_gid)
            (version_tmp / "lib").chmod(0o750)
            os.chown(version_tmp, 0, receive_gid)
            version_tmp.chmod(0o750)
            os.replace(version_tmp, version_root)
            version_tmp = None

        trust_tmp = Path(tempfile.mkdtemp(prefix=".release-controller.", dir=trust_parent))
        trust_files = ("bundle.json", "public.pem", "admission.schema.json", "key-canary.json")
        for name in trust_files:
            relative = Path("bundle.json") if name == "bundle.json" else EXPECTED_FILES[name]
            source = bundle / relative
            _copy_fixed(source, trust_tmp / name, mode=0o640, gid=receive_gid)
        os.chown(trust_tmp, 0, receive_gid)
        trust_tmp.chmod(0o750)
        if transaction_old_trust.exists() or transaction_old_trust.is_symlink():
            raise ValueError("stale release-controller transaction directory exists")
        if trust_root.exists() or trust_root.is_symlink():
            if trust_root.is_symlink() or not trust_root.is_dir():
                raise ValueError("existing trust root is invalid")
            os.replace(trust_root, transaction_old_trust)
            trust_moved = True
        os.replace(trust_tmp, trust_root)
        trust_tmp = None
        installed_trust = True

        state_parent = Path("/var/lib/qazcoop")
        release_root = state_parent / "release"
        receipt_root = release_root / "admissions"
        replay_store = release_root / "consumed-admissions.sqlite3"
        if not state_parent.exists():
            _validate_root_directory(state_parent.parent)
            state_parent.mkdir(mode=0o750)
        for directory in (state_parent, release_root, receipt_root):
            _safe_root_directory(directory, mode=0o750, gid=receive_gid)
        flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(replay_store, flags, 0o600)
        except FileExistsError as error:
            status = replay_store.lstat()
            if (
                not stat.S_ISREG(status.st_mode)
                or stat.S_ISLNK(status.st_mode)
                or status.st_uid != receive_uid
                or status.st_gid != receive_gid
                or status.st_nlink != 1
                or stat.S_IMODE(status.st_mode) != 0o600
            ):
                raise ValueError("replay store path is invalid") from error
        else:
            os.close(descriptor)
        os.chown(replay_store, receive_uid, receive_gid)
        replay_store.chmod(0o600)

        # The hook moves first. A new hook paired with an old launcher rejects
        # updates, while the inverse pairing could accept an incomplete receipt.
        for source, destination in (
            (bundle / EXPECTED_FILES["qazcoop-update"], hook),
            (bundle / EXPECTED_FILES["qdev-controller-verify-admission"], launcher),
        ):
            staged = _staged_path(destination, "new")
            _copy_fixed(source, staged, mode=0o750, gid=receive_gid)
            os.replace(staged, destination)
            if destination == launcher:
                installed_launcher = True
            else:
                installed_hook = True

        _run_as_identity([str(launcher), "--help"], receive_uid, receive_gid)
        if trust_moved:
            shutil.rmtree(transaction_old_trust)
    except Exception:
        if installed_launcher:
            _restore_file(launcher, launcher_backup)
        if installed_hook and hook_backup is not None:
            _restore_file(hook, hook_backup)
        if installed_trust and (trust_root.exists() or trust_root.is_symlink()):
            shutil.rmtree(trust_root, ignore_errors=True)
        if trust_moved and transaction_old_trust.exists():
            os.replace(transaction_old_trust, trust_root)
        if not version_preexisting:
            shutil.rmtree(version_root, ignore_errors=True)
        raise
    finally:
        if version_tmp is not None:
            shutil.rmtree(version_tmp, ignore_errors=True)
        if trust_tmp is not None:
            shutil.rmtree(trust_tmp, ignore_errors=True)
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
