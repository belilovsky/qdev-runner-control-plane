#!/usr/bin/python3
"""Repair the one controller-registered QDev CI worker configuration.

This payload is intentionally not a general systemd editor.  The controller
copies its exact, hashed source to the one registered host and this program
only removes the stale, controller-created position overlays that mask the
base worker environment.  It makes a root-private snapshot first and restores
it automatically if the service cannot be started again.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = "qdev-ci-worker-configuration-recovery-result-v1"
SERVICE_UNIT = "qdev-runner-worker.service"
DROPIN_ROOT = Path("/etc/systemd/system/qdev-runner-worker.service.d")
BASE_ENV = Path("/etc/qdev-runner/worker.env")
POSITION_ENV_ROOT = Path("/etc/qdev-runner")
STATE_ROOT = Path("/var/lib/qdev-runner/worker-configuration-recovery")
SYSTEMCTL = Path("/usr/bin/systemctl")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
STALE_DROPIN = re.compile(r"^~*position-[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.conf$")
STALE_ENV = re.compile(r"^worker\.position-[A-Za-z0-9][A-Za-z0-9._-]{0,180}\.env$")
REQUIRED_ENV = {
    "QDEV_WORKER_NAME": "srv1879763-primary",
    "QDEV_WORKER_TIER": "primary",
    "QDEV_WORKER_PROFILES": "qdev-ci,qdev-ci-browser,qdev-ci-docker",
    "QDEV_WORKER_CONCURRENCY": "1",
    "QDEV_WORKER_MIN_FREE_GIB": "30",
    "QDEV_WORKER_MAX_DISK_USED_PCT": "85",
}


class RecoveryError(RuntimeError):
    """The fixed recovery transition is not safe to perform."""


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _root_private_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise RecoveryError("recovery_state_permissions_invalid")


def _root_managed_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise RecoveryError("worker_configuration_permissions_invalid")


def _root_regular(path: Path, *, private: bool) -> Any:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or (private and stat.S_IMODE(metadata.st_mode) & 0o077)
        or (not private and stat.S_IMODE(metadata.st_mode) & 0o022)
    ):
        raise RecoveryError("worker_configuration_permissions_invalid")
    return metadata


def _base_environment() -> None:
    _root_regular(BASE_ENV, private=True)
    values: dict[str, str] = {}
    for raw_line in BASE_ENV.read_text(encoding="utf-8").splitlines():
        if not raw_line or raw_line.startswith("#"):
            continue
        key, separator, value = raw_line.partition("=")
        if not separator or not key or not value or key in values:
            raise RecoveryError("worker_base_environment_invalid")
        values[key] = value
    if any(values.get(key) != expected for key, expected in REQUIRED_ENV.items()):
        raise RecoveryError("worker_base_environment_identity_invalid")


def _safe_stale_files(root: Path, pattern: re.Pattern[str]) -> list[Path]:
    if not root.exists():
        return []
    _root_managed_directory(root)
    files: list[Path] = []
    for path in sorted(root.iterdir(), key=lambda candidate: candidate.name):
        if not pattern.fullmatch(path.name):
            raise RecoveryError("unrecognized_worker_overlay")
        _root_regular(path, private=False)
        files.append(path)
    return files


def _position_envs() -> list[Path]:
    files: list[Path] = []
    for path in sorted(POSITION_ENV_ROOT.glob("worker.position-*.env"), key=lambda item: item.name):
        if not STALE_ENV.fullmatch(path.name):
            raise RecoveryError("unrecognized_worker_overlay")
        _root_regular(path, private=True)
        files.append(path)
    return files


def _ensure_state_root() -> None:
    if STATE_ROOT.exists():
        _root_private_directory(STATE_ROOT)
        return
    STATE_ROOT.mkdir(mode=0o700, parents=True)
    os.chmod(STATE_ROOT, 0o700)
    _root_private_directory(STATE_ROOT)


def _snapshot(files: list[Path]) -> tuple[Path, dict[str, Any]]:
    _ensure_state_root()
    identity = hashlib.sha256(
        "\n".join(f"{path}:{_sha256(path)}" for path in files).encode("utf-8")
    ).hexdigest()[:16]
    stamp = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    snapshot = STATE_ROOT / f"{stamp}-{identity}"
    snapshot.mkdir(mode=0o700)
    os.chmod(snapshot, 0o700)
    _root_private_directory(snapshot)
    archive = snapshot / "overlays.tar.gz"
    manifest_entries: list[dict[str, Any]] = []
    with tarfile.open(archive, mode="x:gz", format=tarfile.PAX_FORMAT) as bundle:
        for path in files:
            if path.parent == DROPIN_ROOT:
                name = f"dropins/{path.name}"
            elif path.parent == POSITION_ENV_ROOT:
                name = f"position-env/{path.name}"
            else:  # Defensive invariant; source code supplies only fixed roots.
                raise RecoveryError("worker_snapshot_path_invalid")
            metadata = _root_regular(path, private=path.parent == POSITION_ENV_ROOT)
            bundle.add(path, arcname=name, recursive=False)
            manifest_entries.append(
                {
                    "path": name,
                    "sha256": _sha256(path),
                    "mode": stat.S_IMODE(metadata.st_mode),
                }
            )
    os.chmod(archive, 0o600)
    manifest = {
        "schema": "qdev-ci-worker-configuration-snapshot-v1",
        "service_unit": SERVICE_UNIT,
        "base_environment_sha256": _sha256(BASE_ENV),
        "files": manifest_entries,
    }
    manifest_path = snapshot / "manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=True, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.chmod(manifest_path, 0o600)
    return snapshot, manifest


def _systemctl(*arguments: str) -> bool:
    completed = subprocess.run(
        [str(SYSTEMCTL), *arguments],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
        timeout=120,
        env={"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8"},
    )
    return completed.returncode == 0


def _service_active() -> bool:
    return _systemctl("is-active", "--quiet", SERVICE_UNIT)


def _restart_and_verify() -> bool:
    return _systemctl("daemon-reload") and _systemctl("restart", SERVICE_UNIT) and _service_active()


def _restore(snapshot: Path, manifest: dict[str, Any]) -> bool:
    archive = snapshot / "overlays.tar.gz"
    files = manifest.get("files")
    if not isinstance(files, list) or not archive.is_file():
        return False
    temporary = Path(tempfile.mkdtemp(prefix="restore-", dir=snapshot))
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            expected = {str(entry.get("path")) for entry in files if isinstance(entry, dict)}
            members = bundle.getmembers()
            if {member.name for member in members} != expected or any(
                not member.isfile() or member.issym() or member.islnk() for member in members
            ):
                return False
            bundle.extractall(temporary, members=members, filter="data")
        for entry in files:
            if not isinstance(entry, dict):
                return False
            relative = entry.get("path")
            digest = entry.get("sha256")
            mode = entry.get("mode")
            if (
                not isinstance(relative, str)
                or relative.startswith("/")
                or ".." in Path(relative).parts
                or not isinstance(digest, str)
                or SHA256.fullmatch(digest) is None
                or isinstance(mode, bool)
                or not isinstance(mode, int)
            ):
                return False
            source = temporary / relative
            if not source.is_file() or _sha256(source) != digest:
                return False
            if relative.startswith("dropins/"):
                destination = DROPIN_ROOT / Path(relative).name
            elif relative.startswith("position-env/"):
                destination = POSITION_ENV_ROOT / Path(relative).name
            else:
                return False
            if destination.exists():
                return False
            if destination.parent == DROPIN_ROOT:
                if destination.parent.exists():
                    _root_managed_directory(destination.parent)
                else:
                    destination.parent.mkdir(mode=0o755, parents=True)
                    os.chmod(destination.parent, 0o755)  # noqa: S103 - fixed systemd drop-in mode
                    _root_managed_directory(destination.parent)
            elif destination.parent == POSITION_ENV_ROOT:
                _root_managed_directory(destination.parent)
            else:
                return False
            shutil.copyfile(source, destination)
            os.chmod(destination, mode)
            _root_regular(destination, private=destination.parent == POSITION_ENV_ROOT)
        return _restart_and_verify()
    except (OSError, tarfile.TarError, subprocess.TimeoutExpired):
        return False
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def _result(
    *,
    status: str,
    snapshot: Path | None,
    removed_dropins: int,
    removed_position_envs: int,
    error_code: str | None = None,
    rollback_status: str | None = None,
) -> dict[str, Any]:
    value: dict[str, Any] = {
        "schema": SCHEMA,
        "status": status,
        "service_unit": SERVICE_UNIT,
        "removed_dropins": removed_dropins,
        "removed_position_envs": removed_position_envs,
    }
    if snapshot is not None:
        value["snapshot_id"] = snapshot.name
    if error_code is not None:
        value["error_code"] = error_code
    if rollback_status is not None:
        value["rollback_status"] = rollback_status
    return value


def repair(expected_sha256: str) -> dict[str, Any]:
    if SHA256.fullmatch(expected_sha256) is None or _sha256(Path(__file__)) != expected_sha256:
        raise RecoveryError("payload_digest_mismatch")
    if os.geteuid() != 0:
        raise RecoveryError("root_identity_required")
    _base_environment()
    dropins = _safe_stale_files(DROPIN_ROOT, STALE_DROPIN)
    position_envs = _position_envs()
    if not dropins and not position_envs:
        if _service_active():
            return _result(
                status="already_completed",
                snapshot=None,
                removed_dropins=0,
                removed_position_envs=0,
            )
        return _result(
            status="failed",
            snapshot=None,
            removed_dropins=0,
            removed_position_envs=0,
            error_code="worker_service_inactive",
        )
    snapshot, manifest = _snapshot([*dropins, *position_envs])
    try:
        for path in [*dropins, *position_envs]:
            path.unlink()
        if _restart_and_verify():
            return _result(
                status="completed",
                snapshot=snapshot,
                removed_dropins=len(dropins),
                removed_position_envs=len(position_envs),
            )
    except (OSError, subprocess.TimeoutExpired):
        pass
    rollback = "restored" if _restore(snapshot, manifest) else "failed"
    return _result(
        status="failed",
        snapshot=snapshot,
        removed_dropins=len(dropins),
        removed_position_envs=len(position_envs),
        error_code="worker_service_restart_failed",
        rollback_status=rollback,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Repair the fixed QDev CI worker configuration.")
    parser.add_argument("--expected-sha256", required=True)
    arguments = parser.parse_args(argv)
    try:
        result = repair(arguments.expected_sha256)
    except (RecoveryError, OSError, UnicodeDecodeError, subprocess.TimeoutExpired) as error:
        result = _result(
            status="failed",
            snapshot=None,
            removed_dropins=0,
            removed_position_envs=0,
            error_code=str(error),
        )
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
