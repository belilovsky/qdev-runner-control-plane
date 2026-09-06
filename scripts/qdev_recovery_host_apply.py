#!/usr/bin/python3
"""Apply one controller-built recovery-host enrolment bundle from stdin.

The script is copied from the active controller release to one fixed private
host path.  It accepts only the two compiled profiles, validates every bundle
member, keeps the existing binding as a rollback snapshot, and never prints
private configuration values.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

SHA = re.compile(r"^[0-9a-f]{40}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
INTERFACE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
SCHEMA = "qdev-recovery-host-enrol-result-v1"
BUNDLE_SCHEMA = "qdev-recovery-host-enrol-bundle-v1"
ROOT = Path("/var/lib/qdev-runner-recovery")
CONFIG_ROOT = Path("/etc/qdev-runner-recovery")
MTLS_ROOT = CONFIG_ROOT / "mtls"
BACKUP_ROOT = ROOT / "enrol-backups"
INSTALL_ROOT = Path("/opt/qdev-runner-recovery")
PROFILES = {"platform", "qazstack"}
PAYLOAD_FILES = {
    "payload/platform.env",
    "payload/ca.pem",
    "payload/deploy/qdev-runner-recovery-platform.service",
    "payload/deploy/qdev-runner-recovery-qazstack.service",
    "payload/scripts/install_qdev_runner_recovery_host_agent.sh",
    "payload/scripts/qdev_runner_recovery_host_agent.py",
}
CONFIG_KEYS = {
    "QDEV_RECOVERY_CONTROLLER_URL",
    "QDEV_RECOVERY_AGENT_CERT",
    "QDEV_RECOVERY_AGENT_KEY",
    "QDEV_RECOVERY_CONTROLLER_CA",
    "QDEV_RECOVERY_COMMAND_VERIFICATION_KEY",
    "QDEV_RECOVERY_RECONCILE_SIGNING_KEY",
    "QDEV_RECOVERY_STATE_PATH",
    "QDEV_RECOVERY_LOCK_PATH",
    "QDEV_RECOVERY_RECEIPTS_DIR",
    "QDEV_RECOVERY_EXPECTED_CONTROLLER_REVISION",
    "QDEV_RECOVERY_EXPECTED_CONTROLLER_RELEASE_DIGEST",
    "QDEV_RECOVERY_EXPECTED_POLICY_DIGEST",
    "QDEV_RECOVERY_EXPECTED_AGENT_RELEASE_DIGEST",
    "QDEV_RECOVERY_EXPECTED_INTERFACE_VERSION",
    "QDEV_RECOVERY_EXPECTED_INTERFACE_DIGEST",
}


class ApplyError(RuntimeError):
    pass


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _root_regular(path: Path, *, private: bool) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_uid != 0
        or (private and stat.S_IMODE(metadata.st_mode) & 0o077)
        or (not private and stat.S_IMODE(metadata.st_mode) & 0o022)
    ):
        raise ApplyError("host_file_permissions_invalid")


def _run(command: list[str], *, input_bytes: bytes | None = None) -> bytes:
    completed = subprocess.run(
        command,
        input=input_bytes,
        capture_output=True,
        check=False,
        timeout=120,
        env={
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
            "PYTHONNOUSERSITE": "1",
        },
    )
    if completed.returncode != 0:
        raise ApplyError("fixed_native_command_failed")
    return completed.stdout


def _read_bundle(max_bytes: int) -> tuple[dict[str, Any], dict[str, bytes]]:
    payload = sys.stdin.buffer.read(max_bytes + 1)
    if not payload or len(payload) > max_bytes:
        raise ApplyError("bundle_size_invalid")
    files: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=io.BytesIO(payload), mode="r:gz") as archive:
            members = archive.getmembers()
            names = {member.name for member in members}
            expected = {"manifest.json"} | PAYLOAD_FILES
            if names != expected or len(members) != len(expected):
                raise ApplyError("bundle_members_invalid")
            for member in members:
                if (
                    not member.isfile()
                    or member.issym()
                    or member.islnk()
                    or member.name.startswith("/")
                    or ".." in Path(member.name).parts
                    or member.size < 1
                    or member.size > 2 * 1024 * 1024
                ):
                    raise ApplyError("bundle_member_unsafe")
                source = archive.extractfile(member)
                if source is None:
                    raise ApplyError("bundle_member_unreadable")
                files[member.name] = source.read()
    except (tarfile.TarError, OSError) as error:
        raise ApplyError("bundle_invalid") from error
    try:
        manifest = json.loads(files["manifest.json"])
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApplyError("bundle_manifest_invalid") from error
    if not isinstance(manifest, dict):
        raise ApplyError("bundle_manifest_invalid")
    return manifest, files


def _validate_manifest(manifest: dict[str, Any], files: dict[str, bytes], profile: str) -> None:
    expected_fields = {
        "schema",
        "profile",
        "controller_revision",
        "controller_release_digest",
        "policy_digest",
        "agent_release_digest",
        "interface_version",
        "interface_digest",
        "expected_agent_certificate_sha256",
        "files",
    }
    digests = manifest.get("files")
    if (
        set(manifest) != expected_fields
        or manifest.get("schema") != BUNDLE_SCHEMA
        or manifest.get("profile") != profile
        or not isinstance(manifest.get("controller_revision"), str)
        or SHA.fullmatch(manifest["controller_revision"]) is None
        or not isinstance(manifest.get("controller_release_digest"), str)
        or DIGEST.fullmatch(manifest["controller_release_digest"]) is None
        or not isinstance(manifest.get("policy_digest"), str)
        or DIGEST.fullmatch(manifest["policy_digest"]) is None
        or not isinstance(manifest.get("agent_release_digest"), str)
        or DIGEST.fullmatch(manifest["agent_release_digest"]) is None
        or not isinstance(manifest.get("interface_version"), str)
        or INTERFACE.fullmatch(manifest["interface_version"]) is None
        or not isinstance(manifest.get("interface_digest"), str)
        or HEX.fullmatch(manifest["interface_digest"]) is None
        or not isinstance(manifest.get("expected_agent_certificate_sha256"), str)
        or HEX.fullmatch(manifest["expected_agent_certificate_sha256"]) is None
        or not isinstance(digests, dict)
        or set(digests) != PAYLOAD_FILES
    ):
        raise ApplyError("bundle_manifest_invalid")
    for name in PAYLOAD_FILES:
        expected_digest = digests.get(name)
        if (
            not isinstance(expected_digest, str)
            or DIGEST.fullmatch(expected_digest) is None
            or expected_digest != f"sha256:{_sha256(files[name])}"
        ):
            raise ApplyError("bundle_digest_mismatch")


def _parse_config(payload: bytes, manifest: dict[str, Any], profile: str) -> None:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise ApplyError("config_invalid") from error
    values: dict[str, str] = {}
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or not key or not value or key in values:
            raise ApplyError("config_invalid")
        values[key] = value
    expected_paths = {
        "QDEV_RECOVERY_CONTROLLER_URL": "https://worker.ci.qdev.run",
        "QDEV_RECOVERY_AGENT_CERT": str(MTLS_ROOT / "agent-cert.pem"),
        "QDEV_RECOVERY_AGENT_KEY": str(MTLS_ROOT / "agent-key.pem"),
        "QDEV_RECOVERY_CONTROLLER_CA": str(MTLS_ROOT / "ca.pem"),
        "QDEV_RECOVERY_STATE_PATH": str(ROOT / f"{profile}-state.json"),
        "QDEV_RECOVERY_LOCK_PATH": f"/run/qdev-runner-recovery/{profile}.lock",
        "QDEV_RECOVERY_RECEIPTS_DIR": str(ROOT / "receipts"),
        "QDEV_RECOVERY_EXPECTED_CONTROLLER_REVISION": manifest["controller_revision"],
        "QDEV_RECOVERY_EXPECTED_CONTROLLER_RELEASE_DIGEST": manifest[
            "controller_release_digest"
        ].removeprefix("sha256:"),
        "QDEV_RECOVERY_EXPECTED_POLICY_DIGEST": manifest["policy_digest"],
        "QDEV_RECOVERY_EXPECTED_AGENT_RELEASE_DIGEST": manifest["agent_release_digest"],
        "QDEV_RECOVERY_EXPECTED_INTERFACE_VERSION": manifest["interface_version"],
        "QDEV_RECOVERY_EXPECTED_INTERFACE_DIGEST": manifest["interface_digest"],
    }
    if (
        set(values) != CONFIG_KEYS
        or any(values.get(key) != value for key, value in expected_paths.items())
        or len(values.get("QDEV_RECOVERY_COMMAND_VERIFICATION_KEY", "")) < 32
        or len(values.get("QDEV_RECOVERY_RECONCILE_SIGNING_KEY", "")) < 32
    ):
        raise ApplyError("config_invalid")


def _certificate_fingerprint(path: Path) -> str:
    return _sha256(_run(["openssl", "x509", "-in", str(path), "-outform", "DER"]))


def _matching_key(cert: Path, key: Path) -> bool:
    try:
        cert_public = _run(["openssl", "x509", "-in", str(cert), "-pubkey", "-noout"])
        key_public = _run(["openssl", "pkey", "-in", str(key), "-pubout"])
    except ApplyError:
        return False
    return cert_public == key_public


def _select_identity(expected: str) -> tuple[Path, Path]:
    candidates = [MTLS_ROOT / "agent-cert.pem"] + sorted(MTLS_ROOT.glob("agent-cert.pem.*.new"))
    matches: list[tuple[Path, Path]] = []
    for cert in candidates:
        key = Path(str(cert).replace("agent-cert.pem", "agent-key.pem", 1))
        try:
            _root_regular(cert, private=True)
            _root_regular(key, private=True)
            if _certificate_fingerprint(cert) == expected and _matching_key(cert, key):
                matches.append((cert, key))
        except (ApplyError, FileNotFoundError):
            continue
    identities = {(str(cert.resolve()), str(key.resolve())) for cert, key in matches}
    if not matches or len(identities) != 1:
        raise ApplyError("agent_identity_mismatch")
    return matches[0]


def _current_agent_digest() -> str:
    current = INSTALL_ROOT / "current"
    try:
        target = current.resolve(strict=True)
    except OSError:
        return "none"
    if target.parent == (INSTALL_ROOT / "releases").resolve() and HEX.fullmatch(target.name):
        return f"sha256:{target.name}"
    return "unknown"


def _current_release_exact(files: dict[str, bytes], expected_digest: str) -> bool:
    release_id = expected_digest.removeprefix("sha256:")
    current = INSTALL_ROOT / "current"
    try:
        target = current.resolve(strict=True)
        if target != (INSTALL_ROOT / "releases" / release_id).resolve(strict=True):
            return False
        for name in PAYLOAD_FILES - {"payload/platform.env", "payload/ca.pem"}:
            artifact = target / name.removeprefix("payload/")
            _root_regular(artifact, private=False)
            if artifact.read_bytes() != files[name]:
                return False
    except (ApplyError, OSError):
        return False
    return True


def _atomic_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, 0, 0)
        os.replace(temporary, path)
    finally:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(temporary)


def _same(path: Path, payload: bytes) -> bool:
    try:
        _root_regular(path, private=True)
        return path.read_bytes() == payload
    except (ApplyError, OSError):
        return False


def _write_files(root: Path, files: dict[str, bytes]) -> None:
    for name in PAYLOAD_FILES - {"payload/platform.env", "payload/ca.pem"}:
        destination = root / name.removeprefix("payload/")
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(files[name])
        destination.chmod(0o755 if "/scripts/" in f"/{name}" else 0o644)


def _result(
    manifest: dict[str, Any], *, status: str, rollback_agent_release_digest: str
) -> dict[str, str]:
    return {
        "schema": SCHEMA,
        "status": status,
        "profile": str(manifest["profile"]),
        "controller_revision": str(manifest["controller_revision"]),
        "controller_release_digest": str(manifest["controller_release_digest"]),
        "agent_release_digest": str(manifest["agent_release_digest"]),
        "agent_certificate_sha256": str(manifest["expected_agent_certificate_sha256"]),
        "rollback_agent_release_digest": rollback_agent_release_digest,
    }


def apply(profile: str, self_sha256: str, max_bytes: int) -> dict[str, str]:
    if os.geteuid() != 0:
        raise ApplyError("root_identity_required")
    if profile not in PROFILES or HEX.fullmatch(self_sha256) is None:
        raise ApplyError("invocation_invalid")
    _root_regular(Path(__file__), private=False)
    if _sha256_file(Path(__file__)) != self_sha256:
        raise ApplyError("helper_identity_mismatch")
    manifest, files = _read_bundle(max_bytes)
    _validate_manifest(manifest, files, profile)
    config_payload = files["payload/platform.env"]
    _parse_config(config_payload, manifest, profile)
    cert, key = _select_identity(manifest["expected_agent_certificate_sha256"])
    with tempfile.TemporaryDirectory(prefix=".enrol-", dir=ROOT) as temporary:
        staging = Path(temporary)
        _write_files(staging, files)
        ca = staging / "ca.pem"
        ca.write_bytes(files["payload/ca.pem"])
        ca.chmod(0o600)
        _run(["openssl", "verify", "-CAfile", str(ca), str(cert)])
        unit = f"qdev-runner-recovery-{profile}.service"
        active = subprocess.run(
            ["systemctl", "is-active", "--quiet", unit],
            capture_output=True,
            check=False,
            timeout=15,
        )
        if active.returncode == 0:
            raise ApplyError("recovery_service_active")
        expected_agent = str(manifest["agent_release_digest"])
        rollback_agent = _current_agent_digest()
        if rollback_agent == "unknown":
            raise ApplyError("installed_agent_identity_invalid")
        installed_unit = Path("/etc/systemd/system") / unit
        exact_current = rollback_agent == expected_agent and _current_release_exact(
            files, expected_agent
        )
        exact_unit = (
            installed_unit.is_file()
            and not installed_unit.is_symlink()
            and installed_unit.read_bytes() == files[f"payload/deploy/{unit}"]
        )
        stable_cert = MTLS_ROOT / "agent-cert.pem"
        stable_key = MTLS_ROOT / "agent-key.pem"
        exact_identity = (
            cert == stable_cert
            and key == stable_key
            and _certificate_fingerprint(stable_cert)
            == manifest["expected_agent_certificate_sha256"]
        )
        if (
            exact_current
            and exact_unit
            and exact_identity
            and _same(CONFIG_ROOT / f"{profile}.env", config_payload)
            and _same(MTLS_ROOT / "ca.pem", files["payload/ca.pem"])
        ):
            return _result(
                manifest,
                status="already_completed",
                rollback_agent_release_digest=rollback_agent,
            )

        backup_id = (
            f"{profile}-{manifest['controller_revision'][:12]}-"
            f"{manifest['agent_release_digest'].removeprefix('sha256:')[:12]}"
        )
        backup = BACKUP_ROOT / backup_id
        backup.mkdir(parents=True, exist_ok=True, mode=0o700)
        if backup.is_symlink() or backup.stat().st_uid != 0 or backup.stat().st_mode & 0o077:
            raise ApplyError("backup_directory_unsafe")
        backups: dict[Path, Path] = {}
        absent: set[Path] = set()
        for original in (
            CONFIG_ROOT / f"{profile}.env",
            MTLS_ROOT / "ca.pem",
            stable_cert,
            stable_key,
            installed_unit,
        ):
            if original.exists() and not original.is_symlink():
                destination = backup / original.name
                if not destination.exists():
                    shutil.copy2(original, destination)
                    destination.chmod(0o600)
                backups[original] = destination
            elif not original.exists():
                absent.add(original)
            else:
                raise ApplyError("host_file_permissions_invalid")
        old_current = (
            (INSTALL_ROOT / "current").resolve() if (INSTALL_ROOT / "current").exists() else None
        )
        try:
            if cert != stable_cert:
                _atomic_private(stable_cert, cert.read_bytes())
                _atomic_private(stable_key, key.read_bytes())
            _atomic_private(MTLS_ROOT / "ca.pem", files["payload/ca.pem"])
            _atomic_private(CONFIG_ROOT / f"{profile}.env", config_payload)
            completed = subprocess.run(
                [
                    str(staging / "scripts/install_qdev_runner_recovery_host_agent.sh"),
                    "--profile",
                    profile,
                ],
                cwd=staging,
                capture_output=True,
                check=False,
                timeout=180,
                env={
                    "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                    "PYTHONNOUSERSITE": "1",
                },
            )
            if completed.returncode != 0 or _current_agent_digest() != expected_agent:
                raise ApplyError("host_agent_install_failed")
        except BaseException:
            for path in absent:
                with contextlib.suppress(FileNotFoundError):
                    path.unlink()
            for original, saved in backups.items():
                _atomic_private(original, saved.read_bytes())
                if original == installed_unit:
                    original.chmod(0o644)
            if old_current is not None:
                temporary_link = INSTALL_ROOT / f".current.rollback.{os.getpid()}"
                with contextlib.suppress(FileNotFoundError):
                    temporary_link.unlink()
                temporary_link.symlink_to(old_current)
                os.replace(temporary_link, INSTALL_ROOT / "current")
            else:
                with contextlib.suppress(FileNotFoundError):
                    (INSTALL_ROOT / "current").unlink()
            subprocess.run(
                ["systemctl", "daemon-reload"],
                capture_output=True,
                check=False,
                timeout=30,
            )
            raise
        return _result(
            manifest,
            status="completed",
            rollback_agent_release_digest=rollback_agent,
        )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--self-sha256", required=True)
    parser.add_argument("--max-bytes", type=int, default=4 * 1024 * 1024)
    arguments = parser.parse_args()
    if not 1024 <= arguments.max_bytes <= 8 * 1024 * 1024:
        raise ApplyError("invocation_invalid")
    print(
        json.dumps(
            apply(arguments.profile, arguments.self_sha256, arguments.max_bytes),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        ApplyError,
        FileNotFoundError,
        OSError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
