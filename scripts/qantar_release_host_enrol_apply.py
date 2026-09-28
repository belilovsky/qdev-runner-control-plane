#!/usr/bin/python3
"""Apply one controller-bound Qantar host-agent enrollment bundle on the host."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from io import BytesIO
from pathlib import Path, PurePosixPath
from typing import Any

SCHEMA = "qantar-release-host-enrol-bundle-v1"
RESULT_SCHEMA = "qantar-release-host-enrol-apply-result-v1"
HOST_IDENTITY = "qdev-host-agent:qantar-production-controller"
RELEASE_ROOT = Path("/opt/qdev-release-agents")
RELEASES = RELEASE_ROOT / "releases"
CURRENT = RELEASE_ROOT / "current"
MTLS_ROOT = Path("/etc/qdev-release-agents/mtls")
CONFIG = Path("/etc/qdev-release-agents/admin-platform.env")
DISPATCH_SECRET = Path("/etc/qdev-release-agents/dispatch.secret")
SERVICE = Path("/etc/systemd/system/qdev-release-qantar.service")
TIMER = Path("/etc/systemd/system/qdev-release-qantar.timer")
STATE_ROOT = Path("/var/lib/qdev-release-agents")
ENROLMENT_ROOT = STATE_ROOT / "enrolment" / "qantar"
AGENT_STATE = STATE_ROOT / "admin-platform" / "qantar.json"
NATIVE_ADAPTER = Path("/usr/local/sbin/qantar-controller-adapter")
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
FILES = {
    "agent.py",
    "native-adapter.py",
    "service.unit",
    "timer.unit",
    "admin-platform.env",
    "agent-cert.pem",
    "ca.pem",
    "dispatch.secret",
}
MAX_BUNDLE_BYTES = 16 * 1024 * 1024


class ApplyError(RuntimeError):
    """A bounded enrollment operation failed without exposing private data."""


def _run(arguments: list[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            arguments,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=300,
            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ApplyError("fixed_host_command_unavailable") from error
    if result.returncode != 0:
        raise ApplyError("fixed_host_command_failed")
    return result.stdout


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _ensure_directory(path: Path, mode: int) -> None:
    if path == Path("/"):
        return
    parent = path.parent
    if not parent.exists():
        _ensure_directory(parent, 0o755)
    parent_info = parent.lstat()
    if (
        not stat.S_ISDIR(parent_info.st_mode)
        or stat.S_ISLNK(parent_info.st_mode)
        or parent_info.st_uid != 0
        or stat.S_IMODE(parent_info.st_mode) & 0o022
    ):
        raise ApplyError("host_directory_parent_unsafe")
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise ApplyError("host_directory_unsafe")
    else:
        path.mkdir(mode=mode)
        os.chown(path, 0, 0)
    os.chmod(path, mode)


def _assert_safe_parents(path: Path) -> None:
    for parent in reversed(path.parents):
        if parent == Path("/"):
            continue
        try:
            info = parent.lstat()
        except FileNotFoundError:
            continue
        if (
            not stat.S_ISDIR(info.st_mode)
            or stat.S_ISLNK(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) & 0o022
        ):
            raise ApplyError("host_path_parent_unsafe")


def _atomic_write(path: Path, payload: bytes, mode: int) -> None:
    _assert_safe_parents(path)
    if path.exists() or path.is_symlink():
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise ApplyError("host_file_conflict")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), mode)
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.chown(temporary, 0, 0)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_symlink(target: Path, link: Path) -> None:
    if link.exists() and not link.is_symlink():
        raise ApplyError("host_current_path_conflict")
    if link.is_symlink():
        current = link.resolve(strict=True)
        if current.parent != RELEASES.resolve(strict=True) or not SHA.fullmatch(current.name):
            raise ApplyError("host_current_target_conflict")
        if current == target:
            return
    temporary = link.parent / f".{link.name}.{target.name}.new"
    if temporary.exists() or temporary.is_symlink():
        raise ApplyError("host_current_temporary_conflict")
    temporary.symlink_to(target)
    os.replace(temporary, link)
    directory = os.open(link.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _certificate_subject(path: Path) -> str:
    return (
        _run(
            [
                "/usr/bin/openssl",
                "x509",
                "-in",
                str(path),
                "-noout",
                "-subject",
                "-nameopt",
                "RFC2253",
            ]
        )
        .decode("ascii", "strict")
        .strip()
    )


def _validate_certificate_pair(cert: Path, key: Path, ca: Path) -> None:
    expected_subject = f"subject=CN={HOST_IDENTITY}"
    if _certificate_subject(cert) != expected_subject:
        raise ApplyError("host_certificate_identity_invalid")
    cert_public = _run(["/usr/bin/openssl", "x509", "-in", str(cert), "-pubkey", "-noout"]).strip()
    key_public = _run(["/usr/bin/openssl", "pkey", "-in", str(key), "-pubout"]).strip()
    if cert_public != key_public:
        raise ApplyError("host_certificate_key_mismatch")
    _run(["/usr/bin/openssl", "verify", "-purpose", "sslclient", "-CAfile", str(ca), str(cert)])


def _parse_bundle(raw: bytes, revision: str, release_digest: str) -> dict[str, bytes]:
    if not raw or len(raw) > MAX_BUNDLE_BYTES:
        raise ApplyError("enrolment_bundle_size_invalid")
    values: dict[str, bytes] = {}
    try:
        with tarfile.open(fileobj=BytesIO(raw), mode="r:gz") as archive:
            members = archive.getmembers()
            if len(members) != len(FILES) + 1:
                raise ApplyError("enrolment_bundle_member_count_invalid")
            for member in members:
                path = PurePosixPath(member.name)
                if (
                    path.is_absolute()
                    or len(path.parts) != 1
                    or path.name in {"", ".", ".."}
                    or not member.isfile()
                    or member.name in values
                    or member.size < 0
                    or member.size > 8 * 1024 * 1024
                ):
                    raise ApplyError("enrolment_bundle_member_invalid")
                stream = archive.extractfile(member)
                if stream is None:
                    raise ApplyError("enrolment_bundle_member_invalid")
                values[member.name] = stream.read(member.size + 1)
    except (OSError, tarfile.TarError) as error:
        raise ApplyError("enrolment_bundle_invalid") from error
    manifest_bytes = values.pop("manifest.json", None)
    if manifest_bytes is None or set(values) != FILES:
        raise ApplyError("enrolment_bundle_files_invalid")
    try:
        manifest = json.loads(manifest_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApplyError("enrolment_bundle_manifest_invalid") from error
    if (
        not isinstance(manifest, dict)
        or set(manifest)
        != {"schema", "controller_revision", "controller_release_digest", "host_identity", "files"}
        or manifest.get("schema") != SCHEMA
        or manifest.get("controller_revision") != revision
        or manifest.get("controller_release_digest") != release_digest
        or manifest.get("host_identity") != HOST_IDENTITY
        or not isinstance(manifest.get("files"), dict)
        or set(manifest["files"]) != FILES
    ):
        raise ApplyError("enrolment_bundle_manifest_invalid")
    for name, payload in values.items():
        if manifest["files"].get(name) != f"sha256:{_sha256(payload)}":
            raise ApplyError("enrolment_bundle_digest_mismatch")
    return values


def _validate_config(config: bytes) -> None:
    expected = {
        "QDEV_RELEASE_CONTROLLER_URL": "https://worker.ci.qdev.run",
        "QDEV_RELEASE_AGENT_CERT": str(MTLS_ROOT / "agent-cert.pem"),
        "QDEV_RELEASE_AGENT_KEY": str(MTLS_ROOT / "agent-key.pem"),
        "QDEV_RELEASE_CONTROLLER_CA": str(MTLS_ROOT / "ca.pem"),
        "QDEV_RELEASE_HOST_IDENTITY": HOST_IDENTITY,
        "QDEV_RELEASE_DISPATCH_SECRET_FILE": str(DISPATCH_SECRET),
    }
    values: dict[str, str] = {}
    try:
        lines = config.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ApplyError("enrolment_config_invalid") from error
    for line in lines:
        key, separator, value = line.partition("=")
        if not separator or not key or not value or key in values:
            raise ApplyError("enrolment_config_invalid")
        values[key] = value
    if values != expected:
        raise ApplyError("enrolment_config_identity_invalid")


def _validate_agent_state() -> None:
    try:
        info = AGENT_STATE.lstat()
        state = json.loads(AGENT_STATE.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApplyError("bootstrap_heartbeat_not_persisted") from error
    if (
        not stat.S_ISREG(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) != 0o600
        or not isinstance(state, dict)
        or state.get("schema") != "qdev-release-host-state-v1"
        or not isinstance(state.get("active_release"), dict)
        or not isinstance(state.get("rollback"), dict)
        or state["rollback"].get("verified") is not True
        or not SHA.fullmatch(str(state["active_release"].get("source_sha") or ""))
        or not SHA.fullmatch(str(state["rollback"].get("source_sha") or ""))
    ):
        raise ApplyError("bootstrap_heartbeat_not_persisted")


def _install_release(files: dict[str, bytes], revision: str, release_digest: str) -> None:
    release_dir = RELEASES / revision
    release_payloads = {
        "qdev_admin_platform_release_host_agent.py": files["agent.py"],
        "RELEASE.json": json.dumps(
            {
                "schema": "qdev-release-host-agent-payload-v1",
                "controller_revision": revision,
                "controller_release_digest": release_digest,
                "host_identity": HOST_IDENTITY,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n",
    }
    if release_dir.exists() or release_dir.is_symlink():
        info = release_dir.lstat()
        if not stat.S_ISDIR(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
            raise ApplyError("host_release_directory_conflict")
        for name, payload in release_payloads.items():
            existing = release_dir / name
            if existing.is_symlink() or not existing.is_file() or existing.read_bytes() != payload:
                raise ApplyError("host_release_directory_conflict")
    else:
        _ensure_directory(RELEASES, 0o700)
        temporary = Path(tempfile.mkdtemp(prefix=f".{revision}.", dir=RELEASES))
        try:
            os.chown(temporary, 0, 0)
            os.chmod(temporary, 0o700)
            for name, payload in release_payloads.items():
                output = temporary / name
                output.write_bytes(payload)
                os.chown(output, 0, 0)
                os.chmod(output, 0o755 if name.endswith(".py") else 0o644)
            os.rename(temporary, release_dir)
        finally:
            if temporary.exists():
                for child in temporary.iterdir():
                    child.unlink()
                temporary.rmdir()
    _atomic_symlink(release_dir, CURRENT)


def _systemd(arguments: list[str]) -> None:
    _run(["/usr/bin/systemctl", *arguments])


def _heartbeat_bootstrap() -> dict[str, Any]:
    agent = CURRENT / "qdev_admin_platform_release_host_agent.py"
    output = _run(
        [
            "/usr/bin/python3",
            "-I",
            str(agent),
            "--profile",
            "qantar",
            "--config",
            str(CONFIG),
            "--once",
            "--bootstrap-only",
        ]
    )
    try:
        value = json.loads(output)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ApplyError("bootstrap_heartbeat_response_invalid") from error
    if not isinstance(value, dict) or value.get("status") not in {"bootstrapped", "heartbeat"}:
        raise ApplyError("bootstrap_heartbeat_rejected")
    _validate_agent_state()
    return value


def _certificate_fingerprint(cert: Path) -> str:
    der = _run(["/usr/bin/openssl", "x509", "-in", str(cert), "-outform", "DER"])
    return hashlib.sha256(der).hexdigest()


def _apply(files: dict[str, bytes], revision: str, release_digest: str) -> dict[str, Any]:
    _validate_config(files["admin-platform.env"])
    _ensure_directory(RELEASE_ROOT, 0o700)
    _ensure_directory(RELEASES, 0o700)
    _ensure_directory(Path("/etc/qdev-release-agents"), 0o750)
    _ensure_directory(MTLS_ROOT, 0o700)
    _ensure_directory(Path("/var/lib/qdev-release-agents"), 0o700)
    _ensure_directory(Path("/var/lib/qdev-release-agents/admin-platform"), 0o700)
    _ensure_directory(ENROLMENT_ROOT, 0o700)

    key = MTLS_ROOT / "agent-key.pem"
    _assert_safe_parents(key)
    if key.is_symlink() or not key.is_file():
        raise ApplyError("host_agent_key_missing")
    key_info = key.lstat()
    if key_info.st_uid != 0 or stat.S_IMODE(key_info.st_mode) != 0o600:
        raise ApplyError("host_agent_key_permissions_invalid")

    with tempfile.TemporaryDirectory(prefix="qantar-enrol-", dir=ENROLMENT_ROOT) as name:
        work = Path(name)
        ca = work / "ca.pem"
        cert = work / "agent-cert.pem"
        ca.write_bytes(files["ca.pem"])
        cert.write_bytes(files["agent-cert.pem"])
        os.chmod(ca, 0o644)
        os.chmod(cert, 0o644)
        _validate_certificate_pair(cert, key, ca)

        agent_text = files["agent.py"].decode("utf-8")
        service_text = files["service.unit"].decode("utf-8")
        timer_text = files["timer.unit"].decode("utf-8")
        if (
            "--profile qantar" not in service_text
            or str(CURRENT / "qdev_admin_platform_release_host_agent.py") not in service_text
            or str(CONFIG) not in service_text
            or "OnUnitActiveSec=30s" not in timer_text
            or "Unit=qdev-release-qantar.service" not in timer_text
            or "--bootstrap-only" not in agent_text
        ):
            raise ApplyError("enrolment_service_contract_invalid")

    _install_release(files, revision, release_digest)
    _atomic_write(NATIVE_ADAPTER, files["native-adapter.py"], 0o755)
    _atomic_write(SERVICE, files["service.unit"], 0o644)
    _atomic_write(TIMER, files["timer.unit"], 0o644)
    _atomic_write(MTLS_ROOT / "agent-cert.pem", files["agent-cert.pem"], 0o644)
    _atomic_write(MTLS_ROOT / "ca.pem", files["ca.pem"], 0o644)
    _atomic_write(CONFIG, files["admin-platform.env"], 0o600)
    secret = files["dispatch.secret"].strip()
    if not 32 <= len(secret) <= 4096:
        raise ApplyError("host_dispatch_secret_size_invalid")
    _atomic_write(DISPATCH_SECRET, secret + b"\n", 0o600)
    _systemd(["daemon-reload"])
    heartbeat = _heartbeat_bootstrap()
    _systemd(["enable", "--now", "qdev-release-qantar.timer"])
    _run(["/usr/bin/systemctl", "is-enabled", "--quiet", "qdev-release-qantar.timer"])
    _run(["/usr/bin/systemctl", "is-active", "--quiet", "qdev-release-qantar.timer"])
    fingerprint = _certificate_fingerprint(MTLS_ROOT / "agent-cert.pem")
    result = {
        "schema": "qdev-release-host-agent-enrolment-receipt-v1",
        "controller_revision": revision,
        "controller_release_digest": release_digest,
        "host_identity": HOST_IDENTITY,
        "bootstrap_heartbeat": "accepted",
        "timer_state": "active",
        "certificate_fingerprint": fingerprint,
        "active_source_sha": str(
            (heartbeat.get("active_release") or {}).get("source_sha")
            or heartbeat.get("source_sha")
            or "unknown"
        ),
    }
    receipt = json.dumps(result, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    _atomic_write(ENROLMENT_ROOT / "receipt.json", receipt, 0o600)
    return result


def _self_check(expected: str) -> None:
    if not HEX.fullmatch(expected):
        raise ApplyError("helper_identity_invalid")
    if _sha256(Path(__file__).read_bytes()) != expected:
        raise ApplyError("helper_digest_mismatch")


def _prepare(revision: str, release_digest: str) -> dict[str, Any]:
    if not SHA.fullmatch(revision) or not DIGEST.fullmatch(release_digest):
        raise ApplyError("controller_identity_invalid")
    _ensure_directory(Path("/etc/qdev-release-agents"), 0o750)
    _ensure_directory(MTLS_ROOT, 0o700)
    _ensure_directory(ENROLMENT_ROOT, 0o700)
    key = MTLS_ROOT / "agent-key.pem"
    cert = MTLS_ROOT / "agent-cert.pem"
    ca = MTLS_ROOT / "ca.pem"
    for path in (key, cert, ca):
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode) or info.st_uid != 0:
                raise ApplyError("host_mtls_file_conflict")
    if cert.exists():
        if _certificate_subject(cert) != f"subject=CN={HOST_IDENTITY}":
            raise ApplyError("host_certificate_identity_conflict")
        if not key.is_file() or not ca.is_file():
            raise ApplyError("host_mtls_pair_incomplete")
        try:
            _validate_certificate_pair(cert, key, ca)
            _run(
                [
                    "/usr/bin/openssl",
                    "x509",
                    "-in",
                    str(cert),
                    "-checkend",
                    str(30 * 86400),
                    "-noout",
                ]
            )
            return {
                "state": "certificate_ready",
                "certificate_b64": base64.b64encode(cert.read_bytes()).decode("ascii"),
            }
        except ApplyError:
            # A valid target key may receive a replacement certificate from the same CA.
            pass
    if key.exists():
        key_info = key.lstat()
        if stat.S_IMODE(key_info.st_mode) != 0o600:
            raise ApplyError("host_agent_key_permissions_invalid")
        selected_key = key
    else:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".agent-key.", dir=MTLS_ROOT)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            _run(["/usr/bin/openssl", "genrsa", "-out", str(temporary), "3072"])
            os.chmod(temporary, 0o600)
            os.chown(temporary, 0, 0)
            os.replace(temporary, key)
        finally:
            temporary.unlink(missing_ok=True)
        selected_key = key
    descriptor, csr_name = tempfile.mkstemp(prefix=".agent.", suffix=".csr", dir=ENROLMENT_ROOT)
    os.close(descriptor)
    csr = Path(csr_name)
    try:
        _run(
            [
                "/usr/bin/openssl",
                "req",
                "-new",
                "-sha256",
                "-key",
                str(selected_key),
                "-subj",
                f"/CN={HOST_IDENTITY}",
                "-out",
                str(csr),
            ]
        )
        return {
            "state": "csr_required",
            "csr_b64": base64.b64encode(csr.read_bytes()).decode("ascii"),
        }
    finally:
        csr.unlink(missing_ok=True)


def _main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices={"prepare", "install"}, required=True)
    parser.add_argument("--self-sha256", required=True)
    parser.add_argument("--controller-revision", required=True)
    parser.add_argument("--controller-release-digest", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ApplyError("root_identity_required")
    _self_check(args.self_sha256)
    if args.phase == "prepare":
        result = _prepare(args.controller_revision, args.controller_release_digest)
    else:
        result = _apply(
            _parse_bundle(
                sys.stdin.buffer.read(MAX_BUNDLE_BYTES + 1),
                args.controller_revision,
                args.controller_release_digest,
            ),
            args.controller_revision,
            args.controller_release_digest,
        )
    print(
        json.dumps(
            {"schema": RESULT_SCHEMA, "status": "completed", "result": result},
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(_main())
    except (
        ApplyError,
        OSError,
        UnicodeDecodeError,
        ValueError,
        KeyError,
        json.JSONDecodeError,
    ) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
