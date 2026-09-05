#!/usr/bin/env python3
"""Recover one allowlisted GitHub Actions runner from a signed controller command.

The agent is deliberately non-general: the two profiles, repositories, runner
names, services, paths, actions and permanent labels are compiled below.  A
root-owned private configuration supplies only mTLS material, signing keys and
release bindings.  No controller response can select a shell command, host,
service, filesystem path or additional runner.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import hmac
import json
import os
import pwd
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

_SHA = re.compile(r"^[0-9a-f]{40}$")
_SHA256 = re.compile(r"^[0-9a-f]{64}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$")
_CONTROLLER_HOST = "worker.ci.qdev.run"
_RUNNER_VERSION = "2.336.0"
_RUNNER_ARCHIVE = f"actions-runner-linux-x64-{_RUNNER_VERSION}.tar.gz"
_RUNNER_URL = (
    f"https://github.com/actions/runner/releases/download/v{_RUNNER_VERSION}/{_RUNNER_ARCHIVE}"
)
_RUNNER_ARCHIVE_SHA256 = "04cf0be1aff4c3ec3554466c39124ca250e3effd8873bb7e8d68535aa9505d5d"
STATE_SCHEMA = "qdev-runner-recovery-host-state-v1"
RECEIPT_SCHEMA = "qdev-runner-recovery-host-receipt-v1"


class AgentError(RuntimeError):
    """The signed instruction or local fixed target is unsafe to act upon."""


class ExecutionFailure(AgentError):
    """A native attempt reached a terminal, evidence-bearing failure."""

    def __init__(self, message: str, *, outcome: str, proof: dict[str, Any]) -> None:
        super().__init__(message)
        self.outcome = outcome
        self.proof = proof


@dataclass(frozen=True)
class Profile:
    name: str
    target_id: str
    worker_name: str
    repository: str
    labels: tuple[str, ...]
    recovery_action: str
    runner_root: Path
    runner_user: str
    service_unit: str
    expected_provider_runner_id: int | None = None
    base_unit_sha256: str | None = None
    capacity_dropin: Path | None = None
    capacity_dropin_sha256: str | None = None
    retirement_marker: Path | None = None
    retirement_marker_sha256: str | None = None
    retirement_dropin: Path | None = None
    retirement_dropin_sha256: str | None = None


PROFILES = {
    "platform": Profile(
        name="platform",
        target_id="qdev-platform-ci-187",
        worker_name="qdev-platform-ci-187",
        repository="belilovsky/platform-portal",
        labels=("self-hosted", "Linux", "X64", "qdev-platform-ci"),
        recovery_action="restore_saved_configuration",
        runner_root=Path("/opt/github-runners/platform-ci"),
        runner_user="github-platform-ci",
        service_unit="actions.runner.belilovsky-platform-portal.qdev-platform-ci-187.service",
        expected_provider_runner_id=278,
        base_unit_sha256="2bc6a0ff6e6898d78dca07ed58ad3352919ad4e82b9a6d1dcaa61a15b63fa133",
        capacity_dropin=Path(
            "/etc/systemd/system/actions.runner.belilovsky-platform-portal."
            "qdev-platform-ci-187.service.d/90-capacity.conf"
        ),
        capacity_dropin_sha256=("820801e9cb71d6b4e4d2c188631f128cdc8594199b535fdbc93f2a3362e90b21"),
        retirement_marker=Path("/etc/qdev/platform-ci-direct-runner.disabled"),
        retirement_marker_sha256=(
            "25be27ba84fe941320e1c3144978b9a4e6f38e81f23421784ddbfba0227101d5"
        ),
        retirement_dropin=Path(
            "/etc/systemd/system/actions.runner.belilovsky-platform-portal."
            "qdev-platform-ci-187.service.d/99-qdev-gha-direct-runner-retired.conf"
        ),
        retirement_dropin_sha256=(
            "9ac6d5313a76257b76c400ce6c48bcab3e9bb4d568a6079aad7f5c0735427890"
        ),
    ),
    "qazstack": Profile(
        name="qazstack",
        target_id="qdev-qazstack-01",
        worker_name="qdev-qazstack-01",
        repository="belilovsky/qazstack",
        labels=("self-hosted", "Linux", "X64", "qdev-ci"),
        recovery_action="replace_existing_registration",
        runner_root=Path("/opt/github-runners/qazstack-ci"),
        runner_user="github-qazstack",
        service_unit="actions.runner.belilovsky-qazstack.qdev-qazstack-01.service",
    ),
}


@dataclass(frozen=True)
class Config:
    controller_url: str
    client_cert: Path
    client_key: Path
    controller_ca: Path
    command_verification_key: str
    reconcile_signing_key: str
    state_path: Path
    lock_path: Path
    receipts_dir: Path
    expected_controller_revision: str
    expected_controller_release_digest: str
    expected_policy_digest: str
    expected_agent_release_digest: str
    expected_interface_version: str
    expected_interface_digest: str


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _private(path: Path, *, required: bool = True) -> None:
    try:
        metadata = path.lstat()
    except FileNotFoundError as error:
        if required:
            raise AgentError(f"required private file is missing: {path}") from error
        return
    if (
        stat.S_ISLNK(metadata.st_mode)
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o077
    ):
        raise AgentError(f"file must be root-owned and private: {path}")


def load_config(path: Path) -> Config:
    _private(path)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if (
            not separator
            or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key)
            or not value
            or "\x00" in value
            or key in values
        ):
            raise AgentError("recovery agent configuration has an invalid line")
        values[key] = value
    expected = {
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
    if set(values) != expected:
        raise AgentError("recovery agent configuration keys are invalid")
    parsed = urlsplit(values["QDEV_RECOVERY_CONTROLLER_URL"])
    try:
        controller_port = parsed.port
    except ValueError as error:
        raise AgentError("controller URL has an invalid port") from error
    if (
        parsed.scheme != "https"
        or parsed.hostname != _CONTROLLER_HOST
        or parsed.username
        or parsed.password
        or controller_port not in {None, 443}
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise AgentError("controller URL must be the fixed HTTPS mTLS edge")
    if len(values["QDEV_RECOVERY_COMMAND_VERIFICATION_KEY"]) < 32:
        raise AgentError("command verification key is too short")
    if len(values["QDEV_RECOVERY_RECONCILE_SIGNING_KEY"]) < 32:
        raise AgentError("reconcile signing key is too short")
    revision = values["QDEV_RECOVERY_EXPECTED_CONTROLLER_REVISION"]
    release_digest = values["QDEV_RECOVERY_EXPECTED_CONTROLLER_RELEASE_DIGEST"]
    policy_digest = values["QDEV_RECOVERY_EXPECTED_POLICY_DIGEST"]
    agent_digest = values["QDEV_RECOVERY_EXPECTED_AGENT_RELEASE_DIGEST"]
    interface_digest = values["QDEV_RECOVERY_EXPECTED_INTERFACE_DIGEST"]
    if not _SHA.fullmatch(revision) or not _SHA256.fullmatch(release_digest):
        raise AgentError("controller release binding is invalid")
    if not _DIGEST.fullmatch(policy_digest) or not _DIGEST.fullmatch(agent_digest):
        raise AgentError("policy or agent release binding is invalid")
    if not _SHA256.fullmatch(interface_digest):
        raise AgentError("recovery interface digest is invalid")
    if not _IDENTIFIER.fullmatch(values["QDEV_RECOVERY_EXPECTED_INTERFACE_VERSION"]):
        raise AgentError("recovery interface version is invalid")
    config = Config(
        controller_url=values["QDEV_RECOVERY_CONTROLLER_URL"],
        client_cert=Path(values["QDEV_RECOVERY_AGENT_CERT"]),
        client_key=Path(values["QDEV_RECOVERY_AGENT_KEY"]),
        controller_ca=Path(values["QDEV_RECOVERY_CONTROLLER_CA"]),
        command_verification_key=values["QDEV_RECOVERY_COMMAND_VERIFICATION_KEY"],
        reconcile_signing_key=values["QDEV_RECOVERY_RECONCILE_SIGNING_KEY"],
        state_path=Path(values["QDEV_RECOVERY_STATE_PATH"]),
        lock_path=Path(values["QDEV_RECOVERY_LOCK_PATH"]),
        receipts_dir=Path(values["QDEV_RECOVERY_RECEIPTS_DIR"]),
        expected_controller_revision=revision,
        expected_controller_release_digest=release_digest,
        expected_policy_digest=policy_digest,
        expected_agent_release_digest=agent_digest,
        expected_interface_version=values["QDEV_RECOVERY_EXPECTED_INTERFACE_VERSION"],
        expected_interface_digest=interface_digest,
    )
    for credential in (config.client_cert, config.client_key, config.controller_ca):
        _private(credential)
    return config


def _run(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
) -> bytes:
    result = subprocess.run(
        command,
        input=input_bytes,
        capture_output=True,
        check=False,
    )
    if result.returncode:
        raise AgentError(f"fixed native command failed: {command[0]}")
    return result.stdout


def request(
    config: Config,
    path: str,
    payload: dict[str, Any],
    *,
    signature: str | None = None,
) -> tuple[int, bytes]:
    body = _canonical(payload)
    command = [
        "curl",
        "--silent",
        "--show-error",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--request",
        "POST",
        "--cert",
        str(config.client_cert),
        "--key",
        str(config.client_key),
        "--cacert",
        str(config.controller_ca),
        "--header",
        "content-type: application/json",
        "--data-binary",
        "@-",
        "--write-out",
        "\n%{http_code}",
    ]
    if signature is not None:
        command.extend(["--header", f"X-QDev-Recovery-Agent-Signature: sha256={signature}"])
    command.append(f"{config.controller_url.rstrip('/')}{path}")
    output = _run(command, input_bytes=body)
    raw_body, separator, raw_status = output.rpartition(b"\n")
    if not separator:
        raise AgentError("controller response did not expose an HTTP status")
    try:
        return int(raw_status), raw_body
    except ValueError as error:
        raise AgentError("controller response exposed an invalid HTTP status") from error


def _certificate_sha256(path: Path) -> str:
    return _sha256_bytes(_run(["openssl", "x509", "-in", str(path), "-outform", "DER"]))


def _parse_time(value: object, name: str) -> datetime:
    if not isinstance(value, str):
        raise AgentError(f"signed command {name} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise AgentError(f"signed command {name} is invalid") from error
    if parsed.tzinfo is None:
        raise AgentError(f"signed command {name} lacks timezone")
    return parsed.astimezone(UTC)


def validate_envelope(
    document: object,
    profile: Profile,
    config: Config,
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(document, dict) or set(document) != {
        "schema",
        "command",
        "command_digest",
        "signature",
    }:
        raise AgentError("controller command envelope shape is invalid")
    if document.get("schema") != "qdev-runner-recovery-agent-envelope-v1":
        raise AgentError("controller command envelope schema is invalid")
    command = document.get("command")
    if not isinstance(command, dict):
        raise AgentError("controller command is invalid")
    expected_fields = {
        "schema",
        "operation_id",
        "request_fingerprint",
        "target_id",
        "worker_name",
        "repository",
        "provider_runner_id",
        "labels",
        "recovery_action",
        "operator_certificate_sha256",
        "expected_agent_certificate_sha256",
        "interface_version",
        "interface_digest",
        "controller_revision",
        "controller_release_digest",
        "controller_receipt_id",
        "policy_digest",
        "agent_release_digest",
        "provider_idle_proof_digest",
        "provider_reconciliation_digest",
        "request_nonce",
        "issued_at",
        "expires_at",
        "registration_token",
        "registration_token_expires_at",
    }
    if set(command) != expected_fields:
        raise AgentError("controller command fields are invalid")
    canonical = _canonical(command)
    command_digest = document.get("command_digest")
    if command_digest != f"sha256:{_sha256_bytes(canonical)}":
        raise AgentError("controller command digest does not match its body")
    signature = document.get("signature")
    expected_signature = hmac.new(
        config.command_verification_key.encode(), canonical, hashlib.sha256
    ).hexdigest()
    if not isinstance(signature, str) or not hmac.compare_digest(signature, expected_signature):
        raise AgentError("controller command signature is invalid")
    if command.get("schema") != "qdev-runner-recovery-agent-command-v1":
        raise AgentError("controller command schema is invalid")
    exact = {
        "target_id": profile.target_id,
        "worker_name": profile.worker_name,
        "repository": profile.repository,
        "labels": list(profile.labels),
        "recovery_action": profile.recovery_action,
        "interface_version": config.expected_interface_version,
        "interface_digest": config.expected_interface_digest,
        "controller_revision": config.expected_controller_revision,
        "controller_release_digest": config.expected_controller_release_digest,
        "policy_digest": config.expected_policy_digest,
        "agent_release_digest": config.expected_agent_release_digest,
    }
    for key, expected in exact.items():
        if command.get(key) != expected:
            raise AgentError(f"signed command {key} does not match fixed profile")
    for key in (
        "operation_id",
        "request_fingerprint",
        "operator_certificate_sha256",
        "expected_agent_certificate_sha256",
        "interface_digest",
        "controller_release_digest",
        "controller_receipt_id",
    ):
        if not isinstance(command.get(key), str) or not _SHA256.fullmatch(command[key]):
            raise AgentError(f"signed command {key} is invalid")
    for key in (
        "policy_digest",
        "agent_release_digest",
        "provider_idle_proof_digest",
        "provider_reconciliation_digest",
    ):
        if not isinstance(command.get(key), str) or not _DIGEST.fullmatch(command[key]):
            raise AgentError(f"signed command {key} is invalid")
    if not isinstance(command.get("request_nonce"), str) or not _IDENTIFIER.fullmatch(
        command["request_nonce"]
    ):
        raise AgentError("signed command request nonce is invalid")
    provider_id = command.get("provider_runner_id")
    if not isinstance(provider_id, int) or isinstance(provider_id, bool) or provider_id <= 0:
        raise AgentError("signed command provider runner id is invalid")
    if (
        profile.expected_provider_runner_id is not None
        and provider_id != profile.expected_provider_runner_id
    ):
        raise AgentError("signed command provider runner id does not match saved identity")
    if command["expected_agent_certificate_sha256"] != _certificate_sha256(config.client_cert):
        raise AgentError("signed command is bound to another host-agent certificate")
    issued_at = _parse_time(command.get("issued_at"), "issued_at")
    expires_at = _parse_time(command.get("expires_at"), "expires_at")
    observed_now = (now or datetime.now(UTC)).astimezone(UTC)
    if issued_at > observed_now or expires_at <= observed_now:
        raise AgentError("signed command is not currently valid")
    if (expires_at - issued_at).total_seconds() > 300:
        raise AgentError("signed command exceeds the maximum validity interval")
    token = command.get("registration_token")
    token_expiry = command.get("registration_token_expires_at")
    if profile.recovery_action == "restore_saved_configuration":
        if token is not None or token_expiry is not None:
            raise AgentError("saved configuration recovery received a registration token")
    else:
        if not isinstance(token, str) or len(token) < 16:
            raise AgentError("replacement recovery lacks a registration token")
        parsed_token_expiry = _parse_time(token_expiry, "registration_token_expires_at")
        if parsed_token_expiry <= observed_now or expires_at > parsed_token_expiry:
            raise AgentError("replacement registration token is expired or too narrow")
    return command


def _read_state(path: Path) -> dict[str, Any] | None:
    _private(path, required=False)
    if not path.exists():
        return None
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise AgentError("recovery agent state is not JSON") from error
    if not isinstance(document, dict) or document.get("schema") != STATE_SCHEMA:
        raise AgentError("recovery agent state schema is invalid")
    return document


def _write_private_json(path: Path, document: dict[str, Any], *, exclusive: bool = False) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    if exclusive:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(document) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        return
    descriptor, raw = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(raw)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical(document) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _json_runner(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError) as error:
        raise AgentError("saved runner identity is unavailable or invalid") from error
    if not isinstance(value, dict):
        raise AgentError("saved runner identity is invalid")
    return value


def _systemctl_property(unit: str, property_name: str) -> str:
    return (
        _run(["systemctl", "show", unit, f"--property={property_name}", "--value"]).decode().strip()
    )


def _systemctl_ok(unit: str) -> bool:
    active = subprocess.run(
        ["systemctl", "is-active", "--quiet", unit], capture_output=True, check=False
    ).returncode
    enabled = subprocess.run(
        ["systemctl", "is-enabled", "--quiet", unit], capture_output=True, check=False
    ).returncode
    return active == 0 and enabled == 0


def _verify_service(profile: Profile) -> None:
    if _systemctl_property(profile.service_unit, "LoadState") != "loaded":
        raise AgentError("fixed runner service is not loaded")
    if _systemctl_property(profile.service_unit, "User") != profile.runner_user:
        raise AgentError("fixed runner service user does not match")
    if _systemctl_property(profile.service_unit, "WorkingDirectory") != str(profile.runner_root):
        raise AgentError("fixed runner service directory does not match")


def _backup_file(source: Path, destination: Path, expected_digest: str) -> None:
    if not source.is_file() or source.is_symlink() or _sha256_file(source) != expected_digest:
        raise AgentError("saved recovery control file does not match its reviewed digest")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    os.chown(destination, 0, 0)
    os.chmod(destination, 0o600)
    if _sha256_file(destination) != expected_digest:
        raise AgentError("recovery backup digest verification failed")


def _restore_file(source: Path, destination: Path, expected_digest: str) -> None:
    if _sha256_file(source) != expected_digest:
        raise AgentError("recovery rollback backup digest changed")
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    descriptor, raw = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    temporary = Path(raw)
    try:
        with source.open("rb") as input_stream, os.fdopen(descriptor, "wb") as output_stream:
            shutil.copyfileobj(input_stream, output_stream)
            output_stream.flush()
            os.fsync(output_stream.fileno())
        os.chown(temporary, 0, 0)
        os.chmod(temporary, 0o644)
        os.replace(temporary, destination)
    finally:
        temporary.unlink(missing_ok=True)


def _platform_identity(profile: Profile, provider_runner_id: int) -> None:
    unit = Path("/etc/systemd/system") / profile.service_unit
    if not unit.is_file() or _sha256_file(unit) != profile.base_unit_sha256:
        raise AgentError("saved Platform service unit does not match reviewed identity")
    if (
        profile.capacity_dropin is None
        or profile.capacity_dropin_sha256 is None
        or not profile.capacity_dropin.is_file()
        or _sha256_file(profile.capacity_dropin) != profile.capacity_dropin_sha256
    ):
        raise AgentError("saved Platform capacity policy does not match reviewed identity")
    identity = _json_runner(profile.runner_root / ".runner")
    if (
        identity.get("agentId") != provider_runner_id
        or identity.get("agentName") != profile.worker_name
        or identity.get("gitHubUrl") != f"https://github.com/{profile.repository}"
    ):
        raise AgentError("saved Platform runner registration does not match fixed identity")
    credentials = profile.runner_root / ".credentials"
    if not credentials.is_file() or credentials.is_symlink():
        raise AgentError("saved Platform runner credentials are unavailable")
    metadata = credentials.stat()
    if stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AgentError("saved Platform runner credentials are writable by another user")
    _verify_service(profile)


def _recover_platform(
    profile: Profile, command: dict[str, Any], backup_root: Path
) -> dict[str, Any]:
    _platform_identity(profile, command["provider_runner_id"])
    marker = profile.retirement_marker
    dropin = profile.retirement_dropin
    marker_digest = profile.retirement_marker_sha256
    dropin_digest = profile.retirement_dropin_sha256
    assert marker is not None and dropin is not None
    assert marker_digest is not None and dropin_digest is not None
    if not marker.exists() and not dropin.exists():
        if not _systemctl_ok(profile.service_unit):
            raise ExecutionFailure(
                "Platform recovery controls are absent but service is not healthy",
                outcome="ambiguous",
                proof={"mutation": "preexisting", "rollback": "unavailable"},
            )
        return {"mutation": "already_applied", "service": "active_enabled"}
    if not marker.is_file() or not dropin.is_file():
        raise ExecutionFailure(
            "Platform retirement controls are only partially present",
            outcome="not_applied",
            proof={"mutation": "none", "rollback": "not_required"},
        )
    backup = backup_root / command["operation_id"]
    marker_backup = backup / "platform-ci-direct-runner.disabled"
    dropin_backup = backup / "99-qdev-gha-direct-runner-retired.conf"
    _backup_file(marker, marker_backup, marker_digest)
    _backup_file(dropin, dropin_backup, dropin_digest)
    marker.unlink()
    dropin.unlink()
    try:
        _run(["systemctl", "daemon-reload"])
        _run(["systemctl", "enable", "--now", profile.service_unit])
        if not _systemctl_ok(profile.service_unit):
            raise AgentError("Platform runner service did not become active and enabled")
        _platform_identity(profile, command["provider_runner_id"])
    except AgentError as error:
        rollback_verified = False
        try:
            subprocess.run(
                ["systemctl", "disable", "--now", profile.service_unit],
                capture_output=True,
                check=False,
            )
            _restore_file(marker_backup, marker, marker_digest)
            _restore_file(dropin_backup, dropin, dropin_digest)
            _run(["systemctl", "daemon-reload"])
            rollback_verified = (
                marker.is_file() and dropin.is_file() and not _systemctl_ok(profile.service_unit)
            )
        except AgentError:
            rollback_verified = False
        raise ExecutionFailure(
            str(error),
            outcome="failed" if rollback_verified else "ambiguous",
            proof={
                "mutation": "attempted",
                "rollback": "verified" if rollback_verified else "unverified",
            },
        ) from error
    backup_manifest = {"marker": marker_digest, "dropin": dropin_digest}
    return {
        "mutation": "retirement_controls_reversibly_removed",
        "service": "active_enabled",
        "backup_manifest_digest": f"sha256:{_sha256_bytes(_canonical(backup_manifest))}",
    }


def _safe_archive(archive: Path) -> None:
    try:
        with tarfile.open(archive, mode="r:gz") as bundle:
            for member in bundle.getmembers():
                path = PurePosixPath(member.name)
                if path.is_absolute() or ".." in path.parts or member.isdev():
                    raise AgentError("runner archive contains an unsafe member")
                if member.issym() or member.islnk():
                    link = PurePosixPath(member.linkname)
                    if link.is_absolute() or ".." in link.parts:
                        raise AgentError("runner archive contains an unsafe link")
    except (OSError, tarfile.TarError) as error:
        raise AgentError("runner archive cannot be inspected") from error


def _qazstack_identity(profile: Profile) -> bool:
    identity_path = profile.runner_root / ".runner"
    if not identity_path.is_file():
        return False
    identity = _json_runner(identity_path)
    if (
        identity.get("agentName") != profile.worker_name
        or identity.get("gitHubUrl") != f"https://github.com/{profile.repository}"
    ):
        return False
    try:
        _verify_service(profile)
    except AgentError:
        return False
    return _systemctl_ok(profile.service_unit)


def _recover_qazstack(profile: Profile, command: dict[str, Any]) -> dict[str, Any]:
    if _qazstack_identity(profile):
        return {"mutation": "already_applied", "service": "active_enabled"}
    load_state = subprocess.run(
        ["systemctl", "show", profile.service_unit, "--property=LoadState", "--value"],
        capture_output=True,
        check=False,
        text=True,
    )
    if profile.runner_root.exists() or (
        load_state.returncode == 0 and load_state.stdout.strip() not in {"", "not-found"}
    ):
        raise ExecutionFailure(
            "QazStack target contains an unrecognized partial registration",
            outcome="ambiguous",
            proof={"mutation": "preexisting_or_interrupted", "rollback": "unavailable"},
        )
    try:
        account = pwd.getpwnam(profile.runner_user)
    except KeyError as error:
        raise ExecutionFailure(
            "fixed QazStack runner account is absent",
            outcome="not_applied",
            proof={"mutation": "none", "rollback": "not_required"},
        ) from error
    if account.pw_uid == 0:
        raise ExecutionFailure(
            "fixed QazStack runner account cannot be root",
            outcome="not_applied",
            proof={"mutation": "none", "rollback": "not_required"},
        )
    parent = profile.runner_root.parent
    if not parent.is_dir() or parent.is_symlink() or stat.S_IMODE(parent.stat().st_mode) & 0o022:
        raise ExecutionFailure(
            "fixed runner parent is absent or unsafe",
            outcome="not_applied",
            proof={"mutation": "none", "rollback": "not_required"},
        )
    staging = Path(tempfile.mkdtemp(prefix=".qdev-qazstack-recovery-", dir=parent))
    archive = staging / _RUNNER_ARCHIVE
    registration_attempted = False
    installed = False
    try:
        _run(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--location",
                "--connect-timeout",
                "15",
                "--max-time",
                "600",
                "--output",
                str(archive),
                _RUNNER_URL,
            ]
        )
        if _sha256_file(archive) != _RUNNER_ARCHIVE_SHA256:
            raise AgentError("GitHub runner archive digest does not match pinned release")
        _safe_archive(archive)
        _run(["tar", "--extract", "--gzip", "--file", str(archive), "--directory", str(staging)])
        archive.unlink()
        _run(["chown", "-R", f"{profile.runner_user}:{profile.runner_user}", str(staging)])
        os.replace(staging, profile.runner_root)
        token = command["registration_token"]
        registration_attempted = True
        _run(
            [
                "runuser",
                "--user",
                profile.runner_user,
                "--",
                "env",
                f"HOME={profile.runner_root}",
                "RUNNER_ALLOW_RUNASROOT=0",
                str(profile.runner_root / "config.sh"),
                "--unattended",
                "--replace",
                "--url",
                f"https://github.com/{profile.repository}",
                "--token",
                token,
                "--name",
                profile.worker_name,
                "--labels",
                "qdev-ci",
                "--work",
                "_work",
            ]
        )
        _run([str(profile.runner_root / "svc.sh"), "install", profile.runner_user])
        installed = True
        _run(["systemctl", "enable", "--now", profile.service_unit])
        if not _qazstack_identity(profile):
            raise AgentError("QazStack runner service did not match fixed active identity")
    except AgentError as error:
        if not registration_attempted:
            cleanup_target = profile.runner_root if profile.runner_root.exists() else staging
            if cleanup_target.exists():
                shutil.rmtree(cleanup_target)
            outcome = "failed"
            rollback = "verified_absent"
        else:
            outcome = "ambiguous"
            rollback = "unavailable_after_provider_registration"
        raise ExecutionFailure(
            str(error),
            outcome=outcome,
            proof={
                "mutation": (
                    "provider_registration_attempted" if registration_attempted else "local_staging"
                ),
                "service_installed": installed,
                "rollback": rollback,
            },
        ) from error
    return {
        "mutation": "same_name_registration_replaced",
        "service": "active_enabled",
        "runner_distribution": _RUNNER_VERSION,
        "runner_archive_digest": f"sha256:{_RUNNER_ARCHIVE_SHA256}",
    }


def execute(
    profile: Profile, command: dict[str, Any], config: Config
) -> tuple[str, dict[str, Any]]:
    backup_root = config.state_path.parent / "backups"
    try:
        if profile.recovery_action == "restore_saved_configuration":
            proof = _recover_platform(profile, command, backup_root)
        else:
            proof = _recover_qazstack(profile, command)
    except ExecutionFailure as error:
        proof = error.proof
        proof["error_class"] = "native_recovery_failed"
        return error.outcome, proof
    return "completed", proof


def _reconcile_payload(
    profile: Profile,
    command: dict[str, Any],
    outcome: str,
    proof: dict[str, Any],
    config: Config,
) -> tuple[dict[str, Any], dict[str, Any]]:
    observed_at = datetime.now(UTC).isoformat().replace("+00:00", "Z")
    private_proof = {
        "schema": "qdev-runner-recovery-native-proof-v1",
        "operation_id": command["operation_id"],
        "request_fingerprint": command["request_fingerprint"],
        "target_id": profile.target_id,
        "worker_name": profile.worker_name,
        "repository": profile.repository,
        "recovery_action": profile.recovery_action,
        "request_nonce": command["request_nonce"],
        "outcome": outcome,
        "observed_at": observed_at,
        "proof": proof,
    }
    outcome_digest = f"sha256:{_sha256_bytes(_canonical(private_proof))}"
    payload = {
        "schema": "qdev-runner-recovery-reconcile-v1",
        "operation_id": command["operation_id"],
        "request_fingerprint": command["request_fingerprint"],
        "target_id": profile.target_id,
        "recovery_action": profile.recovery_action,
        "request_nonce": command["request_nonce"],
        "provider_reconciliation_digest": command["provider_reconciliation_digest"],
        "outcome": outcome,
        "outcome_digest": outcome_digest,
        "agent_release_digest": config.expected_agent_release_digest,
        "observed_at": observed_at,
    }
    return payload, private_proof


def _post_reconcile(config: Config, payload: dict[str, Any]) -> dict[str, Any]:
    signature = hmac.new(
        config.reconcile_signing_key.encode(), _canonical(payload), hashlib.sha256
    ).hexdigest()
    status, body = request(
        config,
        "/internal/v1/worker-recovery/reconcile",
        payload,
        signature=signature,
    )
    if status != 200:
        raise AgentError("controller did not accept native recovery evidence")
    try:
        response = json.loads(body)
    except json.JSONDecodeError as error:
        raise AgentError("controller reconciliation response is invalid") from error
    if not isinstance(response, dict):
        raise AgentError("controller reconciliation response is invalid")
    return response


def _claim(
    config: Config, profile: Profile, operation_id: str | None = None
) -> tuple[int, dict[str, Any] | None]:
    payload: dict[str, Any] = {"schema": "qdev-runner-recovery-agent-claim-v1"}
    if operation_id is not None:
        payload["operation_id"] = operation_id
    status, body = request(config, "/internal/v1/worker-recovery/claim", payload)
    if status == 204:
        return status, None
    if status != 200:
        raise AgentError("controller rejected fixed-target recovery claim")
    try:
        document = json.loads(body)
    except json.JSONDecodeError as error:
        raise AgentError("controller command envelope is not JSON") from error
    return status, validate_envelope(document, profile, config)


def run_once(config: Config, profile: Profile) -> dict[str, Any]:
    config.lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private(config.lock_path, required=False)
    with config.lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(config.lock_path, 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AgentError("recovery host-agent lock is already held") from error
        state = _read_state(config.state_path)
        if state is not None and state.get("status") == "pending_reconcile":
            payload = state.get("reconcile")
            if not isinstance(payload, dict):
                raise AgentError("pending reconciliation state is invalid")
            response = _post_reconcile(config, payload)
            state["status"] = "reconciled"
            state["controller_state"] = response.get("state")
            _write_private_json(config.state_path, state)
            return {
                "status": "reconciled",
                "operation_id": payload.get("operation_id"),
                "outcome": payload.get("outcome"),
            }
        resume_id: str | None = None
        if state is not None and state.get("status") == "claimed":
            candidate = state.get("operation_id")
            if isinstance(candidate, str) and _SHA256.fullmatch(candidate):
                resume_id = candidate
        _, command = _claim(config, profile, resume_id)
        if command is None:
            return {"status": "idle", "profile": profile.name}
        claimed_state = {
            "schema": STATE_SCHEMA,
            "profile": profile.name,
            "status": "claimed",
            "operation_id": command["operation_id"],
            "request_fingerprint": command["request_fingerprint"],
            "command_digest": f"sha256:{_sha256_bytes(_canonical(command))}",
        }
        _write_private_json(config.state_path, claimed_state)
        outcome, proof = execute(profile, command, config)
        payload, private_proof = _reconcile_payload(profile, command, outcome, proof, config)
        pending_state = {
            **claimed_state,
            "status": "pending_reconcile",
            "reconcile": payload,
        }
        _write_private_json(config.state_path, pending_state)
        receipt = {
            "schema": RECEIPT_SCHEMA,
            "profile": profile.name,
            "agent_release_digest": config.expected_agent_release_digest,
            "policy_digest": config.expected_policy_digest,
            "controller_revision": config.expected_controller_revision,
            "controller_release_digest": config.expected_controller_release_digest,
            "native_proof": private_proof,
            "reconcile": payload,
        }
        receipt_path = config.receipts_dir / (
            f"{command['operation_id']}.{payload['outcome_digest'].removeprefix('sha256:')}.json"
        )
        if not receipt_path.exists():
            _write_private_json(receipt_path, receipt, exclusive=True)
        response = _post_reconcile(config, payload)
        pending_state["status"] = "reconciled"
        pending_state["controller_state"] = response.get("state")
        _write_private_json(config.state_path, pending_state)
        return {
            "status": "reconciled",
            "operation_id": command["operation_id"],
            "outcome": outcome,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true", required=True)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("runner recovery host agent must run as root")
    try:
        result = run_once(load_config(arguments.config), PROFILES[arguments.profile])
    except AgentError as error:
        print(
            json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True), file=sys.stderr
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
