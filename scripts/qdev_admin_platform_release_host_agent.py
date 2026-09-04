#!/usr/bin/env python3
"""Run one compiled QDev Admin Platform release lane through mTLS.

This agent deliberately knows four and only four product lanes.  It never
accepts a host path, registry, public URL, deploy command, or rollback command
from a release request or its configuration file.  Product-owned root
dispatchers own the native deploy details; they receive an immutable tuple and
must return a typed proof before the controller is allowed to mark a release
verified.
"""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
STATE_SCHEMA = "qdev-release-host-state-v1"
NATIVE_RECEIPT_SCHEMA = "qdev-admin-platform-native-receipt-v1"
_SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class AgentError(RuntimeError):
    """The host cannot truthfully accept or complete this release."""


@dataclass(frozen=True)
class Profile:
    name: str
    lane: str
    project_id: str
    placement: str
    artifact_prefix: str
    adapter: str
    minimum_free_gib: float
    state_path: Path
    lock_path: Path
    release_dispatcher: Path
    rollback_dispatcher: Path
    receipt_dispatcher: Path

    @property
    def readiness(self) -> dict[str, str]:
        return {"identity": "ok", "native": "ok", "public": "ok"}


_STATE_ROOT = Path("/var/lib/qdev-release-agents/admin-platform")
_LOCK_ROOT = Path("/run/lock")

# These locations are a compiled, reviewed interface.  Product wrappers may
# invoke their own already-approved native release mechanism, but cannot make
# the controller agent execute a caller-selected program or path.
PROFILES = {
    "ortcom": Profile(
        name="ortcom",
        lane="qdev-release-ortcom",
        project_id="ortcom",
        placement="ortcom-production-controller",
        artifact_prefix="ghcr.io/belilovsky/ortcom-kz",
        adapter="ortcom-root-deploy-v1",
        minimum_free_gib=20,
        state_path=_STATE_ROOT / "ortcom.json",
        lock_path=_LOCK_ROOT / "qdev-admin-platform-ortcom.lock",
        release_dispatcher=Path("/usr/local/sbin/ortcom-controller-release"),
        rollback_dispatcher=Path("/usr/local/sbin/ortcom-controller-rollback"),
        receipt_dispatcher=Path("/usr/local/sbin/ortcom-controller-receipt"),
    ),
    "cmnt": Profile(
        name="cmnt",
        lane="qdev-release-cmnt",
        project_id="cmnt",
        placement="cmnt-rolling-controller",
        artifact_prefix="ci.qdev.run/artifacts/cmnt-web-admin",
        adapter="cmnt-root-rolling-launcher-v1",
        minimum_free_gib=12,
        state_path=_STATE_ROOT / "cmnt.json",
        lock_path=_LOCK_ROOT / "qdev-admin-platform-cmnt.lock",
        release_dispatcher=Path("/usr/local/sbin/cmnt-controller-release"),
        rollback_dispatcher=Path("/usr/local/sbin/cmnt-controller-rollback"),
        receipt_dispatcher=Path("/usr/local/sbin/cmnt-controller-receipt"),
    ),
    "total": Profile(
        name="total",
        lane="qdev-release-total",
        project_id="total-kz",
        placement="total-qdev-origin",
        artifact_prefix="ci.qdev.run/artifacts/total-kz-admin",
        adapter="total-qdev-native-release-v1",
        minimum_free_gib=30,
        state_path=_STATE_ROOT / "total.json",
        lock_path=_LOCK_ROOT / "qdev-admin-platform-total.lock",
        release_dispatcher=Path("/usr/local/sbin/total-controller-release"),
        rollback_dispatcher=Path("/usr/local/sbin/total-controller-rollback"),
        receipt_dispatcher=Path("/usr/local/sbin/total-controller-receipt"),
    ),
    "qazposter": Profile(
        name="qazposter",
        lane="qdev-release-qazposter",
        project_id="qazposter",
        placement="qazposter-production-controller",
        artifact_prefix="ci.qdev.run/artifacts/qazposter-admin",
        adapter="qazposter-native-release-v1",
        minimum_free_gib=12,
        state_path=_STATE_ROOT / "qazposter.json",
        lock_path=_LOCK_ROOT / "qdev-admin-platform-qazposter.lock",
        release_dispatcher=Path("/usr/local/sbin/qazposter-controller-release"),
        rollback_dispatcher=Path("/usr/local/sbin/qazposter-controller-rollback"),
        receipt_dispatcher=Path("/usr/local/sbin/qazposter-controller-receipt"),
    ),
}


@dataclass(frozen=True)
class Config:
    controller_url: str
    client_cert: Path
    client_key: Path
    controller_ca: Path


def _private(path: Path, *, required: bool = True) -> None:
    if path.is_symlink():
        raise AgentError(f"private path must not be a symlink: {path}")
    try:
        meta = path.stat()
    except FileNotFoundError as error:
        if required:
            raise AgentError(f"required file is missing: {path}") from error
        return
    if meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) & 0o077:
        raise AgentError(f"file must be root-owned and private: {path}")


def _root_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise AgentError(f"required root directory is unavailable: {path}")
    meta = path.stat()
    if meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) & 0o022:
        raise AgentError(f"directory must be root-owned and non-writable: {path}")


def load_config(path: Path) -> Config:
    _private(path)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not value:
            raise AgentError("admin-platform host-agent configuration has an invalid line")
        values[key] = value
    expected = {
        "QDEV_RELEASE_CONTROLLER_URL",
        "QDEV_RELEASE_AGENT_CERT",
        "QDEV_RELEASE_AGENT_KEY",
        "QDEV_RELEASE_CONTROLLER_CA",
    }
    if set(values) != expected:
        raise AgentError("admin-platform host-agent configuration keys are invalid")
    parsed = urlsplit(values["QDEV_RELEASE_CONTROLLER_URL"])
    if (
        parsed.scheme != "https"
        or parsed.hostname != "worker.ci.qdev.run"
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise AgentError("controller URL must be the fixed HTTPS mTLS edge")
    config = Config(
        controller_url=values["QDEV_RELEASE_CONTROLLER_URL"],
        client_cert=Path(values["QDEV_RELEASE_AGENT_CERT"]),
        client_key=Path(values["QDEV_RELEASE_AGENT_KEY"]),
        controller_ca=Path(values["QDEV_RELEASE_CONTROLLER_CA"]),
    )
    for credential in (config.client_cert, config.client_key, config.controller_ca):
        _private(credential)
    return config


def _release(value: object, profile: Profile) -> dict[str, str]:
    expected = {"source_sha", "artifact_digest", "artifact_ref"}
    if not isinstance(value, dict) or set(value) != expected:
        raise AgentError("release state shape is invalid")
    source = value.get("source_sha")
    digest = value.get("artifact_digest")
    artifact_ref = value.get("artifact_ref")
    if (
        not isinstance(source, str)
        or not _SHA.fullmatch(source)
        or not isinstance(digest, str)
        or not _DIGEST.fullmatch(digest)
        or artifact_ref != f"{profile.artifact_prefix}@{digest}"
    ):
        raise AgentError("release immutable tuple is not allowlisted")
    return {"source_sha": source, "artifact_digest": digest, "artifact_ref": artifact_ref}


def read_state(path: Path, profile: Profile) -> tuple[dict[str, str], dict[str, str]]:
    _root_directory(path.parent)
    _private(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise AgentError("host-agent state is not JSON") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "active_release", "rollback"}
        or document.get("schema") != STATE_SCHEMA
    ):
        raise AgentError("host-agent state shape is invalid")
    active = _release(document.get("active_release"), profile)
    rollback_raw = document.get("rollback")
    if not isinstance(rollback_raw, dict) or rollback_raw.get("verified") is not True:
        raise AgentError("host-agent rollback is not verified")
    rollback = _release(
        {
            field: rollback_raw.get(field)
            for field in ("source_sha", "artifact_digest", "artifact_ref")
        },
        profile,
    )
    if active == rollback:
        raise AgentError("host-agent rollback must be a distinct immutable tuple")
    return active, rollback


def write_state(path: Path, active: dict[str, str], rollback: dict[str, str]) -> None:
    _root_directory(path.parent)
    _private(path)
    fd, raw_temporary = tempfile.mkstemp(prefix=".admin-platform-release.", dir=path.parent)
    temporary = Path(raw_temporary)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(
                {
                    "schema": STATE_SCHEMA,
                    "active_release": active,
                    "rollback": {"verified": True, **rollback},
                },
                stream,
                sort_keys=True,
                separators=(",", ":"),
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _run(command: list[str], *, payload: bytes | None = None) -> bytes:
    result = subprocess.run(
        command,
        input=payload,
        capture_output=True,
        check=False,
        env=_SAFE_ENV,
    )
    if result.returncode:
        raise AgentError(f"compiled native command failed: {command[0]}")
    return result.stdout


def request(
    config: Config, method: str, path: str, payload: dict[str, Any] | None = None
) -> tuple[int, bytes]:
    command = [
        "/usr/bin/curl",
        "--silent",
        "--show-error",
        "--connect-timeout",
        "10",
        "--max-time",
        "30",
        "--request",
        method,
        "--cert",
        str(config.client_cert),
        "--key",
        str(config.client_key),
        "--cacert",
        str(config.controller_ca),
        "--write-out",
        "\n%{http_code}",
        f"{config.controller_url.rstrip('/')}{path}",
    ]
    body = None
    if payload is not None:
        command[2:2] = ["--header", "content-type: application/json", "--data-binary", "@-"]
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    response = _run(command, payload=body)
    raw_body, _, raw_status = response.rpartition(b"\n")
    try:
        return int(raw_status), raw_body
    except ValueError as error:
        raise AgentError("controller response did not expose HTTP status") from error


def _ensure_dispatcher(path: Path) -> None:
    _private(path)
    if not os.access(path, os.X_OK):
        raise AgentError(f"compiled native dispatcher is not executable: {path}")


def _dispatcher_args(release: dict[str, str]) -> list[str]:
    return [
        "--source-sha",
        release["source_sha"],
        "--artifact-digest",
        release["artifact_digest"],
        "--artifact-ref",
        release["artifact_ref"],
    ]


def native_receipt(profile: Profile, release: dict[str, str]) -> None:
    _ensure_dispatcher(profile.receipt_dispatcher)
    try:
        document = json.loads(_run([str(profile.receipt_dispatcher), *_dispatcher_args(release)]))
    except json.JSONDecodeError as error:
        raise AgentError("native receipt dispatcher did not return JSON") from error
    expected = {
        "schema",
        "project_id",
        "native_host_adapter",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
        "readiness",
    }
    if (
        not isinstance(document, dict)
        or set(document) != expected
        or document.get("schema") != NATIVE_RECEIPT_SCHEMA
        or document.get("project_id") != profile.project_id
        or document.get("native_host_adapter") != profile.adapter
        or _release(
            {
                field: document.get(field)
                for field in ("source_sha", "artifact_digest", "artifact_ref")
            },
            profile,
        )
        != release
        or document.get("readiness") != profile.readiness
    ):
        raise AgentError("native receipt does not bind the requested release tuple")


def invoke_native(profile: Profile, action: str, release: dict[str, str]) -> None:
    dispatchers = {"release": profile.release_dispatcher, "rollback": profile.rollback_dispatcher}
    dispatcher = dispatchers.get(action)
    if dispatcher is None:
        raise AgentError("native action is not allowlisted")
    _ensure_dispatcher(dispatcher)
    _run([str(dispatcher), *_dispatcher_args(release)])


def heartbeat(profile: Profile, active: dict[str, str], rollback: dict[str, str]) -> dict[str, Any]:
    stats = os.statvfs("/")
    free = stats.f_bavail * stats.f_frsize / 1024**3
    return {
        "schema": "qdev-release-host-agent-heartbeat-v1",
        "release_lane": profile.lane,
        "project_id": profile.project_id,
        "placement": profile.placement,
        "state": "ready",
        "release_lock": "available",
        "capacity_free_gib": round(free, 3),
        "active_release": active,
        "rollback": {"verified": True, **rollback},
    }


def validate_job(document: object, profile: Profile) -> tuple[str, dict[str, str]]:
    expected = {
        "schema",
        "release_id",
        "release_lane",
        "project_id",
        "placement",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
    }
    if (
        not isinstance(document, dict)
        or set(document) != expected
        or document.get("schema") != "qdev-release-host-agent-job-v1"
        or (document.get("release_lane"), document.get("project_id"), document.get("placement"))
        != (profile.lane, profile.project_id, profile.placement)
    ):
        raise AgentError("controller release job identity is invalid")
    release_id = document.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        raise AgentError("controller release job id is invalid")
    return release_id, _release(
        {field: document.get(field) for field in ("source_sha", "artifact_digest", "artifact_ref")},
        profile,
    )


def complete(
    config: Config,
    profile: Profile,
    release_id: str,
    release: dict[str, str],
    rollback: dict[str, str],
) -> None:
    receipt = {
        "schema": "qdev-controller-release-runtime-receipt-v1",
        "status": "verified",
        "project": profile.project_id,
        "release_lane": profile.lane,
        "placement": profile.placement,
        **release,
        "health": "ok",
        "readiness": profile.readiness,
        "rollback": {"verified": True, **rollback},
    }
    status, _ = request(
        config,
        "POST",
        f"/internal/v1/release-hosts/{profile.placement}/jobs/{release_id}/complete",
        receipt,
    )
    if status != 200:
        raise AgentError("controller rejected verified runtime receipt")


def _acquire_lock(path: Path):
    _root_directory(path.parent)
    if path.exists():
        _private(path)
    return path.open("a+", encoding="utf-8")


def run_once(config: Config, profile: Profile) -> dict[str, Any]:
    with _acquire_lock(profile.lock_path) as lock:
        os.chmod(profile.lock_path, 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AgentError("release lock is already held") from error

        active, rollback = read_state(profile.state_path, profile)
        # A ready heartbeat is meaningful only when a product-owned native
        # proof confirms the release the state file claims is active.
        native_receipt(profile, active)
        beat = heartbeat(profile, active, rollback)
        if beat["capacity_free_gib"] < profile.minimum_free_gib:
            raise AgentError("release capacity is below the compiled lane minimum")
        status, _ = request(
            config, "POST", f"/internal/v1/release-hosts/{profile.placement}/heartbeat", beat
        )
        if status != 200:
            raise AgentError("controller rejected host-agent heartbeat")
        status, body = request(
            config, "GET", f"/internal/v1/release-hosts/{profile.placement}/jobs/next"
        )
        if status == 204:
            return {"status": "idle", "capacity_free_gib": beat["capacity_free_gib"]}
        if status != 200:
            raise AgentError("controller job poll was rejected")
        release_id, candidate = validate_job(json.loads(body), profile)
        release_attempted = False
        try:
            release_attempted = True
            invoke_native(profile, "release", candidate)
            native_receipt(profile, candidate)
            complete(config, profile, release_id, candidate, active)
        except AgentError as error:
            if release_attempted:
                try:
                    invoke_native(profile, "rollback", active)
                    native_receipt(profile, active)
                except AgentError as rollback_error:
                    raise AgentError(
                        "candidate failed and native rollback could not be proven: "
                        f"{rollback_error}"
                    ) from error
            raise
        write_state(profile.state_path, candidate, active)
        return {"status": "verified", "release_id": release_id, **candidate}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("admin-platform release host agent must run as root")
    try:
        result = run_once(load_config(args.config), PROFILES[args.profile])
    except (AgentError, json.JSONDecodeError) as error:
        print(
            json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
