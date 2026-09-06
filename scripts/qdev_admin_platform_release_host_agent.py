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
import datetime
import fcntl
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import SimpleNamespace
from typing import Any, TextIO
from urllib.parse import urlencode, urlsplit

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LEASE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_FENCE = re.compile(r"^[0-9a-f]{24,128}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_CI_SCOPE_VALUE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,191}$")
_HOST_IDENTITY = re.compile(r"^qdev-host-agent:[a-z0-9][a-z0-9-]{2,127}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_IDP_AUTHORIZATION_PATH = re.compile(
    r"^/internal/v1/release-hosts/[a-z0-9][a-z0-9-]{2,127}/jobs/"
    r"[A-Za-z0-9_-]{16,128}/idp-file-authorization$"
)
_QMT_VERSION = re.compile(r"^4\.4\.[0-9]+$")
_RUNNER_PROFILES = frozenset({"qdev-ci", "qdev-ci-docker", "qdev-ci-browser"})
STATE_SCHEMA = "qdev-release-host-state-v1"
NATIVE_RECEIPT_SCHEMA = "qdev-admin-platform-native-receipt-v1"
RUNTIME_RECEIPT_SCHEMA = "qdev-controller-release-runtime-receipt-v1"
ROLLBACK_RECEIPT_SCHEMA = "qdev-controller-release-rollback-receipt-v1"
HOST_DISPATCH_CLAIM_SCHEMA = "qdev-controller-host-dispatch-claim-v2"
OPERATION_JOURNAL_SCHEMA = "qdev-admin-platform-operation-v3"
_JOURNAL_GENESIS = "0" * 64
_DISPATCH_CLAIM_MAX_TTL_SECONDS = 300
_DISPATCH_CLAIM_CLOCK_SKEW_SECONDS = 30
_SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class AgentError(RuntimeError):
    """The host cannot truthfully accept or complete this release."""


class ControllerTransportError(AgentError):
    """The controller outcome is unknown and must be reconciled before retry."""


class ControllerOutcomeUnresolved(AgentError):
    """Native state must not be changed until the controller outcome is known."""


def _ensure_live_lease(lease_expires_at: object, *, now: float | None = None) -> None:
    current = int(time.time() if now is None else now)
    if (
        not isinstance(lease_expires_at, int)
        or isinstance(lease_expires_at, bool)
        or lease_expires_at <= current
    ):
        raise AgentError("controller release lease is expired or invalid")


@dataclass(frozen=True)
class Profile:
    name: str
    lane: str
    project_id: str
    repository: str
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
        repository="belilovsky/ortcom-kz",
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
        repository="belilovsky/cmnt-web",
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
        repository="belilovsky/total-kz",
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
        repository="belilovsky/qazposter",
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
    "qmt": Profile(
        name="qmt",
        lane="qdev-release-qmt",
        project_id="kaztilshi",
        repository="belilovsky/kazakh-translate",
        placement="srv138jump",
        artifact_prefix="registry.ci.qdev.run/kaztilshi",
        adapter="qmt-native-release-v1",
        minimum_free_gib=0,
        state_path=_STATE_ROOT / "qmt.json",
        lock_path=_LOCK_ROOT / "qdev-admin-platform-qmt.lock",
        release_dispatcher=Path("/usr/local/sbin/qmt-controller-adapter"),
        rollback_dispatcher=Path("/usr/local/sbin/qmt-controller-adapter"),
        receipt_dispatcher=Path("/usr/local/sbin/qmt-controller-adapter"),
    ),
}


@dataclass(frozen=True)
class Config:
    controller_url: str
    client_cert: Path
    client_key: Path
    controller_ca: Path
    host_identity: str
    dispatch_secret: bytes


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
        "QDEV_RELEASE_HOST_IDENTITY",
        "QDEV_RELEASE_DISPATCH_SECRET_FILE",
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
    host_identity = values["QDEV_RELEASE_HOST_IDENTITY"]
    if not _HOST_IDENTITY.fullmatch(host_identity):
        raise AgentError("admin-platform host identity is invalid")
    dispatch_secret_path = Path(values["QDEV_RELEASE_DISPATCH_SECRET_FILE"])
    if not dispatch_secret_path.is_absolute():
        raise AgentError("host dispatch secret path must be absolute")
    _private(dispatch_secret_path)
    try:
        dispatch_secret = dispatch_secret_path.read_bytes().strip()
    except OSError as error:
        raise AgentError("host dispatch secret is unavailable") from error
    if not 32 <= len(dispatch_secret) <= 4096:
        raise AgentError("host dispatch secret length is invalid")
    config = Config(
        controller_url=values["QDEV_RELEASE_CONTROLLER_URL"],
        client_cert=Path(values["QDEV_RELEASE_AGENT_CERT"]),
        client_key=Path(values["QDEV_RELEASE_AGENT_KEY"]),
        controller_ca=Path(values["QDEV_RELEASE_CONTROLLER_CA"]),
        host_identity=host_identity,
        dispatch_secret=dispatch_secret,
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


def read_state(
    path: Path, profile: Profile, *, allow_bootstrap: bool = False
) -> tuple[dict[str, str], dict[str, str]]:
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
    if active == rollback and not allow_bootstrap:
        raise AgentError("host-agent rollback must be a distinct immutable tuple")
    return active, rollback


def _fsync_directory(path: Path) -> None:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    descriptor = os.open(path, flags)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_state(path: Path, active: dict[str, str], rollback: dict[str, str]) -> None:
    _root_directory(path.parent)
    _private(path, required=False)
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
        _fsync_directory(path.parent)
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
    config: Config,
    method: str,
    path: str,
    payload: dict[str, Any] | bytes | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    # Only the fixed IdP collector may send native canonical bytes (including
    # their terminal LF). Re-serializing these as the legacy JSON transport
    # would change the exact observation authenticated by the controller.
    if isinstance(payload, bytes) and (
        method != "POST"
        or not _IDP_AUTHORIZATION_PATH.fullmatch(path)
        or not 0 < len(payload) <= 2 * 1024 * 1024
        or not payload.endswith(b"\n")
        or set(headers or ()) != {"X-QDev-Release-Lease", "X-QDev-Release-Fence"}
    ):
        raise AgentError("raw controller payload requires the fixed IdP authorization endpoint")
    if headers is not None:
        allowed_headers = {"X-QDev-Release-Lease", "X-QDev-Release-Fence"}
        if set(headers) - allowed_headers:
            raise AgentError("controller request contains a non-compiled header")
        for name, value in headers.items():
            if not isinstance(value, str):
                raise AgentError("controller request header is invalid")
            if name == "X-QDev-Release-Lease" and not _LEASE.fullmatch(value):
                raise AgentError("controller release lease is invalid")
            if name == "X-QDev-Release-Fence" and not _FENCE.fullmatch(value):
                raise AgentError("controller release fence is invalid")
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
    if headers:
        insert_at = 1
        for name, value in headers.items():
            command[insert_at:insert_at] = ["--header", f"{name}: {value}"]
            insert_at += 2
    body = None
    if payload is not None:
        command[2:2] = ["--header", "content-type: application/json", "--data-binary", "@-"]
        body = (
            payload
            if isinstance(payload, bytes)
            else json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        )
    try:
        response = _run(command, payload=body)
    except AgentError as error:
        raise ControllerTransportError("controller request outcome is unknown") from error
    raw_body, _, raw_status = response.rpartition(b"\n")
    try:
        return int(raw_status), raw_body
    except ValueError as error:
        raise ControllerTransportError("controller response did not expose HTTP status") from error


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


def _current_dispatcher_args() -> list[str]:
    return ["--current"]


def native_receipt(
    profile: Profile,
    release: dict[str, str] | None = None,
    *,
    current: bool = False,
) -> dict[str, Any]:
    if (release is None) != current:
        raise AgentError("native receipt request mode is invalid")
    _ensure_dispatcher(profile.receipt_dispatcher)
    try:
        args = _current_dispatcher_args() if current else _dispatcher_args(release or {})
        if profile.name == "qmt":
            args = ["--action", "receipt", *args]
        document = json.loads(_run([str(profile.receipt_dispatcher), *args]))
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
    optional = {"runtime_identity", "dependency_identity", "artifact_provenance"}
    if (
        not isinstance(document, dict)
        or not expected.issubset(document)
        or set(document) - expected - optional
        or document.get("schema") != NATIVE_RECEIPT_SCHEMA
        or document.get("project_id") != profile.project_id
        or document.get("native_host_adapter") != profile.adapter
        or document.get("readiness") != profile.readiness
    ):
        raise AgentError("native receipt does not bind the requested release tuple")
    measured_release = _release(
        {field: document.get(field) for field in ("source_sha", "artifact_digest", "artifact_ref")},
        profile,
    )
    if release is not None and measured_release != release:
        raise AgentError("native receipt does not bind the requested release tuple")
    return document


def invoke_native(
    profile: Profile,
    action: str,
    release: dict[str, str],
    candidate_evidence: dict[str, Any] | None = None,
) -> None:
    dispatchers = {"release": profile.release_dispatcher, "rollback": profile.rollback_dispatcher}
    dispatcher = dispatchers.get(action)
    if dispatcher is None:
        raise AgentError("native action is not allowlisted")
    _ensure_dispatcher(dispatcher)
    args = _dispatcher_args(release)
    if profile.name == "qmt":
        args = ["--action", action, *args]
        if action == "release":
            if candidate_evidence is None:
                raise AgentError("QMT release requires signed candidate evidence")
            args.extend(
                [
                    "--candidate-receipt-sha256",
                    candidate_evidence["candidate_receipt_sha256"],
                    "--release-version",
                    candidate_evidence["release_version"],
                    "--migration-receipt-digest",
                    candidate_evidence["migration_receipt_digest"],
                    "--contract-digest",
                    candidate_evidence["contract_digest"],
                ]
            )
    _run([str(dispatcher), *args])


def _candidate_evidence(document: object, profile: Profile) -> dict[str, Any]:
    generic_fields = {"schema", "candidate_receipt_sha256"}
    qmt_fields = generic_fields | {
        "release_version",
        "migration_receipt_digest",
        "contract_digest",
    }
    expected = qmt_fields if profile.name == "qmt" else generic_fields
    if not isinstance(document, dict) or set(document) != expected:
        raise AgentError("controller candidate evidence shape is invalid")
    expected_schema = (
        "qdev-qmt-candidate-evidence-v1"
        if profile.name == "qmt"
        else "qdev-release-candidate-evidence-v1"
    )
    if (
        document.get("schema") != expected_schema
        or not isinstance(document.get("candidate_receipt_sha256"), str)
        or not _HEX64.fullmatch(document["candidate_receipt_sha256"])
    ):
        raise AgentError("controller candidate evidence identity is invalid")
    if profile.name == "qmt" and (
        document.get("release_version") != "4.4.2"
        or not isinstance(document.get("migration_receipt_digest"), str)
        or not _DIGEST.fullmatch(document["migration_receipt_digest"])
        or not isinstance(document.get("contract_digest"), str)
        or not _HEX64.fullmatch(document["contract_digest"])
    ):
        raise AgentError("controller QMT candidate evidence is invalid")
    return document


def heartbeat(
    profile: Profile,
    active: dict[str, str],
    rollback: dict[str, str],
    *,
    bootstrap: bool = False,
) -> dict[str, Any]:
    same_tuple = active == rollback
    if bootstrap != same_tuple:
        raise AgentError("host heartbeat bootstrap state does not match its rollback anchor")
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
        "bootstrap": bootstrap,
    }


def _canonical_bytes(value: dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode(
        "utf-8"
    )


def _validated_job(
    document: object,
    profile: Profile,
    config: Config,
    *,
    now: float | None = None,
) -> tuple[
    str,
    dict[str, str],
    str,
    str,
    str,
    int,
    dict[str, str],
    dict[str, Any],
]:
    expected = {
        "schema",
        "release_id",
        "release_lane",
        "project_id",
        "placement",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
        "lease_id",
        "fence",
        "lease_expires_at",
        "rollback_anchor",
        "candidate_evidence",
        "dispatch_claim",
        "dispatch_claim_signature",
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
    if not isinstance(release_id, str) or not _LEASE.fullmatch(release_id):
        raise AgentError("controller release job id is invalid")
    lease_id = document.get("lease_id")
    fence = document.get("fence")
    lease_expires_at = document.get("lease_expires_at")
    if not isinstance(lease_id, str) or not _LEASE.fullmatch(lease_id):
        raise AgentError("controller release lease is invalid")
    if not isinstance(fence, str) or not _FENCE.fullmatch(fence):
        raise AgentError("controller release fence is invalid")
    _ensure_live_lease(lease_expires_at, now=now)
    release = _release(
        {field: document.get(field) for field in ("source_sha", "artifact_digest", "artifact_ref")},
        profile,
    )
    claim = document.get("dispatch_claim")
    signature = document.get("dispatch_claim_signature")
    claim_fields = {
        "schema",
        "repository",
        "workflow",
        "job",
        "exact_sha",
        "run_id",
        "job_id",
        "attempt",
        "runner_profile",
        "host_identity",
        "release_id",
        "release_lane",
        "project_id",
        "placement",
        "artifact_digest",
        "artifact_ref",
        "lease_id",
        "fence",
        "lease_expires_at",
        "rollback_anchor",
        "candidate_evidence",
        "issued_at",
        "expires_at",
        "nonce",
    }
    if not isinstance(claim, dict) or set(claim) != claim_fields:
        raise AgentError("controller host dispatch claim shape is invalid")
    if not isinstance(signature, str) or not _HEX64.fullmatch(signature):
        raise AgentError("controller host dispatch signature is invalid")
    issued_at = claim.get("issued_at")
    expires_at = claim.get("expires_at")
    current = int(time.time() if now is None else now)
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= issued_at
        or expires_at - issued_at > _DISPATCH_CLAIM_MAX_TTL_SECONDS
        or not isinstance(lease_expires_at, int)
        or isinstance(lease_expires_at, bool)
        or expires_at > lease_expires_at
        or issued_at > current + _DISPATCH_CLAIM_CLOCK_SKEW_SECONDS
        or expires_at <= current
    ):
        raise AgentError("controller host dispatch claim lifetime is invalid")
    nonce = claim.get("nonce")
    if not isinstance(nonce, str) or not _NONCE.fullmatch(nonce):
        raise AgentError("controller host dispatch nonce is invalid")
    if (
        any(
            not isinstance(claim.get(field), int)
            or isinstance(claim.get(field), bool)
            or claim[field] <= 0
            for field in ("run_id", "job_id", "attempt")
        )
        or claim.get("runner_profile") not in _RUNNER_PROFILES
        or any(
            not isinstance(claim.get(field), str) or not _CI_SCOPE_VALUE.fullmatch(claim[field])
            for field in ("workflow", "job")
        )
    ):
        raise AgentError("controller host dispatch CI identity is invalid")
    rollback_anchor = _release(document.get("rollback_anchor"), profile)
    candidate_evidence = _candidate_evidence(document.get("candidate_evidence"), profile)
    if rollback_anchor == release:
        raise AgentError("controller rollback anchor matches the candidate")
    expected_claim = {
        "schema": HOST_DISPATCH_CLAIM_SCHEMA,
        "repository": profile.repository,
        "workflow": claim["workflow"],
        "job": claim["job"],
        "exact_sha": release["source_sha"],
        "run_id": claim["run_id"],
        "job_id": claim["job_id"],
        "attempt": claim["attempt"],
        "runner_profile": claim["runner_profile"],
        "host_identity": config.host_identity,
        "release_id": release_id,
        "release_lane": profile.lane,
        "project_id": profile.project_id,
        "placement": profile.placement,
        "artifact_digest": release["artifact_digest"],
        "artifact_ref": release["artifact_ref"],
        "lease_id": lease_id,
        "fence": fence,
        "lease_expires_at": lease_expires_at,
        "rollback_anchor": rollback_anchor,
        "candidate_evidence": candidate_evidence,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "nonce": nonce,
    }
    expected_host_identity = f"qdev-host-agent:{profile.placement}"
    if config.host_identity != expected_host_identity or claim != expected_claim:
        raise AgentError("controller host dispatch claim does not bind this host and job")
    expected_signature = hmac.new(
        config.dispatch_secret, _canonical_bytes(claim), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(expected_signature, signature):
        raise AgentError("controller host dispatch signature is invalid")
    return (
        release_id,
        release,
        lease_id,
        fence,
        nonce,
        lease_expires_at,
        rollback_anchor,
        candidate_evidence,
    )


def validate_job(
    document: object,
    profile: Profile,
    config: Config,
    *,
    now: float | None = None,
) -> tuple[str, dict[str, str]]:
    """Validate one signed, short-lived controller dispatch for this fixed host."""
    release_id, release, _, _, nonce, _, _, _ = _validated_job(document, profile, config, now=now)
    if _dispatch_nonce_seen(profile, nonce):
        raise AgentError("controller host dispatch claim was already consumed")
    return release_id, release


def _journal_path(profile: Profile) -> Path:
    return profile.state_path.with_suffix(".operation.jsonl")


def _legacy_journal_path(profile: Profile) -> Path:
    return profile.state_path.with_suffix(".operation.json")


def _journal_events(profile: Profile) -> list[dict[str, Any]]:
    path = _journal_path(profile)
    legacy = _legacy_journal_path(profile)
    _root_directory(path.parent)
    if not path.exists() and legacy.exists():
        raise AgentError("legacy replaceable operation journal requires explicit migration")
    _private(path, required=False)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        return []
    except OSError as error:
        raise AgentError("host operation journal is unavailable") from error
    if raw and not raw.endswith(b"\n"):
        raise AgentError("host operation journal has a partial record")
    events: list[dict[str, Any]] = []
    previous = _JOURNAL_GENESIS
    for expected_seq, line in enumerate(raw.splitlines(), start=1):
        try:
            event = json.loads(line)
        except json.JSONDecodeError as error:
            raise AgentError("host operation journal is not JSONL") from error
        if (
            not isinstance(event, dict)
            or event.get("schema") != OPERATION_JOURNAL_SCHEMA
            or event.get("project_id") != profile.project_id
            or event.get("release_lane") != profile.lane
            or event.get("placement") != profile.placement
            or event.get("journal_seq") != expected_seq
            or event.get("previous_event_sha256") != previous
            or not isinstance(event.get("event_sha256"), str)
            or not _HEX64.fullmatch(event["event_sha256"])
        ):
            raise AgentError("host operation journal chain is invalid")
        unsigned = dict(event)
        claimed_hash = unsigned.pop("event_sha256")
        calculated_hash = hashlib.sha256(_canonical_bytes(unsigned)).hexdigest()
        if not hmac.compare_digest(claimed_hash, calculated_hash):
            raise AgentError("host operation journal hash is invalid")
        previous = claimed_hash
        events.append(event)
    return events


def _dispatch_nonce_seen(profile: Profile, nonce: str) -> bool:
    return any(event.get("dispatch_nonce") == nonce for event in _journal_events(profile))


def _write_journal(
    profile: Profile,
    phase: str,
    *,
    release_id: str | None = None,
    lease_id: str | None = None,
    fence: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    path = _journal_path(profile)
    events = _journal_events(profile)
    protected = {
        "schema",
        "project_id",
        "release_lane",
        "placement",
        "journal_seq",
        "previous_event_sha256",
        "event_sha256",
        "phase",
        "recorded_at",
        "release_id",
        "lease_id",
        "fence",
    }
    if protected.intersection(fields):
        raise AgentError("host operation journal fields conflict")
    document: dict[str, Any] = {
        "schema": OPERATION_JOURNAL_SCHEMA,
        "project_id": profile.project_id,
        "release_lane": profile.lane,
        "placement": profile.placement,
        "journal_seq": len(events) + 1,
        "previous_event_sha256": (events[-1]["event_sha256"] if events else _JOURNAL_GENESIS),
        "phase": phase,
        "recorded_at": datetime.datetime.now(datetime.UTC).isoformat(),
    }
    for name, value in (("release_id", release_id), ("lease_id", lease_id), ("fence", fence)):
        if value is not None:
            document[name] = value
    document.update(fields)
    document["event_sha256"] = hashlib.sha256(_canonical_bytes(document)).hexdigest()
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "ab") as stream:
            stream.write(_canonical_bytes(document) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        _fsync_directory(path.parent)
    except OSError as error:
        raise AgentError("host operation journal append failed") from error
    return document


def _runtime_evidence(
    document: dict[str, Any], profile: Profile, release: dict[str, str]
) -> dict[str, Any]:
    runtime = document.get("runtime_identity")
    dependencies = document.get("dependency_identity")
    provenance = document.get("artifact_provenance")
    if (
        not isinstance(runtime, dict)
        or not isinstance(dependencies, dict)
        or not isinstance(provenance, dict)
    ):
        raise AgentError("native receipt lacks runtime evidence")
    required_runtime = {"source_sha", "artifact_digest", "artifact_ref", "measured"}
    if (
        set(runtime) != required_runtime
        or runtime.get("measured") is not True
        or runtime.get("source_sha") != release["source_sha"]
        or runtime.get("artifact_digest") != release["artifact_digest"]
        or runtime.get("artifact_ref") != release["artifact_ref"]
    ):
        raise AgentError("native runtime identity is not measured or does not match release")
    if not dependencies or any(
        not isinstance(value, str) or not value.strip() for value in dependencies.values()
    ):
        raise AgentError("native dependency identity is incomplete")
    if profile.project_id == "id-qdev-run":
        from qdev_runner.idp_file_runtime import (
            ADAPTER,
            ARTIFACT_PREFIX,
            REPOSITORY,
            IdPObservationError,
            validate_runtime_evidence,
        )

        if (profile.repository, profile.adapter, profile.artifact_prefix) != (
            REPOSITORY,
            ADAPTER,
            ARTIFACT_PREFIX,
        ):
            raise AgentError("native IdP adapter scope is invalid")
        try:
            validate_runtime_evidence(document)
        except IdPObservationError:
            raise AgentError("native IdP runtime provenance is invalid") from None
    elif profile.name == "qmt":
        qmt_version = dependencies.get("qmt_version")
        if not isinstance(qmt_version, str) or not _QMT_VERSION.fullmatch(qmt_version):
            raise AgentError("native QMT dependency identity is invalid")
        candidate_fields = {
            "candidate_receipt_sha256",
            "migration_receipt_digest",
            "contract_digest",
        }
        legacy_fields = {"legacy_runtime_receipt_sha256"}
        if set(provenance) == candidate_fields:
            if qmt_version != "4.4.2":
                raise AgentError("native QMT dependency identity is invalid")
            if (
                not isinstance(provenance["candidate_receipt_sha256"], str)
                or not _HEX64.fullmatch(provenance["candidate_receipt_sha256"])
                or not isinstance(provenance["migration_receipt_digest"], str)
                or not _DIGEST.fullmatch(provenance["migration_receipt_digest"])
                or not isinstance(provenance["contract_digest"], str)
                or not _HEX64.fullmatch(provenance["contract_digest"])
            ):
                raise AgentError("native QMT artifact provenance is invalid")
        elif set(provenance) == legacy_fields:
            if (
                qmt_version == "4.4.2"
                or not isinstance(provenance["legacy_runtime_receipt_sha256"], str)
                or not _HEX64.fullmatch(provenance["legacy_runtime_receipt_sha256"])
            ):
                raise AgentError("native QMT legacy provenance is invalid")
        else:
            raise AgentError("native QMT artifact provenance is invalid")
    else:
        if set(provenance) != {
            "qak_wheel_sha256",
            "avds_artifact_sha256",
            "avds_source_sha",
        }:
            raise AgentError("native artifact provenance is incomplete")
        if (
            not isinstance(provenance["qak_wheel_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", provenance["qak_wheel_sha256"])
            or not isinstance(provenance["avds_artifact_sha256"], str)
            or not re.fullmatch(r"[0-9a-f]{64}", provenance["avds_artifact_sha256"])
            or not isinstance(provenance["avds_source_sha"], str)
            or not _SHA.fullmatch(provenance["avds_source_sha"])
        ):
            raise AgentError("native artifact provenance is invalid")
    return {
        "runtime_identity": runtime,
        "dependency_identity": dependencies,
        "artifact_provenance": provenance,
    }


def _validate_native_runtime(
    document: dict[str, Any], profile: Profile, release: dict[str, str]
) -> dict[str, Any]:
    base = {
        "schema",
        "project_id",
        "native_host_adapter",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
        "readiness",
    }
    evidence = {"runtime_identity", "dependency_identity", "artifact_provenance"}
    if (
        not isinstance(document, dict)
        or set(document) != base | evidence
        or document.get("schema") != NATIVE_RECEIPT_SCHEMA
        or document.get("project_id") != profile.project_id
        or document.get("native_host_adapter") != profile.adapter
        or document.get("readiness") != profile.readiness
        or _release(
            {
                field: document.get(field)
                for field in ("source_sha", "artifact_digest", "artifact_ref")
            },
            profile,
        )
        != release
    ):
        raise AgentError("native runtime receipt does not bind the managed release")
    return _runtime_evidence(document, profile, release)


def _native_release(document: dict[str, Any], profile: Profile) -> dict[str, str]:
    release = _release(
        {field: document.get(field) for field in ("source_sha", "artifact_digest", "artifact_ref")},
        profile,
    )
    _validate_native_runtime(document, profile, release)
    return release


def _completion_receipt(
    profile: Profile,
    release: dict[str, str],
    rollback: dict[str, str],
    native: dict[str, Any],
) -> dict[str, Any]:
    if release == rollback:
        raise AgentError("verified runtime receipt requires a distinct rollback anchor")
    evidence = _validate_native_runtime(native, profile, release)
    return {
        "schema": RUNTIME_RECEIPT_SCHEMA,
        "status": "verified",
        "project": profile.project_id,
        "release_lane": profile.lane,
        "placement": profile.placement,
        **release,
        "health": "ok",
        "readiness": profile.readiness,
        "rollback": {"verified": True, **rollback},
        **evidence,
    }


def _validate_completion_receipt(
    receipt: object,
    profile: Profile,
    release: dict[str, str],
    rollback: dict[str, str] | None = None,
) -> dict[str, Any]:
    base = {
        "schema",
        "status",
        "project",
        "release_lane",
        "placement",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
        "health",
        "readiness",
        "rollback",
    }
    evidence = {"runtime_identity", "dependency_identity", "artifact_provenance"}
    if (
        not isinstance(receipt, dict)
        or set(receipt) != base | evidence
        or receipt.get("schema") != RUNTIME_RECEIPT_SCHEMA
        or receipt.get("status") != "verified"
        or receipt.get("project") != profile.project_id
        or receipt.get("release_lane") != profile.lane
        or receipt.get("placement") != profile.placement
        or receipt.get("health") != "ok"
        or receipt.get("readiness") != profile.readiness
        or _release(
            {
                field: receipt.get(field)
                for field in ("source_sha", "artifact_digest", "artifact_ref")
            },
            profile,
        )
        != release
    ):
        raise AgentError("controller runtime receipt does not bind the managed release")
    rollback_raw = receipt.get("rollback")
    if (
        not isinstance(rollback_raw, dict)
        or set(rollback_raw) != {"verified", "source_sha", "artifact_digest", "artifact_ref"}
        or rollback_raw.get("verified") is not True
    ):
        raise AgentError("controller runtime receipt rollback anchor is invalid")
    measured_rollback = _release(
        {
            field: rollback_raw.get(field)
            for field in ("source_sha", "artifact_digest", "artifact_ref")
        },
        profile,
    )
    if measured_rollback == release or (rollback is not None and measured_rollback != rollback):
        raise AgentError("controller runtime receipt rollback anchor does not match")
    _runtime_evidence(receipt, profile, release)
    return receipt


def _rollback_receipt(
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    restored: dict[str, str],
    native: dict[str, Any],
) -> dict[str, Any]:
    if candidate == restored:
        raise AgentError("rollback must restore a distinct immutable tuple")
    _validate_native_runtime(native, profile, restored)
    return {
        "schema": ROLLBACK_RECEIPT_SCHEMA,
        "status": "rolled_back",
        "project_id": profile.project_id,
        "release_lane": profile.lane,
        "placement": profile.placement,
        "release_id": release_id,
        "failed_release": candidate,
        "restored_release": restored,
        "native_receipt": native,
    }


def _validate_rollback_receipt(
    receipt: object,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    restored: dict[str, str] | None = None,
) -> dict[str, Any]:
    expected = {
        "schema",
        "status",
        "project_id",
        "release_lane",
        "placement",
        "release_id",
        "failed_release",
        "restored_release",
        "native_receipt",
    }
    if (
        not isinstance(receipt, dict)
        or set(receipt) != expected
        or receipt.get("schema") != ROLLBACK_RECEIPT_SCHEMA
        or receipt.get("status") != "rolled_back"
        or receipt.get("project_id") != profile.project_id
        or receipt.get("release_lane") != profile.lane
        or receipt.get("placement") != profile.placement
        or receipt.get("release_id") != release_id
        or receipt.get("failed_release") != candidate
    ):
        raise AgentError("controller rollback receipt does not bind the managed operation")
    measured_restored = _release(receipt.get("restored_release"), profile)
    if measured_restored == candidate or (restored is not None and measured_restored != restored):
        raise AgentError("controller rollback receipt restored tuple does not match")
    native = receipt.get("native_receipt")
    if not isinstance(native, dict):
        raise AgentError("controller rollback receipt lacks native runtime evidence")
    _validate_native_runtime(native, profile, measured_restored)
    return receipt


def _controller_headers(lease_id: str, fence: str) -> dict[str, str]:
    if not _LEASE.fullmatch(lease_id) or not _FENCE.fullmatch(fence):
        raise AgentError("managed controller lease or fence is invalid")
    return {
        "X-QDev-Release-Lease": lease_id,
        "X-QDev-Release-Fence": fence,
    }


def _response_json(body: bytes, *, outcome_unknown: bool) -> dict[str, Any]:
    try:
        document = json.loads(body)
    except json.JSONDecodeError as error:
        if outcome_unknown:
            raise ControllerTransportError("controller response is not JSON") from error
        raise AgentError("controller response is not JSON") from error
    if not isinstance(document, dict):
        if outcome_unknown:
            raise ControllerTransportError("controller response is invalid")
        raise AgentError("controller response is invalid")
    return document


def _submit_completion(
    config: Config,
    profile: Profile,
    release_id: str,
    lease_id: str,
    fence: str,
    receipt: dict[str, Any],
) -> None:
    status, body = request(
        config,
        "POST",
        f"/internal/v1/release-hosts/{profile.placement}/jobs/{release_id}/complete",
        receipt,
        headers=_controller_headers(lease_id, fence),
    )
    if status != 200:
        raise AgentError("controller rejected verified runtime receipt")
    returned = _response_json(body, outcome_unknown=True)
    if returned != receipt:
        raise ControllerTransportError(
            "controller completion acknowledgement does not match submitted receipt"
        )


def _submit_rollback(
    config: Config,
    profile: Profile,
    release_id: str,
    lease_id: str,
    fence: str,
    receipt: dict[str, Any],
) -> None:
    status, body = request(
        config,
        "POST",
        f"/internal/v1/release-hosts/{profile.placement}/jobs/{release_id}/rollback",
        receipt,
        headers=_controller_headers(lease_id, fence),
    )
    if status != 200:
        raise AgentError("controller rejected rollback receipt")
    returned = _response_json(body, outcome_unknown=True)
    if returned != receipt:
        raise ControllerTransportError(
            "controller rollback acknowledgement does not match submitted receipt"
        )


def _controller_status(
    config: Config,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    lease_id: str,
    fence: str,
    *,
    restored: dict[str, str] | None = None,
) -> dict[str, Any]:
    status, body = request(
        config,
        "GET",
        f"/internal/v1/release-hosts/{profile.placement}/jobs/{release_id}",
        headers=_controller_headers(lease_id, fence),
    )
    if status != 200:
        raise AgentError("controller has no verifiable release outcome")
    document = _response_json(body, outcome_unknown=False)
    expected = {
        "schema",
        "release_id",
        "status",
        "release_lane",
        "project_id",
        "placement",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
        "runtime_receipt",
        "rollback_receipt",
    }
    if (
        set(document) != expected
        or document.get("schema") != "qdev-controller-release-status-v1"
        or document.get("release_id") != release_id
        or document.get("release_lane") != profile.lane
        or document.get("project_id") != profile.project_id
        or document.get("placement") != profile.placement
        or _release(
            {
                field: document.get(field)
                for field in ("source_sha", "artifact_digest", "artifact_ref")
            },
            profile,
        )
        != candidate
    ):
        raise AgentError("controller release outcome identity is invalid")
    controller_state = document.get("status")
    if controller_state in {"accepted", "dispatched"}:
        if (
            document.get("runtime_receipt") is not None
            or document.get("rollback_receipt") is not None
        ):
            raise AgentError("active controller release has a terminal receipt")
    elif controller_state == "verified":
        if document.get("rollback_receipt") is not None:
            raise AgentError("verified controller release has a rollback receipt")
        _validate_completion_receipt(document.get("runtime_receipt"), profile, candidate, restored)
    elif controller_state == "rolled_back":
        if document.get("runtime_receipt") is not None:
            raise AgentError("rolled-back controller release has a runtime receipt")
        _validate_rollback_receipt(
            document.get("rollback_receipt"),
            profile,
            release_id,
            candidate,
            restored,
        )
    else:
        raise AgentError("controller release outcome state is invalid")
    return document


def reconcile(
    config: Config,
    profile: Profile,
    release_id: str,
    release: dict[str, str],
    *,
    lease_id: str,
    fence: str,
    rollback: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Read and validate the exact controller state without native mutation."""
    return _controller_status(
        config,
        profile,
        release_id,
        release,
        lease_id,
        fence,
        restored=rollback,
    )


def _resolve_completion_outcome(
    config: Config,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    rollback: dict[str, str],
    lease_id: str,
    fence: str,
    receipt: dict[str, Any],
    lease_expires_at: int,
) -> None:
    _validate_completion_receipt(receipt, profile, candidate, rollback)
    try:
        state = _controller_status(
            config,
            profile,
            release_id,
            candidate,
            lease_id,
            fence,
            restored=rollback,
        )
    except (AgentError, ControllerTransportError) as error:
        raise ControllerOutcomeUnresolved(
            "controller completion outcome cannot be reconciled"
        ) from error
    if state["status"] == "verified":
        if state["runtime_receipt"] != receipt:
            raise ControllerOutcomeUnresolved("controller verified a different runtime receipt")
        return
    if state["status"] == "rolled_back":
        raise ControllerOutcomeUnresolved("controller already records the operation as rolled back")
    submission_error: AgentError | None = None
    try:
        _ensure_live_lease(lease_expires_at)
        _submit_completion(config, profile, release_id, lease_id, fence, receipt)
        return
    except AgentError as error:
        submission_error = error
        was_unknown = isinstance(error, ControllerTransportError)
    try:
        state = _controller_status(
            config,
            profile,
            release_id,
            candidate,
            lease_id,
            fence,
            restored=rollback,
        )
    except (AgentError, ControllerTransportError) as error:
        raise ControllerOutcomeUnresolved(
            "controller completion outcome remains unknown"
        ) from error
    if state["status"] == "verified" and state["runtime_receipt"] == receipt:
        return
    if state["status"] != "dispatched" and state["status"] != "accepted":
        raise ControllerOutcomeUnresolved(
            "controller terminal completion outcome conflicts with the host receipt"
        ) from submission_error
    if not was_unknown:
        raise ControllerOutcomeUnresolved(
            "controller rejected the exact runtime receipt"
        ) from submission_error
    try:
        _ensure_live_lease(lease_expires_at)
        _submit_completion(config, profile, release_id, lease_id, fence, receipt)
        return
    except AgentError as retry_error:
        try:
            state = _controller_status(
                config,
                profile,
                release_id,
                candidate,
                lease_id,
                fence,
                restored=rollback,
            )
        except (AgentError, ControllerTransportError) as error:
            raise ControllerOutcomeUnresolved(
                "controller completion retry outcome remains unknown"
            ) from error
        if state["status"] == "verified" and state["runtime_receipt"] == receipt:
            return
        raise ControllerOutcomeUnresolved(
            "controller completion retry was not durably accepted"
        ) from retry_error


def _resolve_rollback_outcome(
    config: Config,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    restored: dict[str, str],
    lease_id: str,
    fence: str,
    receipt: dict[str, Any],
    lease_expires_at: int,
) -> None:
    _validate_rollback_receipt(receipt, profile, release_id, candidate, restored)
    try:
        state = _controller_status(
            config,
            profile,
            release_id,
            candidate,
            lease_id,
            fence,
            restored=restored,
        )
    except (AgentError, ControllerTransportError) as error:
        raise ControllerOutcomeUnresolved(
            "controller rollback outcome cannot be reconciled"
        ) from error
    if state["status"] == "rolled_back":
        if state["rollback_receipt"] != receipt:
            raise ControllerOutcomeUnresolved("controller recorded a different rollback receipt")
        return
    if state["status"] == "verified":
        raise ControllerOutcomeUnresolved("controller already records the candidate as verified")
    submission_error: AgentError | None = None
    try:
        _ensure_live_lease(lease_expires_at)
        _submit_rollback(config, profile, release_id, lease_id, fence, receipt)
        return
    except AgentError as error:
        submission_error = error
        was_unknown = isinstance(error, ControllerTransportError)
    try:
        state = _controller_status(
            config,
            profile,
            release_id,
            candidate,
            lease_id,
            fence,
            restored=restored,
        )
    except (AgentError, ControllerTransportError) as error:
        raise ControllerOutcomeUnresolved("controller rollback outcome remains unknown") from error
    if state["status"] == "rolled_back" and state["rollback_receipt"] == receipt:
        return
    if state["status"] not in {"accepted", "dispatched"}:
        raise ControllerOutcomeUnresolved(
            "controller terminal rollback outcome conflicts with the host receipt"
        ) from submission_error
    if not was_unknown:
        raise ControllerOutcomeUnresolved(
            "controller rejected the exact rollback receipt"
        ) from submission_error
    try:
        _ensure_live_lease(lease_expires_at)
        _submit_rollback(config, profile, release_id, lease_id, fence, receipt)
        return
    except AgentError as retry_error:
        try:
            state = _controller_status(
                config,
                profile,
                release_id,
                candidate,
                lease_id,
                fence,
                restored=restored,
            )
        except (AgentError, ControllerTransportError) as error:
            raise ControllerOutcomeUnresolved(
                "controller rollback retry outcome remains unknown"
            ) from error
        if state["status"] == "rolled_back" and state["rollback_receipt"] == receipt:
            return
        raise ControllerOutcomeUnresolved(
            "controller rollback retry was not durably accepted"
        ) from retry_error


def _operation_context(
    profile: Profile,
    candidate: dict[str, str],
    previous_release: dict[str, str],
    previous_rollback: dict[str, str],
    dispatch_nonce: str,
    lease_expires_at: int,
    rollback_anchor: dict[str, str],
    *,
    runtime_receipt: dict[str, Any] | None = None,
    rollback_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    candidate = _release(candidate, profile)
    previous_release = _release(previous_release, profile)
    previous_rollback = _release(previous_rollback, profile)
    rollback_anchor = _release(rollback_anchor, profile)
    if candidate == previous_release:
        raise AgentError("candidate already matches the active release")
    if rollback_anchor != previous_release:
        raise AgentError("operation does not bind the frozen rollback anchor")
    if (
        not isinstance(lease_expires_at, int)
        or isinstance(lease_expires_at, bool)
        or lease_expires_at <= 0
    ):
        raise AgentError("operation lease expiry is invalid")
    if not _NONCE.fullmatch(dispatch_nonce):
        raise AgentError("operation dispatch nonce is invalid")
    context: dict[str, Any] = {
        "candidate_release": candidate,
        "previous_release": previous_release,
        "previous_rollback": previous_rollback,
        "dispatch_nonce": dispatch_nonce,
        "lease_expires_at": lease_expires_at,
        "rollback_anchor": rollback_anchor,
    }
    if runtime_receipt is not None:
        context["runtime_receipt"] = _validate_completion_receipt(
            runtime_receipt, profile, candidate, previous_release
        )
    if rollback_receipt is not None:
        context["rollback_receipt"] = _validate_rollback_receipt(
            rollback_receipt,
            profile,
            str(rollback_receipt.get("release_id")),
            candidate,
            previous_release,
        )
    return context


def _write_operation(
    profile: Profile,
    phase: str,
    release_id: str,
    lease_id: str,
    fence: str,
    context: dict[str, Any],
) -> dict[str, Any]:
    return _write_journal(
        profile,
        phase,
        release_id=release_id,
        lease_id=lease_id,
        fence=fence,
        **context,
    )


def _pending_operation(
    profile: Profile, *, include_completed: bool = False,
) -> dict[str, Any] | None:
    events = [event for event in _journal_events(profile) if "release_id" in event]
    if not events:
        return None
    release_id = events[-1].get("release_id")
    if not isinstance(release_id, str) or not _LEASE.fullmatch(release_id):
        raise AgentError("host operation journal release id is invalid")
    operation = [event for event in events if event.get("release_id") == release_id]
    if operation[-1].get("phase") == "rolled_back" or (
        operation[-1].get("phase") == "completed" and not include_completed
    ):
        return None
    supported_phases = {
        "dispatch_accepted",
        "release_started",
        "release_ready",
        "completion_unresolved",
        "verified",
        "verified_state_write_failed",
        "rollback_started",
        "rollback_ready",
        "rollback_unresolved",
        "recovery_release_ready",
        "recovery_rollback_ready",
        "recovery_unresolved",
    }
    if include_completed:
        supported_phases.add("completed")
    if any(event.get("phase") not in supported_phases for event in operation):
        raise AgentError("host operation journal phase is invalid")
    identity: dict[str, str] = {}
    context: dict[str, Any] = {}
    context_names = {
        "candidate_release",
        "previous_release",
        "previous_rollback",
        "dispatch_nonce",
        "lease_expires_at",
        "rollback_anchor",
        "runtime_receipt",
        "rollback_receipt",
    }
    for event in operation:
        for name in ("release_id", "lease_id", "fence"):
            value = event.get(name)
            if not isinstance(value, str):
                raise AgentError("host operation journal fencing identity is invalid")
            if name in identity and identity[name] != value:
                raise AgentError("host operation journal fencing identity changed")
            identity[name] = value
        for name in context_names.intersection(event):
            value = event[name]
            if name in context and context[name] != value:
                raise AgentError("host operation journal context changed")
            context[name] = value
    required_context = {
        "candidate_release",
        "previous_release",
        "previous_rollback",
        "dispatch_nonce",
        "lease_expires_at",
        "rollback_anchor",
    }
    if not required_context.issubset(context):
        raise AgentError("host operation journal recovery context is incomplete")
    checked = _operation_context(
        profile,
        context["candidate_release"],
        context["previous_release"],
        context["previous_rollback"],
        context["dispatch_nonce"],
        context["lease_expires_at"],
        context["rollback_anchor"],
        runtime_receipt=context.get("runtime_receipt"),
        rollback_receipt=context.get("rollback_receipt"),
    )
    if "rollback_receipt" in checked:
        _validate_rollback_receipt(
            checked["rollback_receipt"],
            profile,
            release_id,
            checked["candidate_release"],
            checked["previous_release"],
        )
    return {
        **identity,
        **checked,
        "phases": tuple(str(event["phase"]) for event in operation),
    }


def _record_recovery_unresolved(
    profile: Profile,
    release_id: str,
    lease_id: str,
    fence: str,
    context: dict[str, Any],
    reason: str,
) -> None:
    _write_operation(
        profile,
        "recovery_unresolved",
        release_id,
        lease_id,
        fence,
        {**context, "recovery_reason": reason},
    )


def _recover_pending(
    config: Config,
    profile: Profile,
    active: dict[str, str],
    rollback: dict[str, str],
    pending: dict[str, Any],
    *,
    observe_current: Callable[[], dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Reconcile one durable operation without repeating a native mutation."""
    if observe_current is not None and not callable(observe_current):
        raise AgentError("native recovery observation must be a trusted callable")
    release_id = pending.get("release_id")
    lease_id = pending.get("lease_id")
    fence = pending.get("fence")
    dispatch_nonce = pending.get("dispatch_nonce")
    lease_expires_at = pending.get("lease_expires_at")
    phases = pending.get("phases")
    if (
        not isinstance(release_id, str)
        or not _LEASE.fullmatch(release_id)
        or not isinstance(lease_id, str)
        or not _LEASE.fullmatch(lease_id)
        or not isinstance(fence, str)
        or not _FENCE.fullmatch(fence)
        or not isinstance(dispatch_nonce, str)
        or not _NONCE.fullmatch(dispatch_nonce)
        or not isinstance(lease_expires_at, int)
        or isinstance(lease_expires_at, bool)
        or not isinstance(phases, tuple)
        or not phases
        or any(not isinstance(phase, str) for phase in phases)
    ):
        raise AgentError("pending operation identity is invalid")
    candidate = _release(pending.get("candidate_release"), profile)
    previous_release = _release(pending.get("previous_release"), profile)
    previous_rollback = _release(pending.get("previous_rollback"), profile)
    rollback_anchor = _release(pending.get("rollback_anchor"), profile)
    runtime_receipt = pending.get("runtime_receipt")
    rollback_receipt = pending.get("rollback_receipt")
    context = _operation_context(
        profile,
        candidate,
        previous_release,
        previous_rollback,
        dispatch_nonce,
        lease_expires_at,
        rollback_anchor,
        runtime_receipt=runtime_receipt if isinstance(runtime_receipt, dict) else None,
        rollback_receipt=rollback_receipt if isinstance(rollback_receipt, dict) else None,
    )
    before_state = active == previous_release and rollback == previous_rollback
    verified_state = active == candidate and rollback == previous_release
    if not before_state and not verified_state:
        reason = "local state does not match either durable operation boundary"
        _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
        raise ControllerOutcomeUnresolved(reason)

    current_native = (
        native_receipt(profile, current=True) if observe_current is None else observe_current()
    )
    current_release = _native_release(current_native, profile)
    try:
        state = _controller_status(
            config,
            profile,
            release_id,
            candidate,
            lease_id,
            fence,
            restored=previous_release,
        )
    except AgentError as error:
        reason = "controller outcome is unavailable during recovery"
        _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
        raise ControllerOutcomeUnresolved(reason) from error

    if state["status"] == "verified":
        measured_receipt = state["runtime_receipt"]
        assert isinstance(measured_receipt, dict)
        if runtime_receipt is not None and runtime_receipt != measured_receipt:
            reason = "controller and durable runtime receipts disagree"
            _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
            raise ControllerOutcomeUnresolved(reason)
        if current_release != candidate:
            reason = "controller is verified but the candidate is not running"
            _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
            raise ControllerOutcomeUnresolved(reason)
        if profile.adapter == "idp-file-v1":
            _idp_reobserved_completion(
                measured_receipt,
                _completion_receipt(profile, candidate, previous_release, current_native),
            )
        if phases[-1] == "completed":
            if not verified_state or runtime_receipt is None:
                raise ControllerOutcomeUnresolved("completed operation state is inconsistent")
            return {"status": "verified", "recovered": True, "release_id": release_id}
        verified_context = _operation_context(
            profile,
            candidate,
            previous_release,
            previous_rollback,
            dispatch_nonce,
            lease_expires_at,
            rollback_anchor,
            runtime_receipt=measured_receipt,
        )
        _write_operation(
            profile,
            "verified",
            release_id,
            lease_id,
            fence,
            verified_context,
        )
        try:
            write_state(profile.state_path, candidate, previous_release)
        except (AgentError, OSError):
            _write_operation(
                profile,
                "verified_state_write_failed",
                release_id,
                lease_id,
                fence,
                verified_context,
            )
            raise
        _write_operation(
            profile,
            "completed",
            release_id,
            lease_id,
            fence,
            verified_context,
        )
        return {"status": "verified", "recovered": True, "release_id": release_id}

    if state["status"] == "rolled_back":
        measured_receipt = state["rollback_receipt"]
        assert isinstance(measured_receipt, dict)
        if rollback_receipt is not None and rollback_receipt != measured_receipt:
            reason = "controller and durable rollback receipts disagree"
            _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
            raise ControllerOutcomeUnresolved(reason)
        if current_release != previous_release:
            reason = "controller is rolled back but the rollback anchor is not running"
            _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
            raise ControllerOutcomeUnresolved(reason)
        rolled_back_context = _operation_context(
            profile,
            candidate,
            previous_release,
            previous_rollback,
            dispatch_nonce,
            lease_expires_at,
            rollback_anchor,
            rollback_receipt=measured_receipt,
        )
        _write_operation(
            profile,
            "recovery_rollback_ready",
            release_id,
            lease_id,
            fence,
            rolled_back_context,
        )
        write_state(profile.state_path, previous_release, previous_rollback)
        _write_operation(
            profile,
            "rolled_back",
            release_id,
            lease_id,
            fence,
            rolled_back_context,
        )
        return {"status": "rolled_back", "recovered": True, "release_id": release_id}

    if current_release == candidate:
        if phases[-1] == "completed":
            raise ControllerOutcomeUnresolved("completed operation is not controller-verified")
        rollback_intent = any(
            phase
            in {
                "rollback_started",
                "rollback_ready",
                "rollback_unresolved",
                "recovery_rollback_ready",
            }
            for phase in phases
        )
        if rollback_intent:
            reason = "candidate is still running after durable rollback intent"
            _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
            raise ControllerOutcomeUnresolved(reason)
        measured_receipt = _completion_receipt(profile, candidate, previous_release, current_native)
        if runtime_receipt is not None and profile.adapter == "idp-file-v1":
            measured_receipt = _idp_reobserved_completion(runtime_receipt, measured_receipt)
        if runtime_receipt is not None and runtime_receipt != measured_receipt:
            reason = "fresh and durable runtime receipts disagree"
            _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
            raise ControllerOutcomeUnresolved(reason)
        verified_context = _operation_context(
            profile,
            candidate,
            previous_release,
            previous_rollback,
            dispatch_nonce,
            lease_expires_at,
            rollback_anchor,
            runtime_receipt=measured_receipt,
        )
        _write_operation(
            profile,
            "recovery_release_ready",
            release_id,
            lease_id,
            fence,
            verified_context,
        )
        try:
            _resolve_completion_outcome(
                config,
                profile,
                release_id,
                candidate,
                previous_release,
                lease_id,
                fence,
                measured_receipt,
                lease_expires_at,
            )
        except ControllerOutcomeUnresolved:
            _write_operation(
                profile,
                "completion_unresolved",
                release_id,
                lease_id,
                fence,
                verified_context,
            )
            raise
        _write_operation(
            profile,
            "verified",
            release_id,
            lease_id,
            fence,
            verified_context,
        )
        try:
            write_state(profile.state_path, candidate, previous_release)
        except (AgentError, OSError):
            _write_operation(
                profile,
                "verified_state_write_failed",
                release_id,
                lease_id,
                fence,
                verified_context,
            )
            raise
        _write_operation(
            profile,
            "completed",
            release_id,
            lease_id,
            fence,
            verified_context,
        )
        return {"status": "verified", "recovered": True, "release_id": release_id}

    if current_release == previous_release:
        if any(phase in {"verified", "verified_state_write_failed"} for phase in phases):
            reason = "verified journal state conflicts with active controller state"
            _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
            raise ControllerOutcomeUnresolved(reason)
        measured_receipt = _rollback_receipt(
            profile, release_id, candidate, previous_release, current_native
        )
        if rollback_receipt is not None and rollback_receipt != measured_receipt:
            reason = "fresh and durable rollback receipts disagree"
            _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
            raise ControllerOutcomeUnresolved(reason)
        rolled_back_context = _operation_context(
            profile,
            candidate,
            previous_release,
            previous_rollback,
            dispatch_nonce,
            lease_expires_at,
            rollback_anchor,
            rollback_receipt=measured_receipt,
        )
        _write_operation(
            profile,
            "recovery_rollback_ready",
            release_id,
            lease_id,
            fence,
            rolled_back_context,
        )
        try:
            _resolve_rollback_outcome(
                config,
                profile,
                release_id,
                candidate,
                previous_release,
                lease_id,
                fence,
                measured_receipt,
                lease_expires_at,
            )
        except ControllerOutcomeUnresolved:
            _write_operation(
                profile,
                "rollback_unresolved",
                release_id,
                lease_id,
                fence,
                rolled_back_context,
            )
            raise
        write_state(profile.state_path, previous_release, previous_rollback)
        _write_operation(
            profile,
            "rolled_back",
            release_id,
            lease_id,
            fence,
            rolled_back_context,
        )
        return {"status": "rolled_back", "recovered": True, "release_id": release_id}

    reason = "native runtime matches neither durable operation boundary"
    _record_recovery_unresolved(profile, release_id, lease_id, fence, context, reason)
    raise ControllerOutcomeUnresolved(reason)


def rollback_remote(
    config: Config,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    restored: dict[str, str],
    *,
    lease_id: str,
    fence: str,
    dispatch_nonce: str,
    previous_rollback: dict[str, str],
    lease_expires_at: int,
    rollback_anchor: dict[str, str],
) -> dict[str, Any]:
    base_context = _operation_context(
        profile,
        candidate,
        restored,
        previous_rollback,
        dispatch_nonce,
        lease_expires_at,
        rollback_anchor,
    )
    try:
        state = _controller_status(
            config,
            profile,
            release_id,
            candidate,
            lease_id,
            fence,
            restored=restored,
        )
    except (AgentError, ControllerTransportError) as error:
        raise ControllerOutcomeUnresolved("controller state is unknown before rollback") from error
    if state["status"] == "verified":
        raise ControllerOutcomeUnresolved(
            "controller already verified the candidate; rollback is not safe"
        )
    if state["status"] == "rolled_back":
        receipt = state["rollback_receipt"]
        assert isinstance(receipt, dict)
        _write_operation(
            profile,
            "rolled_back",
            release_id,
            lease_id,
            fence,
            _operation_context(
                profile,
                candidate,
                restored,
                previous_rollback,
                dispatch_nonce,
                lease_expires_at,
                rollback_anchor,
                rollback_receipt=receipt,
            ),
        )
        return receipt
    current_native = native_receipt(profile, current=True)
    current = _native_release(current_native, profile)
    if current == candidate:
        _write_operation(
            profile,
            "rollback_started",
            release_id,
            lease_id,
            fence,
            base_context,
        )
        _ensure_live_lease(lease_expires_at)
        invoke_native(profile, "rollback", restored)
        restored_native = native_receipt(profile, current=True)
        _validate_native_runtime(restored_native, profile, restored)
    elif current == restored:
        restored_native = current_native
    else:
        raise ControllerOutcomeUnresolved(
            "native release is neither the candidate nor the verified rollback anchor"
        )
    receipt = _rollback_receipt(profile, release_id, candidate, restored, restored_native)
    context = _operation_context(
        profile,
        candidate,
        restored,
        previous_rollback,
        dispatch_nonce,
        lease_expires_at,
        rollback_anchor,
        rollback_receipt=receipt,
    )
    _write_operation(profile, "rollback_ready", release_id, lease_id, fence, context)
    try:
        _resolve_rollback_outcome(
            config,
            profile,
            release_id,
            candidate,
            restored,
            lease_id,
            fence,
            receipt,
            lease_expires_at,
        )
    except ControllerOutcomeUnresolved:
        _write_operation(
            profile,
            "rollback_unresolved",
            release_id,
            lease_id,
            fence,
            context,
        )
        raise
    _write_operation(profile, "rolled_back", release_id, lease_id, fence, context)
    return receipt


def _lock_directory(path: Path) -> None:
    if not path.is_absolute() or ".." in path.parts:
        raise AgentError("release lock directory must be absolute")
    for directory in reversed((path, *path.parents)):
        meta = directory.lstat()
        # /run/lock may legitimately be root-owned 01777. Sticky protection
        # applies only to this final directory; all ancestors remain immutable
        # to non-root users. Leaf ownership is separately checked before use.
        sticky_leaf = directory == path and bool(meta.st_mode & stat.S_ISVTX)
        if (
            not stat.S_ISDIR(meta.st_mode)
            or meta.st_uid != 0
            or (stat.S_IMODE(meta.st_mode) & 0o022 and not sticky_leaf)
        ):
            raise AgentError("release lock directory has unsafe ancestry")


def _acquire_lock(path: Path) -> TextIO:
    _lock_directory(path.parent)
    _private(path, required=False)
    flags = os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        opened, named = os.fstat(descriptor), path.lstat()
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or (opened.st_dev, opened.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise AgentError("release lock must be one unchanged regular file")
        _private(path)
        stream = os.fdopen(descriptor, "r+", encoding="utf-8")
    except BaseException:
        os.close(descriptor)
        raise
    return stream


class JournaledFileApplyGuard:
    """Live host guard; usable only while the native operation lock is held."""

    def __init__(self, check: Callable[[], None]) -> None:
        self._check = check
        self._active = True

    def assert_current(self) -> None:
        if not self._active:
            raise AgentError("file apply guard is outside its native transaction")
        self._check()

    def close(self) -> None:
        self._active = False


@dataclass(frozen=True)
class FileApplyObservations:
    """Fixed-adapter readers, never serialized claims or supplied receipt flags.

    The IdP adapter must use its already-locked native reader. Re-entering its
    CLI/dispatch here would attempt to acquire the same global lock again.
    Every result still passes the compiled profile's exact runtime validator.
    """

    before_apply: Callable[[], dict[str, Any]]
    after_apply: Callable[[], dict[str, Any]]

    def __post_init__(self) -> None:
        if not callable(self.before_apply) or not callable(self.after_apply):
            raise AgentError("file apply observations must be trusted callables")


def _idp_previous_observation(profile, anchor):
    """Read a prior accepted observation from the existing protected journal.

    Never search arbitrary receipts or infer an artifact from the installed
    manifest. Only a durable verified native completion can supply this anchor.
    The transaction later rechecks state and this record under the host lock.
    """
    from qdev_runner.idp_file_runtime import validate_runtime_evidence

    for event in reversed(_journal_events(profile)):
        if event.get("phase") != "verified" or event.get("candidate_release") != anchor:
            continue
        receipt = _validate_completion_receipt(
            event.get("runtime_receipt"),
            profile,
            anchor,
            event.get("previous_release"),
        )
        validate_runtime_evidence(receipt, installed_only=True)
        return json.loads(_canonical_bytes(receipt["artifact_provenance"]["observation"]))
    raise AgentError("previous IdP release has no accepted native journal observation")


def _validate_idp_file_scope(config, profile, lane):
    from qdev_runner.idp_file_runtime import ADAPTER, ARTIFACT_PREFIX, PROJECT, REPOSITORY

    if (
        (profile.project_id, profile.repository, profile.adapter, profile.artifact_prefix)
        != (PROJECT, REPOSITORY, ADAPTER, ARTIFACT_PREFIX)
        or (
            lane.project_id,
            lane.canonical_repository,
            lane.native_host_adapter,
            lane.artifact_ref_prefix,
        )
        != (PROJECT, REPOSITORY, ADAPTER, ARTIFACT_PREFIX)
        or profile.lane != lane.name
        or profile.placement != lane.placement
        or config.host_identity != lane.host_agent_mtls_identity
        or profile.readiness != {key: "ok" for key in lane.required_readiness}
    ):
        raise AgentError("IdP file adapter requires its fixed native lane and identity")


def _idp_authorization_response(raw, job):
    """Strict bounded transport envelope; signatures are verified by the bridge."""

    def unique(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate")
            value[key] = item
        return value

    try:
        if not isinstance(raw, bytes) or not 0 < len(raw) <= 2 * 1024 * 1024:
            raise ValueError("size")
        value = json.loads(raw, object_pairs_hook=unique)
        if (
            not isinstance(value, dict)
            or set(value)
            != {
                "schema",
                "authorization",
                "authorization_signature",
                "dispatch_claim",
                "dispatch_claim_signature",
                "candidate_receipt",
                "journal_seq",
                "journal_event_sha256",
                "acceptance",
            }
            or value["schema"] != "qdev-controller-idp-file-authorization-receipt-v1"
            or value["acceptance"] != "not_run"
            or value["dispatch_claim"] != job["dispatch_claim"]
            or value["dispatch_claim_signature"] != job["dispatch_claim_signature"]
            or type(value["journal_seq"]) is not int
            or value["journal_seq"] <= 0
            or not isinstance(value["journal_event_sha256"], str)
            or not _HEX64.fullmatch(value["journal_event_sha256"])
            or not isinstance(value["authorization"], dict)
            or not isinstance(value["authorization_signature"], str)
            or not isinstance(value["candidate_receipt"], dict)
        ):
            raise ValueError("envelope")
        return value
    except (ValueError, TypeError, KeyError, RecursionError):
        # Never include an untrusted response, exception body or native evidence.
        raise AgentError("invalid controller IdP authorization response") from None


class ControllerIssuedIdPFileApplyAdapter:
    """Fixed in-process collector/issuer bridge, not an installed enrollment.

    Verified native dispatch holds its global lock across collection, network
    issuance and application. The host lock is released during provider checks;
    the existing durable transaction rechecks everything before consuming the
    dispatch. No retries, renewed lease, native CLI or caller-selected key/path.
    """

    def __init__(self, config, profile, lane, job):
        _validate_idp_file_scope(config, profile, lane)
        _validated_job(job, profile, config)
        self._config, self._profile, self._lane = config, profile, lane
        self._job = _canonical_bytes(job)

    def __call__(self, reader):
        from qdev_runner.file_apply_authorization import canonical_bytes, parse_binding
        from qdev_runner.idp_file_issuer import parse_native
        from qdev_runner.idp_file_runtime import native_receipt

        if not callable(getattr(reader, "observe_prepared", None)) or not callable(
            getattr(reader, "observe_installed", None)
        ):
            raise AgentError("locked native IdP observation reader required")
        config, profile, lane = self._config, self._profile, self._lane
        job = json.loads(self._job)

        @contextmanager
        def authorize(binding):
            scope = parse_binding(binding, now=time.time())
            with _acquire_lock(profile.lock_path) as lock:
                try:
                    fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as error:
                    raise AgentError("release lock is already held") from error
                if _pending_operation(profile) is not None:
                    raise ControllerOutcomeUnresolved(
                        "pending native operation requires reconciliation"
                    )
                release_id, candidate, lease, fence, nonce, _, anchor, _ = _validated_job(
                    job, profile, config
                )
                if _dispatch_nonce_seen(profile, nonce):
                    raise AgentError("controller host dispatch claim was already consumed")
                active, _ = read_state(profile.state_path, profile, allow_bootstrap=True)
                if active != anchor:
                    raise AgentError("IdP runtime anchor differs from current host state")
                previous = (
                    None
                    if anchor["artifact_digest"] == f"sha256:{scope.snapshot_sha256}"
                    else _idp_previous_observation(profile, anchor)
                )
                raw = canonical_bytes(reader.observe_prepared())
                native = parse_native(raw, lane)
                prepared = native_receipt(
                    native,
                    installed=False,
                    expected_binding=binding,
                    now=time.time(),
                    previous_observation=previous,
                )
                _validate_native_runtime(prepared, profile, active)
                current = _controller_status(
                    config, profile, release_id, candidate, lease, fence, restored=active
                )
                if current["status"] != "dispatched":
                    raise AgentError("file apply requires the current dispatched controller job")
            status, body = request(
                config,
                "POST",
                f"/internal/v1/release-hosts/{profile.placement}/jobs/{release_id}"
                "/idp-file-authorization",
                raw,
                headers=_controller_headers(lease, fence),
            )
            if status != 200:
                raise ControllerTransportError("controller IdP authorization was not confirmed")
            response = _idp_authorization_response(body, job)
            adapter = IdPFileApplyAdapter(
                config,
                profile,
                lane,
                job,
                response["authorization"],
                response["authorization_signature"],
                candidate_receipt=response["candidate_receipt"],
            )
            with adapter(reader)(binding) as guard:
                yield guard

        return authorize


def _idp_reobserved_completion(retained, fresh):
    from qdev_runner.idp_file_runtime import IdPObservationError, same_installed_release

    try:
        if not same_installed_release(retained, fresh):
            raise IdPObservationError("changed installed evidence")
    except IdPObservationError:
        raise ControllerOutcomeUnresolved(
            "fresh IdP evidence differs from retained completion"
        ) from None
    # Preserve original evidence; a later observation cannot rewrite history.
    return retained


def retain_controller_idp_inputs(config, profile, lane, job, archive, *, transaction):
    """Authenticate full candidate intake using the existing private transport.

    The installed owner supplies the archive fetched by the native CI artifact
    path, never a caller-selected downloader. This boundary does not load helpers,
    stage native state, poll jobs/next, renew claims or authorize file application.
    Restarts after publication use invoke_retained_idp, not this network intake.
    """
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate")
            result[key] = value
        return result

    try:
        _validate_idp_file_scope(config, profile, lane)
        # Freeze caller input before network I/O; only already-signed jobs enter.
        job = json.loads(_canonical_bytes(job))
        release_id, _, lease, fence, _, _, _, _ = _validated_job(job, profile, config)
        status, body = request(
            config, "GET",
            f"/internal/v1/release-hosts/{profile.placement}/jobs/{release_id}/idp-inputs?"
            + urlencode({"release_lane": lane.name}),
            headers=_controller_headers(lease, fence),
        )
        if status != 200 or not isinstance(body, bytes) or not 0 < len(body) <= 1024 * 1024:
            raise ValueError("transport")
        value = json.loads(body, object_pairs_hook=unique)
        if (
            not isinstance(value, dict)
            or set(value) != {"schema", "status", "job", "candidate_receipt", "acceptance"}
            or value["schema"] != "qdev-controller-idp-dispatch-inputs-v1"
            or value["status"] != "authenticated_inputs" or value["acceptance"] != "not_run"
            or _canonical_bytes(value["job"]) != _canonical_bytes(job)
            or not isinstance(value["candidate_receipt"], dict)
        ):
            raise ValueError("envelope")
        invocation = IdPNativeInvocation(config, profile, lane, job, value["candidate_receipt"])
        # A live read is not a live apply permit; expiry is rechecked after I/O.
        invocation._verified_job(live=True)
        return invocation.retain(archive, transaction=transaction)
    except Exception:
        raise AgentError("IdP controller input intake requires verified-state inspection") from None


class IdPNativeInvocation:
    """Fixed code-only bridge from a signed job and published archive to native.

    The installed owner supplies controller config/profile/lane and its retained
    job/candidate. No request selects target, state root, executable or key. An
    expired signature authenticates historical bytes ONLY for inspect/reconcile/
    observe; apply separately requires a live dispatch, native global lock and
    fresh controller/provider authorization. No retry or artifact rebuild here.
    """

    STATE_ROOT = Path("/var/lib/qdev-idp/releases")
    TARGET = Path("/opt/id.qdev.run")

    def __init__(self, config, profile, lane, job, candidate_receipt):
        _validate_idp_file_scope(config, profile, lane)
        self._config, self._profile, self._lane = config, profile, lane
        self._job = _canonical_bytes(job)
        self._candidate = _canonical_bytes(candidate_receipt)

    def _verified_job(self, *, live):
        from qdev_runner.release_lane import (
            REQUEST_SCHEMA,
            ReleaseAdmissionRequest,
            candidate_evidence,
            validate_candidate,
        )

        job, candidate = json.loads(self._job), json.loads(self._candidate)
        if not isinstance(job, dict) or not isinstance(candidate, dict):
            raise AgentError("invalid retained IdP job or candidate")
        claim = job.get("dispatch_claim")
        if not isinstance(claim, dict):
            raise AgentError("invalid retained IdP dispatch")
        # Historical time is not a renewed permit. Recovery is confined to the
        # exact already-staged native binding and cannot call apply or rollback.
        at = None if live else claim.get("issued_at")
        if not live and type(at) is not int:
            raise AgentError("historical IdP dispatch has no authenticated issue time")
        _validated_job(job, self._profile, self._config, now=at)
        request_document = ReleaseAdmissionRequest(
            schema=REQUEST_SCHEMA,
            release_lane=self._lane.name,
            project_id=self._lane.project_id,
            placement=self._lane.placement,
            **{key: job[key] for key in ("source_sha", "artifact_digest", "artifact_ref")},
            candidate_receipt=candidate,
        )
        validate_candidate(request_document, self._lane)
        claim = job["dispatch_claim"]
        if (
            candidate_evidence({"candidate_receipt": candidate}, self._lane)
            != job["candidate_evidence"]
            or any(candidate.get(key) != claim[key] for key in (
                "repository", "workflow", "job", "run_id", "job_id", "attempt", "runner_profile"
            ))
            or candidate.get("workflow") != "quality.yml"
            or candidate.get("job") != "static-contracts"
            or candidate.get("runner_profile") != "qdev-ci-docker"
            or candidate.get("artifact_type") != "http-archive"
            or job["artifact_digest"] != f"sha256:{candidate.get('archive_sha256')}"
        ):
            raise AgentError("IdP native artifact does not bind the signed candidate")
        return job, candidate

    def retain(self, archive, *, transaction):
        """Persist verified inputs, not an admission or a deployment result.

        An exact already-published retry may finish durability after expiry.
        First publication requires a live dispatch; neither path loads code.
        """
        from qdev_runner import idp_retained_dispatch as storage
        from qdev_runner.idp_native_bundle import verify_native_archive

        try:
            storage.transaction_name(transaction)
            job, candidate = self._verified_job(live=False)
            verify_native_archive(
                archive, source_sha=job["source_sha"],
                archive_sha256=candidate["archive_sha256"],
                bundle_sha256=candidate["payload_sha256"],
            )
            # Immutable storage checks exact equality on any existing result.
            # A missing publication must not turn an expired job into new work.
            if storage.read(transaction) is None:
                self._verified_job(live=True)
            storage.retain(transaction, job, candidate, archive)
        except Exception:
            raise AgentError("IdP input retention requires verified-state inspection") from None
        return {
            "schema": storage.SCHEMA, "transaction": transaction, "status": "retained",
            "source_sha": job["source_sha"], "artifact_digest": job["artifact_digest"],
        }

    def invoke(self, archive, *, action, transaction, ci="none"):
        from qdev_runner.idp_native_bundle import verify_native_archive

        if (
            action not in {"apply", "inspect", "reconcile", "observe"}
            or not isinstance(transaction, str)
            or not re.fullmatch(r"[a-z][a-z0-9-]{7,79}", transaction)
            or not isinstance(ci, str)
            or not (ci == "none" or re.fullmatch(r"ci-[0-9a-f]{16}\.json", ci))
            or (action == "apply" and ci == "none")
        ):
            raise AgentError("invalid fixed IdP native operation")
        job, candidate = self._verified_job(live=action == "apply")
        bundle = verify_native_archive(
            archive,
            source_sha=job["source_sha"],
            archive_sha256=candidate["archive_sha256"],
            bundle_sha256=candidate["payload_sha256"],
        )
        # Loading can be expensive. Recheck live expiry before executing code;
        # the locked bridge rechecks again after actual CI/network observations.
        self._verified_job(live=action == "apply")
        native, helpers = bundle.load()
        args = SimpleNamespace(
            action=action,
            source_sha=job["source_sha"],
            expected_previous=job["rollback_anchor"]["source_sha"],
            bundle_digest=bundle.bundle_sha256,
            manifest_digest=bundle.manifest_sha256,
            ci=ci,
        )
        adapter = (
            ControllerIssuedIdPFileApplyAdapter(self._config, self._profile, self._lane, job)
            if action == "apply" else None
        )
        recovery = (
            {"controller_recovery": lambda reader: self._reconcile_controller(
                reader, bundle, transaction,
            )}
            if action == "reconcile" else {}
        )
        try:
            result = native.dispatch(
                self.STATE_ROOT, self.STATE_ROOT / transaction, self.TARGET, args, helpers,
                controller_adapter=adapter,
                **recovery,
            )
            native.contract.validate_native_response(
                _canonical_bytes(result), action=action, transaction=transaction,
                source_sha=args.source_sha, expected_previous=args.expected_previous,
                bundle_sha256=args.bundle_digest, manifest_sha256=args.manifest_digest,
            )
        except Exception:
            # No raw native output/exception or automatic second invocation.
            # The caller must inspect/reconcile the retained native+host journals.
            raise AgentError("IdP native outcome requires retained-state inspection") from None
        return result

    def _reconcile_controller(self, reader, bundle, transaction):
        """Native lock precedes host lock; recover only this retained signed job."""
        from qdev_runner.file_apply_authorization import verify_dispatch_binding
        from qdev_runner.idp_file_runtime import installed_binding, native_receipt, timestamp

        if not callable(getattr(reader, "observe_installed", None)):
            raise AgentError("locked installed IdP reader required")
        job, candidate = self._verified_job(live=False)
        profile, config, lane = self._profile, self._config, self._lane
        with _acquire_lock(profile.lock_path) as locked:
            fcntl.flock(locked.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            pending = _pending_operation(profile, include_completed=True)
            claim = job["dispatch_claim"]
            expected = {
                "release_id": job["release_id"], "lease_id": job["lease_id"],
                "fence": job["fence"], "dispatch_nonce": claim["nonce"],
                "lease_expires_at": job["lease_expires_at"],
                "rollback_anchor": job["rollback_anchor"],
                "previous_release": job["rollback_anchor"],
                "candidate_release": {key: job[key] for key in (
                    "source_sha", "artifact_digest", "artifact_ref"
                )},
            }
            if pending is None or any(pending.get(k) != v for k, v in expected.items()):
                raise AgentError("IdP recovery does not match the retained host operation")
            observation = reader.observe_installed()
            raw_binding = installed_binding(observation)
            binding = json.loads(raw_binding)
            if (
                binding["transaction"] != transaction
                or binding["bundle_sha256"] != bundle.bundle_sha256
                or binding["manifest_sha256"] != bundle.manifest_sha256
            ):
                raise AgentError("IdP recovery observation belongs to another native bundle")
            previous = None
            if job["rollback_anchor"]["artifact_digest"] != f"sha256:{binding['snapshot_sha256']}":
                previous = _idp_previous_observation(profile, job["rollback_anchor"])
            # Verify signature/CI/archives at the actual cutover time, not now.
            # This is historical authentication and never authorizes installation.
            verify_dispatch_binding(
                raw_binding, lane=lane, claim=claim, candidate=candidate,
                signature=job["dispatch_claim_signature"], signing_key=config.dispatch_secret,
                now=timestamp(observation["events"][6]["observed_at"]),
                previous_observation=previous,
            )
            current = native_receipt(
                observation, installed=True, expected_binding=raw_binding, now=time.time(),
                previous_observation=previous,
            )
            active, rollback = read_state(profile.state_path, profile, allow_bootstrap=False)
            result = _recover_pending(
                config, profile, active, rollback, pending, observe_current=lambda: current,
            )
            if result.get("status") != "verified":
                raise ControllerOutcomeUnresolved("IdP controller recovery is not verified")
            return result


def invoke_retained_idp(config, profile, lane, *, transaction, action, ci="none"):
    """Installed-code entrypoint; never execute an unverified staged helper.

    Intake has its own short lock, released before native-global/host-journal
    locking. Missing publication is inspectable, but is NOT native acceptance.
    Signature, full candidate and both archive bindings are rechecked on every
    invocation, including historical inspect/reconcile after a process restart.
    """
    from qdev_runner import idp_retained_dispatch as storage

    try:
        _validate_idp_file_scope(config, profile, lane)
        storage.transaction_name(transaction)
        if action not in {"apply", "inspect", "reconcile", "observe"}:
            raise AgentError("invalid retained IdP action")
        retained = storage.read(transaction)
        if retained is None:
            if action != "inspect" or ci != "none":
                raise AgentError("IdP inputs have not been published")
            return {
                "schema": storage.SCHEMA, "transaction": transaction,
                "status": "inputs_not_published",
            }
        metadata, archive = retained
        invocation = IdPNativeInvocation(
            config, profile, lane, metadata["job"], metadata["candidate"],
        )
        return invocation.invoke(archive, action=action, transaction=transaction, ci=ci)
    except Exception:
        raise AgentError("retained IdP operation requires verified-state inspection") from None


class IdPFileApplyAdapter:
    """Code-only factory for verified native dispatch, not an enrollment/CLI.

    The installed owner supplies the fixed lane/profile/config and independently
    signed job/envelope. No executable/profile/key comes from IdP or JSON. A
    bundle-verified native dispatch calls this factory under its global lock.
    Every read then occurs under the host journal lock, without reentering IdP.
    """

    def __init__(self, config, profile, lane, job, authorization, signature, *, candidate_receipt):
        _validate_idp_file_scope(config, profile, lane)
        self._config, self._profile, self._lane = config, profile, lane
        self._job = _canonical_bytes(job)
        self._candidate = _canonical_bytes(candidate_receipt)
        self._authorization, self._signature = _canonical_bytes(authorization), signature

    def __call__(self, reader):
        from qdev_runner.file_apply_authorization import FileApplyBridge, parse_binding
        from qdev_runner.idp_file_runtime import native_receipt

        # This is a trusted in-process capability, not an object accepted over an
        # API. Native dispatch itself fences its PID/thread/active-pointer lifetime.
        if not callable(getattr(reader, "observe_prepared", None)) or not callable(
            getattr(reader, "observe_installed", None)
        ):
            raise AgentError("locked native IdP observation reader required")
        job = json.loads(self._job)

        @contextmanager
        def authorize(binding):
            if not isinstance(binding, bytes):
                raise AgentError("immutable native IdP binding required")
            scope = parse_binding(binding, now=time.time())
            anchor = job["dispatch_claim"]["rollback_anchor"]
            previous = None
            if anchor["artifact_digest"] != f"sha256:{scope.snapshot_sha256}":
                previous = _idp_previous_observation(self._profile, anchor)

            def observe(installed):
                # Invoked only under the host lock. A concurrent change between
                # loading the bridge and acquiring that lock fails closed.
                if (
                    previous is not None
                    and _idp_previous_observation(self._profile, anchor) != previous
                ):
                    raise AgentError("previous IdP native observation changed")
                return native_receipt(
                    reader.observe_installed() if installed else reader.observe_prepared(),
                    installed=installed,
                    expected_binding=binding,
                    now=time.time(),
                    previous_observation=previous,
                )

            observations = FileApplyObservations(
                before_apply=lambda: observe(False),
                after_apply=lambda: observe(True),
            )
            bridge = FileApplyBridge(
                lane=self._lane,
                dispatch_claim=job["dispatch_claim"],
                candidate_receipt=json.loads(self._candidate),
                dispatch_signature=job["dispatch_claim_signature"],
                authorization=json.loads(self._authorization),
                authorization_signature=self._signature,
                signing_key=self._config.dispatch_secret,
                dispatch_transaction=JournaledFileApplyTransaction(
                    self._config,
                    self._profile,
                    job,
                    observations=observations,
                ),
                clock=time.time,
                previous_observation=previous,
            )
            with bridge(binding) as guard:
                yield guard

        return authorize


class JournaledFileApplyTransaction:
    """In-process bridge factory using the existing host operation journal.

    Not a CLI, issuer or enrollment. The installed adapter supplies the compiled
    profile/config and signed job; FileApplyBridge separately verifies the full
    candidate and file binding. The IdP global lock is acquired BEFORE this host
    lock. No native release/rollback dispatcher is invoked from this context.
    Unknown outcomes remain pending for explicit native reconciliation.
    """

    def __init__(
        self,
        config: Config,
        profile: Profile,
        job: dict[str, Any],
        *,
        observations: FileApplyObservations | None = None,
    ) -> None:
        if observations is not None and type(observations) is not FileApplyObservations:
            raise AgentError("file apply observations must come from the fixed native adapter")
        self._config, self._profile = config, profile
        self._job = _canonical_bytes(job)
        self._observations = observations

    @contextmanager
    def __call__(self, claim: dict[str, Any]) -> Iterator[JournaledFileApplyGuard]:
        config, profile = self._config, self._profile
        job = json.loads(self._job)
        observations = self._observations
        before_apply = (
            (lambda: native_receipt(profile, current=True))
            if observations is None
            else observations.before_apply
        )
        after_apply = (
            (lambda: native_receipt(profile, current=True))
            if observations is None
            else observations.after_apply
        )
        if claim != job.get("dispatch_claim"):
            raise AgentError("file apply claim differs from the native signed job")
        with _acquire_lock(profile.lock_path) as lock:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as error:
                raise AgentError("release lock is already held") from error
            if _pending_operation(profile) is not None:
                raise ControllerOutcomeUnresolved(
                    "pending native operation requires reconciliation"
                )
            (
                release_id,
                candidate,
                lease_id,
                fence,
                nonce,
                lease_expires_at,
                rollback_anchor,
                _,
            ) = _validated_job(job, profile, config)
            if _dispatch_nonce_seen(profile, nonce):
                raise AgentError("controller host dispatch claim was already consumed")
            active, rollback = read_state(profile.state_path, profile, allow_bootstrap=True)
            context = _operation_context(
                profile, candidate, active, rollback, nonce, lease_expires_at, rollback_anchor
            )
            _validate_native_runtime(before_apply(), profile, active)

            def check() -> None:
                # The signed lifetime is never renewed locally. The authenticated
                # status read rejects changed fencing and terminal controller work.
                _validated_job(job, profile, config)
                state = _controller_status(
                    config, profile, release_id, candidate, lease_id, fence, restored=active
                )
                if state["status"] != "dispatched":
                    raise AgentError("file apply requires the current dispatched controller job")

            guard = JournaledFileApplyGuard(check)
            try:
                guard.assert_current()
                _write_operation(profile, "dispatch_accepted", release_id, lease_id, fence, context)
                _write_operation(profile, "release_started", release_id, lease_id, fence, context)
                guard.assert_current()
                yield guard
                guard.assert_current()
                _validate_native_runtime(after_apply(), profile, candidate)
                # Reuse durable completion and restart handling, including lost
                # controller responses and state-file writes, without a second DB.
                pending = _pending_operation(profile)
                if pending is None:
                    raise AgentError("file apply lost its durable native operation")
                result = _recover_pending(
                    config, profile, active, rollback, pending, observe_current=after_apply
                )
                if result["status"] != "verified":
                    raise AgentError("file apply native completion was not verified")
            finally:
                # A failure, process death or lost response never resets a nonce or
                # labels an unknown operation successful; persisted phases survive.
                guard.close()


def run_once(config: Config, profile: Profile) -> dict[str, Any]:
    with _acquire_lock(profile.lock_path) as lock:
        os.chmod(profile.lock_path, 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AgentError("release lock is already held") from error
        if config.host_identity != f"qdev-host-agent:{profile.placement}":
            raise AgentError("configured host identity does not match compiled placement")
        journal = _journal_events(profile)
        has_release_operation = any("release_id" in event for event in journal)
        bootstrap_persisted = any(
            event.get("phase") == "bootstrap_anchor_persisted" for event in journal
        )
        # The first managed heartbeat is anchored to what the native adapter
        # measures now, never to an unverified local state file.  Repeating
        # this path is intentional when a process died after measurement or
        # controller acknowledgement but before the durable state/journal
        # boundary.  Once any release operation exists, losing the state file
        # is an error and cannot silently reset history to the current runtime.
        needs_bootstrap = not has_release_operation and (
            not bootstrap_persisted or not profile.state_path.exists()
        )
        if needs_bootstrap:
            current_native = native_receipt(profile, current=True)
            active = _native_release(current_native, profile)
            beat = heartbeat(profile, active, active, bootstrap=True)
            _write_journal(
                profile,
                "bootstrap_anchor_measured",
                active_release=active,
                rollback=active,
            )
            if beat["capacity_free_gib"] < profile.minimum_free_gib:
                raise AgentError("release capacity is below the compiled lane minimum")
            status, _ = request(
                config,
                "POST",
                f"/internal/v1/release-hosts/{profile.placement}/heartbeat",
                beat,
            )
            if status != 200:
                raise AgentError("controller rejected bootstrap host-agent heartbeat")
            write_state(profile.state_path, active, active)
            _write_journal(
                profile,
                "bootstrap_anchor_persisted",
                active_release=active,
                rollback=active,
            )
            return {
                "status": "bootstrapped",
                "capacity_free_gib": beat["capacity_free_gib"],
                **active,
            }
        active, rollback = read_state(profile.state_path, profile, allow_bootstrap=True)
        pending = _pending_operation(profile)
        if pending is not None:
            return _recover_pending(config, profile, active, rollback, pending)

        current_native = native_receipt(profile, current=True)
        _validate_native_runtime(current_native, profile, active)
        bootstrap = active == rollback
        beat = heartbeat(profile, active, rollback, bootstrap=bootstrap)
        _write_journal(profile, "heartbeat", active_release=active, rollback=rollback)
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
        try:
            job_document = json.loads(body)
        except json.JSONDecodeError as error:
            raise AgentError("controller release job is not JSON") from error
        (
            release_id,
            candidate,
            lease_id,
            fence,
            dispatch_nonce,
            lease_expires_at,
            rollback_anchor,
            candidate_evidence,
        ) = _validated_job(job_document, profile, config)
        if _dispatch_nonce_seen(profile, dispatch_nonce):
            raise AgentError("controller host dispatch claim was already consumed")
        context = _operation_context(
            profile,
            candidate,
            active,
            rollback,
            dispatch_nonce,
            lease_expires_at,
            rollback_anchor,
        )
        _write_operation(
            profile,
            "dispatch_accepted",
            release_id,
            lease_id,
            fence,
            context,
        )
        _write_operation(
            profile,
            "release_started",
            release_id,
            lease_id,
            fence,
            context,
        )
        try:
            _ensure_live_lease(lease_expires_at)
            if profile.name == "qmt":
                invoke_native(profile, "release", candidate, candidate_evidence)
            else:
                invoke_native(profile, "release", candidate)
            candidate_native = native_receipt(profile, current=True)
            _validate_native_runtime(candidate_native, profile, candidate)
            if profile.name == "qmt" and (
                candidate_native.get("dependency_identity")
                != {"qmt_version": candidate_evidence["release_version"]}
                or candidate_native.get("artifact_provenance")
                != {
                    key: candidate_evidence[key]
                    for key in (
                        "candidate_receipt_sha256",
                        "migration_receipt_digest",
                        "contract_digest",
                    )
                }
            ):
                raise AgentError("native QMT receipt does not bind candidate evidence")
            runtime_receipt = _completion_receipt(profile, candidate, active, candidate_native)
            context = _operation_context(
                profile,
                candidate,
                active,
                rollback,
                dispatch_nonce,
                lease_expires_at,
                rollback_anchor,
                runtime_receipt=runtime_receipt,
            )
            _write_operation(
                profile,
                "release_ready",
                release_id,
                lease_id,
                fence,
                context,
            )
        except AgentError as release_error:
            try:
                rollback_remote(
                    config,
                    profile,
                    release_id,
                    candidate,
                    active,
                    lease_id=lease_id,
                    fence=fence,
                    dispatch_nonce=dispatch_nonce,
                    previous_rollback=rollback,
                    lease_expires_at=lease_expires_at,
                    rollback_anchor=rollback_anchor,
                )
            except AgentError as rollback_error:
                raise AgentError(
                    "candidate release failed and safe rollback could not be proven: "
                    f"{rollback_error}"
                ) from release_error
            raise

        try:
            _resolve_completion_outcome(
                config,
                profile,
                release_id,
                candidate,
                active,
                lease_id,
                fence,
                runtime_receipt,
                lease_expires_at,
            )
        except ControllerOutcomeUnresolved:
            _write_operation(
                profile,
                "completion_unresolved",
                release_id,
                lease_id,
                fence,
                context,
            )
            raise
        _write_operation(
            profile,
            "verified",
            release_id,
            lease_id,
            fence,
            context,
        )
        try:
            write_state(profile.state_path, candidate, active)
        except (AgentError, OSError):
            _write_operation(
                profile,
                "verified_state_write_failed",
                release_id,
                lease_id,
                fence,
                context,
            )
            raise
        _write_operation(
            profile,
            "completed",
            release_id,
            lease_id,
            fence,
            context,
        )
        return {
            "status": "verified",
            "release_id": release_id,
            "lease_id": lease_id,
            "fence": fence,
            **candidate,
        }


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
