#!/usr/bin/env python3
"""One-shot, controller-owned immutable release agent for approved products.

Static profiles are compiled into this file. QGeo instead requires a
short-lived externally signed profile because its application host and
candidate-bound source paths must be discovered by the controller, not guessed
in the repository. A private root-owned config contains the mTLS material and
state paths; it cannot select a registry or arbitrary public URL. The agent proves
the OCI source label, starts only an immutable digest with Docker Compose
without a build, proves local and public release identity, and restores the
previous verified immutable tuple on every failed candidate. QMT requires a
controller-preloaded image and never pulls on the production host.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
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
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_LEASE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_FENCE = re.compile(r"^[0-9a-f]{24,128}$")
_NONCE = re.compile(r"^[A-Za-z0-9_-]{32,128}$")
_HOST_IDENTITY = re.compile(r"^qdev-host-agent:[a-z0-9][a-z0-9-]{1,63}$")
_CI_SCOPE_VALUE = re.compile(r"^[\w][\w .:/\-\u2013]{0,191}$")
_RUNNER_PROFILES = frozenset({"qdev-ci", "qdev-ci-docker", "qdev-ci-browser"})
STATE_SCHEMA = "qdev-release-host-state-v1"
PENDING_SCHEMA = "qdev-release-host-pending-v1"
QGEO_PROFILE_SCHEMA = "qdev-qazgeo-host-profile-v2"
HOST_DISPATCH_CLAIM_SCHEMA = "qdev-controller-host-dispatch-claim-v2"
HOST_DISPATCH_CLAIM_MAX_TTL_SECONDS = 5 * 60
HOST_DISPATCH_CLOCK_SKEW_SECONDS = 30
QGEO_PROFILE_MAX_TTL_SECONDS = 30 * 60
QGEO_PROFILE_CLOCK_SKEW_SECONDS = 60
_QGEO_RECOVERY_SHA = "d65cd62a4c96786d9d5c35ebea8af872dcc3cb69"
_QGEO_RECOVERY_DIGEST = "sha256:96d4399d5f5345f956abbffbd185552da4406a7a26017164f2ca6313688ef5cb"
_QGEO_ROLLBACK_IMAGE = "qazgeo-app:2.18.0-d65cd62-tablet-overflow-20260828"
_QGEO_STATIC_ROOT = Path("/var/lib/qdev-release-agents/qazgeo/static")


class AgentError(RuntimeError):
    """A host proof is absent or unsafe to act upon."""


class ControllerTransportError(AgentError):
    """The controller may have committed a request whose response was lost."""


class ControllerOutcomeUnresolved(AgentError):
    """The host must preserve its journal and reconcile before another mutation."""


class CompletionRejected(AgentError):
    """The controller definitely retained an active job after rejecting completion."""


@dataclass(frozen=True)
class Profile:
    name: str
    lane: str
    project: str
    placement: str
    repository: str
    release_dir: Path
    compose_files: tuple[Path, ...]
    runtime_env: Path
    services: tuple[str, ...]
    local_ready_url: str
    local_readiness_url: str | None
    public_release_url: str
    public_identity_path: tuple[str, ...]
    image_environment: str
    public_version: str | None
    require_runtime_identity: bool
    controller_overlay: Path | None
    preloaded_image_required: bool
    # QGeo keeps its candidate static bundles in a controller-owned release
    # root while the already-running recovery image/static tree remains the
    # rollback target.  The rollback tuple is expressed with the canonical
    # registry identity for controller receipts, then mapped to its local
    # immutable image tag at compose time.
    static_directory_root: Path | None = None
    rollback_static_directory: Path | None = None
    rollback_image_reference: str | None = None
    rollback_release: dict[str, str] | None = None
    # QGeo installs the pinned QazStack source tree directly rather than a
    # wheel.  The runtime receipt therefore carries a deterministic source
    # manifest digest for this lane.
    qazstack_source_directory: Path | None = None
    qazstack_version: str | None = None
    qazstack_source_ref: str | None = None
    qazstack_source_manifest_sha256: str | None = None
    qazstack_wheel_path: Path | None = None
    avds_source_sha: str | None = None
    avds_artifact_sha256: str | None = None
    candidate_source_sha: str | None = None
    candidate_artifact_digest: str | None = None
    dependency_images: dict[str, dict[str, str | None]] | None = None
    signed_profile_digest: str | None = None


PROFILES = {
    "qaz-fund": Profile(
        name="qaz-fund",
        lane="qdev-release-qaz-fund",
        project="qaz-fund",
        placement="vps-apps-148",
        repository="qaz-fund",
        release_dir=Path("/opt/grant-radar"),
        compose_files=(
            Path("/opt/grant-radar/docker-compose.yml"),
            Path("/opt/grant-radar/docker-compose.prod.yml"),
            Path("/opt/grant-radar/docker-compose.controller-release.yml"),
        ),
        runtime_env=Path("/opt/grant-radar/.env.prod"),
        services=("api", "worker"),
        local_ready_url="http://127.0.0.1:8000/ready",
        local_readiness_url=None,
        public_release_url="https://qaz.fund/.well-known/release.json",
        public_identity_path=("sourceSha",),
        image_environment="QAZ_FUND_IMAGE",
        public_version=None,
        require_runtime_identity=False,
        controller_overlay=None,
        preloaded_image_required=False,
    ),
    "qaz-events": Profile(
        name="qaz-events",
        lane="qdev-release-qaz-events",
        project="qaz-events",
        placement="vps-main",
        repository="qaz-events",
        release_dir=Path("/opt/ideo-calendar"),
        compose_files=(
            Path("/opt/ideo-calendar/docker-compose.yml"),
            Path("/opt/ideo-calendar/docker-compose.controller-release.yml"),
        ),
        runtime_env=Path("/opt/ideo-calendar/.env"),
        services=("app",),
        local_ready_url="http://127.0.0.1:8400/api/health",
        local_readiness_url=None,
        public_release_url="https://qaz.events/.well-known/qdev-ecosystem.json",
        public_identity_path=("evidence", "source_revision"),
        image_environment="QAZ_EVENTS_IMAGE",
        public_version=None,
        require_runtime_identity=False,
        controller_overlay=None,
        preloaded_image_required=False,
    ),
    "qmt": Profile(
        name="qmt",
        lane="qdev-release-qmt",
        project="kaztilshi",
        placement="srv138jump",
        repository="kaztilshi",
        release_dir=Path("/opt/kaztilshi"),
        compose_files=(Path("/opt/kaztilshi/docker-compose.yml"),),
        runtime_env=Path("/opt/kaztilshi/.env"),
        services=("kaztilshi",),
        local_ready_url="http://127.0.0.1:5000/api/health",
        local_readiness_url="http://127.0.0.1:5000/api/readiness",
        public_release_url="https://qmt.digital/release.json",
        public_identity_path=("source_revision",),
        image_environment="QMT_IMAGE",
        public_version="4.4.1",
        require_runtime_identity=True,
        controller_overlay=Path(
            "/opt/qdev-runner-control-plane/current/deploy/qdev-release-qmt.compose.yml"
        ),
        preloaded_image_required=True,
    ),
}


@dataclass(frozen=True)
class Config:
    controller_url: str
    client_cert: Path
    client_key: Path
    controller_ca: Path
    state_path: Path
    lock_path: Path
    release_profile_path: Path | None
    release_profile_verification_key: Path | None
    host_identity: str | None = None
    dispatch_secret: bytes | None = None


def _private(path: Path, *, required: bool = True) -> None:
    try:
        meta = path.lstat()
    except FileNotFoundError as error:
        if required:
            raise AgentError(f"required file is missing: {path}") from error
        return
    if (
        not stat.S_ISREG(meta.st_mode)
        or path.is_symlink()
        or meta.st_uid != 0
        or stat.S_IMODE(meta.st_mode) & 0o077
    ):
        raise AgentError(f"file must be root-owned and private: {path}")


def _read_private(path: Path, *, maximum_bytes: int = 256 * 1024) -> bytes:
    """Read one root-owned regular file without following a final symlink."""

    _private(path)
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise AgentError(f"file must be root-owned and private: {path}")
        payload = os.read(descriptor, maximum_bytes + 1)
        if len(payload) > maximum_bytes:
            raise AgentError(f"private file is too large: {path}")
        return payload
    finally:
        os.close(descriptor)


def load_config(path: Path) -> Config:
    values: dict[str, str] = {}
    try:
        config_text = _read_private(path, maximum_bytes=32 * 1024).decode("utf-8")
    except UnicodeDecodeError as error:
        raise AgentError("host-agent configuration is not UTF-8") from error
    for line in config_text.splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not value:
            raise AgentError("host-agent configuration has an invalid line")
        values[key] = value
    required = {
        "QDEV_RELEASE_CONTROLLER_URL",
        "QDEV_RELEASE_AGENT_CERT",
        "QDEV_RELEASE_AGENT_KEY",
        "QDEV_RELEASE_CONTROLLER_CA",
        "QDEV_RELEASE_STATE_PATH",
        "QDEV_RELEASE_LOCK_PATH",
    }
    profile_keys = {
        "QDEV_RELEASE_PROFILE_PATH",
        "QDEV_RELEASE_PROFILE_VERIFICATION_KEY",
    }
    dispatch_keys = {
        "QDEV_RELEASE_HOST_IDENTITY",
        "QDEV_RELEASE_DISPATCH_SECRET_FILE",
    }
    if not required <= set(values) or set(values) - required - profile_keys - dispatch_keys:
        raise AgentError("host-agent configuration keys are invalid")
    configured_profile_keys = set(values) & profile_keys
    if configured_profile_keys not in (set(), profile_keys):
        raise AgentError("signed release profile configuration is incomplete")
    configured_dispatch_keys = set(values) & dispatch_keys
    if configured_dispatch_keys not in (set(), dispatch_keys):
        raise AgentError("signed dispatch configuration is incomplete")
    parsed = urlsplit(values["QDEV_RELEASE_CONTROLLER_URL"])
    if (
        parsed.scheme != "https"
        or parsed.hostname != "worker.ci.qdev.run"
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise AgentError("controller URL must be the fixed HTTPS mTLS edge")
    dispatch_secret_path = (
        Path(values["QDEV_RELEASE_DISPATCH_SECRET_FILE"])
        if "QDEV_RELEASE_DISPATCH_SECRET_FILE" in values
        else None
    )
    dispatch_secret = (
        _read_private(dispatch_secret_path, maximum_bytes=4096).strip()
        if dispatch_secret_path is not None
        else None
    )
    host_identity = values.get("QDEV_RELEASE_HOST_IDENTITY")
    if host_identity is not None and not _HOST_IDENTITY.fullmatch(host_identity):
        raise AgentError("host dispatch identity is invalid")
    if dispatch_secret is not None and not 32 <= len(dispatch_secret) <= 4096:
        raise AgentError("host dispatch secret length is invalid")
    config = Config(
        values["QDEV_RELEASE_CONTROLLER_URL"],
        Path(values["QDEV_RELEASE_AGENT_CERT"]),
        Path(values["QDEV_RELEASE_AGENT_KEY"]),
        Path(values["QDEV_RELEASE_CONTROLLER_CA"]),
        Path(values["QDEV_RELEASE_STATE_PATH"]),
        Path(values["QDEV_RELEASE_LOCK_PATH"]),
        Path(values["QDEV_RELEASE_PROFILE_PATH"])
        if "QDEV_RELEASE_PROFILE_PATH" in values
        else None,
        Path(values["QDEV_RELEASE_PROFILE_VERIFICATION_KEY"])
        if "QDEV_RELEASE_PROFILE_VERIFICATION_KEY" in values
        else None,
        host_identity,
        dispatch_secret,
    )
    for credential in (config.client_cert, config.client_key, config.controller_ca):
        _private(credential)
    if config.release_profile_path is not None:
        _private(config.release_profile_path)
        assert config.release_profile_verification_key is not None
        _private(config.release_profile_verification_key)
    return config


def _canonical_json(value: dict[str, Any]) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("ascii")


def _canonical_path(value: object, *, field: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise AgentError(f"signed QGeo {field} path is invalid")
    path = Path(value)
    if not path.is_absolute() or ".." in path.parts or str(path) != value:
        raise AgentError(f"signed QGeo {field} path is not canonical")
    return path


def _local_health_url(value: object, *, path: str) -> str:
    if not isinstance(value, str):
        raise AgentError("signed QGeo local health URL is invalid")
    parsed = urlsplit(value)
    if (
        parsed.scheme != "http"
        or parsed.hostname != "127.0.0.1"
        or parsed.port is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != path
        or parsed.query
        or parsed.fragment
    ):
        raise AgentError("signed QGeo local health URL is invalid")
    return value


def _profile_public_key(payload: bytes) -> Ed25519PublicKey:
    try:
        key = serialization.load_pem_public_key(payload)
    except (TypeError, ValueError) as error:
        raise AgentError("QGeo profile public key is invalid") from error
    if not isinstance(key, Ed25519PublicKey):
        raise AgentError("QGeo profile public key is not Ed25519")
    return key


def _immutable_image_reference(value: object) -> str:
    if not isinstance(value, str) or len(value) > 512 or value.count("@") != 1:
        raise AgentError("signed QGeo dependency image reference is invalid")
    name, digest = value.split("@", 1)
    if not _DIGEST.fullmatch(digest) or not name or name != name.lower():
        raise AgentError("signed QGeo dependency image reference is invalid")
    if any(character.isspace() for character in name) or "\\" in name:
        raise AgentError("signed QGeo dependency image reference is invalid")
    parts = name.split("/")
    if any(not part or part in {".", ".."} for part in parts):
        raise AgentError("signed QGeo dependency image reference is invalid")
    if any(re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", part) is None for part in parts[1:]):
        raise AgentError("signed QGeo dependency image reference is invalid")
    first = parts[0]
    if len(parts) == 1:
        valid_first = re.fullmatch(r"[a-z0-9]+(?:[._-][a-z0-9]+)*", first)
    else:
        valid_first = re.fullmatch(r"[a-z0-9.-]+(?::[0-9]{1,5})?", first)
    if valid_first is None:
        raise AgentError("signed QGeo dependency image reference is invalid")
    return value


def _qgeo_dependency_images(value: object) -> dict[str, dict[str, str | None]]:
    expected_services = {"db", "martin", "photon", "redis"}
    if not isinstance(value, dict) or set(value) != expected_services:
        raise AgentError("signed QGeo dependency image set is invalid")
    result: dict[str, dict[str, str | None]] = {}
    for service in sorted(expected_services):
        identity = value.get(service)
        if not isinstance(identity, dict) or set(identity) != {"artifact_ref", "source_revision"}:
            raise AgentError("signed QGeo dependency image identity is invalid")
        revision = identity.get("source_revision")
        if revision is not None and (not isinstance(revision, str) or not _SHA.fullmatch(revision)):
            raise AgentError("signed QGeo dependency source revision is invalid")
        result[service] = {
            "artifact_ref": _immutable_image_reference(identity.get("artifact_ref")),
            "source_revision": revision,
        }
    return result


def verify_qgeo_profile_document(
    document: object,
    public_key: Ed25519PublicKey,
    *,
    now: float | None = None,
    allow_expired: bool = False,
) -> Profile:
    """Verify one externally signed candidate-specific QGeo profile."""

    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "issued_at", "expires_at", "profile", "signature"}
        or document.get("schema") != QGEO_PROFILE_SCHEMA
    ):
        raise AgentError("signed QGeo profile envelope shape is invalid")
    issued_at = document.get("issued_at")
    expires_at = document.get("expires_at")
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= issued_at
        or expires_at - issued_at > QGEO_PROFILE_MAX_TTL_SECONDS
    ):
        raise AgentError("signed QGeo profile lifetime is invalid")
    observed_now = time.time() if now is None else now
    if issued_at > observed_now + QGEO_PROFILE_CLOCK_SKEW_SECONDS or (
        expires_at <= observed_now and not allow_expired
    ):
        raise AgentError("signed QGeo profile is not currently valid")
    signature = document.get("signature")
    if not isinstance(signature, str) or not signature:
        raise AgentError("signed QGeo profile signature is missing")
    try:
        signature_bytes = base64.urlsafe_b64decode(f"{signature}==")
    except (binascii.Error, ValueError) as error:
        raise AgentError("signed QGeo profile signature encoding is invalid") from error
    canonical_signature = base64.urlsafe_b64encode(signature_bytes).rstrip(b"=").decode("ascii")
    if len(signature_bytes) != 64 or signature != canonical_signature:
        raise AgentError("signed QGeo profile signature encoding is not canonical")
    unsigned = {key: document[key] for key in ("schema", "issued_at", "expires_at", "profile")}
    try:
        public_key.verify(signature_bytes, _canonical_json(unsigned))
    except InvalidSignature as error:
        raise AgentError("signed QGeo profile signature is invalid") from error

    raw = document.get("profile")
    expected = {
        "name",
        "lane",
        "project",
        "placement",
        "repository",
        "candidate_source_sha",
        "candidate_artifact_digest",
        "dependency_images",
        "release_dir",
        "compose_files",
        "runtime_env",
        "services",
        "local_ready_url",
        "local_readiness_url",
        "public_release_url",
        "public_identity_path",
        "image_environment",
        "controller_overlay",
        "static_directory_root",
        "rollback_static_directory",
        "rollback_image_reference",
        "rollback_release",
        "qazstack_source_directory",
        "qazstack_version",
        "qazstack_source_ref",
        "qazstack_source_manifest_sha256",
        "avds_source_sha",
        "avds_artifact_sha256",
    }
    if not isinstance(raw, dict) or set(raw) != expected:
        raise AgentError("signed QGeo profile fields are invalid")
    fixed = {
        "name": "qazgeo",
        "lane": "qdev-release-qazgeo",
        "project": "qazgeo",
        "placement": "qazgeo-app-runtime",
        "repository": "belilovsky/qazgeo",
        "services": ["db", "redis", "app", "martin", "photon", "valhalla", "nginx"],
        "public_release_url": "https://qgeo.tech/health",
        "public_identity_path": ["source_revision"],
        "image_environment": "QAZGEO_APP_IMAGE",
        "static_directory_root": str(_QGEO_STATIC_ROOT),
        "rollback_image_reference": _QGEO_ROLLBACK_IMAGE,
        "rollback_release": {
            "source_sha": _QGEO_RECOVERY_SHA,
            "artifact_digest": _QGEO_RECOVERY_DIGEST,
            "artifact_ref": (f"registry.ci.qdev.run/belilovsky/qazgeo@{_QGEO_RECOVERY_DIGEST}"),
        },
    }
    if any(raw.get(field) != value for field, value in fixed.items()):
        raise AgentError("signed QGeo profile fixed identity is invalid")
    candidate_source = raw.get("candidate_source_sha")
    candidate_digest = raw.get("candidate_artifact_digest")
    if not isinstance(candidate_source, str) or not _SHA.fullmatch(candidate_source):
        raise AgentError("signed QGeo candidate source is invalid")
    if not isinstance(candidate_digest, str) or not _DIGEST.fullmatch(candidate_digest):
        raise AgentError("signed QGeo candidate digest is invalid")
    dependency_images = _qgeo_dependency_images(raw.get("dependency_images"))
    compose_values = raw.get("compose_files")
    if (
        not isinstance(compose_values, list)
        or not compose_values
        or len(compose_values) > 8
        or len(set(str(item) for item in compose_values)) != len(compose_values)
    ):
        raise AgentError("signed QGeo compose file set is invalid")
    release_dir = _canonical_path(raw.get("release_dir"), field="release directory")
    compose_files = tuple(_canonical_path(value, field="compose file") for value in compose_values)
    if any(path.parent != release_dir for path in compose_files):
        raise AgentError("signed QGeo compose files are outside the release directory")
    runtime_env = _canonical_path(raw.get("runtime_env"), field="runtime environment")
    if runtime_env.parent != release_dir:
        raise AgentError("signed QGeo runtime environment is outside the release directory")
    controller_overlay = _canonical_path(raw.get("controller_overlay"), field="controller overlay")
    static_root = _canonical_path(raw.get("static_directory_root"), field="static root")
    rollback_static = _canonical_path(
        raw.get("rollback_static_directory"), field="rollback static directory"
    )
    qazstack_directory = _canonical_path(
        raw.get("qazstack_source_directory"), field="QazStack source directory"
    )
    qazstack_version = raw.get("qazstack_version")
    qazstack_source_ref = raw.get("qazstack_source_ref")
    qazstack_manifest = raw.get("qazstack_source_manifest_sha256")
    avds_source = raw.get("avds_source_sha")
    avds_digest = raw.get("avds_artifact_sha256")
    if (
        not isinstance(qazstack_version, str)
        or not qazstack_version.strip()
        or len(qazstack_version) > 64
        or not isinstance(qazstack_source_ref, str)
        or not _SHA.fullmatch(qazstack_source_ref)
        or not isinstance(qazstack_manifest, str)
        or not _DIGEST.fullmatch(qazstack_manifest)
        or not isinstance(avds_source, str)
        or not _SHA.fullmatch(avds_source)
        or not isinstance(avds_digest, str)
        or not _HEX64.fullmatch(avds_digest)
    ):
        raise AgentError("signed QGeo source provenance is invalid")
    digest = f"sha256:{hashlib.sha256(_canonical_json(unsigned)).hexdigest()}"
    rollback_release_value = fixed["rollback_release"]
    if not isinstance(rollback_release_value, dict):
        raise AgentError("compiled QGeo rollback release is invalid")
    return Profile(
        name="qazgeo",
        lane="qdev-release-qazgeo",
        project="qazgeo",
        placement="qazgeo-app-runtime",
        repository="belilovsky/qazgeo",
        release_dir=release_dir,
        compose_files=compose_files,
        runtime_env=runtime_env,
        services=("db", "redis", "app", "martin", "photon", "valhalla", "nginx"),
        local_ready_url=_local_health_url(raw.get("local_ready_url"), path="/health"),
        local_readiness_url=_local_health_url(raw.get("local_readiness_url"), path="/health/ready"),
        public_release_url="https://qgeo.tech/health",
        public_identity_path=("source_revision",),
        image_environment="QAZGEO_APP_IMAGE",
        public_version=None,
        require_runtime_identity=False,
        controller_overlay=controller_overlay,
        preloaded_image_required=False,
        static_directory_root=static_root,
        rollback_static_directory=rollback_static,
        rollback_image_reference=_QGEO_ROLLBACK_IMAGE,
        rollback_release={
            key: value
            for key, value in rollback_release_value.items()
            if isinstance(key, str) and isinstance(value, str)
        },
        qazstack_source_directory=qazstack_directory,
        qazstack_version=qazstack_version,
        qazstack_source_ref=qazstack_source_ref,
        qazstack_source_manifest_sha256=qazstack_manifest,
        qazstack_wheel_path=None,
        avds_source_sha=avds_source,
        avds_artifact_sha256=avds_digest,
        candidate_source_sha=candidate_source,
        candidate_artifact_digest=candidate_digest,
        dependency_images=dependency_images,
        signed_profile_digest=digest,
    )


def load_qgeo_profile(
    config: Config, *, now: float | None = None, allow_expired: bool = False
) -> Profile:
    if config.release_profile_path is None or config.release_profile_verification_key is None:
        raise AgentError("QGeo requires an externally signed release profile")
    try:
        document = json.loads(_read_private(config.release_profile_path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AgentError("signed QGeo profile is not valid JSON") from error
    key = _profile_public_key(
        _read_private(config.release_profile_verification_key, maximum_bytes=8192)
    )
    return verify_qgeo_profile_document(document, key, now=now, allow_expired=allow_expired)


def _release(value: object, profile: Profile) -> dict[str, str]:
    expected = {"source_sha", "artifact_digest", "artifact_ref"}
    if not isinstance(value, dict) or set(value) != expected:
        raise AgentError("release state shape is invalid")
    source, digest, ref = (
        value.get("source_sha"),
        value.get("artifact_digest"),
        value.get("artifact_ref"),
    )
    if (
        not isinstance(source, str)
        or not _SHA.fullmatch(source)
        or not isinstance(digest, str)
        or not _DIGEST.fullmatch(digest)
    ):
        raise AgentError("release immutable tuple is invalid")
    if ref != f"registry.ci.qdev.run/{profile.repository}@{digest}":
        raise AgentError("release artifact reference is not allowlisted")
    return {"source_sha": source, "artifact_digest": digest, "artifact_ref": ref}


def _is_profile_rollback(release: dict[str, str], profile: Profile) -> bool:
    return profile.rollback_release is not None and release == profile.rollback_release


def _is_qgeo_bootstrap(active: dict[str, str], rollback: dict[str, str], profile: Profile) -> bool:
    """Allow the one-time recovery state without inventing a third release.

    Before the first managed QGeo cutover, the verified d65 runtime is both
    the observed active image and the retained rollback target.  Once a
    candidate completes, ``write_state`` records the normal distinct tuple.
    """
    return (
        profile.project == "qazgeo"
        and profile.rollback_release is not None
        and active == profile.rollback_release
        and rollback == profile.rollback_release
    )


def read_state(path: Path, profile: Profile) -> tuple[dict[str, str], dict[str, str]]:
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
        {key: rollback_raw.get(key) for key in ("source_sha", "artifact_digest", "artifact_ref")},
        profile,
    )
    if active == rollback and not _is_qgeo_bootstrap(active, rollback, profile):
        raise AgentError("host-agent rollback must be distinct")
    return active, rollback


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_json(path: Path, document: dict[str, Any], *, prefix: str) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=prefix, dir=path.parent)
    temporary = Path(raw)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(document, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_unlink(path: Path) -> None:
    if not path.exists():
        return
    metadata = path.lstat()
    if not stat.S_ISREG(metadata.st_mode) or path.is_symlink():
        raise AgentError(f"refusing to remove non-regular durable state: {path}")
    path.unlink()
    _fsync_directory(path.parent)


def write_state(path: Path, active: dict[str, str], rollback: dict[str, str]) -> None:
    _atomic_json(
        path,
        {
            "schema": STATE_SCHEMA,
            "active_release": active,
            "rollback": {"verified": True, **rollback},
        },
        prefix=".qdev-product-release-state.",
    )


def _pending_path(config: Config) -> Path:
    return config.state_path.with_name(f"{config.state_path.name}.pending")


def _write_pending(config: Config, document: dict[str, Any]) -> None:
    _atomic_json(
        _pending_path(config),
        {"schema": PENDING_SCHEMA, **document},
        prefix=".qdev-product-release-pending.",
    )


def _clear_pending(config: Config) -> None:
    _atomic_unlink(_pending_path(config))


def _dispatch_nonce_path(config: Config) -> Path:
    return config.state_path.with_name(f"{config.state_path.name}.dispatch-nonces.jsonl")


def _consume_dispatch_nonce(config: Config, document: dict[str, Any]) -> None:
    claim = document.get("dispatch_claim")
    if not isinstance(claim, dict) or not isinstance(claim.get("nonce"), str):
        raise AgentError("QGeo dispatch nonce is unavailable")
    nonce = claim["nonce"]
    path = _dispatch_nonce_path(config)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private(path, required=False)
    try:
        raw = path.read_bytes()
    except FileNotFoundError:
        raw = b""
    if raw and not raw.endswith(b"\n"):
        raise AgentError("QGeo dispatch nonce journal has a partial record")
    for line in raw.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise AgentError("QGeo dispatch nonce journal is invalid") from error
        if not isinstance(record, dict) or set(record) != {"nonce", "claim_sha256"}:
            raise AgentError("QGeo dispatch nonce journal shape is invalid")
        if record.get("nonce") == nonce:
            raise AgentError("QGeo controller dispatch nonce was already consumed")
    record = {
        "nonce": nonce,
        "claim_sha256": hashlib.sha256(_canonical_json(claim)).hexdigest(),
    }
    descriptor = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o600)
    try:
        os.write(descriptor, _canonical_json(record) + b"\n")
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    _fsync_directory(path.parent)


def _run(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    environment: dict[str, str] | None = None,
) -> bytes:
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            check=False,
            env=environment,
            timeout=1800,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AgentError(f"command could not complete: {command[0]}") from error
    if result.returncode:
        raise AgentError(f"command failed: {command[0]}")
    return result.stdout


def _json_command(command: list[str], *, description: str) -> object:
    """Run one command and fail closed when its evidence is not valid JSON."""
    try:
        return json.loads(_run(command))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AgentError(f"{description} is not JSON") from error


def request(
    config: Config,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
    if headers is not None:
        allowed = {"X-QDev-Release-Lease", "X-QDev-Release-Fence"}
        if set(headers) - allowed:
            raise AgentError("controller request contains a non-allowlisted header")
        for name, value in headers.items():
            if not isinstance(value, str):
                raise AgentError("controller request header is invalid")
            if name == "X-QDev-Release-Lease" and not _LEASE.fullmatch(value):
                raise AgentError("controller release lease is invalid")
            if name == "X-QDev-Release-Fence" and not _FENCE.fullmatch(value):
                raise AgentError("controller release fence is invalid")
    command = [
        "curl",
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
    if headers:
        insert_at = 1
        for name, value in headers.items():
            command[insert_at:insert_at] = ["--header", f"{name}: {value}"]
            insert_at += 2
    output = _run(command, input_bytes=body)
    raw_body, _, raw_status = output.rpartition(b"\n")
    try:
        return int(raw_status), raw_body
    except ValueError as error:
        raise AgentError("controller response did not expose HTTP status") from error


def heartbeat(profile: Profile, active: dict[str, str], rollback: dict[str, str]) -> dict[str, Any]:
    stats = os.statvfs("/")
    free = stats.f_bavail * stats.f_frsize / 1024**3
    return {
        "schema": "qdev-release-host-agent-heartbeat-v1",
        "release_lane": profile.lane,
        "project_id": profile.project,
        "placement": profile.placement,
        "state": "ready",
        "release_lock": "available",
        "capacity_free_gib": round(free, 3),
        "active_release": active,
        "rollback": {"verified": True, **rollback},
    }


def _validate_qgeo_dispatch(
    document: dict[str, Any], profile: Profile, config: Config, *, now: float | None = None
) -> None:
    if config.host_identity != f"qdev-host-agent:{profile.placement}":
        raise AgentError("QGeo host dispatch identity does not match signed profile")
    if config.dispatch_secret is None:
        raise AgentError("QGeo host dispatch verifier is unavailable")
    claim = document.get("dispatch_claim")
    signature = document.get("dispatch_claim_signature")
    expected_claim_fields = {
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
    if not isinstance(claim, dict) or set(claim) != expected_claim_fields:
        raise AgentError("QGeo controller dispatch claim shape is invalid")
    if not isinstance(signature, str) or not _HEX64.fullmatch(signature):
        raise AgentError("QGeo controller dispatch signature is invalid")
    calculated = hmac.new(
        config.dispatch_secret, _canonical_json(claim), hashlib.sha256
    ).hexdigest()
    if not hmac.compare_digest(calculated, signature):
        raise AgentError("QGeo controller dispatch signature is invalid")
    current = int(time.time() if now is None else now)
    issued_at, expires_at = claim.get("issued_at"), claim.get("expires_at")
    lease_expires_at = claim.get("lease_expires_at")
    if (
        not isinstance(issued_at, int)
        or isinstance(issued_at, bool)
        or not isinstance(expires_at, int)
        or isinstance(expires_at, bool)
        or expires_at <= issued_at
        or expires_at - issued_at > HOST_DISPATCH_CLAIM_MAX_TTL_SECONDS
        or issued_at > current + HOST_DISPATCH_CLOCK_SKEW_SECONDS
        or expires_at <= current
        or not isinstance(lease_expires_at, int)
        or isinstance(lease_expires_at, bool)
        or expires_at > lease_expires_at
        or lease_expires_at <= current
        or not isinstance(claim.get("nonce"), str)
        or not _NONCE.fullmatch(claim["nonce"])
    ):
        raise AgentError("QGeo controller dispatch claim is expired or not yet valid")
    bound = {
        "repository": profile.repository,
        "exact_sha": document.get("source_sha"),
        "host_identity": config.host_identity,
        "release_id": document.get("release_id"),
        "release_lane": profile.lane,
        "project_id": profile.project,
        "placement": profile.placement,
        "artifact_digest": document.get("artifact_digest"),
        "artifact_ref": document.get("artifact_ref"),
        "lease_id": document.get("lease_id"),
        "fence": document.get("fence"),
        "lease_expires_at": document.get("lease_expires_at"),
        "rollback_anchor": document.get("rollback_anchor"),
        "candidate_evidence": document.get("candidate_evidence"),
    }
    if any(claim.get(key) != value for key, value in bound.items()):
        raise AgentError("QGeo controller dispatch claim does not bind the exact job")
    if (
        claim.get("runner_profile") not in _RUNNER_PROFILES
        or any(
            not isinstance(claim.get(field), str) or not _CI_SCOPE_VALUE.fullmatch(claim[field])
            for field in ("workflow", "job")
        )
        or any(
            not isinstance(claim.get(field), int)
            or isinstance(claim[field], bool)
            or claim[field] <= 0
            for field in ("run_id", "job_id", "attempt")
        )
    ):
        raise AgentError("QGeo controller dispatch CI scope is invalid")
    candidate_evidence = document.get("candidate_evidence")
    expected_provenance = _expected_qgeo_artifact_provenance(profile)
    if (
        not isinstance(candidate_evidence, dict)
        or set(candidate_evidence) != {"schema", "candidate_receipt_sha256", "artifact_provenance"}
        or candidate_evidence.get("schema") != "qdev-release-candidate-evidence-v1"
        or not isinstance(candidate_evidence.get("candidate_receipt_sha256"), str)
        or not _HEX64.fullmatch(candidate_evidence["candidate_receipt_sha256"])
        or candidate_evidence.get("artifact_provenance") != expected_provenance
        or document.get("artifact_provenance") != expected_provenance
    ):
        raise AgentError("QGeo controller dispatch candidate evidence is invalid")


def validate_job(
    document: object, profile: Profile, config: Config | None = None, *, now: float | None = None
) -> tuple[str, dict[str, str]]:
    required = {
        "schema",
        "release_id",
        "release_lane",
        "project_id",
        "placement",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
    }
    optional = {"lease_id", "fence"}
    if profile.project == "qazgeo":
        required.update(
            {
                "lease_expires_at",
                "rollback_anchor",
                "candidate_evidence",
                "dispatch_claim",
                "dispatch_claim_signature",
                "artifact_provenance",
            }
        )
    if (
        not isinstance(document, dict)
        or not required.issubset(document)
        or set(document) - required - optional
        or document.get("schema") != "qdev-release-host-agent-job-v1"
    ):
        raise AgentError("controller release job shape is invalid")
    if (document.get("release_lane"), document.get("project_id"), document.get("placement")) != (
        profile.lane,
        profile.project,
        profile.placement,
    ):
        raise AgentError("controller release job identity is invalid")
    release_id = document.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        raise AgentError("controller release job id is invalid")
    lease_id = document.get("lease_id")
    fence = document.get("fence")
    if lease_id is not None and (not isinstance(lease_id, str) or not _LEASE.fullmatch(lease_id)):
        raise AgentError("controller release lease is invalid")
    if fence is not None and (not isinstance(fence, str) or not _FENCE.fullmatch(fence)):
        raise AgentError("controller release fence is invalid")
    if profile.project == "qazgeo" and (lease_id is None or fence is None):
        raise AgentError("QGeo managed release fencing is missing")
    release = _release(
        {key: document.get(key) for key in ("source_sha", "artifact_digest", "artifact_ref")},
        profile,
    )
    if profile.project == "qazgeo":
        if config is None:
            raise AgentError("QGeo signed dispatch configuration is missing")
        _validate_qgeo_dispatch(document, profile, config, now=now)
        if (
            release["source_sha"] != profile.candidate_source_sha
            or release["artifact_digest"] != profile.candidate_artifact_digest
        ):
            raise AgentError("QGeo job does not match the signed candidate profile")
        _job_artifact_provenance(document, profile)
    return release_id, release


def _expected_qgeo_artifact_provenance(profile: Profile) -> dict[str, str]:
    values = {
        "qazstack_source_sha": profile.qazstack_source_ref,
        "qazstack_version": profile.qazstack_version,
        "qazstack_source_manifest_sha256": profile.qazstack_source_manifest_sha256,
        "avds_source_sha": profile.avds_source_sha,
        "avds_artifact_sha256": profile.avds_artifact_sha256,
    }
    if set(values) != {
        "qazstack_source_sha",
        "qazstack_version",
        "qazstack_source_manifest_sha256",
        "avds_source_sha",
        "avds_artifact_sha256",
    } or any(not isinstance(value, str) for value in values.values()):
        raise AgentError("QGeo signed source provenance is incomplete")
    return {name: value for name, value in values.items() if isinstance(value, str)}


def _job_artifact_provenance(document: object, profile: Profile) -> dict[str, str]:
    value = document.get("artifact_provenance") if isinstance(document, dict) else None
    expected = _expected_qgeo_artifact_provenance(profile)
    if not isinstance(value, dict) or value != expected:
        raise AgentError("QGeo job provenance does not match the signed profile")
    return expected


def _job_fencing(document: object, profile: Profile) -> tuple[str | None, str | None]:
    """Return the controller lease/fence after the job has been validated."""
    if not isinstance(document, dict):
        raise AgentError("controller release job is invalid")
    lease_id = document.get("lease_id")
    fence = document.get("fence")
    if profile.project == "qazgeo" and (
        not isinstance(lease_id, str)
        or not _LEASE.fullmatch(lease_id)
        or not isinstance(fence, str)
        or not _FENCE.fullmatch(fence)
    ):
        raise AgentError("QGeo managed release fencing is missing")
    return lease_id, fence


def verify_image(release: dict[str, str], profile: Profile) -> None:
    image_reference = release["artifact_ref"]
    if _is_profile_rollback(release, profile) and profile.rollback_image_reference:
        image_reference = profile.rollback_image_reference
    elif not profile.preloaded_image_required:
        _run(["docker", "pull", release["artifact_ref"]])
    digests = _json_command(
        [
            "docker",
            "image",
            "inspect",
            image_reference,
            "--format",
            "{{json .RepoDigests}}",
        ],
        description="image repository digests",
    )
    expected_refs = {release["artifact_ref"]}
    # The recovery image is intentionally kept under its historical local
    # tag.  Docker reports that tag's repository digest as ``qazgeo-app@…``;
    # accepting it is limited to the compiled rollback tuple and never
    # weakens candidate registry binding.
    if _is_profile_rollback(release, profile):
        expected_refs.add(f"qazgeo-app@{release['artifact_digest']}")
    if not isinstance(digests, list) or not expected_refs.intersection(digests):
        raise AgentError("pulled image does not retain requested immutable reference")
    revision = (
        _run(
            [
                "docker",
                "image",
                "inspect",
                image_reference,
                "--format",
                '{{ index .Config.Labels "org.opencontainers.image.revision" }}',
            ]
        )
        .decode()
        .strip()
    )
    if revision != release["source_sha"]:
        raise AgentError("OCI image source revision does not match controller job")


def _static_manifest(directory: Path, release: dict[str, str]) -> tuple[dict[str, Any], str]:
    """Return a deterministic file manifest and its digest for a static tree."""
    files: list[dict[str, str]] = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise AgentError("static bundle contains a symlink")
        if not path.is_file():
            continue
        relative = path.relative_to(directory).as_posix()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        files.append({"path": relative, "sha256": digest})
    if not files:
        raise AgentError("static bundle is empty")
    payload = {
        "schema": "qdev-qazgeo-static-bundle-v1",
        "source_sha": release["source_sha"],
        "artifact_digest": release["artifact_digest"],
        "files": files,
    }
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return payload, hashlib.sha256(encoded).hexdigest()


def _static_manifest_document(bundle: dict[str, Any], digest: str) -> dict[str, Any]:
    return {
        "schema": "qdev-qazgeo-static-manifest-v1",
        "bundle": bundle,
        "manifest_digest": digest,
    }


def _read_static_manifest(path: Path) -> dict[str, Any]:
    if path.is_symlink() or not path.is_file():
        raise AgentError("QGeo static manifest is unavailable")
    try:
        recorded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AgentError("QGeo static manifest is unreadable") from error
    if (
        not isinstance(recorded, dict)
        or set(recorded) != {"schema", "bundle", "manifest_digest"}
        or recorded.get("schema") != "qdev-qazgeo-static-manifest-v1"
    ):
        raise AgentError("QGeo static manifest shape is invalid")
    return recorded


def _install_static_manifest(path: Path, manifest: dict[str, Any]) -> None:
    """Install one immutable manifest without a check-then-replace overwrite."""

    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", dir=path.parent, prefix=".static-", delete=False
        ) as descriptor:
            temporary = Path(descriptor.name)
            json.dump(manifest, descriptor, sort_keys=True, separators=(",", ":"))
            descriptor.write("\n")
            descriptor.flush()
            os.fsync(descriptor.fileno())
        assert temporary is not None
        os.chmod(temporary, 0o644)
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise AgentError("QGeo static manifest appeared during materialization") from error
        _fsync_directory(path.parent)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _mkdir_durable(path: Path, mode: int = 0o755) -> None:
    """Create a directory chain and durably publish every new entry."""

    missing: list[Path] = []
    current = path
    while not current.exists():
        missing.append(current)
        if current == current.parent:
            raise AgentError("static directory has no existing ancestor")
        current = current.parent
    if current.is_symlink() or not current.is_dir():
        raise AgentError("static directory parent is not canonical")
    # The first existing ancestor can itself be the result of a mkdir that
    # survived a crash before its parent directory was synced.  Close that
    # interrupted publication boundary before extending the chain.
    _fsync_directory(current.parent)
    for directory in reversed(missing):
        try:
            directory.mkdir(mode=mode)
        except FileExistsError:
            if directory.is_symlink() or not directory.is_dir():
                raise AgentError("static directory is not canonical") from None
        _fsync_directory(directory.parent)
    if path.is_symlink() or not path.is_dir():
        raise AgentError("static directory is not canonical")


def _fsync_static_tree(directory: Path) -> None:
    """Make every file and directory entry durable before publishing proof."""

    directories = [directory]
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise AgentError("static bundle contains a symlink")
        if path.is_dir():
            directories.append(path)
            continue
        if not path.is_file():
            raise AgentError("static bundle contains an unsupported entry")
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
    for path in sorted(directories, key=lambda value: len(value.parts), reverse=True):
        _fsync_directory(path)


def _remove_static_staging(directory: Path) -> None:
    """Remove only a controller-created staging tree without following links."""

    for child in sorted(directory.rglob("*"), key=lambda value: len(value.parts), reverse=True):
        if child.is_file() or child.is_symlink():
            child.unlink(missing_ok=True)
        elif child.is_dir():
            child.rmdir()
        else:
            raise AgentError("static staging contains an unsupported entry")
    directory.rmdir()


def _remove_stale_static_staging(root: Path, source_sha: str) -> None:
    """Remove abandoned staging trees for one exact immutable release."""

    if not _SHA.fullmatch(source_sha):
        raise AgentError("QGeo static source revision is invalid")
    for directory in sorted(root.glob(f".{source_sha}.*")):
        if directory.is_symlink() or not directory.is_dir():
            raise AgentError("QGeo static staging path is not canonical")
        _remove_static_staging(directory)
    _fsync_directory(root)


def _directory_manifest_digest(directory: Path) -> str:
    """Hash a canonical directory without following links.

    QazStack is mounted from a controller-pinned source checkout.  A content
    manifest is the truthful provenance for that source install; hashing the
    path and each file digest keeps the result stable across hosts while
    detecting both content and file-set changes.
    """
    if directory.is_symlink() or not directory.is_dir():
        raise AgentError("pinned source directory is unavailable")
    files: list[dict[str, str]] = []
    for path in sorted(directory.rglob("*")):
        if path.is_symlink():
            raise AgentError("pinned source directory contains a symlink")
        if not path.is_file():
            continue
        files.append(
            {
                "path": path.relative_to(directory).as_posix(),
                "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            }
        )
    if not files:
        raise AgentError("pinned source directory is empty")
    encoded = json.dumps(
        {"schema": "qdev-source-directory-manifest-v1", "files": files},
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


def _compose_container(profile: Profile, service: str) -> tuple[str, dict[str, Any]]:
    """Return the unique running Compose container for a compiled service."""
    ids = [
        item.strip()
        for item in _run(
            [
                "docker",
                "ps",
                "--filter",
                f"label=com.docker.compose.project={profile.name}",
                "--filter",
                f"label=com.docker.compose.service={service}",
                "--format",
                "{{.ID}}",
            ]
        )
        .decode()
        .splitlines()
        if item.strip()
    ]
    if len(ids) != 1:
        raise AgentError(f"QGeo service {service} does not have one running container")
    inspected = _json_command(
        ["docker", "inspect", ids[0]], description=f"QGeo service {service} inspection"
    )
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        raise AgentError(f"QGeo service {service} inspection is invalid")
    container = inspected[0]
    state = container.get("State")
    if not isinstance(state, dict) or state.get("Running") is not True:
        raise AgentError(f"QGeo service {service} is not running")
    return ids[0], container


def _running_image_identity(profile: Profile, release: dict[str, str]) -> dict[str, Any]:
    """Prove the exact immutable image currently serving the app service."""
    container_id, container = _compose_container(profile, "app")
    config = container.get("Config")
    if not isinstance(config, dict) or not isinstance(config.get("Image"), str):
        raise AgentError("QGeo app container image identity is unavailable")
    configured_image = config["Image"]
    expected_image = release["artifact_ref"]
    if _is_profile_rollback(release, profile) and profile.rollback_image_reference:
        expected_image = profile.rollback_image_reference
    if configured_image != expected_image:
        raise AgentError("QGeo app container is running a different image reference")
    inspected_image = _json_command(
        ["docker", "image", "inspect", configured_image],
        description="QGeo app image inspection",
    )
    if not isinstance(inspected_image, list) or len(inspected_image) != 1:
        raise AgentError("QGeo app image inspection is invalid")
    image = inspected_image[0]
    if not isinstance(image, dict):
        raise AgentError("QGeo app image identity is invalid")
    repo_digests = image.get("RepoDigests")
    expected_refs = {release["artifact_ref"]}
    if _is_profile_rollback(release, profile):
        expected_refs.add(f"qazgeo-app@{release['artifact_digest']}")
    if not isinstance(repo_digests, list) or not expected_refs.intersection(repo_digests):
        raise AgentError("QGeo app image digest is not the requested immutable digest")
    image_config = image.get("Config")
    image_labels = image_config.get("Labels") if isinstance(image_config, dict) else None
    labels = image_labels
    if (
        not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.revision") != release["source_sha"]
    ):
        raise AgentError("QGeo app OCI source revision does not match release")
    image_id = image.get("Id")
    container_image_id = container.get("Image")
    if (
        not isinstance(image_id, str)
        or not image_id
        or not isinstance(container_image_id, str)
        or container_image_id != image_id
    ):
        raise AgentError("QGeo app image ID is unavailable")
    return {
        "source_sha": release["source_sha"],
        "artifact_digest": release["artifact_digest"],
        "artifact_ref": release["artifact_ref"],
        "measured": True,
        "container_id": container_id,
        # The controller contract records the canonical immutable registry
        # reference.  For the preserved recovery image we first prove the
        # allowlisted local tag and its RepoDigest above, then project that
        # measured identity back to the canonical release tuple.
        "config_image": release["artifact_ref"],
        "image_id": image_id,
        "image_repo_digests": sorted(str(item) for item in repo_digests),
    }


def _running_dependency_image_identity(
    profile: Profile,
    service: str,
    expected: dict[str, str | None],
) -> dict[str, Any]:
    """Measure one dependency and bind it to the signed immutable profile."""
    container_id, container = _compose_container(profile, service)
    config = container.get("Config")
    configured_image = config.get("Image") if isinstance(config, dict) else None
    expected_ref = expected["artifact_ref"]
    if not isinstance(configured_image, str) or configured_image != expected_ref:
        raise AgentError(f"QGeo service {service} is running a different image reference")
    inspected = _json_command(
        ["docker", "image", "inspect", configured_image],
        description=f"QGeo service {service} image inspection",
    )
    if not isinstance(inspected, list) or len(inspected) != 1 or not isinstance(inspected[0], dict):
        raise AgentError(f"QGeo service {service} image inspection is invalid")
    image = inspected[0]
    image_id = image.get("Id")
    container_image_id = container.get("Image")
    repo_digests = image.get("RepoDigests")
    image_config = image.get("Config")
    labels = image_config.get("Labels") if isinstance(image_config, dict) else None
    measured_revision = (
        labels.get("org.opencontainers.image.revision") if isinstance(labels, dict) else None
    )
    expected_revision = expected["source_revision"]
    if measured_revision != expected_revision:
        raise AgentError(f"QGeo service {service} OCI source revision does not match profile")
    if (
        not isinstance(image_id, str)
        or not image_id.startswith("sha256:")
        or not isinstance(container_image_id, str)
        or container_image_id != image_id
        or not isinstance(repo_digests, list)
        or expected_ref not in repo_digests
        or any(not isinstance(value, str) for value in repo_digests)
    ):
        raise AgentError(f"QGeo service {service} immutable image identity is unavailable")
    return {
        "artifact_ref": expected_ref,
        "source_revision": measured_revision,
        "container_id": container_id,
        "config_image": configured_image,
        "image_id": image_id,
        "image_repo_digests": sorted(repo_digests),
    }


def _qgeo_artifact_provenance(profile: Profile) -> dict[str, str]:
    if profile.qazstack_source_directory is None or not profile.qazstack_source_ref:
        raise AgentError("QGeo QazStack source binding is unavailable")
    if profile.qazstack_version is None:
        raise AgentError("QGeo QazStack version is unavailable")
    measured_manifest = _directory_manifest_digest(profile.qazstack_source_directory)
    if measured_manifest != profile.qazstack_source_manifest_sha256:
        raise AgentError("QGeo QazStack source manifest does not match signed profile")
    provenance: dict[str, str] = {
        "qazstack_source_sha": profile.qazstack_source_ref,
        "qazstack_version": profile.qazstack_version,
        "qazstack_source_manifest_sha256": measured_manifest,
    }
    if profile.qazstack_wheel_path is not None:
        raise AgentError("QGeo signed source profile must not select a wheel")
    if profile.avds_source_sha is None or not _SHA.fullmatch(profile.avds_source_sha):
        raise AgentError("QGeo AVDS source binding is unavailable")
    if profile.avds_artifact_sha256 is None or not _HEX64.fullmatch(profile.avds_artifact_sha256):
        raise AgentError("QGeo AVDS artifact binding is unavailable")
    provenance.update(
        {
            "avds_source_sha": profile.avds_source_sha,
            "avds_artifact_sha256": profile.avds_artifact_sha256,
        }
    )
    if provenance != _expected_qgeo_artifact_provenance(profile):
        raise AgentError("QGeo runtime provenance does not match signed profile")
    return provenance


def materialize_static(release: dict[str, str], profile: Profile) -> dict[str, str] | None:
    """Extract candidate ``/app/static`` into an immutable host directory.

    The image has already passed ``verify_image`` when this helper runs.  A
    pre-existing directory is reused only when its controller-owned manifest
    proves the same source SHA and image digest; otherwise the release fails
    closed instead of overwriting an ambiguous tree.
    """
    if profile.project != "qazgeo" or profile.static_directory_root is None:
        return None
    if _is_profile_rollback(release, profile):
        return None
    root = profile.static_directory_root
    if root.is_symlink() or (root.exists() and not root.is_dir()):
        raise AgentError("QGeo static root is not canonical")
    _mkdir_durable(root)
    # Also closes a retry after mkdir(2) succeeded but its parent fsync did not.
    _fsync_directory(root.parent)
    _remove_stale_static_staging(root, release["source_sha"])
    target = root / release["source_sha"]
    manifest_dir = root.parent / "manifests"
    manifest_path = manifest_dir / f"{release['source_sha']}.json"
    target_exists = target.exists()
    manifest_exists = manifest_path.exists()
    if target_exists and (target.is_symlink() or not target.is_dir()):
        raise AgentError("QGeo static release path is not canonical")
    if target_exists and manifest_exists:
        recorded = _read_static_manifest(manifest_path)
        expected, digest = _static_manifest(target, release)
        if recorded != _static_manifest_document(expected, digest):
            raise AgentError("QGeo static release proof does not match candidate")
        # A retry can observe entries created immediately before a crash.  Make
        # both publication directories durable before accepting the fast path.
        _fsync_static_tree(target)
        _fsync_directory(root)
        _fsync_directory(manifest_dir)
        return {"digest": f"sha256:{digest}", "manifest": str(manifest_path)}

    temporary = Path(tempfile.mkdtemp(prefix=f".{release['source_sha']}.", dir=root))
    container_id = ""
    try:
        container_id = _run(["docker", "create", release["artifact_ref"]]).decode().strip()
        if not container_id:
            raise AgentError("candidate image container could not be created")
        _run(["docker", "cp", f"{container_id}:/app/static/.", str(temporary)])
        bundle, digest = _static_manifest(temporary, release)
        _fsync_static_tree(temporary)
        manifest = _static_manifest_document(bundle, digest)
        _mkdir_durable(manifest_dir)
        # Re-fsync even when the directory pre-existed: this closes recovery
        # after os.link() published the manifest but crashed before its fsync.
        _fsync_directory(manifest_dir.parent)
        if manifest_exists and _read_static_manifest(manifest_path) != manifest:
            raise AgentError("QGeo static release proof does not match candidate")
        if target_exists:
            existing_bundle, existing_digest = _static_manifest(target, release)
            if existing_bundle != bundle or existing_digest != digest:
                raise AgentError("QGeo static release proof does not match candidate")
            _fsync_static_tree(target)
        if not manifest_exists:
            _install_static_manifest(manifest_path, manifest)
        else:
            _fsync_directory(manifest_dir)
        if not target_exists:
            temporary.rename(target)
            _fsync_directory(root)
        else:
            _remove_static_staging(temporary)
        return {"digest": f"sha256:{digest}", "manifest": str(manifest_path)}
    except Exception:
        if temporary.exists():
            _remove_static_staging(temporary)
        raise
    finally:
        if container_id:
            with contextlib.suppress(AgentError):
                _run(["docker", "rm", "--force", container_id])


def _compose(profile: Profile, release: dict[str, str]) -> None:
    for file in profile.compose_files:
        if not file.is_file() or file.parent != profile.release_dir:
            raise AgentError("canonical controller compose overlay is unavailable")
    if profile.controller_overlay is not None and not profile.controller_overlay.is_file():
        raise AgentError("canonical controller compose overlay is unavailable")
    _private(profile.runtime_env)
    image_reference = release["artifact_ref"]
    if _is_profile_rollback(release, profile) and profile.rollback_image_reference:
        image_reference = profile.rollback_image_reference
    static_directory: Path | None = None
    if profile.static_directory_root is not None:
        if _is_profile_rollback(release, profile):
            static_directory = profile.rollback_static_directory
        else:
            static_directory = profile.static_directory_root / release["source_sha"]
        if static_directory is None or not static_directory.is_dir():
            raise AgentError("immutable release static directory is unavailable")
        if static_directory.is_symlink() or static_directory.parent != (
            profile.rollback_static_directory.parent
            if _is_profile_rollback(release, profile) and profile.rollback_static_directory
            else profile.static_directory_root
        ):
            raise AgentError("release static directory is not canonical")
    environment = dict(os.environ)
    environment.update(
        {
            "QDEV_RELEASE_SOURCE_SHA": release["source_sha"],
            "QDEV_RELEASE_ARTIFACT_DIGEST": release["artifact_digest"],
        }
    )
    environment[profile.image_environment] = image_reference
    if static_directory is not None:
        environment["QAZGEO_STATIC_DIR"] = str(static_directory)
    if profile.project == "qazgeo":
        if profile.qazstack_source_directory is None:
            raise AgentError("QGeo QazStack source directory is unavailable")
        environment["QAZGEO_SOURCE_REVISION"] = release["source_sha"]
        environment["QAZSTACK_SOURCE_DIR"] = str(profile.qazstack_source_directory)
    command = [
        "docker",
        "compose",
        "--project-name",
        profile.name,
        "--env-file",
        str(profile.runtime_env),
    ]
    for file in profile.compose_files:
        command.extend(["-f", str(file)])
    if profile.controller_overlay is not None:
        command.extend(["-f", str(profile.controller_overlay)])
    command.extend(
        ["up", "-d", "--force-recreate", "--no-build", "--pull", "never", *profile.services]
    )
    _run(command, environment=environment)


def _read_path(document: object, path: tuple[str, ...]) -> object:
    value = document
    for segment in path:
        if not isinstance(value, dict):
            return None
        value = value.get(segment)
    return value


def runtime_proof(
    profile: Profile,
    release: dict[str, str],
    static_bundle: dict[str, str] | None = None,
) -> dict[str, Any]:
    local = _json_command(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            profile.local_ready_url,
        ],
        description="local readiness",
    )
    if not isinstance(local, dict) or local.get("status") != "ok":
        raise AgentError("local readiness is not truthful")
    readiness: dict[str, str] = {"local": "ok"}
    if profile.local_readiness_url is not None:
        local_readiness = _json_command(
            [
                "curl",
                "--fail",
                "--silent",
                "--show-error",
                "--connect-timeout",
                "10",
                "--max-time",
                "30",
                profile.local_readiness_url,
            ],
            description="local startup readiness",
        )
        if not isinstance(local_readiness, dict) or not (
            local_readiness.get("ready") is True
            or (profile.project == "qazgeo" and local_readiness.get("status") == "ok")
        ):
            raise AgentError("local startup readiness is not truthful")
        readiness["migration"] = "startup-readiness-verified"
    public = _json_command(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            profile.public_release_url,
        ],
        description="public release identity",
    )
    if not isinstance(public, dict):
        raise AgentError("public release identity is invalid")
    if _read_path(public, profile.public_identity_path) != release["source_sha"]:
        raise AgentError("public release identity does not match promoted source")
    if profile.public_version is not None and public.get("version") != profile.public_version:
        raise AgentError("public release version does not match allowlisted profile")
    if profile.require_runtime_identity and (
        public.get("runtime_revision") != release["source_sha"]
        or public.get("identityStatus") != "verified"
    ):
        raise AgentError("public runtime identity is not verified")
    if profile.name == "qaz-fund" and (
        public.get("imageDigest") != release["artifact_digest"]
        or public.get("artifactDigest") != release["artifact_digest"]
    ):
        raise AgentError("public QAZ.FUND artifact identity does not match promoted image")
    proof: dict[str, Any] = {}
    if profile.project == "qazgeo":
        dependency_values = {
            "db": local.get("db_connected"),
            "postgis": local.get("postgis"),
            "martin": local.get("martin_tiles"),
            "photon": local.get("photon_geocoder"),
        }
        if any(value is not True for value in dependency_values.values()):
            raise AgentError("QGeo local dependency readiness is not truthful")
        if profile.dependency_images is None:
            raise AgentError("QGeo signed dependency image identities are unavailable")
        dependencies: dict[str, dict[str, Any]] = {
            service: _running_dependency_image_identity(profile, service, expected)
            for service, expected in profile.dependency_images.items()
        }
        dependencies["postgis"] = {
            **dependencies["db"],
            "image_repo_digests": list(dependencies["db"]["image_repo_digests"]),
        }
        redis_container_id = _compose_container(profile, "redis")[0]
        redis_inspection = _json_command(
            ["docker", "inspect", redis_container_id], description="QGeo Redis inspection"
        )
        if not isinstance(redis_inspection, list) or len(redis_inspection) != 1:
            raise AgentError("QGeo Redis inspection is invalid")
        redis_document = redis_inspection[0]
        redis_state = redis_document.get("State") if isinstance(redis_document, dict) else None
        redis_health = redis_state.get("Health") if isinstance(redis_state, dict) else None
        if not isinstance(redis_health, dict) or redis_health.get("Status") != "healthy":
            raise AgentError("QGeo Redis readiness is not truthful")
        readiness.update({key: "ok" for key in dependency_values})
        readiness["redis"] = "ok"
        readiness["app"] = "ok"
        runtime_identity = _running_image_identity(profile, release)
        proof["runtime_identity"] = runtime_identity
        dependencies["app"] = {
            "artifact_ref": release["artifact_ref"],
            "source_revision": release["source_sha"],
            "container_id": runtime_identity["container_id"],
            "config_image": runtime_identity["config_image"],
            "image_id": runtime_identity["image_id"],
            "image_repo_digests": list(runtime_identity["image_repo_digests"]),
        }
        proof["dependency_identity"] = dependencies
        proof["artifact_provenance"] = _qgeo_artifact_provenance(profile)
        if not _is_profile_rollback(release, profile):
            if static_bundle is None:
                if profile.static_directory_root is None:
                    raise AgentError("QGeo static root is unavailable")
                target = profile.static_directory_root / release["source_sha"]
                manifest_path = (
                    profile.static_directory_root.parent
                    / "manifests"
                    / (f"{release['source_sha']}.json")
                )
                if not target.is_dir() or not manifest_path.is_file():
                    raise AgentError("QGeo static release proof is unavailable")
                bundle, digest = _static_manifest(target, release)
                try:
                    recorded = json.loads(manifest_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError) as error:
                    raise AgentError("QGeo static manifest is unreadable") from error
                if (
                    not isinstance(recorded, dict)
                    or recorded.get("bundle") != bundle
                    or recorded.get("manifest_digest") != digest
                ):
                    raise AgentError("QGeo static release proof does not match candidate")
                static_bundle = {"digest": f"sha256:{digest}", "manifest": str(manifest_path)}
            proof["static_bundle"] = static_bundle
    readiness["public"] = "ok"
    proof["readiness"] = readiness
    return proof


def _completion_receipt(
    profile: Profile,
    release: dict[str, str],
    rollback: dict[str, str],
    readiness: dict[str, Any] | None = None,
    *,
    proof: dict[str, Any] | None = None,
    static_bundle: dict[str, str] | None = None,
) -> dict[str, Any]:
    evidence = dict(proof or {})
    if readiness is None:
        readiness = evidence.pop("readiness", None)
    else:
        evidence.pop("readiness", None)
    if not isinstance(readiness, dict):
        raise AgentError("runtime readiness proof is missing")
    if static_bundle is not None:
        evidence["static_bundle"] = static_bundle
    receipt = {
        "schema": "qdev-controller-release-runtime-receipt-v1",
        "status": "verified",
        "project": profile.project,
        "release_lane": profile.lane,
        "placement": profile.placement,
        **release,
        "health": "ok",
        "readiness": readiness,
        "rollback": {"verified": True, **rollback},
    }
    receipt.update(evidence)
    return receipt


def _controller_headers(lease_id: str | None, fence: str | None) -> dict[str, str]:
    headers = {
        name: value
        for name, value in (
            ("X-QDev-Release-Lease", lease_id),
            ("X-QDev-Release-Fence", fence),
        )
        if value is not None
    }
    if len(headers) != 2:
        raise AgentError("managed controller fencing is incomplete")
    return headers


def _submission_headers(
    profile: Profile, lease_id: str | None, fence: str | None
) -> dict[str, str]:
    """Require fencing for managed QGeo without breaking legacy static lanes."""

    if profile.project == "qazgeo":
        return _controller_headers(lease_id, fence)
    headers: dict[str, str] = {}
    if lease_id is not None:
        if not _LEASE.fullmatch(lease_id):
            raise AgentError("controller release lease is invalid")
        headers["X-QDev-Release-Lease"] = lease_id
    if fence is not None:
        if not _FENCE.fullmatch(fence):
            raise AgentError("controller release fence is invalid")
        headers["X-QDev-Release-Fence"] = fence
    return headers


def _response_document(body: bytes, *, uncertain: bool) -> dict[str, Any]:
    try:
        document = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        error_type = ControllerTransportError if uncertain else AgentError
        raise error_type("controller response is not valid JSON") from error
    if not isinstance(document, dict):
        error_type = ControllerTransportError if uncertain else AgentError
        raise error_type("controller response shape is invalid")
    return document


def _controller_status(
    config: Config,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    restored: dict[str, str],
    *,
    lease_id: str | None,
    fence: str | None,
) -> dict[str, Any]:
    status, body = request(
        config,
        "GET",
        f"/internal/v1/release-hosts/{profile.placement}/jobs/{release_id}",
        headers=_controller_headers(lease_id, fence),
    )
    if status != 200:
        raise AgentError("controller has no verifiable release outcome")
    document = _response_document(body, uncertain=False)
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
        or document.get("project_id") != profile.project
        or document.get("placement") != profile.placement
        or _release(
            {key: document.get(key) for key in ("source_sha", "artifact_digest", "artifact_ref")},
            profile,
        )
        != candidate
    ):
        raise AgentError("controller release outcome identity is invalid")
    state = document.get("status")
    if state in {"accepted", "dispatched"}:
        if (
            document.get("runtime_receipt") is not None
            or document.get("rollback_receipt") is not None
        ):
            raise AgentError("active controller outcome has a terminal receipt")
    elif state == "verified":
        if document.get("rollback_receipt") is not None:
            raise AgentError("verified controller outcome has a rollback receipt")
        measured_receipt = document.get("runtime_receipt")
        if not isinstance(measured_receipt, dict):
            raise AgentError("verified controller outcome lacks a runtime receipt")
        expected_receipt = _completion_receipt(
            profile,
            candidate,
            restored,
            proof={
                key: value
                for key, value in measured_receipt.items()
                if key
                not in {
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
            },
            readiness=measured_receipt.get("readiness"),
        )
        if measured_receipt != expected_receipt:
            raise AgentError("verified controller runtime receipt is invalid")
    elif state == "rolled_back":
        receipt = document.get("rollback_receipt")
        if (
            document.get("runtime_receipt") is not None
            or not isinstance(receipt, dict)
            or receipt.get("schema") != "qdev-controller-release-rollback-receipt-v1"
            or receipt.get("status") != "rolled_back"
            or receipt.get("project_id") != profile.project
            or receipt.get("release_lane") != profile.lane
            or receipt.get("placement") != profile.placement
            or receipt.get("release_id") != release_id
            or receipt.get("failed_release") != candidate
            or receipt.get("restored_release") != restored
        ):
            raise AgentError("rolled-back controller receipt is invalid")
    else:
        raise AgentError("controller release outcome state is invalid")
    return document


def _submit_completion(
    config: Config,
    profile: Profile,
    release_id: str,
    receipt: dict[str, Any],
    *,
    lease_id: str | None,
    fence: str | None,
) -> None:
    try:
        status, body = request(
            config,
            "POST",
            f"/internal/v1/release-hosts/{profile.placement}/jobs/{release_id}/complete"
            f"?release_lane={profile.lane}",
            receipt,
            headers=_submission_headers(profile, lease_id, fence),
        )
    except AgentError as error:
        raise ControllerTransportError("controller completion outcome is unknown") from error
    if status != 200:
        raise AgentError("controller rejected verified runtime receipt")
    if _response_document(body, uncertain=True) != receipt:
        raise ControllerTransportError("controller completion acknowledgement is not exact")


def complete(
    config: Config,
    profile: Profile,
    release_id: str,
    release: dict[str, str],
    rollback: dict[str, str],
    readiness: dict[str, Any] | None = None,
    *,
    proof: dict[str, Any] | None = None,
    static_bundle: dict[str, str] | None = None,
    lease_id: str | None = None,
    fence: str | None = None,
) -> dict[str, Any]:
    receipt = _completion_receipt(
        profile,
        release,
        rollback,
        readiness,
        proof=proof,
        static_bundle=static_bundle,
    )
    _submit_completion(
        config,
        profile,
        release_id,
        receipt,
        lease_id=lease_id,
        fence=fence,
    )
    return receipt


def _rollback_receipt(
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    restored: dict[str, str],
    *,
    proof: dict[str, Any],
) -> dict[str, Any]:
    evidence = dict(proof)
    readiness = evidence.pop("readiness", None)
    evidence.pop("static_bundle", None)
    if not isinstance(readiness, dict):
        raise AgentError("rollback readiness proof is missing")
    native = {
        "schema": "qdev-admin-platform-native-receipt-v1",
        "project_id": profile.project,
        "native_host_adapter": "qazgeo-native-immutable-release-v1",
        **restored,
        "readiness": readiness,
        **evidence,
    }
    return {
        "schema": "qdev-controller-release-rollback-receipt-v1",
        "status": "rolled_back",
        "project_id": profile.project,
        "release_lane": profile.lane,
        "placement": profile.placement,
        "release_id": release_id,
        "failed_release": candidate,
        "restored_release": restored,
        "native_receipt": native,
    }


def _submit_rollback(
    config: Config,
    profile: Profile,
    release_id: str,
    receipt: dict[str, Any],
    *,
    lease_id: str | None,
    fence: str | None,
) -> None:
    try:
        status, body = request(
            config,
            "POST",
            f"/internal/v1/release-hosts/{profile.placement}/jobs/{release_id}/rollback"
            f"?release_lane={profile.lane}",
            receipt,
            headers=_submission_headers(profile, lease_id, fence),
        )
    except AgentError as error:
        raise ControllerTransportError("controller rollback outcome is unknown") from error
    if status != 200:
        raise AgentError("controller rejected rollback receipt")
    if _response_document(body, uncertain=True) != receipt:
        raise ControllerTransportError("controller rollback acknowledgement is not exact")


def rollback_remote(
    config: Config,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    restored: dict[str, str],
    *,
    lease_id: str | None = None,
    fence: str | None = None,
) -> dict[str, Any]:
    """Restore the compiled previous tuple and record a managed rollback."""
    _compose(profile, restored)
    proof = runtime_proof(profile, restored)
    receipt = _rollback_receipt(profile, release_id, candidate, restored, proof=proof)
    _submit_rollback(
        config,
        profile,
        release_id,
        receipt,
        lease_id=lease_id,
        fence=fence,
    )
    return receipt


def _pending_document(
    phase: str,
    release_id: str,
    lease_id: str,
    fence: str,
    candidate: dict[str, str],
    previous_active: dict[str, str],
    previous_rollback: dict[str, str],
    *,
    dispatch_metadata: dict[str, Any] | None = None,
    runtime_receipt: dict[str, Any] | None = None,
    rollback_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    document: dict[str, Any] = {
        "phase": phase,
        "release_id": release_id,
        "lease_id": lease_id,
        "fence": fence,
        "candidate": candidate,
        "previous_active": previous_active,
        "previous_rollback": previous_rollback,
    }
    if dispatch_metadata is not None:
        document.update(dispatch_metadata)
    if runtime_receipt is not None:
        document["runtime_receipt"] = runtime_receipt
    if rollback_receipt is not None:
        document["rollback_receipt"] = rollback_receipt
    return document


def _dispatch_metadata(document: dict[str, Any], profile: Profile) -> dict[str, Any]:
    if "dispatch_claim" in document:
        claim = document.get("dispatch_claim")
        candidate_evidence = document.get("candidate_evidence")
        if not isinstance(claim, dict) or not isinstance(candidate_evidence, dict):
            raise AgentError("QGeo dispatch metadata is incomplete")
        return {
            "lease_expires_at": document.get("lease_expires_at"),
            "dispatch_nonce": claim.get("nonce"),
            "dispatch_claim_sha256": hashlib.sha256(_canonical_json(claim)).hexdigest(),
            "signed_profile_digest": profile.signed_profile_digest,
            "candidate_evidence_sha256": hashlib.sha256(
                _canonical_json(candidate_evidence)
            ).hexdigest(),
        }
    fields = {
        "lease_expires_at",
        "dispatch_nonce",
        "dispatch_claim_sha256",
        "signed_profile_digest",
        "candidate_evidence_sha256",
    }
    if not fields <= set(document):
        raise AgentError("QGeo pending dispatch metadata is incomplete")
    return {field: document[field] for field in fields}


def _read_pending(config: Config, profile: Profile) -> dict[str, Any] | None:
    path = _pending_path(config)
    if not path.exists():
        return None
    try:
        document = json.loads(_read_private(path).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AgentError("pending release journal is not valid JSON") from error
    required = {
        "schema",
        "phase",
        "release_id",
        "lease_id",
        "fence",
        "candidate",
        "previous_active",
        "previous_rollback",
    }
    dispatch_fields = {
        "lease_expires_at",
        "dispatch_nonce",
        "dispatch_claim_sha256",
        "signed_profile_digest",
        "candidate_evidence_sha256",
    }
    required |= dispatch_fields
    optional = {"runtime_receipt", "rollback_receipt"}
    phases = {
        "prepared",
        "runtime_ready",
        "completion_submitting",
        "completion_confirmed",
        "rollback_submitting",
        "rollback_confirmed",
    }
    if (
        not isinstance(document, dict)
        or set(document) - required - optional
        or not required <= set(document)
        or document.get("schema") != PENDING_SCHEMA
        or document.get("phase") not in phases
        or not isinstance(document.get("release_id"), str)
        or not document["release_id"]
        or not isinstance(document.get("lease_id"), str)
        or not _LEASE.fullmatch(document["lease_id"])
        or not isinstance(document.get("fence"), str)
        or not _FENCE.fullmatch(document["fence"])
        or not isinstance(document.get("lease_expires_at"), int)
        or isinstance(document.get("lease_expires_at"), bool)
        or not isinstance(document.get("dispatch_nonce"), str)
        or not _NONCE.fullmatch(document["dispatch_nonce"])
        or not isinstance(document.get("dispatch_claim_sha256"), str)
        or not _HEX64.fullmatch(document["dispatch_claim_sha256"])
        or document.get("signed_profile_digest") != profile.signed_profile_digest
        or not isinstance(document.get("candidate_evidence_sha256"), str)
        or not _HEX64.fullmatch(document["candidate_evidence_sha256"])
    ):
        raise AgentError("pending release journal shape is invalid")
    document["candidate"] = _release(document["candidate"], profile)
    document["previous_active"] = _release(document["previous_active"], profile)
    document["previous_rollback"] = _release(document["previous_rollback"], profile)
    if document["candidate"] == document["previous_active"]:
        raise AgentError("pending release candidate already matches active state")
    runtime_receipt = document.get("runtime_receipt")
    rollback_receipt = document.get("rollback_receipt")
    if runtime_receipt is not None and not isinstance(runtime_receipt, dict):
        raise AgentError("pending runtime receipt is invalid")
    if rollback_receipt is not None and not isinstance(rollback_receipt, dict):
        raise AgentError("pending rollback receipt is invalid")
    return document


def _read_controller_status(
    config: Config,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    restored: dict[str, str],
    lease_id: str,
    fence: str,
) -> dict[str, Any]:
    try:
        return _controller_status(
            config,
            profile,
            release_id,
            candidate,
            restored,
            lease_id=lease_id,
            fence=fence,
        )
    except AgentError as error:
        raise ControllerOutcomeUnresolved("controller outcome cannot be reconciled") from error


def _resolve_completion(
    config: Config,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    restored: dict[str, str],
    receipt: dict[str, Any],
    lease_id: str,
    fence: str,
) -> None:
    try:
        _submit_completion(
            config,
            profile,
            release_id,
            receipt,
            lease_id=lease_id,
            fence=fence,
        )
        return
    except AgentError as first_error:
        uncertain = isinstance(first_error, ControllerTransportError)
    state = _read_controller_status(
        config, profile, release_id, candidate, restored, lease_id, fence
    )
    if state["status"] == "verified":
        if state["runtime_receipt"] != receipt:
            raise ControllerOutcomeUnresolved("controller verified a different runtime receipt")
        return
    if state["status"] == "rolled_back":
        raise ControllerOutcomeUnresolved("controller rolled back before completion reconciliation")
    if not uncertain:
        raise CompletionRejected("controller definitely rejected the runtime receipt")
    try:
        _submit_completion(
            config,
            profile,
            release_id,
            receipt,
            lease_id=lease_id,
            fence=fence,
        )
        return
    except AgentError as retry_error:
        retry_uncertain = isinstance(retry_error, ControllerTransportError)
    state = _read_controller_status(
        config, profile, release_id, candidate, restored, lease_id, fence
    )
    if state["status"] == "verified" and state["runtime_receipt"] == receipt:
        return
    if state["status"] in {"accepted", "dispatched"} and not retry_uncertain:
        raise CompletionRejected("controller definitely rejected the exact runtime receipt")
    raise ControllerOutcomeUnresolved("controller completion outcome remains unresolved")


def _resolve_rollback(
    config: Config,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    restored: dict[str, str],
    receipt: dict[str, Any],
    lease_id: str,
    fence: str,
) -> None:
    try:
        _submit_rollback(
            config,
            profile,
            release_id,
            receipt,
            lease_id=lease_id,
            fence=fence,
        )
        return
    except AgentError as first_error:
        uncertain = isinstance(first_error, ControllerTransportError)
    state = _read_controller_status(
        config, profile, release_id, candidate, restored, lease_id, fence
    )
    if state["status"] == "rolled_back":
        if state["rollback_receipt"] != receipt:
            raise ControllerOutcomeUnresolved("controller recorded a different rollback receipt")
        return
    if state["status"] == "verified":
        raise ControllerOutcomeUnresolved("controller is verified after local rollback")
    if not uncertain:
        raise ControllerOutcomeUnresolved("controller definitely rejected the rollback receipt")
    try:
        _submit_rollback(
            config,
            profile,
            release_id,
            receipt,
            lease_id=lease_id,
            fence=fence,
        )
        return
    except AgentError as retry_error:
        state = _read_controller_status(
            config, profile, release_id, candidate, restored, lease_id, fence
        )
        if state["status"] == "rolled_back" and state["rollback_receipt"] == receipt:
            return
        raise ControllerOutcomeUnresolved(
            "controller rollback outcome remains unresolved"
        ) from retry_error


def _managed_rollback(
    config: Config,
    profile: Profile,
    release_id: str,
    candidate: dict[str, str],
    previous_active: dict[str, str],
    previous_rollback: dict[str, str],
    lease_id: str,
    fence: str,
    *,
    runtime_receipt: dict[str, Any] | None = None,
) -> dict[str, Any]:
    pending = _read_pending(config, profile)
    if pending is None:
        raise ControllerOutcomeUnresolved("managed rollback has no durable dispatch context")
    dispatch_metadata = _dispatch_metadata(pending, profile)
    context = _pending_document(
        "rollback_submitting",
        release_id,
        lease_id,
        fence,
        candidate,
        previous_active,
        previous_rollback,
        dispatch_metadata=dispatch_metadata,
        runtime_receipt=runtime_receipt,
    )
    _write_pending(config, context)
    _compose(profile, previous_active)
    proof = runtime_proof(profile, previous_active)
    receipt = _rollback_receipt(profile, release_id, candidate, previous_active, proof=proof)
    context = _pending_document(
        "rollback_submitting",
        release_id,
        lease_id,
        fence,
        candidate,
        previous_active,
        previous_rollback,
        dispatch_metadata=dispatch_metadata,
        runtime_receipt=runtime_receipt,
        rollback_receipt=receipt,
    )
    _write_pending(config, context)
    _resolve_rollback(
        config,
        profile,
        release_id,
        candidate,
        previous_active,
        receipt,
        lease_id,
        fence,
    )
    _write_pending(config, {**context, "phase": "rollback_confirmed"})
    write_state(config.state_path, previous_active, previous_rollback)
    _clear_pending(config)
    return receipt


def _recover_pending(
    config: Config,
    profile: Profile,
    active: dict[str, str],
    rollback: dict[str, str],
) -> dict[str, Any] | None:
    pending = _read_pending(config, profile)
    if pending is None:
        return None
    candidate = pending["candidate"]
    previous_active = pending["previous_active"]
    previous_rollback = pending["previous_rollback"]
    release_id = pending["release_id"]
    lease_id = pending["lease_id"]
    fence = pending["fence"]
    if not (
        (active == previous_active and rollback == previous_rollback)
        or (active == candidate and rollback == previous_active)
    ):
        raise ControllerOutcomeUnresolved("local state is outside the pending release boundaries")
    state = _read_controller_status(
        config, profile, release_id, candidate, previous_active, lease_id, fence
    )
    if state["status"] == "verified":
        receipt = pending.get("runtime_receipt")
        if not isinstance(receipt, dict) or state["runtime_receipt"] != receipt:
            raise ControllerOutcomeUnresolved("verified outcome does not match durable receipt")
        runtime_proof(profile, candidate)
        write_state(config.state_path, candidate, previous_active)
        _clear_pending(config)
        return {"status": "verified", "release_id": release_id, "recovered": True, **candidate}
    if state["status"] == "rolled_back":
        receipt = pending.get("rollback_receipt")
        if not isinstance(receipt, dict) or state["rollback_receipt"] != receipt:
            raise ControllerOutcomeUnresolved("rolled-back outcome does not match durable receipt")
        runtime_proof(profile, previous_active)
        write_state(config.state_path, previous_active, previous_rollback)
        _clear_pending(config)
        return {"status": "rolled_back", "release_id": release_id, "recovered": True}

    phase = pending["phase"]
    runtime_receipt = pending.get("runtime_receipt")
    if phase in {"runtime_ready", "completion_submitting", "completion_confirmed"}:
        if not isinstance(runtime_receipt, dict):
            raise ControllerOutcomeUnresolved("pending completion has no durable runtime receipt")
        runtime_proof(profile, candidate)
        try:
            _resolve_completion(
                config,
                profile,
                release_id,
                candidate,
                previous_active,
                runtime_receipt,
                lease_id,
                fence,
            )
        except CompletionRejected:
            _managed_rollback(
                config,
                profile,
                release_id,
                candidate,
                previous_active,
                previous_rollback,
                lease_id,
                fence,
                runtime_receipt=runtime_receipt,
            )
            return {"status": "rolled_back", "release_id": release_id, "recovered": True}
        _write_pending(config, {**pending, "phase": "completion_confirmed"})
        write_state(config.state_path, candidate, previous_active)
        _clear_pending(config)
        return {"status": "verified", "release_id": release_id, "recovered": True, **candidate}
    if phase in {"rollback_submitting", "rollback_confirmed"}:
        rollback_receipt = pending.get("rollback_receipt")
        if not isinstance(rollback_receipt, dict):
            _managed_rollback(
                config,
                profile,
                release_id,
                candidate,
                previous_active,
                previous_rollback,
                lease_id,
                fence,
                runtime_receipt=runtime_receipt if isinstance(runtime_receipt, dict) else None,
            )
            return {"status": "rolled_back", "release_id": release_id, "recovered": True}
        runtime_proof(profile, previous_active)
        _resolve_rollback(
            config,
            profile,
            release_id,
            candidate,
            previous_active,
            rollback_receipt,
            lease_id,
            fence,
        )
        write_state(config.state_path, previous_active, previous_rollback)
        _clear_pending(config)
        return {"status": "rolled_back", "release_id": release_id, "recovered": True}

    # A crash in the prepared phase may have occurred on either side of the
    # native Compose mutation.  Measure both exact boundaries before deciding.
    try:
        proof = runtime_proof(profile, candidate)
    except AgentError:
        runtime_proof(profile, previous_active)
        _managed_rollback(
            config,
            profile,
            release_id,
            candidate,
            previous_active,
            previous_rollback,
            lease_id,
            fence,
        )
        return {"status": "rolled_back", "release_id": release_id, "recovered": True}
    receipt = _completion_receipt(profile, candidate, previous_active, proof=proof)
    _write_pending(config, {**pending, "phase": "runtime_ready", "runtime_receipt": receipt})
    return _recover_pending(config, profile, active, rollback)


def run_once(config: Config, profile: Profile) -> dict[str, Any]:
    config.lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private(config.lock_path, required=False)
    with config.lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(config.lock_path, 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AgentError("release lock is already held") from error
        active, rollback = read_state(config.state_path, profile)
        recovered = _recover_pending(config, profile, active, rollback)
        if recovered is not None:
            return recovered
        beat = heartbeat(profile, active, rollback)
        if beat["capacity_free_gib"] < 20:
            raise AgentError("release capacity is below 20 GiB; no cleanup was attempted")
        status, _ = request(
            config, "POST", f"/internal/v1/release-hosts/{profile.placement}/heartbeat", beat
        )
        if status != 200:
            raise AgentError("controller rejected host-agent heartbeat")
        status, body = request(
            config,
            "GET",
            f"/internal/v1/release-hosts/{profile.placement}/jobs/next?release_lane={profile.lane}",
        )
        if status == 204:
            return {"status": "idle", "capacity_free_gib": beat["capacity_free_gib"]}
        if status != 200:
            raise AgentError("controller job poll was rejected")
        try:
            job_document = json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AgentError("controller release job is not JSON") from error
        release_id, release = validate_job(job_document, profile, config)
        lease_id, fence = _job_fencing(job_document, profile)
        if profile.project == "qazgeo":
            assert lease_id is not None and fence is not None
            _consume_dispatch_nonce(config, job_document)
            _write_pending(
                config,
                _pending_document(
                    "prepared",
                    release_id,
                    lease_id,
                    fence,
                    release,
                    active,
                    rollback,
                    dispatch_metadata=_dispatch_metadata(job_document, profile),
                ),
            )
        try:
            # Prove candidate-bound shared sources before pulling an image or
            # touching Compose/static state.  A signed path is not evidence
            # until its complete file manifest has been measured on this host.
            if profile.project == "qazgeo" and _qgeo_artifact_provenance(
                profile
            ) != _job_artifact_provenance(job_document, profile):
                raise AgentError("QGeo source provenance changed before activation")
            verify_image(release, profile)
            static_bundle = materialize_static(release, profile)
            _compose(profile, release)
            proof = runtime_proof(profile, release, static_bundle)
            if profile.project == "qazgeo":
                assert lease_id is not None and fence is not None
                receipt = _completion_receipt(
                    profile,
                    release,
                    active,
                    proof=proof,
                    static_bundle=static_bundle,
                )
                completion_context = _pending_document(
                    "completion_submitting",
                    release_id,
                    lease_id,
                    fence,
                    release,
                    active,
                    rollback,
                    # Re-bind the controller-signed dispatch directly.  The
                    # prepared journal is recovery evidence, not an input
                    # dependency for the same uninterrupted transaction.
                    dispatch_metadata=_dispatch_metadata(job_document, profile),
                    runtime_receipt=receipt,
                )
                _write_pending(config, completion_context)
                _resolve_completion(
                    config,
                    profile,
                    release_id,
                    release,
                    active,
                    receipt,
                    lease_id,
                    fence,
                )
                try:
                    _write_pending(config, {**completion_context, "phase": "completion_confirmed"})
                except (OSError, AgentError) as error:
                    # The controller may already be terminal verified.  Keep
                    # the earlier completion_submitting journal and reconcile
                    # on restart instead of rolling back a verified release.
                    raise ControllerOutcomeUnresolved(
                        "controller completion is verified but local journal finalization failed"
                    ) from error
            else:
                complete(
                    config,
                    profile,
                    release_id,
                    release,
                    active,
                    proof=proof,
                    static_bundle=static_bundle,
                    lease_id=lease_id,
                    fence=fence,
                )
        except CompletionRejected as error:
            assert lease_id is not None and fence is not None
            try:
                _managed_rollback(
                    config,
                    profile,
                    release_id,
                    release,
                    active,
                    rollback,
                    lease_id,
                    fence,
                    runtime_receipt=receipt,
                )
            except Exception as rollback_error:
                raise AgentError(
                    "candidate completion was rejected and rollback failed"
                ) from rollback_error
            raise AgentError("candidate completion was rejected and rolled back") from error
        except ControllerOutcomeUnresolved:
            # The candidate and exact receipt stay journalled.  A retry must
            # reconcile controller state before it may mutate the runtime.
            raise
        except Exception as error:
            if profile.project == "qazgeo":
                assert lease_id is not None and fence is not None
                try:
                    _managed_rollback(
                        config,
                        profile,
                        release_id,
                        release,
                        active,
                        rollback,
                        lease_id=lease_id,
                        fence=fence,
                    )
                except Exception as rollback_error:
                    raise AgentError(
                        "candidate release failed and managed rollback failed"
                    ) from rollback_error
            if isinstance(error, AgentError):
                raise
            raise AgentError("candidate release failed with an operational error") from error
        write_state(config.state_path, release, active)
        if profile.project == "qazgeo":
            _clear_pending(config)
        return {"status": "verified", "release_id": release_id, **release}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted((*PROFILES, "qazgeo")), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("product release host agent must run as root")
    try:
        config = load_config(args.config)
        if args.profile == "qazgeo":
            if config.host_identity is None or config.dispatch_secret is None:
                raise AgentError("QGeo requires signed controller dispatch configuration")
            # An already durable operation may outlive the short-lived profile.
            # Its exact signed profile digest is re-checked by _read_pending and
            # it may only reconcile that operation; no new poll occurs first.
            profile = load_qgeo_profile(config, allow_expired=_pending_path(config).exists())
        else:
            if (
                config.release_profile_path is not None
                or config.release_profile_verification_key is not None
            ):
                raise AgentError("static release lane cannot select a signed QGeo profile")
            profile = PROFILES[args.profile]
        result = run_once(config, profile)
    except (AgentError, json.JSONDecodeError) as error:
        print(
            json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True), file=sys.stderr
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
