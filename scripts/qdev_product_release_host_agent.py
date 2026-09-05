#!/usr/bin/env python3
"""One-shot, controller-owned immutable release agent for approved products.

Only profiles compiled into this file may run.  A private root-owned config
contains the mTLS material and state paths; it cannot select a product, a
registry, a compose directory, or an arbitrary public URL. The agent proves
the OCI source label, starts only an immutable digest with Docker Compose
without a build, proves local and public release identity, and restores the
previous verified immutable tuple on every failed candidate. Pulls are limited
to the compiled repository and exact digest; builds and mutable tags are denied.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_LEASE = re.compile(r"^[A-Za-z0-9_-]{16,128}$")
_FENCE = re.compile(r"^[0-9a-f]{24,128}$")
STATE_SCHEMA = "qdev-release-host-state-v1"
OPERATION_SCHEMA = "qdev-product-release-operation-v1"


class AgentError(RuntimeError):
    """A host proof is absent or unsafe to act upon."""


class AcknowledgementPending(AgentError):
    """Local state is durable, but the remote acknowledgement is uncertain."""


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
        public_version="4.4.2",
        require_runtime_identity=True,
        controller_overlay=Path(
            "/opt/qdev-runner-control-plane/current/deploy/qdev-release-qmt.compose.yml"
        ),
        preloaded_image_required=False,
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


def _private(path: Path, *, required: bool = True) -> None:
    if path.is_symlink():
        raise AgentError("private file must not be a symlink")
    try:
        meta = path.stat()
    except FileNotFoundError as error:
        if required:
            raise AgentError(f"required file is missing: {path}") from error
        return
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) & 0o077:
        raise AgentError(f"file must be root-owned and private: {path}")


def load_config(path: Path) -> Config:
    _private(path)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not value:
            raise AgentError("host-agent configuration has an invalid line")
        values[key] = value
    expected = {
        "QDEV_RELEASE_CONTROLLER_URL",
        "QDEV_RELEASE_AGENT_CERT",
        "QDEV_RELEASE_AGENT_KEY",
        "QDEV_RELEASE_CONTROLLER_CA",
        "QDEV_RELEASE_STATE_PATH",
        "QDEV_RELEASE_LOCK_PATH",
    }
    if set(values) != expected:
        raise AgentError("host-agent configuration keys are invalid")
    parsed = urlsplit(values["QDEV_RELEASE_CONTROLLER_URL"])
    if (
        parsed.scheme != "https"
        or parsed.hostname != "worker.ci.qdev.run"
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.username
        or parsed.password
        or parsed.port not in {None, 443}
    ):
        raise AgentError("controller URL must be the fixed HTTPS mTLS edge")
    config = Config(
        values["QDEV_RELEASE_CONTROLLER_URL"],
        Path(values["QDEV_RELEASE_AGENT_CERT"]),
        Path(values["QDEV_RELEASE_AGENT_KEY"]),
        Path(values["QDEV_RELEASE_CONTROLLER_CA"]),
        Path(values["QDEV_RELEASE_STATE_PATH"]),
        Path(values["QDEV_RELEASE_LOCK_PATH"]),
    )
    for credential in (config.client_cert, config.client_key, config.controller_ca):
        _private(credential)
    return config


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
    if active == rollback:
        raise AgentError("host-agent rollback must be distinct")
    return active, rollback


def write_state(path: Path, active: dict[str, str], rollback: dict[str, str]) -> None:
    _write_json(
        path,
        {
            "schema": STATE_SCHEMA,
            "active_release": active,
            "rollback": {"verified": True, **rollback},
        },
    )


def _write_json(path: Path, document: dict[str, Any]) -> None:
    """Atomic replacement plus directory fsync: success means durable metadata."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private(path, required=False)
    fd, raw = tempfile.mkstemp(prefix=".qdev-product-release-state.", dir=path.parent)
    temporary = Path(raw)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(
                document,
                stream,
                sort_keys=True,
                separators=(",", ":"),
            )
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)


def _run(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    environment: dict[str, str] | None = None,
) -> bytes:
    result = subprocess.run(
        command,
        input=input_bytes,
        capture_output=True,
        check=False,
        env=environment,
        timeout=600,
    )
    if result.returncode:
        raise AgentError(f"command failed: {command[0]}")
    return result.stdout


def request(
    config: Config,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
    *,
    headers: dict[str, str] | None = None,
) -> tuple[int, bytes]:
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
    for name, value in (headers or {}).items():
        if name not in {"X-QDev-Release-Lease", "X-QDev-Release-Fence"} or not re.fullmatch(
            r"[A-Za-z0-9_-]{16,128}", value
        ):
            raise AgentError("invalid release fencing header")
        command[2:2] = ["--header", f"{name}: {value}"]
    if payload is not None:
        command[2:2] = ["--header", "content-type: application/json", "--data-binary", "@-"]
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
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


def validate_job(document: object, profile: Profile) -> tuple[str, dict[str, str]]:
    required = {
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
    }
    if (
        not isinstance(document, dict)
        or set(document) != required
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
    if not isinstance(release_id, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,128}", release_id):
        raise AgentError("controller release job id is invalid")
    if (
        not isinstance(document.get("lease_id"), str)
        or not _LEASE.fullmatch(document["lease_id"])
        or not isinstance(document.get("fence"), str)
        or not _FENCE.fullmatch(document["fence"])
    ):
        raise AgentError("controller release fencing is invalid")
    return release_id, _release(
        {key: document.get(key) for key in ("source_sha", "artifact_digest", "artifact_ref")},
        profile,
    )


def verify_image(
    release: dict[str, str],
    profile: Profile,
    *,
    pull: bool = True,
) -> dict[str, Any]:
    _release(release, profile)
    if pull and not profile.preloaded_image_required:
        _run(["docker", "pull", release["artifact_ref"]])
    images = json.loads(_run(["docker", "image", "inspect", release["artifact_ref"]]))
    if not isinstance(images, list) or len(images) != 1 or not isinstance(images[0], dict):
        raise AgentError("image inspection is invalid")
    image = images[0]
    digests = image.get("RepoDigests")
    if not isinstance(digests, list) or release["artifact_ref"] not in digests:
        raise AgentError("pulled image does not retain requested immutable reference")
    labels = _read_path(image, ("Config", "Labels"))
    if not isinstance(labels, dict):
        raise AgentError("OCI image labels are absent")
    revision = labels.get("org.opencontainers.image.revision")
    if revision != release["source_sha"]:
        raise AgentError("OCI image source revision does not match controller job")
    if not isinstance(image.get("Id"), str) or not _DIGEST.fullmatch(image["Id"]):
        raise AgentError("OCI image ID is invalid")
    return image


def _compose_command(profile: Profile, release: dict[str, str]) -> tuple[list[str], dict[str, str]]:
    for file in profile.compose_files:
        if not file.is_file() or file.parent != profile.release_dir:
            raise AgentError("canonical controller compose overlay is unavailable")
    if profile.controller_overlay is not None and not profile.controller_overlay.is_file():
        raise AgentError("canonical controller compose overlay is unavailable")
    _private(profile.runtime_env)
    environment = dict(os.environ)
    environment.update(
        {
            "QDEV_RELEASE_SOURCE_SHA": release["source_sha"],
            "QDEV_RELEASE_ARTIFACT_DIGEST": release["artifact_digest"],
        }
    )
    environment[profile.image_environment] = release["artifact_ref"]
    command = [
        "docker",
        "compose",
        "--project-name",
        profile.name,
        "--project-directory",
        str(profile.release_dir),
        "--env-file",
        str(profile.runtime_env),
    ]
    for file in profile.compose_files:
        command.extend(["-f", str(file)])
    if profile.controller_overlay is not None:
        command.extend(["-f", str(profile.controller_overlay)])
    return command, environment


def _compose(profile: Profile, release: dict[str, str]) -> None:
    command, environment = _compose_command(profile, release)
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


def container_proof(profile: Profile, release: dict[str, str]) -> dict[str, Any]:
    """Compare every running service with the inspected immutable image ID."""
    image = verify_image(release, profile, pull=False)
    command, environment = _compose_command(profile, release)
    services: dict[str, str] = {}
    for service in profile.services:
        ids = _run([*command, "ps", "--all", "--quiet", service], environment=environment)
        identifiers = ids.decode().split()
        if len(identifiers) != 1 or not re.fullmatch(r"[0-9a-f]{12,64}", identifiers[0]):
            raise AgentError("expected exactly one container for the fixed service")
        containers = json.loads(_run(["docker", "container", "inspect", identifiers[0]]))
        if not isinstance(containers, list) or len(containers) != 1:
            raise AgentError("container inspection is invalid")
        container = containers[0]
        if (
            _read_path(container, ("Image",)) != image["Id"]
            or _read_path(container, ("Config", "Image")) != release["artifact_ref"]
            or _read_path(container, ("State", "Running")) is not True
            or _read_path(container, ("Config", "Labels", "com.docker.compose.service")) != service
            or _read_path(container, ("Config", "Labels", "com.docker.compose.project"))
            != profile.name
        ):
            raise AgentError("running container does not match the immutable release")
        services[service] = image["Id"]
    return {"image_id": image["Id"], "services": services}


def runtime_proof(
    profile: Profile,
    release: dict[str, str],
    *,
    expected_version: str | None = None,
) -> dict[str, str]:
    local = json.loads(
        _run(
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
            ]
        )
    )
    if not isinstance(local, dict) or local.get("status") != "ok":
        raise AgentError("local readiness is not truthful")
    readiness = {"local": "ok"}
    if profile.local_readiness_url is not None:
        local_readiness = json.loads(
            _run(
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
                ]
            )
        )
        if not isinstance(local_readiness, dict) or local_readiness.get("ready") is not True:
            raise AgentError("local startup readiness is not truthful")
        # Startup readiness is not a database migration/rollback receipt.
        readiness["startup"] = "ok"
    public = json.loads(
        _run(
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
            ]
        )
    )
    if _read_path(public, profile.public_identity_path) != release["source_sha"]:
        raise AgentError("public release identity does not match promoted source")
    if expected_version is not None and public.get("version") != expected_version:
        raise AgentError("public release version does not match its own release tuple")
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
    readiness["public"] = "ok"
    return readiness


def runtime_receipt(
    profile: Profile,
    release: dict[str, str],
    rollback: dict[str, str],
    readiness: dict[str, str],
    containers: dict[str, Any],
    config_digest: str,
) -> dict[str, Any]:
    return {
        "schema": "qdev-controller-release-runtime-receipt-v1",
        "status": "verified",
        "project": profile.project,
        "release_lane": profile.lane,
        "placement": profile.placement,
        **release,
        "health": "ok",
        "readiness": readiness,
        "rollback": {"verified": True, **rollback},
        "runtime_identity": {**release, "measured": True, **containers},
        "dependency_identity": {"compose_config_sha256": config_digest},
        "artifact_provenance": {
            "schema": "qdev-product-oci-provenance-v1",
            **release,
            "image_id": containers["image_id"],
            "config_sha256": config_digest,
        },
    }


def _headers(job: dict[str, Any]) -> dict[str, str]:
    return {"X-QDev-Release-Lease": job["lease_id"], "X-QDev-Release-Fence": job["fence"]}


def acknowledge(
    config: Config,
    profile: Profile,
    job: dict[str, Any],
    receipt: dict[str, Any],
    *,
    rollback: bool = False,
) -> None:
    """An identical POST reconciles a lost response without a second deployment."""
    action = "rollback" if rollback else "complete"
    try:
        status, body = request(
            config,
            "POST",
            f"/internal/v1/release-hosts/{profile.placement}/jobs/{job['release_id']}/{action}"
            f"?release_lane={profile.lane}",
            receipt,
            headers=_headers(job),
        )
        if status == 200 and json.loads(body) == receipt:
            return
    except (AgentError, OSError, ValueError, subprocess.SubprocessError):
        pass
    # No success is reported and no new job is admitted until this operation
    # receives the controller's exact durable receipt. Never roll back solely
    # because the response was lost: the controller may have accepted it.
    raise AcknowledgementPending("controller acknowledgement pending; local tuple retained")


def _config_files(profile: Profile) -> tuple[Path, ...]:
    return (
        *profile.compose_files,
        profile.runtime_env,
        *((profile.controller_overlay,) if profile.controller_overlay is not None else ()),
    )


def _write_bytes(path: Path, content: bytes, mode: int = 0o600) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".qdev-release-config.", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        Path(temporary).unlink(missing_ok=True)


def snapshot_config(profile: Profile, directory: Path) -> list[dict[str, Any]]:
    """Keep configuration only in private host storage, never in a receipt."""
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    records = []
    for index, path in enumerate(_config_files(profile)):
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
            raise AgentError("release configuration is not a trusted regular file")
        if path == profile.runtime_env:
            _private(path)
        content = path.read_bytes()
        saved = directory / str(index)
        _private(saved, required=False)
        if saved.exists() and saved.read_bytes() != content:
            raise AgentError("rollback configuration snapshot cannot be replaced")
        if not saved.exists():
            _write_bytes(saved, content)
        # Allocate the restore copy on the target filesystem BEFORE pulling or
        # starting the candidate. Rename can restore changed bytes even when
        # that filesystem has no space for a new temporary file afterwards.
        reserve = _restore_reserve(path, directory)
        _private(reserve, required=False)
        if reserve.exists() and reserve.read_bytes() != content:
            raise AgentError("preallocated rollback configuration differs")
        if not reserve.exists():
            _write_bytes(reserve, content)
        records.append(
            {"sha256": hashlib.sha256(content).hexdigest(), "mode": stat.S_IMODE(info.st_mode)}
        )
    return records


def _restore_reserve(path: Path, directory: Path) -> Path:
    suffix = hashlib.sha256(str(directory).encode()).hexdigest()[:24]
    return path.with_name(f".{path.name}.qdev-rollback-{suffix}")


def restore_config(profile: Profile, directory: Path, records: list[dict[str, Any]]) -> None:
    files = _config_files(profile)
    if len(records) != len(files):
        raise AgentError("rollback configuration inventory does not match profile")
    # Validate all bytes before replacing any configuration. Recovery retries
    # after a partial write always restore the same immutable snapshot.
    content = []
    for index, record in enumerate(records):
        saved = directory / str(index)
        _private(saved)
        data = saved.read_bytes()
        if hashlib.sha256(data).hexdigest() != record.get("sha256"):
            raise AgentError("rollback configuration snapshot digest mismatch")
        mode = record.get("mode")
        if not isinstance(mode, int) or mode & ~0o755 or mode & 0o022:
            raise AgentError("rollback configuration mode is unsafe")
        content.append(data)
    for path, data, record in zip(files, content, records, strict=True):
        if path.is_symlink():
            raise AgentError("rollback target must not be a symlink")
        if path.is_file() and path.read_bytes() == data:
            if path.stat().st_uid != 0:
                raise AgentError("rollback configuration owner is not trusted")
            os.chmod(path, record["mode"])
            continue
        reserve = _restore_reserve(path, directory)
        _private(reserve)
        if reserve.read_bytes() != data:
            raise AgentError("preallocated rollback configuration digest mismatch")
        os.chmod(reserve, record["mode"])
        os.replace(reserve, path)
        target_directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(target_directory)
        finally:
            os.close(target_directory)


def config_digest(records: list[dict[str, Any]]) -> str:
    return hashlib.sha256(
        json.dumps(records, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def verify_config(profile: Profile, records: list[dict[str, Any]]) -> None:
    files = _config_files(profile)
    if len(files) != len(records):
        raise AgentError("applied configuration inventory changed")
    for path, expected in zip(files, records, strict=True):
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != 0
            or stat.S_IMODE(info.st_mode) != expected["mode"]
            or hashlib.sha256(path.read_bytes()).hexdigest() != expected["sha256"]
        ):
            raise AgentError("applied configuration differs from frozen release")


def _operation_path(config: Config) -> Path:
    return config.state_path.with_suffix(".operation.json")


def _snapshot_path(config: Config, job: dict[str, Any]) -> Path:
    # release_id was validated before this function; no caller-selected path.
    return config.state_path.parent / "rollback-config" / str(job["release_id"])


def _own_version(image: dict[str, Any], profile: Profile) -> str | None:
    value = _read_path(image, ("Config", "Labels", "org.opencontainers.image.version"))
    if profile.public_version is not None and (
        not isinstance(value, str) or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value)
    ):
        raise AgentError("rollback image lacks its own immutable version label")
    return value if isinstance(value, str) else None


def _rollback_operation(config: Config, profile: Profile, operation: dict[str, Any]) -> None:
    operation["phase"] = "rollback_pending"
    # A full disk must not prevent restoring the already journaled previous
    # image. If this write fails, the durable applying/ack_pending phase still
    # forces reconciliation on restart; no acknowledgement can escape below
    # until both state and the final journal have been written successfully.
    with suppress(OSError):
        _write_json(_operation_path(config), operation)
    previous = _release(operation["previous"], profile)
    restore_config(profile, _snapshot_path(config, operation["job"]), operation["config"])
    _compose(profile, previous)
    containers = container_proof(profile, previous)
    if containers["image_id"] != operation["previous_image_id"]:
        raise AgentError("rollback image differs from the verified previous container")
    ready = runtime_proof(profile, previous, expected_version=operation["previous_version"])
    verify_config(profile, operation["config"])
    write_state(config.state_path, previous, _release(operation["previous_rollback"], profile))
    operation["rollback_receipt"] = {
        "schema": "qdev-controller-release-rollback-receipt-v1",
        "status": "rolled_back",
        "project_id": profile.project,
        "release_lane": profile.lane,
        "placement": profile.placement,
        "release_id": operation["job"]["release_id"],
        "failed_release": operation["candidate"],
        "restored_release": previous,
        "native_receipt": {
            "schema": "qdev-admin-platform-native-receipt-v1",
            "project_id": profile.project,
            "native_host_adapter": "product-compose-v2",
            **previous,
            "readiness": ready,
            **containers,
            "config_sha256": config_digest(operation["config"]),
        },
    }
    operation["phase"] = "rollback_ack_pending"
    _write_json(_operation_path(config), operation)


def resume_operation(config: Config, profile: Profile, operation: dict[str, Any]) -> dict[str, Any]:
    validate_job(operation["job"], profile)
    candidate = _release(operation["candidate"], profile)
    if candidate != {key: operation["job"][key] for key in candidate}:
        raise AgentError("operation candidate does not bind controller job")
    phase = operation["phase"]
    if phase in {"prepared", "applying", "rollback_pending"}:
        _rollback_operation(config, profile, operation)
    elif phase == "ack_pending":
        try:
            container_proof(profile, candidate)
            runtime_proof(profile, candidate, expected_version=profile.public_version)
            verify_config(profile, operation["config"])
            if read_state(config.state_path, profile)[0] != candidate:
                raise AgentError("durable active tuple differs from pending release")
        except (AgentError, OSError, ValueError, subprocess.SubprocessError):
            _rollback_operation(config, profile, operation)
    elif phase == "rollback_ack_pending":
        previous = _release(operation["previous"], profile)
        containers = container_proof(profile, previous)
        runtime_proof(profile, previous, expected_version=operation["previous_version"])
        verify_config(profile, operation["config"])
        if (
            containers["image_id"] != operation["previous_image_id"]
            or read_state(config.state_path, profile)[0] != previous
        ):
            raise AgentError("restored tuple no longer matches pending rollback")
    elif phase not in {"verified", "rolled_back"}:
        raise AgentError("operation phase is invalid")
    if operation["phase"] in {"ack_pending", "rollback_ack_pending"}:
        rolled_back = operation["phase"] == "rollback_ack_pending"
        receipt = operation["rollback_receipt"] if rolled_back else operation["runtime_receipt"]
        acknowledge(config, profile, operation["job"], receipt, rollback=rolled_back)
        operation["phase"] = "rolled_back" if rolled_back else "verified"
        _write_json(_operation_path(config), operation)
    return {"status": operation["phase"], "release_id": operation["job"]["release_id"]}


def archive_operation(config: Config, profile: Profile, operation: dict[str, Any]) -> None:
    validate_job(operation["job"], profile)
    if operation.get("phase") not in {"verified", "rolled_back"}:
        raise AgentError("only terminal operations can be archived")
    target = config.state_path.parent / "operations" / f"{operation['job']['release_id']}.json"
    _private(target, required=False)
    if target.exists():
        if json.loads(target.read_text(encoding="utf-8")) != operation:
            raise AgentError("terminal operation archive cannot be replaced")
        return
    _write_json(target, operation)


def execute_job(
    config: Config,
    profile: Profile,
    job: dict[str, Any],
    active: dict[str, str],
    rollback: dict[str, str],
) -> dict[str, Any]:
    _, candidate = validate_job(job, profile)
    if candidate == active:
        raise AgentError("candidate is already active; no distinct transition")
    # An existing state file alone is not rollback evidence. Prove the current
    # container and its own public version before any candidate mutation.
    previous_image = verify_image(active, profile, pull=False)
    previous_version = _own_version(previous_image, profile)
    container_proof(profile, active)
    runtime_proof(profile, active, expected_version=previous_version)
    records = snapshot_config(profile, _snapshot_path(config, job))
    operation: dict[str, Any] = {
        "schema": OPERATION_SCHEMA,
        "phase": "prepared",
        "job": job,
        "candidate": candidate,
        "previous": active,
        "previous_rollback": rollback,
        "previous_version": previous_version,
        "previous_image_id": previous_image["Id"],
        "config": records,
    }
    _write_json(_operation_path(config), operation)
    try:
        image = verify_image(candidate, profile)
        if (
            profile.public_version is not None
            and _own_version(image, profile) != profile.public_version
        ):
            raise AgentError("candidate OCI version does not match release profile")
        operation["phase"] = "applying"
        _write_json(_operation_path(config), operation)
        verify_config(profile, records)
        _compose(profile, candidate)
        containers = container_proof(profile, candidate)
        ready = runtime_proof(profile, candidate, expected_version=profile.public_version)
        verify_config(profile, records)
        # Metadata is durable BEFORE any success acknowledgement can escape.
        write_state(config.state_path, candidate, active)
        operation["runtime_receipt"] = runtime_receipt(
            profile,
            candidate,
            active,
            ready,
            containers,
            config_digest(records),
        )
        operation["phase"] = "ack_pending"
        _write_json(_operation_path(config), operation)
    except (AgentError, OSError, ValueError, subprocess.SubprocessError):
        _rollback_operation(config, profile, operation)
    return resume_operation(config, profile, operation)


def run_once(config: Config, profile: Profile) -> dict[str, Any]:
    config.lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _private(config.lock_path, required=False)
    with config.lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(config.lock_path, 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AgentError("release lock is already held") from error
        operation_path = _operation_path(config)
        if operation_path.exists():
            _private(operation_path)
            operation = json.loads(operation_path.read_text(encoding="utf-8"))
            if not isinstance(operation, dict) or operation.get("schema") != OPERATION_SCHEMA:
                raise AgentError("operation journal is invalid")
            if operation.get("phase") not in {"verified", "rolled_back"}:
                return resume_operation(config, profile, operation)
            archive_operation(config, profile, operation)
        active, rollback = read_state(config.state_path, profile)
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
        return execute_job(config, profile, json.loads(body), active, rollback)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=sorted(PROFILES), required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--once", action="store_true", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("product release host agent must run as root")
    try:
        result = run_once(load_config(args.config), PROFILES[args.profile])
    except (AgentError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(
            json.dumps({"status": "blocked", "reason": type(error).__name__}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
