#!/usr/bin/env python3
"""One-shot, controller-owned immutable release agent for approved products.

Only profiles compiled into this file may run.  A private root-owned config
contains the mTLS material and state paths; it cannot select a product, a
registry, a compose directory, or an arbitrary public URL. The agent proves
the OCI source label, starts only an immutable digest with Docker Compose
without a build, proves local and public release identity, and restores the
previous verified immutable tuple on every failed candidate. QMT requires a
controller-preloaded image and never pulls on the production host.
"""

from __future__ import annotations

import argparse
import contextlib
import fcntl
import hashlib
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


class AgentError(RuntimeError):
    """A host proof is absent or unsafe to act upon."""


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
    "qazgeo": Profile(
        name="qazgeo",
        lane="qdev-release-qazgeo",
        project="qazgeo",
        placement="qazgeo-primary-187",
        repository="belilovsky/qazgeo",
        release_dir=Path("/opt/qazgeo"),
        compose_files=(Path("/opt/qazgeo/docker-compose.yml"),),
        runtime_env=Path("/opt/qazgeo/.env"),
        services=("db", "redis", "app", "martin", "photon", "valhalla", "nginx"),
        local_ready_url="http://127.0.0.1:18280/health",
        local_readiness_url="http://127.0.0.1:18280/health/ready",
        public_release_url="https://qgeo.tech/health",
        public_identity_path=("source_revision",),
        image_environment="QAZGEO_APP_IMAGE",
        public_version=None,
        require_runtime_identity=False,
        controller_overlay=Path("/opt/qazgeo/releases/controller/compose-runtime.override.yml"),
        preloaded_image_required=False,
        static_directory_root=Path("/opt/qazgeo/releases/controller/static"),
        rollback_static_directory=Path(
            "/opt/qazgeo/releases/2.18.0-gitd65cd62-tablet-overflow-20260828/static"
        ),
        rollback_image_reference=("qazgeo-app:2.18.0-d65cd62-tablet-overflow-20260828"),
        rollback_release={
            "source_sha": "d65cd62a4c96786d9d5c35ebea8af872dcc3cb69",
            "artifact_digest": (
                "sha256:96d4399d5f5345f956abbffbd185552da4406a7a26017164f2ca6313688ef5cb"
            ),
            "artifact_ref": (
                "registry.ci.qdev.run/belilovsky/qazgeo@"
                "sha256:96d4399d5f5345f956abbffbd185552da4406a7a26017164f2ca6313688ef5cb"
            ),
        },
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
    try:
        meta = path.stat()
    except FileNotFoundError as error:
        if required:
            raise AgentError(f"required file is missing: {path}") from error
        return
    if meta.st_uid != 0 or stat.S_IMODE(meta.st_mode) & 0o077:
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


def write_state(path: Path, active: dict[str, str], rollback: dict[str, str]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, raw = tempfile.mkstemp(prefix=".qdev-product-release-state.", dir=path.parent)
    temporary = Path(raw)
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


def _run(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    environment: dict[str, str] | None = None,
) -> bytes:
    result = subprocess.run(
        command, input=input_bytes, capture_output=True, check=False, env=environment
    )
    if result.returncode:
        raise AgentError(f"command failed: {command[0]}")
    return result.stdout


def request(
    config: Config, method: str, path: str, payload: dict[str, Any] | None = None
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
    if not isinstance(release_id, str) or not release_id:
        raise AgentError("controller release job id is invalid")
    return release_id, _release(
        {key: document.get(key) for key in ("source_sha", "artifact_digest", "artifact_ref")},
        profile,
    )


def verify_image(release: dict[str, str], profile: Profile) -> None:
    image_reference = release["artifact_ref"]
    if _is_profile_rollback(release, profile) and profile.rollback_image_reference:
        image_reference = profile.rollback_image_reference
    elif not profile.preloaded_image_required:
        _run(["docker", "pull", release["artifact_ref"]])
    digests = json.loads(
        _run(
            [
                "docker",
                "image",
                "inspect",
                image_reference,
                "--format",
                "{{json .RepoDigests}}",
            ]
        )
    )
    expected_digest_ref = f"qazgeo-app@{release['artifact_digest']}"
    if not isinstance(digests, list) or not (
        release["artifact_ref"] in digests or expected_digest_ref in digests
    ):
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


def _static_manifest(directory: Path, release: dict[str, str]) -> tuple[dict[str, str], str]:
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
    root.mkdir(mode=0o755, parents=True, exist_ok=True)
    target = root / release["source_sha"]
    manifest_dir = root.parent / "manifests"
    manifest_path = manifest_dir / f"{release['source_sha']}.json"
    if target.exists():
        if target.is_symlink() or not target.is_dir() or not manifest_path.is_file():
            raise AgentError("QGeo static release already exists without proof")
        try:
            recorded = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            raise AgentError("QGeo static manifest is unreadable") from error
        if not isinstance(recorded, dict):
            raise AgentError("QGeo static manifest shape is invalid")
        expected, digest = _static_manifest(target, release)
        if recorded.get("manifest_digest") != digest or recorded.get("bundle") != expected:
            raise AgentError("QGeo static release proof does not match candidate")
        return {"digest": f"sha256:{digest}", "manifest": str(manifest_path)}

    temporary = Path(tempfile.mkdtemp(prefix=f".{release['source_sha']}.", dir=root))
    container_id = ""
    try:
        container_id = _run(["docker", "create", release["artifact_ref"]]).decode().strip()
        if not container_id:
            raise AgentError("candidate image container could not be created")
        _run(["docker", "cp", f"{container_id}:/app/static/.", str(temporary)])
        bundle, digest = _static_manifest(temporary, release)
        manifest_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
        if manifest_path.exists():
            raise AgentError("QGeo static manifest appeared during materialization")
        temporary.rename(target)
        manifest = {
            "schema": "qdev-qazgeo-static-manifest-v1",
            "bundle": bundle,
            "manifest_digest": digest,
        }
        temporary_manifest: Path | None = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", dir=manifest_dir, prefix=".static-", delete=False
            ) as descriptor:
                temporary_manifest = Path(descriptor.name)
                json.dump(manifest, descriptor, sort_keys=True, separators=(",", ":"))
                descriptor.write("\n")
                descriptor.flush()
                os.fsync(descriptor.fileno())
            assert temporary_manifest is not None
            os.chmod(temporary_manifest, 0o644)
            os.replace(temporary_manifest, manifest_path)
        except Exception:
            if temporary_manifest is not None:
                temporary_manifest.unlink(missing_ok=True)
            raise
        return {"digest": f"sha256:{digest}", "manifest": str(manifest_path)}
    except Exception:
        if temporary.exists():
            for child in sorted(temporary.rglob("*"), reverse=True):
                if child.is_file() or child.is_symlink():
                    child.unlink(missing_ok=True)
                elif child.is_dir():
                    child.rmdir()
            temporary.rmdir()
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


def runtime_proof(profile: Profile, release: dict[str, str]) -> dict[str, str]:
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
        if not isinstance(local_readiness, dict) or not (
            local_readiness.get("ready") is True
            or (profile.project == "qazgeo" and local_readiness.get("status") == "ok")
        ):
            raise AgentError("local startup readiness is not truthful")
        readiness["migration"] = "startup-readiness-verified"
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
    if profile.project == "qazgeo":
        dependency_values = {
            "db": local.get("db_connected"),
            "postgis": local.get("postgis"),
            "martin": local.get("martin_tiles"),
            "photon": local.get("photon_geocoder"),
        }
        if any(value is not True for value in dependency_values.values()):
            raise AgentError("QGeo local dependency readiness is not truthful")
        redis_state = (
            _run(
                [
                    "docker",
                    "inspect",
                    "qazgeo_redis",
                    "--format",
                    "{{.State.Health.Status}}",
                ]
            )
            .decode()
            .strip()
        )
        if redis_state != "healthy":
            raise AgentError("QGeo Redis readiness is not truthful")
        readiness.update({key: "ok" for key in dependency_values})
        readiness["redis"] = "ok"
    readiness["public"] = "ok"
    return readiness


def complete(
    config: Config,
    profile: Profile,
    release_id: str,
    release: dict[str, str],
    rollback: dict[str, str],
    readiness: dict[str, str],
) -> None:
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
    status, _ = request(
        config,
        "POST",
        f"/internal/v1/release-hosts/{profile.placement}/jobs/{release_id}/complete"
        f"?release_lane={profile.lane}",
        receipt,
    )
    if status != 200:
        raise AgentError("controller rejected verified runtime receipt")


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
        release_id, release = validate_job(json.loads(body), profile)
        try:
            verify_image(release, profile)
            materialize_static(release, profile)
            _compose(profile, release)
            readiness = runtime_proof(profile, release)
            complete(config, profile, release_id, release, active, readiness)
        except AgentError:
            _compose(profile, active)
            runtime_proof(profile, active)
            raise
        write_state(config.state_path, release, active)
        return {"status": "verified", "release_id": release_id, **release}


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
    except (AgentError, json.JSONDecodeError) as error:
        print(
            json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True), file=sys.stderr
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
