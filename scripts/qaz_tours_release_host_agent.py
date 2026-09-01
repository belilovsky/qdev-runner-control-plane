#!/usr/bin/env python3
"""One-shot, mTLS-enrolled host agent for the Qaz.Tours release lane.

The agent is deliberately narrow: it accepts a controller job only for the
fixed Qaz.Tours registry namespace, starts an immutable digest through the
existing Compose definition, and proves both the container and public health
before it advances the locally verified rollback pointer.  It never builds,
copies, deletes, prunes, or reads application/provider secret values.
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

PLACEMENT = "vps-hostinger-186"
LANE = "qdev-release-qaz-tours"
PROJECT = "qaz-tours"
STATE_SCHEMA = "qdev-release-host-state-v1"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


class AgentError(RuntimeError):
    """A host proof is unavailable or unsafe to act upon."""


@dataclass(frozen=True)
class Config:
    controller_url: str
    client_cert: Path
    client_key: Path
    controller_ca: Path
    state_path: Path
    lock_path: Path
    compose_file: Path
    runtime_env: Path


def _root_owned_private(path: Path, *, required: bool = True) -> None:
    try:
        metadata = path.stat()
    except FileNotFoundError as error:
        if required:
            raise AgentError(f"required file is missing: {path}") from error
        return
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AgentError(f"file must be root-owned and private: {path}")


def _read_env(path: Path) -> dict[str, str]:
    _root_owned_private(path)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key):
            raise AgentError("host-agent configuration has an invalid line")
        if not value or "\x00" in value:
            raise AgentError("host-agent configuration has an empty value")
        values[key] = value
    return values


def load_config(path: Path) -> Config:
    values = _read_env(path)
    expected = {
        "QDEV_RELEASE_CONTROLLER_URL",
        "QDEV_RELEASE_AGENT_CERT",
        "QDEV_RELEASE_AGENT_KEY",
        "QDEV_RELEASE_CONTROLLER_CA",
        "QDEV_RELEASE_STATE_PATH",
        "QDEV_RELEASE_LOCK_PATH",
        "QAZ_TOURS_COMPOSE_FILE",
        "QAZ_TOURS_RUNTIME_ENV",
    }
    if set(values) != expected:
        raise AgentError("host-agent configuration keys are invalid")
    parsed = urlsplit(values["QDEV_RELEASE_CONTROLLER_URL"])
    if (
        parsed.scheme != "https"
        or parsed.hostname != "worker.ci.qdev.run"
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise AgentError("controller URL must be the fixed HTTPS mTLS edge")
    config = Config(
        controller_url=values["QDEV_RELEASE_CONTROLLER_URL"].rstrip("/"),
        client_cert=Path(values["QDEV_RELEASE_AGENT_CERT"]),
        client_key=Path(values["QDEV_RELEASE_AGENT_KEY"]),
        controller_ca=Path(values["QDEV_RELEASE_CONTROLLER_CA"]),
        state_path=Path(values["QDEV_RELEASE_STATE_PATH"]),
        lock_path=Path(values["QDEV_RELEASE_LOCK_PATH"]),
        compose_file=Path(values["QAZ_TOURS_COMPOSE_FILE"]),
        runtime_env=Path(values["QAZ_TOURS_RUNTIME_ENV"]),
    )
    for credential in (config.client_cert, config.client_key, config.controller_ca):
        _root_owned_private(credential)
    _root_owned_private(config.runtime_env)
    if config.compose_file != Path("/opt/qaz-tours/current/ops/vps/docker-compose.yml"):
        raise AgentError("host-agent compose path is not the canonical release path")
    if not config.compose_file.is_file():
        raise AgentError("canonical compose file is unavailable")
    return config


def _release(value: object) -> dict[str, str]:
    fields = {"source_sha", "artifact_digest", "artifact_ref"}
    if not isinstance(value, dict) or set(value) != fields:
        raise AgentError("release state shape is invalid")
    source_sha = value.get("source_sha")
    digest = value.get("artifact_digest")
    artifact_ref = value.get("artifact_ref")
    if not isinstance(source_sha, str) or not _SHA.fullmatch(source_sha):
        raise AgentError("release source SHA is invalid")
    if not isinstance(digest, str) or not _DIGEST.fullmatch(digest):
        raise AgentError("release artifact digest is invalid")
    if artifact_ref != f"registry.ci.qdev.run/qaz-tours@{digest}":
        raise AgentError("release artifact reference is invalid")
    return {"source_sha": source_sha, "artifact_digest": digest, "artifact_ref": artifact_ref}


def read_state(path: Path) -> tuple[dict[str, str], dict[str, str]]:
    _root_owned_private(path)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise AgentError("host-agent state is not JSON") from error
    if not isinstance(document, dict) or set(document) != {"schema", "active_release", "rollback"}:
        raise AgentError("host-agent state shape is invalid")
    if document.get("schema") != STATE_SCHEMA:
        raise AgentError("host-agent state schema is invalid")
    active = _release(document.get("active_release"))
    rollback_raw = document.get("rollback")
    if not isinstance(rollback_raw, dict) or set(rollback_raw) != {
        "verified",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
    }:
        raise AgentError("host-agent rollback state is invalid")
    if rollback_raw.get("verified") is not True:
        raise AgentError("host-agent rollback has not been verified")
    rollback = _release(
        {
            "source_sha": rollback_raw.get("source_sha"),
            "artifact_digest": rollback_raw.get("artifact_digest"),
            "artifact_ref": rollback_raw.get("artifact_ref"),
        }
    )
    if active == rollback:
        raise AgentError("host-agent rollback must be distinct")
    return active, rollback


def write_state(path: Path, *, active: dict[str, str], rollback: dict[str, str]) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=".qaz-tours-state.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
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


def free_gib(path: Path = Path("/")) -> float:
    filesystem = os.statvfs(path)
    return filesystem.f_bavail * filesystem.f_frsize / 1024**3


def heartbeat(active: dict[str, str], rollback: dict[str, str]) -> dict[str, Any]:
    return {
        "schema": "qdev-release-host-agent-heartbeat-v1",
        "release_lane": LANE,
        "project_id": PROJECT,
        "placement": PLACEMENT,
        "state": "ready",
        "release_lock": "available",
        "capacity_free_gib": round(free_gib(), 3),
        "active_release": active,
        "rollback": {"verified": True, **rollback},
    }


def _run(command: list[str], *, input_bytes: bytes | None = None) -> bytes:
    result = subprocess.run(command, input=input_bytes, capture_output=True, check=False)
    if result.returncode:
        raise AgentError(f"command failed: {command[0]}")
    return result.stdout


def controller_request(
    config: Config,
    method: str,
    path: str,
    payload: dict[str, Any] | None = None,
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
        "\\n%{http_code}",
        f"{config.controller_url}{path}",
    ]
    if payload is not None:
        command[2:2] = ["--header", "content-type: application/json", "--data-binary", "@-"]
        body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    else:
        body = None
    output = _run(command, input_bytes=body)
    body, _, raw_status = output.rpartition(b"\n")
    try:
        status = int(raw_status)
    except ValueError as error:
        raise AgentError("controller response did not expose an HTTP status") from error
    return status, body


def validate_job(document: object) -> tuple[str, dict[str, str]]:
    fields = {
        "schema",
        "release_id",
        "release_lane",
        "project_id",
        "placement",
        "source_sha",
        "artifact_digest",
        "artifact_ref",
    }
    if not isinstance(document, dict) or set(document) != fields:
        raise AgentError("controller release job shape is invalid")
    if (
        document.get("schema") != "qdev-release-host-agent-job-v1"
        or document.get("release_lane") != LANE
        or document.get("project_id") != PROJECT
        or document.get("placement") != PLACEMENT
    ):
        raise AgentError("controller release job identity is invalid")
    release_id = document.get("release_id")
    if not isinstance(release_id, str) or not release_id:
        raise AgentError("controller release job id is invalid")
    release = {key: document.get(key) for key in ("source_sha", "artifact_digest", "artifact_ref")}
    return release_id, _release(release)


def verify_image(release: dict[str, str]) -> None:
    _run(["docker", "pull", release["artifact_ref"]])
    digest_output = _run(
        [
            "docker",
            "image",
            "inspect",
            release["artifact_ref"],
            "--format",
            "{{json .RepoDigests}}",
        ]
    )
    try:
        repo_digests = json.loads(digest_output)
    except json.JSONDecodeError as error:
        raise AgentError("pulled image digest cannot be verified") from error
    if not isinstance(repo_digests, list) or release["artifact_ref"] not in repo_digests:
        raise AgentError("pulled image does not retain the requested immutable reference")
    label = _run(
        [
            "docker",
            "image",
            "inspect",
            release["artifact_ref"],
            "--format",
            "{{ index .Config.Labels \"org.opencontainers.image.revision\" }}",
        ]
    ).decode().strip()
    if label != release["source_sha"]:
        raise AgentError("OCI image source revision does not match controller job")


def promote(config: Config, release: dict[str, str]) -> None:
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", prefix="qaz-tours-release-", delete=False
    ) as stream:
        temporary_env = Path(stream.name)
        os.fchmod(stream.fileno(), 0o600)
        stream.write(f"QAZ_TOURS_IMAGE={release['artifact_ref']}\nSOURCE_REVISION={release['source_sha']}\n")
    try:
        _run(
            [
                "docker",
                "compose",
                "--project-name",
                "qaztours",
                "--env-file",
                str(temporary_env),
                "-f",
                str(config.compose_file),
                "up",
                "-d",
                "--force-recreate",
                "--no-build",
                "--pull",
                "never",
                "app",
            ]
        )
    finally:
        temporary_env.unlink(missing_ok=True)


def runtime_proof(release: dict[str, str]) -> dict[str, str]:
    local_probe = (
        "Promise.all(['live',''].map(async suffix=>{"
        "const r=await fetch('http://127.0.0.1:3000/api/health/'+suffix);"
        "if(!r.ok)throw Error('health');return r.json()}))"
        ".then(x=>process.stdout.write(JSON.stringify(x)))"
        ".catch(()=>process.exit(1))"
    )
    local = _run([
        "docker", "exec", "qaz-tours-app", "node", "-e",
        local_probe,
    ])
    try:
        live, readiness = json.loads(local)
    except (ValueError, json.JSONDecodeError) as error:
        raise AgentError("container health response is invalid") from error
    if (
        live.get("status") != "ok"
        or live.get("probe") != "liveness"
        or live.get("revision") != release["source_sha"]
    ):
        raise AgentError("container liveness does not match release")
    qazgeo = readiness.get("dependencies", {}).get("qazgeo", {}).get("status")
    if readiness.get("status") != "ok" or qazgeo not in {"ok", "degraded"}:
        raise AgentError("container readiness is not truthful")
    public = _run(
        [
            "curl",
            "--fail",
            "--silent",
            "--show-error",
            "--connect-timeout",
            "10",
            "--max-time",
            "30",
            "https://qaz.tours/api/health/live",
        ]
    )
    try:
        public_health = json.loads(public)
    except json.JSONDecodeError as error:
        raise AgentError("public liveness response is invalid") from error
    if (
        public_health.get("status") != "ok"
        or public_health.get("revision") != release["source_sha"]
    ):
        raise AgentError("public liveness does not match promoted release")
    return {"qazgeo": str(qazgeo)}


def complete(
    config: Config,
    release_id: str,
    release: dict[str, str],
    rollback: dict[str, str],
    readiness: dict[str, str],
) -> None:
    receipt = {
        "schema": "qdev-controller-release-runtime-receipt-v1",
        "status": "verified",
        "project": PROJECT,
        "release_lane": LANE,
        "placement": PLACEMENT,
        **release,
        "health": "ok",
        "readiness": readiness,
        "rollback": {"verified": True, **rollback},
    }
    status, _body = controller_request(
        config,
        "POST",
        f"/internal/v1/release-hosts/{PLACEMENT}/jobs/{release_id}/complete",
        receipt,
    )
    if status != 200:
        raise AgentError("controller rejected verified runtime receipt")


def run_once(config: Config) -> dict[str, Any]:
    config.lock_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    _root_owned_private(config.lock_path, required=False)
    with config.lock_path.open("a+", encoding="utf-8") as lock:
        os.chmod(config.lock_path, 0o600)
        try:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AgentError("release lock is already held") from error
        active, rollback = read_state(config.state_path)
        payload = heartbeat(active, rollback)
        if payload["capacity_free_gib"] < 60:
            raise AgentError("release capacity is below 60 GiB; no cleanup was attempted")
        status, _body = controller_request(
            config,
            "POST",
            f"/internal/v1/release-hosts/{PLACEMENT}/heartbeat",
            payload,
        )
        if status != 200:
            raise AgentError("controller rejected host-agent heartbeat")
        status, body = controller_request(
            config, "GET", f"/internal/v1/release-hosts/{PLACEMENT}/jobs/next"
        )
        if status == 204:
            return {"status": "idle", "capacity_free_gib": payload["capacity_free_gib"]}
        if status != 200:
            raise AgentError("controller job poll was rejected")
        try:
            release_id, release = validate_job(json.loads(body))
        except json.JSONDecodeError as error:
            raise AgentError("controller release job is not JSON") from error
        try:
            verify_image(release)
            promote(config, release)
            readiness = runtime_proof(release)
            complete(config, release_id, release, active, readiness)
        except AgentError:
            # The previously verified image is retained and explicitly restored;
            # no cache/image/release deletion is ever used as recovery.
            promote(config, active)
            runtime_proof(active)
            raise
        write_state(config.state_path, active=release, rollback=active)
        return {
            "status": "verified",
            "release_id": release_id,
            **release,
            "qazgeo": readiness["qazgeo"],
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--config",
        type=Path,
        default=Path("/etc/qdev-release-agents/qaz-tours.env"),
    )
    parser.add_argument("--once", action="store_true", required=True)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("qaz-tours release host agent must run as root")
    try:
        result = run_once(load_config(arguments.config))
    except AgentError as error:
        print(
            json.dumps({"status": "blocked", "reason": str(error)}, sort_keys=True),
            file=sys.stderr,
        )
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
