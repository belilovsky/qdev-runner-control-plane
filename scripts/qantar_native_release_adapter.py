#!/usr/bin/env python3
"""Fixed QDev release dispatcher for Qantar's transactional production runtime."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from contextlib import suppress
from pathlib import Path, PurePosixPath
from typing import Any

import httpx

PROJECT_ID = "qantar"
ADAPTER = "qantar-transactional-release-v1"
IMAGE_PREFIX = "registry.ci.qdev.run/qantar"
ROOT = Path("/opt/qantar")
PUBLIC_URL = "https://q22.qdev.run"
DOCKER = Path("/usr/bin/docker")
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PROVENANCE_FIELDS = {
    "candidate_receipt_sha256",
    "bundle_manifest_sha256",
    "source_archive_sha256",
    "image_receipt_sha256",
    "image_sbom_sha256",
    "application_image_id",
}
BUNDLE_FILES = {
    "source.tar.gz": 2 * 1024**3,
    "image.tar.gz": 8 * 1024**3,
    "image-receipt.json": 8 * 1024**2,
    "image-sbom.cdx.json": 64 * 1024**2,
}


class AdapterError(RuntimeError):
    """Raised when an immutable candidate or measured runtime is invalid."""


def _run(arguments: list[str], *, timeout: int = 300, env: dict[str, str] | None = None) -> str:
    try:
        result = subprocess.run(
            arguments,
            check=True,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env
            or {
                "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                "LC_ALL": "C",
                "PYTHONNOUSERSITE": "1",
            },
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise AdapterError("fixed_release_command_failed:" + Path(arguments[0]).name) from error
    return result.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _canonical_sha256(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def _read_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdapterError("runtime_receipt_invalid") from error
    if not isinstance(value, dict):
        raise AdapterError("runtime_receipt_invalid")
    return value


def _write_private_json(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink() or not path.parent.is_dir():
        raise AdapterError("runtime_state_path_invalid")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        payload = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            os.fchmod(handle.fileno(), 0o600)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)


def _docker_image(reference: str) -> dict[str, Any]:
    try:
        value = json.loads(_run([str(DOCKER), "image", "inspect", reference], timeout=120))
    except json.JSONDecodeError as error:
        raise AdapterError("docker_image_identity_invalid") from error
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise AdapterError("docker_image_identity_invalid")
    return value[0]


def _http_json(path: str, *, allow_not_ready: bool = False) -> tuple[int, dict[str, Any]]:
    try:
        with httpx.stream(
            "GET",
            f"{PUBLIC_URL}{path}",
            headers={"Accept": "application/json", "User-Agent": "qantar-qdev-release/1"},
            timeout=20,
            follow_redirects=False,
        ) as response:
            status = response.status_code
            content_type = response.headers.get("content-type", "")
            media_type = content_type.split(";", maxsplit=1)[0].strip().lower()
            if media_type != "application/json" and not media_type.endswith("+json"):
                raise AdapterError("public_runtime_content_type_invalid")
            body = bytearray()
            for chunk in response.iter_bytes():
                if len(body) + len(chunk) > 2 * 1024 * 1024:
                    raise AdapterError("public_runtime_payload_too_large")
                body.extend(chunk)
    except httpx.HTTPError as error:
        raise AdapterError("public_runtime_unreachable") from error
    try:
        payload = json.loads(body)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise AdapterError("public_runtime_identity_invalid") from error
    if not isinstance(payload, dict):
        raise AdapterError("public_runtime_identity_invalid")
    if status != 200 and not (allow_not_ready and status == 503):
        raise AdapterError("public_runtime_http_status_invalid")
    return status, payload


def _release_tuple(source_sha: str, artifact_digest: str, artifact_ref: str) -> dict[str, str]:
    if (
        not SHA.fullmatch(source_sha)
        or not DIGEST.fullmatch(artifact_digest)
        or artifact_ref != f"{IMAGE_PREFIX}@{artifact_digest}"
    ):
        raise AdapterError("release_tuple_invalid")
    return {
        "source_sha": source_sha,
        "artifact_digest": artifact_digest,
        "artifact_ref": artifact_ref,
    }


def _safe_member(name: str) -> tuple[str, ...]:
    path = PurePosixPath(name)
    if path.is_absolute() or not path.parts or any(part in {"", ".", ".."} for part in path.parts):
        raise AdapterError("source_archive_path_invalid")
    return path.parts


def _extract_source(source_archive: Path, destination: Path, expected_sha: str) -> int:
    total_size = 0
    seen: set[str] = set()
    try:
        with tarfile.open(source_archive, "r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > 100_000:
                raise AdapterError("source_archive_member_count_invalid")
            for member in members:
                parts = _safe_member(member.name.rstrip("/"))
                normalized = "/".join(parts)
                if normalized in seen or not (member.isfile() or member.isdir()):
                    raise AdapterError("source_archive_member_invalid")
                seen.add(normalized)
                if member.isfile():
                    total_size += member.size
                    if total_size > 8 * 1024**3:
                        raise AdapterError("source_archive_expansion_too_large")
                    source = archive.extractfile(member)
                    if source is None:
                        raise AdapterError("source_archive_member_unreadable")
                    target = destination.joinpath(*parts)
                    target.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                    with source, target.open("xb") as output:
                        shutil.copyfileobj(source, output)
                    os.chmod(target, 0o755 if member.mode & 0o111 else 0o644)
                else:
                    destination.joinpath(*parts).mkdir(mode=0o755, parents=True, exist_ok=True)
    except (OSError, tarfile.TarError) as error:
        raise AdapterError("source_archive_invalid") from error
    commit_path = destination / "RELEASE_COMMIT"
    ancestors_path = destination / "RELEASE_ANCESTORS"
    if (
        not commit_path.is_file()
        or commit_path.read_text(encoding="ascii").strip() != expected_sha
        or not ancestors_path.is_file()
        or expected_sha not in ancestors_path.read_text(encoding="ascii").splitlines()
        or not (destination / "scripts" / "deploy.sh").is_file()
        or not (destination / "scripts" / "rollback.sh").is_file()
    ):
        raise AdapterError("source_archive_commit_identity_invalid")
    return total_size


def _source_expanded_size(source_archive: Path) -> int:
    try:
        with tarfile.open(source_archive, "r:gz") as archive:
            members = archive.getmembers()
    except (OSError, tarfile.TarError) as error:
        raise AdapterError("source_archive_invalid") from error
    if not members or len(members) > 100_000:
        raise AdapterError("source_archive_member_count_invalid")
    total = 0
    for member in members:
        _safe_member(member.name.rstrip("/"))
        if not (member.isfile() or member.isdir()):
            raise AdapterError("source_archive_member_invalid")
        if member.isfile():
            total += member.size
            if total > 8 * 1024**3:
                raise AdapterError("source_archive_expansion_too_large")
    return total


def _bundle_manifest(
    directory: Path, source_sha: str
) -> tuple[dict[str, Any], str, dict[str, Path]]:
    manifest_path = directory / "bundle-manifest.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise AdapterError("release_bundle_manifest_invalid")
    manifest = _read_json(manifest_path)
    if (
        set(manifest)
        != {
            "schema_version",
            "source_sha",
            "application_image_id",
            "files",
            "capacity",
        }
        or manifest.get("schema_version") != "qantar-qdev-release-bundle-v1"
        or manifest.get("source_sha") != source_sha
        or not isinstance(manifest.get("application_image_id"), str)
        or not DIGEST.fullmatch(manifest["application_image_id"])
        or not isinstance(manifest.get("files"), dict)
        or set(manifest["files"]) != set(BUNDLE_FILES)
        or not isinstance(manifest.get("capacity"), dict)
        or set(manifest["capacity"])
        != {
            "expanded_release_bytes",
            "bundle_payload_bytes",
            "application_image_size_bytes",
        }
        or any(
            isinstance(value, bool) or not isinstance(value, int) or value < 1
            for value in manifest["capacity"].values()
        )
    ):
        raise AdapterError("release_bundle_manifest_invalid")
    paths: dict[str, Path] = {}
    for name, maximum in BUNDLE_FILES.items():
        path = directory / name
        evidence = manifest["files"].get(name)
        if (
            path.is_symlink()
            or not path.is_file()
            or path.stat().st_size < 1
            or path.stat().st_size > maximum
            or not isinstance(evidence, dict)
            or set(evidence) != {"sha256", "size_bytes"}
            or evidence.get("size_bytes") != path.stat().st_size
            or not isinstance(evidence.get("sha256"), str)
            or not HEX64.fullmatch(evidence["sha256"])
            or _sha256(path) != evidence["sha256"]
        ):
            raise AdapterError("release_bundle_file_invalid")
        paths[name] = path
    actual_payload_bytes = (
        sum(path.stat().st_size for path in paths.values()) + manifest_path.stat().st_size
    )
    if manifest["capacity"]["bundle_payload_bytes"] != actual_payload_bytes:
        raise AdapterError("release_bundle_capacity_manifest_mismatch")
    return manifest, _sha256(manifest_path), paths


def _copy_candidate(image_ref: str, destination: Path) -> tuple[Path, int]:
    _run([str(DOCKER), "pull", image_ref], timeout=900)
    image = _docker_image(image_ref)
    repo_digests = image.get("RepoDigests")
    if not isinstance(repo_digests, list) or image_ref not in repo_digests:
        raise AdapterError("release_bundle_registry_digest_mismatch")
    image_size = image.get("Size")
    if isinstance(image_size, bool) or not isinstance(image_size, int) or image_size < 1:
        raise AdapterError("release_bundle_image_size_invalid")
    container_id = _run([str(DOCKER), "create", image_ref], timeout=120)
    try:
        _run(
            [str(DOCKER), "cp", f"{container_id}:/qantar/.", str(destination)],
            timeout=120,
        )
    finally:
        with suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                [str(DOCKER), "rm", "-f", container_id],
                check=False,
                capture_output=True,
                timeout=60,
            )
    return destination, image_size


def _verify_image_receipt(
    release_dir: Path, paths: dict[str, Path], source_sha: str, image_id: str
) -> dict[str, Any]:
    output = _run(
        [
            sys.executable,
            str(release_dir / "scripts" / "verify_image_release_receipt.py"),
            "--receipt",
            str(paths["image-receipt.json"]),
            "--image-archive",
            str(paths["image.tar.gz"]),
            "--sbom",
            str(paths["image-sbom.cdx.json"]),
            "--source-sha",
            source_sha,
        ],
        timeout=120,
    )
    try:
        receipt = json.loads(output)
    except json.JSONDecodeError as error:
        raise AdapterError("image_receipt_verification_invalid") from error
    if not isinstance(receipt, dict) or receipt.get("image_id") != image_id:
        raise AdapterError("image_receipt_image_id_mismatch")
    return receipt


def _capacity_receipt(
    trusted_release_dir: Path,
    *,
    source_sha: str,
    expanded_release_bytes: int,
    application_image_size_bytes: int,
    bundle_image_size_bytes: int,
    bundle_payload_bytes: int,
) -> Path:
    stats = os.statvfs(ROOT)
    total = stats.f_blocks * stats.f_frsize
    free = stats.f_bavail * stats.f_frsize
    used = total - free
    database_bytes = 0
    running = _run(
        [str(DOCKER), "inspect", "qantar_db", "--format", "{{.State.Running}}"],
        timeout=30,
    )
    if running != "true":
        raise AdapterError("database_not_running_for_capacity_measurement")
    value = _run(
        [
            str(DOCKER),
            "exec",
            "qantar_db",
            "sh",
            "-c",
            (
                'PGPASSWORD="$POSTGRES_PASSWORD" psql -U "$POSTGRES_USER" '
                '-d "$POSTGRES_DB" -Atc "SELECT pg_database_size(current_database())"'
            ),
        ],
        timeout=60,
    )
    if not value.isdigit():
        raise AdapterError("database_size_measurement_invalid")
    database_bytes = int(value)
    backups = ROOT / "shared" / "backups"
    latest_backup = max(
        (
            item.stat().st_size
            for item in backups.glob("*.dump")
            if item.is_file() and not item.is_symlink()
        ),
        default=0,
    )
    backup_bytes = max(database_bytes, latest_backup)
    scratch = max(database_bytes // 5, 512 * 1024**2)
    checker = trusted_release_dir / "scripts" / "check_release_capacity.py"
    if checker.is_symlink() or not checker.is_file():
        raise AdapterError("trusted_release_capacity_checker_unavailable")
    target_dir = Path(tempfile.mkdtemp(prefix=".qantar-capacity-", dir=ROOT / "incoming"))
    target = target_dir / "capacity.json"
    arguments = [
        sys.executable,
        str(checker),
        "--source-sha",
        source_sha,
        "--total-bytes",
        str(total),
        "--used-bytes",
        str(used),
        "--free-bytes",
        str(free),
        "--source-archive-bytes",
        "0",
        "--expanded-release-bytes",
        str(expanded_release_bytes),
        "--image-archive-bytes",
        "0",
        "--new-image-bytes",
        str(application_image_size_bytes),
        "--backup-bytes",
        str(backup_bytes),
        "--media-delta-bytes",
        "0",
        "--input-bundle-bytes",
        str(bundle_image_size_bytes + bundle_payload_bytes),
        "--migration-scratch-bytes",
        str(scratch),
        "--measurement-source",
        "qantar-host:/opt/qantar",
        "--receipt-output",
        str(target),
    ]
    try:
        _run(arguments, timeout=120)
    except Exception:
        shutil.rmtree(target_dir, ignore_errors=True)
        raise
    return target


def _runtime_probe(
    source_sha: str, *, allow_prelaunch: bool
) -> tuple[dict[str, str], dict[str, str]]:
    health_status, health = _http_json("/health")
    release_status, release = _http_json("/release.json")
    if (
        health_status != 200
        or health.get("status") != "ok"
        or release_status != 200
        or release.get("source_sha") != source_sha
    ):
        raise AdapterError("public_release_identity_mismatch")
    ready_status, ready = _http_json("/ready", allow_not_ready=True)
    if (
        ready_status == 200
        and ready.get("status") == "ready"
        and ready.get("release_sha") == source_sha
    ):
        content_state = "ready"
    elif (
        allow_prelaunch
        and ready_status == 503
        and ready.get("status") == "not_ready"
        and ready.get("release_sha") == source_sha
        and ready.get("reason") == "published_content_manifest_required"
    ):
        content_state = "prelaunch_content_required"
    else:
        raise AdapterError("public_readiness_contract_failed")
    return {"public_release": "ok", "public_health": "ok"}, {
        "content_readiness": content_state,
        "content_readiness_reason": str(ready.get("reason") or "ready"),
    }


def _bootstrap_state() -> dict[str, Any]:
    """Measure the existing runtime and publish its exact image as a rollback anchor."""
    runtime = _read_json(ROOT / "runtime" / "active-release.json")
    current = ROOT / "runtime" / "current"
    if (
        runtime.get("schema") != "qantar-active-release-v1"
        or not current.is_symlink()
        or current.resolve().parent != (ROOT / "releases").resolve()
    ):
        raise AdapterError("existing_runtime_cannot_be_enrolled")
    source_sha = str(runtime.get("source_sha") or "")
    if not SHA.fullmatch(source_sha):
        raise AdapterError("existing_runtime_source_mismatch")
    release_sha = (current.resolve() / "RELEASE_COMMIT").read_text(encoding="ascii").strip()
    if release_sha != source_sha:
        raise AdapterError("existing_runtime_source_mismatch")
    image_id = str(runtime.get("image_id") or "")
    if not DIGEST.fullmatch(image_id):
        raise AdapterError("existing_runtime_image_identity_missing")
    container = _run([str(DOCKER), "inspect", "qantar_app", "--format", "{{.Image}}"], timeout=30)
    if container != image_id or _docker_image(image_id).get("Id") != image_id:
        raise AdapterError("existing_runtime_image_mismatch")
    _, readiness = _runtime_probe(source_sha, allow_prelaunch=True)
    receipt_path = ROOT / "runtime" / "release-evidence" / source_sha / "image.json"
    sbom_path = ROOT / "runtime" / "release-evidence" / source_sha / "image-sbom.cdx.json"
    if (
        receipt_path.is_symlink()
        or sbom_path.is_symlink()
        or not receipt_path.is_file()
        or not sbom_path.is_file()
    ):
        raise AdapterError("existing_runtime_image_evidence_missing")
    receipt = _read_json(receipt_path)
    if (
        receipt.get("source_sha") != source_sha
        or receipt.get("image_id") != image_id
        or receipt.get("image_reference") != f"qantar-app:{source_sha}"
    ):
        raise AdapterError("existing_runtime_image_evidence_mismatch")
    transport_tag = f"{IMAGE_PREFIX}:bootstrap-{source_sha}"
    _run([str(DOCKER), "tag", image_id, transport_tag], timeout=60)
    _run([str(DOCKER), "push", transport_tag], timeout=900)
    pushed = _docker_image(transport_tag)
    matching = sorted(
        item
        for item in pushed.get("RepoDigests", [])
        if isinstance(item, str) and item.startswith(f"{IMAGE_PREFIX}@sha256:")
    )
    if len(matching) != 1:
        raise AdapterError("bootstrap_registry_digest_unavailable")
    artifact_ref = matching[0]
    artifact_digest = artifact_ref.removeprefix(f"{IMAGE_PREFIX}@")
    provenance = {
        "legacy_runtime_receipt_sha256": _canonical_sha256(
            {
                "active_release": runtime,
                "source_sha": source_sha,
                "image_id": image_id,
                "artifact_ref": artifact_ref,
                "image_receipt_sha256": _sha256(receipt_path),
                "image_sbom_sha256": _sha256(sbom_path),
            }
        )
    }
    state = {
        "schema": "qantar-qdev-release-state-v1",
        "release": _release_tuple(source_sha, artifact_digest, artifact_ref),
        "artifact_provenance": provenance,
        "application_image_id": image_id,
        "image_receipt_sha256": _sha256(receipt_path),
        "image_sbom_sha256": _sha256(sbom_path),
        "content_readiness": readiness["content_readiness"],
        "content_readiness_reason": readiness["content_readiness_reason"],
    }
    state_root = ROOT / "runtime" / "qdev-release-state"
    state_root.mkdir(mode=0o700, exist_ok=True)
    os.chmod(state_root, 0o700)
    _write_private_json(state_root / f"{source_sha}.json", state)
    _write_private_json(ROOT / "runtime" / "qdev-release-state.json", state)
    return state


def _read_state(source_sha: str | None = None) -> dict[str, Any]:
    state_root = ROOT / "runtime" / "qdev-release-state"
    current_path = ROOT / "runtime" / "qdev-release-state.json"
    if not current_path.exists():
        return _bootstrap_state()
    current = _read_json(current_path)
    if current.get("schema") != "qantar-qdev-release-state-v1":
        raise AdapterError("runtime_release_state_invalid")
    selected_sha = source_sha or str((current.get("release") or {}).get("source_sha") or "")
    if not SHA.fullmatch(selected_sha):
        raise AdapterError("runtime_release_state_invalid")
    selected_path = state_root / f"{selected_sha}.json"
    state = _read_json(selected_path) if selected_path.is_file() else current
    release = state.get("release")
    if not isinstance(release, dict) or release.get("source_sha") != selected_sha:
        raise AdapterError("runtime_release_state_invalid")
    _release_tuple(
        str(release.get("source_sha")),
        str(release.get("artifact_digest")),
        str(release.get("artifact_ref")),
    )
    return state


def _native_receipt(state: dict[str, Any]) -> dict[str, Any]:
    release = state["release"]
    source_sha = str(release["source_sha"])
    active = _read_json(ROOT / "runtime" / "active-release.json")
    current = ROOT / "runtime" / "current"
    if (
        active.get("schema") != "qantar-active-release-v1"
        or active.get("source_sha") != source_sha
        or not current.is_symlink()
        or (current.resolve() / "RELEASE_COMMIT").read_text(encoding="ascii").strip() != source_sha
    ):
        raise AdapterError("active_release_files_do_not_match")
    actual_image_id = _run(
        [str(DOCKER), "inspect", "qantar_app", "--format", "{{.Image}}"], timeout=30
    )
    expected_image_id = str(state.get("application_image_id") or "")
    if actual_image_id != expected_image_id or active.get("image_id") != expected_image_id:
        raise AdapterError("active_application_image_mismatch")
    dependency_identity = {
        "application_image_id": expected_image_id,
        "database_image": str(
            _run(
                [str(DOCKER), "inspect", "qantar_db", "--format", "{{.Config.Image}}"],
                timeout=30,
            )
        ),
        "release_profile": "qantar-transactional-release-v1",
        "content_readiness": str(state.get("content_readiness") or "unknown"),
        "content_readiness_reason": str(state.get("content_readiness_reason") or "unknown"),
    }
    _, observed_readiness = _runtime_probe(
        source_sha,
        allow_prelaunch=dependency_identity["content_readiness"] == "prelaunch_content_required",
    )
    if (
        observed_readiness["content_readiness"] != dependency_identity["content_readiness"]
        or observed_readiness["content_readiness_reason"]
        != dependency_identity["content_readiness_reason"]
    ):
        raise AdapterError("content_readiness_state_changed")
    return {
        "schema": "qdev-admin-platform-native-receipt-v1",
        "project_id": PROJECT_ID,
        "native_host_adapter": ADAPTER,
        **release,
        "readiness": {"identity": "ok", "native": "ok", "public": "ok"},
        "runtime_identity": {**release, "measured": True},
        "dependency_identity": dependency_identity,
        "artifact_provenance": state["artifact_provenance"],
    }


def _release(arguments: argparse.Namespace) -> None:
    release = _release_tuple(
        arguments.source_sha, arguments.artifact_digest, arguments.artifact_ref
    )
    if not HEX64.fullmatch(arguments.candidate_receipt_sha256):
        raise AdapterError("candidate_receipt_identity_invalid")
    size_evidence = {
        "expanded_release_bytes": arguments.expanded_release_bytes,
        "bundle_payload_bytes": arguments.bundle_payload_bytes,
        "bundle_image_size_bytes": arguments.bundle_image_size_bytes,
        "application_image_size_bytes": arguments.application_image_size_bytes,
    }
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 1
        for value in size_evidence.values()
    ):
        raise AdapterError("candidate_capacity_evidence_invalid")
    incoming = ROOT / "incoming"
    releases = ROOT / "releases"
    if not incoming.is_dir() or not releases.is_dir():
        raise AdapterError("Qantar runtime layout is missing")
    candidate_release = releases / release["source_sha"]
    old_state = _read_state()
    old_release = dict(old_state["release"])
    if (
        old_release == release
        or not SHA.fullmatch(str(old_release.get("source_sha") or ""))
        or not (releases / str(old_release["source_sha"]) / "scripts" / "rollback.sh").is_file()
    ):
        raise AdapterError("rollback_anchor_unavailable")
    temporary_root = Path(
        tempfile.mkdtemp(prefix=f".qdev-release-{release['source_sha']}-", dir=incoming)
    )
    extracted = temporary_root / "bundle"
    extracted.mkdir(mode=0o700)
    staged = temporary_root / "source"
    staged.mkdir(mode=0o700)
    candidate_created = False
    image_ref = release["artifact_ref"]
    try:
        capacity = _capacity_receipt(
            releases / str(old_release["source_sha"]),
            source_sha=release["source_sha"],
            expanded_release_bytes=size_evidence["expanded_release_bytes"],
            application_image_size_bytes=size_evidence["application_image_size_bytes"],
            bundle_image_size_bytes=size_evidence["bundle_image_size_bytes"],
            bundle_payload_bytes=size_evidence["bundle_payload_bytes"],
        )
        bundle, observed_bundle_image_bytes = _copy_candidate(image_ref, extracted)
        if observed_bundle_image_bytes != size_evidence["bundle_image_size_bytes"]:
            raise AdapterError("release_bundle_image_size_mismatch")
        manifest, manifest_sha, paths = _bundle_manifest(bundle, release["source_sha"])
        manifest_capacity = manifest["capacity"]
        if (
            manifest_capacity["expanded_release_bytes"] != size_evidence["expanded_release_bytes"]
            or manifest_capacity["bundle_payload_bytes"] != size_evidence["bundle_payload_bytes"]
            or manifest_capacity["application_image_size_bytes"]
            != size_evidence["application_image_size_bytes"]
        ):
            raise AdapterError("release_bundle_capacity_evidence_mismatch")
        image_id = str(manifest["application_image_id"])
        expanded_release_bytes = _source_expanded_size(paths["source.tar.gz"])
        if expanded_release_bytes != size_evidence["expanded_release_bytes"]:
            raise AdapterError("source_expansion_size_mismatch")
        _extract_source(paths["source.tar.gz"], staged, release["source_sha"])
        receipt = _verify_image_receipt(staged, paths, release["source_sha"], image_id)
        if (
            int(receipt.get("image_size_bytes") or 0)
            != size_evidence["application_image_size_bytes"]
        ):
            raise AdapterError("application_image_size_mismatch")
        source_sha256 = _sha256(paths["source.tar.gz"])
        (staged / "ARTIFACT_SHA256").write_text(source_sha256 + "\n", encoding="ascii")
        os.chmod(staged / "ARTIFACT_SHA256", 0o644)
        if candidate_release.exists() or candidate_release.is_symlink():
            raise AdapterError("candidate_release_directory_already_exists")
        os.rename(staged, candidate_release)
        candidate_created = True
        env = {
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LC_ALL": "C",
            "PYTHONNOUSERSITE": "1",
            "QANTAR_ROOT": str(ROOT),
            "QANTAR_PRELAUNCH_NOINDEX": "true",
            "QANTAR_IMAGE_ARCHIVE": str(paths["image.tar.gz"]),
            "QANTAR_IMAGE_RECEIPT": str(paths["image-receipt.json"]),
            "QANTAR_IMAGE_SBOM": str(paths["image-sbom.cdx.json"]),
            "QANTAR_CAPACITY_RECEIPT": str(capacity),
        }
        _run(
            [str(candidate_release / "scripts" / "deploy.sh"), release["source_sha"]],
            timeout=3600,
            env=env,
        )
        actual_image = _docker_image(f"qantar-app:{release['source_sha']}")
        if actual_image.get("Id") != image_id:
            raise AdapterError("loaded_application_image_mismatch")
        _, observed = _runtime_probe(release["source_sha"], allow_prelaunch=True)
        _run([str(DOCKER), "image", "rm", image_ref], timeout=60)
        provenance = {
            "candidate_receipt_sha256": arguments.candidate_receipt_sha256,
            "bundle_manifest_sha256": manifest_sha,
            "source_archive_sha256": source_sha256,
            "image_receipt_sha256": _sha256(paths["image-receipt.json"]),
            "image_sbom_sha256": _sha256(paths["image-sbom.cdx.json"]),
            "application_image_id": image_id,
        }
        state = {
            "schema": "qantar-qdev-release-state-v1",
            "release": release,
            "artifact_provenance": provenance,
            "application_image_id": image_id,
            "image_receipt_sha256": provenance["image_receipt_sha256"],
            "image_sbom_sha256": provenance["image_sbom_sha256"],
            "content_readiness": observed["content_readiness"],
            "content_readiness_reason": observed["content_readiness_reason"],
        }
        state_root = ROOT / "runtime" / "qdev-release-state"
        state_root.mkdir(mode=0o700, exist_ok=True)
        os.chmod(state_root, 0o700)
        _write_private_json(state_root / f"{release['source_sha']}.json", state)
        _write_private_json(ROOT / "runtime" / "qdev-release-state.json", state)
        _native_receipt(state)
    except Exception as release_error:
        # Qantar's existing rollback script preserves the previous immutable
        # release and database data. Use it only if the candidate reached the
        # active pointer and the product rollback anchor is retained.
        current = ROOT / "runtime" / "current"
        if current.is_symlink() and current.resolve() == candidate_release.resolve():
            previous_sha = str(old_release.get("source_sha") or "")
            if SHA.fullmatch(previous_sha) and (releases / previous_sha).is_dir():
                rollback_env = {
                    "PATH": (
                        ":".join(
                            (
                                "/usr/local/sbin",
                                "/usr/local/bin",
                                "/usr/sbin",
                                "/usr/bin",
                                "/sbin",
                                "/bin",
                            )
                        )
                    ),
                    "LC_ALL": "C",
                    "PYTHONNOUSERSITE": "1",
                    "QANTAR_ROOT": str(ROOT),
                    "QANTAR_ALLOW_ROLLBACK": "true",
                    "QANTAR_ROLLBACK_REASON": ("qdev_release_runtime_verification_failed"),
                    "QANTAR_ROLLBACK_CONFIRM": previous_sha,
                }
                try:
                    _run(
                        [
                            str(releases / previous_sha / "scripts" / "rollback.sh"),
                            previous_sha,
                        ],
                        timeout=900,
                        env=rollback_env,
                    )
                    _write_private_json(ROOT / "runtime" / "qdev-release-state.json", old_state)
                    _native_receipt(old_state)
                    (
                        ROOT / "runtime" / "qdev-release-state" / f"{release['source_sha']}.json"
                    ).unlink(missing_ok=True)
                except Exception as rollback_error:
                    raise AdapterError(
                        "release_verification_failed_and_rollback_failed"
                    ) from rollback_error
            else:
                raise AdapterError(
                    "release_verification_failed_and_rollback_anchor_missing"
                ) from release_error
        if candidate_created and (
            not current.is_symlink() or current.resolve() != candidate_release.resolve()
        ):
            shutil.rmtree(candidate_release, ignore_errors=True)
        raise
    finally:
        with suppress(OSError, subprocess.TimeoutExpired):
            subprocess.run(
                [str(DOCKER), "image", "rm", image_ref],
                check=False,
                capture_output=True,
                timeout=60,
            )
        shutil.rmtree(temporary_root, ignore_errors=True)
        if "capacity" in locals():
            shutil.rmtree(capacity.parent, ignore_errors=True)


def _rollback(arguments: argparse.Namespace) -> None:
    target = _release_tuple(arguments.source_sha, arguments.artifact_digest, arguments.artifact_ref)
    state = _read_state(target["source_sha"])
    if state.get("release") != target:
        raise AdapterError("rollback_release_tuple_not_retained")
    script = ROOT / "releases" / target["source_sha"] / "scripts" / "rollback.sh"
    env = {
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C",
        "PYTHONNOUSERSITE": "1",
        "QANTAR_ROOT": str(ROOT),
        "QANTAR_ALLOW_ROLLBACK": "true",
        "QANTAR_ROLLBACK_REASON": "qdev_controller_rollback",
        "QANTAR_ROLLBACK_CONFIRM": target["source_sha"],
    }
    _run([str(script), target["source_sha"]], timeout=900, env=env)
    _write_private_json(ROOT / "runtime" / "qdev-release-state.json", state)
    _native_receipt(state)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices={"receipt", "release", "rollback"}, required=True)
    parser.add_argument("--current", action="store_true")
    parser.add_argument("--source-sha")
    parser.add_argument("--artifact-digest")
    parser.add_argument("--artifact-ref")
    parser.add_argument("--candidate-receipt-sha256")
    parser.add_argument("--expanded-release-bytes", type=int)
    parser.add_argument("--bundle-payload-bytes", type=int)
    parser.add_argument("--bundle-image-size-bytes", type=int)
    parser.add_argument("--application-image-size-bytes", type=int)
    args = parser.parse_args()
    try:
        if args.action == "release" and any(
            value is None
            for value in (
                args.expanded_release_bytes,
                args.bundle_payload_bytes,
                args.bundle_image_size_bytes,
                args.application_image_size_bytes,
            )
        ):
            raise AdapterError("candidate_capacity_evidence_missing")
        if os.geteuid() != 0 or not ROOT.is_dir() or not DOCKER.is_file():
            raise AdapterError("Qantar production root identity or runtime is unavailable")
        if args.action == "receipt":
            state = _read_state(None if args.current else args.source_sha)
            result = _native_receipt(state)
        elif args.action == "release":
            if (
                not args.source_sha
                or not args.artifact_digest
                or not args.artifact_ref
                or not args.candidate_receipt_sha256
            ):
                raise AdapterError("candidate release identity is incomplete")
            _release(args)
            state = _read_state(args.source_sha)
            result = _native_receipt(state)
        else:
            if not args.source_sha or not args.artifact_digest or not args.artifact_ref:
                raise AdapterError("rollback release identity is incomplete")
            _rollback(args)
            state = _read_state(args.source_sha)
            result = _native_receipt(state)
    except (
        AdapterError,
        OSError,
        ValueError,
        KeyError,
        tarfile.TarError,
        json.JSONDecodeError,
    ) as error:
        print(f"qantar-qdev-release-failed:{error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
