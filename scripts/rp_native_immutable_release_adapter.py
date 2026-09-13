#!/usr/bin/env python3
"""Root-owned immutable release adapter for the private RP reports service.

The controller can supply only a source SHA and an OCI digest produced by the
IPOS reports pipeline.  All paths, host commands, registry scope and runtime
checks below are compiled constants.  The adapter deliberately refuses a first
unmeasured release: a root-owned bootstrap procedure must first create and
prove one immutable RP release, including its restore drill.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from contextlib import suppress
from pathlib import Path
from typing import Any

PROJECT_ID = "rp"
ADAPTER = "rp-native-immutable-release-v1"
RECEIPT_SCHEMA = "qdev-admin-platform-native-receipt-v1"
STATE_SCHEMA = "rp-native-release-state-v1"
IMAGE_PREFIX = "registry.ci.qdev.run/belilovsky/ipos"
CANONICAL_REPOSITORY = "https://github.com/belilovsky/ipos.git"
SOURCE_ROOT = Path("/opt/rp/source")
SOURCE_HISTORY_ROOT = Path("/opt/rp/source-history")
RELEASE_ROOT = Path("/opt/rp/releases")
CURRENT_LINK = Path("/opt/rp/current")
STATE_ROOT = Path("/var/lib/qdev-release-agents/rp-native")
STATE_FILE = STATE_ROOT / "state.json"
LOCK_FILE = Path("/run/lock/rp-native-release.lock")
CANDIDATE_PORT = "3871"
RESERVE_BYTES = 2 * 1024**3
QAZSTACK_VERSION = "1.53.0"
QAZSTACK_SOURCE_SHA = "64e1ba4d65c3e2b5368636fafb0cdb4645c749b6"
_SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_MIGRATION = re.compile(r"^[a-z0-9_]{4,128}$")
_RELEASE_ID = re.compile(r"^rp-[a-z0-9][a-z0-9._-]{6,119}$")


class AdapterError(RuntimeError):
    """An RP release cannot safely be accepted or proven."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def atomic_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    root_directory(path.parent)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, mode)
        if os.geteuid() == 0:
            os.chown(temporary, 0, 0)
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise


def run(command: list[str], *, timeout: int = 900) -> str:
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=_SAFE_ENV,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AdapterError(f"fixed native operation failed: {command[0]}") from error
    return completed.stdout.strip()


def root_directory(path: Path, *, allow_missing: bool = False) -> None:
    if not path.exists() and allow_missing:
        return
    if path.is_symlink() or not path.is_dir():
        raise AdapterError(f"required root directory is unavailable: {path}")
    metadata = path.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AdapterError(f"directory must be root-owned and non-writable: {path}")


def immutable_file(path: Path, *, mode: int | None = None) -> None:
    if path.is_symlink() or not path.is_file():
        raise AdapterError(f"required immutable file is unavailable: {path}")
    metadata = path.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AdapterError(f"file must be root-owned and non-writable: {path}")
    if mode is not None and stat.S_IMODE(metadata.st_mode) != mode:
        raise AdapterError(f"file mode is invalid: {path}")


def sha256_file(path: Path) -> str:
    immutable_file(path)
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ensure_within(path: Path, root: Path) -> Path:
    resolved_root = root.resolve(strict=True)
    resolved = path.resolve(strict=True)
    try:
        resolved.relative_to(resolved_root)
    except ValueError as error:
        raise AdapterError("release path escapes the compiled RP root") from error
    return resolved


def release_tuple(source_sha: str, artifact_digest: str, artifact_ref: str) -> dict[str, str]:
    if (
        not _SHA.fullmatch(source_sha)
        or not _DIGEST.fullmatch(artifact_digest)
        or artifact_ref != f"{IMAGE_PREFIX}@{artifact_digest}"
    ):
        raise AdapterError("release tuple is not a fixed RP immutable artifact")
    return {
        "source_sha": source_sha,
        "artifact_digest": artifact_digest,
        "artifact_ref": artifact_ref,
    }


def manifest_evidence(manifest: object, manifest_sha256: str) -> dict[str, str]:
    if not isinstance(manifest, dict) or set(manifest) < {
        "source_sha",
        "deployment_profile",
        "dependency_lock_sha256",
        "artifact_tree_sha256",
        "migration_revision",
        "method_bundle_digest",
        "project",
        "qazstack",
        "qazstack_source",
        "source_worktree_dirty",
    }:
        raise AdapterError("RP release manifest is incomplete")
    qazstack = manifest.get("qazstack")
    values = {
        "release_manifest_sha256": manifest_sha256,
        "dependency_lock_sha256": manifest.get("dependency_lock_sha256"),
        "artifact_tree_sha256": manifest.get("artifact_tree_sha256"),
        "method_bundle_digest": manifest.get("method_bundle_digest"),
        "migration_revision": manifest.get("migration_revision"),
    }
    if (
        manifest.get("deployment_profile") != "reports-private"
        or manifest.get("source_worktree_dirty") is not False
        or not isinstance(manifest.get("project"), dict)
        or manifest["project"].get("project_id") != PROJECT_ID
        or not _HEX64.fullmatch(str(manifest["project"].get("manifest_sha256", "")))
        or not isinstance(qazstack, dict)
        or qazstack.get("expected_version") != QAZSTACK_VERSION
        or qazstack.get("installed_version") != QAZSTACK_VERSION
        or qazstack.get("status") != "ready"
        or manifest.get("qazstack_source") != QAZSTACK_SOURCE_SHA
        or not _HEX64.fullmatch(manifest_sha256)
        or not _HEX64.fullmatch(str(values["dependency_lock_sha256"]))
        or not _HEX64.fullmatch(str(values["artifact_tree_sha256"]))
        or not _DIGEST.fullmatch(str(values["method_bundle_digest"]))
        or not _MIGRATION.fullmatch(str(values["migration_revision"]))
    ):
        raise AdapterError("RP release manifest does not bind the approved dependency profile")
    return {key: str(value) for key, value in values.items()}


def validate_record(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"release", "evidence"}:
        raise AdapterError("RP native release record is invalid")
    release = value.get("release")
    evidence = value.get("evidence")
    if not isinstance(release, dict) or not isinstance(evidence, dict):
        raise AdapterError("RP native release record is invalid")
    normalized = release_tuple(
        str(release.get("source_sha", "")),
        str(release.get("artifact_digest", "")),
        str(release.get("artifact_ref", "")),
    )
    expected = {
        "release_manifest_sha256",
        "dependency_lock_sha256",
        "artifact_tree_sha256",
        "method_bundle_digest",
        "migration_revision",
    }
    if set(evidence) != expected or (
        not _HEX64.fullmatch(str(evidence.get("release_manifest_sha256", "")))
        or not _HEX64.fullmatch(str(evidence.get("dependency_lock_sha256", "")))
        or not _HEX64.fullmatch(str(evidence.get("artifact_tree_sha256", "")))
        or not _DIGEST.fullmatch(str(evidence.get("method_bundle_digest", "")))
        or not _MIGRATION.fullmatch(str(evidence.get("migration_revision", "")))
    ):
        raise AdapterError("RP native release evidence is invalid")
    return {"release": normalized, "evidence": {key: str(evidence[key]) for key in expected}}


def read_state() -> dict[str, Any]:
    root_directory(STATE_ROOT)
    immutable_file(STATE_FILE, mode=0o600)
    try:
        value = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdapterError("RP native state is unavailable") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "active", "rollback"}
        or value.get("schema") != STATE_SCHEMA
    ):
        raise AdapterError("RP native state is invalid")
    return {
        "schema": STATE_SCHEMA,
        "active": validate_record(value["active"]),
        "rollback": validate_record(value["rollback"]),
    }


def write_state(active: dict[str, Any], rollback: dict[str, Any]) -> None:
    atomic_json(
        STATE_FILE,
        {
            "schema": STATE_SCHEMA,
            "active": validate_record(active),
            "rollback": validate_record(rollback),
        },
    )


def read_deployment_env(path: Path) -> dict[str, str]:
    immutable_file(path, mode=0o600)
    required = {
        "RP_RELEASE_ID",
        "RP_COMPOSE_PROJECT",
        "RP_IMAGE_REF",
        "RP_BIND_PORT",
        "RP_ENV_FILE",
        "RP_DATABASE_ENV_FILE",
        "RP_MIGRATION_ENV_FILE",
        "RP_SOURCE_SHA",
        "RP_LOCK_SHA256",
        "RP_ARTIFACT_TREE_SHA256",
        "RP_RELEASE_MANIFEST_SHA256",
        "RP_MIGRATION_REVISION",
        "RP_PROJECT_ID",
        "RP_PROJECT_MANIFEST_SHA256",
        "RP_METHOD_BUNDLE_DIGEST",
        "RP_CAPACITY_BUDGET",
        "RP_POSTGRES_CONTAINER",
        "RP_PROFILE_ROOT",
        "RP_BACKUP_BUNDLE_SHA256",
    }
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        key, separator, value = line.partition("=")
        if (
            not separator
            or key not in required
            or key in values
            or not value
            or not re.fullmatch(r"[A-Za-z0-9._/@:+=-]+", value)
        ):
            raise AdapterError("RP deployment environment is invalid")
        values[key] = value
    if set(values) != required:
        raise AdapterError("RP deployment environment is incomplete")
    return values


def current_release_directory() -> Path:
    root_directory(RELEASE_ROOT)
    if not CURRENT_LINK.is_symlink():
        raise AdapterError("RP has no immutable current release to measure")
    release = ensure_within(CURRENT_LINK, RELEASE_ROOT)
    root_directory(release)
    return release


def record_from_release_directory(release_dir: Path) -> dict[str, Any]:
    release = ensure_within(release_dir, RELEASE_ROOT)
    environment = read_deployment_env(release / "deployment.env")
    manifest_path = release / "release-manifest.json"
    immutable_file(manifest_path, mode=0o644)
    published_path = release / "published-image.json"
    immutable_file(published_path, mode=0o644)
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        published = json.loads(published_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdapterError("RP release receipt JSON is invalid") from error
    manifest_sha256 = sha256_file(manifest_path)
    source_sha = environment["RP_SOURCE_SHA"]
    image_ref = environment["RP_IMAGE_REF"]
    artifact_digest = image_ref.removeprefix(f"{IMAGE_PREFIX}@")
    normalized = release_tuple(source_sha, artifact_digest, image_ref)
    if (
        environment["RP_PROJECT_ID"] != PROJECT_ID
        or not _RELEASE_ID.fullmatch(environment["RP_RELEASE_ID"])
        or environment["RP_RELEASE_MANIFEST_SHA256"] != manifest_sha256
        or environment["RP_MIGRATION_REVISION"] != manifest.get("migration_revision")
        or manifest.get("source_sha") != source_sha
        or not isinstance(published, dict)
        or published.get("schema_id") != "rp-published-image-v1"
        or published.get("source_sha") != source_sha
        or published.get("image_ref") != image_ref
        or published.get("release_manifest_sha256") != manifest_sha256
    ):
        raise AdapterError("RP immutable release files do not bind one tuple")
    evidence = manifest_evidence(manifest, manifest_sha256)
    return {"release": normalized, "evidence": evidence}


def record_from_current_release() -> dict[str, Any]:
    return record_from_release_directory(current_release_directory())


def docker_json(*arguments: str) -> Any:
    output = run(["/usr/bin/docker", *arguments], timeout=300)
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise AdapterError("Docker returned invalid JSON") from error


def image_inspect(reference: str) -> dict[str, Any]:
    value = docker_json("image", "inspect", reference)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise AdapterError("immutable RP image inspection failed")
    return value[0]


def prove_image(record: dict[str, Any]) -> dict[str, Any]:
    checked = validate_record(record)
    release = checked["release"]
    inspected = image_inspect(release["artifact_ref"])
    labels = (inspected.get("Config") or {}).get("Labels") or {}
    repo_digests = inspected.get("RepoDigests")
    evidence = checked["evidence"]
    expected_labels = {
        "org.opencontainers.image.revision": release["source_sha"],
        "run.qdev.ipos.lock-sha256": evidence["dependency_lock_sha256"],
        "run.qdev.ipos.artifact-tree-sha256": evidence["artifact_tree_sha256"],
        "run.qdev.ipos.release-manifest-sha256": evidence["release_manifest_sha256"],
        "run.qdev.ipos.project-id": PROJECT_ID,
    }
    if (
        not isinstance(repo_digests, list)
        or release["artifact_ref"] not in repo_digests
        or not isinstance(labels, dict)
        or any(labels.get(key) != value for key, value in expected_labels.items())
        or not isinstance(inspected.get("Size"), int)
        or inspected["Size"] <= 0
    ):
        raise AdapterError("OCI image does not prove the RP release tuple")
    return inspected


def prove_runtime(record: dict[str, Any]) -> dict[str, Any]:
    checked = validate_record(record)
    measured = record_from_current_release()
    if measured != checked:
        raise AdapterError("active RP immutable release does not match the retained record")
    release_dir = current_release_directory()
    output = run(
        [
            str(release_dir / "deploy" / "verify-reports-runtime-identity.sh"),
            str(release_dir / "deployment.env"),
        ],
        timeout=300,
    )
    try:
        runtime = json.loads(output)
    except json.JSONDecodeError as error:
        raise AdapterError("RP runtime verifier did not return JSON") from error
    release = checked["release"]
    if (
        not isinstance(runtime, dict)
        or runtime.get("status") != "ready"
        or runtime.get("profile") != "reports-private"
        or runtime.get("source_sha") != release["source_sha"]
        or runtime.get("image_ref") != release["artifact_ref"]
        or runtime.get("release_manifest_sha256") != checked["evidence"]["release_manifest_sha256"]
        or runtime.get("migration_revision") != checked["evidence"]["migration_revision"]
        or runtime.get("protected_readiness") != "unauthenticated_401"
    ):
        raise AdapterError("RP runtime verifier did not bind the active immutable tuple")
    prove_image(checked)
    return receipt(checked)


def receipt(record: dict[str, Any]) -> dict[str, Any]:
    checked = validate_record(record)
    return {
        "schema": RECEIPT_SCHEMA,
        "project_id": PROJECT_ID,
        "native_host_adapter": ADAPTER,
        **checked["release"],
        "readiness": {"identity": "ok", "native": "ok", "public": "ok"},
        "runtime_identity": {**checked["release"], "measured": True},
        "dependency_identity": {
            "deployment_profile": "reports-private",
            "qazstack_version": QAZSTACK_VERSION,
            "qazstack_source_sha": QAZSTACK_SOURCE_SHA,
        },
        "artifact_provenance": checked["evidence"],
    }


def read_image_manifest(
    image_ref: str, expected_source_sha: str, destination: Path
) -> dict[str, Any]:
    run(["/usr/bin/docker", "pull", image_ref], timeout=600)
    container = run(["/usr/bin/docker", "create", image_ref], timeout=120)
    try:
        run(
            ["/usr/bin/docker", "cp", f"{container}:/app/.release-manifest.json", str(destination)],
            timeout=120,
        )
    finally:
        with suppress(AdapterError):
            run(["/usr/bin/docker", "rm", "-f", container], timeout=120)
    os.chown(destination, 0, 0)
    os.chmod(destination, 0o644)
    immutable_file(destination, mode=0o644)
    try:
        manifest = json.loads(destination.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdapterError("RP image manifest is unavailable") from error
    if manifest.get("source_sha") != expected_source_sha:
        raise AdapterError("RP image manifest source does not match the requested SHA")
    manifest_evidence(manifest, sha256_file(destination))
    return manifest


def build_candidate_record(
    source_sha: str, artifact_digest: str, artifact_ref: str, checkout: Path
) -> dict[str, Any]:
    release = release_tuple(source_sha, artifact_digest, artifact_ref)
    artifacts = checkout / "artifacts" / "reports"
    artifacts.mkdir(parents=True, exist_ok=True)
    manifest_path = artifacts / "release-manifest.json"
    manifest = read_image_manifest(artifact_ref, source_sha, manifest_path)
    evidence = manifest_evidence(manifest, sha256_file(manifest_path))
    record = {"release": release, "evidence": evidence}
    prove_image(record)
    atomic_json(
        artifacts / "published-image.json",
        {
            "schema_id": "rp-published-image-v1",
            "source_sha": source_sha,
            "image_ref": artifact_ref,
            "release_manifest_sha256": evidence["release_manifest_sha256"],
        },
        mode=0o644,
    )
    return validate_record(record)


def clone_source(source_sha: str) -> Path:
    root_directory(SOURCE_ROOT)
    root_directory(SOURCE_ROOT.parent)
    temporary = Path(tempfile.mkdtemp(prefix="rp-source-", dir=str(SOURCE_ROOT.parent)))
    try:
        run(
            ["/usr/bin/git", "clone", "--no-checkout", CANONICAL_REPOSITORY, str(temporary)],
            timeout=600,
        )
        run(["/usr/bin/git", "-C", str(temporary), "checkout", "--detach", source_sha], timeout=300)
        if run(["/usr/bin/git", "-C", str(temporary), "rev-parse", "HEAD"]) != source_sha:
            raise AdapterError("canonical RP source checkout did not bind the requested SHA")
        run(["/usr/bin/git", "-C", str(temporary), "diff", "--quiet"])
        run(["/usr/bin/git", "-C", str(temporary), "diff", "--cached", "--quiet"])
        return temporary
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def install_candidate_source(candidate: Path, source_sha: str) -> Path:
    root_directory(SOURCE_ROOT)
    SOURCE_HISTORY_ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    root_directory(SOURCE_HISTORY_ROOT)
    destination = SOURCE_HISTORY_ROOT / f"source-{source_sha}-{int(time.time())}"
    if destination.exists():
        raise AdapterError("RP source history target already exists")
    try:
        os.replace(SOURCE_ROOT, destination)
        os.replace(candidate, SOURCE_ROOT)
    except BaseException:
        if not SOURCE_ROOT.exists() and destination.exists():
            os.replace(destination, SOURCE_ROOT)
        raise
    root_directory(SOURCE_ROOT)
    return destination


def restore_source(previous: Path) -> None:
    root_directory(previous)
    if not SOURCE_ROOT.exists():
        os.replace(previous, SOURCE_ROOT)
        return
    displaced = SOURCE_HISTORY_ROOT / f"failed-source-{int(time.time())}"
    os.replace(SOURCE_ROOT, displaced)
    os.replace(previous, SOURCE_ROOT)
    root_directory(SOURCE_ROOT)


def image_size(record: dict[str, Any]) -> int:
    value = prove_image(record).get("Size")
    if not isinstance(value, int) or value <= 0:
        raise AdapterError("RP image capacity evidence is invalid")
    return value


def ensure_capacity(candidate: dict[str, Any], previous: dict[str, Any]) -> None:
    candidate_size = image_size(candidate)
    rollback_size = image_size(previous)
    free = shutil.disk_usage(SOURCE_ROOT.parent).free
    if candidate_size <= 0 or rollback_size <= 0 or free < RESERVE_BYTES:
        raise AdapterError(
            "measured disk capacity cannot retain the RP tuple and a 2 GiB recovery reserve"
        )


def release_id(record: dict[str, Any]) -> str:
    release = validate_record(record)["release"]
    digest_prefix = release["artifact_digest"].removeprefix("sha256:")[:16]
    value = f"rp-{release['source_sha'][:16]}-{digest_prefix}"
    if not _RELEASE_ID.fullmatch(value):
        raise AdapterError("compiled RP release identifier is invalid")
    return value


def do_release(source_sha: str, artifact_digest: str, artifact_ref: str) -> dict[str, Any]:
    state = read_state()
    previous = validate_record(state["active"])
    prove_runtime(previous)
    checkout = clone_source(source_sha)
    candidate: dict[str, Any] | None = None
    old_source: Path | None = None
    try:
        candidate = build_candidate_record(source_sha, artifact_digest, artifact_ref, checkout)
        ensure_capacity(candidate, previous)
        if candidate["release"] == previous["release"]:
            raise AdapterError("RP candidate is already the active immutable release")
        old_source = install_candidate_source(checkout, source_sha)
        checkout = Path("/")
        run(
            [
                str(SOURCE_ROOT / "deploy" / "deploy-reports-immutable.sh"),
                release_id(candidate),
                artifact_ref,
                CANDIDATE_PORT,
                "standard",
            ],
            timeout=1800,
        )
        proven = prove_runtime(candidate)
        write_state(candidate, previous)
        return proven
    except Exception as error:
        rollback_error: Exception | None = None
        try:
            active = record_from_current_release()
            if candidate is not None and active["release"] == candidate["release"]:
                run(
                    [
                        str(SOURCE_ROOT / "deploy" / "rollback-reports-immutable.sh"),
                        release_id(previous),
                    ],
                    timeout=1800,
                )
                prove_runtime(previous)
        except Exception as nested:
            rollback_error = nested
        if old_source is not None:
            try:
                restore_source(old_source)
            except Exception as nested:
                rollback_error = rollback_error or nested
        if rollback_error is not None:
            raise AdapterError(
                "RP candidate failed and verified rollback did not complete"
            ) from rollback_error
        raise error
    finally:
        if checkout != Path("/"):
            shutil.rmtree(checkout, ignore_errors=True)


def source_for_record(record: dict[str, Any]) -> Path:
    checked = validate_record(record)
    temporary = clone_source(checked["release"]["source_sha"])
    try:
        release_dir = current_release_directory()
        source_artifacts = temporary / "artifacts" / "reports"
        source_artifacts.mkdir(parents=True, exist_ok=True)
        for name in ("release-manifest.json", "published-image.json"):
            copied = release_dir / name
            immutable_file(copied, mode=0o644)
            shutil.copyfile(copied, source_artifacts / name)
            os.chmod(source_artifacts / name, 0o644)
        return temporary
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def do_rollback(source_sha: str, artifact_digest: str, artifact_ref: str) -> dict[str, Any]:
    state = read_state()
    active = validate_record(state["active"])
    target = validate_record(state["rollback"])
    requested = release_tuple(source_sha, artifact_digest, artifact_ref)
    if requested != target["release"]:
        raise AdapterError("controller rollback is not the retained RP immutable tuple")
    prove_runtime(active)
    run(
        [str(SOURCE_ROOT / "deploy" / "rollback-reports-immutable.sh"), release_id(target)],
        timeout=1800,
    )
    prove_runtime(target)
    candidate_source = source_for_record(target)
    try:
        install_candidate_source(candidate_source, target["release"]["source_sha"])
        candidate_source = Path("/")
        write_state(target, active)
    except Exception:
        if candidate_source != Path("/"):
            shutil.rmtree(candidate_source, ignore_errors=True)
        raise
    return prove_runtime(target)


def enroll_current_runtime() -> dict[str, Any]:
    if STATE_FILE.exists():
        raise AdapterError("RP native runtime is already enrolled")
    current = record_from_current_release()
    prove_runtime(current)
    write_state(current, current)
    return receipt(current)


def parse_tuple(arguments: argparse.Namespace) -> tuple[str, str, str]:
    return (
        str(arguments.source_sha or ""),
        str(arguments.artifact_digest or ""),
        str(arguments.artifact_ref or ""),
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--action",
        choices=("receipt", "release", "rollback", "enroll-current"),
        required=True,
    )
    parser.add_argument("--current", action="store_true")
    parser.add_argument("--source-sha")
    parser.add_argument("--artifact-digest")
    parser.add_argument("--artifact-ref")
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        raise AdapterError("RP immutable adapter must run as root")
    root_directory(LOCK_FILE.parent)
    with LOCK_FILE.open("a+", encoding="utf-8") as stream:
        os.chmod(LOCK_FILE, 0o600)
        try:
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise AdapterError("RP immutable release lock is already held") from error
        if arguments.action == "enroll-current":
            if arguments.current or any(parse_tuple(arguments)):
                raise AdapterError("current RP enrollment accepts no caller supplied release tuple")
            print(json.dumps(enroll_current_runtime(), sort_keys=True))
            return 0
        if arguments.action == "receipt":
            if arguments.current:
                if any(parse_tuple(arguments)):
                    raise AdapterError(
                        "current RP receipt accepts no caller supplied release tuple"
                    )
                print(json.dumps(prove_runtime(record_from_current_release()), sort_keys=True))
                return 0
            record = {
                "release": release_tuple(*parse_tuple(arguments)),
                "evidence": record_from_current_release()["evidence"],
            }
            print(json.dumps(prove_runtime(record), sort_keys=True))
            return 0
        if arguments.current:
            raise AdapterError("RP release action requires an immutable candidate tuple")
        source_sha, artifact_digest, artifact_ref = parse_tuple(arguments)
        if arguments.action == "release":
            print(json.dumps(do_release(source_sha, artifact_digest, artifact_ref), sort_keys=True))
            return 0
        print(json.dumps(do_rollback(source_sha, artifact_digest, artifact_ref), sort_keys=True))
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AdapterError as error:
        print(f"rp immutable release adapter: {error}", file=sys.stderr)
        raise SystemExit(1) from error
