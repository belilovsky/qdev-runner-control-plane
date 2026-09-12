#!/usr/bin/env python3
"""Fixed-surface controller adapter for QazPolit private release archives.

The controller agent has already checked the signed lease and fetched the
archive through its mTLS-only endpoint.  This adapter deliberately receives no
URL, target path, compose command, or arbitrary environment from that request.
It validates that exact cached archive, follows QazPolit's native release
layout, and keeps a typed record of the last verified deployment for rollback.
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
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any

PROJECT_ID = "qazpolit"
ADAPTER = "qazpolit-native-release-v1"
RECEIPT_SCHEMA = "qdev-admin-platform-native-receipt-v1"
STATE_SCHEMA = "qazpolit-native-release-state-v1"
TRANSACTION_SCHEMA = "qazpolit-native-release-transaction-v1"
IMAGE_PREFIX = "registry.ci.qdev.run/qazpolit"
OPERATOR_ROOT = Path("/opt/qazpolit")
RELEASES_ROOT = Path("/opt/qazpolit-releases")
ARTIFACT_ROOT = Path("/var/lib/qdev-release-agents/admin-platform/qazpolit-artifacts")
ROOT = Path("/var/lib/qdev-release-agents/qazpolit-native")
STATE_FILE = ROOT / "state.json"
TRANSACTION_FILE = ROOT / "transaction.json"
LOCK_FILE = Path("/run/lock/qazpolit-native-release.lock")
OVERLAYS_ROOT = ROOT / "overlays"
EXTRACTED_ROOT = ROOT / "extracted"
PUBLIC_ORIGIN = "https://qazpolit.com"
# The public ingress keeps this compose nginx hop loopback-only.  Proving this
# hop as well as the public origin prevents CDN/DNS state from being mistaken
# for a successful container switch.
LOCAL_ORIGIN = "http://127.0.0.1:8091"
RESERVE_BYTES = 2 * 1024**3
MAX_ARCHIVE_BYTES = 8 * 1024**3
REQUIRED_ARCHIVE_FILES = frozenset(
    {
        "images.oci.tar.zst",
        "provenance.json",
        "SHA256SUMS",
        "qazstack-1.37.0-py3-none-any.whl",
        "sbom.cdx.json",
        "source-sha.txt",
        "trivy-postgres.json",
        "trivy.json",
    }
)
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class AdapterError(RuntimeError):
    """The release cannot be proven or safely completed."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(value) + b"\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
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


def root_private_directory(path: Path) -> None:
    if path.is_symlink() or not path.is_dir():
        raise AdapterError(f"required private directory is unavailable: {path}")
    metadata = path.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o022:
        raise AdapterError(f"private directory is writable or not root-owned: {path}")


def root_private_file(path: Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise AdapterError(f"required private file is unavailable: {path}")
    metadata = path.stat()
    if metadata.st_uid != 0 or stat.S_IMODE(metadata.st_mode) & 0o077:
        raise AdapterError(f"private file is readable outside root: {path}")


def run(command: list[str], *, timeout: int = 600) -> str:
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


def release_tuple(source_sha: str, artifact_digest: str, artifact_ref: str) -> dict[str, str]:
    if (
        not _SHA.fullmatch(source_sha)
        or not _DIGEST.fullmatch(artifact_digest)
        or artifact_ref != f"{IMAGE_PREFIX}@{artifact_digest}"
    ):
        raise AdapterError("release tuple is not the fixed QazPolit artifact")
    return {
        "source_sha": source_sha,
        "artifact_digest": artifact_digest,
        "artifact_ref": artifact_ref,
    }


def artifact_provenance(
    archive_sha256: str, payload_sha256: str, archive_size_bytes: int
) -> dict[str, Any]:
    if (
        not _HEX64.fullmatch(archive_sha256)
        or not _HEX64.fullmatch(payload_sha256)
        or isinstance(archive_size_bytes, bool)
        or not isinstance(archive_size_bytes, int)
        or not 0 < archive_size_bytes <= MAX_ARCHIVE_BYTES
    ):
        raise AdapterError("private artifact provenance is invalid")
    return {
        "archive_sha256": archive_sha256,
        "payload_sha256": payload_sha256,
        "archive_size_bytes": archive_size_bytes,
    }


def read_state() -> dict[str, Any]:
    try:
        document = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdapterError("QazPolit native state is unavailable") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "active", "rollback"}
        or document.get("schema") != STATE_SCHEMA
    ):
        raise AdapterError("QazPolit native state is invalid")
    return {
        "schema": STATE_SCHEMA,
        "active": validate_record(document["active"]),
        "rollback": validate_record(document["rollback"]),
    }


def validate_record(value: object) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"release", "provenance", "deployment"}:
        raise AdapterError("QazPolit native release record is invalid")
    release = value["release"]
    provenance = value["provenance"]
    deployment = value["deployment"]
    if (
        not isinstance(release, dict)
        or not isinstance(provenance, dict)
        or not isinstance(deployment, dict)
    ):
        raise AdapterError("QazPolit native release record is invalid")
    normalized = release_tuple(
        release.get("source_sha", ""),
        release.get("artifact_digest", ""),
        release.get("artifact_ref", ""),
    )
    if set(provenance) == {"legacy_runtime_receipt_sha256"}:
        if not _HEX64.fullmatch(provenance["legacy_runtime_receipt_sha256"]):
            raise AdapterError("legacy QazPolit receipt is invalid")
    elif set(provenance) == {"archive_sha256", "payload_sha256", "archive_size_bytes"}:
        artifact_provenance(
            provenance["archive_sha256"],
            provenance["payload_sha256"],
            provenance["archive_size_bytes"],
        )
    else:
        raise AdapterError("QazPolit native artifact provenance is invalid")
    required_deployment = {"worktree", "overlay", "release_id"}
    if set(deployment) != required_deployment or not all(
        isinstance(deployment[key], str) and deployment[key] for key in required_deployment
    ):
        raise AdapterError("QazPolit native deployment record is invalid")
    return {"release": normalized, "provenance": provenance, "deployment": deployment}


def http_json(origin: str, path: str) -> dict[str, Any]:
    if origin not in {LOCAL_ORIGIN, PUBLIC_ORIGIN}:
        raise AdapterError("QazPolit runtime origin is not allowlisted")
    request = urllib.request.Request(  # noqa: S310 - exact allowlisted origins above
        f"{origin}{path}", headers={"Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310 - compiled origins
            if response.status != 200:
                raise AdapterError("QazPolit runtime endpoint is not healthy")
            value = json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise AdapterError("QazPolit runtime proof failed") from error
    if not isinstance(value, dict):
        raise AdapterError("QazPolit runtime proof is not an object")
    return value


def runtime_release(runtime: dict[str, Any]) -> tuple[str, str, str]:
    build = runtime.get("build")
    if not isinstance(build, dict):
        raise AdapterError("QazPolit runtime build identity is absent")
    source_sha = build.get("source_sha")
    image_digest = build.get("image_digest")
    release_id = build.get("release_id")
    if not isinstance(source_sha, str) or not _SHA.fullmatch(source_sha):
        raise AdapterError("QazPolit runtime source identity is invalid")
    if not isinstance(image_digest, str) or not _DIGEST.fullmatch(image_digest):
        raise AdapterError("QazPolit runtime image identity is invalid")
    if not isinstance(release_id, str) or not release_id:
        raise AdapterError("QazPolit runtime release identity is invalid")
    return source_sha, image_digest, release_id


def checked_runtime(expected_source_sha: str) -> tuple[dict[str, Any], str]:
    # A local proof avoids DNS/CDN ambiguity; public proof confirms what readers receive.
    runtime = http_json(LOCAL_ORIGIN, "/api/runtime")
    source_sha, _, release_id = runtime_release(runtime)
    if source_sha != expected_source_sha:
        raise AdapterError("local QazPolit runtime did not reach the requested source")
    public_runtime = http_json(PUBLIC_ORIGIN, "/api/runtime")
    public_source_sha, _, _ = runtime_release(public_runtime)
    if public_source_sha != expected_source_sha:
        raise AdapterError("public QazPolit runtime did not reach the requested source")
    return runtime, release_id


def bootstrap_record() -> dict[str, Any]:
    runtime = http_json(PUBLIC_ORIGIN, "/api/runtime")
    source_sha, image_digest, release_id = runtime_release(runtime)
    legacy = hashlib.sha256(canonical_bytes(runtime)).hexdigest()
    return {
        "release": release_tuple(source_sha, image_digest, f"{IMAGE_PREFIX}@{image_digest}"),
        "provenance": {"legacy_runtime_receipt_sha256": legacy},
        "deployment": {
            "worktree": str(OPERATOR_ROOT),
            "overlay": str(OPERATOR_ROOT / ".env"),
            "release_id": release_id,
        },
    }


def current_state() -> dict[str, Any]:
    if STATE_FILE.exists():
        return read_state()
    record = bootstrap_record()
    state = {"schema": STATE_SCHEMA, "active": record, "rollback": record}
    atomic_json(STATE_FILE, state)
    return state


def archive_path(source_sha: str, archive_sha256: str) -> Path:
    return ARTIFACT_ROOT / source_sha / f"{archive_sha256}.zip"


def checked_archive(source_sha: str, provenance: dict[str, Any]) -> Path:
    path = archive_path(source_sha, provenance["archive_sha256"])
    root_private_directory(ARTIFACT_ROOT)
    root_private_directory(path.parent)
    root_private_file(path)
    metadata = path.stat()
    if (
        metadata.st_size != provenance["archive_size_bytes"]
        or sha256_file(path) != provenance["archive_sha256"]
    ):
        raise AdapterError("cached controller archive does not match signed delivery")
    return path


def extract_archive(path: Path, source_sha: str, provenance: dict[str, Any]) -> Path:
    archive_sha256 = provenance.get("archive_sha256")
    if not isinstance(archive_sha256, str) or not _HEX64.fullmatch(archive_sha256):
        raise AdapterError("private artifact provenance is invalid")
    destination = EXTRACTED_ROOT / source_sha / archive_sha256
    if destination.exists():
        root_private_directory(destination)
        if {entry.name for entry in destination.iterdir()} == REQUIRED_ARCHIVE_FILES:
            return destination
        raise AdapterError("existing private artifact extraction is incomplete")
    destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = Path(tempfile.mkdtemp(prefix=".extract-", dir=destination.parent))
    try:
        with zipfile.ZipFile(path) as archive:
            members = archive.infolist()
            names = {member.filename for member in members}
            if names != REQUIRED_ARCHIVE_FILES or len(members) != len(REQUIRED_ARCHIVE_FILES):
                raise AdapterError("private archive file set is invalid")
            for member in members:
                if (
                    member.is_dir()
                    or member.filename.startswith("/")
                    or ".." in Path(member.filename).parts
                ):
                    raise AdapterError("private archive contains an unsafe member")
                if stat.S_IFMT(member.external_attr >> 16) == stat.S_IFLNK:
                    raise AdapterError("private archive contains a symlink")
                target = temporary / member.filename
                with archive.open(member) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                os.chmod(target, 0o600)
        os.replace(temporary, destination)
        os.chmod(destination, 0o700)
        return destination
    except BaseException:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def release_provenance(extracted: Path, source_sha: str) -> dict[str, str]:
    try:
        document = json.loads((extracted / "provenance.json").read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdapterError("private artifact provenance is unreadable") from error
    if not isinstance(document, dict) or document.get("schema") != "qazpolit.release-provenance.v1":
        raise AdapterError("private artifact provenance schema is invalid")
    image_ref = document.get("image_ref")
    image_digest = document.get("image_digest")
    postgres = document.get("postgres")
    if (
        document.get("source_sha") != source_sha
        or not isinstance(image_ref, str)
        or not _DIGEST.fullmatch(image_digest if isinstance(image_digest, str) else "")
        or image_ref != f"{IMAGE_PREFIX}@{image_digest}"
        or not isinstance(postgres, dict)
        or not isinstance(postgres.get("image_ref"), str)
    ):
        raise AdapterError("private artifact provenance is inconsistent")
    source_file = (extracted / "source-sha.txt").read_text(encoding="utf-8").strip()
    if source_file != source_sha:
        raise AdapterError("private artifact source pointer is inconsistent")
    return {
        "app_image": image_ref,
        "app_digest": image_digest,
        "db_image": postgres["image_ref"],
        "release_id": str(document.get("release_id", "")),
    }


def prepare_worktree(source_sha: str) -> Path:
    if not OPERATOR_ROOT.is_dir() or not (OPERATOR_ROOT / ".git").exists():
        raise AdapterError("QazPolit operator checkout is unavailable")
    run(["/usr/bin/git", "-C", str(OPERATOR_ROOT), "fetch", "--quiet", "origin", "main"])
    if run(["/usr/bin/git", "-C", str(OPERATOR_ROOT), "rev-parse", "origin/main"]) != source_sha:
        raise AdapterError("controller source is not current canonical QazPolit main")
    worktree = RELEASES_ROOT / source_sha
    if worktree.exists():
        if (
            not worktree.is_dir()
            or run(["/usr/bin/git", "-C", str(worktree), "rev-parse", "HEAD"]) != source_sha
        ):
            raise AdapterError("existing QazPolit release worktree is not the requested source")
    else:
        RELEASES_ROOT.mkdir(parents=True, exist_ok=True, mode=0o755)
        run(
            [
                "/usr/bin/git",
                "-C",
                str(OPERATOR_ROOT),
                "worktree",
                "add",
                "--detach",
                str(worktree),
                source_sha,
            ]
        )
    return worktree


def write_overlay(worktree: Path, source_sha: str, details: dict[str, str]) -> Path:
    env_source = OPERATOR_ROOT / ".env"
    root_private_file(env_source)
    release_id = details["release_id"]
    if not release_id:
        raise AdapterError("private artifact does not declare a release identifier")
    overlay = OVERLAYS_ROOT / source_sha / ".env"
    overlay.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    base = env_source.read_text(encoding="utf-8")
    controlled = {
        "QAZPOLIT_APP_IMAGE",
        "QAZPOLIT_DB_IMAGE",
        "QAZPOLIT_SOURCE_SHA",
        "QAZPOLIT_RELEASE_ID",
    }
    preserved = [
        line
        for line in base.splitlines()
        if not any(line.startswith(f"{key}=") for key in controlled)
    ]
    preserved.extend(
        (
            f"QAZPOLIT_APP_IMAGE={details['app_image']}",
            f"QAZPOLIT_DB_IMAGE={details['db_image']}",
            f"QAZPOLIT_SOURCE_SHA={source_sha}",
            f"QAZPOLIT_RELEASE_ID={release_id}",
        )
    )
    atomic_json(
        overlay.with_suffix(".json"),
        {"sha256": hashlib.sha256("\n".join(preserved).encode()).hexdigest()},
    )
    descriptor, temporary = tempfile.mkstemp(prefix=".env.", dir=overlay.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write("\n".join(preserved) + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o600)
        os.replace(temporary, overlay)
    except BaseException:
        Path(temporary).unlink(missing_ok=True)
        raise
    return overlay


def bind_operator_runtime(worktree: Path, overlay: Path) -> None:
    """Bind only the fixed operator-owned inputs needed by a clean worktree."""
    data_source = OPERATOR_ROOT / "data"
    if not data_source.is_dir() or data_source.is_symlink():
        raise AdapterError("QazPolit operator data directory is unavailable")
    bindings = ((worktree / ".env", overlay, False), (worktree / "data", data_source, True))
    for destination, source, is_directory in bindings:
        if destination.is_symlink():
            if destination.resolve() != source.resolve():
                raise AdapterError("release worktree has a conflicting runtime binding")
            continue
        if destination.exists():
            raise AdapterError("release worktree unexpectedly contains mutable runtime material")
        destination.symlink_to(source, target_is_directory=is_directory)


def compose(worktree: Path, overlay: Path, *arguments: str) -> str:
    return run(
        [
            "/usr/bin/docker",
            "compose",
            "--project-name",
            "qazpolit",
            "--env-file",
            str(overlay),
            "-f",
            str(worktree / "docker-compose.yml"),
            *arguments,
        ]
    )


def deploy_record(record: dict[str, Any]) -> None:
    deployment = record["deployment"]
    worktree = Path(deployment["worktree"])
    overlay = Path(deployment["overlay"])
    if not worktree.is_dir() or not overlay.is_file():
        raise AdapterError("rollback deployment material is unavailable")
    compose(worktree, overlay, "config", "--quiet")
    compose(worktree, overlay, "up", "-d", "--no-build", "--no-deps", "app", "nginx")
    checked_runtime(record["release"]["source_sha"])


def release(args: argparse.Namespace) -> dict[str, Any]:
    current = current_state()
    candidate = release_tuple(args.source_sha, args.artifact_digest, args.artifact_ref)
    provenance = artifact_provenance(
        args.private_archive_sha256, args.private_payload_sha256, args.private_archive_size_bytes
    )
    archive = checked_archive(candidate["source_sha"], provenance)
    extracted = extract_archive(archive, candidate["source_sha"], provenance)
    details = release_provenance(extracted, candidate["source_sha"])
    if details["app_digest"] != candidate["artifact_digest"]:
        raise AdapterError("controller artifact digest and QazPolit provenance differ")
    worktree = prepare_worktree(candidate["source_sha"])
    free = shutil.disk_usage(ROOT).free
    # Archive extraction plus image load are bounded by the signed archive.  The
    # native loader performs its own image checks before compose can mutate.
    if free < provenance["archive_size_bytes"] * 2 + RESERVE_BYTES:
        raise AdapterError("insufficient measured free space for private QazPolit release")
    run([str(worktree / "deploy" / "load-release-artifact.sh"), str(extracted)], timeout=1200)
    overlay = write_overlay(worktree, candidate["source_sha"], details)
    bind_operator_runtime(worktree, overlay)
    record = {
        "release": candidate,
        "provenance": provenance,
        "deployment": {
            "worktree": str(worktree),
            "overlay": str(overlay),
            "release_id": details["release_id"],
        },
    }
    atomic_json(
        TRANSACTION_FILE,
        {"schema": TRANSACTION_SCHEMA, "previous": current["active"], "candidate": record},
    )
    try:
        deploy_record(record)
    except Exception as release_error:
        rollback_error: AdapterError | None = None
        try:
            deploy_record(current["active"])
        except AdapterError as error:
            rollback_error = error
        if rollback_error is not None:
            raise AdapterError(
                "candidate failed and the retained QazPolit release could not be restored"
            ) from rollback_error
        TRANSACTION_FILE.unlink(missing_ok=True)
        raise release_error
    atomic_json(
        STATE_FILE, {"schema": STATE_SCHEMA, "active": record, "rollback": current["active"]}
    )
    TRANSACTION_FILE.unlink(missing_ok=True)
    return receipt(record)


def rollback(args: argparse.Namespace) -> dict[str, Any]:
    state = current_state()
    target = release_tuple(args.source_sha, args.artifact_digest, args.artifact_ref)
    if target != state["rollback"]["release"]:
        raise AdapterError("rollback target is not the retained verified QazPolit release")
    deploy_record(state["rollback"])
    atomic_json(
        STATE_FILE,
        {"schema": STATE_SCHEMA, "active": state["rollback"], "rollback": state["active"]},
    )
    return receipt(state["rollback"])


def receipt(record: dict[str, Any]) -> dict[str, Any]:
    runtime = http_json(PUBLIC_ORIGIN, "/api/runtime")
    source_sha, _, release_id = runtime_release(runtime)
    if source_sha != record["release"]["source_sha"]:
        raise AdapterError("QazPolit public runtime does not match recorded release")
    return {
        "schema": RECEIPT_SCHEMA,
        "project_id": PROJECT_ID,
        "native_host_adapter": ADAPTER,
        **record["release"],
        "readiness": {"identity": "ok", "native": "ok", "public": "ok"},
        "runtime_identity": {**record["release"], "measured": True, "release_id": release_id},
        "dependency_identity": {"qazstack": "1.37.0", "database_schema": "035"},
        "artifact_provenance": record["provenance"],
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--action", choices=("release", "rollback", "receipt"), required=True)
    parser.add_argument("--source-sha")
    parser.add_argument("--artifact-digest")
    parser.add_argument("--artifact-ref")
    parser.add_argument("--private-archive-sha256")
    parser.add_argument("--private-payload-sha256")
    parser.add_argument("--private-archive-size-bytes", type=int)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if os.geteuid() != 0:
        raise AdapterError("QazPolit native adapter must run as root")
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
    with LOCK_FILE.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        if args.action == "receipt":
            result = receipt(current_state()["active"])
        elif args.action == "release":
            if None in (
                args.source_sha,
                args.artifact_digest,
                args.artifact_ref,
                args.private_archive_sha256,
                args.private_payload_sha256,
                args.private_archive_size_bytes,
            ):
                raise AdapterError("private QazPolit release arguments are incomplete")
            result = release(args)
        else:
            if None in (args.source_sha, args.artifact_digest, args.artifact_ref):
                raise AdapterError("QazPolit rollback arguments are incomplete")
            result = rollback(args)
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AdapterError as error:
        print(f"qazpolit native release refused: {error}", file=sys.stderr)
        raise SystemExit(2) from error
