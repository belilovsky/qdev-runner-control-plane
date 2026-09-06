#!/usr/bin/env python3
"""Root-owned, fixed-surface QMT immutable release adapter.

The controller supplies only an already published OCI digest and signed
candidate evidence.  This adapter owns every host detail, retains the previous
verified image, and restores that exact tuple if any mutation fails.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

PROJECT_ID = "kaztilshi"
ADAPTER = "qmt-native-release-v1"
RECEIPT_SCHEMA = "qdev-admin-platform-native-receipt-v1"
STATE_SCHEMA = "qmt-native-release-state-v1"
TRANSACTION_SCHEMA = "qmt-native-release-transaction-v1"
IMAGE_PREFIX = "registry.ci.qdev.run/kaztilshi"
COMPOSE_FILE = Path("/opt/kaztilshi/docker-compose.yml")
ENV_FILE = Path("/opt/kaztilshi/.env")
ROOT = Path("/var/lib/qdev-release-agents/qmt-native")
STATE_FILE = ROOT / "state.json"
TRANSACTION_FILE = ROOT / "transaction.json"
OVERLAY_FILE = ROOT / "docker-compose.controller-release.yml"
METADATA_FILE = ROOT / "release-metadata.json"
LOCK_FILE = Path("/run/lock/qmt-native-release.lock")
SERVICE = "kaztilshi"
CONTAINER = "kaztilshi-app"
LOCAL_ORIGIN = "http://127.0.0.1:5000"
PUBLIC_ORIGIN = "https://qmt.digital"
LEGACY_VERSION = "4.4.1"
LEGACY_SOURCE_SHA = "308cb4cc4e84749293560c642bd73cfa899a5eea"
RESERVE_BYTES = 2 * 1024**3
_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
_VERSION = re.compile(r"^4\.4\.[0-9]+$")
_SAFE_ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"}


class AdapterError(RuntimeError):
    """The immutable release cannot be proven or safely completed."""


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )


def atomic_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
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


def run(command: list[str]) -> str:
    try:
        completed = subprocess.run(
            command,
            check=True,
            capture_output=True,
            text=True,
            env=_SAFE_ENV,
            timeout=300,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise AdapterError(f"fixed native operation failed: {command[0]}") from error
    return completed.stdout.strip()


def docker_json(*arguments: str) -> Any:
    output = run(["/usr/bin/docker", *arguments])
    try:
        return json.loads(output)
    except json.JSONDecodeError as error:
        raise AdapterError("Docker returned invalid JSON") from error


def http_json(origin: str, path: str) -> dict[str, Any]:
    request = urllib.request.Request(  # noqa: S310 - origins are compiled constants
        f"{origin}{path}", headers={"Accept": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=20) as response:  # noqa: S310
            if response.status != 200:
                raise AdapterError("QMT endpoint is not healthy")
            value = json.loads(response.read())
    except (OSError, urllib.error.URLError, json.JSONDecodeError) as error:
        raise AdapterError("QMT endpoint proof failed") from error
    if not isinstance(value, dict):
        raise AdapterError("QMT endpoint proof is not an object")
    return value


def release_tuple(source_sha: str, artifact_digest: str, artifact_ref: str) -> dict[str, str]:
    if (
        not _SHA.fullmatch(source_sha)
        or not _DIGEST.fullmatch(artifact_digest)
        or artifact_ref != f"{IMAGE_PREFIX}@{artifact_digest}"
    ):
        raise AdapterError("release tuple is not the fixed QMT immutable artifact")
    return {
        "source_sha": source_sha,
        "artifact_digest": artifact_digest,
        "artifact_ref": artifact_ref,
    }


def evidence(
    version: str,
    candidate_receipt_sha256: str,
    migration_receipt_digest: str,
    contract_digest: str,
) -> dict[str, Any]:
    if (
        version != "4.4.2"
        or not _HEX64.fullmatch(candidate_receipt_sha256)
        or not _DIGEST.fullmatch(migration_receipt_digest)
        or not _HEX64.fullmatch(contract_digest)
    ):
        raise AdapterError("QMT candidate evidence is invalid")
    return {
        "version": version,
        "artifact_provenance": {
            "candidate_receipt_sha256": candidate_receipt_sha256,
            "migration_receipt_digest": migration_receipt_digest,
            "contract_digest": contract_digest,
        },
    }


def read_state() -> dict[str, Any]:
    try:
        document = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdapterError("QMT native state is unavailable") from error
    if (
        not isinstance(document, dict)
        or set(document) != {"schema", "active", "rollback"}
        or document.get("schema") != STATE_SCHEMA
        or not isinstance(document.get("active"), dict)
        or not isinstance(document.get("rollback"), dict)
    ):
        raise AdapterError("QMT native state is invalid")
    return document


def validate_record(value: object, *, allow_legacy: bool = True) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {"release", "evidence"}:
        raise AdapterError("QMT native release record is invalid")
    release = value["release"]
    proof = value["evidence"]
    if not isinstance(release, dict) or not isinstance(proof, dict):
        raise AdapterError("QMT native release record is invalid")
    normalized = release_tuple(
        release.get("source_sha", ""),
        release.get("artifact_digest", ""),
        release.get("artifact_ref", ""),
    )
    version = proof.get("version")
    provenance = proof.get("artifact_provenance")
    if (
        not isinstance(version, str)
        or not _VERSION.fullmatch(version)
        or not isinstance(provenance, dict)
    ):
        raise AdapterError("QMT native release evidence is invalid")
    candidate_fields = {
        "candidate_receipt_sha256",
        "migration_receipt_digest",
        "contract_digest",
    }
    if set(provenance) == candidate_fields:
        evidence(
            version,
            provenance.get("candidate_receipt_sha256", ""),
            provenance.get("migration_receipt_digest", ""),
            provenance.get("contract_digest", ""),
        )
    elif (
        allow_legacy
        and version != "4.4.2"
        and set(provenance) == {"legacy_runtime_receipt_sha256"}
        and isinstance(provenance.get("legacy_runtime_receipt_sha256"), str)
        and _HEX64.fullmatch(provenance["legacy_runtime_receipt_sha256"])
    ):
        pass
    else:
        raise AdapterError("QMT native artifact provenance is invalid")
    return {"release": normalized, "evidence": proof}


def write_state(active: dict[str, Any], rollback: dict[str, Any]) -> None:
    atomic_json(
        STATE_FILE,
        {
            "schema": STATE_SCHEMA,
            "active": validate_record(active),
            "rollback": validate_record(rollback),
        },
    )


def image_inspect(reference: str) -> dict[str, Any]:
    value = docker_json("image", "inspect", reference)
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise AdapterError("immutable image inspection failed")
    return value[0]


def prove_image(record: dict[str, Any]) -> dict[str, Any]:
    record = validate_record(record)
    release = record["release"]
    inspected = image_inspect(release["artifact_ref"])
    repo_digests = inspected.get("RepoDigests")
    labels = (inspected.get("Config") or {}).get("Labels") or {}
    if (
        not isinstance(repo_digests, list)
        or release["artifact_ref"] not in repo_digests
        or not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.revision") != release["source_sha"]
    ):
        raise AdapterError("OCI image does not prove the release tuple")
    size = inspected.get("Size")
    if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
        raise AdapterError("OCI image size is unavailable")
    return inspected


def compose_document(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "services": {
            SERVICE: {
                "image": record["release"]["artifact_ref"],
                "volumes": [f"{METADATA_FILE}:/app/release-metadata.json:ro"],
            }
        }
    }


def metadata_document(record: dict[str, Any]) -> dict[str, Any]:
    release = record["release"]
    proof = record["evidence"]["artifact_provenance"]
    return {
        "schema_version": "kaztilshi-runtime-release-v1",
        "project_id": PROJECT_ID,
        "source_revision": release["source_sha"],
        "image_digest": release["artifact_digest"],
        "migration_receipt_digest": proof.get("migration_receipt_digest"),
        "release_receipt_digest": (
            f"sha256:{proof['candidate_receipt_sha256']}"
            if "candidate_receipt_sha256" in proof
            else f"sha256:{proof['legacy_runtime_receipt_sha256']}"
        ),
        "contract_digest": proof.get("contract_digest"),
    }


def is_legacy(record: dict[str, Any]) -> bool:
    provenance = record["evidence"]["artifact_provenance"]
    return set(provenance) == {"legacy_runtime_receipt_sha256"}


def compose_up(record: dict[str, Any]) -> None:
    atomic_json(METADATA_FILE, metadata_document(record), 0o644)
    atomic_json(OVERLAY_FILE, compose_document(record), 0o644)
    run(
        [
            "/usr/bin/docker",
            "compose",
            "--project-name",
            PROJECT_ID,
            "--env-file",
            str(ENV_FILE),
            "-f",
            str(COMPOSE_FILE),
            "-f",
            str(OVERLAY_FILE),
            "up",
            "-d",
            "--force-recreate",
            "--no-build",
            "--pull",
            "never",
            SERVICE,
        ]
    )


def prove_runtime(record: dict[str, Any]) -> dict[str, Any]:
    record = validate_record(record)
    release = record["release"]
    proof = record["evidence"]
    image = prove_image(record)
    containers = docker_json("inspect", CONTAINER)
    if (
        not isinstance(containers, list)
        or len(containers) != 1
        or not isinstance(containers[0], dict)
    ):
        raise AdapterError("running QMT container is unavailable")
    container = containers[0]
    configured_image = (container.get("Config") or {}).get("Image")
    if (
        container.get("Image") != image.get("Id")
        or (configured_image != release["artifact_ref"] and not is_legacy(record))
        or not (container.get("State") or {}).get("Running")
    ):
        raise AdapterError("running QMT container does not match the immutable image")
    for origin in (LOCAL_ORIGIN, PUBLIC_ORIGIN):
        health = http_json(origin, "/api/health")
        readiness = http_json(origin, "/api/readiness")
        identity = http_json(origin, "/release.json")
        if health.get("status") != "ok" or readiness.get("ready") is not True:
            raise AdapterError("QMT health or readiness proof failed")
        expected_receipt = metadata_document(record)
        base_identity_matches = (
            identity.get("version") == proof["version"]
            and identity.get("source_revision") == release["source_sha"]
            and identity.get("runtime_revision") == release["source_sha"]
        )
        if is_legacy(record):
            optional_identity_matches = all(
                identity.get(field) in (None, expected_receipt[field])
                for field in (
                    "image_digest",
                    "migration_receipt_digest",
                    "release_receipt_digest",
                    "contract_digest",
                )
            )
            identity_matches = base_identity_matches and optional_identity_matches
        else:
            identity_matches = base_identity_matches and (
                identity.get("image_digest") == release["artifact_digest"]
                and identity.get("migration_receipt_digest")
                == expected_receipt["migration_receipt_digest"]
                and identity.get("release_receipt_digest")
                == expected_receipt["release_receipt_digest"]
                and identity.get("contract_digest") == expected_receipt["contract_digest"]
                and identity.get("identityStatus") == "verified"
            )
        if not identity_matches:
            raise AdapterError("QMT public identity does not bind the runtime tuple")
    return receipt(record)


def receipt(record: dict[str, Any]) -> dict[str, Any]:
    record = validate_record(record)
    release = record["release"]
    proof = record["evidence"]
    return {
        "schema": RECEIPT_SCHEMA,
        "project_id": PROJECT_ID,
        "native_host_adapter": ADAPTER,
        **release,
        "readiness": {"identity": "ok", "native": "ok", "public": "ok"},
        "runtime_identity": {**release, "measured": True},
        "dependency_identity": {"qmt_version": proof["version"]},
        "artifact_provenance": proof["artifact_provenance"],
    }


def required_capacity(candidate: dict[str, Any], previous: dict[str, Any]) -> int:
    candidate_size = prove_image(candidate).get("Size")
    previous_size = prove_image(previous).get("Size")
    if not isinstance(candidate_size, int) or not isinstance(previous_size, int):
        raise AdapterError("image capacity evidence is invalid")
    return candidate_size + previous_size + RESERVE_BYTES


def ensure_capacity(required: int, *, already_retained: int = 0) -> None:
    free = shutil.disk_usage(ROOT).free
    if free + already_retained < required:
        raise AdapterError("measured disk capacity cannot retain candidate and rollback")


def enroll_current_runtime() -> dict[str, Any]:
    """Seal the one existing 4.4.1 runtime as the controller rollback tuple.

    The mutable tag is used only as registry transport.  State and every later
    operation retain the registry-provided immutable digest.
    """
    if STATE_FILE.exists() or TRANSACTION_FILE.exists():
        raise AdapterError("QMT native runtime is already enrolled")
    ensure_capacity(RESERVE_BYTES)
    containers = docker_json("inspect", CONTAINER)
    if (
        not isinstance(containers, list)
        or len(containers) != 1
        or not isinstance(containers[0], dict)
        or not (containers[0].get("State") or {}).get("Running")
    ):
        raise AdapterError("existing QMT runtime is unavailable for enrollment")
    container = containers[0]
    image_id = container.get("Image")
    if not isinstance(image_id, str) or not _DIGEST.fullmatch(image_id):
        raise AdapterError("existing QMT image identity is invalid")
    inspected = image_inspect(image_id)
    labels = (inspected.get("Config") or {}).get("Labels") or {}
    if (
        not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.revision") != LEGACY_SOURCE_SHA
    ):
        raise AdapterError("existing QMT image source cannot be proven")
    for origin in (LOCAL_ORIGIN, PUBLIC_ORIGIN):
        identity = http_json(origin, "/release.json")
        if (
            identity.get("version") != LEGACY_VERSION
            or identity.get("source_revision") != LEGACY_SOURCE_SHA
            or identity.get("runtime_revision") != LEGACY_SOURCE_SHA
        ):
            raise AdapterError("existing QMT public identity cannot be proven")
    transport_ref = f"{IMAGE_PREFIX}:rollback-{LEGACY_SOURCE_SHA}"
    run(["/usr/bin/docker", "tag", image_id, transport_ref])
    run(["/usr/bin/docker", "push", transport_ref])
    pushed = image_inspect(transport_ref)
    repo_digests = pushed.get("RepoDigests")
    immutable_refs = sorted(
        value
        for value in repo_digests or []
        if isinstance(value, str)
        and value.startswith(f"{IMAGE_PREFIX}@sha256:")
        and _DIGEST.fullmatch(value.removeprefix(f"{IMAGE_PREFIX}@"))
    )
    if len(immutable_refs) != 1:
        raise AdapterError("registry did not return one immutable QMT digest")
    artifact_ref = immutable_refs[0]
    artifact_digest = artifact_ref.removeprefix(f"{IMAGE_PREFIX}@")
    measurement = {
        "schema": "qmt-legacy-runtime-measurement-v1",
        "project_id": PROJECT_ID,
        "version": LEGACY_VERSION,
        "source_sha": LEGACY_SOURCE_SHA,
        "local_image_id": image_id,
        "artifact_ref": artifact_ref,
    }
    record = {
        "release": release_tuple(LEGACY_SOURCE_SHA, artifact_digest, artifact_ref),
        "evidence": {
            "version": LEGACY_VERSION,
            "artifact_provenance": {
                "legacy_runtime_receipt_sha256": hashlib.sha256(
                    canonical_bytes(measurement)
                ).hexdigest()
            },
        },
    }
    prove_runtime(record)
    write_state(record, record)
    return prove_runtime(record)


def recover_interrupted(state: dict[str, Any]) -> dict[str, Any]:
    if not TRANSACTION_FILE.exists():
        return state
    try:
        transaction = json.loads(TRANSACTION_FILE.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise AdapterError("QMT native transaction journal is unreadable") from error
    if (
        not isinstance(transaction, dict)
        or transaction.get("schema") != TRANSACTION_SCHEMA
        or set(transaction) != {"schema", "previous", "candidate"}
    ):
        raise AdapterError("QMT native transaction journal is invalid")
    previous = validate_record(transaction["previous"])
    compose_up(previous)
    prove_runtime(previous)
    write_state(previous, state["rollback"])
    TRANSACTION_FILE.unlink()
    return read_state()


def do_release(candidate: dict[str, Any]) -> dict[str, Any]:
    state = recover_interrupted(read_state())
    previous = validate_record(state["active"])
    prove_runtime(previous)
    ensure_capacity(RESERVE_BYTES)
    run(["/usr/bin/docker", "pull", candidate["release"]["artifact_ref"]])
    required = required_capacity(candidate, previous)
    # Both measured images are already present after the exact-digest pull.
    # Count their retained bytes once and require the remaining 2 GiB reserve.
    ensure_capacity(required, already_retained=required - RESERVE_BYTES)
    atomic_json(
        TRANSACTION_FILE,
        {"schema": TRANSACTION_SCHEMA, "previous": previous, "candidate": candidate},
    )
    try:
        compose_up(candidate)
        result = prove_runtime(candidate)
        write_state(candidate, previous)
        TRANSACTION_FILE.unlink()
        return result
    except BaseException as release_error:
        try:
            compose_up(previous)
            prove_runtime(previous)
            write_state(previous, state["rollback"])
            TRANSACTION_FILE.unlink(missing_ok=True)
        except BaseException as rollback_error:
            raise AdapterError(
                "candidate failed and exact rollback could not be proven"
            ) from rollback_error
        raise AdapterError("candidate failed; previous QMT runtime was restored") from release_error


def do_rollback(target_release: dict[str, str]) -> dict[str, Any]:
    state = recover_interrupted(read_state())
    active = validate_record(state["active"])
    rollback = validate_record(state["rollback"])
    if active["release"] == target_release:
        return prove_runtime(active)
    if rollback["release"] != target_release:
        raise AdapterError("requested rollback is not the retained verified tuple")
    compose_up(rollback)
    result = prove_runtime(rollback)
    write_state(rollback, active)
    return result


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--action", required=True, choices=("enroll-current", "receipt", "release", "rollback")
    )
    parser.add_argument("--current", action="store_true")
    parser.add_argument("--source-sha")
    parser.add_argument("--artifact-digest")
    parser.add_argument("--artifact-ref")
    parser.add_argument("--candidate-receipt-sha256")
    parser.add_argument("--release-version")
    parser.add_argument("--migration-receipt-digest")
    parser.add_argument("--contract-digest")
    return parser.parse_args()


def selected_release(arguments: argparse.Namespace) -> dict[str, str]:
    return release_tuple(
        arguments.source_sha or "",
        arguments.artifact_digest or "",
        arguments.artifact_ref or "",
    )


def main() -> int:
    if os.geteuid() != 0:
        raise AdapterError("QMT native adapter must run as root")
    ROOT.mkdir(parents=True, exist_ok=True, mode=0o700)
    LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with LOCK_FILE.open("a+", encoding="utf-8") as lock:
        os.chmod(LOCK_FILE, 0o600)
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        arguments = parse_args()
        if arguments.action == "enroll-current":
            if any(
                (
                    arguments.current,
                    arguments.source_sha,
                    arguments.artifact_digest,
                    arguments.artifact_ref,
                    arguments.candidate_receipt_sha256,
                    arguments.release_version,
                    arguments.migration_receipt_digest,
                    arguments.contract_digest,
                )
            ):
                raise AdapterError("QMT enrollment does not accept caller-supplied release data")
            result = enroll_current_runtime()
        elif arguments.action == "receipt":
            state = recover_interrupted(read_state())
            record = (
                state["active"]
                if arguments.current
                else next(
                    (
                        value
                        for value in (state["active"], state["rollback"])
                        if validate_record(value)["release"] == selected_release(arguments)
                    ),
                    None,
                )
            )
            if record is None:
                raise AdapterError("requested QMT release tuple is not retained")
            result = prove_runtime(record)
        elif arguments.action == "release":
            candidate = {
                "release": selected_release(arguments),
                "evidence": evidence(
                    arguments.release_version or "",
                    arguments.candidate_receipt_sha256 or "",
                    arguments.migration_receipt_digest or "",
                    arguments.contract_digest or "",
                ),
            }
            result = do_release(validate_record(candidate, allow_legacy=False))
        else:
            result = do_rollback(selected_release(arguments))
        print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AdapterError as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
