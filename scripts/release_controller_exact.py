#!/usr/bin/env python3
"""Owner-operated controller release transaction; no worker or queue mutations.

Run on the controller host after exact-SHA full provider CI. SSH may transport
this reviewed command but must not supply arbitrary recovery shell. Artifacts,
old image IDs, configuration backups and signed audits remain on the host.
An interrupted activation is reconciled or rolled back, never dispatched twice.
"""

from __future__ import annotations

import argparse
import fcntl
import hashlib
import json
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Importing a helper must never create an unbound __pycache__ in the artifact.
sys.dont_write_bytecode = True
from controller_release_guard import check_current, exact, verify_artifact  # noqa: E402

ROOT = Path("/opt/qdev-runner-control-plane")
TRANSACTIONS = Path("/var/lib/qdev-runner/controller-releases")
CONFIG = Path("/etc/qdev-runner")
STATUS = CONFIG / "controller-release.json"
DATABASE = Path("/var/lib/qdev-runner/broker.db")
SERVICES = ("broker-public", "broker-internal")
CONFIG_FILES = (
    "repos.json",
    "profiles.yml",
    "release-lanes.yml",
    "managed-registry.yml",
    "admin-platform-ledger.yml",
    "managed-release-ledger.yml",
    "controller-release.json",
)
SOURCE_CONFIG = {
    name: "config/" + name for name in CONFIG_FILES if name != "controller-release.json"
} | {
    "repos.json": "inventory/repos.json",
    "admin-platform-ledger.yml": "config/admin-platform-ledger-v2.yml",
}


def run(command: list[str], **kwargs: Any) -> str:
    return subprocess.check_output(command, text=True, **kwargs).strip()


def atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".new")
    with temporary.open("w") as stream:
        os.chmod(temporary, 0o600)
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    descriptor = os.open(path.parent, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def image_id(service: str) -> str:
    value = run(["docker", "inspect", "qdev-runner-" + service, "--format", "{{.Image}}"])
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", value):
        raise ValueError("container has no immutable image identity")
    return value


def images() -> dict[str, str]:
    return {service: image_id(service) for service in SERVICES}


def compose_file(path: Path, bindings: dict[str, str]) -> None:
    atomic_json(path, {"services": {name: {"image": image} for name, image in bindings.items()}})


def phase(directory: Path, record: dict[str, Any], value: str) -> None:
    record["phase"] = value
    atomic_json(directory / "transaction.json", record)


def load_transaction(directory: Path, binding: dict[str, str]) -> dict[str, Any]:
    record_path = directory / "transaction.json"
    if record_path.exists():
        record = json.loads(record_path.read_text())
        if record.get("binding") != binding:
            raise ValueError("idempotency key already binds a different release")
        return dict(record)
    record = {"schema": "qdev-controller-release-transaction-v1", "binding": binding}
    phase(directory, record, "prepared")
    return record


def current_matches(revision: str, digest: str) -> bool:
    try:
        check_current(STATUS, revision, digest)
    except (ValueError, OSError):
        return False
    return True


def file_digest(path: Path) -> str | None:
    if path.is_symlink():
        raise ValueError("configuration must not be a symlink")
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def verify_configuration(record: dict[str, Any], *, previous_only: bool = False) -> None:
    release = Path(record["binding"]["release"])
    for name, relative in SOURCE_CONFIG.items():
        allowed = {record["previous_configuration"][name]}
        if not previous_only:
            allowed.add(file_digest(release / relative))
        if file_digest(CONFIG / name) not in allowed:
            raise ValueError(
                "foreign configuration change; reconcile before activation or rollback"
            )


def rollback_permitted(record: dict[str, Any], actual_images: dict[str, str]) -> bool:
    """Never overwrite a third party's release, including a hot image change."""
    binding = record["binding"]
    known_status = current_matches(binding["expected_revision"], binding["expected_digest"]) or (
        current_matches(binding["revision"], binding["digest"])
    )
    old = record.get("previous_images", {})
    candidate = record.get("candidate_image")
    return known_status and all(
        actual_images.get(service) in {old.get(service), candidate}
        and actual_images.get(service) is not None
        for service in SERVICES
    )


def restore(directory: Path, record: dict[str, Any]) -> None:
    if "previous_images" not in record or "previous_configuration" not in record:
        raise ValueError("transaction has no complete rollback snapshot")
    if not rollback_permitted(record, images()):
        raise ValueError("foreign runtime change: rollback requires reconciliation")
    previous = Path(record["previous_release"])
    if previous.parent != ROOT / "releases" or not previous.is_dir():
        raise ValueError("recorded rollback source is unavailable")
    if (ROOT / "current").resolve() not in {previous, Path(record["binding"]["release"])}:
        raise ValueError("foreign current link; rollback requires reconciliation")
    verify_configuration(record)
    for name in CONFIG_FILES:
        if (
            file_digest(directory / "configuration" / name)
            != record["previous_configuration"][name]
        ):
            raise ValueError("rollback configuration backup changed")
    if record["phase"] == "rolled-back":
        if images() != record["previous_images"]:
            raise ValueError("terminal rollback images changed")
        check_current(
            STATUS, record["binding"]["expected_revision"], record["binding"]["expected_digest"]
        )
        verify_configuration(record, previous_only=True)
        signed_audits(directory, prefix="rollback-")
        return
    phase(directory, record, "rolling-back")
    for name in CONFIG_FILES:
        destination = CONFIG / name
        backup = directory / "configuration" / name
        if backup.exists():
            temporary_config = CONFIG / (".rollback-" + name)
            shutil.copy2(backup, temporary_config)
            os.replace(temporary_config, destination)
        elif destination.exists():
            destination.unlink()
    temporary = ROOT / ".controller-rollback-current"
    temporary.unlink(missing_ok=True)
    temporary.symlink_to(previous)
    os.replace(temporary, ROOT / "current")
    run(
        [
            "docker",
            "compose",
            "-p",
            "qdev-runner",
            "-f",
            str(previous / "deploy/compose.yml"),
            "-f",
            str(directory / "rollback-compose.json"),
            "up",
            "-d",
            "--force-recreate",
            "--no-build",
            "--no-deps",
            *SERVICES,
        ]
    )
    if images() != record["previous_images"]:
        raise ValueError("rollback image verification failed; backups retained")
    check_current(
        STATUS, record["binding"]["expected_revision"], record["binding"]["expected_digest"]
    )
    # Rollback acceptance uses the real authenticated operator, not public health.
    signed_audits(directory, prefix="rollback-")
    phase(directory, record, "rolled-back")


def signed_audits(directory: Path, prefix: str = "") -> dict[str, Any]:
    receipts = {}
    for command in ("audit", "release-audit"):
        # The existing operator checks the signature inside its protected environment.
        deadline = time.monotonic() + 45
        while True:
            try:
                output = run(
                    [
                        "docker",
                        "exec",
                        "qdev-runner-broker-internal",
                        "qdev-runner-operator",
                        command,
                    ],
                    timeout=10,
                )
                break
            except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(1)
        receipt = json.loads(output)
        if (
            receipt.get("schema") != "qdev-controller-receipt-v2"
            or receipt.get("enforcement") != "enforced"
        ):
            raise ValueError("native operator returned no receipt v2")
        observed = datetime.fromisoformat(receipt["payload"]["observed_at"].replace("Z", "+00:00"))
        if observed.tzinfo is None:
            raise ValueError("native operator receipt has no timezone")
        if not 0 <= (datetime.now(UTC) - observed).total_seconds() <= 120:
            raise ValueError("native operator receipt is not fresh")
        atomic_json(directory / f"{prefix}{command}.json", receipt)
        receipts[command] = receipt
    return receipts


def accept(directory: Path, record: dict[str, Any]) -> None:
    binding = record["binding"]
    verify_artifact(Path(binding["release"]), binding["revision"], binding["digest"])
    check_current(STATUS, binding["revision"], binding["digest"])
    if images() != {service: record["candidate_image"] for service in SERVICES}:
        raise ValueError("runtime image binding differs from candidate")
    if (ROOT / "current").resolve() != Path(binding["release"]):
        raise ValueError("runtime source link differs from candidate")
    receipts = signed_audits(directory)
    live = receipts["release-audit"]["payload"]["controller_release"]
    if (
        live.get("revision") != binding["revision"]
        or live.get("release_digest") != binding["digest"]
        or live.get("state") != "active"
    ):
        raise ValueError("signed release audit does not bind candidate source")
    phase(directory, record, "completed")


def reconcile(directory: Path, record: dict[str, Any]) -> bool:
    """Return True only for an already completed activation; never repeat it."""
    state = record["phase"]
    if state == "completed":
        accept(directory, record)
        return True
    if state in {"activating", "verifying", "rolling-back"}:
        binding = record["binding"]
        if (
            state != "rolling-back"
            and current_matches(binding["revision"], binding["digest"])
            and images() == {service: record["candidate_image"] for service in SERVICES}
        ):
            accept(directory, record)
            return True
        restore(directory, record)
        raise ValueError("interrupted activation restored; use a new transaction after diagnosis")
    if state == "rolled-back":
        raise ValueError("transaction is terminal rolled-back; it cannot deploy again")
    if state not in {"prepared", "snapshotted"}:
        raise ValueError("unknown release transaction phase")
    return False


def snapshot(directory: Path, record: dict[str, Any]) -> None:
    if "previous_images" in record:
        return
    previous = (ROOT / "current").resolve(strict=True)
    if previous.parent != ROOT / "releases":
        raise ValueError("current source is not a staged release")
    bindings = images()
    backup = directory / "configuration"
    backup.mkdir(mode=0o700, exist_ok=True)
    for name in CONFIG_FILES:
        source = CONFIG / name
        if source.is_symlink():
            raise ValueError("configuration symlink cannot be snapshotted")
        if source.exists():
            shutil.copy2(source, backup / name)
    for service, identity in bindings.items():
        # Durable tags prevent garbage collection; never delete these automatically.
        run(["docker", "image", "tag", identity, f"qdev-rollback-{service}:{directory.name}"])
    compose_file(directory / "rollback-compose.json", bindings)
    record["previous_images"] = bindings
    record["previous_release"] = str(previous)
    record["previous_configuration"] = {name: file_digest(backup / name) for name in CONFIG_FILES}
    phase(directory, record, "snapshotted")


def migration_preflight(directory: Path, candidate: str, previous: str) -> None:
    if not DATABASE.is_file():
        raise ValueError("native broker database not found; do not guess a migration source")
    migration = directory / "migration"
    migration.mkdir(mode=0o700, exist_ok=True)
    database_copy = migration / "migration.sqlite3"
    with (
        sqlite3.connect(DATABASE.as_uri() + "?mode=ro", uri=True) as source,
        sqlite3.connect(database_copy) as destination,
    ):
        source.backup(destination)
    before = sqlite_projection(database_copy)
    # Only an isolated copy is migrated. No direct queue writes or restore of
    # production DB are performed. Old code must still open the migrated copy.
    program = (
        "from pathlib import Path; from qdev_runner.store import Store; "
        'import sqlite3; s=Store(Path("/migration/migration.sqlite3")); '
        'c=sqlite3.connect("/migration/migration.sqlite3"); '
        'assert c.execute("PRAGMA integrity_check").fetchone()[0] == "ok"; '
        'print("migration_compatibility_ok")'
    )
    for image in (candidate, previous):
        run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--user",
                "0:0",
                "--read-only",
                "--tmpfs",
                "/tmp",  # noqa: S108 - isolated container tmpfs
                "-v",
                f"{migration}:/migration",
                "--entrypoint",
                "python",
                image,
                "-I",
                "-c",
                program,
            ]
        )
        if sqlite_projection(database_copy, before) != before:
            raise ValueError(
                "migration changed existing columns or queue data on the isolated copy"
            )


def sqlite_projection(database: Path, baseline: dict[str, Any] | None = None) -> dict[str, Any]:
    """Hash only the original columns; additive tables/columns remain compatible."""

    def quote(value: str) -> str:
        return '"' + value.replace('"', '""') + '"'

    projection = {}
    with sqlite3.connect(database.as_uri() + "?mode=ro", uri=True) as connection:
        tables = [
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'"
            )
        ]
        for table in baseline if baseline is not None else tables:
            if table not in tables:
                raise ValueError("migration dropped an existing table")
            columns = {
                row[1]: list(row[2:])
                for row in connection.execute(f"PRAGMA table_info({quote(table)})")
            }
            selected = baseline[table]["columns"] if baseline is not None else columns
            if any(columns.get(name) != info for name, info in selected.items()):
                raise ValueError("migration changed an existing column")
            fields = ",".join(quote(name) for name in selected)
            checksum = hashlib.sha256()
            count = 0
            for row in connection.execute(f"SELECT {fields} FROM {quote(table)} ORDER BY {fields}"):  # noqa: S608 - quoted SQLite identifiers
                checksum.update(repr(row).encode())
                checksum.update(b"\n")
                count += 1
            projection[table] = {"columns": selected, "rows": count, "digest": checksum.hexdigest()}
    return projection


def capacity_preflight() -> None:
    disk = shutil.disk_usage(ROOT)
    memory = dict(line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines())
    available = int(memory["MemAvailable"].split()[0]) * 1024
    used_pct = 100 * disk.used / disk.total
    if (
        disk.free < 30 * 1024**3
        or used_pct > 85
        or available < 4 * 1024**3
        or os.getloadavg()[2] > 2 * (os.cpu_count() or 1)
    ):
        raise ValueError("build capacity gate rejected; no images or services changed")


def execute(directory: Path, record: dict[str, Any]) -> None:
    if reconcile(directory, record):
        return
    binding = record["binding"]
    release = Path(binding["release"])
    verify_artifact(release, binding["revision"], binding["digest"])
    check_current(STATUS, binding["expected_revision"], binding["expected_digest"])
    capacity_preflight()
    snapshot(directory, record)
    tag = f"qdev-controller:{binding['revision']}-{binding['digest'][:16]}"
    run(
        [
            "docker",
            "build",
            "--label",
            "org.opencontainers.image.revision=" + binding["revision"],
            "--label",
            "run.qdev.source-digest=" + binding["digest"],
            "-t",
            tag,
            "-f",
            str(release / "deploy/Dockerfile.broker"),
            str(release),
        ]
    )
    image = run(["docker", "image", "inspect", tag, "--format", "{{.Id}}"])
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise ValueError("candidate image identity is invalid")
    run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--tmpfs",
            "/tmp",  # noqa: S108
            "--entrypoint",
            "python",
            image,
            "-I",
            "-c",
            "import importlib,pkgutil,qdev_runner; "
            "[importlib.import_module(m.name) for m in pkgutil.iter_modules("
            'qdev_runner.__path__, qdev_runner.__name__+".")]; print("runtime_imports_ok")',
        ]
    )
    migration_preflight(directory, image, record["previous_images"]["broker-internal"])
    record["candidate_image"] = image
    compose_file(directory / "candidate-compose.json", {service: image for service in SERVICES})
    # Check both metadata AND actual images immediately before activation.
    check_current(STATUS, binding["expected_revision"], binding["expected_digest"])
    if images() != record["previous_images"]:
        raise ValueError("current image changed during build; reconcile before activation")
    verify_configuration(record, previous_only=True)
    verify_artifact(release, binding["revision"], binding["digest"])
    phase(directory, record, "activating")
    environment = dict(os.environ) | {
        "QDEV_CONTROLLER_TRANSACTION_DIR": str(directory),
        "QDEV_CONTROLLER_RELEASE_REVISION": binding["revision"],
        "QDEV_CONTROLLER_ARTIFACT_DIGEST": binding["digest"],
        "QDEV_CONTROLLER_EXPECTED_REVISION": binding["expected_revision"],
        "QDEV_CONTROLLER_EXPECTED_DIGEST": binding["expected_digest"],
        "QDEV_CONTROLLER_NO_BUILD": "true",
        "QDEV_CONTROLLER_LEGACY_ROLLBACK": "false",
        "QDEV_CONTROLLER_RELEASE_STATUS": str(STATUS),
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    try:
        run(
            ["bash", str(release / "scripts/activate_controller_release.sh"), str(release)],
            env=environment,
        )
        phase(directory, record, "verifying")
        accept(directory, record)
    except (subprocess.SubprocessError, ValueError, OSError):
        restore(directory, record)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--release", type=Path)
    parser.add_argument("--revision")
    parser.add_argument("--digest")
    parser.add_argument("--expected-revision")
    parser.add_argument("--expected-digest")
    parser.add_argument("--transaction-id")
    parser.add_argument("--rollback-transaction")
    args = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("native controller release requires root on the controller host")
    try:
        if args.rollback_transaction:
            if any(
                (
                    args.release,
                    args.revision,
                    args.digest,
                    args.expected_revision,
                    args.expected_digest,
                    args.transaction_id,
                )
            ):
                raise ValueError("rollback takes only the existing transaction id")
            args.transaction_id = args.rollback_transaction
        elif not all(
            (
                args.release,
                args.revision,
                args.digest,
                args.expected_revision,
                args.expected_digest,
                args.transaction_id,
            )
        ):
            raise ValueError("activation requires every exact source/current binding")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]{7,79}", args.transaction_id):
            raise ValueError("invalid transaction id")
        if args.rollback_transaction:
            directory = TRANSACTIONS / args.transaction_id
            if directory.is_symlink():
                raise ValueError("transaction path cannot be a symlink")
            with (TRANSACTIONS / "release.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                record = json.loads((directory / "transaction.json").read_text())
                restore(directory, record)
                print(json.dumps({"transaction": args.transaction_id, "phase": record["phase"]}))
                return 0
        release = args.release.resolve(strict=True)
        if release.parent != ROOT / "releases" or args.release.is_symlink():
            raise ValueError("release must be an exact staged directory")
        binding = {
            "release": str(release),
            "revision": exact(args.revision, 40),
            "digest": exact(args.digest, 64),
            "expected_revision": exact(args.expected_revision, 40),
            "expected_digest": exact(args.expected_digest, 64),
        }
        TRANSACTIONS.mkdir(mode=0o700, parents=True, exist_ok=True)
        with (TRANSACTIONS / "release.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            directory = TRANSACTIONS / args.transaction_id
            if directory.is_symlink():
                raise ValueError("transaction path cannot be a symlink")
            directory.mkdir(mode=0o700, exist_ok=True)
            record = load_transaction(directory, binding)
            execute(directory, record)
            print(
                json.dumps(
                    {
                        "transaction": args.transaction_id,
                        "phase": record["phase"],
                        "revision": args.revision,
                        "receipt_directory": str(directory),
                    }
                )
            )
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        parser.exit(1, f"controller_release_failed: {error}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
