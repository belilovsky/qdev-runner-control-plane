#!/usr/bin/env python3
"""Initialize the durable Admin Platform v3 ledger from one exact release.

This is the deliberately narrow owner-authorized bootstrap used to break the
initial controller/admission cycle.  It accepts no repository, source SHA, or
receipt payload from the caller: those values are measured from the clean Git
release and the source receipt is signed locally with the controller key.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

from qdev_runner.admin_platform import AdminPlatformCandidate
from qdev_runner.admin_platform_state import (
    AdminPlatformStateError,
    AdminPlatformStateStore,
)
from qdev_runner.operations import OperationStore, format_utc, utc_now

REPOSITORY = "belilovsky/qdev-runner-control-plane"
PROGRAM_ID = "qdev-admin-platform-wave-1"
PRODUCTION_RELEASE_ROOT = Path("/opt/qdev-runner-control-plane/releases")
DEFAULT_TEMPLATE = Path("config/admin-platform-ledger-v2.yml")
DEFAULT_LEDGER = Path(
    "/var/lib/qdev-runner/admin-platform-state/admin-platform-ledger.yml"
)
DEFAULT_RECEIPT_ROOT = Path("/var/lib/qdev-runner/admin-platform-receipts")
DEFAULT_ARCHIVE_ROOT = Path("/var/lib/qdev-runner/admin-platform-ledger-migrations")
DEFAULT_SIGNER_ROOT = Path("/var/lib/qdev-runner/admin-platform-bootstrap")
DEFAULT_RUNTIME_UID = 9020
DEFAULT_RUNTIME_GID = 9020


class BootstrapError(ValueError):
    """Raised when the exact release cannot safely seed the durable ledger."""


def _git(release: Path, *arguments: str) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(release), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        raise BootstrapError("controller release Git identity is unavailable") from error
    return completed.stdout.strip()


def _exact_clean_release(release: Path) -> tuple[Path, str]:
    try:
        resolved = release.resolve(strict=True)
    except OSError as error:
        raise BootstrapError("controller release is unavailable") from error
    if not resolved.is_dir():
        raise BootstrapError("controller release is not a directory")
    root = Path(_git(resolved, "rev-parse", "--show-toplevel")).resolve(strict=True)
    if root != resolved:
        raise BootstrapError("controller release must be the Git worktree root")
    source_sha = _git(resolved, "rev-parse", "HEAD")
    if len(source_sha) != 40 or any(
        character not in "0123456789abcdef" for character in source_sha
    ):
        raise BootstrapError("controller release HEAD is not an exact source SHA")
    if _git(resolved, "status", "--porcelain=v1", "--untracked-files=all"):
        raise BootstrapError("controller release contains uncommitted files")
    return resolved, source_sha


def _require_production_boundary(release: Path, ledger: Path) -> None:
    """Keep the production default root-only and inside the release archive."""

    if ledger != DEFAULT_LEDGER:
        return
    if os.geteuid() != 0:
        raise BootstrapError("production ledger initialization requires root")
    try:
        release.relative_to(PRODUCTION_RELEASE_ROOT)
    except ValueError as error:
        raise BootstrapError(
            "production ledger initialization requires an archived controller release"
        ) from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bootstrap-admin-platform-ledger-v3",
        description="Bind the durable Admin Platform v3 ledger to one clean controller release.",
    )
    parser.add_argument("release", type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--release-id")
    parser.add_argument("--template", type=Path)
    parser.add_argument("--ledger", type=Path, default=DEFAULT_LEDGER)
    parser.add_argument("--receipt-root", type=Path, default=DEFAULT_RECEIPT_ROOT)
    parser.add_argument("--migration-archive-root", type=Path, default=DEFAULT_ARCHIVE_ROOT)
    parser.add_argument("--signer-state-root", type=Path, default=DEFAULT_SIGNER_ROOT)
    parser.add_argument("--runtime-uid", type=int)
    parser.add_argument("--runtime-gid", type=int)
    parser.add_argument("--allow-legacy-migration", action="store_true")
    return parser


def run(argv: list[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        release, source_sha = _exact_clean_release(arguments.release)
        _require_production_boundary(release, arguments.ledger)
        template = arguments.template or release / DEFAULT_TEMPLATE
        receipt_key = os.environ.get("QDEV_OPERATOR_RECEIPT_KEY", "")
        if not receipt_key:
            raise BootstrapError("QDEV_OPERATOR_RECEIPT_KEY is required")
        release_id = arguments.release_id or f"controller-v3-{source_sha[:12]}"
        candidate = AdminPlatformCandidate(
            release_id=release_id,
            repository=REPOSITORY,
            source_sha=source_sha,
            reference=arguments.reference,
        )
        signer = OperationStore(
            arguments.signer_state_root,
            worker_signing_key=receipt_key,
            receipt_signing_key=receipt_key,
        )
        observed_at = format_utc(utc_now())
        source_receipt = signer.receipt(
            {
                "kind": "admin-platform-evidence",
                "observed_at": observed_at,
                "program_id": PROGRAM_ID,
                "stage": "controller",
                "release_id": release_id,
                "source_sha": source_sha,
                "evidence_type": "lane_result",
                "lane": "source",
                "outcome": "passed",
            }
        )
        runtime_uid = arguments.runtime_uid
        runtime_gid = arguments.runtime_gid
        if arguments.ledger == DEFAULT_LEDGER:
            runtime_uid = DEFAULT_RUNTIME_UID if runtime_uid is None else runtime_uid
            runtime_gid = DEFAULT_RUNTIME_GID if runtime_gid is None else runtime_gid
        state = AdminPlatformStateStore(
            arguments.ledger,
            receipt_key=receipt_key,
            receipt_root=arguments.receipt_root,
            file_uid=runtime_uid,
            file_gid=runtime_gid,
        )
        update = state.initialize_from_template(
            template_path=template,
            candidate=candidate,
            source_receipt=source_receipt,
            allow_legacy_migration=arguments.allow_legacy_migration,
            migration_archive_root=arguments.migration_archive_root,
        )
    except (BootstrapError, AdminPlatformStateError, OSError, ValueError) as error:
        print(f"admin_platform_ledger_bootstrap_failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(update.as_dict(), sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
