#!/usr/bin/env python3
"""Audit every active runner repository at its freshly resolved default SHA.

The canonical workflow scanner is reused rather than reimplemented. This
wrapper binds every result to the GitHub default branch and commit observed at
the start of that repository audit, preventing stale inventory records or a
moving branch from being reported as a clean default-branch audit.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
import tempfile
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "qdev-ci-default-branch-audit-v1"
INVENTORY_SCHEMA = "qdev-runner-inventory-v1"
EXACT_SHA = re.compile(r"^[0-9a-f]{40}$")


class AuditError(RuntimeError):
    """A receipt cannot be safely bound to its authoritative source."""


def load_auditor() -> ModuleType:
    """Load the canonical workflow auditor from this release tree."""

    path = ROOT / "scripts" / "audit_workflows.py"
    spec = importlib.util.spec_from_file_location("qdev_workflow_auditor", path)
    if spec is None or spec.loader is None:
        raise AuditError("workflow auditor is unavailable")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def load_inventory(path: Path) -> tuple[dict[str, Any], ...]:
    """Load only active, identity-bound runner repository records."""

    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise AuditError("inventory is unreadable") from exc
    if not isinstance(document, Mapping) or document.get("schema_version") != INVENTORY_SCHEMA:
        raise AuditError("inventory schema is invalid")
    repositories = document.get("repositories")
    if not isinstance(repositories, list):
        raise AuditError("inventory repositories are invalid")

    selected: list[dict[str, Any]] = []
    seen_ids: set[int] = set()
    seen_names: set[str] = set()
    for record in repositories:
        if not isinstance(record, Mapping):
            raise AuditError("inventory repository is invalid")
        repository_id = record.get("id")
        full_name = record.get("full_name")
        default_branch = record.get("default_branch")
        archived = record.get("archived")
        if (
            not isinstance(repository_id, int)
            or repository_id <= 0
            or not isinstance(full_name, str)
            or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", full_name)
            or not isinstance(default_branch, str)
            or not default_branch.strip()
            or not isinstance(archived, bool)
        ):
            raise AuditError("inventory repository identity is invalid")
        if archived:
            continue
        identity = full_name.lower()
        if repository_id in seen_ids or identity in seen_names:
            raise AuditError("inventory contains duplicate active repository identity")
        seen_ids.add(repository_id)
        seen_names.add(identity)
        selected.append(
            {"id": repository_id, "full_name": full_name, "default_branch": default_branch}
        )
    return tuple(sorted(selected, key=lambda item: item["full_name"].lower()))


def _metadata(auditor: ModuleType, record: Mapping[str, Any]) -> tuple[str, str]:
    """Resolve one repository's current default branch and exact head commit."""

    full_name = str(record["full_name"])
    metadata = auditor.gh_api(f"/repos/{full_name}")
    if not isinstance(metadata, Mapping):
        raise AuditError("github repository metadata is invalid")
    if metadata.get("id") != record["id"] or metadata.get("full_name") != full_name:
        raise AuditError("repository identity drift")
    default_branch = metadata.get("default_branch")
    if not isinstance(default_branch, str) or not default_branch:
        raise AuditError("github default branch is invalid")
    if default_branch != record["default_branch"]:
        raise AuditError("inventory default branch drift")

    reference = auditor.gh_api(f"/repos/{full_name}/git/ref/heads/{quote(default_branch, safe='')}")
    if not isinstance(reference, Mapping):
        raise AuditError("github default ref is invalid")
    target = reference.get("object")
    if not isinstance(target, Mapping) or target.get("type") != "commit":
        raise AuditError("github default ref is not a commit")
    sha = target.get("sha")
    if not isinstance(sha, str) or EXACT_SHA.fullmatch(sha) is None:
        raise AuditError("github default ref SHA is invalid")
    return default_branch, sha


def audit_record(auditor: ModuleType, record: Mapping[str, Any]) -> dict[str, Any]:
    """Produce one identity- and SHA-bound result without provider mutation."""

    full_name = str(record["full_name"])
    try:
        default_branch, revision = _metadata(auditor, record)
        result = auditor.audit_repository(
            {"full_name": full_name, "default_branch": default_branch}, revision
        )
        violations = result.get("violations") if isinstance(result, Mapping) else None
        if not isinstance(violations, list):
            raise AuditError("workflow auditor returned an invalid result")
        return {
            "repository": full_name,
            "repository_id": record["id"],
            "default_branch": default_branch,
            "revision": revision,
            "status": "passed" if not violations else "violations",
            "violations": violations,
        }
    except Exception as exc:  # Receipt remains complete even if one repo is unavailable.
        return {
            "repository": full_name,
            "repository_id": record["id"],
            "status": "unverifiable",
            "error": str(exc),
        }


def build_report(inventory: Path, *, workers: int = 4) -> dict[str, Any]:
    """Audit the complete active inventory, bounded to sixteen read-only workers."""

    if workers < 1 or workers > 16:
        raise AuditError("workers must be between 1 and 16")
    auditor = load_auditor()
    records = load_inventory(inventory)
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=workers) as executor:
        futures = [executor.submit(audit_record, auditor, record) for record in records]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: str(item["repository"]).lower())
    passed = sum(item["status"] == "passed" for item in results)
    violations = sum(len(item.get("violations", [])) for item in results)
    unverifiable = sum(item["status"] == "unverifiable" for item in results)
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "inventory_path": str(inventory),
        "repositories": len(results),
        "passed": passed,
        "violations": violations,
        "unverifiable": unverifiable,
        "critical_violations": violations + unverifiable,
        "results": results,
    }


def write_report(path: Path, report: Mapping[str, Any]) -> None:
    """Write a root-private receipt atomically without following a symlink."""

    if path.exists() and path.is_symlink():
        raise AuditError("audit output must not be a symlink")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(report, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    except Exception:
        Path(temporary_name).unlink(missing_ok=True)
        raise


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=ROOT / "inventory" / "repos.json")
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--workers", type=int, default=4)
    args = parser.parse_args(argv)
    try:
        report = build_report(args.inventory, workers=args.workers)
        write_report(args.output, report)
    except AuditError as exc:
        print(f"default branch audit error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({key: report[key] for key in report if key != "results"}, sort_keys=True))
    return 1 if report["critical_violations"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
