"""Root-owned verification for QazCoop release admission evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, cast

from qdev_runner.controller_admission import (
    ControllerAdmissionError,
    load_json_strict,
    verify_and_consume_receipt,
    verify_receipt,
)

REPOSITORY_ID = 1_357_887_516
REPOSITORY = "belilovsky/qazcoop"
PROTECTED_REF = "refs/heads/codex/qazcoop-mvp"
PAYLOAD_PATH = "docs/acceptance/release-receipt.v3.payload.json"
CONTROLLER_PATH = "app/contracts/qdev_ci_controller.v1.json"
LOCK_PATH = "app/contracts/release_lock.v1.json"
PUBLIC_KEY_MIRROR_PATH = "app/contracts/trust/qdev-ci-controller-ed25519.pub"
EVIDENCE_ALLOWLIST = frozenset({PAYLOAD_PATH, CONTROLLER_PATH, LOCK_PATH})
RELEASABLE = frozenset({"release_ready", "released"})
EXPECTED_JOBS = {
    "reuse-first": "qdev-ci",
    "postgres-migrations": "qdev-ci-docker",
    "container-supply-chain": "qdev-ci-docker",
}
DEFAULT_TRUST_DIR = Path("/etc/qazcoop/release-controller")
DEFAULT_RECEIPT_DIR = Path("/var/lib/qazcoop/release/admissions")
DEFAULT_REPLAY_STORE = Path("/var/lib/qazcoop/release/consumed-admissions.sqlite3")
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
ADMISSION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$")


class QazCoopReleaseGuardError(ValueError):
    """Raised when product evidence is not safe to admit."""


def _git(repository: Path, *arguments: str, text: bool = True) -> str | bytes:
    try:
        result = subprocess.run(  # noqa: S603
            ["/usr/bin/git", *arguments],
            cwd=repository,
            check=True,
            capture_output=True,
            text=text,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        raise QazCoopReleaseGuardError("candidate repository cannot be inspected") from error
    return cast(str | bytes, result.stdout.strip() if text else result.stdout)


def _strict_json_bytes(raw: bytes, label: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in items:
            if key in value:
                raise QazCoopReleaseGuardError(f"{label} contains duplicate key {key}")
            value[key] = item
        return value

    def constant(value: str) -> None:
        raise QazCoopReleaseGuardError(f"{label} contains forbidden constant {value}")

    try:
        value = json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise QazCoopReleaseGuardError(f"{label} is not valid JSON") from error
    if not isinstance(value, dict):
        raise QazCoopReleaseGuardError(f"{label} must be an object")
    return value


def _object_at(repository: Path, revision: str, relative_path: str) -> dict[str, Any]:
    raw = _bytes_at(repository, revision, relative_path)
    return _strict_json_bytes(
        raw,
        relative_path,
    )


def _bytes_at(repository: Path, revision: str, relative_path: str) -> bytes:
    return cast(bytes, _git(repository, "show", f"{revision}:{relative_path}", text=False))


def _file_digest_at(repository: Path, revision: str, relative_path: str) -> str:
    return "sha256:" + hashlib.sha256(
        _bytes_at(repository, revision, relative_path)
    ).hexdigest()


def _exact_fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise QazCoopReleaseGuardError(f"{label} fields do not match the contract")


def _sha(value: object, label: str) -> str:
    if not isinstance(value, str) or SHA.fullmatch(value) is None:
        raise QazCoopReleaseGuardError(f"{label} is not a full commit SHA")
    return value


def _digest(value: object, label: str) -> str:
    if not isinstance(value, str) or DIGEST.fullmatch(value) is None:
        raise QazCoopReleaseGuardError(f"{label} is not a SHA-256 digest")
    return value


def _mapping(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise QazCoopReleaseGuardError(f"{label} must be an object")
    return value


def _non_negative(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise QazCoopReleaseGuardError(f"{label} must be a non-negative integer")
    return value


def _admission_id(value: object) -> str:
    if not isinstance(value, str) or ADMISSION_ID.fullmatch(value) is None:
        raise QazCoopReleaseGuardError("controller admission ID is invalid")
    return value


def _require_trusted_directory(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_dir():
        raise QazCoopReleaseGuardError(f"{label} is unavailable")
    status = path.stat()
    if status.st_uid not in {0, os.geteuid()} or stat.S_IMODE(status.st_mode) & 0o022:
        raise QazCoopReleaseGuardError(f"{label} is not owner controlled")


def _load_bundle_manifest(trust_dir: Path) -> dict[str, Any]:
    _require_trusted_directory(trust_dir, "release trust directory")
    manifest_path = trust_dir / "bundle.json"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        raise QazCoopReleaseGuardError("release trust manifest is unavailable")
    manifest = load_json_strict(manifest_path)
    if not isinstance(manifest, dict):
        raise QazCoopReleaseGuardError("release trust manifest must be an object")
    _exact_fields(
        manifest,
        {"contract", "controller_revision", "repository", "files"},
        "release trust manifest",
    )
    if manifest["contract"] != "qazcoop-release-guard-trust-bundle/v1":
        raise QazCoopReleaseGuardError("release trust bundle contract is invalid")
    _sha(manifest["controller_revision"], "bundle controller revision")
    repository = manifest["repository"]
    if repository != {
        "id": REPOSITORY_ID,
        "full_name": REPOSITORY,
        "protected_ref": PROTECTED_REF,
    }:
        raise QazCoopReleaseGuardError("release trust repository identity is invalid")
    files = manifest["files"]
    expected_files = {
        "public.pem",
        "admission.schema.json",
        "key-canary.json",
        "controller_admission.py",
        "qazcoop_release_guard.py",
        "qdev_runner.__init__.py",
        "qdev-controller-verify-admission",
        "qazcoop-update",
    }
    if not isinstance(files, dict) or set(files) != expected_files:
        raise QazCoopReleaseGuardError("release trust file manifest is invalid")
    for name, expected_digest in files.items():
        _digest(expected_digest, f"release trust file digest for {name}")
        if name in {"public.pem", "admission.schema.json", "key-canary.json"}:
            candidate = trust_dir / name
        elif name == "qazcoop_release_guard.py":
            candidate = Path(__file__)
        elif name == "controller_admission.py":
            from qdev_runner import controller_admission

            candidate = Path(str(controller_admission.__file__))
        elif name == "qdev_runner.__init__.py":
            from qdev_runner import __file__ as package_file

            candidate = Path(str(package_file))
        elif name == "qdev-controller-verify-admission":
            launcher = os.environ.get("QAZCOOP_GUARD_LAUNCHER")
            if not launcher:
                raise QazCoopReleaseGuardError("release guard launcher identity is unavailable")
            candidate = Path(launcher)
        else:
            hook = os.environ.get("QAZCOOP_GUARD_HOOK")
            if not hook:
                raise QazCoopReleaseGuardError("release guard hook identity is unavailable")
            candidate = Path(hook)
        if candidate.is_symlink() or not candidate.is_file():
            raise QazCoopReleaseGuardError(f"trusted file is unavailable: {name}")
        status = candidate.stat()
        if status.st_uid not in {0, os.geteuid()} or stat.S_IMODE(status.st_mode) & 0o022:
            raise QazCoopReleaseGuardError(f"trusted file is not owner controlled: {name}")
        observed = "sha256:" + hashlib.sha256(candidate.read_bytes()).hexdigest()
        if observed != expected_digest:
            raise QazCoopReleaseGuardError(f"trusted file digest mismatch: {name}")
    return manifest


def _validate_releasable_payload(payload: Mapping[str, Any], functional_sha: str) -> None:
    """Validate release-critical v3 fields without running candidate code."""

    _exact_fields(
        payload,
        {
            "contract",
            "status",
            "scope",
            "functional_source_sha",
            "artifact_identity",
            "browser_acceptance",
            "restore",
            "previous_release",
            "rollback",
            "controller_admission",
            "supply_chain",
        },
        "release payload",
    )
    artifact = _mapping(payload["artifact_identity"], "artifact identity")
    _exact_fields(
        artifact,
        {
            "application_image_digest",
            "retention_image_digest",
            "migration_head",
            "edge_config_sha256",
        },
        "artifact identity",
    )
    for field in (
        "application_image_digest",
        "retention_image_digest",
        "edge_config_sha256",
    ):
        _digest(artifact[field], f"artifact identity {field}")
    if not isinstance(artifact["migration_head"], str) or not artifact["migration_head"]:
        raise QazCoopReleaseGuardError("artifact migration head is unavailable")

    browser = _mapping(payload["browser_acceptance"], "browser acceptance")
    _exact_fields(
        browser,
        {
            "observed_source_sha",
            "status",
            "artifact",
            "artifact_sha256",
            "routes_total",
            "batch_checked",
            "browser_cases",
            "passed",
            "failed",
            "auth_blocked",
            "not_applicable",
            "acceptance_rule",
        },
        "browser acceptance",
    )
    if browser["observed_source_sha"] != functional_sha or browser["status"] != "verified":
        raise QazCoopReleaseGuardError("browser acceptance is not bound and verified")
    _digest(browser["artifact_sha256"], "browser artifact digest")
    counts = {
        field: _non_negative(browser[field], f"browser acceptance {field}")
        for field in (
            "routes_total",
            "batch_checked",
            "browser_cases",
            "passed",
            "failed",
            "auth_blocked",
            "not_applicable",
        )
    }
    if counts["batch_checked"] != counts["routes_total"]:
        raise QazCoopReleaseGuardError("browser route coverage is incomplete")
    if counts["failed"] or counts["auth_blocked"]:
        raise QazCoopReleaseGuardError("browser acceptance contains failed or blocked cases")
    if counts["passed"] + counts["not_applicable"] != counts["browser_cases"]:
        raise QazCoopReleaseGuardError("browser case accounting is incomplete")

    restore = _mapping(payload["restore"], "restore")
    _exact_fields(
        restore,
        {
            "observed_source_sha",
            "status",
            "backup_id",
            "backup_sha256",
            "receipt_sha256",
            "control_document_sha256",
            "measured_rpo_seconds",
            "measured_rto_seconds",
            "evidence_gap",
        },
        "restore",
    )
    if restore["observed_source_sha"] != functional_sha or restore["status"] != "verified":
        raise QazCoopReleaseGuardError("restore is not bound and verified")
    for field in ("backup_sha256", "receipt_sha256", "control_document_sha256"):
        _digest(restore[field], f"restore {field}")
    if _non_negative(restore["measured_rpo_seconds"], "restore RPO") > 86_400:
        raise QazCoopReleaseGuardError("restore RPO exceeds 24 hours")
    if _non_negative(restore["measured_rto_seconds"], "restore RTO") > 7_200:
        raise QazCoopReleaseGuardError("restore RTO exceeds two hours")
    if restore["evidence_gap"] not in {None, ""}:
        raise QazCoopReleaseGuardError("restore still contains an evidence gap")

    rollback = _mapping(payload["rollback"], "rollback")
    _exact_fields(
        rollback,
        {
            "status",
            "application_image_digest",
            "retention_image_digest",
            "historical_tags",
            "reason",
        },
        "rollback",
    )
    if rollback["status"] != "verified":
        raise QazCoopReleaseGuardError("rollback is not verified")
    _digest(rollback["application_image_digest"], "rollback application digest")
    _digest(rollback["retention_image_digest"], "rollback retention digest")
    tags = rollback["historical_tags"]
    if (
        not isinstance(tags, list)
        or any(not isinstance(tag, str) or not tag for tag in tags)
        or len(tags) != len(set(tags))
    ):
        raise QazCoopReleaseGuardError("rollback historical tags are invalid")
    if not isinstance(rollback["reason"], str) or not rollback["reason"]:
        raise QazCoopReleaseGuardError("rollback reason is unavailable")

    supply = _mapping(payload["supply_chain"], "supply chain")
    _exact_fields(supply, {"sbom_sha256", "provenance_sha256", "status"}, "supply chain")
    if supply["status"] != "verified":
        raise QazCoopReleaseGuardError("supply chain evidence is not verified")
    _digest(supply["sbom_sha256"], "SBOM digest")
    _digest(supply["provenance_sha256"], "provenance digest")

    previous = _mapping(payload["previous_release"], "previous release")
    _exact_fields(
        previous,
        {"functional_source_sha", "application_image_digest", "evidence_status"},
        "previous release",
    )
    _sha(previous["functional_source_sha"], "previous release source SHA")
    _digest(previous["application_image_digest"], "previous release image digest")
    if not isinstance(previous["evidence_status"], str) or not previous["evidence_status"]:
        raise QazCoopReleaseGuardError("previous release evidence status is unavailable")


def validate_evidence_commit(
    repository: Path,
    evidence_commit_sha: str,
    protected_ref: str,
) -> tuple[dict[str, Any], dict[str, Any], str]:
    """Validate immutable product evidence without executing candidate code."""

    evidence_sha = _sha(evidence_commit_sha, "evidence commit SHA")
    if protected_ref != PROTECTED_REF:
        raise QazCoopReleaseGuardError("protected ref does not match QazCoop policy")
    repository = repository.resolve(strict=True)
    parents = str(_git(repository, "rev-list", "--parents", "-n", "1", evidence_sha)).split()
    if len(parents) != 2:
        raise QazCoopReleaseGuardError("evidence commit must have one direct parent")
    functional_sha = parents[1]
    changed = {
        line
        for line in str(
            _git(
                repository,
                "diff-tree",
                "--no-commit-id",
                "--name-only",
                "-r",
                functional_sha,
                evidence_sha,
            )
        ).splitlines()
        if line
    }
    if changed != EVIDENCE_ALLOWLIST:
        raise QazCoopReleaseGuardError("evidence commit changed files outside the exact allowlist")
    for relative_path in EVIDENCE_ALLOWLIST:
        listing = str(_git(repository, "ls-tree", evidence_sha, "--", relative_path)).split()
        if len(listing) < 4 or listing[0] not in {"100644", "100755"}:
            raise QazCoopReleaseGuardError(
                f"evidence path is not a regular Git file: {relative_path}"
            )

    payload = _object_at(repository, evidence_sha, PAYLOAD_PATH)
    controller = _object_at(repository, evidence_sha, CONTROLLER_PATH)
    release_lock = _object_at(repository, evidence_sha, LOCK_PATH)
    if payload.get("contract") != "qazcoop-release-receipt-payload/v3":
        raise QazCoopReleaseGuardError("release payload contract is invalid")
    if payload.get("status") not in {"acceptance_incomplete", *RELEASABLE}:
        raise QazCoopReleaseGuardError("release payload status is invalid")
    if payload.get("functional_source_sha") != functional_sha:
        raise QazCoopReleaseGuardError("release payload is not bound to its direct parent")
    _exact_fields(
        release_lock,
        {"contract", "status", "functional_source_sha", "public_marker"},
        "release lock",
    )
    if (
        release_lock.get("contract") != "qazcoop-release-lock/v1"
        or release_lock.get("status") != "active"
        or release_lock.get("functional_source_sha") != functional_sha
        or release_lock.get("public_marker") != f"qazcoop-{functional_sha[:7]}"
    ):
        raise QazCoopReleaseGuardError("release lock is not bound to the functional parent")
    if controller.get("contract") != "qdev-ci-controller-admission/v1":
        raise QazCoopReleaseGuardError("controller contract is invalid")
    _exact_fields(
        controller,
        {
            "contract",
            "project_id",
            "repository",
            "protected_branch",
            "requested_functional_source_sha",
            "required_profiles",
            "registration_status",
            "admission_status",
            "admission_id",
            "claim_id",
            "external_verifier",
            "trust",
            "evidence_gap",
            "claim_boundary",
        },
        "controller",
    )
    expected_controller = {
        "project_id": "qazcoop",
        "repository": REPOSITORY,
        "protected_branch": PROTECTED_REF.removeprefix("refs/heads/"),
        "requested_functional_source_sha": functional_sha,
    }
    for field, expected in expected_controller.items():
        if controller.get(field) != expected:
            raise QazCoopReleaseGuardError(f"controller {field} does not match release evidence")
    if controller.get("required_profiles") != list(EXPECTED_JOBS):
        raise QazCoopReleaseGuardError("controller required profiles do not match QazCoop policy")
    if payload["status"] in RELEASABLE:
        _validate_releasable_payload(payload, functional_sha)
    return payload, controller, functional_sha


def verify_qazcoop_admission(
    *,
    repository: Path,
    protected_ref: str,
    evidence_commit_sha: str,
    require_authoritative: bool,
    trust_dir: Path,
    receipt_dir: Path,
    replay_store: Path,
) -> dict[str, Any]:
    manifest = _load_bundle_manifest(trust_dir)
    payload, controller, functional_sha = validate_evidence_commit(
        repository, evidence_commit_sha, protected_ref
    )
    release_admission = payload.get("controller_admission")
    if not isinstance(release_admission, dict):
        raise QazCoopReleaseGuardError("release controller admission is invalid")
    _exact_fields(
        release_admission,
        {"status", "contract_path", "admission_id", "claim_id"},
        "release controller admission",
    )
    if release_admission.get("contract_path") != CONTROLLER_PATH:
        raise QazCoopReleaseGuardError("release controller contract path is invalid")
    admission_status = release_admission.get("status")
    controller_status = controller.get("admission_status")
    if admission_status != controller_status:
        raise QazCoopReleaseGuardError("controller admission status differs between evidence files")
    if payload["status"] == "acceptance_incomplete":
        if require_authoritative:
            raise QazCoopReleaseGuardError("authoritative admission requires a releasable payload")
        if (
            admission_status != "not_obtained"
            or release_admission.get("admission_id") is not None
            or release_admission.get("claim_id") is not None
        ):
            raise QazCoopReleaseGuardError("incomplete evidence cannot claim admission")
        return {"state": "evidence_valid", "functional_source_sha": functional_sha}

    if payload["status"] not in RELEASABLE or admission_status != "external_required":
        raise QazCoopReleaseGuardError("releasable evidence requires external admission")
    admission_id = _admission_id(release_admission.get("admission_id"))
    claim_id = _admission_id(release_admission.get("claim_id"))
    if (
        controller.get("admission_id") != admission_id
        or controller.get("claim_id") != claim_id
        or controller.get("registration_status") != "confirmed"
    ):
        raise QazCoopReleaseGuardError("controller registration or admission binding is invalid")
    verifier = controller.get("external_verifier")
    expected_verifier = {
        "delivery": "root_owned_controller_bundle",
        "protected_environment": "qazcoop-release-admission",
        "controller_repository": "belilovsky/qdev-runner-control-plane",
        "controller_revision": manifest["controller_revision"],
        "bundle_contract": "qazcoop-release-guard-trust-bundle/v1",
    }
    if verifier != expected_verifier:
        raise QazCoopReleaseGuardError("controller revision differs from installed trust bundle")
    trust = _mapping(controller.get("trust"), "controller trust")
    _exact_fields(
        trust,
        {
            "signature_algorithm",
            "trust_root_id",
            "verifier_sha256",
            "schema_sha256",
            "public_key_sha256",
            "public_key_mirror_path",
        },
        "controller trust",
    )
    if trust["signature_algorithm"] != "ed25519":
        raise QazCoopReleaseGuardError("controller trust algorithm is invalid")
    if trust["trust_root_id"] != "qdev-ci-controller-production-v1":
        raise QazCoopReleaseGuardError("controller trust root is invalid")
    if trust["public_key_mirror_path"] != PUBLIC_KEY_MIRROR_PATH:
        raise QazCoopReleaseGuardError("controller public key mirror path is invalid")
    expected_trust = {
        "verifier_sha256": manifest["files"]["qazcoop_release_guard.py"],
        "schema_sha256": manifest["files"]["admission.schema.json"],
        "public_key_sha256": manifest["files"]["public.pem"],
    }
    for field, expected in expected_trust.items():
        if trust.get(field) != expected:
            raise QazCoopReleaseGuardError(f"controller trust {field} differs from bundle")
    mirrored_public_key = cast(
        bytes,
        _git(repository, "show", f"{evidence_commit_sha}:{PUBLIC_KEY_MIRROR_PATH}", text=False),
    )
    if mirrored_public_key != (trust_dir / "public.pem").read_bytes():
        raise QazCoopReleaseGuardError("tracked controller public key differs from trust root")
    receipt_path = receipt_dir / f"{admission_id}.json"
    _require_trusted_directory(receipt_dir, "admission receipt directory")
    if (
        receipt_path.parent != receipt_dir
        or receipt_path.is_symlink()
        or not receipt_path.is_file()
    ):
        raise QazCoopReleaseGuardError("admission receipt is unavailable")
    receipt_status = receipt_path.stat()
    if receipt_status.st_uid not in {0, os.geteuid()} or stat.S_IMODE(
        receipt_status.st_mode
    ) & 0o022:
        raise QazCoopReleaseGuardError("admission receipt is not owner controlled")
    receipt = load_json_strict(receipt_path)
    receipt_root = _mapping(receipt, "controller receipt")
    signed_payload = _mapping(receipt_root.get("payload"), "controller receipt payload")
    workflow = _mapping(signed_payload.get("workflow"), "controller receipt workflow")
    workflow_run_id = _non_negative(workflow.get("run_id"), "workflow run ID")
    workflow_run_attempt = _non_negative(
        workflow.get("run_attempt"), "workflow run attempt"
    )
    if workflow_run_id == 0 or workflow_run_attempt == 0:
        raise QazCoopReleaseGuardError("controller workflow identity must be positive")
    required_jobs = signed_payload.get("required_jobs")
    if not isinstance(required_jobs, list):
        raise QazCoopReleaseGuardError("controller receipt required jobs are invalid")
    job_ids: dict[str, int] = {}
    for index, raw_job in enumerate(required_jobs):
        job = _mapping(raw_job, f"controller receipt job {index}")
        name = job.get("name")
        job_id = _non_negative(job.get("job_id"), f"controller receipt job {index} ID")
        if not isinstance(name, str) or name in job_ids or job_id == 0:
            raise QazCoopReleaseGuardError("controller receipt job identity is invalid")
        job_ids[name] = job_id
    if set(job_ids) != set(EXPECTED_JOBS):
        raise QazCoopReleaseGuardError("controller receipt job set is invalid")
    expected_evidence = {
        "release_payload_sha256": _file_digest_at(
            repository, evidence_commit_sha, PAYLOAD_PATH
        ),
        "controller_contract_sha256": _file_digest_at(
            repository, evidence_commit_sha, CONTROLLER_PATH
        ),
        "release_lock_sha256": _file_digest_at(
            repository, evidence_commit_sha, LOCK_PATH
        ),
    }
    if require_authoritative:
        verified = verify_and_consume_receipt(
            receipt,
            trust_dir / "public.pem",
            replay_store,
            consumer=f"qazcoop-{evidence_commit_sha[:16]}",
            now=None,
            expected_repository_id=REPOSITORY_ID,
            expected_repository=REPOSITORY,
            expected_ref=PROTECTED_REF,
            expected_sha=functional_sha,
            expected_evidence=expected_evidence,
            expected_controller_revision=str(manifest["controller_revision"]),
            expected_admission_id=admission_id,
            expected_claim_id=claim_id,
            expected_jobs=EXPECTED_JOBS,
            expected_workflow_run_id=workflow_run_id,
            expected_workflow_run_attempt=workflow_run_attempt,
            expected_job_ids=job_ids,
        )
    else:
        verified = verify_receipt(
            receipt,
            trust_dir / "public.pem",
            now=None,
            expected_repository_id=REPOSITORY_ID,
            expected_repository=REPOSITORY,
            expected_ref=PROTECTED_REF,
            expected_sha=functional_sha,
            expected_evidence=expected_evidence,
            expected_controller_revision=str(manifest["controller_revision"]),
            expected_admission_id=admission_id,
            expected_claim_id=claim_id,
            expected_jobs=EXPECTED_JOBS,
        )
    verified_admission = verified.get("admission")
    if not isinstance(verified_admission, dict) or verified_admission.get("id") != admission_id:
        raise QazCoopReleaseGuardError("signed receipt admission ID does not match evidence")
    return {
        "state": "admission_consumed" if require_authoritative else "admission_verified",
        "functional_source_sha": functional_sha,
        "admission_id": admission_id,
        "claim_id": claim_id,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    verify = subparsers.add_parser("verify-qazcoop-admission")
    verify.add_argument("--repository", required=True, type=Path)
    verify.add_argument("--protected-ref", required=True)
    verify.add_argument("--evidence-commit-sha", required=True)
    verify.add_argument("--require-authoritative-admission", action="store_true")
    verify.add_argument("--trust-dir", type=Path, default=DEFAULT_TRUST_DIR)
    verify.add_argument("--receipt-dir", type=Path, default=DEFAULT_RECEIPT_DIR)
    verify.add_argument("--replay-store", type=Path, default=DEFAULT_REPLAY_STORE)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = verify_qazcoop_admission(
            repository=args.repository,
            protected_ref=args.protected_ref,
            evidence_commit_sha=args.evidence_commit_sha,
            require_authoritative=args.require_authoritative_admission,
            trust_dir=args.trust_dir,
            receipt_dir=args.receipt_dir,
            replay_store=args.replay_store,
        )
    except (ControllerAdmissionError, QazCoopReleaseGuardError, OSError) as error:
        print(f"QazCoop admission rejected: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
