"""Create and verify source-bound controller image candidate receipts."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

SCHEMA = "qdev-controller-image-candidate-receipt-v1"
REPOSITORY = "registry.ci.qdev.run/qdev-runner-control-plane"
WORKFLOW = ".github/workflows/controller-image-candidate.yml"
BUILDER_PROFILE = "qdev-ci-docker"
BASE_IMAGE = "python:3.12.11-slim-bookworm"
_SHA = re.compile(r"^[0-9a-f]{40}$")
_HEX_DIGEST = re.compile(r"^[0-9a-f]{64}$")
_OCI_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_RUN_ID = re.compile(r"^[1-9][0-9]*$")


class CandidateReceiptError(ValueError):
    """The image candidate receipt is malformed or not source-bound."""


def _canonical(payload: object) -> bytes:
    return json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()


def _timestamp(value: str) -> str:
    if not value.endswith("Z"):
        raise CandidateReceiptError("created_at must be UTC")
    try:
        parsed = datetime.fromisoformat(value.removesuffix("Z") + "+00:00")
    except ValueError as error:
        raise CandidateReceiptError("created_at is invalid") from error
    if parsed.tzinfo != UTC:
        raise CandidateReceiptError("created_at must be UTC")
    return value


def receipt_digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def create(
    *,
    source_revision: str,
    bundle_digest: str,
    image_digest: str,
    base_image_digest: str,
    wheelhouse_digest: str,
    requirements_digest: str,
    sbom_digest: str,
    run_id: str,
    run_attempt: int,
    job: str,
    created_at: str,
) -> dict[str, Any]:
    if not _SHA.fullmatch(source_revision):
        raise CandidateReceiptError("source revision is invalid")
    if not _HEX_DIGEST.fullmatch(bundle_digest):
        raise CandidateReceiptError("bundle digest is invalid")
    if not _OCI_DIGEST.fullmatch(image_digest):
        raise CandidateReceiptError("image digest is invalid")
    if not _OCI_DIGEST.fullmatch(base_image_digest):
        raise CandidateReceiptError("base image digest is invalid")
    for name, value in (
        ("wheelhouse", wheelhouse_digest),
        ("requirements", requirements_digest),
        ("sbom", sbom_digest),
    ):
        if not _HEX_DIGEST.fullmatch(value):
            raise CandidateReceiptError(f"{name} digest is invalid")
    if not _RUN_ID.fullmatch(run_id):
        raise CandidateReceiptError("run id is invalid")
    if run_attempt < 1:
        raise CandidateReceiptError("run attempt is invalid")
    if job != "controller-image-candidate":
        raise CandidateReceiptError("job identity is invalid")
    payload = {
        "schema": SCHEMA,
        "repository": REPOSITORY,
        "source_revision": source_revision,
        "bundle_digest": bundle_digest,
        "image_digest": image_digest,
        "image_ref": f"{REPOSITORY}@{image_digest}",
        "base_image": BASE_IMAGE,
        "base_image_digest": base_image_digest,
        "wheelhouse_digest": wheelhouse_digest,
        "requirements_digest": requirements_digest,
        "sbom_digest": sbom_digest,
        "builder_profile": BUILDER_PROFILE,
        "workflow": WORKFLOW,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "job": job,
        "created_at": _timestamp(created_at),
    }
    return {**payload, "receipt_digest": receipt_digest(payload)}


def verify(payload: object) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise CandidateReceiptError("receipt must be an object")
    expected_keys = {
        "schema",
        "repository",
        "source_revision",
        "bundle_digest",
        "image_digest",
        "image_ref",
        "base_image",
        "base_image_digest",
        "wheelhouse_digest",
        "requirements_digest",
        "sbom_digest",
        "builder_profile",
        "workflow",
        "run_id",
        "run_attempt",
        "job",
        "created_at",
        "receipt_digest",
    }
    if set(payload) != expected_keys:
        raise CandidateReceiptError("receipt shape is invalid")
    source_revision = payload.get("source_revision")
    bundle_digest_value = payload.get("bundle_digest")
    image_digest = payload.get("image_digest")
    base_image_digest = payload.get("base_image_digest")
    wheelhouse_digest = payload.get("wheelhouse_digest")
    requirements_digest = payload.get("requirements_digest")
    sbom_digest = payload.get("sbom_digest")
    run_id = payload.get("run_id")
    run_attempt = payload.get("run_attempt")
    job = payload.get("job")
    created_at = payload.get("created_at")
    if (
        not isinstance(source_revision, str)
        or not isinstance(bundle_digest_value, str)
        or not isinstance(image_digest, str)
        or not isinstance(base_image_digest, str)
        or not isinstance(wheelhouse_digest, str)
        or not isinstance(requirements_digest, str)
        or not isinstance(sbom_digest, str)
        or not isinstance(run_id, str)
        or not isinstance(run_attempt, int)
        or not isinstance(job, str)
        or not isinstance(created_at, str)
    ):
        raise CandidateReceiptError("receipt field types are invalid")
    recreated = create(
        source_revision=source_revision,
        bundle_digest=bundle_digest_value,
        image_digest=image_digest,
        base_image_digest=base_image_digest,
        wheelhouse_digest=wheelhouse_digest,
        requirements_digest=requirements_digest,
        sbom_digest=sbom_digest,
        run_id=run_id,
        run_attempt=run_attempt,
        job=job,
        created_at=created_at,
    )
    if payload != recreated:
        raise CandidateReceiptError("receipt identity mismatch")
    return recreated


def main() -> int:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="command", required=True)
    create_parser = subparsers.add_parser("create")
    create_parser.add_argument("--source-revision", required=True)
    create_parser.add_argument("--bundle-digest", required=True)
    create_parser.add_argument("--image-digest", required=True)
    create_parser.add_argument("--base-image-digest", required=True)
    create_parser.add_argument("--wheelhouse-digest", required=True)
    create_parser.add_argument("--requirements-digest", required=True)
    create_parser.add_argument("--sbom-digest", required=True)
    create_parser.add_argument("--run-id", required=True)
    create_parser.add_argument("--run-attempt", type=int, required=True)
    create_parser.add_argument("--job", required=True)
    create_parser.add_argument("--created-at", required=True)
    create_parser.add_argument("--output", type=Path, required=True)
    verify_parser = subparsers.add_parser("verify")
    verify_parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    try:
        if args.command == "create":
            result = create(
                source_revision=args.source_revision,
                bundle_digest=args.bundle_digest,
                image_digest=args.image_digest,
                base_image_digest=args.base_image_digest,
                wheelhouse_digest=args.wheelhouse_digest,
                requirements_digest=args.requirements_digest,
                sbom_digest=args.sbom_digest,
                run_id=args.run_id,
                run_attempt=args.run_attempt,
                job=args.job,
                created_at=args.created_at,
            )
            args.output.write_bytes(_canonical(result) + b"\n")
        else:
            result = verify(json.loads(args.receipt.read_text(encoding="utf-8")))
    except (CandidateReceiptError, OSError, UnicodeDecodeError, json.JSONDecodeError, TypeError):
        print("controller_image_candidate_receipt_invalid")
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
