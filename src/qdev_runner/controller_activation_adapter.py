"""Install and activate one exact controller OCI artifact.

This is the fixed root-owned native helper behind the privileged bootstrap
executor.  It accepts no hostname, executable, compose path or mutable tag.
The image is both the broker runtime and the transport for the independently
verified controller filesystem bundle.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from .controller_release_bundle import BundleError
from .controller_release_bundle import verify as verify_bundle
from .controller_transaction import Paths, TransactionError, activate, rollback_accepted
from .fleet_bootstrap_operation_executor import RESULT_SCHEMA
from .privileged_bootstrap_client import MAX_MESSAGE_BYTES

IMAGE_REPOSITORY = "registry.ci.qdev.run/qdev-runner-control-plane"
IMAGE_SCHEMA = "qdev-controller-release-image-v1"
IMAGE_BUNDLE_PATH = "/opt/qdev-controller-release"
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_BUNDLE_DIGEST = re.compile(r"[0-9a-f]{64}")
_FENCE = re.compile(r"[0-9a-f]{64}")


class ActivationAdapterError(RuntimeError):
    """The immutable artifact cannot be safely installed or activated."""


def _run(argv: list[str], *, timeout: int = 900) -> str:
    try:
        result = subprocess.run(  # noqa: S603
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise ActivationAdapterError("controller artifact operation unavailable") from error
    if result.returncode:
        raise ActivationAdapterError("controller artifact operation failed")
    return result.stdout.strip()


def _object(value: str, *, message: str) -> dict[str, Any]:
    try:
        parsed = json.loads(value)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ActivationAdapterError(message) from error
    if not isinstance(parsed, dict):
        raise ActivationAdapterError(message)
    return parsed


def _image_identity(reference: str, revision: str) -> tuple[str, str]:
    try:
        values = json.loads(_run(["docker", "image", "inspect", reference]))
    except json.JSONDecodeError as error:
        raise ActivationAdapterError("controller image identity unavailable") from error
    if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
        raise ActivationAdapterError("controller image identity unavailable")
    record = values[0]
    image_id = record.get("Id")
    repo_digests = record.get("RepoDigests")
    config = record.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    bundle_digest = (
        labels.get("run.qdev.controller.bundle-digest") if isinstance(labels, dict) else None
    )
    if (
        not isinstance(image_id, str)
        or not _DIGEST.fullmatch(image_id)
        or not isinstance(repo_digests, list)
        or reference not in repo_digests
        or not isinstance(labels, dict)
        or labels.get("org.opencontainers.image.revision") != revision
        or labels.get("run.qdev.controller.schema") != IMAGE_SCHEMA
        or not isinstance(bundle_digest, str)
        or not _BUNDLE_DIGEST.fullmatch(bundle_digest)
    ):
        raise ActivationAdapterError("controller image identity mismatch")
    return image_id, bundle_digest


def _root_owned_tree(root: Path) -> None:
    for path in (root, *sorted(root.rglob("*"))):
        metadata = path.lstat()
        if path.is_symlink():
            raise ActivationAdapterError("controller bundle contains a symbolic link")
        os.chown(path, 0, 0)
        if metadata.st_mode & 0o022:
            raise ActivationAdapterError("controller bundle permissions are unsafe")


def _install_bundle(*, reference: str, revision: str, bundle_digest: str, releases: Path) -> Path:
    releases.mkdir(parents=True, mode=0o755, exist_ok=True)
    final = releases / f"{revision}-{bundle_digest[:12]}"
    if final.exists() or final.is_symlink():
        try:
            verify_bundle(final, source_revision=revision, expected_digest=bundle_digest)
        except (BundleError, OSError, ValueError) as error:
            raise ActivationAdapterError("installed controller bundle identity mismatch") from error
        return final
    staging = Path(tempfile.mkdtemp(prefix=".incoming-controller-", dir=releases))
    container_id = ""
    try:
        container_id = _run(["docker", "create", reference], timeout=120)
        if not re.fullmatch(r"[0-9a-f]{12,64}", container_id):
            raise ActivationAdapterError("controller transport container identity unavailable")
        _run(
            ["docker", "cp", f"{container_id}:{IMAGE_BUNDLE_PATH}/.", str(staging)],
            timeout=300,
        )
        verify_bundle(staging, source_revision=revision, expected_digest=bundle_digest)
        _root_owned_tree(staging)
        os.replace(staging, final)
        descriptor = os.open(releases, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return final
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    finally:
        if container_id:
            try:
                _run(["docker", "rm", "-f", container_id], timeout=120)
            except ActivationAdapterError:
                if final.exists():
                    raise


def _actual_runtime(reference: str, image_id: str) -> None:
    for service in ("broker-public", "broker-internal"):
        try:
            values = json.loads(_run(["docker", "inspect", f"qdev-runner-{service}"]))
        except json.JSONDecodeError as error:
            raise ActivationAdapterError("active controller image identity unavailable") from error
        if not isinstance(values, list) or len(values) != 1 or not isinstance(values[0], dict):
            raise ActivationAdapterError("active controller image identity unavailable")
        record = values[0]
        config = record.get("Config")
        state = record.get("State")
        if (
            record.get("Image") != image_id
            or not isinstance(config, dict)
            or config.get("Image") != reference
            or not isinstance(state, dict)
            or state.get("Running") is not True
        ):
            raise ActivationAdapterError("active controller image identity mismatch")


def _validated_request(
    envelope: dict[str, Any],
) -> tuple[str, str, str, str, str, str, str, str]:
    if set(envelope) != {"schema", "operation", "request", "target", "active_jobs"}:
        raise ActivationAdapterError("controller activation envelope shape is invalid")
    if envelope.get("schema") != "qdev-fleet-bootstrap-adapter-request-v1":
        raise ActivationAdapterError("controller activation envelope schema is invalid")
    request = envelope.get("request")
    target = envelope.get("target")
    operation = envelope.get("operation")
    if (
        not isinstance(request, dict)
        or not isinstance(target, dict)
        or not isinstance(operation, dict)
    ):
        raise ActivationAdapterError("controller activation identity is unavailable")
    payload = operation.get("payload")
    provenance = payload.get("candidate_provenance") if isinstance(payload, dict) else None
    revision = request.get("controller_revision")
    image_digest = request.get("controller_release_digest")
    fence = payload.get("fence") if isinstance(payload, dict) else None
    provenance_digest = (
        provenance.get("provenance_digest") if isinstance(provenance, dict) else None
    )
    signed_bundle_digest = provenance.get("bundle_digest") if isinstance(provenance, dict) else None
    reference = f"{IMAGE_REPOSITORY}@{image_digest}"
    if (
        request.get("action") != "activate-controller"
        or request.get("release_lane") is not None
        or request.get("worker_name") is not None
        or not isinstance(revision, str)
        or not _SHA.fullmatch(revision)
        or not isinstance(image_digest, str)
        or not _DIGEST.fullmatch(image_digest)
        or not isinstance(fence, str)
        or not _FENCE.fullmatch(fence)
        or not isinstance(provenance, dict)
        or provenance.get("source_revision") != revision
        or provenance.get("image_digest") != image_digest
        or provenance.get("run_conclusion") != "success"
        or provenance.get("job_conclusion") != "success"
        or not isinstance(signed_bundle_digest, str)
        or not _BUNDLE_DIGEST.fullmatch(signed_bundle_digest)
        or not isinstance(provenance_digest, str)
        or not _FENCE.fullmatch(provenance_digest)
        or envelope.get("active_jobs") != 0
        or target.get("target_id") != f"controller:{revision}"
        or target.get("revision") != revision
        or target.get("release_digest") != image_digest
        or target.get("artifact_ref") != reference
        or set(target)
        != {
            "target_id",
            "revision",
            "release_digest",
            "artifact_ref",
            "rollback_revision",
            "rollback_release_digest",
        }
        or not _SHA.fullmatch(str(target.get("rollback_revision", "")))
        or not _DIGEST.fullmatch(str(target.get("rollback_release_digest", "")))
    ):
        raise ActivationAdapterError("controller activation tuple is invalid")
    return (
        revision,
        image_digest,
        reference,
        fence,
        provenance_digest,
        signed_bundle_digest,
        str(target["rollback_revision"]),
        str(target["rollback_release_digest"]),
    )


def execute(envelope: dict[str, Any], *, paths: Paths | None = None) -> dict[str, Any]:
    paths = paths or Paths()
    (
        revision,
        image_digest,
        reference,
        fence,
        provenance_digest,
        signed_bundle_digest,
        rollback_revision,
        rollback_release_digest,
    ) = _validated_request(envelope)
    _run(["docker", "pull", reference])
    image_id, bundle_digest = _image_identity(reference, revision)
    if bundle_digest != signed_bundle_digest:
        raise ActivationAdapterError("controller image bundle differs from signed provenance")
    release = _install_bundle(
        reference=reference,
        revision=revision,
        bundle_digest=signed_bundle_digest,
        releases=paths.releases,
    )
    transaction = activate(
        paths,
        release,
        expected_revision=revision,
        expected_artifact_digest=image_digest,
        expected_release_digest=signed_bundle_digest,
        expected_previous_revision=rollback_revision,
        expected_previous_release_digest=rollback_release_digest,
        candidate_image_ref=reference,
    )
    try:
        _actual_runtime(reference, image_id)
    except ActivationAdapterError:
        try:
            rollback_accepted(paths, transaction["id"])
        except (TransactionError, OSError, ValueError, KeyError, TypeError) as error:
            raise ActivationAdapterError(
                "controller runtime identity mismatch and rollback failed"
            ) from error
        raise
    return {
        "schema": RESULT_SCHEMA,
        "status": "completed",
        "action": "activate-controller",
        "target_id": f"controller:{revision}",
        "result": {
            "revision": revision,
            "artifact_digest": image_digest,
            "bundle_digest": signed_bundle_digest,
            "actual_image_id": image_id,
            "candidate_provenance_digest": provenance_digest,
            "transaction": "accepted",
        },
        "operation_fence": fence,
    }


def main() -> int:
    try:
        if os.geteuid() != 0:
            raise ActivationAdapterError("controller activation requires root")
        raw = sys.stdin.buffer.read(MAX_MESSAGE_BYTES + 1)
        if not raw or len(raw) > MAX_MESSAGE_BYTES:
            raise ActivationAdapterError("controller activation request is invalid")
        envelope = _object(raw.decode("utf-8"), message="controller activation request is invalid")
        result = execute(envelope)
    except (
        ActivationAdapterError,
        BundleError,
        TransactionError,
        OSError,
        UnicodeDecodeError,
        ValueError,
        KeyError,
        TypeError,
    ):
        print("controller_activation_failed", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
