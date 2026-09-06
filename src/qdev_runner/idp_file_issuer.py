"""Fixed private issuer helpers. No enrollment, lease creation or native execution.

Native bytes originate only at the configured mTLS release host. Shape/digests
are not origin authentication. Provider CI is independently collected by the
controller and prior installed observations come only from its protected journal.
"""

from __future__ import annotations

import json
import os
import stat
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from .file_apply_authorization import canonical_bytes, verify_dispatch_binding
from .idp_file_runtime import (
    ADAPTER,
    ARTIFACT_PREFIX,
    REPOSITORY,
    IdPObservationError,
    native_receipt,
)
from .release_lane import (
    ReleaseLane,
    ReleaseLaneError,
    host_dispatch_claim_payload,
    validate_native_runtime_receipt,
    validate_runtime_receipt,
)

MAX_NATIVE_OBSERVATION = 2 * 1024 * 1024


@contextmanager
def private_handle(
    path: Path, *, directory: bool = False, private_parent: bool = True
) -> Iterator[int]:
    """Walk no-follow handles, with private leaf/parent and trusted ancestry."""
    descriptor = -1
    try:
        if not path.is_absolute() or ".." in path.parts or path == Path("/"):
            raise ReleaseLaneError("IdP private storage path is invalid")
        descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for index, part in enumerate(path.parts[1:], start=1):
            final = index == len(path.parts) - 1
            parent = os.fstat(descriptor)
            if final and not directory and private_parent and stat.S_IMODE(parent.st_mode) != 0o700:
                raise ReleaseLaneError("IdP private file parent is not private")
            child = os.open(
                part,
                os.O_RDONLY
                | os.O_NOFOLLOW
                | os.O_NONBLOCK
                | (os.O_DIRECTORY if directory or not final else 0),
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
            meta = os.fstat(descriptor)
            # Native /tmp and /run/lock ancestry is safe only with root sticky
            # protection. The actual state/key directory must still be 0700.
            sticky_root = (
                not final
                and stat.S_ISDIR(meta.st_mode)
                and meta.st_uid == 0
                and bool(meta.st_mode & stat.S_ISVTX)
            )
            if meta.st_uid not in (0, os.geteuid()) or (
                stat.S_IMODE(meta.st_mode) & 0o022 and not sticky_root
            ):
                raise ReleaseLaneError("IdP private storage ancestry is unsafe")
        meta = os.fstat(descriptor)
        if directory:
            safe = stat.S_ISDIR(meta.st_mode) and stat.S_IMODE(meta.st_mode) == 0o700
        else:
            safe = (
                stat.S_ISREG(meta.st_mode)
                and stat.S_IMODE(meta.st_mode) == 0o600
                and meta.st_nlink == 1
            )
        if not safe:
            raise ReleaseLaneError("IdP private storage type or mode is invalid")
        yield descriptor
    except OSError:
        raise ReleaseLaneError("IdP private storage is unavailable or unsafe") from None
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def private_bytes(path: Path, *, limit: int, private_parent: bool = True) -> bytes:
    with private_handle(path, private_parent=private_parent) as fd:
        before = os.fstat(fd)
        if not 0 <= before.st_size <= limit:
            raise ReleaseLaneError("IdP private record exceeds size limit")
        chunks = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(fd, min(remaining, 1024 * 1024))
            if not chunk:
                raise ReleaseLaneError("IdP private record was truncated")
            chunks.append(chunk)
            remaining -= len(chunk)
        after = os.fstat(fd)
        if (
            before.st_size != after.st_size
            or before.st_mtime_ns != after.st_mtime_ns
            or before.st_ctime_ns != after.st_ctime_ns
            or after.st_nlink != 1
        ):
            raise ReleaseLaneError("IdP private record changed while reading")
        return b"".join(chunks)


def check_storage(root: Path, lane: ReleaseLane) -> None:
    """Do not let the generic store create/chmod through untrusted ancestry."""
    for path in (root, *(root / x for x in ("agents", "jobs", "locks", "operations"))):
        with private_handle(path, directory=True):
            pass
    for path in (
        root / "operations" / f"{lane.name}.jsonl",
        root / "locks" / f"{lane.name}.lock",
    ):
        with private_handle(path):
            pass
    snapshot = root / "jobs" / f"{lane.name}.json"
    # An interrupted snapshot rename is recoverable from the durable journal.
    if snapshot.exists() or snapshot.is_symlink():
        with private_handle(snapshot):
            pass


def parse_native(raw: bytes, lane: ReleaseLane) -> dict[str, Any]:
    if (
        lane.project_id,
        lane.canonical_repository,
        lane.native_host_adapter,
        lane.artifact_ref_prefix,
    ) != ("id-qdev-run", REPOSITORY, ADAPTER, ARTIFACT_PREFIX):
        raise ReleaseLaneError("lane is not the fixed IdP file adapter")
    try:
        if not isinstance(raw, bytes) or len(raw) > MAX_NATIVE_OBSERVATION:
            raise ValueError("size")
        document = json.loads(raw)
        if (
            not isinstance(document, dict)
            or canonical_bytes(document) != raw
            or document.get("schema_version") != "qdev-idp-prepared-observation-v2"
        ):
            raise ValueError("shape")
        return document
    except (ValueError, TypeError, RecursionError):
        raise ReleaseLaneError("invalid IdP native observation") from None


def previous_observation(
    events: list[dict[str, Any]],
    lane: ReleaseLane,
    anchor: dict[str, Any],
) -> dict[str, Any] | None:
    for event in reversed(events):
        job = event.get("job_snapshot", {})
        if event.get("phase") != "verified" or any(job.get(k) != v for k, v in anchor.items()):
            continue
        receipt = job.get("runtime_receipt")
        if not isinstance(receipt, dict):
            raise ReleaseLaneError("prior IdP journal receipt is missing")
        validate_runtime_receipt(
            receipt,
            lane=lane,
            **anchor,
            rollback_anchor=job.get("rollback_anchor"),
        )
        prior: dict[str, Any] = receipt["artifact_provenance"]["observation"]
        detached: dict[str, Any] = json.loads(canonical_bytes(prior))
        return detached
    return None  # initial bootstrap is allowed only if snapshot equals the frozen anchor


def verify_native_dispatch(
    native: dict[str, Any],
    job: dict[str, Any],
    lane: ReleaseLane,
    *,
    signing_key: str | bytes,
    now: float,
    previous: dict[str, Any] | None,
) -> bytes:
    claim, candidate = job.get("dispatch_claim"), job.get("candidate_receipt")
    signature = job.get("dispatch_claim_signature")
    if (
        not isinstance(claim, dict)
        or not isinstance(candidate, dict)
        or not isinstance(signature, str)
    ):
        raise ReleaseLaneError("IdP release has no persisted dispatch or candidate")
    try:
        raw = canonical_bytes(native["binding"])
        verify_dispatch_binding(
            raw,
            lane=lane,
            claim=claim,
            candidate=candidate,
            signature=signature,
            signing_key=signing_key,
            now=now,
            previous_observation=previous,
        )
        if claim != host_dispatch_claim_payload(
            job,
            lane,
            host_identity=lane.host_agent_mtls_identity,
            issued_at=claim["issued_at"],
            expires_at=claim["expires_at"],
            nonce=claim["nonce"],
        ):
            raise ReleaseLaneError("IdP dispatch does not match the current admitted job")
        prepared = native_receipt(
            native,
            installed=False,
            expected_binding=raw,
            now=now,
            previous_observation=previous,
        )
        validate_native_runtime_receipt(prepared, lane=lane, **job["rollback_anchor"])
        return raw
    except (IdPObservationError, KeyError, TypeError, ValueError, RecursionError):
        raise ReleaseLaneError("IdP native observation does not bind admitted release") from None
