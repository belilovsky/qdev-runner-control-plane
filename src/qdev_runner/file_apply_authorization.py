"""Source-only IdP binding adapter; not an issuer, enrollment or host dispatcher.

The native host agent supplies the mandatory durable dispatch transaction. This
module never turns signature verification alone into permission to apply files.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable, Iterator
from contextlib import AbstractContextManager, contextmanager
from datetime import datetime
from typing import Annotated, Any, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from qdev_runner.release_lane import (
    REQUEST_SCHEMA,
    ReleaseAdmissionRequest,
    ReleaseLane,
    ReleaseLaneError,
    host_dispatch_claim_payload,
    sign_host_dispatch_claim,
    validate_candidate,
)

SHA = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
Digest = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
PositiveInt = Annotated[int, Field(strict=True, gt=0)]
ENVELOPE_SCHEMA = "qdev-controller-file-apply-authorization-v1"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class CITuple(StrictModel):
    source_sha: SHA
    status: Literal["completed"]
    conclusion: Literal["success"]
    profile: str
    run_id: PositiveInt
    job_id: PositiveInt
    attempt: PositiveInt
    workflow: Literal["quality.yml", "qdev-runner-contract.yml"]
    url: str
    started_at: str
    completed_at: str


class Artifact(StrictModel):
    schema_version: Literal["qdev-idp-ci-bundle-v1"]
    repository: Literal["belilovsky/id-qdev-run"]
    source_sha: SHA
    bundle_sha256: Digest
    manifest_sha256: Digest
    artifact_sha256: Digest
    artifact_name: Literal["idp-release"]
    storage_key: str
    profile: Literal["qdev-ci-docker"]
    run_id: PositiveInt
    job_id: PositiveInt
    attempt: PositiveInt


class Observation(StrictModel):
    path: Annotated[str, Field(pattern=r"^ci-[0-9a-f]{16}\.json$")]
    sha256: Digest
    observed_at: str
    quality: CITuple
    runner_contract: CITuple
    artifact: Artifact


class FileApplyBinding(StrictModel):
    schema_version: Literal["qdev-idp-controller-apply-binding-v1"]
    repository: Literal["belilovsky/id-qdev-run"]
    source_sha: SHA
    transaction: Annotated[str, Field(pattern=r"^[A-Za-z0-9_-]{1,128}$")]
    expected_previous_sha: SHA
    bundle_sha256: Digest
    manifest_sha256: Digest
    snapshot_sha256: Digest
    ci_observation: Observation


def canonical_bytes(document: dict[str, Any]) -> bytes:
    """Native contract serialization includes exactly one terminal LF."""
    return (json.dumps(document, sort_keys=True, separators=(",", ":")) + "\n").encode()


def utc_timestamp(value: str) -> float:
    if not re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|\+00:00)", value
    ):
        raise ValueError("CI timestamps must be UTC RFC3339")
    return datetime.fromisoformat(value.replace("Z", "+00:00")).timestamp()


def parse_binding(raw: bytes, *, now: float) -> FileApplyBinding:
    if not isinstance(raw, bytes) or len(raw) > 32768:
        raise ReleaseLaneError("file apply binding must be bounded canonical bytes")
    try:
        document = json.loads(raw)
        binding = FileApplyBinding.model_validate(document)
        if canonical_bytes(document) != raw:
            raise ValueError("noncanonical binding")
        observation = binding.ci_observation
        observed = utc_timestamp(observation.observed_at)
        if not now - 300 <= observed <= now + 30:
            raise ValueError("CI observation is stale or future dated")
        quality, contract, artifact = (
            observation.quality,
            observation.runner_contract,
            observation.artifact,
        )
        for ci, workflow in (
            (quality, "quality.yml"), (contract, "qdev-runner-contract.yml")
        ):
            if (
                ci.workflow != workflow
                or ci.url != (
                    f"https://github.com/{binding.repository}/actions/runs/"
                    f"{ci.run_id}/job/{ci.job_id}"
                )
                or not utc_timestamp(ci.started_at) <= utc_timestamp(ci.completed_at) <= observed
            ):
                raise ValueError("CI workflow, locator or timing mismatch")
        if (
            quality.profile != "qdev-ci-docker"
            or contract.profile != "qdev-ci"
            or any(item.source_sha != binding.source_sha for item in (quality, contract, artifact))
            or artifact.bundle_sha256 != binding.bundle_sha256
            or artifact.manifest_sha256 != binding.manifest_sha256
            or any(
                getattr(artifact, key) != getattr(quality, key)
                for key in ("run_id", "job_id", "attempt")
            )
            or artifact.storage_key
            != (f"{binding.repository}/{binding.source_sha}/{quality.job_id}/idp-release.tar.gz")
            or binding.expected_previous_sha == binding.source_sha
        ):
            raise ValueError("file apply immutable binding mismatch")
        return binding
    except (ValueError, TypeError, ValidationError) as exc:
        raise ReleaseLaneError("invalid file apply binding") from exc


def authorization_payload(binding_bytes: bytes, dispatch_claim: dict[str, Any]) -> dict[str, Any]:
    """Issuer building block only: callers still need native admission evidence.

    No public API exposes this function. Signing must happen in a future enrolled
    controller path after fresh provider/native evidence, not in IdP or the CLI.
    """
    return {
        "schema": ENVELOPE_SCHEMA,
        "binding_sha256": hashlib.sha256(binding_bytes).hexdigest(),
        "dispatch_sha256": hashlib.sha256(canonical_bytes(dispatch_claim)).hexdigest(),
    }


class NativeDispatchGuard(Protocol):
    def assert_current(self) -> None:
        """Recheck live lease/fence under the durable transaction; never consume twice."""


class FileApplyGuard:
    def __init__(self, check: Callable[[], None]) -> None:
        self._check = check
        self._active = True

    def assert_current(self) -> None:
        if not self._active:
            raise ReleaseLaneError("file apply guard is outside its transaction")
        self._check()

    def close(self) -> None:
        self._active = False


class FileApplyBridge:
    """Callable ``authorize_apply(bytes)`` for the fixed, enrolled host adapter.

    ``dispatch_transaction`` is trusted controller code, never a JSON/CLI input.
    Before yielding it MUST check live lease/fence and immutable host state, reject
    replay/pending work, durably append dispatch_accepted and release_started, and
    hold its protected journal lock until exit. Existing host-agent validate_job
    alone does not satisfy this interface. No default transaction is provided.
    """

    def __init__(
        self,
        *,
        lane: ReleaseLane,
        dispatch_claim: dict[str, Any],
        candidate_receipt: dict[str, Any],
        dispatch_signature: str,
        authorization: dict[str, Any],
        authorization_signature: str,
        signing_key: bytes,
        dispatch_transaction: Callable[
            [dict[str, Any]], AbstractContextManager[NativeDispatchGuard]
        ],
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not callable(dispatch_transaction):
            raise ReleaseLaneError("native durable dispatch transaction is required")
        self._lane = lane
        # Immutable snapshots: caller mutations cannot change what was authorized.
        self._dispatch = canonical_bytes(dispatch_claim)
        self._candidate = canonical_bytes(candidate_receipt)
        self._authorization = canonical_bytes(authorization)
        self._dispatch_signature = dispatch_signature
        self._authorization_signature = authorization_signature
        self._key = signing_key
        self._transaction = dispatch_transaction
        self._clock = clock

    def _verify(self, raw: bytes) -> dict[str, Any]:
        now = self._clock()
        binding = parse_binding(raw, now=now)
        claim: dict[str, Any] = json.loads(self._dispatch)
        envelope = json.loads(self._authorization)
        for document, signature in (
            (claim, self._dispatch_signature),
            (envelope, self._authorization_signature),
        ):
            if not isinstance(signature, str) or not re.fullmatch(r"[0-9a-f]{64}", signature):
                raise ReleaseLaneError("invalid file apply authorization signature")
            expected = sign_host_dispatch_claim(document, signing_key=self._key)
            if not hmac.compare_digest(expected, signature):
                raise ReleaseLaneError("file apply authorization signature mismatch")
        if envelope != authorization_payload(raw, claim):
            raise ReleaseLaneError("file apply authorization binding mismatch")
        quality = binding.ci_observation.quality
        artifact = binding.ci_observation.artifact
        candidate = json.loads(self._candidate)
        artifact_ref = claim.get("artifact_ref")
        if not isinstance(artifact_ref, str):
            raise ReleaseLaneError("file apply dispatch artifact reference missing")
        try:
            request = ReleaseAdmissionRequest(
                schema=REQUEST_SCHEMA,
                release_lane=self._lane.name,
                project_id=self._lane.project_id,
                placement=self._lane.placement,
                source_sha=binding.source_sha,
                artifact_digest=f"sha256:{artifact.artifact_sha256}",
                artifact_ref=artifact_ref,
                candidate_receipt=candidate,
            )
            validate_candidate(request, self._lane)
        except (ValidationError, TypeError) as exc:
            raise ReleaseLaneError("invalid file apply candidate receipt") from exc
        expected_candidate = {
            "repository": binding.repository,
            "workflow": "quality.yml",
            "job": "static-contracts",
            "run_id": quality.run_id,
            "job_id": quality.job_id,
            "attempt": quality.attempt,
            "runner_profile": quality.profile,
            "artifact_type": "http-archive",
            "archive_sha256": artifact.artifact_sha256,
            "payload_sha256": binding.bundle_sha256,
        }
        if any(candidate.get(key) != value for key, value in expected_candidate.items()):
            raise ReleaseLaneError("file apply candidate does not bind observed CI and archives")
        job = {
            **claim,
            "source_sha": binding.source_sha,
            "artifact_digest": f"sha256:{artifact.artifact_sha256}",
            "candidate_receipt": candidate,
        }
        issued_at, expires_at, nonce = (
            claim.get("issued_at"),
            claim.get("expires_at"),
            claim.get("nonce"),
        )
        if type(issued_at) is not int or type(expires_at) is not int or not isinstance(nonce, str):
            raise ReleaseLaneError("file apply dispatch lifetime or nonce missing")
        expected_claim = host_dispatch_claim_payload(
            job,
            self._lane,
            host_identity=self._lane.host_agent_mtls_identity,
            issued_at=issued_at,
            expires_at=expires_at,
            nonce=nonce,
        )
        if (
            claim != expected_claim
            or not claim["issued_at"] <= now + 30
            or not now < claim["expires_at"] <= claim["lease_expires_at"]
            or claim["rollback_anchor"]["source_sha"] != binding.expected_previous_sha
            or claim["rollback_anchor"]["artifact_digest"] != f"sha256:{binding.snapshot_sha256}"
            or claim["rollback_anchor"]["artifact_ref"]
            != f"{self._lane.artifact_ref_prefix}@sha256:{binding.snapshot_sha256}"
            or any(
                not re.fullmatch(pattern, claim[field])
                for field, pattern in (
                    ("release_id", r"[A-Za-z0-9_-]{16,128}"),
                    ("lease_id", r"[A-Za-z0-9_-]{16,128}"),
                    ("fence", r"[0-9a-f]{24,128}"),
                )
            )
        ):
            raise ReleaseLaneError("file apply dispatch scope or lifetime mismatch")
        return claim

    @contextmanager
    def __call__(self, binding_bytes: bytes) -> Iterator[FileApplyGuard]:
        claim = self._verify(binding_bytes)
        failure: BaseException | None = None
        with self._transaction(claim) as native_guard:

            def check() -> None:
                self._verify(binding_bytes)
                native_guard.assert_current()

            guard = FileApplyGuard(check)
            try:
                # Native lock acquisition/consume can take time; do not use stale proof.
                guard.assert_current()
                yield guard
            except BaseException as exc:
                failure = exc
                raise
            finally:
                guard.close()
        if failure is not None:
            # A broken native adapter must never suppress an IdP apply failure.
            raise failure
