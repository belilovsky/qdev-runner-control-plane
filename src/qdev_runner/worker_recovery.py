from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, NoReturn, cast

from .claim_scope import ClaimScopeError, load_claim_scopes
from .github import GitHubAppClient
from .models import (
    RecoveryAcceptRequest,
    RecoveryAgentClaimRequest,
    RecoveryAgentCommand,
    RecoveryBindingsResponse,
    RecoveryOperationResponse,
    RecoveryPrepareRequest,
    RecoveryReconcileRequest,
    RecoveryRequestProvenance,
    RecoveryStatusRequest,
    RecoveryTargetId,
)
from .settings import BrokerSettings
from .store import Store

INTERFACE_VERSION = "qdev-worker-recovery-v2"
_SHA256_HEX = re.compile(r"^[0-9a-f]{64}$")
_SHA256_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_GIT_REVISION = re.compile(r"^[0-9a-f]{40}$")


class WorkerRecoveryError(RuntimeError):
    """A fail-closed controller-owned recovery error safe for HTTP mapping."""


class WorkerRecoveryConfigurationError(WorkerRecoveryError):
    """Recovery is unavailable because its immutable bindings are incomplete."""


@dataclass(frozen=True)
class RecoveryTarget:
    target_id: RecoveryTargetId
    worker_name: str
    repository: str
    labels: tuple[str, ...]
    action: str
    workflow: str
    ref: str = "main"


RECOVERY_TARGETS: Mapping[RecoveryTargetId, RecoveryTarget] = {
    "qdev-platform-ci-187": RecoveryTarget(
        target_id="qdev-platform-ci-187",
        worker_name="qdev-platform-ci-187",
        repository="belilovsky/platform-portal",
        labels=("self-hosted", "Linux", "X64", "qdev-platform-ci"),
        action="restore_saved_configuration",
        workflow=".github/workflows/runner-smoke.yml",
        ref="master",
    ),
    "qdev-qazstack-01": RecoveryTarget(
        target_id="qdev-qazstack-01",
        worker_name="qdev-qazstack-01",
        repository="belilovsky/qazstack",
        labels=("self-hosted", "Linux", "X64", "qdev-ci"),
        action="replace_existing_registration",
        workflow=".github/workflows/self-hosted-recovery.yml",
    ),
}

# This manifest is the complete executable-independent wire contract.  Its
# canonical digest is provisioned to both controller and host agent; neither
# side derives trust from a mutable source path or an HTTP request field.
INTERFACE_MANIFEST: dict[str, Any] = {
    "schema": "qdev-runner-recovery-interface-v2",
    "interface_version": INTERFACE_VERSION,
    "canonical_json": {
        "sort_keys": True,
        "separators": [",", ":"],
        "ensure_ascii": False,
        "allow_nan": False,
    },
    "endpoints": {
        "bindings": "/internal/v1/operations/worker-recovery/bindings",
        "prepare": "/internal/v1/operations/worker-recovery/prepare",
        "status": "/internal/v1/operations/worker-recovery/status",
        "accept": "/internal/v1/operations/worker-recovery/accept",
        "claim": "/internal/v1/worker-recovery/claim",
        "reconcile": "/internal/v1/worker-recovery/reconcile",
    },
    "schemas": {
        "bindings": "qdev-runner-recovery-bindings-v1",
        "claim": "qdev-runner-recovery-agent-claim-v1",
        "command": "qdev-runner-recovery-agent-command-v1",
        "envelope": "qdev-runner-recovery-agent-envelope-v1",
        "reconcile": "qdev-runner-recovery-reconcile-v1",
    },
    "provider_runner_identity": {
        "restore_saved_configuration": "required-positive-integer",
        "replace_existing_registration": "positive-integer-or-observed-absent",
        "absence_observation": "qdev-worker-provider-absence-observation-v1",
        "absence_requires_zero_active_target_jobs": True,
    },
    "targets": {
        target_id: {
            "worker_name": target.worker_name,
            "repository": target.repository,
            "labels": list(target.labels),
            "recovery_action": target.action,
        }
        for target_id, target in RECOVERY_TARGETS.items()
    },
}

# The environment can only confirm deployment of this checked-in policy; it
# cannot supply a different valid-looking digest and silently change recovery
# behavior.  Workflow inputs are included because they are part of the exact
# provider-side acceptance binding.
POLICY_MANIFEST: dict[str, Any] = {
    "schema": "qdev-runner-recovery-policy-v1",
    "targets": {
        target_id: {
            "worker_name": target.worker_name,
            "repository": target.repository,
            "labels": list(target.labels),
            "recovery_action": target.action,
            "identity": "unique-same-name",
            "canary": {
                "workflow": target.workflow,
                "ref": target.ref,
                "dispatch_authority": "owner_operator",
                "controller_provider_permissions": [
                    "actions:read",
                    "administration:write",
                ],
                "inputs": [
                    "operation_id",
                    "dispatch_correlation",
                    "runner_label",
                ]
                + (["confirm_recovery"] if target_id == "qdev-qazstack-01" else []),
            },
        }
        for target_id, target in RECOVERY_TARGETS.items()
    },
}


def canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        allow_nan=False,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


INTERFACE_DIGEST = hashlib.sha256(canonical_json(INTERFACE_MANIFEST)).hexdigest()
POLICY_DIGEST = "sha256:" + hashlib.sha256(canonical_json(POLICY_MANIFEST)).hexdigest()


def _digest(value: object, *, prefix: bool = False) -> str:
    result = hashlib.sha256(canonical_json(value)).hexdigest()
    return f"sha256:{result}" if prefix else result


def _rfc3339(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _timestamp(value: object, *, field: str) -> float:
    if not isinstance(value, str):
        raise WorkerRecoveryError(f"provider {field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise WorkerRecoveryError(f"provider {field} is invalid") from error
    if parsed.tzinfo is None:
        raise WorkerRecoveryError(f"provider {field} has no timezone")
    return parsed.timestamp()


def _runner_record(raw: object) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise WorkerRecoveryError("GitHub runner collection is malformed")
    runner_id = raw.get("id")
    name = raw.get("name")
    status = raw.get("status")
    busy = raw.get("busy")
    raw_labels = raw.get("labels")
    if (
        isinstance(runner_id, bool)
        or not isinstance(runner_id, int)
        or runner_id <= 0
        or not isinstance(name, str)
        or not name
        or status not in {"online", "offline"}
        or not isinstance(busy, bool)
        or not isinstance(raw_labels, list)
    ):
        raise WorkerRecoveryError("GitHub runner collection is malformed")
    labels: list[str] = []
    for raw_label in raw_labels:
        label = raw_label.get("name") if isinstance(raw_label, dict) else None
        if not isinstance(label, str) or not label:
            raise WorkerRecoveryError("GitHub runner labels are malformed")
        labels.append(label)
    if not labels or len({label.lower() for label in labels}) != len(labels):
        raise WorkerRecoveryError("GitHub runner labels are malformed")
    return {
        "id": runner_id,
        "name": name,
        "status": status,
        "busy": busy,
        "labels": labels,
    }


class WorkerRecoveryController:
    """Own all provider observation, target selection, and native command binding."""

    def __init__(
        self,
        *,
        settings: BrokerSettings,
        store: Store,
        github: GitHubAppClient,
        release_status_reader: Callable[[], dict[str, Any]],
    ) -> None:
        self.settings = settings
        self.store = store
        self.github = github
        self.release_status_reader = release_status_reader

    def target_for_agent_certificate(self, certificate_sha256: str) -> RecoveryTarget:
        certificate = certificate_sha256.strip().lower()
        if not _SHA256_HEX.fullmatch(certificate):
            raise WorkerRecoveryError("verified agent certificate fingerprint is invalid")
        matches = [
            target
            for target in RECOVERY_TARGETS.values()
            if hmac.compare_digest(certificate, self._agent_certificate(target))
        ]
        if len(matches) != 1:
            raise WorkerRecoveryError("verified agent certificate is not allowlisted")
        return matches[0]

    def bindings(
        self,
        *,
        operator_certificate_sha256: str,
    ) -> RecoveryBindingsResponse:
        """Return only active, source-bound values needed for fresh provenance."""

        release = self._configuration()
        self._operator_certificate(operator_certificate_sha256)
        return RecoveryBindingsResponse.model_validate(
            {
                "schema": "qdev-runner-recovery-bindings-v1",
                "controller_revision": release["revision"],
                "controller_release_digest": release["release_digest"],
                "policy_digest": self._policy_digest(),
                "agent_release_digest": self._agent_release_digest(),
                "interface_version": INTERFACE_VERSION,
                "interface_digest": INTERFACE_DIGEST,
                "observed_at": datetime.now(UTC),
                "proof_max_age_seconds": self.settings.recovery_proof_max_age_seconds,
            }
        )

    def prepare(
        self,
        request: RecoveryPrepareRequest,
        *,
        operator_certificate_sha256: str,
    ) -> RecoveryOperationResponse:
        target = RECOVERY_TARGETS[request.target_id]
        release = self._configuration()
        certificate = self._operator_certificate(operator_certificate_sha256)
        fingerprint = self._request_fingerprint(request, certificate)

        existing = self.store.worker_recovery_by_idempotency_key(request.idempotency_key)
        if existing is not None:
            self._require_row_binding(
                existing,
                target=target,
                fingerprint=fingerprint,
                operator_certificate=certificate,
                release=release,
            )
            return self._project(existing, idempotent_replay=True)

        self._validate_provenance(request.provenance, release=release)
        self._require_no_claim_scope(target.worker_name)
        try:
            runners, observed, provider_observation = self._observe_runner(
                target, expected_labels=target.labels, status="offline", require_idle=True
            )
            provider_runner_id: int | None = int(observed["id"])
            provider_observed_at = float(observed["observed_at"])
        except WorkerRecoveryError as error:
            if target.action != "replace_existing_registration":
                raise
            installation_id = self.github.repository_installation_id(target.repository)
            runners = sorted(
                (
                    _runner_record(raw)
                    for raw in self.github.repository_runners(installation_id, target.repository)
                ),
                key=lambda runner: int(runner["id"]),
            )
            if any(runner["name"] == target.worker_name for runner in runners):
                raise error
            active_jobs = self.github.runner_name_active_jobs(
                installation_id, target.repository, target.worker_name
            )
            if active_jobs:
                raise WorkerRecoveryError("absent GitHub runner still owns active jobs") from None
            provider_runner_id = None
            provider_observed_at = time.time()
            provider_observation = {
                "schema": "qdev-worker-provider-absence-observation-v1",
                "repository": target.repository,
                "worker_name": target.worker_name,
                "runners": {"total_count": len(runners), "items": runners},
                "active_target_jobs": {"total_count": 0, "items": []},
            }
        proof_key = self._receipt_key()
        proof = self.store.issue_worker_provider_idle_proof(
            key=proof_key,
            worker_name=target.worker_name,
            repository=target.repository,
            labels=target.labels,
            provider_runner_id=provider_runner_id,
            provider_status=None if provider_runner_id is None else "offline",
            provider_busy=None if provider_runner_id is None else False,
            active_jobs=0,
            provider_observation=provider_observation,
            observed_at=provider_observed_at,
        )
        controller_receipt_id = _digest(
            {
                "schema": "qdev-runner-recovery-controller-receipt-v1",
                "request_fingerprint": fingerprint,
                "operator_certificate_sha256": certificate,
                "provider_idle_proof_digest": proof["digest"],
            }
        )
        row = self.store.begin_worker_recovery(
            target.worker_name,
            request.idempotency_key,
            fingerprint,
            repository=target.repository,
            labels=target.labels,
            provider_idle_proof=proof,
            provider_proof_key=proof_key,
            recovery_action=target.action,
            operator_certificate_sha256=certificate,
            expected_agent_certificate_sha256=self._agent_certificate(target),
            interface_version=INTERFACE_VERSION,
            interface_digest=INTERFACE_DIGEST,
            controller_revision=cast(str, release["revision"]),
            controller_release_digest=cast(str, release["release_digest"]),
            policy_digest=self._policy_digest(),
            agent_release_digest=self._agent_release_digest(),
            controller_receipt_id=controller_receipt_id,
            controller_observed_at=provider_observed_at,
            request_nonce=request.provenance.nonce,
            requested_at=provider_observed_at,
            proof_max_age_seconds=self.settings.recovery_proof_max_age_seconds,
        )
        return self._project(row, idempotent_replay=False)

    def status(
        self,
        request: RecoveryStatusRequest,
        *,
        operator_certificate_sha256: str,
    ) -> RecoveryOperationResponse:
        release = self._configuration()
        self._validate_provenance(request.provenance, release=release)
        row = self._operation(request.operation_id, request.request_fingerprint)
        self._require_current_row(row, release=release)
        self._require_operation_operator(row, operator_certificate_sha256)
        return self._project(row, idempotent_replay=False)

    def claim(
        self,
        request: RecoveryAgentClaimRequest,
        *,
        agent_certificate_sha256: str,
    ) -> dict[str, Any] | None:
        target = self.target_for_agent_certificate(agent_certificate_sha256)
        release = self._configuration()
        row = (
            self.store.worker_recovery(request.operation_id)
            if request.operation_id is not None
            else self.store.prepared_worker_recovery(target.worker_name)
        )
        if row is None:
            return None
        self._require_row_binding(
            row,
            target=target,
            fingerprint=str(row["request_fingerprint"]),
            operator_certificate=str(row["operator_certificate_sha256"]),
            release=release,
        )
        if row["state"] == "prepared":
            row = self.store.advance_worker_recovery(
                str(row["idempotency_key"]),
                expected="prepared",
                state="invoking",
                proof_max_age_seconds=self.settings.recovery_proof_max_age_seconds,
            )
        elif row["state"] != "invoking":
            return None
        return self._command_envelope(row, target=target)

    def reconcile(
        self,
        request: RecoveryReconcileRequest,
        *,
        agent_certificate_sha256: str,
        supplied_signature: str,
    ) -> RecoveryOperationResponse:
        target = self.target_for_agent_certificate(agent_certificate_sha256)
        release = self._configuration()
        if request.target_id != target.target_id:
            raise WorkerRecoveryError("agent outcome target does not match its certificate")
        signature = supplied_signature.strip().lower()
        if not re.fullmatch(r"sha256=[0-9a-f]{64}", signature):
            raise WorkerRecoveryError("agent outcome signature is invalid")
        expected = hmac.new(
            self._agent_signing_key().encode("utf-8"),
            canonical_json(request.model_dump(mode="json", by_alias=True)),
            hashlib.sha256,
        ).hexdigest()
        if not hmac.compare_digest(signature.removeprefix("sha256="), expected):
            raise WorkerRecoveryError("agent outcome signature is invalid")
        row = self._operation(request.operation_id, request.request_fingerprint)
        self._require_row_binding(
            row,
            target=target,
            fingerprint=request.request_fingerprint,
            operator_certificate=str(row["operator_certificate_sha256"]),
            release=release,
        )
        if (
            request.recovery_action != target.action
            or request.request_nonce != row["request_nonce"]
            or request.provider_reconciliation_digest != row["provider_reconciliation_digest"]
            or request.agent_release_digest != row["agent_release_digest"]
        ):
            raise WorkerRecoveryError("agent outcome does not match recovery operation")
        replay = (
            row.get("native_outcome") == request.outcome
            and row.get("native_outcome_digest") == request.outcome_digest
        )
        reconciled = self.store.reconcile_worker_recovery(
            operation_id=request.operation_id,
            worker_name=target.worker_name,
            request_fingerprint=request.request_fingerprint,
            recovery_action=request.recovery_action,
            request_nonce=request.request_nonce,
            provider_reconciliation_digest=request.provider_reconciliation_digest,
            agent_certificate_sha256=agent_certificate_sha256,
            outcome=request.outcome,
            outcome_digest=request.outcome_digest,
            agent_release_digest=request.agent_release_digest,
            reconciliation_key=self._receipt_key(),
            observed_at=request.observed_at.timestamp(),
            proof_max_age_seconds=self.settings.recovery_proof_max_age_seconds,
        )
        return self._project(reconciled, idempotent_replay=replay)

    def accept(
        self,
        request: RecoveryAcceptRequest,
        *,
        operator_certificate_sha256: str,
    ) -> RecoveryOperationResponse:
        release = self._configuration()
        self._validate_provenance(request.provenance, release=release)
        row = self._operation(request.operation_id, request.request_fingerprint)
        self._require_acceptance_row(row, release=release)
        self._require_operation_operator(row, operator_certificate_sha256)
        target = self._target_from_row(row)
        if row["state"] == "released":
            return self._project(row, idempotent_replay=True)
        if row["state"] != "completed" or row.get("native_outcome") != "completed":
            raise WorkerRecoveryError("recovery operation is not ready for acceptance")

        # Progress all immediately observable/controller-only phases.  A caller
        # safely repeats accept while GitHub is still scheduling/running the
        # canary; provider ambiguity never causes an automatic redispatch.
        for _ in range(12):
            progressed = self._advance_acceptance(
                row,
                target=target,
                canary_head_sha=request.canary_head_sha,
            )
            current = self._operation(request.operation_id, request.request_fingerprint)
            if current["state"] == "released":
                return self._project(current, idempotent_replay=False)
            if not progressed:
                return self._project(current, idempotent_replay=False)
            row = current
        raise WorkerRecoveryError("recovery acceptance exceeded its bounded transition count")

    def _advance_acceptance(
        self,
        row: dict[str, Any],
        *,
        target: RecoveryTarget,
        canary_head_sha: str | None,
    ) -> bool:
        operation_id = str(row["operation_id"])
        canary = self.store.worker_recovery_canary(operation_id)
        if canary is None:
            runners, observed, _ = self._observe_recovered(target, row, target.labels)
            installation_id = self.github.repository_installation_id(target.repository)
            runs = self.github.workflow_runs_complete(
                installation_id,
                target.repository,
                workflow=target.workflow,
                branch=target.ref,
                event="workflow_dispatch",
            )
            baseline = max((self._positive_id(run, "id") for run in runs), default=0)
            if canary_head_sha is None:
                raise WorkerRecoveryError("exact canary head SHA is required")
            if len([runner for runner in runners if runner["name"] == target.worker_name]) != 1:
                raise WorkerRecoveryError("recovered GitHub runner identity is not unique")
            self.store.create_worker_recovery_canary_intent(
                operation_id=operation_id,
                repository=target.repository,
                workflow=target.workflow,
                ref=target.ref,
                head_sha=canary_head_sha,
                baseline_run_id=baseline,
                provider_runner_id=observed["id"],
                provider_runner_name=target.worker_name,
            )
            return True

        phase = str(canary["phase"])
        revision = int(canary["revision"])
        correlation = str(canary["dispatch_correlation"])
        temporary_label = str(canary["temporary_label"])
        dispatch_accepted = False
        if phase == "dispatch_intent":
            # The controller persists the exact, secret-free intent first.  An
            # authenticated owner dispatches that intent with repository-scoped
            # credentials; the GitHub App only needs read access to correlate
            # the exact run.  This avoids giving the controller a user token or
            # broader Contents/Actions write permissions.
            run = self._find_canary_run(target, canary)
            if run is None:
                return False
            claimed, may_dispatch = self.store.claim_worker_recovery_canary_dispatch(
                operation_id=operation_id, expected_revision=revision
            )
            if may_dispatch:
                dispatch_accepted = True
            canary = claimed
            phase = str(canary["phase"])
            revision = int(canary["revision"])

        if phase == "dispatching":
            run = self._find_canary_run(target, canary)
            # The correlated provider run is evidence that the owner dispatch
            # used the exact accepted input tuple.  Until it appears, this
            # transaction remains fenced and is never redispatched here.
            if run is None and not dispatch_accepted:
                return False
            self.store.transition_worker_recovery_canary(
                operation_id=operation_id,
                expected_revision=revision,
                expected_phase="dispatching",
                phase="dispatched",
                dispatch_correlation=correlation,
                observed_temporary_label=temporary_label,
            )
            return True

        if phase == "dispatched":
            run = self._find_canary_run(target, canary)
            if run is None:
                return False
            self.store.transition_worker_recovery_canary(
                operation_id=operation_id,
                expected_revision=revision,
                expected_phase="dispatched",
                phase="run_observed",
                dispatch_correlation=correlation,
                observed_temporary_label=temporary_label,
                run_id=self._positive_id(run, "id"),
                run_attempt=self._positive_id(run, "run_attempt"),
            )
            return True

        if phase == "run_observed":
            self.store.transition_worker_recovery_canary(
                operation_id=operation_id,
                expected_revision=revision,
                expected_phase="run_observed",
                phase="labels_pending",
            )
            return True

        if phase == "labels_pending":
            labels = target.labels + (temporary_label,)
            _, observed, _ = self._observe_recovered(
                target, row, (target.labels, labels), require_idle=False
            )
            if tuple(observed["labels"]) != labels:
                installation_id = self.github.repository_installation_id(target.repository)
                self.github.replace_runner_labels(
                    installation_id, target.repository, int(observed["id"]), labels
                )
                _, observed, _ = self._observe_recovered(target, row, labels, require_idle=False)
            if tuple(observed["labels"]) != labels:
                raise WorkerRecoveryError("GitHub did not apply the canary runner label")
            self.store.transition_worker_recovery_canary(
                operation_id=operation_id,
                expected_revision=revision,
                expected_phase="labels_pending",
                phase="labels_applied",
            )
            return True

        if phase == "labels_applied":
            installation_id = self.github.repository_installation_id(target.repository)
            jobs = self.github.workflow_jobs(
                installation_id, target.repository, int(canary["run_id"])
            )
            expected_labels = target.labels + (temporary_label,)
            matches = [
                job
                for job in jobs
                if tuple(job.get("labels") or ()) == expected_labels
                and job.get("runner_id") == canary["provider_runner_id"]
                and job.get("runner_name") == target.worker_name
            ]
            if not matches:
                return False
            if len(matches) != 1:
                raise WorkerRecoveryError("GitHub canary job identity is ambiguous")
            job = matches[0]
            status = job.get("status")
            if status not in {"queued", "in_progress", "waiting", "pending", "completed"}:
                raise WorkerRecoveryError("GitHub canary job status is invalid")
            self.store.transition_worker_recovery_canary(
                operation_id=operation_id,
                expected_revision=revision,
                expected_phase="labels_applied",
                phase="job_observed",
                dispatch_correlation=correlation,
                observed_temporary_label=temporary_label,
                job_id=self._positive_id(job, "id"),
                job_labels=expected_labels,
                job_runner_id=int(canary["provider_runner_id"]),
                job_runner_name=target.worker_name,
                run_status=cast(str, status),
            )
            return True

        if phase == "job_observed":
            installation_id = self.github.repository_installation_id(target.repository)
            run = self.github.workflow_run(
                installation_id, target.repository, int(canary["run_id"])
            )
            self._require_canary_run(run, canary)
            if run.get("status") != "completed":
                return False
            conclusion = run.get("conclusion")
            if conclusion not in {
                "success",
                "failure",
                "neutral",
                "cancelled",
                "skipped",
                "timed_out",
                "action_required",
                "stale",
                "startup_failure",
            }:
                raise WorkerRecoveryError("GitHub canary conclusion is invalid")
            completed_at = _timestamp(run.get("updated_at"), field="canary completion timestamp")
            self.store.transition_worker_recovery_canary(
                operation_id=operation_id,
                expected_revision=revision,
                expected_phase="job_observed",
                phase="completed",
                run_status="completed",
                conclusion=cast(str, conclusion),
                completed_at=completed_at,
            )
            return True

        if phase == "completed":
            self.store.transition_worker_recovery_canary(
                operation_id=operation_id,
                expected_revision=revision,
                expected_phase="completed",
                phase="cleanup_pending",
            )
            return True

        if phase == "cleanup_pending":
            _, observed, _ = self._observe_recovered(
                target,
                row,
                (target.labels, target.labels + (temporary_label,)),
                require_idle=False,
            )
            if tuple(observed["labels"]) != target.labels:
                installation_id = self.github.repository_installation_id(target.repository)
                self.github.replace_runner_labels(
                    installation_id,
                    target.repository,
                    int(observed["id"]),
                    target.labels,
                )
                self._observe_recovered(target, row, target.labels, require_idle=False)
            self.store.transition_worker_recovery_canary(
                operation_id=operation_id,
                expected_revision=revision,
                expected_phase="cleanup_pending",
                phase="cleaned",
            )
            return True

        if phase == "cleaned":
            if canary.get("conclusion") != "success":
                return False
            runners, observed, provider_observation = self._observe_recovered(
                target, row, target.labels, require_idle=True, canary=canary
            )
            initial_runner_id = row["provider_runner_id"]
            prior_disposition = (
                "same"
                if initial_runner_id is not None and observed["id"] == initial_runner_id
                else "absent"
            )
            proof = self.store.issue_worker_recovery_acceptance_proof(
                key=self._receipt_key(),
                operation_id=operation_id,
                worker_name=target.worker_name,
                repository=target.repository,
                labels=target.labels,
                prior_provider_runner_id=initial_runner_id,
                prior_provider_runner_disposition=prior_disposition,
                provider_runner_id=int(observed["id"]),
                matching_runner_count=len(
                    [runner for runner in runners if runner["name"] == target.worker_name]
                ),
                provider_status="online",
                provider_busy=False,
                active_jobs=0,
                provider_observation=provider_observation,
                canary_repository=target.repository,
                canary_workflow=target.workflow,
                canary_ref=str(canary["ref"]),
                canary_head_sha=str(canary["head_sha"]),
                canary_dispatch_correlation=correlation,
                canary_temporary_label=temporary_label,
                canary_dispatch_observed_label=str(canary["dispatch_observed_label"]),
                canary_run_observed_label=str(canary["run_observed_label"]),
                canary_baseline_run_id=int(canary["baseline_run_id"]),
                canary_run_id=int(canary["run_id"]),
                canary_run_attempt=int(canary["run_attempt"]),
                canary_job_id=int(canary["job_id"]),
                canary_job_labels=cast(tuple[str, ...], canary["job_labels"]),
                canary_job_runner_id=int(canary["job_runner_id"]),
                canary_job_runner_name=str(canary["job_runner_name"]),
                canary_runner_id=int(observed["id"]),
                canary_runner_name=target.worker_name,
                canary_status="completed",
                canary_conclusion="success",
                canary_completed_at=float(canary["completed_at"]),
                observed_at=float(observed["observed_at"]),
            )
            self.store.advance_worker_recovery(
                str(row["idempotency_key"]),
                expected="completed",
                state="released",
                acceptance_proof=proof,
                acceptance_proof_key=self._receipt_key(),
                proof_max_age_seconds=self.settings.recovery_proof_max_age_seconds,
            )
            return True
        if phase in {"accepted", "ambiguous"}:
            return False
        raise WorkerRecoveryError("recovery canary phase is invalid")

    def _find_canary_run(
        self, target: RecoveryTarget, canary: dict[str, Any]
    ) -> dict[str, Any] | None:
        installation_id = self.github.repository_installation_id(target.repository)
        runs = self.github.workflow_runs_complete(
            installation_id,
            target.repository,
            workflow=target.workflow,
            branch=target.ref,
            event="workflow_dispatch",
        )
        matches = []
        for run in runs:
            run_id = run.get("id")
            if (
                isinstance(run_id, int)
                and not isinstance(run_id, bool)
                and run_id > int(canary["baseline_run_id"])
                and run.get("event") == "workflow_dispatch"
                and run.get("head_sha") == canary["head_sha"]
                and run.get("display_title") == canary["dispatch_correlation"]
            ):
                matches.append(run)
        if len(matches) > 1:
            raise WorkerRecoveryError("GitHub canary run correlation is ambiguous")
        if not matches:
            return None
        if canary.get("run_id") is not None:
            self._require_canary_run(matches[0], canary)
        return matches[0]

    def _require_canary_run(self, run: dict[str, Any], canary: dict[str, Any]) -> None:
        if (
            run.get("id") != canary["run_id"]
            or run.get("head_sha") != canary["head_sha"]
            or run.get("event") != "workflow_dispatch"
            or run.get("display_title") != canary["dispatch_correlation"]
        ):
            raise WorkerRecoveryError("GitHub canary run binding changed")

    @staticmethod
    def _positive_id(value: dict[str, Any], field: str) -> int:
        result = value.get(field)
        if isinstance(result, bool) or not isinstance(result, int) or result <= 0:
            raise WorkerRecoveryError(f"GitHub {field} is invalid")
        return result

    def _observe_recovered(
        self,
        target: RecoveryTarget,
        row: dict[str, Any],
        expected_labels: tuple[str, ...] | tuple[tuple[str, ...], ...],
        *,
        require_idle: bool = True,
        canary: dict[str, Any] | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
        allowed = (
            expected_labels
            if expected_labels and isinstance(expected_labels[0], tuple)
            else (cast(tuple[str, ...], expected_labels),)
        )
        runners, observed, provider = self._observe_runner(
            target,
            expected_labels=cast(tuple[tuple[str, ...], ...], allowed),
            status="online",
            require_idle=require_idle,
            canary=canary,
        )
        matches = [runner for runner in runners if runner["name"] == target.worker_name]
        prior_id = row["provider_runner_id"]
        if len(matches) != 1:
            raise WorkerRecoveryError("recovered GitHub runner identity is not unique")
        if target.action == "restore_saved_configuration" and observed["id"] != prior_id:
            raise WorkerRecoveryError("saved Platform runner identity changed")
        return runners, observed, provider

    def _observe_runner(
        self,
        target: RecoveryTarget,
        *,
        expected_labels: tuple[str, ...] | tuple[tuple[str, ...], ...],
        status: str,
        require_idle: bool,
        canary: dict[str, Any] | None = None,
    ) -> tuple[list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
        installation_id = self.github.repository_installation_id(target.repository)
        runners = sorted(
            (
                _runner_record(raw)
                for raw in self.github.repository_runners(installation_id, target.repository)
            ),
            key=lambda runner: int(runner["id"]),
        )
        matches = [runner for runner in runners if runner["name"] == target.worker_name]
        if len(matches) != 1:
            raise WorkerRecoveryError("GitHub runner identity is not unique")
        listed = matches[0]
        observed_value = self.github.observe_repository_runner(target.repository, int(listed["id"]))
        observed: dict[str, Any] = {
            "id": observed_value.runner_id,
            "name": observed_value.name,
            "status": observed_value.status,
            "busy": observed_value.busy,
            "labels": list(observed_value.labels),
            "active_job_ids": list(observed_value.active_job_ids),
            "observed_at": observed_value.observed_at,
        }
        allowed_labels = (
            expected_labels
            if expected_labels and isinstance(expected_labels[0], tuple)
            else (cast(tuple[str, ...], expected_labels),)
        )
        if (
            listed
            != {
                "id": observed["id"],
                "name": observed["name"],
                "status": observed["status"],
                "busy": observed["busy"],
                "labels": observed["labels"],
            }
            or observed["name"] != target.worker_name
            or observed["status"] != status
            or tuple(observed["labels"]) not in allowed_labels
            or (require_idle and (observed["busy"] or observed["active_job_ids"]))
        ):
            raise WorkerRecoveryError("GitHub runner observation does not satisfy recovery policy")
        provider_observation: dict[str, Any] = {
            "schema": (
                "qdev-worker-recovery-provider-observation-v1"
                if canary is not None
                else "qdev-worker-provider-observation-v1"
            ),
            "repository": target.repository,
            "runners": {"total_count": len(runners), "items": runners},
            "active_target_jobs": {
                "total_count": len(observed["active_job_ids"]),
                "items": list(observed["active_job_ids"]),
            },
        }
        if canary is not None:
            provider_observation["canary"] = {
                "repository": target.repository,
                "workflow": target.workflow,
                "ref": canary["ref"],
                "head_sha": canary["head_sha"],
                "dispatch_correlation": canary["dispatch_correlation"],
                "temporary_label": canary["temporary_label"],
                "dispatch_observed_label": canary["dispatch_observed_label"],
                "run_observed_label": canary["run_observed_label"],
                "baseline_run_id": canary["baseline_run_id"],
                "run_id": canary["run_id"],
                "run_attempt": canary["run_attempt"],
                "job_id": canary["job_id"],
                "job_labels": list(canary["job_labels"]),
                "job_runner_id": canary["job_runner_id"],
                "job_runner_name": canary["job_runner_name"],
                "status": canary["run_status"],
                "conclusion": canary["conclusion"],
                "completed_at": canary["completed_at"],
            }
        return runners, observed, provider_observation

    def _command_envelope(self, row: dict[str, Any], *, target: RecoveryTarget) -> dict[str, Any]:
        now = datetime.now(UTC)
        expires_at = now + timedelta(seconds=self.settings.recovery_command_ttl_seconds)
        registration_token: str | None = None
        token_expires_at: datetime | None = None
        if target.action == "replace_existing_registration":
            minted = self.github.runner_registration_token(target.repository)
            registration_token = minted.token
            token_expires_at = minted.expires_at.astimezone(UTC)
            expires_at = min(expires_at, token_expires_at)
        command: dict[str, Any] = {
            "schema": "qdev-runner-recovery-agent-command-v1",
            "operation_id": row["operation_id"],
            "request_fingerprint": row["request_fingerprint"],
            "target_id": target.target_id,
            "worker_name": target.worker_name,
            "repository": target.repository,
            "provider_runner_id": row["provider_runner_id"],
            "labels": list(target.labels),
            "recovery_action": target.action,
            "operator_certificate_sha256": row["operator_certificate_sha256"],
            "expected_agent_certificate_sha256": row["expected_agent_certificate_sha256"],
            "interface_version": INTERFACE_VERSION,
            "interface_digest": INTERFACE_DIGEST,
            "controller_revision": row["controller_revision"],
            "controller_release_digest": row["controller_release_digest"],
            "controller_receipt_id": row["controller_receipt_id"],
            "policy_digest": row["policy_digest"],
            "agent_release_digest": row["agent_release_digest"],
            "provider_idle_proof_digest": row["provider_idle_proof_digest"],
            "provider_reconciliation_digest": row["provider_reconciliation_digest"],
            "request_nonce": row["request_nonce"],
            "issued_at": _rfc3339(now),
            "expires_at": _rfc3339(expires_at),
            "registration_token": registration_token,
            "registration_token_expires_at": (
                None if token_expires_at is None else _rfc3339(token_expires_at)
            ),
        }
        # Validate the public shape without serializing SecretStr back out: the
        # raw credential remains only in this mTLS response and is never logged.
        RecoveryAgentCommand.model_validate(command)
        command_digest = _digest(command, prefix=True)
        signature = hmac.new(
            self._agent_signing_key().encode("utf-8"),
            canonical_json(command),
            hashlib.sha256,
        ).hexdigest()
        return {
            "schema": "qdev-runner-recovery-agent-envelope-v1",
            "command": command,
            "command_digest": command_digest,
            "signature": signature,
        }

    def _project(
        self, row: dict[str, Any], *, idempotent_replay: bool
    ) -> RecoveryOperationResponse:
        target = self._target_from_row(row)
        state = str(row["state"])
        native_outcome = row.get("native_outcome")
        if state == "completed":
            canary = self.store.worker_recovery_canary(str(row["operation_id"]))
            if canary is None:
                projected = "awaiting_acceptance"
            elif canary.get("phase") == "ambiguous" or (
                canary.get("phase") in {"completed", "cleanup_pending", "cleaned"}
                and canary.get("conclusion") not in {None, "success"}
            ):
                projected = "failed"
            else:
                projected = "pending_canary"
        elif state == "released":
            if native_outcome == "not_applied":
                projected = "not_applied"
            else:
                projected = "already_completed" if idempotent_replay else "completed"
        elif native_outcome in {"failed", "ambiguous"}:
            projected = str(native_outcome)
        else:
            projected = state
        return RecoveryOperationResponse.model_validate(
            {
                "schema": "qdev-runner-recovery-operation-v1",
                "operation_id": row["operation_id"],
                "request_fingerprint": row["request_fingerprint"],
                "target_id": target.target_id,
                "worker_name": row["worker_name"],
                "repository": row["repository"],
                "provider_runner_id": row["provider_runner_id"],
                "state": projected,
                "native_outcome": native_outcome,
                "controller_revision": row["controller_revision"],
                "controller_release_digest": row["controller_release_digest"],
                "policy_digest": row["policy_digest"],
                "agent_release_digest": row["agent_release_digest"],
                "idempotent_replay": idempotent_replay,
            }
        )

    def _operation(self, operation_id: str, fingerprint: str) -> dict[str, Any]:
        row = self.store.worker_recovery(operation_id)
        if row is None or not hmac.compare_digest(str(row["request_fingerprint"]), fingerprint):
            raise WorkerRecoveryError("recovery operation is unavailable")
        return row

    def _require_row_binding(
        self,
        row: dict[str, Any],
        *,
        target: RecoveryTarget,
        fingerprint: str,
        operator_certificate: str,
        release: dict[str, Any],
    ) -> None:
        try:
            labels = tuple(json.loads(str(row["labels_json"])))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise WorkerRecoveryError("recovery operation binding is invalid") from error
        expected = (
            target.worker_name,
            fingerprint,
            target.repository,
            labels,
            target.action,
            operator_certificate,
            self._agent_certificate(target),
            INTERFACE_VERSION,
            INTERFACE_DIGEST,
            release["revision"],
            release["release_digest"],
            self._policy_digest(),
            self._agent_release_digest(),
        )
        actual = (
            row.get("worker_name"),
            row.get("request_fingerprint"),
            row.get("repository"),
            labels,
            row.get("recovery_action"),
            row.get("operator_certificate_sha256"),
            row.get("expected_agent_certificate_sha256"),
            row.get("interface_version"),
            row.get("interface_digest"),
            row.get("controller_revision"),
            row.get("controller_release_digest"),
            row.get("policy_digest"),
            row.get("agent_release_digest"),
        )
        if actual != expected:
            raise WorkerRecoveryError("recovery operation binding changed")

    def _require_current_row(self, row: dict[str, Any], *, release: dict[str, Any]) -> None:
        target = self._target_from_row(row)
        self._require_row_binding(
            row,
            target=target,
            fingerprint=str(row["request_fingerprint"]),
            operator_certificate=str(row["operator_certificate_sha256"]),
            release=release,
        )

    def _require_acceptance_row(self, row: dict[str, Any], *, release: dict[str, Any]) -> None:
        """Allow a completed native mutation to finish after controller upgrade.

        Native execution remains bound to its original immutable release.  Only
        the provider/canary acceptance half may cross a release boundary, and
        only when every non-release authority binding is still exact.  The
        current signed provenance authenticates each acceptance attempt, while
        the durable canary ledger binds the exact provider run and recovered
        runner.  The original native operation receipt remains release-bound.
        """

        try:
            self._require_current_row(row, release=release)
            return
        except WorkerRecoveryError:
            pass
        target = self._target_from_row(row)
        try:
            labels = tuple(json.loads(str(row["labels_json"])))
        except (TypeError, ValueError, json.JSONDecodeError) as error:
            raise WorkerRecoveryError("recovery operation binding is invalid") from error
        if (
            row.get("state") != "completed"
            or row.get("native_outcome") != "completed"
            or row.get("worker_name") != target.worker_name
            or row.get("repository") != target.repository
            or labels != target.labels
            or row.get("recovery_action") != target.action
            or row.get("expected_agent_certificate_sha256") != self._agent_certificate(target)
            or row.get("interface_version") != INTERFACE_VERSION
            or row.get("interface_digest") != INTERFACE_DIGEST
            or row.get("agent_release_digest") != self._agent_release_digest()
        ):
            raise WorkerRecoveryError("recovery operation binding changed")

    @staticmethod
    def _target_from_row(row: dict[str, Any]) -> RecoveryTarget:
        worker_name = row.get("worker_name")
        matches = [
            target for target in RECOVERY_TARGETS.values() if target.worker_name == worker_name
        ]
        if len(matches) != 1:
            raise WorkerRecoveryError("recovery operation target is invalid")
        return matches[0]

    def _configuration(self) -> dict[str, Any]:
        self._receipt_key()
        self._agent_signing_key()
        self._policy_digest()
        self._agent_release_digest()
        for target in RECOVERY_TARGETS.values():
            self._agent_certificate(target)
        release = self.release_status_reader()
        if (
            release.get("state") != "active"
            or not isinstance(release.get("revision"), str)
            or not _GIT_REVISION.fullmatch(str(release["revision"]))
            or not isinstance(release.get("release_digest"), str)
            or not _SHA256_HEX.fullmatch(str(release["release_digest"]))
        ):
            raise WorkerRecoveryConfigurationError(
                "active controller release binding is unavailable"
            )
        return release

    def _validate_provenance(
        self,
        provenance: RecoveryRequestProvenance,
        *,
        release: dict[str, Any],
    ) -> float:
        now = datetime.now(UTC)
        issued = provenance.issued_at.astimezone(UTC)
        expires = provenance.expires_at.astimezone(UTC)
        max_age = timedelta(seconds=self.settings.recovery_proof_max_age_seconds)
        if (
            issued > now + timedelta(seconds=5)
            or now > expires
            or expires - issued > max_age
            or now - issued > max_age
            or provenance.controller_revision != release["revision"]
            or provenance.controller_release_digest != release["release_digest"]
            or provenance.policy_digest != self._policy_digest()
            or provenance.agent_release_digest != self._agent_release_digest()
        ):
            raise WorkerRecoveryError("recovery request provenance is stale or mismatched")
        return issued.timestamp()

    def _require_no_claim_scope(self, worker_name: str) -> None:
        try:
            scopes = load_claim_scopes(self.settings.claim_scopes_path)
        except ClaimScopeError as error:
            raise WorkerRecoveryError("claim-scope state is unavailable") from error
        now = datetime.now(UTC)
        if any(
            scope.worker_name == worker_name and scope.expires_at > now for scope in scopes.values()
        ):
            raise WorkerRecoveryError("worker has an unexpired claim scope")

    def _request_fingerprint(
        self, request: RecoveryPrepareRequest, operator_certificate: str
    ) -> str:
        return _digest(
            {
                "schema": "qdev-runner-recovery-request-binding-v1",
                "request": request.model_dump(mode="json", by_alias=True),
                "operator_certificate_sha256": operator_certificate,
                "interface_version": INTERFACE_VERSION,
                "interface_digest": INTERFACE_DIGEST,
            }
        )

    def _operator_certificate(self, value: str) -> str:
        certificate = value.strip().lower()
        if not _SHA256_HEX.fullmatch(certificate):
            raise WorkerRecoveryError("verified operator certificate fingerprint is invalid")
        allowlist = self.settings.recovery_operator_certificate_sha256s
        if not any(hmac.compare_digest(certificate, allowed) for allowed in allowlist):
            raise WorkerRecoveryError("verified operator certificate is not allowlisted")
        return certificate

    def _require_operation_operator(self, row: dict[str, Any], value: str) -> None:
        certificate = self._operator_certificate(value)
        if not hmac.compare_digest(certificate, str(row.get("operator_certificate_sha256", ""))):
            raise WorkerRecoveryError(
                "verified operator certificate does not own recovery operation"
            )

    def _agent_certificate(self, target: RecoveryTarget) -> str:
        value = (
            self.settings.recovery_platform_agent_certificate_sha256
            if target.target_id == "qdev-platform-ci-187"
            else self.settings.recovery_qazstack_agent_certificate_sha256
        )
        if value is None or not _SHA256_HEX.fullmatch(value):
            raise WorkerRecoveryConfigurationError("recovery agent certificate binding is invalid")
        return value

    def _receipt_key(self) -> str:
        value = self.settings.operator_receipt_key
        if value is None or len(value) < 32:
            raise WorkerRecoveryConfigurationError("recovery receipt key is unavailable")
        return value

    def _agent_signing_key(self) -> str:
        value = self.settings.recovery_agent_signing_key
        if value is None or len(value) < 32:
            raise WorkerRecoveryConfigurationError("recovery agent signing key is unavailable")
        return value

    def _policy_digest(self) -> str:
        value = self.settings.recovery_policy_digest
        if value is None or not hmac.compare_digest(value, POLICY_DIGEST):
            raise WorkerRecoveryConfigurationError(
                "recovery policy digest does not match the checked-in policy"
            )
        return value

    def _agent_release_digest(self) -> str:
        value = self.settings.recovery_agent_release_digest
        if value is None or not _SHA256_DIGEST.fullmatch(value):
            raise WorkerRecoveryConfigurationError("recovery agent release digest is unavailable")
        return value


def recover_idle_worker(*_args: Any, **_kwargs: Any) -> NoReturn:
    """Retired compatibility symbol; legacy caller-owned recovery is forbidden."""

    raise WorkerRecoveryError(
        "legacy worker recovery is retired; use the typed controller-owned API"
    )
