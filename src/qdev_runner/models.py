from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, model_validator


@dataclass(frozen=True)
class Profile:
    name: str
    labels: tuple[str, ...]
    cpu: float
    memory_mb: int
    disk_mb: int
    pids_limit: int
    timeout_minutes: int
    allow_public_pr: bool


@dataclass(frozen=True)
class RepositoryPolicy:
    full_name: str
    repository_id: int
    private: bool
    archived: bool
    default_branch: str
    profiles: tuple[str, ...]


@dataclass(frozen=True)
class QueuedJob:
    delivery_id: str
    job_id: int
    run_id: int
    repository: str
    repository_id: int
    installation_id: int
    labels: tuple[str, ...]
    head_sha: str
    head_branch: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class GitHubRunnerObservation:
    repository: str
    runner_id: int
    name: str
    status: str
    busy: bool
    labels: tuple[str, ...]
    active_job_ids: tuple[int, ...]
    observed_at: float


@dataclass(frozen=True)
class GitHubRegistrationToken:
    token: str = field(repr=False)
    expires_at: datetime


GitRevision = Annotated[str, Field(pattern=r"^[0-9a-f]{40}$")]
Sha256Hex = Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
Sha256Digest = Annotated[str, Field(pattern=r"^sha256:[0-9a-f]{64}$")]
RecoveryIdentifier = Annotated[
    str,
    Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$"),
]
RecoveryTargetId = Literal["qdev-platform-ci-187", "qdev-qazstack-01"]
RecoveryAction = Literal["restore_saved_configuration", "replace_existing_registration"]
RecoveryNativeOutcome = Literal["completed", "not_applied", "failed", "ambiguous"]


class RecoveryRequestProvenance(BaseModel):
    """Fresh request binding supplied by the certificate-authenticated operator."""

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(
        default="qdev-runner-recovery-provenance-v1",
        alias="schema",
        pattern=r"^qdev-runner-recovery-provenance-v1$",
    )
    nonce: RecoveryIdentifier
    issued_at: datetime
    expires_at: datetime
    controller_revision: GitRevision
    controller_release_digest: Sha256Hex
    policy_digest: Sha256Digest
    agent_release_digest: Sha256Digest

    @model_validator(mode="after")
    def validate_time_order(self) -> RecoveryRequestProvenance:
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("recovery provenance timestamps must include a timezone")
        if self.expires_at <= self.issued_at:
            raise ValueError("recovery provenance expiry must follow issuance")
        return self


class RecoveryPrepareRequest(BaseModel):
    """The only operator-supplied shape that can start fixed-target recovery."""

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(
        default="qdev-runner-recovery-prepare-v1",
        alias="schema",
        pattern=r"^qdev-runner-recovery-prepare-v1$",
    )
    target_id: RecoveryTargetId
    idempotency_key: RecoveryIdentifier
    reason: str = Field(min_length=8, max_length=500)
    provenance: RecoveryRequestProvenance


class RecoveryStatusRequest(BaseModel):
    """Exact operation reference; it cannot select a target or native outcome."""

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(
        default="qdev-runner-recovery-status-v1",
        alias="schema",
        pattern=r"^qdev-runner-recovery-status-v1$",
    )
    operation_id: Sha256Hex
    request_fingerprint: Sha256Hex
    provenance: RecoveryRequestProvenance


class RecoveryReconcileRequest(BaseModel):
    """Native result supplied by the certificate-authenticated host agent."""

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(
        default="qdev-runner-recovery-reconcile-v1",
        alias="schema",
        pattern=r"^qdev-runner-recovery-reconcile-v1$",
    )
    operation_id: Sha256Hex
    request_fingerprint: Sha256Hex
    target_id: RecoveryTargetId
    recovery_action: RecoveryAction
    request_nonce: RecoveryIdentifier
    provider_reconciliation_digest: Sha256Digest
    outcome: Literal["completed", "not_applied", "failed", "ambiguous"]
    outcome_digest: Sha256Digest
    agent_release_digest: Sha256Digest
    observed_at: datetime

    @model_validator(mode="after")
    def validate_observed_at(self) -> RecoveryReconcileRequest:
        if self.observed_at.tzinfo is None:
            raise ValueError("agent outcome timestamp must include a timezone")
        return self


class RecoveryAcceptRequest(BaseModel):
    """Request controller-owned provider and canary acceptance for one operation."""

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(
        default="qdev-runner-recovery-accept-v1",
        alias="schema",
        pattern=r"^qdev-runner-recovery-accept-v1$",
    )
    operation_id: Sha256Hex
    request_fingerprint: Sha256Hex
    provenance: RecoveryRequestProvenance


class RecoveryAgentClaimRequest(BaseModel):
    """Secret-free pull request; the verified certificate selects the target."""

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(
        default="qdev-runner-recovery-agent-claim-v1",
        alias="schema",
        pattern=r"^qdev-runner-recovery-agent-claim-v1$",
    )
    operation_id: Sha256Hex | None = None


class RecoveryAgentCommand(BaseModel):
    """One signed command understood by the fixed host recovery agent."""

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(
        default="qdev-runner-recovery-agent-command-v1",
        alias="schema",
        pattern=r"^qdev-runner-recovery-agent-command-v1$",
    )
    operation_id: Sha256Hex
    request_fingerprint: Sha256Hex
    target_id: RecoveryTargetId
    worker_name: RecoveryIdentifier
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    provider_runner_id: int = Field(gt=0)
    labels: tuple[str, ...] = Field(min_length=1, max_length=16)
    recovery_action: RecoveryAction
    operator_certificate_sha256: Sha256Hex
    expected_agent_certificate_sha256: Sha256Hex
    interface_version: RecoveryIdentifier
    interface_digest: Sha256Hex
    controller_revision: GitRevision
    controller_release_digest: Sha256Hex
    controller_receipt_id: Sha256Hex
    policy_digest: Sha256Digest
    agent_release_digest: Sha256Digest
    provider_idle_proof_digest: Sha256Digest
    provider_reconciliation_digest: Sha256Digest
    request_nonce: RecoveryIdentifier
    issued_at: datetime
    expires_at: datetime
    registration_token: SecretStr | None = None
    registration_token_expires_at: datetime | None = None

    @model_validator(mode="after")
    def validate_registration_token(self) -> RecoveryAgentCommand:
        if self.issued_at.tzinfo is None or self.expires_at.tzinfo is None:
            raise ValueError("agent command timestamps must include a timezone")
        if self.expires_at <= self.issued_at:
            raise ValueError("agent command expiry must follow issuance")
        token_present = self.registration_token is not None
        expiry_present = self.registration_token_expires_at is not None
        if token_present != expiry_present:
            raise ValueError("registration token and expiry must be supplied together")
        if self.registration_token_expires_at is not None:
            if self.registration_token_expires_at.tzinfo is None:
                raise ValueError("registration token expiry must include a timezone")
            if self.registration_token_expires_at <= self.issued_at:
                raise ValueError("registration token must be fresh")
            if self.expires_at > self.registration_token_expires_at:
                raise ValueError("agent command cannot outlive its registration token")
        if self.recovery_action == "replace_existing_registration" and not token_present:
            raise ValueError("replacement recovery requires a registration token")
        if self.recovery_action == "restore_saved_configuration" and token_present:
            raise ValueError("saved-configuration recovery cannot receive a registration token")
        return self


class RecoveryAgentCommandEnvelope(BaseModel):
    """Signed, non-executable instruction returned only to the outbound agent."""

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(
        default="qdev-runner-recovery-agent-envelope-v1",
        alias="schema",
        pattern=r"^qdev-runner-recovery-agent-envelope-v1$",
    )
    command: RecoveryAgentCommand
    command_digest: Sha256Digest
    signature: Sha256Hex


class RecoveryBindingsResponse(BaseModel):
    """Current non-secret bindings for a fresh operator recovery request."""

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(
        default="qdev-runner-recovery-bindings-v1",
        alias="schema",
        pattern=r"^qdev-runner-recovery-bindings-v1$",
    )
    controller_revision: GitRevision
    controller_release_digest: Sha256Hex
    policy_digest: Sha256Digest
    agent_release_digest: Sha256Digest
    interface_version: RecoveryIdentifier
    interface_digest: Sha256Hex
    observed_at: datetime
    proof_max_age_seconds: float = Field(gt=0, le=300)

    @model_validator(mode="after")
    def validate_observed_at(self) -> RecoveryBindingsResponse:
        if self.observed_at.tzinfo is None:
            raise ValueError("recovery binding timestamp must include a timezone")
        return self


class RecoveryOperationResponse(BaseModel):
    """Topology-free recovery projection safe for the private operator API."""

    model_config = ConfigDict(extra="forbid")

    schema_name: str = Field(default="qdev-runner-recovery-operation-v1", alias="schema")
    operation_id: Sha256Hex
    request_fingerprint: Sha256Hex
    target_id: RecoveryTargetId
    worker_name: RecoveryIdentifier
    repository: str = Field(pattern=r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
    provider_runner_id: int = Field(gt=0)
    state: str = Field(
        pattern=(
            r"^(prepared|invoking|awaiting_acceptance|pending_canary|completed|"
            r"already_completed|not_applied|failed|ambiguous)$"
        )
    )
    native_outcome: str | None = Field(
        default=None,
        pattern=r"^(completed|not_applied|failed|ambiguous)$",
    )
    controller_revision: GitRevision
    controller_release_digest: Sha256Hex
    policy_digest: Sha256Digest
    agent_release_digest: Sha256Digest
    idempotent_replay: bool = False
