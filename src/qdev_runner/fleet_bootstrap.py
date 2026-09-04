"""Fail-closed policy for the one-time fleet bootstrap control operation.

The policy deliberately authorizes *intent* only.  A controller process must
separately validate the GitHub Actions OIDC token and use the existing QDev CA
to mint the short-lived mTLS claim consumed by the root-owned lifecycle agent.
Keeping those roles separate prevents a repository workflow from choosing a
host, image, compose file, worker, or arbitrary controller revision.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, model_validator

from .release_lane import ReleaseLanePolicy

POLICY_SCHEMA = "qdev-fleet-bootstrap-policy-v1"
REQUEST_SCHEMA = "qdev-fleet-bootstrap-request-v1"
ALLOWED_ACTIONS = frozenset(
    {"activate-controller", "enrol-host-agent", "restore-existing-worker"}
)

_SHA = re.compile(r"^[0-9a-f]{40}$")
_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_BRANCH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]{0,127}$")
_WORKFLOW_PATH = re.compile(r"^\.github/workflows/[A-Za-z0-9._-]+\.ya?ml$")
_WORKER = re.compile(r"^[a-z0-9][a-z0-9-]{2,127}$")


class FleetBootstrapError(RuntimeError):
    """The bootstrap policy or request cannot be trusted."""


@dataclass(frozen=True)
class BootstrapIdentity:
    repository: str
    branch: str
    workflow: str
    audience: str
    max_claim_ttl_seconds: int


@dataclass(frozen=True)
class ControllerActivation:
    revision: str
    release_digest: str
    rollback_revision: str
    rollback_release_digest: str


class FleetBootstrapRequest(BaseModel):
    """The controller-facing, non-secret bootstrap request envelope."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)

    schema_name: str = Field(alias="schema")
    action: Literal[
        "activate-controller", "enrol-host-agent", "restore-existing-worker"
    ]
    source_sha: str
    run_id: int = Field(ge=1)
    job_id: int = Field(ge=1)
    attempt: int = Field(ge=1)
    claim_ttl_seconds: int = Field(ge=1)
    controller_revision: str
    controller_release_digest: str
    release_lane: str | None = None
    worker_name: str | None = None

    @model_validator(mode="after")
    def validate_action_shape(self) -> FleetBootstrapRequest:
        if self.action == "activate-controller":
            if self.release_lane is not None or self.worker_name is not None:
                raise ValueError("controller activation cannot name a lane or worker")
        elif self.action == "enrol-host-agent":
            if self.release_lane is None or self.worker_name is not None:
                raise ValueError("host-agent enrolment must name exactly one release lane")
        elif self.release_lane is not None or self.worker_name is None:
            raise ValueError("worker restoration must name exactly one worker")
        return self


class FleetBootstrapPolicy:
    """Strict allowlist for the controller bootstrap transition."""

    def __init__(self, path: Path, release_lanes_path: Path) -> None:
        try:
            document = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise FleetBootstrapError("fleet bootstrap policy is unavailable") from exc
        if not isinstance(document, dict) or set(document) != {
            "schema_version",
            "bootstrap",
            "activation",
            "enrolment",
            "workers",
        }:
            raise FleetBootstrapError("fleet bootstrap policy shape is invalid")
        if document["schema_version"] != POLICY_SCHEMA:
            raise FleetBootstrapError("fleet bootstrap policy schema is invalid")
        self.identity = self._identity(document["bootstrap"])
        self.activation = self._activation(document["activation"])
        self._allowed_lanes = self._parse_lanes(document["enrolment"], release_lanes_path)
        self._allowed_workers = self._parse_workers(document["workers"])

    @staticmethod
    def _identity(raw: object) -> BootstrapIdentity:
        if not isinstance(raw, dict) or set(raw) != {
            "repository",
            "branch",
            "workflow",
            "audience",
            "max_claim_ttl_seconds",
        }:
            raise FleetBootstrapError("bootstrap identity is invalid")
        repository = raw["repository"]
        branch = raw["branch"]
        workflow = raw["workflow"]
        audience = raw["audience"]
        ttl = raw["max_claim_ttl_seconds"]
        if (
            not isinstance(repository, str)
            or repository.count("/") != 1
            or not all(part for part in repository.split("/"))
            or not isinstance(branch, str)
            or not _BRANCH.fullmatch(branch)
            or not isinstance(workflow, str)
            or not _WORKFLOW_PATH.fullmatch(workflow)
            or not isinstance(audience, str)
            or not audience
            or isinstance(ttl, bool)
            or not isinstance(ttl, int)
            or not 60 <= ttl <= 900
        ):
            raise FleetBootstrapError("bootstrap identity values are invalid")
        return BootstrapIdentity(repository, branch, workflow, audience, ttl)

    @staticmethod
    def _activation(raw: object) -> ControllerActivation:
        expected = {
            "controller_revision",
            "controller_release_digest",
            "rollback_revision",
            "rollback_release_digest",
        }
        if not isinstance(raw, dict) or set(raw) != expected:
            raise FleetBootstrapError("bootstrap activation policy is invalid")
        values = tuple(raw[name] for name in sorted(expected))
        if not all(isinstance(value, str) for value in values):
            raise FleetBootstrapError("bootstrap activation values are invalid")
        activation = ControllerActivation(
            revision=str(raw["controller_revision"]),
            release_digest=str(raw["controller_release_digest"]),
            rollback_revision=str(raw["rollback_revision"]),
            rollback_release_digest=str(raw["rollback_release_digest"]),
        )
        if (
            not _SHA.fullmatch(activation.revision)
            or not _DIGEST.fullmatch(activation.release_digest)
            or not _SHA.fullmatch(activation.rollback_revision)
            or not _DIGEST.fullmatch(activation.rollback_release_digest)
            or activation.revision == activation.rollback_revision
            or activation.release_digest == activation.rollback_release_digest
        ):
            raise FleetBootstrapError("bootstrap immutable controller tuple is invalid")
        return activation

    @staticmethod
    def _parse_lanes(raw: object, release_lanes_path: Path) -> frozenset[str]:
        if not isinstance(raw, dict) or set(raw) != {"lanes"}:
            raise FleetBootstrapError("bootstrap enrolment policy is invalid")
        values = raw["lanes"]
        if (
            not isinstance(values, list)
            or not values
            or not all(isinstance(value, str) for value in values)
            or len(values) != len(set(values))
        ):
            raise FleetBootstrapError("bootstrap enrolment lanes are invalid")
        try:
            policy = ReleaseLanePolicy(release_lanes_path)
            for name in values:
                policy.lane(name)
        except Exception as exc:
            raise FleetBootstrapError("bootstrap enrolment lane is not registered") from exc
        return frozenset(values)

    @staticmethod
    def _parse_workers(raw: object) -> frozenset[str]:
        if (
            not isinstance(raw, list)
            or not raw
            or not all(isinstance(value, str) and _WORKER.fullmatch(value) for value in raw)
            or len(raw) != len(set(raw))
        ):
            raise FleetBootstrapError("bootstrap workers are invalid")
        return frozenset(raw)

    def validate(self, request: FleetBootstrapRequest) -> None:
        if request.schema_name != REQUEST_SCHEMA:
            raise FleetBootstrapError("bootstrap request schema is invalid")
        if (
            not _SHA.fullmatch(request.source_sha)
            or not _SHA.fullmatch(request.controller_revision)
            or not _DIGEST.fullmatch(request.controller_release_digest)
        ):
            raise FleetBootstrapError("bootstrap immutable request values are invalid")
        if request.claim_ttl_seconds > self.identity.max_claim_ttl_seconds:
            raise FleetBootstrapError("bootstrap claim TTL exceeds policy")
        if (
            request.controller_revision != self.activation.revision
            or request.controller_release_digest != self.activation.release_digest
        ):
            raise FleetBootstrapError("bootstrap controller tuple is not allowlisted")
        if request.action == "enrol-host-agent" and request.release_lane not in self._allowed_lanes:
            raise FleetBootstrapError("bootstrap release lane is not allowlisted")
        if (
            request.action == "restore-existing-worker"
            and request.worker_name not in self._allowed_workers
        ):
            raise FleetBootstrapError("bootstrap worker is not allowlisted")

    def validate_oidc_claims(
        self, claims: dict[str, Any], request: FleetBootstrapRequest
    ) -> None:
        """Bind the OIDC claim to one immutable workflow attempt.

        The JWT signature and standard temporal checks are performed by the
        GitHub OIDC verifier before this policy method is called.  This method
        supplies the controller-specific repository, workflow, branch, SHA,
        run, job-attempt and audience binding.
        """
        expected_workflow_ref = (
            f"{self.identity.repository}/{self.identity.workflow}@refs/heads/"
            f"{self.identity.branch}"
        )
        attempt = claims.get("run_attempt")
        if isinstance(attempt, bool) or str(attempt) != str(request.attempt):
            raise FleetBootstrapError("bootstrap OIDC attempt is invalid")
        if (
            claims.get("repository") != self.identity.repository
            or claims.get("ref") != f"refs/heads/{self.identity.branch}"
            or claims.get("sha") != request.source_sha
            or str(claims.get("run_id")) != str(request.run_id)
            or claims.get("workflow_ref") != expected_workflow_ref
            or claims.get("job_workflow_ref") != expected_workflow_ref
        ):
            raise FleetBootstrapError("bootstrap OIDC scope is invalid")
