"""Synthetic bootstrap identities; never production credentials or receipts."""
from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from qdev_runner.bootstrap_authority import authorize_bootstrap
from qdev_runner.fleet_bootstrap import REQUEST_SCHEMA, FleetBootstrapPolicy, FleetBootstrapRequest
from qdev_runner.models import QueuedJob
from qdev_runner.store import Store

ROOT = Path(__file__).resolve().parents[1]
KEY = "synthetic-directive-key"


def policy() -> FleetBootstrapPolicy:
    return FleetBootstrapPolicy(
        ROOT / "config/fleet-bootstrap.yml", ROOT / "config/release-lanes.yml",
    )


def request(worker: str = "qdev-platform-ci-187") -> FleetBootstrapRequest:
    activation = policy().activation
    return FleetBootstrapRequest.model_validate({
        "schema": REQUEST_SCHEMA, "action": "restore-existing-worker", "source_sha": "a" * 40,
        "run_id": 123, "job_id": 456, "attempt": 1, "claim_ttl_seconds": 300,
        "controller_revision": activation.revision,
        "controller_release_digest": activation.release_digest,
        "release_lane": None, "worker_name": worker,
    })


def claims() -> dict[str, Any]:
    identity = policy().identity
    now = int(time.time())
    return {
        "iss": "https://token.actions.githubusercontent.com", "aud": identity.audience,
        "repository": identity.repository, "ref": "refs/heads/main", "sha": "a" * 40,
        "run_id": "123", "run_attempt": "1", "event_name": "workflow_dispatch",
        "workflow_ref": f"{identity.repository}/{identity.workflow}@refs/heads/main",
        "iat": now, "nbf": now, "exp": now + 300,
    }


class Verifier:
    def __init__(self) -> None:
        self.claims = claims()

    def verify_and_decode(self, token: str, **kwargs: Any) -> dict[str, Any]:
        assert token == "synthetic-oidc"  # noqa: S105 - inert fixture
        assert kwargs == {
            "repository": policy().identity.repository, "sha": "a" * 40, "run_id": 123,
        }
        return self.claims


class GitHub:
    def __init__(self) -> None:
        self.job = {
            "id": 456, "run_id": 123, "run_attempt": 1, "head_sha": "a" * 40,
            "status": "in_progress", "name": "fleet-bootstrap-execute",
        }
        self.run = {
            "id": 123, "run_attempt": 1, "head_sha": "a" * 40, "head_branch": "main",
            "path": policy().identity.workflow,
            "event": "workflow_dispatch", "status": "in_progress",
        }

    def workflow_job(self, installation: int, repository: str, job_id: int) -> dict[str, Any]:
        assert (installation, repository, job_id) == (300, policy().identity.repository, 456)
        return self.job

    def workflow_run(self, installation: int, repository: str, run_id: int) -> dict[str, Any]:
        assert (installation, repository, run_id) == (300, policy().identity.repository, 123)
        return self.run


def register(store: Store, worker: str = "qdev-platform-ci-187", active_jobs: int = 0) -> None:
    store.enqueue(QueuedJob(
        "bootstrap", 456, 123, policy().identity.repository, 1, 300,
        ("self-hosted", "Linux", "X64", "qdev-ci"), "a" * 40, "main", {},
    ))
    assert store.claim("bootstrap-executor", ("qdev-ci",)) is not None
    store.heartbeat(worker, ("qdev-ci",), active_jobs, (), {"tier": "primary"})


def operation(store: Store, req: FleetBootstrapRequest, key: str = KEY) -> Any:
    return authorize_bootstrap(
        token="synthetic-oidc", request=req, idempotency_key="worker-recovery-001",
        policy=policy(), verifier=Verifier(), github=GitHub(),  # type: ignore[arg-type]
        controller_store=store, signing_key=key,
    )
