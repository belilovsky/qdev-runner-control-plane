from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from qdev_runner.admin_platform import AdminPlatformCandidate
from qdev_runner.admin_platform_state import AdminPlatformStateStore
from qdev_runner.broker import create_app
from qdev_runner.fleet_host_dispatch import FleetHostDispatchSpool
from qdev_runner.models import QueuedJob
from qdev_runner.operations import OperationStore
from qdev_runner.operator import verify_controller_receipt
from qdev_runner.policy import Policy
from qdev_runner.release_lane import (
    ReleaseAdmissionRequest,
    ReleaseLaneError,
    ReleaseLanePolicy,
    controller_claim_payload,
)
from qdev_runner.settings import BrokerSettings
from qdev_runner.store import Store

OPERATOR_TOKEN = "operator-token"  # noqa: S105 - inert test fixture
RECEIPT_KEY = "receipt-key"
DIRECTIVE_KEY = "directive-key"
WORKER_TOKEN = "worker-token"  # noqa: S105 - inert test fixture
WORKER_NAME = "srv1879763-light-primary"
OPERATOR_HEADERS = {
    "X-QDev-Operator-Token": OPERATOR_TOKEN,
    "X-QDev-Operator-mTLS-Identity": "qdev-fleet-operations",
}
_FLEET_BOOTSTRAP_POLICY = Path(__file__).resolve().parents[1] / "config" / "fleet-bootstrap.yml"


def _fleet_bootstrap_activation() -> dict[str, str]:
    return {
        "controller_revision": "a" * 40,
        "controller_release_digest": "sha256:" + "b" * 64,
    }


def _initialized_admin_platform_ledger(tmp_path: Path) -> tuple[Path, Path]:
    template_path = Path(__file__).parents[1] / "config" / "admin-platform-ledger-v2.yml"
    template = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    candidate = AdminPlatformCandidate(**template["active_candidate"])
    state_root = tmp_path / "admin-platform-state"
    state_root.mkdir()
    ledger_path = state_root / "admin-platform-ledger.yml"
    receipt_root = state_root / "receipts"
    signer = OperationStore(
        tmp_path / "admin-platform-operation-store",
        worker_signing_key="unused-worker-key",
        receipt_signing_key=RECEIPT_KEY,
    )
    source_receipt = signer.receipt(
        {
            "kind": "admin-platform-evidence",
            "observed_at": "2026-09-05T00:01:00Z",
            "program_id": template["program"]["id"],
            "stage": "controller",
            "release_id": candidate.release_id,
            "source_sha": candidate.source_sha,
            "evidence_type": "lane_result",
            "lane": "source",
            "outcome": "passed",
        }
    )
    AdminPlatformStateStore(
        ledger_path,
        receipt_key=RECEIPT_KEY,
        receipt_root=receipt_root,
    ).initialize_from_template(
        template_path=template_path,
        candidate=candidate,
        source_receipt=source_receipt,
    )
    return ledger_path, receipt_root


def _app(tmp_path: Path, github: Any | None = None) -> TestClient:
    inventory = tmp_path / "repos.json"
    inventory.write_text(
        json.dumps(
            {
                "repositories": [
                    {
                        "id": 1,
                        "full_name": "belilovsky/qazshield",
                        "private": True,
                        "archived": False,
                        "default_branch": "main",
                        "profiles": ["qdev-ci-docker"],
                    },
                    {
                        "id": 2,
                        "full_name": "belilovsky/qazlake",
                        "private": True,
                        "archived": False,
                        "default_branch": "main",
                        "profiles": ["qdev-ci-docker"],
                    },
                    {
                        "id": 3,
                        "full_name": "belilovsky/example",
                        "private": True,
                        "archived": False,
                        "default_branch": "main",
                        "profiles": ["qdev-ci-docker", "qdev-ci-browser"],
                    },
                    {
                        "id": 4,
                        "full_name": "belilovsky/qazposter",
                        "private": True,
                        "archived": False,
                        "default_branch": "main",
                        "profiles": ["qdev-ci-docker"],
                    },
                    {
                        "id": 5,
                        "full_name": "belilovsky/qdev-runner-control-plane",
                        "private": True,
                        "archived": False,
                        "default_branch": "main",
                        "profiles": ["qdev-ci-docker"],
                    },
                    {
                        "id": 6,
                        "full_name": "belilovsky/qazgeo",
                        "private": True,
                        "archived": False,
                        "default_branch": "main",
                        "profiles": ["qdev-ci-docker"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    profiles = tmp_path / "profiles.yml"
    profiles.write_text(
        yaml.safe_dump(
            {
                "repository_admission_disk_mb": {
                    "belilovsky/qazshield": {"qdev-ci-docker": 15360},
                    "belilovsky/qazlake": {"qdev-ci-docker": 12288},
                    "belilovsky/example": {"qdev-ci-docker": 15360},
                    "belilovsky/qazposter": {"qdev-ci-docker": 15360},
                    "belilovsky/qdev-runner-control-plane": {"qdev-ci-docker": 15360},
                    "belilovsky/qazgeo": {"qdev-ci-docker": 15360},
                },
                "profiles": {
                    "qdev-ci-docker": {
                        "labels": ["self-hosted", "Linux", "X64", "qdev-ci-docker"],
                        "resources": {
                            "cpu": 2.0,
                            "memory_mb": 5120,
                            "disk_mb": 20480,
                            "pids_limit": 1024,
                        },
                        "timeout_minutes": 90,
                        "allow_public_pr": True,
                    },
                    "qdev-ci-browser": {
                        "labels": ["self-hosted", "Linux", "X64", "qdev-ci-browser"],
                        "resources": {
                            "cpu": 2.0,
                            "memory_mb": 5120,
                            "disk_mb": 20480,
                            "pids_limit": 1024,
                        },
                        "timeout_minutes": 90,
                        "allow_public_pr": True,
                    },
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    release_lanes = tmp_path / "release-lanes.yml"
    release_lanes.write_text(
        yaml.safe_dump(
            {
                "schema_version": "qdev-release-lanes-v1",
                "lanes": {
                    "qdev-release-qaz-tours": {
                        "project_id": "qaz-tours",
                        "placement": "vps-hostinger-186",
                        "client_mtls_identity": "qdev-release-client:qaz-tours",
                        "host_agent_mtls_identity": "qdev-host-agent:vps-hostinger-186",
                        "minimum_free_gib": 60,
                        "heartbeat_ttl_seconds": 90,
                        "artifact_repository": "qaz-tours",
                    },
                    "qdev-release-qmt": {
                        "project_id": "kaztilshi",
                        "placement": "srv138jump",
                        "client_mtls_identity": "qdev-release-client:kaztilshi",
                        "host_agent_mtls_identity": "qdev-host-agent:srv138jump",
                        "minimum_free_gib": 20,
                        "heartbeat_ttl_seconds": 90,
                        "artifact_repository": "kaztilshi",
                    },
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    fleet_bootstrap_policy = tmp_path / "fleet-bootstrap.yml"
    fleet_bootstrap_document = yaml.safe_load(_FLEET_BOOTSTRAP_POLICY.read_text(encoding="utf-8"))
    fleet_bootstrap_document["enrolment"] = {"lanes": ["qdev-release-qmt"]}
    fleet_bootstrap_policy.write_text(
        yaml.safe_dump(fleet_bootstrap_document, sort_keys=False),
        encoding="utf-8",
    )
    admin_platform_ledger, admin_platform_receipts = _initialized_admin_platform_ledger(tmp_path)
    settings = BrokerSettings(
        app_id="1",
        app_private_key_path=tmp_path / "app.pem",
        webhook_secret="webhook",
        worker_token=WORKER_TOKEN,
        inventory_path=inventory,
        profiles_path=profiles,
        database_path=tmp_path / "broker.db",
        artifact_root=tmp_path / "artifacts",
        operator_token=OPERATOR_TOKEN,
        operator_receipt_key=RECEIPT_KEY,
        operator_directive_key=DIRECTIVE_KEY,
        operations_root=tmp_path / "operations",
        controller_release_status_path=tmp_path / "controller-release.json",
        claim_scopes_path=tmp_path / "claim-scopes.json",
        release_lanes_path=release_lanes,
        fleet_bootstrap_policy_path=fleet_bootstrap_policy,
        fleet_bootstrap_operation_root=tmp_path / "fleet-bootstrap-operations",
        fleet_bootstrap_receipt_root=tmp_path / "fleet-bootstrap-receipts",
        fleet_host_dispatch_request_root=tmp_path / "fleet-host-dispatch" / "incoming",
        fleet_host_dispatch_result_root=tmp_path / "fleet-host-dispatch" / "results",
        managed_registry_path=Path(__file__).parents[1] / "config" / "managed-registry.yml",
        managed_release_ledger_path=(
            Path(__file__).parents[1] / "config" / "managed-release-ledger.yml"
        ),
        admin_platform_ledger_path=admin_platform_ledger,
        admin_platform_receipt_root=admin_platform_receipts,
        release_jobs_root=tmp_path / "release-jobs",
        release_host_dispatch_keys_file=tmp_path / "release-host-dispatch-keys.json",
        release_host_dispatch_claim_ttl_seconds=120,
    )
    app = create_app(
        settings,
        store=Store(settings.database_path),
        policy=Policy(inventory, profiles),
        github=github or object(),  # type: ignore[arg-type]
    )
    return TestClient(app)


def _release_heartbeat() -> dict[str, Any]:
    return {
        "schema": "qdev-release-host-agent-heartbeat-v1",
        "release_lane": "qdev-release-qaz-tours",
        "project_id": "qaz-tours",
        "placement": "vps-hostinger-186",
        "state": "ready",
        "release_lock": "available",
        "capacity_free_gib": 64,
        "active_release": {
            "source_sha": "c" * 40,
            "artifact_digest": "sha256:" + "c" * 64,
            "artifact_ref": "registry.ci.qdev.run/qaz-tours@sha256:" + "c" * 64,
        },
        "rollback": {
            "verified": True,
            "source_sha": "d" * 40,
            "artifact_digest": "sha256:" + "d" * 64,
            "artifact_ref": "registry.ci.qdev.run/qaz-tours@sha256:" + "d" * 64,
        },
    }


def _release_request(source_sha: str = "a" * 40) -> dict[str, Any]:
    digest = "sha256:" + "b" * 64
    artifact_ref = f"registry.ci.qdev.run/qaz-tours@{digest}"
    return {
        "schema": "qdev-controller-release-request-v1",
        "release_lane": "qdev-release-qaz-tours",
        "project_id": "qaz-tours",
        "placement": "vps-hostinger-186",
        "source_sha": source_sha,
        "artifact_digest": digest,
        "artifact_ref": artifact_ref,
        "candidate_receipt": {
            "schema": "qdev-release-candidate-receipt-v1",
            "status": "passed",
            "source_sha": source_sha,
            "artifact_digest": digest,
            "artifact_ref": artifact_ref,
        },
    }


def test_shared_host_requires_explicit_release_lane(tmp_path: Path) -> None:
    policy_path = tmp_path / "release-lanes.yml"
    policy_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "qdev-release-lanes-v1",
                "lanes": {
                    "qdev-release-qaz-events": {
                        "project_id": "qaz-events",
                        "placement": "vps-main",
                        "client_mtls_identity": "qdev-release-client:qaz-events",
                        "host_agent_mtls_identity": "qdev-host-agent:vps-main",
                        "minimum_free_gib": 20,
                        "heartbeat_ttl_seconds": 90,
                        "artifact_repository": "qaz-events",
                    },
                    "qdev-release-qazgeo": {
                        "project_id": "qazgeo",
                        "placement": "vps-main",
                        "client_mtls_identity": "qdev-release-client:qazgeo",
                        "host_agent_mtls_identity": "qdev-host-agent:vps-main",
                        "minimum_free_gib": 20,
                        "heartbeat_ttl_seconds": 90,
                        "artifact_repository": "qazgeo",
                    },
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )

    policy = ReleaseLanePolicy(policy_path)

    with pytest.raises(ReleaseLaneError, match="must be explicit"):
        policy.lane_for_host("vps-main")
    assert policy.lane_for_host("vps-main", "qdev-release-qazgeo").project_id == "qazgeo"
    with pytest.raises(ReleaseLaneError, match="does not match"):
        policy.lane_for_host("other-host", "qdev-release-qazgeo")


def test_dedicated_qaz_tours_release_lane_binds_mtls_ci_capacity_and_runtime(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)
    product_headers = {"X-QDev-mTLS-Identity": "qdev-release-client:qaz-tours"}
    host_headers = {"X-QDev-mTLS-Identity": "qdev-host-agent:vps-hostinger-186"}

    assert (
        client.post("/internal/v1/releases/qaz-tours", json=_release_request()).status_code == 403
    )
    missing_ref = _release_request()
    missing_ref.pop("artifact_ref")
    assert (
        client.post(
            "/internal/v1/releases/qaz-tours", json=missing_ref, headers=product_headers
        ).status_code
        == 422
    )
    invalid = _release_request()
    invalid["untrusted"] = True
    assert (
        client.post(
            "/internal/v1/releases/qaz-tours", json=invalid, headers=product_headers
        ).status_code
        == 422
    )
    assert (
        client.post(
            "/internal/v1/release-hosts/vps-hostinger-186/heartbeat",
            json=_release_heartbeat(),
            headers=host_headers,
        ).status_code
        == 200
    )

    accepted = client.post(
        "/internal/v1/releases/qaz-tours", json=_release_request(), headers=product_headers
    )
    assert accepted.status_code == 202
    receipt = accepted.json()
    assert receipt == {
        "schema": "qdev-controller-release-receipt-v1",
        "status": "accepted",
        "release_id": receipt["release_id"],
        "release_lane": "qdev-release-qaz-tours",
        "project_id": "qaz-tours",
        "placement": "vps-hostinger-186",
        "source_sha": "a" * 40,
        "artifact_digest": "sha256:" + "b" * 64,
        "artifact_ref": "registry.ci.qdev.run/qaz-tours@sha256:" + "b" * 64,
    }
    assert (
        client.post(
            "/internal/v1/releases/qaz-tours", json=_release_request(), headers=product_headers
        )
    ).json() == receipt
    assert (
        client.post(
            "/internal/v1/releases/qaz-tours",
            json=_release_request("e" * 40),
            headers=product_headers,
        ).status_code
        == 409
    )

    job = client.get("/internal/v1/release-hosts/vps-hostinger-186/jobs/next", headers=host_headers)
    assert job.status_code == 200
    assert job.json()["release_id"] == receipt["release_id"]
    assert (
        client.post(
            f"/internal/v1/release-hosts/vps-hostinger-186/jobs/{receipt['release_id']}/complete",
            json={},
            headers=host_headers,
        ).status_code
        == 409
    )
    runtime_receipt = {
        "schema": "qdev-controller-release-runtime-receipt-v1",
        "status": "verified",
        "project": "qaz-tours",
        "release_lane": "qdev-release-qaz-tours",
        "placement": "vps-hostinger-186",
        "source_sha": "a" * 40,
        "artifact_digest": "sha256:" + "b" * 64,
        "artifact_ref": "registry.ci.qdev.run/qaz-tours@sha256:" + "b" * 64,
        "health": "ok",
        "readiness": {"qazgeo": "degraded"},
        "rollback": {
            "verified": True,
            "source_sha": "c" * 40,
            "artifact_digest": "sha256:" + "c" * 64,
            "artifact_ref": "registry.ci.qdev.run/qaz-tours@sha256:" + "c" * 64,
        },
    }
    completed = client.post(
        f"/internal/v1/release-hosts/vps-hostinger-186/jobs/{receipt['release_id']}/complete",
        json=runtime_receipt,
        headers=host_headers,
    )
    assert completed.status_code == 200
    assert completed.json() == runtime_receipt
    status = client.get(
        f"/internal/v1/releases/qaz-tours/{receipt['release_id']}", headers=product_headers
    )
    assert status.status_code == 200
    assert status.json()["status"] == "verified"
    assert status.json()["runtime_receipt"] == runtime_receipt


def test_managed_next_job_is_bound_to_private_host_key_and_mtls_identity(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)
    settings: BrokerSettings = client.app.state.settings
    settings.release_lanes_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "qdev-release-lanes-v2",
                "lanes": {
                    "qdev-release-qaz-tours": {
                        "project_id": "qaz-tours",
                        "placement": "vps-hostinger-186",
                        "client_mtls_identity": "qdev-release-client:qaz-tours",
                        "host_agent_mtls_identity": "qdev-host-agent:vps-hostinger-186",
                        "minimum_free_gib": 60,
                        "heartbeat_ttl_seconds": 90,
                        "artifact_repository": "qaz-tours",
                        "canonical_repository": "belilovsky/qaz-tours",
                        "artifact_ref_prefix": "registry.ci.qdev.run/qaz-tours",
                        "native_host_adapter": "legacy-qaz-tours-v1",
                        "runtime_endpoints": ["https://qaza.tours/.well-known/release.json"],
                        "rollback_reference": "qdev-release-host-state-v1",
                        "required_readiness": ["qazgeo"],
                    }
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    host_identity = "qdev-host-agent:vps-hostinger-186"
    host_headers = {"X-QDev-mTLS-Identity": host_identity}
    heartbeat = _release_heartbeat()
    heartbeat["bootstrap"] = True
    heartbeat["rollback"] = {
        "verified": True,
        **heartbeat["active_release"],
    }
    assert (
        client.post(
            "/internal/v1/release-hosts/vps-hostinger-186/heartbeat",
            json=heartbeat,
            headers=host_headers,
        ).status_code
        == 200
    )
    request = _release_request()
    request["candidate_receipt"].update(
        {
            "repository": "belilovsky/qaz-tours",
            "workflow": "release.yml",
            "job": "release-qaz-tours",
            "run_id": 123,
            "job_id": 456,
            "attempt": 1,
            "runner_profile": "qdev-ci-docker",
        }
    )
    lane = ReleaseLanePolicy(settings.release_lanes_path).lane("qdev-release-qaz-tours")
    admission_now = int(time.time())
    candidate = ReleaseAdmissionRequest.model_validate(request)
    controller_claim = controller_claim_payload(
        candidate,
        lane,
        issued_at=admission_now,
        expires_at=admission_now + 120,
        nonce="managed-controller-claim-nonce-0001",
    )
    request["controller_claim"] = controller_claim
    request["controller_claim_signature"] = hmac.new(
        b"managed-controller-claim-key-for-test",
        json.dumps(
            controller_claim,
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    release_store = client.app.state.release_store
    release_store.admit(ReleaseAdmissionRequest.model_validate(request), lane, now=admission_now)

    next_path = "/internal/v1/release-hosts/vps-hostinger-186/jobs/next"
    blocked = client.get(next_path, headers=host_headers)
    assert blocked.status_code == 503
    assert blocked.json()["detail"] == "managed release host dispatch is unavailable"

    signing_key = "managed-host-dispatch-key-for-test-0001"
    secret_path = tmp_path / "host-dispatch.secret"
    secret_path.write_text(signing_key + "\n", encoding="utf-8")
    secret_path.chmod(0o600)
    settings.release_host_dispatch_keys_file.write_text(
        json.dumps({host_identity: str(secret_path)}),
        encoding="utf-8",
    )
    settings.release_host_dispatch_keys_file.chmod(0o600)

    response = client.get(next_path, headers=host_headers)
    assert response.status_code == 200
    job = response.json()
    claim = job["dispatch_claim"]
    assert set(claim) == {
        "schema",
        "repository",
        "workflow",
        "job",
        "exact_sha",
        "run_id",
        "job_id",
        "attempt",
        "runner_profile",
        "host_identity",
        "release_id",
        "release_lane",
        "project_id",
        "placement",
        "artifact_digest",
        "artifact_ref",
        "lease_id",
        "fence",
        "lease_expires_at",
        "rollback_anchor",
        "candidate_evidence",
        "issued_at",
        "expires_at",
        "nonce",
    }
    assert claim["schema"] == "qdev-controller-host-dispatch-claim-v2"
    assert claim["host_identity"] == host_identity
    assert claim["repository"] == "belilovsky/qaz-tours"
    assert claim["exact_sha"] == "a" * 40
    assert claim["workflow"] == "release.yml"
    assert claim["job"] == "release-qaz-tours"
    assert claim["lease_expires_at"] == job["lease_expires_at"]
    assert claim["rollback_anchor"] == job["rollback_anchor"]
    assert claim["candidate_evidence"] == job["candidate_evidence"]
    assert claim["candidate_evidence"]["schema"] == ("qdev-release-candidate-evidence-v1")
    assert len(claim["candidate_evidence"]["candidate_receipt_sha256"]) == 64
    assert claim["expires_at"] - claim["issued_at"] == 120
    canonical = json.dumps(claim, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode(
        "utf-8"
    )
    assert (
        job["dispatch_claim_signature"]
        == hmac.new(signing_key.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    )
    assert signing_key not in response.text


def test_generic_release_endpoint_keeps_the_same_lane_allowlist(tmp_path: Path) -> None:
    client = _app(tmp_path)
    headers = {"X-QDev-mTLS-Identity": "qdev-release-client:qaz-tours"}
    response = client.post(
        "/internal/v1/releases/qdev-release-qaz-tours",
        json=_release_request(),
        headers=headers,
    )
    # The request is correctly identified, but an enrolled host heartbeat is
    # still mandatory before a release can enter the controller queue.
    assert response.status_code == 409
    assert (
        client.post(
            "/internal/v1/releases/not-allowlisted", json=_release_request(), headers=headers
        ).status_code
        == 404
    )


class FakeGitHub:
    def __init__(
        self,
        *,
        job_status: str = "queued",
        job_conclusion: str | None = None,
        run_status: str = "in_progress",
        run_conclusion: str | None = None,
        head_sha: str = "a" * 40,
        run_attempt: int = 1,
        job_run_id: int = 84,
    ) -> None:
        self.job_status = job_status
        self.job_conclusion = job_conclusion
        self.run_status = run_status
        self.run_conclusion = run_conclusion
        self.head_sha = head_sha
        self.run_attempt = run_attempt
        self.job_run_id = job_run_id

    def workflow_job(self, installation_id: int, repository: str, job_id: int) -> dict[str, object]:
        return {
            "id": job_id,
            "run_id": self.job_run_id,
            "status": self.job_status,
            "conclusion": self.job_conclusion,
        }

    def workflow_run(self, installation_id: int, repository: str, run_id: int) -> dict[str, object]:
        return {
            "id": run_id,
            "head_sha": self.head_sha,
            "run_attempt": self.run_attempt,
            "status": self.run_status,
            "conclusion": self.run_conclusion,
        }

    def generate_jit_config(
        self,
        installation_id: int,
        repository: str,
        runner_name: str,
        labels: tuple[str, ...],
    ) -> str:
        return "signed-jit-config"


def _seed_stale_running_job(client: TestClient) -> float:
    store: Store = client.app.state.store
    queued = QueuedJob(
        delivery_id="delivery-42",
        job_id=42,
        run_id=84,
        repository="belilovsky/example",
        repository_id=1,
        installation_id=2,
        labels=("self-hosted", "Linux", "X64", "qdev-ci-docker"),
        head_sha="a" * 40,
        head_branch="main",
        payload={"workflow_job": {"run_attempt": 1}},
    )
    assert store.enqueue(queued) is True
    claimed = store.claim(WORKER_NAME, ("qdev-ci-docker",))
    assert claimed is not None
    store.set_status(42, "running", "runner started")
    original = store.job(42)
    assert original is not None
    created_at = float(original["created_at"])
    with store.connect() as connection:
        connection.execute(
            "UPDATE jobs SET updated_at=? WHERE job_id=?",
            (time.time() - 600, 42),
        )
    return created_at


def _seed_failed_worker_job(client: TestClient) -> float:
    created_at = _seed_stale_running_job(client)
    store: Store = client.app.state.store
    assert store.fail_if_active(
        42,
        f"worker={WORKER_NAME} exit=143 capacity override expired",
    ) is True
    return created_at


def _heartbeat(
    client: TestClient,
    *,
    active_jobs: int = 0,
    disk_free_gib: float = 30.0,
    admitted: bool = False,
    scope_id: str | None = None,
    profiles: list[str] | None = None,
) -> dict[str, object]:
    registered_profiles = profiles or ["qdev-ci-docker"]
    raw = {
        "allowed": True,
        "disk_used_pct": 87.0,
        "disk_free_gib": disk_free_gib,
        "memory_available_gib": 8.0,
        "load_15": 0.5,
        "cpu_psi_avg10": 0.0,
        "cpus": 8,
        "blockers": [],
    }
    baseline = raw if admitted else raw | {"allowed": False, "blockers": ["disk_used_pct"]}
    response = client.post(
        "/internal/v1/workers/heartbeat",
        headers={"X-QDev-Worker-Token": WORKER_TOKEN},
        json={
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "profiles": registered_profiles,
            "active_jobs": active_jobs,
            "active_job_ids": [42] if active_jobs else [],
            "detail": {
                **baseline,
                "raw_capacity": raw,
                "baseline_capacity": baseline,
                "effective_capacity": baseline,
                "effective_profiles": registered_profiles if admitted else [],
                "capacity_directive_id": None,
                "configured_claim_scope_id": scope_id,
                "concurrency": 1,
                "slots_available": 0 if active_jobs else 1,
                "min_disk_free_gib": 30.0,
            },
        },
    )
    assert response.status_code == 200
    return response.json()


def _seed_pending_job(
    client: TestClient,
    job_id: int,
    delivery_id: str,
    *,
    repository: str = "belilovsky/example",
    head_sha: str = "a" * 40,
    profile: str = "qdev-ci-docker",
) -> None:
    store: Store = client.app.state.store
    assert (
        store.enqueue(
            QueuedJob(
                delivery_id=delivery_id,
                job_id=job_id,
                run_id=84000000000 + job_id,
                repository=repository,
                repository_id=1,
                installation_id=2,
                labels=("self-hosted", "Linux", "X64", profile),
                head_sha=head_sha,
                head_branch="main",
                payload={"workflow_job": {"run_attempt": 1}},
            )
        )
        is True
    )


def test_controller_release_audit_is_signed_and_public_health_is_non_secret(tmp_path: Path) -> None:
    status_path = tmp_path / "controller-release.json"
    status = {
        "schema": "qdev-controller-release-status-v1",
        "state": "active",
        "revision": "a" * 40,
        "release_digest": "b" * 64,
        "activated_at": "2026-08-31T00:00:00Z",
    }
    status_path.write_text(json.dumps(status), encoding="utf-8")
    client = _app(tmp_path)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["controller_release"] == status
    assert client.get("/health/runtime").json() == {
        "schema": "qdev-controller-runtime-health-v1",
        "state": "legacy",
        "revision": "a" * 40,
        "digest": "sha256:" + "b" * 64,
        "activated": "2026-08-31T00:00:00Z",
        "runtime_identity": None,
        "dependency_identity": None,
        "receipt": status,
    }

    unauthorized = client.get("/internal/v1/operations/controller-release")
    assert unauthorized.status_code == 401
    response = client.get(
        "/internal/v1/operations/controller-release",
        headers=OPERATOR_HEADERS,
    )
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    assert receipt["payload"]["kind"] == "controller-release-audit"
    assert receipt["payload"]["controller_release"] == status


def test_controller_runtime_health_reports_measured_v2_identity(tmp_path: Path) -> None:
    status_path = tmp_path / "controller-release.json"
    runtime_identity = {
        "source_revision": "a" * 40,
        "source_digest": "sha256:" + "c" * 64,
        "public_image_id": "sha256:" + "d" * 64,
        "internal_image_id": "sha256:" + "e" * 64,
    }
    dependency_identity = {
        "requirements_digest": "sha256:" + "f" * 64,
        "public_installed_digest": "sha256:" + "1" * 64,
        "internal_installed_digest": "sha256:" + "1" * 64,
    }
    status = {
        "schema": "qdev-controller-release-status-v2",
        "state": "active",
        "revision": "a" * 40,
        "release_digest": "sha256:" + "b" * 64,
        "activated_at": "2026-09-05T00:00:00Z",
        "runtime_identity": runtime_identity,
        "dependency_identity": dependency_identity,
    }
    status_path.write_text(json.dumps(status), encoding="utf-8")
    client = _app(tmp_path)

    assert client.get("/health").json()["controller_release"] == status
    assert client.get("/health/runtime").json() == {
        "schema": "qdev-controller-runtime-health-v1",
        "state": "active",
        "revision": "a" * 40,
        "digest": "sha256:" + "b" * 64,
        "activated": "2026-09-05T00:00:00Z",
        "runtime_identity": runtime_identity,
        "dependency_identity": dependency_identity,
        "receipt": status,
    }


def test_controller_runtime_health_rejects_unbound_v2_identity(tmp_path: Path) -> None:
    status_path = tmp_path / "controller-release.json"
    status = {
        "schema": "qdev-controller-release-status-v2",
        "state": "active",
        "revision": "a" * 40,
        "release_digest": "sha256:" + "b" * 64,
        "activated_at": "2026-09-05T00:00:00Z",
        "runtime_identity": {
            "source_revision": "a" * 40,
            "source_digest": "sha256:" + "c" * 64,
            "public_image_id": "sha256:" + "d" * 64,
            "internal_image_id": "sha256:" + "e" * 64,
        },
        "dependency_identity": {
            "requirements_digest": "sha256:" + "f" * 64,
            "public_installed_digest": "sha256:" + "1" * 64,
            "internal_installed_digest": "sha256:" + "2" * 64,
        },
    }
    status_path.write_text(json.dumps(status), encoding="utf-8")
    client = _app(tmp_path)

    unavailable = {
        "schema": "qdev-controller-runtime-health-v1",
        "state": "unavailable",
        "revision": None,
        "digest": None,
        "activated": None,
        "runtime_identity": None,
        "dependency_identity": None,
        "receipt": None,
    }
    assert client.get("/health/runtime").json() == unavailable

    status["dependency_identity"]["internal_installed_digest"] = "sha256:" + "1" * 64
    status["runtime_identity"]["source_digest"] = "c" * 64
    status_path.write_text(json.dumps(status), encoding="utf-8")
    assert client.get("/health/runtime").json() == unavailable


def test_existing_worker_recovery_is_controller_bound_and_fail_closed_without_adapter(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)
    activation = _fleet_bootstrap_activation()
    request = {
        "schema": "qdev-fleet-bootstrap-request-v1",
        "action": "restore-existing-worker",
        "source_sha": "a" * 40,
        "run_id": 123,
        "job_id": 456,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": activation["controller_revision"],
        "controller_release_digest": activation["controller_release_digest"],
        "release_lane": None,
        "worker_name": "qdev-platform-ci-187",
    }
    body = {
        "request": request,
        "idempotency_key": "worker-recovery-001",
        "active_jobs": 0,
        "timeout_seconds": 5,
    }
    path = "/internal/v1/operations/fleet-bootstrap/recover-existing-worker"
    assert client.post(path, json=body).status_code == 401
    assert (
        client.post(
            path,
            json=body,
            headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
        ).status_code
        == 403
    )

    response = client.post(path, json=body, headers=OPERATOR_HEADERS)
    assert response.status_code == 410
    assert response.json()["detail"] == "legacy worker recovery endpoint is retired"
    operation = tmp_path / "fleet-bootstrap-operations" / "worker-recovery-001.json"
    assert not operation.exists()


def test_activation_and_enrolment_routes_are_mtls_bound_and_fail_closed_without_bridge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _app(tmp_path)
    activation = _fleet_bootstrap_activation()
    base_request: dict[str, Any] = {
        "schema": "qdev-fleet-bootstrap-request-v1",
        "source_sha": "a" * 40,
        "run_id": 123,
        "job_id": 456,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": activation["controller_revision"],
        "controller_release_digest": activation["controller_release_digest"],
        "worker_name": None,
    }
    activation_path = "/internal/v1/operations/fleet-bootstrap/activate-controller"
    activation_body = {
        "request": base_request
        | {
            "action": "activate-controller",
            "release_lane": None,
        },
        "idempotency_key": "controller-activation-001",
        "timeout_seconds": 5,
    }
    assert client.post(activation_path, json=activation_body).status_code == 401
    assert (
        client.post(
            activation_path,
            json=activation_body,
            headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
        ).status_code
        == 403
    )
    activation_response = client.post(
        activation_path,
        json=activation_body,
        headers=OPERATOR_HEADERS,
    )
    assert activation_response.status_code == 200
    activation_receipt = verify_controller_receipt(
        activation_response.json(), receipt_key=RECEIPT_KEY
    )
    activation_execution = activation_receipt["payload"]["execution"]
    assert activation_receipt["payload"]["kind"] == "fleet-bootstrap-operation"
    assert activation_execution["action"] == "activate-controller"
    assert activation_execution["status"] == "access_blocked"
    assert activation_execution["operation_status"] == "pending"
    assert activation_execution["error_code"] == "host_dispatch_unavailable"
    assert activation_execution["release_lane"] is None
    assert activation_execution["host_agent_mtls_identity"] is None
    assert not (tmp_path / "fleet-bootstrap-receipts" / "controller-activation-001.json").exists()

    incoming = tmp_path / "fleet-host-dispatch" / "incoming"
    results = tmp_path / "fleet-host-dispatch" / "results"
    incoming.mkdir(parents=True)
    results.mkdir()
    incoming.chmod(0o700)
    results.chmod(0o750)
    monkeypatch.setattr(
        "qdev_runner.broker.FleetHostDispatchSpool",
        lambda request_root, result_root: FleetHostDispatchSpool(
            request_root,
            result_root,
            result_uid=os.geteuid(),
        ),
    )
    queued_body = activation_body | {"idempotency_key": "controller-activation-queued-001"}
    queued_response = client.post(
        activation_path,
        json=queued_body,
        headers=OPERATOR_HEADERS,
    )
    assert queued_response.status_code == 200
    queued_receipt = verify_controller_receipt(queued_response.json(), receipt_key=RECEIPT_KEY)
    queued_execution = queued_receipt["payload"]["execution"]
    assert queued_execution["status"] == "queued"
    assert queued_execution["operation_status"] == "pending"
    assert queued_execution["error_code"] is None
    assert (incoming / "controller-activation-queued-001.json").is_file()

    enrolment_path = "/internal/v1/operations/fleet-bootstrap/enrol-host-agent"
    enrolment_body = {
        "request": base_request
        | {
            "action": "enrol-host-agent",
            "release_lane": "qdev-release-qmt",
        },
        "idempotency_key": "host-enrolment-001",
        "timeout_seconds": 5,
    }
    enrolment_response = client.post(
        enrolment_path,
        json=enrolment_body,
        headers=OPERATOR_HEADERS,
    )
    assert enrolment_response.status_code == 200
    enrolment_receipt = verify_controller_receipt(
        enrolment_response.json(), receipt_key=RECEIPT_KEY
    )
    enrolment_execution = enrolment_receipt["payload"]["execution"]
    assert enrolment_execution["action"] == "enrol-host-agent"
    assert enrolment_execution["status"] == "queued"
    assert enrolment_execution["operation_status"] == "pending"
    assert enrolment_execution["error_code"] is None
    assert enrolment_execution["release_lane"] == "qdev-release-qmt"
    assert enrolment_execution["host_agent_mtls_identity"] == "qdev-host-agent:srv138jump"
    assert (incoming / "host-enrolment-001.json").is_file()

    mismatched = client.post(
        activation_path,
        json=enrolment_body | {"idempotency_key": "route-action-mismatch-001"},
        headers=OPERATOR_HEADERS,
    )
    assert mismatched.status_code == 422
    assert mismatched.json()["detail"] == "fleet bootstrap operation request is invalid"


def test_admin_platform_audit_is_mtls_protected_and_binds_registry_to_ledger(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)

    assert client.get("/internal/v1/operations/admin-platform").status_code == 401
    assert (
        client.get(
            "/internal/v1/operations/admin-platform",
            headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
        ).status_code
        == 403
    )
    response = client.get(
        "/internal/v1/operations/admin-platform",
        headers={
            "X-QDev-Operator-Token": OPERATOR_TOKEN,
            "X-QDev-Operator-mTLS-Identity": "qdev-fleet-operations",
        },
    )
    assert response.status_code == 200
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    payload = receipt["payload"]
    assert payload["kind"] == "admin-platform-audit"
    assert payload["active_candidate"] == "controller"
    assert payload["admission"]["claim_scope"] == "controller-signed-only"
    assert payload["managed_registry"]["schema"] == "qdev-managed-registry-v3"
    assert payload["admin_platform_ledger"]["schema"] == "qdev-admin-platform-ledger-v3"


def test_health_reports_profile_specific_admission_without_job_details(tmp_path: Path) -> None:
    client = _app(tmp_path)
    store: Store = client.app.state.store
    assert store.enqueue(
        QueuedJob(
            delivery_id="profile-health",
            job_id=99,
            run_id=84000000099,
            repository="belilovsky/example",
            repository_id=1,
            installation_id=2,
            labels=("self-hosted", "Linux", "X64", "qdev-ci-browser"),
            head_sha="a" * 40,
            head_branch="main",
            payload={"workflow_job": {"run_attempt": 1}},
        )
    )
    _heartbeat(client, admitted=True)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["profile_admission"] == {
        "qdev-ci-browser": {
            "pending": 1,
            "primary_slots_available": 0,
            "reserve_slots_available": 0,
            "admission": "no-fresh-eligible-worker",
        }
    }

    _heartbeat(client, active_jobs=1, admitted=True)
    assert client.get("/health").json()["profile_admission"]["qdev-ci-browser"] == {
        "pending": 1,
        "primary_slots_available": 0,
        "reserve_slots_available": 0,
        "admission": "no-fresh-eligible-worker",
    }


def test_controller_release_status_rejects_unverifiable_values(tmp_path: Path) -> None:
    status_path = tmp_path / "controller-release.json"
    status_path.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-release-status-v1",
                "state": "active",
                "revision": "unknown",
                "release_digest": "b" * 64,
                "activated_at": "2026-08-31T09:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    client = _app(tmp_path)

    assert client.get("/health").json()["controller_release"] == {
        "schema": "qdev-controller-release-status-v1",
        "state": "unavailable",
    }
    assert client.get("/health/runtime").json() == {
        "schema": "qdev-controller-runtime-health-v1",
        "state": "unavailable",
        "revision": None,
        "digest": None,
        "activated": None,
        "runtime_identity": None,
        "dependency_identity": None,
        "receipt": None,
    }


def test_operator_audit_and_override_are_signed_and_reach_heartbeat(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client)
    _seed_pending_job(
        client,
        42,
        "qazshield-head",
        repository="belilovsky/qazshield",
        head_sha="a" * 40,
    )

    unauthorized = client.get("/internal/v1/operations/workers")
    assert unauthorized.status_code == 401
    missing_identity = client.get(
        "/internal/v1/operations/workers",
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
    )
    assert missing_identity.status_code == 403
    assert missing_identity.json()["detail"] == "qdev-fleet-operations mTLS identity required"
    wrong_identity = client.get(
        "/internal/v1/operations/workers",
        headers={
            "X-QDev-Operator-Token": OPERATOR_TOKEN,
            "X-QDev-Operator-mTLS-Identity": "untrusted-operator",
        },
    )
    assert wrong_identity.status_code == 403

    audit_response = client.get(
        "/internal/v1/operations/workers",
        headers=OPERATOR_HEADERS,
    )
    assert audit_response.status_code == 200
    audit = verify_controller_receipt(audit_response.json(), receipt_key=RECEIPT_KEY)
    assert audit["payload"]["workers"][0]["worker"] == WORKER_NAME
    assert audit["payload"]["workers"][0]["active_jobs"] == 0

    override_response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qazshield",
            "head_sha": "a" * 40,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 90.0,
            "duration_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "bounded disk-only recovery",
        },
    )
    assert override_response.status_code == 200
    override = verify_controller_receipt(override_response.json(), receipt_key=RECEIPT_KEY)
    operation = override["payload"]["operation"]
    assert operation["profiles"] == ["qdev-ci-docker"]
    assert operation["repository"] == "belilovsky/qazshield"
    assert operation["head_sha"] == "a" * 40
    assert operation["min_disk_free_gib"] == 4.5

    directive_response = _heartbeat(client)
    directive = directive_response["capacity_override"]
    assert isinstance(directive, dict)
    assert directive["operation_id"] == operation["operation_id"]
    assert directive["signature"] == operation["signature"]

    changed = client.delete(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override"
        "?operation_id=foreign-operation",
        headers=OPERATOR_HEADERS,
    )
    assert changed.status_code == 409
    assert changed.json()["detail"] == "capacity override operation changed"
    assert _heartbeat(client)["capacity_override"]["operation_id"] == operation["operation_id"]

    cancelled = client.delete(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override"
        f"?operation_id={operation['operation_id']}",
        headers=OPERATOR_HEADERS,
    )
    assert cancelled.status_code == 200
    cancelled_payload = verify_controller_receipt(cancelled.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert cancelled_payload["operation"]["operation_id"] == operation["operation_id"]
    assert cancelled_payload["operation"]["status"] == "cancelled"


def test_durable_queue_audit_is_signed_and_reports_profile_heads(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _seed_pending_job(
        client,
        42,
        "oldest-docker",
        repository="belilovsky/qazshield",
        head_sha="a" * 40,
    )
    _seed_pending_job(
        client,
        43,
        "later-docker",
        repository="belilovsky/qazlake",
        head_sha="b" * 40,
    )

    response = client.get(
        "/internal/v1/operations/jobs/pending",
        headers=OPERATOR_HEADERS,
    )

    assert response.status_code == 200
    payload = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["kind"] == "durable-queue-audit"
    assert payload["pending"] == 2
    assert payload["unclassified"] == []
    assert payload["profile_heads"] == [
        {
            "repository": "belilovsky/qazshield",
            "run_id": 84000000042,
            "job_id": 42,
            "attempt": 1,
            "exact_sha": "a" * 40,
            "profile": "qdev-ci-docker",
            "state": "pending",
            "created_at": payload["profile_heads"][0]["created_at"],
        }
    ]


def test_controller_issues_only_profile_fifo_head_scope_idempotently(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(client, 42, "delivery-42")
    _seed_pending_job(client, 43, "delivery-43")
    headers = OPERATOR_HEADERS
    request = {
        "job_id": 42,
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": "srv1879763-primary",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "c" * 64,
        "correlation_id": "fifo-head-42",
        "duration_seconds": 900,
    }

    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope", headers=headers, json=request
    )
    assert issued.status_code == 200
    receipt = verify_controller_receipt(issued.json(), receipt_key=RECEIPT_KEY)
    payload = receipt["payload"]
    assert payload["kind"] == "fifo-claim-scope-issued"
    assert payload["idempotent"] is False
    assert payload["immutable_tuple"] == {
        "repository": "belilovsky/example",
        "run_id": 84000000042,
        "job_id": 42,
        "attempt": 1,
        "exact_sha": "a" * 40,
        "profile": "qdev-ci-docker",
        "runner": "qdev-ci-docker",
        "host": "srv1879763-light-primary",
    }

    repeated = client.post(
        "/internal/v1/operations/jobs/42/claim-scope", headers=headers, json=request
    )
    assert repeated.status_code == 200
    repeated_payload = verify_controller_receipt(repeated.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert repeated_payload["idempotent"] is True

    tail_request = request | {"job_id": 43, "correlation_id": "fifo-tail-43"}
    tail = client.post(
        "/internal/v1/operations/jobs/43/claim-scope",
        headers=headers,
        json=tail_request,
    )
    assert tail.status_code == 409
    assert tail.json()["detail"] == "job is not the FIFO head for its profile"

    scope_path = tmp_path / "claim-scopes.json"
    document = json.loads(scope_path.read_text(encoding="utf-8"))
    document["scopes"][0]["expires_at"] = (datetime.now(UTC) - timedelta(seconds=1)).isoformat()
    scope_path.write_text(json.dumps(document), encoding="utf-8")
    refreshed_request = request | {"correlation_id": "fifo-head-42-refresh"}
    refreshed = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=headers,
        json=refreshed_request,
    )
    assert refreshed.status_code == 200
    refreshed_payload = verify_controller_receipt(refreshed.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert refreshed_payload["idempotent"] is False
    assert refreshed_payload["replaced_expired_scope"] is True


def test_fifo_skips_stale_admin_platform_rows_with_signed_evidence(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub())
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    stale_sha = "9ebf6718c2085d1a58f59323f37b1e1dd707225f"
    _seed_pending_job(
        client,
        41,
        "delivery-41",
        repository="belilovsky/qazposter",
        head_sha=stale_sha,
    )
    _seed_pending_job(client, 42, "delivery-42")
    request = {
        "job_id": 42,
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": "srv1879763-primary",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "c" * 64,
        "correlation_id": "fifo-head-after-stale-admin-row",
        "duration_seconds": 900,
    }

    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json=request,
    )
    assert issued.status_code == 200
    payload = verify_controller_receipt(issued.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["fifo_skipped"] == [
        {
            "job_id": 41,
            "repository": "belilovsky/qazposter",
            "run_id": 84000000041,
            "attempt": 1,
            "head_sha": stale_sha,
            "profile": "qdev-ci-docker",
            "managed_registry_entry": "qazposter",
            "reason": "admin-platform-candidate-not-active",
        }
    ]
    assert payload["immutable_tuple"]["job_id"] == 42

    claimed = client.post(
        "/internal/v1/jobs/claim",
        headers={"X-QDev-Client-Certificate-SHA256": "c" * 64},
        json={
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "profiles": ["qdev-ci-docker"],
            "claim_scope_id": "srv1879763-primary",
            "disk_free_gib": 30.0,
            "min_disk_free_gib": 4.5,
        },
    )
    assert claimed.status_code == 200
    assert claimed.json()["job_id"] == 42
    assert client.app.state.store.job_status(41) == "pending"


def test_direct_claim_of_stale_admin_platform_row_remains_fail_closed(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(
        client,
        41,
        "delivery-41",
        repository="belilovsky/qazposter",
        head_sha="9ebf6718c2085d1a58f59323f37b1e1dd707225f",
    )
    request = {
        "job_id": 41,
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": "srv1879763-primary",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "c" * 64,
        "correlation_id": "stale-admin-row-direct",
        "duration_seconds": 900,
    }

    response = client.post(
        "/internal/v1/operations/jobs/41/claim-scope",
        headers=OPERATOR_HEADERS,
        json=request,
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "admin platform candidate is not active"


def test_active_controller_candidate_bypasses_earlier_unrelated_profile_rows(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(client, 41, "unrelated-earlier-row")
    template = yaml.safe_load(
        (Path(__file__).parents[1] / "config" / "admin-platform-ledger-v2.yml").read_text(
            encoding="utf-8"
        )
    )
    controller_sha = template["active_candidate"]["source_sha"]
    _seed_pending_job(
        client,
        42,
        "active-controller-candidate",
        repository="belilovsky/qdev-runner-control-plane",
        head_sha=controller_sha,
    )
    request = {
        "job_id": 42,
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": "srv1879763-primary",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "c" * 64,
        "correlation_id": "active-controller-prerequisite",
        "duration_seconds": 900,
    }

    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json=request,
    )

    assert issued.status_code == 200
    payload = verify_controller_receipt(issued.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["managed_registry_entry"] is None
    assert payload["admission_ledger"] == "admin-platform"
    assert payload["admin_platform_ledger_entry"] == "controller"
    assert payload["fifo_skipped"] == [
        {
            "job_id": 41,
            "repository": "belilovsky/example",
            "run_id": 84000000041,
            "attempt": 1,
            "head_sha": "a" * 40,
            "profile": "qdev-ci-docker",
            "managed_registry_entry": None,
            "reason": "active-admin-platform-controller-priority",
        }
    ]
    assert client.app.state.store.job_status(41) == "pending"


def test_fifo_skips_stale_managed_release_rows_with_signed_evidence(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub())
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    stale_sha = "5dff352e7cb08af9abef292680b9fbadf2714145"
    _seed_pending_job(
        client,
        41,
        "stale-managed-release-row",
        repository="belilovsky/qazgeo",
        head_sha=stale_sha,
        profile="qdev-ci-docker",
    )
    _seed_pending_job(client, 42, "first-admissible-row")
    request = {
        "job_id": 42,
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": "srv1879763-primary",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "c" * 64,
        "correlation_id": "fifo-head-after-stale-managed-release-row",
        "duration_seconds": 900,
    }

    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json=request,
    )
    assert issued.status_code == 200
    payload = verify_controller_receipt(issued.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["fifo_skipped"] == [
        {
            "job_id": 41,
            "repository": "belilovsky/qazgeo",
            "run_id": 84000000041,
            "attempt": 1,
            "head_sha": stale_sha,
            "profile": "qdev-ci-docker",
            "managed_registry_entry": "qazgeo",
            "reason": "managed-release-candidate-tuple-not-admitted",
        }
    ]
    assert payload["immutable_tuple"]["job_id"] == 42

    claimed = client.post(
        "/internal/v1/jobs/claim",
        headers={"X-QDev-Client-Certificate-SHA256": "c" * 64},
        json={
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "profiles": ["qdev-ci-docker"],
            "claim_scope_id": "srv1879763-primary",
            "disk_free_gib": 30.0,
            "min_disk_free_gib": 4.5,
        },
    )
    assert claimed.status_code == 200
    assert claimed.json()["job_id"] == 42
    assert client.app.state.store.job_status(41) == "pending"


def test_direct_claim_of_stale_managed_release_row_remains_fail_closed(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(
        client,
        41,
        "stale-managed-release-row",
        repository="belilovsky/qazgeo",
        head_sha="5dff352e7cb08af9abef292680b9fbadf2714145",
        profile="qdev-ci-docker",
    )

    response = client.post(
        "/internal/v1/operations/jobs/41/claim-scope",
        headers=OPERATOR_HEADERS,
        json={
            "job_id": 41,
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "scope_id": "srv1879763-primary",
            "host": "srv1879763-light-primary",
            "runner": "qdev-ci-docker",
            "worker_certificate_sha256": "c" * 64,
            "correlation_id": "direct-stale-managed-release-row",
            "duration_seconds": 900,
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "managed production candidate tuple is not admitted"
    assert client.app.state.store.job_status(41) == "pending"


def test_active_controller_scope_supersedes_stale_capacity_tuple_for_claim(
    tmp_path: Path,
) -> None:
    template = yaml.safe_load(
        (Path(__file__).parents[1] / "config" / "admin-platform-ledger-v2.yml").read_text(
            encoding="utf-8"
        )
    )
    controller_sha = template["active_candidate"]["source_sha"]
    client = _app(
        tmp_path,
        FakeGitHub(head_sha=controller_sha, job_run_id=84000000042),
    )
    scope_id = "admin-platform-controller-candidate"
    _heartbeat(
        client,
        admitted=True,
        scope_id=scope_id,
        profiles=["qdev-ci-docker"],
    )
    _seed_pending_job(client, 41, "stale-capacity-candidate")
    _seed_pending_job(
        client,
        42,
        "active-controller-candidate",
        repository="belilovsky/qdev-runner-control-plane",
        head_sha=controller_sha,
    )
    operation = client.app.state.operations.create_capacity_override(
        worker_name=WORKER_NAME,
        repository="belilovsky/example",
        head_sha="a" * 40,
        profiles=("qdev-ci-docker",),
        min_disk_free_gib=4.5,
        max_disk_used_pct=94.0,
        owner="admin-platform",
        reason="retain measured capacity while advancing exact signed scope",
        duration_seconds=300,
        registered_profiles=("qdev-ci-docker",),
    )
    store: Store = client.app.state.store
    worker = store.health()["workers"][0]
    detail = json.loads(worker["detail_json"])
    detail["capacity_directive_id"] = operation.operation_id
    with store.connect() as connection:
        connection.execute(
            "UPDATE workers SET detail_json=? WHERE name=?",
            (json.dumps(detail, separators=(",", ":")), WORKER_NAME),
        )

    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json={
            "job_id": 42,
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "scope_id": scope_id,
            "host": WORKER_NAME,
            "runner": "qdev-ci-docker",
            "worker_certificate_sha256": "c" * 64,
            "correlation_id": "active-controller-prerequisite",
            "duration_seconds": 900,
        },
    )
    assert issued.status_code == 200

    claim = client.post(
        "/internal/v1/jobs/claim",
        headers={"X-QDev-Client-Certificate-SHA256": "c" * 64},
        json={
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "claim_scope_id": scope_id,
            "profiles": ["qdev-ci-docker"],
            "disk_free_gib": 20.0,
            "min_disk_free_gib": 4.5,
            "capacity_directive_id": operation.operation_id,
            "capacity_repository": "belilovsky/example",
            "capacity_head_sha": "a" * 40,
        },
    )

    assert claim.status_code == 200
    assert claim.json()["job_id"] == 42
    assert claim.json()["repository"] == "belilovsky/qdev-runner-control-plane"
    assert store.job_status(41) == "pending"


def test_non_active_controller_sha_cannot_bypass_profile_fifo(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(client, 41, "unrelated-earlier-row")
    _seed_pending_job(
        client,
        42,
        "non-active-controller-candidate",
        repository="belilovsky/qdev-runner-control-plane",
        head_sha="f" * 40,
    )
    request = {
        "job_id": 42,
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": "srv1879763-primary",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "c" * 64,
        "correlation_id": "non-active-controller-candidate",
        "duration_seconds": 900,
    }

    response = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json=request,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "job is not the FIFO head for its profile"


def test_controller_rolls_scope_forward_only_after_terminal_fifo_tuple(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(client, 42, "delivery-42")
    _seed_pending_job(client, 43, "delivery-43")
    headers = OPERATOR_HEADERS
    request = {
        "job_id": 42,
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": "srv1879763-primary",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "c" * 64,
        "correlation_id": "fifo-head-42",
        "duration_seconds": 900,
    }
    assert (
        client.post(
            "/internal/v1/operations/jobs/42/claim-scope", headers=headers, json=request
        ).status_code
        == 200
    )

    store: Store = client.app.state.store
    store.set_status(42, "completed", "success")
    rollover = client.post(
        "/internal/v1/operations/jobs/43/claim-scope",
        headers=headers,
        json=request | {"job_id": 43, "correlation_id": "fifo-head-43"},
    )
    assert rollover.status_code == 200
    payload = verify_controller_receipt(rollover.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["idempotent"] is False
    assert payload["rolled_over_terminal_scope"] is True
    assert [item["job_id"] for item in payload["claim_scope"]["jobs"]] == [42, 43]


def test_cross_profile_rollover_claim_uses_registered_profiles_for_scope_identity(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path, FakeGitHub(job_run_id=84000000043))
    profiles = ["qdev-ci-docker", "qdev-ci-browser"]
    _heartbeat(
        client,
        admitted=True,
        scope_id="srv1879763-primary",
        profiles=profiles,
    )
    _seed_pending_job(client, 42, "docker-before-browser")
    _seed_pending_job(client, 43, "browser-head", profile="qdev-ci-browser")
    base_request = {
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": "srv1879763-primary",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "c" * 64,
        "duration_seconds": 900,
    }
    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json=base_request
        | {"job_id": 42, "correlation_id": "cross-profile-rollover"},
    )
    assert issued.status_code == 200
    client.app.state.store.set_status(42, "completed", "success")
    rollover = client.post(
        "/internal/v1/operations/jobs/43/claim-scope",
        headers=OPERATOR_HEADERS,
        json=base_request
        | {"job_id": 43, "correlation_id": "cross-profile-rollover"},
    )
    assert rollover.status_code == 200

    # Reproduce the live constrained-capacity state only after the v2 scope
    # has retained tuples from both profiles.  The directive below admits the
    # browser subset while the durable worker registration remains unchanged.
    _heartbeat(
        client,
        admitted=False,
        scope_id="srv1879763-primary",
        profiles=profiles,
    )

    operation = client.app.state.operations.create_capacity_override(
        worker_name=WORKER_NAME,
        repository="belilovsky/example",
        head_sha="a" * 40,
        profiles=("qdev-ci-browser",),
        min_disk_free_gib=4.5,
        max_disk_used_pct=94.0,
        owner="test-owner",
        reason="admit the exact browser FIFO tuple",
        duration_seconds=300,
        registered_profiles=tuple(profiles),
    )
    worker = client.app.state.store.health()["workers"][0]
    detail = json.loads(worker["detail_json"])
    detail["capacity_directive_id"] = operation.operation_id
    with client.app.state.store.connect() as connection:
        connection.execute(
            "UPDATE workers SET detail_json=? WHERE name=?",
            (json.dumps(detail, separators=(",", ":")), WORKER_NAME),
        )

    claim = client.post(
        "/internal/v1/jobs/claim",
        headers={"X-QDev-Client-Certificate-SHA256": "c" * 64},
        json={
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "claim_scope_id": "srv1879763-primary",
            "profiles": ["qdev-ci-browser"],
            "disk_free_gib": 100.0,
            "min_disk_free_gib": 4.5,
            "capacity_directive_id": operation.operation_id,
            "capacity_repository": "belilovsky/example",
            "capacity_head_sha": "a" * 40,
        },
    )

    assert claim.status_code == 200
    assert claim.json()["job_id"] == 43
    assert claim.json()["profile"]["name"] == "qdev-ci-browser"


def test_controller_rebinds_legacy_scope_only_for_its_same_immutable_tuple(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(client, 42, "delivery-42")
    headers = OPERATOR_HEADERS
    request = {
        "job_id": 42,
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": "srv1879763-primary",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "c" * 64,
        "correlation_id": "recover-legacy-binding",
        "duration_seconds": 900,
    }
    scope_path = tmp_path / "claim-scopes.json"
    scope_path.write_text(
        json.dumps(
            {
                "schema": "qdev-runner-claim-scopes-v2",
                "scopes": [
                    {
                        "schema": "claim-scope-v2",
                        "scope_id": "srv1879763-primary",
                        "worker_name": WORKER_NAME,
                        "tier": "primary",
                        "repository": "belilovsky/example",
                        "head_sha": "a" * 40,
                        "host": "srv1879763-light-primary",
                        "runner": "qdev-ci-docker",
                        "correlation_id": "legacy",
                        "expires_at": (datetime.now(UTC) + timedelta(minutes=10)).isoformat(),
                        "jobs": [
                            {
                                "job_id": 42,
                                "repository": "belilovsky/example",
                                "exact_sha": "a" * 40,
                                "profile": "qdev-ci-docker",
                                "run_id": 84000000042,
                                "attempt": 1,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    response = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=headers,
        json=request,
    )
    assert response.status_code == 200
    payload = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["rebound_legacy_scope"] is True
    assert payload["claim_scope"]["worker_certificate_sha256"] == "c" * 64


def test_override_refuses_worker_with_active_task(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, active_jobs=1)

    response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qazshield",
            "head_sha": "a" * 40,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 90.0,
            "duration_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "must not interrupt active work",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "worker has an active task"


def test_override_uses_only_the_pinned_repository_reservation(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, disk_free_gib=17.0)
    _seed_pending_job(
        client,
        42,
        "qazlake-head",
        repository="belilovsky/qazlake",
        head_sha="a" * 40,
    )

    response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qazlake",
            "head_sha": "a" * 40,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 95.0,
            "duration_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "pinned QazLake compose validation",
        },
    )

    assert response.status_code == 200
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    assert receipt["payload"]["operation"]["repository"] == "belilovsky/qazlake"


def test_worker_audit_closes_expired_capacity_directive(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True)
    operation_store = client.app.state.operations
    assert operation_store is not None
    directive = operation_store.create_capacity_override(
        worker_name=WORKER_NAME,
        repository="belilovsky/qazshield",
        head_sha="a" * 40,
        profiles=("qdev-ci-docker",),
        min_disk_free_gib=4.5,
        max_disk_used_pct=95.0,
        owner="portfolio-ci",
        reason="expired directive audit regression",
        duration_seconds=300,
        now=datetime.now(UTC) - timedelta(seconds=301),
    )
    store: Store = client.app.state.store
    worker = store.health()["workers"][0]
    detail = json.loads(worker["detail_json"])
    detail["capacity_directive_id"] = directive.operation_id
    with store.connect() as connection:
        connection.execute(
            "UPDATE workers SET detail_json=? WHERE name=?",
            (json.dumps(detail, separators=(",", ":")), WORKER_NAME),
        )

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["primary_capacity_allowed"] is False
    response = client.get("/internal/v1/operations/workers", headers=OPERATOR_HEADERS)
    assert response.status_code == 200
    payload = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)["payload"]
    audit = payload["workers"][0]
    assert audit["capacity_allowed"] is False
    assert audit["admission"]["allowed"] is False
    assert audit["admission"]["profiles"] == []


def test_capacity_override_claim_is_bound_to_directive_repository(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub())
    _heartbeat(client)
    store: Store = client.app.state.store
    assert store.enqueue(
        QueuedJob(
            delivery_id="foreign",
            job_id=100,
            run_id=84,
            repository="belilovsky/qazshield",
            repository_id=1,
            installation_id=2,
            labels=("self-hosted", "Linux", "X64", "qdev-ci"),
            head_sha="a" * 40,
            head_branch="main",
            payload={"workflow_job": {"run_attempt": 1}},
        )
    )
    assert store.enqueue(
        QueuedJob(
            delivery_id="target",
            job_id=102,
            run_id=85,
            repository="belilovsky/qazlake",
            repository_id=2,
            installation_id=2,
            labels=("self-hosted", "Linux", "X64", "qdev-ci-docker"),
            head_sha="b" * 40,
            head_branch="candidate",
            payload={"workflow_job": {"run_attempt": 1}},
        )
    )
    override_response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qazlake",
            "head_sha": "b" * 40,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 95.0,
            "duration_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "repository-bound regression",
        },
    )
    operation = verify_controller_receipt(override_response.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]["operation"]
    claim = {
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "profiles": ["qdev-ci-docker"],
        "disk_free_gib": 20.0,
        "min_disk_free_gib": 4.5,
    }
    headers = {"X-QDev-Worker-Token": WORKER_TOKEN}

    missing_binding = client.post("/internal/v1/jobs/claim", headers=headers, json=claim)
    wrong_repository = client.post(
        "/internal/v1/jobs/claim",
        headers=headers,
        json=claim
        | {
            "capacity_directive_id": operation["operation_id"],
            "capacity_repository": "belilovsky/qazshield",
            "capacity_head_sha": "b" * 40,
        },
    )
    wrong_sha = client.post(
        "/internal/v1/jobs/claim",
        headers=headers,
        json=claim
        | {
            "capacity_directive_id": operation["operation_id"],
            "capacity_repository": "belilovsky/qazlake",
            "capacity_head_sha": "a" * 40,
        },
    )
    accepted = client.post(
        "/internal/v1/jobs/claim",
        headers=headers,
        json=claim
        | {
            "capacity_directive_id": operation["operation_id"],
            "capacity_repository": "belilovsky/qazlake",
            "capacity_head_sha": "b" * 40,
        },
    )

    assert missing_binding.status_code == 403
    assert missing_binding.json()["detail"] == "capacity override binding rejected"
    assert wrong_repository.status_code == 403
    assert wrong_repository.json()["detail"] == "capacity override binding rejected"
    assert wrong_sha.status_code == 403
    assert wrong_sha.json()["detail"] == "capacity override binding rejected"
    assert accepted.status_code == 200
    assert accepted.json()["job_id"] == 102
    assert accepted.json()["repository"] == "belilovsky/qazlake"
    assert store.job_status(100) == "pending"


def test_capacity_override_rejects_non_fifo_target(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client)
    _seed_pending_job(
        client,
        101,
        "fifo-head",
        repository="belilovsky/qazlake",
        head_sha="a" * 40,
    )
    _seed_pending_job(
        client,
        102,
        "later-target",
        repository="belilovsky/qazlake",
        head_sha="b" * 40,
    )

    response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qazlake",
            "head_sha": "b" * 40,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 95.0,
            "duration_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "must not leapfrog FIFO",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "capacity override target is not the durable FIFO head"
    assert (
        client.app.state.operations.active(
            WORKER_NAME,
            registered_profiles=("qdev-ci", "qdev-ci-docker"),
        )
        is None
    )


def test_capacity_override_skips_inadmissible_admin_platform_fifo_rows(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)
    _heartbeat(client)
    stale_sha = "9ebf6718c2085d1a58f59323f37b1e1dd707225f"
    _seed_pending_job(
        client,
        41,
        "blocked-admin-platform-row",
        repository="belilovsky/qazposter",
        head_sha=stale_sha,
    )
    _seed_pending_job(
        client,
        42,
        "first-admissible-row",
        repository="belilovsky/qazlake",
        head_sha="b" * 40,
    )

    response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qazlake",
            "head_sha": "b" * 40,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 95.0,
            "duration_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "admissible FIFO head after blocked managed row",
        },
    )

    assert response.status_code == 200
    payload = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["immutable_tuple"]["job_id"] == 42
    assert payload["fifo_skipped"] == [
        {
            "job_id": 41,
            "repository": "belilovsky/qazposter",
            "run_id": 84000000041,
            "attempt": 1,
            "head_sha": stale_sha,
            "profile": "qdev-ci-docker",
            "managed_registry_entry": "qazposter",
            "reason": "admin-platform-candidate-not-active",
        }
    ]


def test_capacity_override_prioritizes_exact_active_controller_candidate(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)
    _heartbeat(client)
    _seed_pending_job(client, 41, "unrelated-earlier-row")
    template = yaml.safe_load(
        (Path(__file__).parents[1] / "config" / "admin-platform-ledger-v2.yml").read_text(
            encoding="utf-8"
        )
    )
    controller_sha = template["active_candidate"]["source_sha"]
    _seed_pending_job(
        client,
        42,
        "active-controller-candidate",
        repository="belilovsky/qdev-runner-control-plane",
        head_sha=controller_sha,
    )

    response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qdev-runner-control-plane",
            "head_sha": controller_sha,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 95.0,
            "duration_seconds": 300,
            "owner": "admin-platform",
            "reason": "restore exact controller prerequisite admission",
        },
    )

    assert response.status_code == 200
    payload = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["immutable_tuple"]["job_id"] == 42
    assert payload["fifo_skipped"] == [
        {
            "job_id": 41,
            "repository": "belilovsky/example",
            "run_id": 84000000041,
            "attempt": 1,
            "head_sha": "a" * 40,
            "profile": "qdev-ci-docker",
            "managed_registry_entry": None,
            "reason": "active-admin-platform-controller-priority",
        }
    ]
    assert client.app.state.store.job_status(41) == "pending"


def test_capacity_override_skips_inadmissible_managed_release_fifo_rows(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)
    _heartbeat(client)
    stale_sha = "5dff352e7cb08af9abef292680b9fbadf2714145"
    _seed_pending_job(
        client,
        41,
        "blocked-managed-release-row",
        repository="belilovsky/qazgeo",
        head_sha=stale_sha,
        profile="qdev-ci-docker",
    )
    _seed_pending_job(
        client,
        42,
        "first-admissible-row",
        repository="belilovsky/qazlake",
        head_sha="b" * 40,
    )

    response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qazlake",
            "head_sha": "b" * 40,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 95.0,
            "duration_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "admissible FIFO head after stale managed release row",
        },
    )

    assert response.status_code == 200
    payload = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["immutable_tuple"]["job_id"] == 42
    assert payload["fifo_skipped"] == [
        {
            "job_id": 41,
            "repository": "belilovsky/qazgeo",
            "run_id": 84000000041,
            "attempt": 1,
            "head_sha": stale_sha,
            "profile": "qdev-ci-docker",
            "managed_registry_entry": "qazgeo",
            "reason": "managed-release-candidate-tuple-not-admitted",
        }
    ]
    assert client.app.state.store.job_status(41) == "pending"


def test_capacity_override_does_not_prioritize_non_active_controller_sha(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)
    _heartbeat(client)
    _seed_pending_job(client, 41, "unrelated-earlier-row")
    _seed_pending_job(
        client,
        42,
        "non-active-controller-candidate",
        repository="belilovsky/qdev-runner-control-plane",
        head_sha="f" * 40,
    )

    response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qdev-runner-control-plane",
            "head_sha": "f" * 40,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 95.0,
            "duration_seconds": 300,
            "owner": "admin-platform",
            "reason": "must remain ledger bound",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "capacity override target is not the durable FIFO head"
    )
    assert (
        client.app.state.operations.active(
            WORKER_NAME,
            registered_profiles=("qdev-ci", "qdev-ci-docker"),
        )
        is None
    )


def test_stale_job_audit_is_signed_and_read_only(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub())
    _seed_stale_running_job(client)

    response = client.get(
        "/internal/v1/operations/jobs/stale?worker_timeout_seconds=300",
        headers=OPERATOR_HEADERS,
    )

    assert response.status_code == 200
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    candidate = receipt["payload"]["candidates"][0]
    assert candidate["job_id"] == 42
    assert candidate["run_id"] == 84
    assert candidate["attempt"] == 1
    assert candidate["exact_sha"] == "a" * 40
    assert candidate["profile"] == "qdev-ci-docker"
    assert client.app.state.store.job_status(42) == "running"


def test_stale_queued_provider_job_is_released_without_losing_fifo(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path, FakeGitHub())
    created_at = _seed_stale_running_job(client)

    response = client.post(
        "/internal/v1/operations/jobs/42/recover-stale",
        headers=OPERATOR_HEADERS,
        json={
            "worker_timeout_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "provider-confirmed queued job on stale worker",
        },
    )

    assert response.status_code == 200
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    assert receipt["payload"]["action"] == "released-preserving-fifo"
    assert receipt["payload"]["fifo_preserved"] is True
    job = client.app.state.store.job(42)
    assert job is not None
    assert job["status"] == "pending"
    assert float(job["created_at"]) == created_at


def test_stale_provider_active_job_is_never_released(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub(job_status="in_progress"))
    _seed_stale_running_job(client)

    response = client.post(
        "/internal/v1/operations/jobs/42/recover-stale",
        headers=OPERATOR_HEADERS,
        json={
            "worker_timeout_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "must reconcile before release",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "provider reports the job is still in progress"
    assert client.app.state.store.job_status(42) == "running"


def test_stale_job_with_provider_sha_mismatch_is_never_released(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub(head_sha="b" * 40))
    _seed_stale_running_job(client)

    response = client.post(
        "/internal/v1/operations/jobs/42/recover-stale",
        headers=OPERATOR_HEADERS,
        json={
            "worker_timeout_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "must preserve exact SHA",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == ("provider immutable tuple does not match the queued job")
    assert client.app.state.store.job_status(42) == "running"


def test_stale_job_with_provider_job_run_mismatch_is_never_released(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub(job_run_id=85))
    _seed_stale_running_job(client)

    response = client.post(
        "/internal/v1/operations/jobs/42/recover-stale",
        headers=OPERATOR_HEADERS,
        json={
            "worker_timeout_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "must preserve provider job-to-run binding",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == ("provider immutable tuple does not match the queued job")
    assert client.app.state.store.job_status(42) == "running"


def test_stale_provider_completed_job_is_closed_not_requeued(tmp_path: Path) -> None:
    client = _app(
        tmp_path,
        FakeGitHub(job_status="completed", job_conclusion="success"),
    )
    _seed_stale_running_job(client)

    response = client.post(
        "/internal/v1/operations/jobs/42/recover-stale",
        headers=OPERATOR_HEADERS,
        json={
            "worker_timeout_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "provider terminal reconciliation",
        },
    )

    assert response.status_code == 200
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    assert receipt["payload"]["action"] == "completed-from-provider"
    job = client.app.state.store.job(42)
    assert job is not None
    assert job["status"] == "completed"
    assert job["result"] == "success"


def test_failed_worker_job_audit_is_signed_and_read_only(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub())
    _seed_failed_worker_job(client)

    response = client.get(
        "/internal/v1/operations/jobs/failed-worker-exit",
        headers=OPERATOR_HEADERS,
    )

    assert response.status_code == 200
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    candidate = receipt["payload"]["candidates"][0]
    assert candidate["job_id"] == 42
    assert candidate["run_id"] == 84
    assert candidate["exact_sha"] == "a" * 40
    assert candidate["state"] == "failed"
    assert client.app.state.store.job_status(42) == "failed"


def test_failed_worker_job_is_released_only_when_provider_is_queued(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub())
    created_at = _seed_failed_worker_job(client)

    response = client.post(
        "/internal/v1/operations/jobs/42/recover-failed-worker-exit",
        headers=OPERATOR_HEADERS,
        json={
            "owner": "portfolio-ci",
            "reason": "provider remains queued after local worker exit",
        },
    )

    assert response.status_code == 200
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    assert receipt["payload"]["action"] == "released-preserving-fifo"
    assert receipt["payload"]["fifo_preserved"] is True
    job = client.app.state.store.job(42)
    assert job is not None
    assert job["status"] == "pending"
    assert job["completed_at"] is None
    assert float(job["created_at"]) == created_at


def test_failed_worker_job_is_not_released_while_provider_is_active(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub(job_status="in_progress"))
    _seed_failed_worker_job(client)

    response = client.post(
        "/internal/v1/operations/jobs/42/recover-failed-worker-exit",
        headers=OPERATOR_HEADERS,
        json={
            "owner": "portfolio-ci",
            "reason": "provider state must win",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "provider reports the job is still in progress"
    assert client.app.state.store.job_status(42) == "failed"


def test_failed_worker_job_with_provider_tuple_mismatch_is_not_released(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path, FakeGitHub(head_sha="b" * 40))
    _seed_failed_worker_job(client)

    response = client.post(
        "/internal/v1/operations/jobs/42/recover-failed-worker-exit",
        headers=OPERATOR_HEADERS,
        json={
            "owner": "portfolio-ci",
            "reason": "immutable provider tuple must match",
        },
    )

    assert response.status_code == 409
    assert response.json()["detail"] == (
        "provider immutable tuple does not match the failed job"
    )
    assert client.app.state.store.job_status(42) == "failed"
