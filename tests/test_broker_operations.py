from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from fastapi.testclient import TestClient

from qdev_runner.broker import create_app
from qdev_runner.models import QueuedJob
from qdev_runner.operator import verify_controller_receipt
from qdev_runner.policy import Policy
from qdev_runner.settings import BrokerSettings
from qdev_runner.store import Store

OPERATOR_TOKEN = "operator-token"  # noqa: S105 - inert test fixture
RECEIPT_KEY = "receipt-key"
DIRECTIVE_KEY = "directive-key"
WORKER_TOKEN = "worker-token"  # noqa: S105 - inert test fixture
WORKER_NAME = "srv1879763-light-primary"


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
                    }
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
                    }
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
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
        managed_registry_path=Path(__file__).parents[1] / "config" / "managed-registry.yml",
        release_jobs_root=tmp_path / "release-jobs",
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


def _heartbeat(
    client: TestClient,
    *,
    active_jobs: int = 0,
    disk_free_gib: float = 30.0,
    admitted: bool = False,
    scope_id: str | None = None,
) -> dict[str, object]:
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
            "profiles": ["qdev-ci-docker"],
            "active_jobs": active_jobs,
            "active_job_ids": [42] if active_jobs else [],
            "detail": {
                **baseline,
                "raw_capacity": raw,
                "baseline_capacity": baseline,
                "effective_capacity": baseline,
                "effective_profiles": ["qdev-ci-docker"] if admitted else [],
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


def _seed_pending_job(client: TestClient, job_id: int, delivery_id: str) -> None:
    store: Store = client.app.state.store
    assert (
        store.enqueue(
            QueuedJob(
                delivery_id=delivery_id,
                job_id=job_id,
                run_id=84000000000 + job_id,
                repository="belilovsky/example",
                repository_id=1,
                installation_id=2,
                labels=("self-hosted", "Linux", "X64", "qdev-ci-docker"),
                head_sha="a" * 40,
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

    unauthorized = client.get("/internal/v1/operations/controller-release")
    assert unauthorized.status_code == 401
    response = client.get(
        "/internal/v1/operations/controller-release",
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
    )
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    assert receipt["payload"]["kind"] == "controller-release-audit"
    assert receipt["payload"]["controller_release"] == status


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


def test_operator_audit_and_override_are_signed_and_reach_heartbeat(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client)

    unauthorized = client.get("/internal/v1/operations/workers")
    assert unauthorized.status_code == 401

    audit_response = client.get(
        "/internal/v1/operations/workers",
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
    )
    assert audit_response.status_code == 200
    audit = verify_controller_receipt(audit_response.json(), receipt_key=RECEIPT_KEY)
    assert audit["payload"]["workers"][0]["worker"] == WORKER_NAME
    assert audit["payload"]["workers"][0]["active_jobs"] == 0

    override_response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
        json={
            "repository": "belilovsky/qazshield",
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
    assert operation["min_disk_free_gib"] == 4.5

    directive_response = _heartbeat(client)
    directive = directive_response["capacity_override"]
    assert isinstance(directive, dict)
    assert directive["operation_id"] == operation["operation_id"]
    assert directive["signature"] == operation["signature"]


def test_controller_issues_only_profile_fifo_head_scope_idempotently(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(client, 42, "delivery-42")
    _seed_pending_job(client, 43, "delivery-43")
    headers = {
        "X-QDev-Operator-Token": OPERATOR_TOKEN,
        "X-QDev-Operator-mTLS-Identity": "qdev-fleet-operations",
    }
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


def test_controller_rolls_scope_forward_only_after_terminal_fifo_tuple(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(client, 42, "delivery-42")
    _seed_pending_job(client, 43, "delivery-43")
    headers = {
        "X-QDev-Operator-Token": OPERATOR_TOKEN,
        "X-QDev-Operator-mTLS-Identity": "qdev-fleet-operations",
    }
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


def test_controller_rebinds_legacy_scope_only_for_its_same_immutable_tuple(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(client, 42, "delivery-42")
    headers = {
        "X-QDev-Operator-Token": OPERATOR_TOKEN,
        "X-QDev-Operator-mTLS-Identity": "qdev-fleet-operations",
    }
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
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
        json={
            "repository": "belilovsky/qazshield",
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

    response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
        json={
            "repository": "belilovsky/qazlake",
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
            labels=("self-hosted", "Linux", "X64", "qdev-ci-docker"),
            head_sha="a" * 40,
            head_branch="main",
            payload={},
        )
    )
    assert store.enqueue(
        QueuedJob(
            delivery_id="target",
            job_id=101,
            run_id=84,
            repository="belilovsky/qazlake",
            repository_id=2,
            installation_id=2,
            labels=("self-hosted", "Linux", "X64", "qdev-ci-docker"),
            head_sha="a" * 40,
            head_branch="main",
            payload={},
        )
    )
    override_response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
        json={
            "repository": "belilovsky/qazlake",
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
        },
    )
    accepted = client.post(
        "/internal/v1/jobs/claim",
        headers=headers,
        json=claim
        | {
            "capacity_directive_id": operation["operation_id"],
            "capacity_repository": "belilovsky/qazlake",
        },
    )

    assert missing_binding.status_code == 403
    assert missing_binding.json()["detail"] == "capacity override binding rejected"
    assert wrong_repository.status_code == 403
    assert wrong_repository.json()["detail"] == "capacity override binding rejected"
    assert accepted.status_code == 200
    assert accepted.json()["job_id"] == 101
    assert accepted.json()["repository"] == "belilovsky/qazlake"
    assert store.job_status(100) == "pending"


def test_stale_job_audit_is_signed_and_read_only(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub())
    _seed_stale_running_job(client)

    response = client.get(
        "/internal/v1/operations/jobs/stale?worker_timeout_seconds=300",
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
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
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
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
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
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
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
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
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
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
        headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
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
