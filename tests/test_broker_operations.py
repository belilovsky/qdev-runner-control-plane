from __future__ import annotations

import json
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
import yaml
from fastapi.testclient import TestClient

from qdev_runner.broker import create_app
from qdev_runner.models import QueuedJob
from qdev_runner.operator import verify_controller_receipt
from qdev_runner.policy import Policy
from qdev_runner.release_lane import ReleaseLaneError, ReleaseLanePolicy
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


def _app(
    tmp_path: Path,
    github: Any | None = None,
    *,
    include_qgeo: bool = False,
) -> TestClient:
    inventory = tmp_path / "repos.json"
    repositories = [
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
    if include_qgeo:
        repositories.append(
            {
                "id": 4,
                "full_name": "belilovsky/qazgeo",
                "private": True,
                "archived": False,
                "default_branch": "main",
                "profiles": ["qdev-ci", "qdev-ci-docker"],
            }
        )
    inventory.write_text(
        json.dumps({"repositories": repositories}),
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
                    "qdev-ci": {
                        "labels": ["self-hosted", "Linux", "X64", "qdev-ci"],
                        "resources": {
                            "cpu": 1.0,
                            "memory_mb": 3072,
                            "disk_mb": 12288,
                            "pids_limit": 512,
                        },
                        "timeout_minutes": 45,
                        "allow_public_pr": True,
                    },
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
    managed_release_ledger = Path(__file__).parents[1] / "config" / "managed-release-ledger.yml"
    if include_qgeo:
        managed_release_ledger = tmp_path / "managed-release-ledger.yml"
        managed_release_ledger.write_bytes(
            (Path(__file__).parents[1] / "config" / "managed-release-ledger.yml").read_bytes()
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
        fleet_bootstrap_policy_path=Path(__file__).parents[1] / "config" / "fleet-bootstrap.yml",
        fleet_bootstrap_operation_root=tmp_path / "fleet-bootstrap-operations",
        fleet_bootstrap_receipt_root=tmp_path / "fleet-bootstrap-receipts",
        fleet_recovery_executable=tmp_path / "not-installed-recovery",
        managed_registry_path=Path(__file__).parents[1] / "config" / "managed-registry.yml",
        admin_platform_ledger_path=(
            Path(__file__).parents[1] / "config" / "admin-platform-ledger.yml"
        ),
        managed_release_ledger_path=(managed_release_ledger),
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


def test_certificate_bound_release_lane_ignores_spoofed_identity_header(tmp_path: Path) -> None:
    client = _app(tmp_path)
    settings = client.app.state.settings
    document = yaml.safe_load(settings.release_lanes_path.read_text(encoding="utf-8"))
    document["lanes"]["qdev-release-qaz-tours"]["client_certificate_sha256"] = "a" * 64
    document["lanes"]["qdev-release-qaz-tours"]["host_agent_certificate_sha256"] = "b" * 64
    settings.release_lanes_path.write_text(yaml.safe_dump(document), encoding="utf-8")

    heartbeat = _release_heartbeat()
    assert (
        client.post(
            "/internal/v1/release-hosts/vps-hostinger-186/heartbeat",
            json=heartbeat,
            headers={
                "X-QDev-mTLS-Identity": "qdev-host-agent:vps-hostinger-186",
                "X-QDev-Client-Certificate-SHA256": "c" * 64,
            },
        ).status_code
        == 403
    )
    assert (
        client.post(
            "/internal/v1/release-hosts/vps-hostinger-186/heartbeat",
            json=heartbeat,
            headers={
                "X-QDev-mTLS-Identity": "spoofed",
                "X-QDev-Client-Certificate-SHA256": "b" * 64,
            },
        ).status_code
        == 200
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


QGEO_SOURCE_SHA = "8bfd4e5bb7da5c7c99fd12865fb56d88fc5c9d7d"
QGEO_PR_BRANCH = "codex/qgeo-unified-recovery-20260904"
QGEO_CI_BINDINGS = (
    (33838251934, 100915082535, "qdev-ci"),
    (33838251867, 100915081363, "qdev-ci"),
    (33838251934, 100982561858, "qdev-ci"),
    (33838251934, 100982561902, "qdev-ci-docker"),
)


class QGeoFakeGitHub:
    def __init__(
        self,
        *,
        event: str = "pull_request",
        branch: str = QGEO_PR_BRANCH,
        run_status: str = "completed",
        run_conclusion: str | None = "success",
        job_status: str = "completed",
        job_conclusion: str | None = "success",
        head_sha: str = QGEO_SOURCE_SHA,
        run_id: int = 0,
        profile: str = "qdev-ci",
    ) -> None:
        self.event = event
        self.branch = branch
        self.run_status = run_status
        self.run_conclusion = run_conclusion
        self.job_status = job_status
        self.job_conclusion = job_conclusion
        self.head_sha = head_sha
        self.run_id = run_id
        self.profile = profile

    def workflow_run(self, installation_id: int, repository: str, run_id: int) -> dict[str, object]:
        return {
            "id": run_id,
            "head_sha": self.head_sha,
            "run_attempt": 1,
            "status": self.run_status,
            "conclusion": self.run_conclusion,
            "event": self.event,
            "ref": "refs/heads/main" if self.event == "push" else None,
            "head_branch": self.branch,
        }

    def workflow_job(self, installation_id: int, repository: str, job_id: int) -> dict[str, object]:
        binding = next((item for item in QGEO_CI_BINDINGS if item[1] == job_id), None)
        run_id = binding[0] if binding is not None else self.run_id
        profile = binding[2] if binding is not None else self.profile
        return {
            "id": job_id,
            "run_id": run_id,
            "run_attempt": 1,
            "head_sha": self.head_sha,
            "head_branch": self.branch,
            "status": self.job_status,
            "conclusion": self.job_conclusion,
            "labels": ["self-hosted", "Linux", "X64", profile],
        }


def _seed_qgeo_jobs(
    client: TestClient,
    bindings: tuple[tuple[int, int, str], ...] = QGEO_CI_BINDINGS,
    *,
    branch: str = QGEO_PR_BRANCH,
) -> None:
    store: Store = client.app.state.store
    for index, (run_id, job_id, profile) in enumerate(bindings):
        queued = QueuedJob(
            delivery_id=f"qgeo-delivery-{job_id}",
            job_id=job_id,
            run_id=run_id,
            repository="belilovsky/qazgeo",
            repository_id=4,
            installation_id=2,
            labels=("self-hosted", "Linux", "X64", profile),
            head_sha=QGEO_SOURCE_SHA,
            head_branch=branch,
            payload={"workflow_job": {"run_attempt": 1}},
        )
        assert store.enqueue(queued) is True, index


def test_qgeo_ci_registration_accepts_allowlisted_pr_and_main_push_idempotently(
    tmp_path: Path,
) -> None:
    github = QGeoFakeGitHub()
    client = _app(tmp_path, github=github, include_qgeo=True)
    _seed_qgeo_jobs(client, QGEO_CI_BINDINGS[:1])
    body = {
        "repository": "belilovsky/qazgeo",
        "source_sha": QGEO_SOURCE_SHA,
        "run_id": QGEO_CI_BINDINGS[0][0],
        "attempt": 1,
        "job_id": QGEO_CI_BINDINGS[0][1],
    }

    first = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-registration",
        json=body,
        headers=OPERATOR_HEADERS,
    )
    assert first.status_code == 200, first.text
    first_payload = verify_controller_receipt(first.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert first_payload["idempotent"] is True
    assert first_payload["provider"]["event"] == "pull_request"

    repeated = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-registration",
        json=body,
        headers=OPERATOR_HEADERS,
    )
    assert repeated.status_code == 200
    repeated_payload = verify_controller_receipt(repeated.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert repeated_payload["idempotent"] is True

    main_run_id, main_job_id, _ = (33870997811, 101016693706, "qdev-ci")
    main_github = QGeoFakeGitHub(event="push", branch="main", run_id=main_run_id)
    main_tmp_path = tmp_path / "main"
    main_tmp_path.mkdir()
    main_client = _app(main_tmp_path, github=main_github, include_qgeo=True)
    _seed_qgeo_jobs(main_client, ((main_run_id, main_job_id, "qdev-ci"),), branch="main")
    main_body = {
        "repository": "belilovsky/qazgeo",
        "source_sha": QGEO_SOURCE_SHA,
        "run_id": main_run_id,
        "attempt": 1,
        "job_id": main_job_id,
    }
    main = main_client.post(
        "/internal/v1/operations/releases/qazgeo/ci-registration",
        json=main_body,
        headers=OPERATOR_HEADERS,
    )
    assert main.status_code == 200, main.text
    main_payload = verify_controller_receipt(main.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert main_payload["idempotent"] is False
    assert main_payload["provider"]["event"] == "push"


def test_qgeo_ci_registration_rejects_provider_sha_mismatch(tmp_path: Path) -> None:
    github = QGeoFakeGitHub(head_sha="f" * 40)
    client = _app(tmp_path, github=github, include_qgeo=True)
    _seed_qgeo_jobs(client, QGEO_CI_BINDINGS[:1])
    response = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-registration",
        json={
            "repository": "belilovsky/qazgeo",
            "source_sha": QGEO_SOURCE_SHA,
            "run_id": QGEO_CI_BINDINGS[0][0],
            "attempt": 1,
            "job_id": QGEO_CI_BINDINGS[0][1],
        },
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 409
    assert "provider tuple" in response.json()["detail"]


def test_qgeo_ci_registration_allows_completed_job_while_run_aggregate_is_queued(
    tmp_path: Path,
) -> None:
    main_run_id, main_job_id, _ = (33870997811, 101016693706, "qdev-ci")
    github = QGeoFakeGitHub(
        event="push",
        branch="main",
        run_status="queued",
        run_conclusion=None,
        job_status="completed",
        job_conclusion="success",
        run_id=main_run_id,
    )
    client = _app(tmp_path, github=github, include_qgeo=True)
    _seed_qgeo_jobs(client, ((main_run_id, main_job_id, "qdev-ci"),), branch="main")
    response = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-registration",
        json={
            "repository": "belilovsky/qazgeo",
            "source_sha": QGEO_SOURCE_SHA,
            "run_id": main_run_id,
            "attempt": 1,
            "job_id": main_job_id,
        },
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 200, response.text
    payload = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["provider"]["run_status"] == "queued"
    assert payload["provider"]["job_status"] == "completed"


def test_qgeo_ci_reconcile_promotes_all_bindings_and_is_idempotent(tmp_path: Path) -> None:
    client = _app(tmp_path, github=QGeoFakeGitHub(), include_qgeo=True)
    _seed_qgeo_jobs(client)
    response = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-reconcile",
        json={"source_sha": QGEO_SOURCE_SHA},
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 200, response.text
    payload = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["idempotent"] is False
    assert payload["run_ids"] == [33838251867, 33838251934]
    assert len(payload["bindings"]) == 4
    ledger = yaml.safe_load(client.app.state.settings.managed_release_ledger_path.read_text())
    entry = ledger["entries"]["qazgeo"]
    assert entry["status"] == "ci_passed"
    assert all(item["state"] == "terminal" for item in entry["ci_runs"])

    repeated = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-reconcile",
        json={"source_sha": QGEO_SOURCE_SHA},
        headers=OPERATOR_HEADERS,
    )
    assert repeated.status_code == 200
    repeated_payload = verify_controller_receipt(repeated.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert repeated_payload["idempotent"] is True


def test_qgeo_ci_reconcile_waits_for_provider_terminal_state(tmp_path: Path) -> None:
    client = _app(
        tmp_path,
        github=QGeoFakeGitHub(run_status="in_progress", job_status="queued"),
        include_qgeo=True,
    )
    _seed_qgeo_jobs(client)
    response = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-reconcile",
        json={"source_sha": QGEO_SOURCE_SHA},
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "managed CI is still running"


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
    profiles: list[str] | None = None,
    effective_profiles: list[str] | None = None,
) -> dict[str, object]:
    worker_profiles = profiles or ["qdev-ci-docker"]
    admitted_profiles = effective_profiles if effective_profiles is not None else ["qdev-ci-docker"]
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
            "profiles": worker_profiles,
            "active_jobs": active_jobs,
            "active_job_ids": [42] if active_jobs else [],
            "detail": {
                **baseline,
                "raw_capacity": raw,
                "baseline_capacity": baseline,
                "effective_capacity": baseline,
                "effective_profiles": admitted_profiles if admitted else [],
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
        headers=OPERATOR_HEADERS,
    )
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    assert receipt["payload"]["kind"] == "controller-release-audit"
    assert receipt["payload"]["controller_release"] == status


def test_existing_worker_recovery_is_controller_bound_and_fail_closed_without_adapter(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)
    request = {
        "schema": "qdev-fleet-bootstrap-request-v1",
        "action": "restore-existing-worker",
        "source_sha": "a" * 40,
        "run_id": 123,
        "job_id": 456,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": "d3341e9f0d900d7dc023dfb2e95efd45ef45d8cd",
        "controller_release_digest": (
            "sha256:14c5a8b506947c18c55646e36bfec077885a63a8a272b5aea1112d31266e969f"
        ),
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
    assert (
        client.post(path, json=body).status_code == 401
    )
    assert (
        client.post(
            path,
            json=body,
            headers={"X-QDev-Operator-Token": OPERATOR_TOKEN},
        ).status_code
        == 403
    )

    response = client.post(path, json=body, headers=OPERATOR_HEADERS)
    assert response.status_code == 200
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    payload = receipt["payload"]
    assert payload["kind"] == "fleet-bootstrap-recovery"
    assert payload["status"] == "access_blocked"
    assert payload["operation_status"] == "pending"
    assert payload["worker_name"] == "qdev-platform-ci-187"
    assert payload["target_id"].endswith("qdev-platform-ci-187")
    assert payload["active_jobs"] == 0
    private_receipt = tmp_path / "fleet-bootstrap-receipts" / "worker-recovery-001.json"
    assert json.loads(private_receipt.read_text(encoding="utf-8"))["status"] == "access_blocked"


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
    assert payload["active_candidate"] == "avds-admin-shell"
    assert payload["admission"]["claim_scope"] == "controller-signed-only"
    assert payload["managed_registry"]["schema"] == "qdev-managed-registry-v3"
    assert payload["admin_platform_ledger"]["schema"] == "qdev-admin-platform-ledger-v1"


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


def test_managed_qgeo_scope_prunes_terminal_profile_tuple_on_reuse(tmp_path: Path) -> None:
    client = _app(tmp_path, include_qgeo=True)
    store: Store = client.app.state.store
    candidate_sha = "8bfd4e5bb7da5c7c99fd12865fb56d88fc5c9d7d"
    first_job = QueuedJob(
        delivery_id="qgeo-security",
        job_id=100982561858,
        run_id=33838251934,
        repository="belilovsky/qazgeo",
        repository_id=4,
        installation_id=1,
        labels=("self-hosted", "Linux", "X64", "qdev-ci"),
        head_sha=candidate_sha,
        head_branch="main",
        payload={"workflow_job": {"run_attempt": 1}},
    )
    second_job = QueuedJob(
        delivery_id="qgeo-test",
        job_id=100982561902,
        run_id=33838251934,
        repository="belilovsky/qazgeo",
        repository_id=4,
        installation_id=1,
        labels=("self-hosted", "Linux", "X64", "qdev-ci-docker"),
        head_sha=candidate_sha,
        head_branch="main",
        payload={"workflow_job": {"run_attempt": 1}},
    )
    assert store.enqueue(first_job) is True
    assert store.enqueue(second_job) is True
    scope_id = "qgeo-release-scope-20260904"
    request = {
        "job_id": first_job.job_id,
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": scope_id,
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci",
        "worker_certificate_sha256": "c" * 64,
        "correlation_id": "qgeo-profile-transition",
        "duration_seconds": 900,
    }
    _heartbeat(
        client,
        admitted=True,
        scope_id=scope_id,
        profiles=["qdev-ci", "qdev-ci-docker"],
        effective_profiles=["qdev-ci"],
    )
    headers = OPERATOR_HEADERS
    first = client.post(
        f"/internal/v1/operations/jobs/{first_job.job_id}/claim-scope",
        headers=headers,
        json=request,
    )
    assert first.status_code == 200
    store.set_status(first_job.job_id, "completed", "success")

    _heartbeat(
        client,
        admitted=True,
        scope_id=scope_id,
        profiles=["qdev-ci", "qdev-ci-docker"],
        effective_profiles=["qdev-ci-docker"],
    )
    second_request = request | {
        "job_id": second_job.job_id,
    }
    rollover = client.post(
        f"/internal/v1/operations/jobs/{second_job.job_id}/claim-scope",
        headers=headers,
        json=second_request,
    )
    assert rollover.status_code == 200
    rollover_payload = verify_controller_receipt(rollover.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert rollover_payload["rolled_over_terminal_scope"] is True
    assert [item["job_id"] for item in rollover_payload["claim_scope"]["jobs"]] == [
        first_job.job_id,
        second_job.job_id,
    ]

    repaired = client.post(
        f"/internal/v1/operations/jobs/{second_job.job_id}/claim-scope",
        headers=headers,
        json=second_request,
    )
    assert repaired.status_code == 200
    repaired_payload = verify_controller_receipt(repaired.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert repaired_payload["idempotent"] is False
    assert repaired_payload["repaired_managed_scope"] is True
    assert [item["job_id"] for item in repaired_payload["claim_scope"]["jobs"]] == [
        second_job.job_id
    ]

    repeated = client.post(
        f"/internal/v1/operations/jobs/{second_job.job_id}/claim-scope",
        headers=headers,
        json=second_request,
    )
    assert repeated.status_code == 200
    repeated_payload = verify_controller_receipt(repeated.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert repeated_payload["idempotent"] is True


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
        headers=OPERATOR_HEADERS,
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


def test_worker_audit_closes_expired_capacity_directive(tmp_path: Path) -> None:
    client = _app(tmp_path)
    _heartbeat(client, admitted=True)
    operation_store = client.app.state.operations
    assert operation_store is not None
    directive = operation_store.create_capacity_override(
        worker_name=WORKER_NAME,
        repository="belilovsky/qazshield",
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
        headers=OPERATOR_HEADERS,
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
