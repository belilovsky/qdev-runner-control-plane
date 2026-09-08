from __future__ import annotations

import hashlib
import hmac
import json
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
from qdev_runner.fleet_bootstrap import (
    REQUEST_SCHEMA,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    bootstrap_ingress_operation_key,
)
from qdev_runner.fleet_host_dispatch import FleetHostDispatchSpool
from qdev_runner.managed_release_ledger import (
    QGEO_REQUIRED_JOB_PROFILES,
    qgeo_dynamic_job_label,
)
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
_FLEET_RELEASE_LANES = Path(__file__).resolve().parents[1] / "config" / "release-lanes.yml"


def _fleet_bootstrap_activation() -> dict[str, str]:
    return {
        "controller_revision": "a" * 40,
        "controller_release_digest": "sha256:" + "b" * 64,
        "controller_image_digest": "sha256:" + "c" * 64,
        "activation_envelope_digest": "sha256:" + "d" * 64,
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


def _app(
    tmp_path: Path,
    github: Any | None = None,
    *,
    managed_release_ledger_path: Path | None = None,
    include_qgeo: bool = False,
    fleet_bootstrap_oidc_verifier_factory: Any | None = None,
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
        {
            "id": 4,
            "full_name": "belilovsky/qazposter",
            "private": True,
            "archived": False,
            "default_branch": "main",
            "profiles": ["qdev-ci-docker"],
        },
    ]
    repositories.append(
        {
            "id": 5,
            "full_name": "belilovsky/qdev-runner-control-plane",
            "private": True,
            "archived": False,
            "default_branch": "main",
            "profiles": ["qdev-ci-docker"],
        }
    )
    if include_qgeo:
        repositories.append(
            {
                "id": 6,
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
    admission_overrides: dict[str, dict[str, int]] = {
        "belilovsky/qazshield": {"qdev-ci-docker": 15360},
        "belilovsky/qazlake": {"qdev-ci-docker": 12288},
        "belilovsky/example": {"qdev-ci-docker": 15360},
        "belilovsky/qazposter": {"qdev-ci-docker": 15360},
        "belilovsky/qdev-runner-control-plane": {"qdev-ci-docker": 15360},
    }
    repository_constraints: dict[str, dict[str, float | int]] = {}
    if include_qgeo:
        admission_overrides["belilovsky/qazgeo"] = {"qdev-ci-docker": 15360}
        repository_constraints["belilovsky/qazgeo"] = {
            "min_disk_free_gib": 35,
            "max_concurrency": 1,
        }
    profiles.write_text(
        yaml.safe_dump(
            {
                "repository_admission_disk_mb": admission_overrides,
                "repository_admission_constraints": repository_constraints,
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
    lane_document: dict[str, Any] = {
        "schema_version": "qdev-release-lanes-v2" if include_qgeo else "qdev-release-lanes-v1",
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
    }
    if include_qgeo:
        lane_document["lanes"]["qdev-release-qazgeo"] = {
            "project_id": "qazgeo",
            "placement": "qazgeo-app-runtime",
            "client_mtls_identity": "qdev-release-client:qazgeo",
            "host_agent_mtls_identity": "qdev-host-agent:qazgeo-app-runtime",
            "minimum_free_gib": 20,
            "heartbeat_ttl_seconds": 90,
            "artifact_repository": "belilovsky/qazgeo",
            "canonical_repository": "belilovsky/qazgeo",
            "artifact_ref_prefix": "registry.ci.qdev.run/belilovsky/qazgeo",
            "native_host_adapter": "qazgeo-native-immutable-release-v1",
            "runtime_endpoints": [
                "https://qgeo.tech/health",
                "https://qgeo.tech/health/live",
                "https://qgeo.tech/health/ready",
                "https://qgeo.tech/health/quality",
            ],
            "rollback_reference": "controller-verified immutable runtime rollback receipt",
            "required_readiness": ["db", "postgis", "martin", "photon", "redis", "app"],
        }
    release_lanes.write_text(
        yaml.safe_dump(lane_document, sort_keys=True),
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
        controller_activation_status_path=tmp_path / "controller-activation.json",
        claim_scopes_path=tmp_path / "claim-scopes.json",
        release_lanes_path=release_lanes,
        fleet_bootstrap_policy_path=fleet_bootstrap_policy,
        fleet_bootstrap_operation_root=tmp_path / "fleet-bootstrap-operations",
        fleet_bootstrap_receipt_root=tmp_path / "fleet-bootstrap-receipts",
        fleet_host_dispatch_request_root=tmp_path / "fleet-host-dispatch" / "incoming",
        fleet_host_dispatch_result_root=tmp_path / "fleet-host-dispatch" / "results",
        managed_registry_path=Path(__file__).parents[1] / "config" / "managed-registry.yml",
        admin_platform_ledger_path=admin_platform_ledger,
        admin_platform_receipt_root=admin_platform_receipts,
        managed_release_ledger_path=(managed_release_ledger_path or managed_release_ledger),
        release_jobs_root=tmp_path / "release-jobs",
        release_host_dispatch_keys_file=tmp_path / "release-host-dispatch-keys.json",
        release_host_dispatch_claim_ttl_seconds=120,
    )
    app = create_app(
        settings,
        store=Store(settings.database_path),
        policy=Policy(inventory, profiles),
        github=github or object(),  # type: ignore[arg-type]
        fleet_bootstrap_oidc_verifier_factory=fleet_bootstrap_oidc_verifier_factory,
    )
    return TestClient(app)


def _managed_release_ledger(
    tmp_path: Path,
    *,
    source_sha: str,
    run_id: int,
    status: str = "ci_queued",
) -> Path:
    template_path = Path(__file__).parents[1] / "config" / "managed-release-ledger.yml"
    document = yaml.safe_load(template_path.read_text(encoding="utf-8"))
    entry = document["entries"]["qazgeo"]
    entry["source_sha"] = source_sha
    entry["status"] = status
    entry["registration"].update(
        {
            "state": "open",
            "phase": "push",
            "pr_verified": True,
            "job_set_digest": None,
        }
    )
    entry["ci_runs"] = [
        {
            "repository": "belilovsky/qazgeo",
            "candidate_sha": source_sha,
            "checkout_sha": source_sha,
            "run_id": str(run_id),
            "attempt": "1",
            "job_id": "41",
            "workflow_path": ".github/workflows/ci.yml",
            "event": "push",
            "ref": "refs/heads/main",
            "head_branch": "main",
            "profile": "qdev-ci-docker",
            "labels": sorted(
                [
                    "self-hosted",
                    "Linux",
                    "X64",
                    "qdev-ci-docker",
                    qgeo_dynamic_job_label(str(run_id), "1", "test"),
                ]
            ),
            "job_name": "test",
            "state": "queued",
            "conclusion": None,
        }
    ]
    entry["ci"] = {"state": "ci_queued", "receipt_uri": None}
    path = tmp_path / "custom-managed-release-ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    return path


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


@pytest.mark.parametrize(
    ("certificate_sha256", "host_headers"),
    [
        (
            None,
            {"X-QDev-mTLS-Identity": "qdev-host-agent:vps-hostinger-186"},
        ),
        (
            "b" * 64,
            {"X-QDev-Client-Certificate-SHA256": "b" * 64},
        ),
        (
            "b" * 64,
            {
                "X-QDev-mTLS-Identity": "spoofed",
                "X-QDev-Client-Certificate-SHA256": "b" * 64,
            },
        ),
    ],
)
def test_managed_next_job_is_bound_to_private_host_key_and_authenticated_lane(
    tmp_path: Path,
    certificate_sha256: str | None,
    host_headers: dict[str, str],
) -> None:
    client = _app(tmp_path)
    settings: BrokerSettings = client.app.state.settings
    lane_document = {
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
    if certificate_sha256 is not None:
        lane_document["host_agent_certificate_sha256"] = certificate_sha256
    settings.release_lanes_path.write_text(
        yaml.safe_dump(
            {
                "schema_version": "qdev-release-lanes-v2",
                "lanes": {"qdev-release-qaz-tours": lane_document},
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    host_identity = "qdev-host-agent:vps-hostinger-186"
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


def test_certificate_bound_host_status_and_rollback_reject_stale_certificate(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path)
    settings = client.app.state.settings
    document = yaml.safe_load(settings.release_lanes_path.read_text(encoding="utf-8"))
    lane = document["lanes"]["qdev-release-qaz-tours"]
    lane["client_certificate_sha256"] = "a" * 64
    lane["host_agent_certificate_sha256"] = "b" * 64
    settings.release_lanes_path.write_text(yaml.safe_dump(document), encoding="utf-8")

    product_headers = {
        "X-QDev-mTLS-Identity": "qdev-release-client:qaz-tours",
        "X-QDev-Client-Certificate-SHA256": "a" * 64,
    }
    host_headers = {
        "X-QDev-mTLS-Identity": "qdev-host-agent:vps-hostinger-186",
        "X-QDev-Client-Certificate-SHA256": "b" * 64,
    }
    stale_host_headers = {
        "X-QDev-mTLS-Identity": "qdev-host-agent:vps-hostinger-186",
        "X-QDev-Client-Certificate-SHA256": "c" * 64,
    }
    assert (
        client.post(
            "/internal/v1/release-hosts/vps-hostinger-186/heartbeat",
            json=_release_heartbeat(),
            headers=host_headers,
        ).status_code
        == 200
    )
    accepted = client.post(
        "/internal/v1/releases/qaz-tours",
        json=_release_request(),
        headers=product_headers,
    )
    assert accepted.status_code == 202
    release_id = accepted.json()["release_id"]

    assert (
        client.get(
            f"/internal/v1/release-hosts/vps-hostinger-186/jobs/{release_id}",
            headers=host_headers,
        ).status_code
        == 200
    )
    assert (
        client.get(
            f"/internal/v1/release-hosts/vps-hostinger-186/jobs/{release_id}",
            headers=stale_host_headers,
        ).status_code
        == 403
    )
    assert (
        client.post(
            f"/internal/v1/release-hosts/vps-hostinger-186/jobs/{release_id}/rollback",
            json={},
            headers=host_headers,
        ).status_code
        == 409
    )
    assert (
        client.post(
            f"/internal/v1/release-hosts/vps-hostinger-186/jobs/{release_id}/rollback",
            json={},
            headers=stale_host_headers,
        ).status_code
        == 403
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
        self.jit_runner_names: list[str] = []

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
        self.jit_runner_names.append(runner_name)
        return "signed-jit-config"


QGEO_SOURCE_SHA = "9" * 40
QGEO_PR_CHECKOUT_SHA = "8" * 40
QGEO_PR_BRANCH = "codex/qgeo-final"
_QGEO_PROVIDER_JOB_NAMES = {
    "lint": "lint",
    "security-source": "security-source",
    "test": "test",
    "docker-build": "docker-build",
    "contract": "qdev-runner-contract",
}


def _qgeo_bindings(
    phase: str, *, pr_checkout_sha: str = QGEO_PR_CHECKOUT_SHA
) -> tuple[dict[str, object], ...]:
    event_offset = 0 if phase == "pull_request" else 1000
    workflow_run_ids = {
        ".github/workflows/ci.yml": 41001 + event_offset,
        ".github/workflows/qdev-runner-contract.yml": 41002 + event_offset,
    }
    bindings: list[dict[str, object]] = []
    job_id = 51000 + event_offset
    for workflow_path, jobs in QGEO_REQUIRED_JOB_PROFILES[phase].items():
        for job_name, profile in jobs.items():
            job_id += 1
            run_id = workflow_run_ids[workflow_path]
            checkout_sha = pr_checkout_sha if phase == "pull_request" else QGEO_SOURCE_SHA
            head_branch = QGEO_PR_BRANCH if phase == "pull_request" else "main"
            ref = "refs/pull/63/merge" if phase == "pull_request" else "refs/heads/main"
            bindings.append(
                {
                    "repository": "belilovsky/qazgeo",
                    "candidate_sha": QGEO_SOURCE_SHA,
                    "checkout_sha": checkout_sha,
                    "run_id": run_id,
                    "attempt": 1,
                    "job_id": job_id,
                    "workflow_path": workflow_path,
                    "event": phase,
                    "ref": ref,
                    "head_branch": head_branch,
                    "profile": profile,
                    "job_name": job_name,
                    "provider_name": _QGEO_PROVIDER_JOB_NAMES[job_name],
                    "labels": sorted(
                        [
                            "self-hosted",
                            "Linux",
                            "X64",
                            profile,
                            qgeo_dynamic_job_label(str(run_id), "1", job_name),
                        ]
                    ),
                }
            )
    return tuple(bindings)


class QGeoFakeGitHub:
    def __init__(
        self,
        *,
        phase: str = "pull_request",
        pr_checkout_sha: str = QGEO_PR_CHECKOUT_SHA,
    ) -> None:
        self.phase = phase
        self.pr_checkout_sha = pr_checkout_sha
        self.run_status = "completed"
        self.run_conclusion: str | None = "success"
        self.job_status = "completed"
        self.job_conclusion: str | None = "success"
        self.run_overrides: dict[int, dict[str, object]] = {}
        self.job_overrides: dict[int, dict[str, object]] = {}
        self.extra_jobs_by_run: dict[int, list[dict[str, object]]] = {}

    @property
    def bindings(self) -> tuple[dict[str, object], ...]:
        return _qgeo_bindings(self.phase, pr_checkout_sha=self.pr_checkout_sha)

    def _binding_for_run(self, run_id: int) -> dict[str, object]:
        return next(binding for binding in self.bindings if binding["run_id"] == run_id)

    def _binding_for_job(self, job_id: int) -> dict[str, object]:
        return next(binding for binding in self.bindings if binding["job_id"] == job_id)

    def workflow_run(self, installation_id: int, repository: str, run_id: int) -> dict[str, object]:
        binding = self._binding_for_run(run_id)
        is_pr = self.phase == "pull_request"
        value: dict[str, object] = {
            "id": run_id,
            "repository": {"full_name": "belilovsky/qazgeo"},
            "head_sha": binding["checkout_sha"],
            "run_attempt": 1,
            "status": self.run_status,
            "conclusion": self.run_conclusion,
            "event": self.phase,
            "path": binding["workflow_path"],
            "ref": binding["ref"],
            "head_branch": binding["head_branch"],
            "pull_requests": (
                [
                    {
                        "number": 63,
                        "head": {
                            "sha": QGEO_SOURCE_SHA,
                            "ref": QGEO_PR_BRANCH,
                            "repo": {"full_name": "belilovsky/qazgeo"},
                        },
                        "base": {"ref": "main"},
                    }
                ]
                if is_pr
                else []
            ),
        }
        value.update(self.run_overrides.get(run_id, {}))
        return value

    def workflow_job(self, installation_id: int, repository: str, job_id: int) -> dict[str, object]:
        binding = self._binding_for_job(job_id)
        value: dict[str, object] = {
            "id": job_id,
            "run_id": binding["run_id"],
            "run_attempt": 1,
            "head_sha": binding["checkout_sha"],
            "head_branch": binding["head_branch"],
            "status": self.job_status,
            "conclusion": self.job_conclusion,
            "name": binding["provider_name"],
            "labels": binding["labels"],
        }
        value.update(self.job_overrides.get(job_id, {}))
        return value

    def workflow_run_jobs(
        self, installation_id: int, repository: str, run_id: int, attempt: int
    ) -> list[dict[str, object]]:
        jobs = [
            self.workflow_job(installation_id, repository, int(binding["job_id"]))
            for binding in self.bindings
            if binding["run_id"] == run_id
        ]
        first = self._binding_for_run(run_id)
        if self.phase == "pull_request" and first["workflow_path"] == ".github/workflows/ci.yml":
            jobs.append(
                {
                    "id": 51999,
                    "run_id": run_id,
                    "run_attempt": attempt,
                    "head_sha": QGEO_PR_CHECKOUT_SHA,
                    "head_branch": QGEO_PR_BRANCH,
                    "status": "completed",
                    "conclusion": "skipped",
                    "name": "docker-build",
                    "labels": sorted(
                        [
                            "self-hosted",
                            "Linux",
                            "X64",
                            "qdev-ci-docker",
                            qgeo_dynamic_job_label(str(run_id), str(attempt), "docker-build"),
                        ]
                    ),
                }
            )
        jobs.extend(self.extra_jobs_by_run.get(run_id, []))
        return jobs


def _seed_qgeo_jobs(
    client: TestClient,
    bindings: tuple[dict[str, object], ...],
) -> None:
    store: Store = client.app.state.store
    for index, binding in enumerate(bindings):
        run_id = int(binding["run_id"])
        job_id = int(binding["job_id"])
        labels = tuple(str(label) for label in binding["labels"])
        queued = QueuedJob(
            delivery_id=f"qgeo-delivery-{job_id}",
            job_id=job_id,
            run_id=run_id,
            repository="belilovsky/qazgeo",
            repository_id=5,
            installation_id=2,
            labels=labels,
            head_sha=str(binding["checkout_sha"]),
            head_branch=str(binding["head_branch"]),
            payload={
                "action": "queued",
                "repository": {"id": 5, "full_name": "belilovsky/qazgeo"},
                "installation": {"id": 2},
                "workflow_job": {
                    "id": job_id,
                    "run_id": run_id,
                    "run_attempt": 1,
                    "name": binding["provider_name"],
                    "labels": list(labels),
                    "head_sha": binding["checkout_sha"],
                    "head_branch": binding["head_branch"],
                },
            },
        )
        assert store.enqueue(queued) is True, index


def _qgeo_registration_body(binding: dict[str, object]) -> dict[str, object]:
    return {
        "repository": "belilovsky/qazgeo",
        "source_sha": QGEO_SOURCE_SHA,
        "run_id": binding["run_id"],
        "attempt": binding["attempt"],
        "job_id": binding["job_id"],
    }


def _register_qgeo_bindings(client: TestClient, bindings: tuple[dict[str, object], ...]) -> None:
    for binding in bindings:
        response = client.post(
            "/internal/v1/operations/releases/qazgeo/ci-registration",
            json=_qgeo_registration_body(binding),
            headers=OPERATOR_HEADERS,
        )
        assert response.status_code == 200, response.text


def test_qgeo_ci_registration_is_protected_exact_and_idempotent(tmp_path: Path) -> None:
    github = QGeoFakeGitHub()
    client = _app(tmp_path, github=github, include_qgeo=True)
    binding = github.bindings[0]
    _seed_qgeo_jobs(client, (binding,))
    body = _qgeo_registration_body(binding)

    path = "/internal/v1/operations/releases/qazgeo/ci-registration"
    assert client.post(path, json=body).status_code == 401
    assert (
        client.post(path, json=body, headers={"X-QDev-Operator-Token": OPERATOR_TOKEN}).status_code
        == 403
    )

    first = client.post(path, json=body, headers=OPERATOR_HEADERS)
    assert first.status_code == 200, first.text
    first_payload = verify_controller_receipt(first.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert first_payload["idempotent"] is False
    assert first_payload["provider"]["event"] == "pull_request"
    assert first_payload["provider"]["candidate_sha"] == QGEO_SOURCE_SHA
    assert first_payload["provider"]["checkout_sha"] == QGEO_PR_CHECKOUT_SHA
    assert first_payload["provider"]["labels"] == binding["labels"]

    repeated = client.post(path, json=body, headers=OPERATOR_HEADERS)
    assert repeated.status_code == 200
    repeated_payload = verify_controller_receipt(repeated.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert repeated_payload["idempotent"] is True


def test_qgeo_ci_registration_rejects_main_push_from_closed_ledger(tmp_path: Path) -> None:
    github = QGeoFakeGitHub(phase="push")
    client = _app(tmp_path, github=github, include_qgeo=True)
    binding = github.bindings[0]
    _seed_qgeo_jobs(client, (binding,))
    response = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-registration",
        json=_qgeo_registration_body(binding),
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 409


def test_qgeo_ci_registration_rejects_forged_provider_labels(tmp_path: Path) -> None:
    github = QGeoFakeGitHub()
    client = _app(tmp_path, github=github, include_qgeo=True)
    binding = github.bindings[0]
    _seed_qgeo_jobs(client, (binding,))
    github.job_overrides[int(binding["job_id"])] = {
        "labels": [*binding["labels"], "forged-extra-label"]
    }
    response = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-registration",
        json=_qgeo_registration_body(binding),
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "managed CI binding was rejected"


def test_qgeo_ci_reconcile_promotes_all_bindings_and_is_idempotent(tmp_path: Path) -> None:
    github = QGeoFakeGitHub()
    client = _app(tmp_path, github=github, include_qgeo=True)
    _seed_qgeo_jobs(client, github.bindings)
    _register_qgeo_bindings(client, github.bindings)
    response = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-reconcile",
        json={"source_sha": QGEO_SOURCE_SHA},
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 200, response.text
    payload = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["idempotent"] is False
    assert payload["run_ids"] == [41001, 41002]
    assert len(payload["bindings"]) == 4
    ledger = yaml.safe_load(client.app.state.settings.managed_release_ledger_path.read_text())
    entry = ledger["entries"]["qazgeo"]
    assert entry["status"] == "ci_passed"
    assert entry["registration"]["state"] == "sealed"
    assert entry["registration"]["phase"] == "pull_request"
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


def test_qgeo_ci_reconcile_seals_exact_main_push_after_verified_pr(tmp_path: Path) -> None:
    github = QGeoFakeGitHub()
    client = _app(tmp_path, github=github, include_qgeo=True)
    _seed_qgeo_jobs(client, github.bindings)
    _register_qgeo_bindings(client, github.bindings)
    pr_response = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-reconcile",
        json={"source_sha": QGEO_SOURCE_SHA},
        headers=OPERATOR_HEADERS,
    )
    assert pr_response.status_code == 200, pr_response.text

    github.phase = "push"
    _seed_qgeo_jobs(client, github.bindings)
    _register_qgeo_bindings(client, github.bindings)
    push_response = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-reconcile",
        json={"source_sha": QGEO_SOURCE_SHA},
        headers=OPERATOR_HEADERS,
    )
    assert push_response.status_code == 200, push_response.text
    ledger = yaml.safe_load(client.app.state.settings.managed_release_ledger_path.read_text())
    entry = ledger["entries"]["qazgeo"]
    assert entry["registration"]["state"] == "sealed"
    assert entry["registration"]["phase"] == "push"
    assert len(entry["ci_runs"]) == 5
    assert {item["event"] for item in entry["ci_runs"]} == {"push"}
    assert {item["checkout_sha"] for item in entry["ci_runs"]} == {QGEO_SOURCE_SHA}


def test_qgeo_ci_reconcile_rejects_extra_provider_job(tmp_path: Path) -> None:
    github = QGeoFakeGitHub()
    client = _app(tmp_path, github=github, include_qgeo=True)
    _seed_qgeo_jobs(client, github.bindings)
    _register_qgeo_bindings(client, github.bindings)
    run_id = int(github.bindings[0]["run_id"])
    github.extra_jobs_by_run[run_id] = [
        {
            "id": 59999,
            "run_id": run_id,
            "run_attempt": 1,
            "head_sha": QGEO_PR_CHECKOUT_SHA,
            "head_branch": QGEO_PR_BRANCH,
            "status": "completed",
            "conclusion": "success",
            "name": "unexpected",
            "labels": [],
        }
    ]
    response = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-reconcile",
        json={"source_sha": QGEO_SOURCE_SHA},
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 409
    assert response.json()["detail"] == "GitHub job set is not exact"


def test_qgeo_ci_registration_accepts_exact_pr_head_and_rejects_non_success(
    tmp_path: Path,
) -> None:
    github = QGeoFakeGitHub()
    client = _app(tmp_path, github=github, include_qgeo=True)
    binding = github.bindings[0]
    _seed_qgeo_jobs(client, (binding,))
    github.job_overrides[int(binding["job_id"])] = {"conclusion": "neutral"}
    neutral = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-registration",
        json=_qgeo_registration_body(binding),
        headers=OPERATOR_HEADERS,
    )
    assert neutral.status_code == 409

    github = QGeoFakeGitHub(pr_checkout_sha=QGEO_SOURCE_SHA)
    exact_head_path = tmp_path / "exact-head"
    exact_head_path.mkdir()
    client = _app(exact_head_path, github=github, include_qgeo=True)
    binding = github.bindings[0]
    _seed_qgeo_jobs(client, (binding,))
    exact_head = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-registration",
        json=_qgeo_registration_body(binding),
        headers=OPERATOR_HEADERS,
    )
    assert exact_head.status_code == 200, exact_head.text


def test_qgeo_ci_registration_rejects_foreign_pr_head_repository(tmp_path: Path) -> None:
    github = QGeoFakeGitHub()
    client = _app(tmp_path, github=github, include_qgeo=True)
    binding = github.bindings[0]
    _seed_qgeo_jobs(client, (binding,))
    github.run_overrides[int(binding["run_id"])] = {
        "pull_requests": [
            {
                "number": 63,
                "head": {
                    "sha": QGEO_SOURCE_SHA,
                    "ref": QGEO_PR_BRANCH,
                    "repo": {"full_name": "attacker/qazgeo"},
                },
                "base": {"ref": "main"},
            }
        ]
    }

    rejected = client.post(
        "/internal/v1/operations/releases/qazgeo/ci-registration",
        json=_qgeo_registration_body(binding),
        headers=OPERATOR_HEADERS,
    )
    assert rejected.status_code == 409
    assert rejected.json()["detail"] == "managed CI binding was rejected"


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
    assert (
        store.fail_if_active(
            42,
            f"worker={WORKER_NAME} exit=143 capacity override expired",
        )
        is True
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
    capacity_directive_id: str | None = None,
    concurrency: int = 1,
) -> dict[str, object]:
    worker_profiles = profiles or ["qdev-ci-docker"]
    admitted_profiles = effective_profiles if effective_profiles is not None else worker_profiles
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
                "capacity_directive_id": capacity_directive_id,
                "configured_claim_scope_id": scope_id,
                "concurrency": concurrency,
                "slots_available": max(0, concurrency - active_jobs),
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
        "schema": "qdev-controller-release-status-v2",
        "state": "active",
        "revision": "a" * 40,
        "release_digest": "sha256:" + "b" * 64,
        "activated_at": "2026-08-31T00:00:00Z",
        "runtime_identity": {
            "source_revision": "a" * 40,
            "source_digest": "sha256:" + "c" * 64,
            "public_image_id": "sha256:" + "d" * 64,
            "internal_image_id": "sha256:" + "e" * 64,
        },
        "dependency_identity": {
            "requirements_digest": "sha256:" + "f" * 64,
            "public_installed_digest": "sha256:" + "1" * 64,
            "internal_installed_digest": "sha256:" + "1" * 64,
        },
    }
    status_path.write_text(json.dumps(status), encoding="utf-8")
    client = _app(tmp_path)

    health = client.get("/health")
    assert health.status_code == 200
    assert health.json()["controller_release"] == status
    assert client.get("/health/runtime").json() == {
        "schema": "qdev-controller-runtime-health-v1",
        "state": "active",
        "revision": "a" * 40,
        "digest": "sha256:" + "b" * 64,
        "activated": "2026-08-31T00:00:00Z",
        "runtime_identity": status["runtime_identity"],
        "dependency_identity": status["dependency_identity"],
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
    # The bootstrap policy enrols the managed QGeo lane; include its test lane
    # while retaining the active controller tuple from the policy fixture.
    client = _app(tmp_path, include_qgeo=True)
    request = {
        "schema": "qdev-fleet-bootstrap-request-v2",
        "action": "restore-existing-worker",
        "source_sha": "a" * 40,
        "run_id": 123,
        "job_id": 456,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": None,
        "controller_image_digest": None,
        "activation_envelope_digest": None,
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


class _BootstrapIngressGitHub:
    """Minimal GitHub App observation used by the closed bootstrap ingress."""

    def __init__(self, *, job_attempt: int = 1) -> None:
        self.job_attempt = job_attempt
        self.calls: list[tuple[object, ...]] = []

    def repository_installation_id(self, repository: str) -> int:
        self.calls.append(("installation", repository))
        return 71

    def workflow_run(self, installation_id: int, repository: str, run_id: int) -> dict[str, Any]:
        self.calls.append(("run", installation_id, repository, run_id))
        return {
            "id": run_id,
            "run_attempt": 1,
            "repository": {"full_name": repository},
            "head_sha": "a" * 40,
            "event": "workflow_dispatch",
            "path": ".github/workflows/fleet-bootstrap.yml",
            "ref": "refs/heads/main",
            "head_branch": "main",
            "status": "in_progress",
            "conclusion": None,
        }

    def workflow_run_jobs(
        self, installation_id: int, repository: str, run_id: int, attempt: int
    ) -> list[dict[str, Any]]:
        self.calls.append(("jobs", installation_id, repository, run_id, attempt))
        return [
            {
                "id": 456,
                "run_id": run_id,
                "run_attempt": self.job_attempt,
                "head_sha": "a" * 40,
                "head_branch": "main",
                "status": "in_progress",
                "conclusion": None,
            }
        ]


class _BootstrapIngressOIDC:
    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, int]] = []

    def verify_and_decode(
        self, token: str, *, repository: str, sha: str, run_id: int
    ) -> dict[str, Any]:
        self.calls.append((token, repository, sha, run_id))
        return {
            "repository": repository,
            "ref": "refs/heads/main",
            "sha": sha,
            "run_id": run_id,
            "run_attempt": "1",
            "workflow_ref": (
                "belilovsky/qdev-runner-control-plane/.github/workflows/"
                "fleet-bootstrap.yml@refs/heads/main"
            ),
        }


def _bootstrap_ingress_body(*, key: str = "ingress-activation-001") -> dict[str, Any]:
    activation = _fleet_bootstrap_activation()
    return {
        "request": {
            "action": "activate-controller",
            "source_sha": "a" * 40,
            "run_id": 123,
            "job_id": 456,
            "attempt": 1,
            "claim_ttl_seconds": 300,
            "controller_revision": activation["controller_revision"],
            "controller_release_digest": activation["controller_release_digest"],
            "controller_image_digest": activation["controller_image_digest"],
            "activation_envelope_digest": activation["activation_envelope_digest"],
            "release_lane": None,
        },
        "idempotency_key": key,
    }


def _bootstrap_ingress_operation_key(body: dict[str, Any]) -> str:
    request = FleetBootstrapRequest.model_validate({"schema": REQUEST_SCHEMA, **body["request"]})
    return bootstrap_ingress_operation_key(
        FleetBootstrapPolicy(_FLEET_BOOTSTRAP_POLICY, _FLEET_RELEASE_LANES),
        request,
    )


def _bootstrap_ingress_spool(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    incoming = tmp_path / "fleet-host-dispatch" / "incoming"
    results = tmp_path / "fleet-host-dispatch" / "results"
    incoming.mkdir(parents=True)
    results.mkdir()
    incoming.chmod(0o700)
    results.chmod(0o750)

    def _fixture_dispatch_spool(request_root: Path, result_root: Path) -> FleetHostDispatchSpool:
        request_metadata = request_root.stat()
        result_metadata = result_root.stat()
        assert request_metadata.st_uid == result_metadata.st_uid
        assert request_metadata.st_gid == result_metadata.st_gid
        return FleetHostDispatchSpool(
            request_root,
            result_root,
            runtime_uid=request_metadata.st_uid,
            runtime_gid=request_metadata.st_gid,
            result_uid=result_metadata.st_uid,
        )

    monkeypatch.setattr("qdev_runner.broker.FleetHostDispatchSpool", _fixture_dispatch_spool)
    return incoming, results


def test_github_oidc_bootstrap_ingress_observes_exact_attempt_before_spooling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github = _BootstrapIngressGitHub()
    verifier = _BootstrapIngressOIDC()
    audiences: list[str] = []
    incoming, _ = _bootstrap_ingress_spool(tmp_path, monkeypatch)
    client = _app(
        tmp_path,
        github,
        fleet_bootstrap_oidc_verifier_factory=lambda audience: (
            audiences.append(audience) or verifier
        ),
    )

    response = client.post(
        "/internal/v1/ingress/fleet-bootstrap/activate-controller",
        json=_bootstrap_ingress_body(),
        headers={"X-QDev-GitHub-OIDC": "test-oidc-token"},
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["schema"] == "qdev-fleet-bootstrap-ingress-v1"
    execution = payload["execution"]
    assert execution["schema"] == "qdev-fleet-bootstrap-execution-receipt-v2"
    assert execution["action"] == "activate-controller"
    operation_key = _bootstrap_ingress_operation_key(_bootstrap_ingress_body())
    assert execution["idempotency_key"] == operation_key
    assert payload["correlation_id"] == "ingress-activation-001"
    assert execution["status"] == "queued"
    assert execution["operation_status"] == "pending"
    assert execution["error_code"] is None
    assert execution["release_lane"] is None
    assert execution["host_agent_mtls_identity"] is None
    assert audiences == ["qdev-fleet-bootstrap-v1"]
    assert verifier.calls == [
        (
            "test-oidc-token",
            "belilovsky/qdev-runner-control-plane",
            "a" * 40,
            123,
        )
    ]
    assert github.calls == [
        ("installation", "belilovsky/qdev-runner-control-plane"),
        ("run", 71, "belilovsky/qdev-runner-control-plane", 123),
        ("jobs", 71, "belilovsky/qdev-runner-control-plane", 123, 1),
    ]
    assert (incoming / f"{operation_key}.json").is_file()


def test_github_oidc_bootstrap_ingress_replays_only_an_identical_request(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github = _BootstrapIngressGitHub()
    verifier = _BootstrapIngressOIDC()
    incoming, _ = _bootstrap_ingress_spool(tmp_path, monkeypatch)
    client = _app(
        tmp_path,
        github,
        fleet_bootstrap_oidc_verifier_factory=lambda _audience: verifier,
    )
    path = "/internal/v1/ingress/fleet-bootstrap/activate-controller"
    headers = {"X-QDev-GitHub-OIDC": "test-oidc-token"}
    key = "ingress-replay-001"

    first = client.post(path, json=_bootstrap_ingress_body(key=key), headers=headers)
    repeated = client.post(path, json=_bootstrap_ingress_body(key=key), headers=headers)
    alternate = client.post(
        path,
        json=_bootstrap_ingress_body(key="ingress-replay-002"),
        headers=headers,
    )
    changed_body = _bootstrap_ingress_body(key="ingress-replay-drift-001")
    changed_body["request"]["controller_release_digest"] = "sha256:" + "e" * 64
    changed = client.post(path, json=changed_body, headers=headers)

    assert first.status_code == 200, first.text
    assert repeated.status_code == 200, repeated.text
    assert alternate.status_code == 200, alternate.text
    assert first.json()["execution"] == repeated.json()["execution"]
    assert first.json()["execution"] == alternate.json()["execution"]
    assert alternate.json()["correlation_id"] == "ingress-replay-002"
    assert changed.status_code == 422
    assert changed.json()["detail"] == "fleet bootstrap operation request is invalid"
    assert [path.name for path in incoming.iterdir()] == [
        f"{_bootstrap_ingress_operation_key(_bootstrap_ingress_body(key=key))}.json"
    ]


def test_github_oidc_bootstrap_ingress_rejects_missing_auth_drift_and_caller_knobs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    github = _BootstrapIngressGitHub(job_attempt=2)
    verifier = _BootstrapIngressOIDC()
    incoming, _ = _bootstrap_ingress_spool(tmp_path, monkeypatch)
    client = _app(
        tmp_path,
        github,
        fleet_bootstrap_oidc_verifier_factory=lambda _audience: verifier,
    )
    path = "/internal/v1/ingress/fleet-bootstrap/activate-controller"

    missing = client.post(path, json=_bootstrap_ingress_body())
    assert missing.status_code == 401
    assert github.calls == []
    assert not list(incoming.iterdir())

    caller_knob = _bootstrap_ingress_body(key="ingress-caller-knob-001")
    caller_knob["active_jobs"] = 0
    rejected = client.post(
        path,
        json=caller_knob,
        headers={"X-QDev-GitHub-OIDC": "token"},
    )
    assert rejected.status_code == 422
    assert not list(incoming.iterdir())

    drift = client.post(
        path,
        json=_bootstrap_ingress_body(key="ingress-attempt-drift-001"),
        headers={"X-QDev-GitHub-OIDC": "token"},
    )
    assert drift.status_code == 409
    assert drift.json()["detail"] == "fleet bootstrap GitHub identity is invalid"
    assert not list(incoming.iterdir())
    assert (
        client.post(
            "/internal/v1/ingress/fleet-bootstrap/restore-existing-worker",
            json=_bootstrap_ingress_body(key="ingress-no-recovery-001"),
            headers={"X-QDev-GitHub-OIDC": "token"},
        ).status_code
        == 404
    )


def test_activation_and_enrolment_routes_are_mtls_bound_and_fail_closed_without_bridge(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    client = _app(tmp_path)
    activation = _fleet_bootstrap_activation()
    base_request: dict[str, Any] = {
        "schema": "qdev-fleet-bootstrap-request-v2",
        "source_sha": "a" * 40,
        "run_id": 123,
        "job_id": 456,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": activation["controller_revision"],
        "controller_release_digest": activation["controller_release_digest"],
        "controller_image_digest": activation["controller_image_digest"],
        "activation_envelope_digest": activation["activation_envelope_digest"],
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

    def _fixture_dispatch_spool(request_root: Path, result_root: Path) -> FleetHostDispatchSpool:
        request_metadata = request_root.stat()
        result_metadata = result_root.stat()
        assert request_metadata.st_uid == result_metadata.st_uid
        assert request_metadata.st_gid == result_metadata.st_gid
        return FleetHostDispatchSpool(
            request_root,
            result_root,
            runtime_uid=request_metadata.st_uid,
            runtime_gid=request_metadata.st_gid,
            result_uid=result_metadata.st_uid,
        )

    monkeypatch.setattr("qdev_runner.broker.FleetHostDispatchSpool", _fixture_dispatch_spool)
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
    assert not (tmp_path / "fleet-bootstrap-receipts" / "host-enrolment-001.json").exists()

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


def test_health_does_not_count_override_bound_to_another_candidate(tmp_path: Path) -> None:
    client = _app(tmp_path)
    store: Store = client.app.state.store
    assert store.enqueue(
        QueuedJob(
            delivery_id="profile-health-bound-override",
            job_id=99,
            run_id=84000000099,
            repository="belilovsky/example",
            repository_id=1,
            installation_id=2,
            labels=("self-hosted", "Linux", "X64", "qdev-ci-docker"),
            head_sha="a" * 40,
            head_branch="main",
            payload={"workflow_job": {"run_attempt": 1}},
        )
    )
    _heartbeat(
        client,
        admitted=True,
        capacity_directive_id="operation-other-candidate",
    )
    with store.connect() as connection:
        row = connection.execute(
            "SELECT detail_json FROM workers WHERE name=?", (WORKER_NAME,)
        ).fetchone()
        assert row is not None
        detail = json.loads(row["detail_json"])
        detail["capacity_directive_repository"] = "belilovsky/other"
        detail["capacity_directive_head_sha"] = "b" * 40
        connection.execute(
            "UPDATE workers SET detail_json=? WHERE name=?",
            (json.dumps(detail), WORKER_NAME),
        )

    profile = client.get("/health").json()["profile_admission"]["qdev-ci-docker"]
    assert profile == {
        "pending": 1,
        "primary_slots_available": 0,
        "reserve_slots_available": 0,
        "admission": "no-fresh-eligible-worker",
    }


@pytest.mark.parametrize(
    "status",
    [
        {
            "schema": "qdev-controller-release-status-v1",
            "state": "active",
            "revision": "a" * 40,
            "release_digest": "b" * 64,
            "activated_at": "2026-08-31T09:00:00Z",
        },
        {
            "schema": "qdev-controller-release-status-v2",
            "state": "active",
            "generation": 2,
            "source_sha": "a" * 40,
            "image_digest": "b" * 64,
            "policy_bundle_digest": "c" * 63,
            "previous": None,
            "transaction_id": "activate-0002",
            "activated_at": "2026-08-31T09:00:00Z",
        },
        {
            "schema": "qdev-controller-release-status-v2",
            "state": "active",
            "generation": 2,
            "source_sha": "a" * 40,
            "image_digest": "b" * 64,
            "policy_bundle_digest": "c" * 64,
            "previous": None,
            "transaction_id": "activate-0002",
            "activated_at": "2026-08-31T09:00:00Z",
            "forged": True,
        },
    ],
)
def test_controller_release_status_rejects_unverifiable_values(
    tmp_path: Path, status: dict[str, object]
) -> None:
    status_path = tmp_path / "controller-release.json"
    status_path.write_text(json.dumps(status), encoding="utf-8")
    client = _app(tmp_path)

    assert client.get("/health").json()["controller_release"] == {
        "schema": "qdev-controller-release-status-v2",
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


def test_durable_queue_audit_omits_superseded_managed_production_head(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path, include_qgeo=True)
    _seed_pending_job(
        client,
        41,
        "superseded-managed-production-row",
        repository="belilovsky/qazgeo",
        head_sha="5dff352e7ddfbb7e4a8c94643d87f7c24cfaf6ea",
    )
    _seed_pending_job(client, 42, "first-admissible-row")

    response = client.get(
        "/internal/v1/operations/jobs/pending",
        headers=OPERATOR_HEADERS,
    )

    assert response.status_code == 200
    payload = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["pending"] == 2
    assert payload["unclassified"] == []
    assert len(payload["profile_heads"]) == 1
    assert payload["profile_heads"][0]["job_id"] == 42
    assert payload["profile_heads"][0]["repository"] == "belilovsky/example"


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
    github = FakeGitHub()
    client = _app(tmp_path, github)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary", disk_free_gib=50.0)
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
    assert claimed.json()["runner_name"] == "qdev-example-42-a1"
    assert github.jit_runner_names == ["qdev-example-42-a1"]
    assert client.app.state.store.job_status(41) == "pending"


def test_v2_claim_rejects_stale_empty_heartbeat_without_issuing_jit(tmp_path: Path) -> None:
    github = FakeGitHub()
    client = _app(tmp_path, github)
    scope_id = "srv1879763-primary"
    _heartbeat(client, admitted=True, scope_id=scope_id)
    _seed_pending_job(client, 42, "delivery-42")
    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json={
            "job_id": 42,
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "scope_id": scope_id,
            "host": "srv1879763-light-primary",
            "runner": "qdev-ci-docker",
            "worker_certificate_sha256": "c" * 64,
            "correlation_id": "stale-heartbeat-regression",
            "duration_seconds": 900,
        },
    )
    assert issued.status_code == 200
    store: Store = client.app.state.store
    with store.connect() as connection:
        connection.execute(
            "UPDATE workers SET last_seen=?, detail_json=? WHERE name=?",
            (time.time() - 120, "{}", WORKER_NAME),
        )

    claimed = client.post(
        "/internal/v1/jobs/claim",
        headers={"X-QDev-Client-Certificate-SHA256": "c" * 64},
        json={
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "profiles": ["qdev-ci-docker"],
            "claim_scope_id": scope_id,
            "disk_free_gib": 200.0,
            "min_disk_free_gib": 0.0,
        },
    )

    assert claimed.status_code == 204
    assert store.job_status(42) == "pending"


def test_v2_claim_uses_heartbeat_capacity_not_claim_assertions(tmp_path: Path) -> None:
    client = _app(tmp_path, FakeGitHub())
    scope_id = "srv1879763-primary"
    _heartbeat(client, admitted=True, scope_id=scope_id, disk_free_gib=30.0)
    _seed_pending_job(client, 42, "delivery-42")
    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json={
            "job_id": 42,
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "scope_id": scope_id,
            "host": "srv1879763-light-primary",
            "runner": "qdev-ci-docker",
            "worker_certificate_sha256": "c" * 64,
            "correlation_id": "heartbeat-capacity-regression",
            "duration_seconds": 900,
        },
    )
    assert issued.status_code == 200

    claimed = client.post(
        "/internal/v1/jobs/claim",
        headers={"X-QDev-Client-Certificate-SHA256": "c" * 64},
        json={
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "profiles": ["qdev-ci-docker"],
            "claim_scope_id": scope_id,
            "disk_free_gib": 200.0,
            "min_disk_free_gib": 0.0,
        },
    )

    assert claimed.status_code == 204
    assert client.app.state.store.job_status(42) == "pending"


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


def test_fifo_skips_superseded_managed_production_rows_with_signed_evidence(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path, FakeGitHub(), include_qgeo=True)
    _heartbeat(
        client,
        admitted=True,
        disk_free_gib=46.0,
        scope_id="srv1879763-primary",
    )
    stale_sha = "5dff352e7ddfbb7e4a8c94643d87f7c24cfaf6ea"
    _seed_pending_job(
        client,
        41,
        "superseded-managed-production-row",
        repository="belilovsky/qazgeo",
        head_sha=stale_sha,
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
        "correlation_id": "fifo-head-after-superseded-managed-row",
        "duration_seconds": 900,
    }

    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json=request,
    )

    assert issued.status_code == 200
    payload = verify_controller_receipt(issued.json(), receipt_key=RECEIPT_KEY)["payload"]
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
            "reason": "managed-production-candidate-not-active",
        }
    ]

    claimed = client.post(
        "/internal/v1/jobs/claim",
        headers={"X-QDev-Client-Certificate-SHA256": "c" * 64},
        json={
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "profiles": ["qdev-ci-docker"],
            "claim_scope_id": "srv1879763-primary",
            "disk_free_gib": 46.0,
            "min_disk_free_gib": 4.5,
        },
    )
    assert claimed.status_code == 200
    assert claimed.json()["job_id"] == 42
    assert client.app.state.store.job_status(41) == "pending"


def test_direct_claim_of_superseded_managed_production_row_remains_fail_closed(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path, include_qgeo=True)
    _heartbeat(
        client,
        admitted=True,
        disk_free_gib=60.0,
        scope_id="srv1879763-primary",
    )
    _seed_pending_job(
        client,
        41,
        "superseded-managed-production-row",
        repository="belilovsky/qazgeo",
        head_sha="5dff352e7ddfbb7e4a8c94643d87f7c24cfaf6ea",
    )
    request = {
        "job_id": 41,
        "worker_name": WORKER_NAME,
        "tier": "primary",
        "scope_id": "srv1879763-primary",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "c" * 64,
        "correlation_id": "superseded-managed-row-direct",
        "duration_seconds": 900,
    }

    response = client.post(
        "/internal/v1/operations/jobs/41/claim-scope",
        headers=OPERATOR_HEADERS,
        json=request,
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "managed production candidate is not open"


def test_managed_production_unknown_run_is_fail_closed_but_does_not_block_fifo(
    tmp_path: Path,
) -> None:
    exact_sha = "9" * 40
    ledger_path = _managed_release_ledger(
        tmp_path,
        source_sha=exact_sha,
        run_id=84000000999,
    )
    client = _app(
        tmp_path,
        FakeGitHub(),
        include_qgeo=True,
        managed_release_ledger_path=ledger_path,
    )
    _heartbeat(
        client,
        admitted=True,
        disk_free_gib=60.0,
        scope_id="srv1879763-primary",
    )
    _seed_pending_job(
        client,
        41,
        "unlisted-managed-production-run",
        repository="belilovsky/qazgeo",
        head_sha=exact_sha,
    )
    _seed_pending_job(client, 42, "first-admissible-row")

    direct = client.post(
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
            "correlation_id": "unlisted-managed-run-direct",
            "duration_seconds": 900,
        },
    )
    assert direct.status_code == 409
    assert direct.json()["detail"] == "managed production provider binding is not admitted"

    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json={
            "job_id": 42,
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "scope_id": "srv1879763-primary",
            "host": "srv1879763-light-primary",
            "runner": "qdev-ci-docker",
            "worker_certificate_sha256": "c" * 64,
            "correlation_id": "fifo-after-unlisted-managed-run",
            "duration_seconds": 900,
        },
    )
    assert issued.status_code == 200
    payload = verify_controller_receipt(issued.json(), receipt_key=RECEIPT_KEY)["payload"]
    assert payload["fifo_skipped"] == [
        {
            "job_id": 41,
            "repository": "belilovsky/qazgeo",
            "run_id": 84000000041,
            "attempt": 1,
            "head_sha": exact_sha,
            "profile": "qdev-ci-docker",
            "managed_registry_entry": "qazgeo",
            "reason": "managed-production-candidate-tuple-not-admitted",
        }
    ]

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


def test_managed_production_fifo_skip_is_rechecked_when_ledger_reactivates(
    tmp_path: Path,
) -> None:
    active_sha = "9" * 40
    stale_sha = "8" * 40
    ledger_path = _managed_release_ledger(
        tmp_path,
        source_sha=stale_sha,
        run_id=84000000041,
    )
    client = _app(tmp_path, managed_release_ledger_path=ledger_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(
        client,
        41,
        "temporarily-stale-managed-row",
        repository="belilovsky/qazgeo",
        head_sha=active_sha,
    )
    _seed_pending_job(client, 42, "first-admissible-row")

    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json={
            "job_id": 42,
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "scope_id": "srv1879763-primary",
            "host": "srv1879763-light-primary",
            "runner": "qdev-ci-docker",
            "worker_certificate_sha256": "c" * 64,
            "correlation_id": "fifo-before-managed-reactivation",
            "duration_seconds": 900,
        },
    )
    assert issued.status_code == 200

    _managed_release_ledger(
        tmp_path,
        source_sha=active_sha,
        run_id=84000000041,
    )
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
    assert claimed.status_code == 204
    assert client.app.state.store.job_status(41) == "pending"
    assert client.app.state.store.job_status(42) == "pending"


def test_managed_production_fifo_skip_is_rechecked_inside_claim_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    active_sha = "9" * 40
    stale_sha = "8" * 40
    ledger_path = _managed_release_ledger(
        tmp_path,
        source_sha=stale_sha,
        run_id=84000000041,
    )
    client = _app(tmp_path, managed_release_ledger_path=ledger_path)
    _heartbeat(client, admitted=True, scope_id="srv1879763-primary")
    _seed_pending_job(
        client,
        41,
        "managed-row-reactivated-at-claim-boundary",
        repository="belilovsky/qazgeo",
        head_sha=active_sha,
    )
    _seed_pending_job(client, 42, "later-admissible-row")

    issued = client.post(
        "/internal/v1/operations/jobs/42/claim-scope",
        headers=OPERATOR_HEADERS,
        json={
            "job_id": 42,
            "worker_name": WORKER_NAME,
            "tier": "primary",
            "scope_id": "srv1879763-primary",
            "host": "srv1879763-light-primary",
            "runner": "qdev-ci-docker",
            "worker_certificate_sha256": "c" * 64,
            "correlation_id": "fifo-race-at-durable-claim",
            "duration_seconds": 900,
        },
    )
    assert issued.status_code == 200

    store: Store = client.app.state.store
    original_claim = store.claim

    def reactivate_then_claim(*args: Any, **kwargs: Any) -> dict[str, Any] | None:
        _managed_release_ledger(
            tmp_path,
            source_sha=active_sha,
            run_id=84000000041,
        )
        return original_claim(*args, **kwargs)

    monkeypatch.setattr(store, "claim", reactivate_then_claim)
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

    assert claimed.status_code == 204
    assert store.job_status(41) == "pending"
    assert store.job_status(42) == "pending"


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
        # The signed directive below lowers the baseline 30 GiB floor to
        # 4.5 GiB. With a 20 GiB profile reservation, this exact scoped claim
        # is admissible at 25 GiB and would be rejected if Store.claim()
        # accidentally reapplied the heartbeat's baseline floor.
        disk_free_gib=25.0,
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
        disk_free_gib=100.0,
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
        json=base_request | {"job_id": 42, "correlation_id": "cross-profile-rollover"},
    )
    assert issued.status_code == 200
    client.app.state.store.set_status(42, "completed", "success")
    rollover = client.post(
        "/internal/v1/operations/jobs/43/claim-scope",
        headers=OPERATOR_HEADERS,
        json=base_request | {"job_id": 43, "correlation_id": "cross-profile-rollover"},
    )
    assert rollover.status_code == 200, rollover.text

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
    _heartbeat(
        client,
        admitted=True,
        disk_free_gib=100.0,
        scope_id="srv1879763-primary",
        profiles=profiles,
        effective_profiles=["qdev-ci-browser"],
        capacity_directive_id=operation.operation_id,
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


def test_managed_qgeo_scope_prunes_terminal_profile_tuple_on_reuse(tmp_path: Path) -> None:
    github = QGeoFakeGitHub()
    github.run_status = "queued"
    github.run_conclusion = None
    github.job_status = "queued"
    github.job_conclusion = None
    client = _app(tmp_path, github=github, include_qgeo=True)
    store: Store = client.app.state.store
    _seed_qgeo_jobs(client, github.bindings)
    _register_qgeo_bindings(client, github.bindings)
    first_binding = next(binding for binding in github.bindings if binding["profile"] == "qdev-ci")
    second_binding = next(
        binding for binding in github.bindings if binding["profile"] == "qdev-ci-docker"
    )
    first_job_id = int(first_binding["job_id"])
    second_job_id = int(second_binding["job_id"])
    scope_id = "qgeo-release-scope-20260904"
    request = {
        "job_id": first_job_id,
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
        disk_free_gib=40,
        scope_id=scope_id,
        profiles=["qdev-ci", "qdev-ci-docker"],
        effective_profiles=["qdev-ci"],
    )
    headers = OPERATOR_HEADERS
    first = client.post(
        f"/internal/v1/operations/jobs/{first_job_id}/claim-scope",
        headers=headers,
        json=request,
    )
    assert first.status_code == 200, first.text
    store.set_status(first_job_id, "completed", "success")

    _heartbeat(
        client,
        admitted=True,
        disk_free_gib=40,
        scope_id=scope_id,
        profiles=["qdev-ci", "qdev-ci-docker"],
        effective_profiles=["qdev-ci-docker"],
    )
    second_request = request | {
        "job_id": second_job_id,
    }
    rollover = client.post(
        f"/internal/v1/operations/jobs/{second_job_id}/claim-scope",
        headers=headers,
        json=second_request,
    )
    assert rollover.status_code == 200
    rollover_payload = verify_controller_receipt(rollover.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert rollover_payload["rolled_over_terminal_scope"] is True
    assert [item["job_id"] for item in rollover_payload["claim_scope"]["jobs"]] == [
        first_job_id,
        second_job_id,
    ]

    repaired = client.post(
        f"/internal/v1/operations/jobs/{second_job_id}/claim-scope",
        headers=headers,
        json=second_request,
    )
    assert repaired.status_code == 200
    repaired_payload = verify_controller_receipt(repaired.json(), receipt_key=RECEIPT_KEY)[
        "payload"
    ]
    assert repaired_payload["idempotent"] is False
    assert repaired_payload["repaired_managed_scope"] is True
    assert [item["job_id"] for item in repaired_payload["claim_scope"]["jobs"]] == [second_job_id]

    repeated = client.post(
        f"/internal/v1/operations/jobs/{second_job_id}/claim-scope",
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


@pytest.mark.parametrize(
    ("disk_free_gib", "concurrency", "message"),
    [
        (34.999, 1, "repository admission requires at least 35 GiB free disk"),
        (40.0, 2, "repository admission requires worker concurrency at most 1"),
    ],
)
def test_qazgeo_capacity_override_cannot_weaken_repository_constraints(
    tmp_path: Path,
    disk_free_gib: float,
    concurrency: int,
    message: str,
) -> None:
    github = QGeoFakeGitHub()
    github.run_status = "queued"
    github.run_conclusion = None
    github.job_status = "queued"
    github.job_conclusion = None
    client = _app(tmp_path, github=github, include_qgeo=True)
    _heartbeat(client, disk_free_gib=disk_free_gib, concurrency=concurrency)
    binding = next(item for item in github.bindings if item["profile"] == "qdev-ci-docker")
    _seed_qgeo_jobs(client, (binding,))
    _register_qgeo_bindings(client, (binding,))

    response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qazgeo",
            "head_sha": QGEO_PR_CHECKOUT_SHA,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 95.0,
            "duration_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "must preserve the QGeo absolute admission floor",
        },
    )

    assert response.status_code == 409
    assert message in response.json()["detail"]
    assert (
        client.app.state.operations.active(
            WORKER_NAME,
            registered_profiles=("qdev-ci", "qdev-ci-docker"),
        )
        is None
    )


def test_qazgeo_capacity_override_accepts_exact_server_owned_boundary(tmp_path: Path) -> None:
    github = QGeoFakeGitHub()
    github.run_status = "queued"
    github.run_conclusion = None
    github.job_status = "queued"
    github.job_conclusion = None
    client = _app(tmp_path, github=github, include_qgeo=True)
    _heartbeat(client, disk_free_gib=35.0, concurrency=1)
    binding = next(item for item in github.bindings if item["profile"] == "qdev-ci-docker")
    _seed_qgeo_jobs(client, (binding,))
    _register_qgeo_bindings(client, (binding,))

    response = client.post(
        f"/internal/v1/operations/workers/{WORKER_NAME}/capacity-override",
        headers=OPERATOR_HEADERS,
        json={
            "repository": "belilovsky/qazgeo",
            "head_sha": QGEO_PR_CHECKOUT_SHA,
            "profiles": ["qdev-ci-docker"],
            "min_disk_free_gib": 4.5,
            "max_disk_used_pct": 95.0,
            "duration_seconds": 300,
            "owner": "portfolio-ci",
            "reason": "exact QGeo admission boundary regression",
        },
    )

    assert response.status_code == 200
    receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
    operation = receipt["payload"]["operation"]
    assert operation["repository"] == "belilovsky/qazgeo"
    assert operation["min_disk_free_gib"] == 4.5


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


def test_capacity_override_skips_superseded_managed_production_fifo_rows(
    tmp_path: Path,
) -> None:
    client = _app(tmp_path, include_qgeo=True)
    _heartbeat(client)
    stale_sha = "5dff352e7ddfbb7e4a8c94643d87f7c24cfaf6ea"
    _seed_pending_job(
        client,
        41,
        "superseded-managed-production-row",
        repository="belilovsky/qazgeo",
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
            "reason": "admissible head after superseded managed-production row",
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
            "reason": "managed-production-candidate-not-active",
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
    assert response.json()["detail"] == ("capacity override target is not the durable FIFO head")
    assert (
        client.app.state.operations.active(
            WORKER_NAME,
            registered_profiles=("qdev-ci", "qdev-ci-docker"),
        )
        is None
    )


@pytest.mark.parametrize(
    ("status", "conclusion", "sha", "attempt", "expected"),
    [
        ("completed", "cancelled", "a" * 40, 1, 200),
        ("queued", None, "a" * 40, 1, 409),
        ("in_progress", None, "a" * 40, 1, 409),
        ("completed", None, "a" * 40, 1, 409),
        ("completed", "cancelled", "b" * 40, 1, 409),
        ("completed", "cancelled", "a" * 40, 2, 409),
    ],
)
def test_pending_terminal_reconciliation(
    tmp_path: Path, status: str, conclusion: str | None, sha: str, attempt: int, expected: int
) -> None:
    client = _app(
        tmp_path,
        FakeGitHub(job_status=status, job_conclusion=conclusion, head_sha=sha, run_attempt=attempt),
    )
    created_at = _seed_stale_running_job(client)
    store = client.app.state.store
    store.set_status(42, "pending")
    response = client.post(
        "/internal/v1/operations/jobs/42/recover-stale",
        headers=OPERATOR_HEADERS,
        json={
            "owner": "portfolio-ci",
            "reason": "reconcile terminal provider state",
            "pending_terminal_only": True,
        },
    )
    assert response.status_code == expected
    assert store.job_status(42) == ("completed" if expected == 200 else "pending")
    assert float(store.job(42)["created_at"]) == created_at
    if expected == 200:
        receipt = verify_controller_receipt(response.json(), receipt_key=RECEIPT_KEY)
        assert receipt["payload"]["action"] == "pending-completed-from-provider"
        assert store.job(42)["result"] == "cancelled"
    store.set_status(42, "running")
    assert not store.complete_pending_from_provider(42, "cancelled")
    assert store.job_status(42) == "running"


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
    assert response.json()["detail"] == ("provider immutable tuple does not match the failed job")
    assert client.app.state.store.job_status(42) == "failed"
