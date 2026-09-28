from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fastapi.testclient import TestClient

from qdev_runner.broker import (
    artifact_token,
    create_app,
    eligible_slot_health,
    oldest_pending_age_seconds,
)
from qdev_runner.controller_activation import (
    ControllerReleaseStatus,
    ControllerTuple,
    write_public_activation_projection,
)
from qdev_runner.models import QueuedJob
from qdev_runner.policy import Policy
from qdev_runner.settings import BrokerSettings
from qdev_runner.store import Store


def _activation_ledger() -> dict[str, object]:
    return ControllerReleaseStatus(
        generation=12,
        current=ControllerTuple("a" * 40, "b" * 64, "b" * 64),
        previous=(11, ControllerTuple("c" * 40, "d" * 64, "d" * 64)),
        transaction_id="controller-eb9eea64-34515000659-r1",
        activated_at=datetime(2026, 9, 10, 18, 43, 22, tzinfo=UTC),
    ).mapping()


def _settings(
    tmp_path: Path,
    inventory: Path,
    profiles: Path,
    *,
    surface: Literal["public", "internal"],
) -> BrokerSettings:
    return BrokerSettings(
        app_id="1",
        app_private_key_path=tmp_path / "app.pem",
        webhook_secret="webhook",
        worker_token="worker",
        inventory_path=inventory,
        profiles_path=profiles,
        database_path=tmp_path / f"{surface}.db",
        artifact_root=tmp_path / f"{surface}-artifacts",
        surface=surface,
        artifact_token_key="artifact-key",
        operator_token="operator-token",
        operator_receipt_key="receipt-key",
        operator_directive_key="directive-key",
        operations_root=tmp_path / f"{surface}-operations",
    )


def test_public_surface_hides_internal_handlers_even_with_forged_identity(
    tmp_path: Path,
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    settings = _settings(tmp_path, inventory, profiles, surface="public")
    app = create_app(
        settings,
        store=Store(settings.database_path),
        policy=Policy(inventory, profiles),
        github=object(),
    )

    with TestClient(app) as client:
        health = client.get("/health")
        forged = client.get(
            "/internal/v1/operations/controller-release",
            headers={
                "X-QDev-Operator-Token": "operator-token",
                "X-QDev-Operator-mTLS-Identity": "qdev-fleet-operations",
            },
        )

    assert health.status_code == 200
    assert forged.status_code == 404
    assert forged.content == b""


def test_internal_surface_rejects_public_webhook_route(
    tmp_path: Path,
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    settings = _settings(tmp_path, inventory, profiles, surface="internal")
    app = create_app(
        settings,
        store=Store(settings.database_path),
        policy=Policy(inventory, profiles),
        github=object(),
    )

    with TestClient(app) as client:
        response = client.post("/github/workflow-job", content=b"{}")

    assert response.status_code == 404


def test_public_artifact_surface_only_queues_qantar_candidate_intent(
    tmp_path: Path,
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    settings = _settings(tmp_path, inventory, profiles, surface="public")
    store = Store(settings.database_path)
    source_sha = "a" * 40
    job_id = 700
    job = QueuedJob(
        delivery_id="qantar-release-delivery",
        job_id=job_id,
        run_id=600,
        repository="belilovsky/qantar",
        repository_id=1,
        installation_id=300,
        labels=("self-hosted", "Linux", "X64", "qdev-ci", "qdev-job-600-2-release"),
        head_sha=source_sha,
        head_branch="main",
        payload={
            "workflow_job": {
                "id": job_id,
                "run_id": 600,
                "run_attempt": 2,
                "name": "release",
                "path": ".github/workflows/ci.yml@refs/heads/main",
                "head_sha": source_sha,
                "head_branch": "main",
            }
        },
    )
    store.enqueue(job)
    store.set_status(job_id, "running")
    with store.connect() as connection:
        connection.execute("UPDATE jobs SET profile='qdev-ci' WHERE job_id=?", (job_id,))
    app = create_app(settings, store=store, policy=Policy(inventory, profiles), github=object())
    digest = "sha256:" + "b" * 64
    headers = {
        "X-QDev-Artifact-Token": artifact_token(
            "artifact-key", "belilovsky/qantar", source_sha, job_id
        )
    }

    with TestClient(app) as client:
        response = client.post(
            "/artifacts/releases/qantar",
            headers=headers,
            json={
                "schema": "qdev-qantar-ci-release-v1",
                "job_id": job_id,
                "source_sha": source_sha,
                "artifact_digest": digest,
                "artifact_ref": f"registry.ci.qdev.run/qantar@{digest}",
                "expanded_release_bytes": 2_000_000,
                "bundle_payload_bytes": 3_000_000,
                "bundle_image_size_bytes": 4_000_000,
                "application_image_size_bytes": 5_000_000,
            },
        )
        status = client.get(f"/artifacts/releases/qantar/{job_id}", headers=headers)

    assert response.status_code == 202
    assert response.json()["status"] == "queued"
    assert status.status_code == 200
    assert status.json()["status"] == "queued"
    assert store.pending_qantar_release_intents()[0]["artifact_digest"] == digest


def test_compose_assigns_disjoint_broker_surfaces() -> None:
    compose = (Path(__file__).parents[1] / "deploy" / "compose.yml").read_text(encoding="utf-8")
    public = compose.split("  broker-public:", 1)[1].split("  broker-internal:", 1)[0]
    internal = compose.split("  broker-internal:", 1)[1].split("  registry:", 1)[0]

    assert "QDEV_BROKER_SURFACE: public" in public
    assert "QDEV_BROKER_SURFACE: internal" in internal
    assert 'QDEV_OPERATOR_TOKEN: ""' in public
    assert 'QDEV_WORKER_TOKEN: ""' in public
    assert "QDEV_RELEASE_HOST_DISPATCH_KEYS_FILE: /nonexistent/" in public
    assert (
        "QDEV_CONTROLLER_RELEASE_STATUS: /var/lib/qdev-runner/controller-status/"
        "controller-release.json" in public
    )
    assert (
        "/var/lib/qdev-runner/controller-status:/var/lib/qdev-runner/controller-status:ro" in public
    )
    assert "QDEV_CLAIM_SCOPES: /nonexistent/" in public
    assert "control-state/claim-scopes.json" not in public
    assert (
        "QDEV_CONTROLLER_RELEASE_STATUS: "
        "/var/lib/qdev-runner/controller-status/controller-release.json"
    ) in public
    assert (
        "/var/lib/qdev-runner/controller-status:/var/lib/qdev-runner/controller-status:ro"
    ) in public
    assert 'QDEV_OPERATOR_PROXY_SECRET: ""' in public
    assert 'QDEV_RECOVERY_AGENT_SIGNING_KEY: ""' in public
    assert 'QDEV_GITHUB_WEBHOOK_SECRET: ""' in internal
    assert "/etc/qdev-runner/recovery-controller.env" in internal
    assert "path: /etc/qdev-runner/recovery-controller.env" in internal
    assert "required: false" in internal
    assert "/etc/qdev-runner/recovery-controller.env" not in public
    assert "QDEV_CLAIM_SCOPES: /var/lib/qdev-runner/control-state/claim-scopes.json" in internal


def test_public_health_reads_only_the_sanitized_activation_projection(
    tmp_path: Path,
    policy_files: tuple[Path, Path],
) -> None:
    inventory, profiles = policy_files
    raw = tmp_path / "activation-status.json"
    raw.write_text(
        json.dumps(_activation_ledger(), sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    projection = tmp_path / "controller-activation.json"

    def health(settings: BrokerSettings) -> dict:
        app = create_app(
            settings,
            store=Store(settings.database_path),
            policy=Policy(inventory, profiles),
            github=object(),
        )
        with TestClient(app) as client:
            return client.get("/health").json()

    public = replace(
        _settings(tmp_path, inventory, profiles, surface="public"),
        controller_activation_status_path=raw,
        controller_activation_projection_path=projection,
    )

    # Without the aggregate the public surface degrades to unavailable and
    # never falls back to the private ledger it cannot legitimately read.
    empty = health(public)
    assert empty["controller_activation"] == {
        "schema": "qdev-controller-activation-status-v2",
        "state": "unavailable",
    }
    # Additive capacity aggregates stay identity-free and are present on an
    # idle queue, so an operator can distinguish "no eligible slot" from
    # "capacity exists but the required profile cannot be claimed".
    assert empty["eligible_slots"] == {"primary": 0, "reserve": 0, "total": 0}
    assert empty["oldest_pending_age_seconds"] is None

    write_public_activation_projection(raw, projection)
    body = health(public)["controller_activation"]
    assert body["schema"] == "qdev-controller-activation-projection-v1"
    assert body["state"] == "active"
    assert body["source_revision"] == "a" * 40
    assert "transaction_id" not in body
    assert "previous" not in body
    assert "policy_bundle_digest" not in body

    # The internal surface keeps the raw CAS ledger for its mTLS audit.
    internal = replace(
        _settings(tmp_path, inventory, profiles, surface="internal"),
        controller_activation_status_path=raw,
        controller_activation_projection_path=projection,
    )
    internal_body = health(internal)["controller_activation"]
    assert internal_body["schema"] == "qdev-controller-activation-status-v2"
    assert internal_body["transaction_id"] == "controller-eb9eea64-34515000659-r1"


def test_eligible_slot_health_ignores_ineligible_and_unknown_tiers() -> None:
    workers = [
        {"tier": "primary", "capacity_allowed": True, "slots_available": 2},
        {"tier": "primary", "capacity_allowed": False, "slots_available": 5},
        {"tier": "reserve", "capacity_allowed": True, "slots_available": 1},
        {"tier": "unknown", "capacity_allowed": True, "slots_available": 9},
    ]

    assert eligible_slot_health(workers) == {"primary": 2, "reserve": 1, "total": 3}


def test_oldest_pending_age_reports_only_a_duration() -> None:
    assert oldest_pending_age_seconds([], now=1_000.0) is None
    assert (
        oldest_pending_age_seconds([{"created_at": 900.0}, {"created_at": 940.5}], now=1_000.0)
        == 100
    )
    # A malformed durable row must not fabricate a breach.
    assert oldest_pending_age_seconds([{"created_at": "not-a-time"}], now=1_000.0) is None
