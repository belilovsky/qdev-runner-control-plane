from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi.testclient import TestClient

from qdev_runner.broker import create_app
from qdev_runner.policy import Policy
from qdev_runner.settings import BrokerSettings
from qdev_runner.store import Store


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


def test_compose_assigns_disjoint_broker_surfaces() -> None:
    compose = (Path(__file__).parents[1] / "deploy" / "compose.yml").read_text(
        encoding="utf-8"
    )
    public = compose.split("  broker-public:", 1)[1].split("  broker-internal:", 1)[0]
    internal = compose.split("  broker-internal:", 1)[1].split("  registry:", 1)[0]

    assert "QDEV_BROKER_SURFACE: public" in public
    assert "QDEV_BROKER_SURFACE: internal" in internal
    assert 'QDEV_OPERATOR_TOKEN: ""' in public
    assert 'QDEV_WORKER_TOKEN: ""' in public
    assert "QDEV_RELEASE_HOST_DISPATCH_KEYS_FILE: /nonexistent/" in public
    assert "QDEV_CLAIM_SCOPES: /nonexistent/" in public
    assert "control-state/claim-scopes.json" not in public
    assert 'QDEV_GITHUB_WEBHOOK_SECRET: ""' in internal
    assert "QDEV_CLAIM_SCOPES: /var/lib/qdev-runner/control-state/claim-scopes.json" in internal


def test_public_broker_reads_only_non_secret_controller_release_projection() -> None:
    compose = (Path(__file__).parents[1] / "deploy" / "compose.yml").read_text(
        encoding="utf-8"
    )
    public = compose.split("  broker-public:", 1)[1].split("  broker-internal:", 1)[0]

    assert (
        "QDEV_CONTROLLER_RELEASE_STATUS: "
        "/var/lib/qdev-runner/controller-status/controller-release.json"
    ) in public
    assert (
        "- /var/lib/qdev-runner/controller-status:"
        "/var/lib/qdev-runner/controller-status:ro"
    ) in public
    assert "/var/lib/qdev-runner/operations" not in public
    assert "/var/lib/qdev-runner/release-jobs" not in public
    assert "/var/lib/qdev-runner/admin-platform-receipts" not in public
