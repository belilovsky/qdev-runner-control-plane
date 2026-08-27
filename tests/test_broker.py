from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

from fastapi.testclient import TestClient

from qdev_runner.broker import (
    artifact_job_is_active,
    artifact_token,
    completed_run_conclusion,
    create_app,
    registry_credentials,
    verify_signature,
)
from qdev_runner.settings import BrokerSettings
from qdev_runner.store import Store


def test_webhook_signature() -> None:
    body = b'{"action":"queued"}'
    signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert verify_signature("secret", body, signature)
    assert not verify_signature("secret", body + b"x", signature)
    assert not verify_signature("secret", body, None)


def test_artifact_token_is_scoped() -> None:
    token = artifact_token("secret", "belilovsky/repo", "abc", 1)
    assert token == artifact_token("secret", "belilovsky/repo", "abc", 1)
    assert token != artifact_token("secret", "belilovsky/repo", "abc", 2)


def test_artifact_credentials_expire_with_job() -> None:
    job = {
        "job_id": 1,
        "repository": "belilovsky/repo",
        "head_sha": "abc",
        "status": "running",
    }
    assert artifact_job_is_active(job, "belilovsky/repo", "abc", 1)
    job["status"] = "completed"
    assert not artifact_job_is_active(job, "belilovsky/repo", "abc", 1)
    assert not artifact_job_is_active(job, "belilovsky/other", "abc", 1)
    assert not artifact_job_is_active(None, "belilovsky/repo", "abc", 1)


def test_registry_credentials_are_limited_to_docker_profile() -> None:
    settings = BrokerSettings(
        app_id="1",
        app_private_key_path=Path("app.pem"),
        webhook_secret="webhook",
        worker_token="worker",
        inventory_path=Path("repos.json"),
        profiles_path=Path("profiles.yml"),
        database_path=Path("broker.db"),
        artifact_root=Path("artifacts"),
        registry_password="registry-token",
    )

    assert registry_credentials(settings, "qdev-ci") is None
    assert registry_credentials(settings, "qdev-ci-browser") is None
    assert registry_credentials(settings, "qdev-ci-docker") == {
        "url": "registry.ci.qdev.run",
        "username": "qdev-runner",
        "password": "registry-token",
    }


def test_completed_parent_run_is_terminal_even_when_job_api_stays_queued() -> None:
    assert completed_run_conclusion({"status": "completed", "conclusion": "cancelled"}) == (
        "cancelled"
    )
    assert completed_run_conclusion({"status": "completed", "conclusion": None}) == "unknown"
    assert completed_run_conclusion({"status": "in_progress", "conclusion": None}) is None


def test_queued_webhook_persists_derived_profile_once(tmp_path: Path) -> None:
    root = Path(__file__).resolve().parents[1]
    settings = BrokerSettings(
        app_id="1",
        app_private_key_path=tmp_path / "app.pem",
        webhook_secret="webhook",
        worker_token="worker",
        inventory_path=root / "inventory" / "repos.json",
        profiles_path=root / "config" / "profiles.yml",
        project_priority_path=root / "config" / "project-priority.json",
        database_path=tmp_path / "broker.db",
        artifact_root=tmp_path / "artifacts",
    )
    store = Store(settings.database_path)
    app = create_app(settings, store=store)
    payload = {
        "action": "queued",
        "installation": {"id": 1},
        "repository": {"id": 1206670519, "full_name": "belilovsky/qazcompute"},
        "workflow_job": {
            "id": 42,
            "run_id": 24,
            "labels": ["self-hosted", "Linux", "X64", "qdev-ci"],
            "head_sha": "a" * 40,
            "head_branch": "main",
        },
    }
    body = json.dumps(payload).encode()
    signature = "sha256=" + hmac.new(b"webhook", body, hashlib.sha256).hexdigest()

    response = TestClient(app).post(
        "/github/workflow-job",
        content=body,
        headers={
            "X-Hub-Signature-256": signature,
            "X-GitHub-Delivery": "delivery-42",
            "X-GitHub-Event": "workflow_job",
        },
    )

    assert response.status_code == 202
    assert store.job_status(42) == "pending"
    with store.connect() as connection:
        row = connection.execute("SELECT required_profile FROM jobs WHERE job_id=42").fetchone()
    assert row["required_profile"] == "qdev-ci"
