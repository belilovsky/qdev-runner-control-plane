from __future__ import annotations

import hashlib
import hmac
from pathlib import Path

from qdev_runner.broker import (
    artifact_job_is_active,
    artifact_token,
    completed_run_conclusion,
    registry_credentials,
    verify_signature,
)
from qdev_runner.settings import BrokerSettings


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
        "username": "qdev",
        "password": "registry-token",
    }


def test_completed_parent_run_is_terminal_even_when_job_api_stays_queued() -> None:
    assert completed_run_conclusion({"status": "completed", "conclusion": "cancelled"}) == (
        "cancelled"
    )
    assert completed_run_conclusion({"status": "completed", "conclusion": None}) == "unknown"
    assert completed_run_conclusion({"status": "in_progress", "conclusion": None}) is None
