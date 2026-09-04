from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

from qdev_runner.broker import (
    artifact_job_is_active,
    artifact_token,
    completed_run_conclusion,
    create_app,
    registry_credentials,
    verify_signature,
)
from qdev_runner.models import QueuedJob
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


class FakeGitHub:
    def __init__(self, sha: str) -> None:
        self.sha = sha
        self.rerun_calls: list[tuple[int, str, int]] = []
        self.dispatch_calls: list[tuple[int, str, str, str, dict[str, str] | None]] = []

    def workflow_job(self, installation_id: int, repository: str, job_id: int) -> dict[str, Any]:
        return {"head_sha": self.sha, "status": "completed", "run_id": 200}

    def rerun_job(self, installation_id: int, repository: str, job_id: int) -> None:
        self.rerun_calls.append((installation_id, repository, job_id))

    def dispatch_workflow(
        self,
        installation_id: int,
        repository: str,
        workflow: str,
        ref: str,
        inputs: dict[str, str] | None = None,
    ) -> None:
        self.dispatch_calls.append((installation_id, repository, workflow, ref, inputs))


def _app_settings(tmp_path: Path, policy_files: tuple[Path, Path]) -> BrokerSettings:
    inventory, profiles = policy_files
    return BrokerSettings(
        app_id="1",
        app_private_key_path=tmp_path / "app.pem",
        webhook_secret="webhook",
        worker_token="worker",
        inventory_path=inventory,
        profiles_path=profiles,
        database_path=tmp_path / "broker.db",
        artifact_root=tmp_path / "artifacts",
        operator_token="operator-secret",
    )


def _queued_test_job() -> QueuedJob:
    return QueuedJob(
        delivery_id="delivery-test",
        job_id=100,
        run_id=200,
        repository="belilovsky/private-repo",
        repository_id=1,
        installation_id=300,
        labels=("self-hosted", "Linux", "X64", "qdev-ci"),
        head_sha="a" * 40,
        head_branch="main",
        payload={
            "workflow_job": {
                "workflow_name": "unit tests",
                "path": ".github/workflows/tests.yml",
            }
        },
    )


def _test_report() -> dict[str, object]:
    return {
        "schema": "qdev-test-run-v1",
        "contract_version": 1,
        "project": "private-repo",
        "repository": "belilovsky/private-repo",
        "commit_sha": "a" * 40,
        "suite": "unit",
        "workflow": "tests.yml",
        "job_id": 100,
        "attempt": 1,
        "execution": {
            "environment": "self-hosted:qdev-ci",
            "started_at": "2026-09-04T00:00:00Z",
            "finished_at": "2026-09-04T00:00:03Z",
            "status": "completed",
        },
        "result": {"status": "passed", "total": 1, "executed": 1, "failed": 0, "skipped": 0},
        "coverage": [{"status": "unknown"}],
        "critical_scenarios": [],
        "reports": [],
        "flags": {"flaky": False, "quarantined": False},
    }


def test_test_report_artifact_is_bound_idempotently_and_rejects_empty_pass(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings = _app_settings(tmp_path, policy_files)
    store = Store(settings.database_path)
    store.enqueue(_queued_test_job())
    assert store.claim("worker-1", ("qdev-ci",)) is not None
    client = TestClient(create_app(settings, store=store, github=FakeGitHub("a" * 40)))
    body = json.dumps(_test_report(), separators=(",", ":")).encode()
    headers = {
        "X-Qdev-Artifact-Token": artifact_token(
            settings.worker_token, "belilovsky/private-repo", "a" * 40, 100
        ),
        "X-Qdev-SHA256": hashlib.sha256(body).hexdigest(),
    }
    response = client.put(
        "/artifacts/belilovsky/private-repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/100/qdev-test-run.json",
        content=body,
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["test_run"]["idempotent"] is False
    duplicate = client.put(
        "/artifacts/belilovsky/private-repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/100/qdev-test-run.json",
        content=body,
        headers=headers,
    )
    assert duplicate.status_code == 200
    assert duplicate.json()["test_run"]["idempotent"] is True
    empty = _test_report()
    empty["result"] = {"status": "passed", "total": 0, "executed": 0, "failed": 0, "skipped": 0}
    empty_body = json.dumps(empty, separators=(",", ":")).encode()
    empty_headers = dict(headers)
    empty_headers["X-Qdev-SHA256"] = hashlib.sha256(empty_body).hexdigest()
    rejected = client.put(
        "/artifacts/belilovsky/private-repo/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/100/qdev-test-run.json",
        content=empty_body,
        headers=empty_headers,
    )
    assert rejected.status_code == 422


def test_infrastructure_worker_failure_is_retried_once(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings = _app_settings(tmp_path, policy_files)
    store = Store(settings.database_path)
    store.enqueue(_queued_test_job())
    store.claim("worker-1", ("qdev-ci",))
    store.set_status(100, "running")
    client = TestClient(create_app(settings, store=store, github=FakeGitHub("a" * 40)))
    headers = {"X-Qdev-Worker-Token": "worker"}
    first = client.post(
        "/internal/v1/jobs/complete",
        headers=headers,
        json={
            "worker_name": "worker-1",
            "job_id": 100,
            "runner_exit_code": 125,
            "infrastructure_error": True,
            "detail": "sidecar unavailable",
        },
    )
    assert first.status_code == 204
    assert store.job_status(100) == "pending"
    store.claim("worker-2", ("qdev-ci",))
    second = client.post(
        "/internal/v1/jobs/complete",
        headers=headers,
        json={
            "worker_name": "worker-2",
            "job_id": 100,
            "runner_exit_code": 125,
            "infrastructure_error": True,
            "detail": "sidecar unavailable again",
        },
    )
    assert second.status_code == 204
    assert store.job_status(100) == "failed"


def test_operator_summary_and_retry_are_separately_authorized(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings = _app_settings(tmp_path, policy_files)
    store = Store(settings.database_path)
    store.enqueue(_queued_test_job())
    github = FakeGitHub("a" * 40)
    app = create_app(settings, store=store, github=github)
    client = TestClient(app)
    assert client.get("/operator/v1/test-summary").status_code == 401
    assert (
        client.get(
            "/operator/v1/test-summary", headers={"X-Qdev-Operator-Token": "operator-secret"}
        ).json()["runs_total"]
        == 0
    )
    store.set_status(100, "failed", "assertion")
    cross_site = client.post(
        "/operator/v1/jobs/100/retry",
        headers={
            "X-Qdev-Operator-Token": "operator-secret",
            "Origin": "https://evil.example",
        },
        json={"reason": "recheck"},
    )
    assert cross_site.status_code == 403
    retry = client.post(
        "/operator/v1/jobs/100/retry",
        headers={
            "X-Qdev-Operator-Token": "operator-secret",
            "Origin": "http://testserver",
        },
        json={"reason": "recheck"},
    )
    assert retry.status_code == 200
    assert github.rerun_calls == [(300, "belilovsky/private-repo", 100)]


def test_operator_oidc_requires_server_side_proxy_secret(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings = _app_settings(tmp_path, policy_files)
    settings = BrokerSettings(
        **{
            **settings.__dict__,
            "operator_token": None,
            "operator_proxy_secret": "proxy-secret",
            "allow_legacy_local_oidc": False,
        }
    )
    client = TestClient(
        create_app(settings, github=FakeGitHub("a" * 40)),
        client=("127.0.0.1", 12345),
    )
    identity_headers = {
        "X-Auth-Request-Email": "operator@example.test",
        "X-Auth-Request-Groups": "qdev-ci-operators",
        "X-Real-IP": "127.0.0.1",
    }
    response = client.get(
        "/operator/v1/test-summary",
        headers=identity_headers,
    )
    assert response.status_code == 401
    accepted = client.get(
        "/operator/v1/test-summary",
        headers={**identity_headers, "X-Qdev-Operator-Proxy-Auth": "proxy-secret"},
    )
    assert accepted.status_code == 200
    assert accepted.json()["runs_total"] == 0


def test_scheduler_registers_only_safe_workflows_and_dispatches_once(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings = _app_settings(tmp_path, policy_files)
    github = FakeGitHub("a" * 40)
    app = create_app(settings, github=github)
    client = TestClient(app)
    operator_headers = {"X-Qdev-Operator-Token": "operator-secret"}
    registered = client.put(
        "/operator/v1/test-schedules",
        headers=operator_headers,
        json={
            "repository": "belilovsky/private-repo",
            "workflow": ".github/workflows/tests.yml",
            "suite": "unit",
            "installation_id": 300,
            "ref": "main",
            "interval_seconds": 60,
            "next_run_at": 100,
        },
    )
    assert registered.status_code == 200
    tick_headers = {"X-Qdev-Worker-Token": "worker"}
    first = client.post(
        "/internal/v1/scheduler/tick",
        headers=tick_headers,
        json={"now": 100},
    )
    assert first.status_code == 200
    assert first.json()["dispatched"] == 1
    assert github.dispatch_calls == [
        (
            300,
            "belilovsky/private-repo",
            ".github/workflows/tests.yml",
            "main",
            {"qdev_suite": "unit"},
        )
    ]
    second = client.post(
        "/internal/v1/scheduler/tick",
        headers=tick_headers,
        json={"now": 100},
    )
    assert second.status_code == 200
    assert second.json()["items"] == []
    rejected = client.put(
        "/operator/v1/test-schedules",
        headers=operator_headers,
        json={
            "repository": "belilovsky/private-repo",
            "workflow": ".github/workflows/release.yml",
            "installation_id": 300,
            "ref": "main",
        },
    )
    assert rejected.status_code == 403


def test_explicitly_registered_test_workflow_need_not_have_marker_name(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    inventory, profiles = policy_files
    data = json.loads(inventory.read_text(encoding="utf-8"))
    data["repositories"][0]["workflow_files"] = [".github/workflows/build.yml"]
    inventory.write_text(json.dumps(data), encoding="utf-8")
    settings = _app_settings(tmp_path, (inventory, profiles))
    client = TestClient(create_app(settings, github=FakeGitHub("a" * 40)))
    response = client.put(
        "/operator/v1/test-schedules",
        headers={"X-Qdev-Operator-Token": "operator-secret"},
        json={
            "repository": "belilovsky/private-repo",
            "workflow": ".github/workflows/build.yml",
            "suite": "unit",
            "installation_id": 300,
            "ref": "main",
            "interval_seconds": 60,
        },
    )
    assert response.status_code == 200
