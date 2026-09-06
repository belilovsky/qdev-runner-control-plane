from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from qdev_runner.broker import (
    artifact_job_is_active,
    artifact_token,
    completed_run_conclusion,
    create_app,
    registry_credentials,
    verify_signature,
    worker_authenticated,
)
from qdev_runner.claim_scope import ClaimScope, ScopedJob
from qdev_runner.github import GitHubAppClient, GitHubError
from qdev_runner.models import QueuedJob
from qdev_runner.policy import Policy
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


def test_github_transport_errors_are_broker_recoverable(tmp_path: Path) -> None:
    def unavailable(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("temporary DNS failure", request=request)

    client = GitHubAppClient(
        "1",
        tmp_path / "unused-app.pem",
        transport=httpx.MockTransport(unavailable),
    )
    with pytest.raises(GitHubError, match="transport failure"):
        client._request("GET", "/rate_limit")
    client.close()


def test_workflow_run_jobs_reads_every_page_for_the_exact_attempt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    observed_pages: list[str] = []

    def provider(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/repos/belilovsky/qazgeo/actions/runs/41/attempts/2/jobs"
        assert request.url.params["filter"] == "all"
        assert request.url.params["per_page"] == "100"
        page = request.url.params["page"]
        observed_pages.append(page)
        job_id = 501 if page == "1" else 502
        return httpx.Response(200, json={"total_count": 2, "jobs": [{"id": job_id}]})

    client = GitHubAppClient(
        "1",
        tmp_path / "unused-app.pem",
        transport=httpx.MockTransport(provider),
    )
    monkeypatch.setattr(client, "installation_token", lambda _installation_id: "token")

    assert [job["id"] for job in client.workflow_run_jobs(7, "belilovsky/qazgeo", 41, 2)] == [
        501,
        502,
    ]
    assert observed_pages == ["1", "2"]
    client.close()


@pytest.mark.parametrize(
    ("pages", "message"),
    [
        (
            [
                {"total_count": 2, "jobs": [{"id": 501}]},
                {"total_count": 3, "jobs": [{"id": 502}, {"id": 503}]},
            ],
            "changed during pagination",
        ),
        (
            [{"total_count": 2, "jobs": [{"id": 501}, {"id": 501}]}],
            "duplicated",
        ),
    ],
)
def test_workflow_run_jobs_rejects_unstable_or_duplicated_inventory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pages: list[dict[str, object]],
    message: str,
) -> None:
    def provider(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        return httpx.Response(200, json=pages[page - 1])

    client = GitHubAppClient(
        "1",
        tmp_path / "unused-app.pem",
        transport=httpx.MockTransport(provider),
    )
    monkeypatch.setattr(client, "installation_token", lambda _installation_id: "token")

    with pytest.raises(GitHubError, match=message):
        client.workflow_run_jobs(7, "belilovsky/qazgeo", 41, 2)
    client.close()


def test_certificate_bound_scope_does_not_fall_back_to_static_worker_token() -> None:
    fingerprint = "a" * 64
    scope = ClaimScope(
        scope_id="maturity-20260831",
        worker_name="qdev-maturity-primary",
        tier="primary",
        repository="belilovsky/qazagents",
        head_sha="b" * 40,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(ScopedJob(100, "qdev-ci"), ScopedJob(101, "qdev-ci-docker")),
        worker_certificate_sha256=fingerprint,
    )

    assert worker_authenticated(
        None,
        "ordinary-token",
        claim_scope=scope,
        client_certificate_sha256=fingerprint,
    )
    assert not worker_authenticated("ordinary-token", "ordinary-token", claim_scope=scope)
    assert not worker_authenticated(
        None,
        "ordinary-token",
        claim_scope=scope,
        client_certificate_sha256="b" * 64,
    )
    assert worker_authenticated("ordinary-token", "ordinary-token")


def test_expired_scope_heartbeats_only_its_already_bound_job(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    inventory, profiles = policy_files
    scopes_path = tmp_path / "claim-scopes.json"
    fingerprint = "a" * 64
    scopes_path.write_text(
        json.dumps(
            {
                "schema": "claim-scope-v1",
                "scopes": [
                    {
                        "scope_id": "maturity-20260831",
                        "worker_name": "qdev-maturity-primary",
                        "tier": "primary",
                        "repository": "belilovsky/qazagents",
                        "head_sha": "a" * 40,
                        "expires_at": (datetime.now(UTC) - timedelta(seconds=1)).isoformat(),
                        "worker_certificate_sha256": fingerprint,
                        "jobs": [
                            {"job_id": 100, "profile": "qdev-ci"},
                            {"job_id": 101, "profile": "qdev-ci-docker"},
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    store = Store(tmp_path / "broker.db")
    assert store.enqueue(
        QueuedJob(
            delivery_id="delivery-100",
            job_id=100,
            run_id=200,
            repository="belilovsky/qazagents",
            repository_id=1,
            installation_id=300,
            labels=("self-hosted", "Linux", "X64", "qdev-ci"),
            head_sha="a" * 40,
            head_branch="main",
            payload={},
        )
    )
    scope = ClaimScope(
        scope_id="maturity-20260831",
        worker_name="qdev-maturity-primary",
        tier="primary",
        repository="belilovsky/qazagents",
        head_sha="a" * 40,
        expires_at=datetime.now(UTC) - timedelta(seconds=1),
        jobs=(ScopedJob(100, "qdev-ci"), ScopedJob(101, "qdev-ci-docker")),
        worker_certificate_sha256=fingerprint,
    )
    assert (
        store.claim("qdev-maturity-primary", ("qdev-ci", "qdev-ci-docker"), claim_scope=scope)
        is not None
    )
    settings = BrokerSettings(
        app_id="1",
        app_private_key_path=tmp_path / "app.pem",
        webhook_secret="webhook",
        worker_token="ordinary-token",
        inventory_path=inventory,
        profiles_path=profiles,
        database_path=tmp_path / "broker.db",
        artifact_root=tmp_path / "artifacts",
        claim_scopes_path=scopes_path,
    )
    app = create_app(settings, store=store, policy=Policy(inventory, profiles), github=object())
    payload = {
        "worker_name": "qdev-maturity-primary",
        "tier": "primary",
        "profiles": ["qdev-ci", "qdev-ci-docker"],
        "active_jobs": 1,
        "active_job_ids": [100],
        "claim_scope_id": "maturity-20260831",
        "detail": {},
    }
    with TestClient(app) as client:
        accepted = client.post(
            "/internal/v1/workers/heartbeat",
            json=payload,
            headers={"X-QDev-Client-Certificate-SHA256": fingerprint},
        )
        wrong_worker = client.post(
            "/internal/v1/workers/heartbeat",
            json={**payload, "worker_name": "another-primary"},
            headers={"X-QDev-Client-Certificate-SHA256": fingerprint},
        )
        rejected = client.post("/internal/v1/workers/heartbeat", json=payload)

    assert accepted.status_code == 200
    assert accepted.json() == {
        "schema": "qdev-worker-directives-v1",
        "capacity_override": None,
    }
    assert wrong_worker.status_code == 403
    assert rejected.status_code == 401
