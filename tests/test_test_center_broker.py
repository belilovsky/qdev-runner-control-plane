from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import yaml
from fastapi.testclient import TestClient

from qdev_runner.broker import artifact_token, create_app
from qdev_runner.github_oidc import GitHubActionsArtifactOIDCVerifier, GitHubActionsOIDCError
from qdev_runner.models import QueuedJob
from qdev_runner.settings import BrokerSettings
from qdev_runner.store import Store

SHA = "a" * 40
WORKFLOW = ".github/workflows/tests.yml"


class FakeGitHub:
    def __init__(self, sha: str = SHA) -> None:
        self.sha = sha
        self.rerun_calls: list[tuple[int, str, int]] = []
        self.dispatch_calls: list[tuple[int, str, str, str, dict[str, str] | None]] = []

    def workflow_job(self, installation_id: int, repository: str, job_id: int) -> dict[str, Any]:
        return {
            "head_sha": self.sha,
            "status": "completed",
            "run_id": 200,
            "run_attempt": 1,
            "started_at": "2026-09-08T00:00:00Z",
            "completed_at": "2026-09-08T00:01:00Z",
            "repository_id": 1,
            "repository": {"id": 1, "full_name": repository},
            "path": WORKFLOW,
        }

    def rerun_job(self, installation_id: int, repository: str, job_id: int) -> dict[str, Any]:
        self.rerun_calls.append((installation_id, repository, job_id))
        return {"run_id": 201, "job_id": 201, "run_attempt": 1}

    def dispatch_workflow(
        self,
        installation_id: int,
        repository: str,
        workflow: str,
        ref: str,
        inputs: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        self.dispatch_calls.append((installation_id, repository, workflow, ref, inputs))
        return {"run_id": 201}

    def ref_sha(self, installation_id: int, repository: str, ref: str) -> str:
        return self.sha


class RecordingArtifactOIDCVerifier(GitHubActionsArtifactOIDCVerifier):
    def __init__(self, *, reject: bool = False) -> None:
        self.reject = reject
        self.calls: list[tuple[str, str, str, int]] = []

    def verify(self, token: str, *, repository: str, sha: str, run_id: int) -> None:
        self.calls.append((token, repository, sha, run_id))
        if self.reject:
            raise GitHubActionsOIDCError("rejected by test verifier")


def _app_settings(
    tmp_path: Path, policy_files: tuple[Path, Path], **overrides: Any
) -> BrokerSettings:
    inventory, profiles = policy_files
    data = json.loads(inventory.read_text(encoding="utf-8"))
    data["repositories"][0]["test_workflows"] = [
        {
            "path": WORKFLOW,
            "suites": ["unit"],
            "profile": "qdev-ci",
            "refs": ["main"],
            "required": True,
        }
    ]
    inventory.write_text(json.dumps(data), encoding="utf-8")
    values: dict[str, Any] = {
        "app_id": "1",
        "app_private_key_path": tmp_path / "app.pem",
        "webhook_secret": "webhook",
        "worker_token": "worker",
        "inventory_path": inventory,
        "profiles_path": profiles,
        "database_path": tmp_path / "broker.db",
        "artifact_root": tmp_path / "artifacts",
        "operations_root": tmp_path / "operations",
        "operator_token": "operator-secret",
        "operator_receipt_key": "receipt-secret",
        "operator_directive_key": "directive-secret",
        "scheduler_enabled": False,
    }
    values.update(overrides)
    return BrokerSettings(**values)


def _queued_test_job() -> QueuedJob:
    return QueuedJob(
        delivery_id="delivery-test",
        job_id=100,
        run_id=200,
        repository="belilovsky/private-repo",
        repository_id=1,
        installation_id=300,
        labels=("self-hosted", "Linux", "X64", "qdev-ci"),
        head_sha=SHA,
        head_branch="main",
        payload={
            "workflow_job": {
                "workflow_name": "Build and verify",
                "path": WORKFLOW,
                "run_id": 200,
                "run_attempt": 1,
            }
        },
    )


def _test_report() -> dict[str, Any]:
    return {
        "schema": "qdev-test-run-v1",
        "contract_version": 1,
        "project": "private-repo",
        "repository": "belilovsky/private-repo",
        "commit_sha": SHA,
        "suite": "unit",
        "workflow": WORKFLOW,
        "job_id": 100,
        "run_id": 200,
        "repository_id": 1,
        "attempt": 1,
        "profile": "qdev-ci",
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


def _claimed_client(
    tmp_path: Path, policy_files: tuple[Path, Path], github: FakeGitHub | None = None
) -> tuple[BrokerSettings, Store, TestClient, FakeGitHub]:
    settings = _app_settings(tmp_path, policy_files)
    store = Store(settings.database_path)
    assert store.enqueue(_queued_test_job())
    assert store.claim("worker-1", ("qdev-ci",)) is not None
    fake = github or FakeGitHub()
    return settings, store, TestClient(create_app(settings, store=store, github=fake)), fake


def _legacy_oidc_client(
    tmp_path: Path, policy_files: tuple[Path, Path], *, reject: bool = False
) -> tuple[BrokerSettings, TestClient, RecordingArtifactOIDCVerifier]:
    settings = _app_settings(tmp_path, policy_files)
    verifier = RecordingArtifactOIDCVerifier(reject=reject)
    client = TestClient(
        create_app(
            settings,
            github=FakeGitHub(),
            github_actions_oidc_verifier=verifier,
        )
    )
    return settings, client, verifier


def _legacy_oidc_headers(body: bytes, **extra: str) -> dict[str, str]:
    return {
        "X-Qdev-GitHub-OIDC": "github-oidc-token",
        "X-Qdev-SHA256": hashlib.sha256(body).hexdigest(),
        **extra,
    }


def test_legacy_oidc_archive_upload_uses_workflow_run_without_controller_job(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings, client, verifier = _legacy_oidc_client(tmp_path, policy_files)
    body = b"controller recovery archive"
    response = client.put(
        f"/artifacts/belilovsky/private-repo/{SHA}/123/controller-recovery-build.tar.gz",
        content=body,
        headers=_legacy_oidc_headers(body),
    )
    assert response.status_code == 200, response.text
    assert response.json() == {
        "schema": "qdev-artifact-v1",
        "sha256": hashlib.sha256(body).hexdigest(),
        "size": len(body),
    }
    assert verifier.calls == [("github-oidc-token", "belilovsky/private-repo", SHA, 123)]
    target = (
        settings.artifact_root
        / "belilovsky"
        / "private-repo"
        / SHA
        / "123"
        / "controller-recovery-build.tar.gz"
    )
    assert target.read_bytes() == body
    assert target.stat().st_mode & 0o777 == 0o600


def test_legacy_archive_does_not_bypass_report_or_worker_job_binding(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings, client, verifier = _legacy_oidc_client(tmp_path, policy_files)
    body = b"archive"
    path = f"/artifacts/belilovsky/private-repo/{SHA}/123/controller-recovery-build.tar.gz"
    report_metadata = client.put(
        path,
        content=body,
        headers=_legacy_oidc_headers(body, **{"X-Qdev-Test-Suite": "unit"}),
    )
    assert report_metadata.status_code == 422
    assert verifier.calls == []
    invalid_checksum = client.put(
        path,
        content=body,
        headers=_legacy_oidc_headers(b"different"),
    )
    assert invalid_checksum.status_code == 422
    assert verifier.calls == [("github-oidc-token", "belilovsky/private-repo", SHA, 123)]
    worker_token = client.put(
        path,
        content=body,
        headers={
            "X-Qdev-Artifact-Token": artifact_token(
                settings.worker_token, "belilovsky/private-repo", SHA, 123
            ),
            "X-Qdev-SHA256": hashlib.sha256(body).hexdigest(),
        },
    )
    assert worker_token.status_code == 401
    target = settings.artifact_root / "belilovsky" / "private-repo" / SHA / "123"
    assert not target.exists()


def test_legacy_oidc_archive_rejects_invalid_identity(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings, client, verifier = _legacy_oidc_client(tmp_path, policy_files, reject=True)
    body = b"archive"
    response = client.put(
        f"/artifacts/belilovsky/private-repo/{SHA}/123/controller-recovery-build.tar.gz",
        content=body,
        headers=_legacy_oidc_headers(body),
    )
    assert response.status_code == 401
    assert verifier.calls == [("github-oidc-token", "belilovsky/private-repo", SHA, 123)]
    assert not (settings.artifact_root / "belilovsky").exists()


def test_registered_report_is_idempotent_and_empty_pass_is_rejected(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings, _store, client, _github = _claimed_client(tmp_path, policy_files)
    body = json.dumps(_test_report(), separators=(",", ":")).encode()
    headers = {
        "X-Qdev-Artifact-Token": artifact_token(
            settings.worker_token, "belilovsky/private-repo", SHA, 100
        ),
        "X-Qdev-SHA256": hashlib.sha256(body).hexdigest(),
        "X-Qdev-Test-Format": "qdev-test-run",
        "X-Qdev-Test-Suite": "unit",
        "X-Qdev-Test-Workflow": WORKFLOW,
    }
    path = f"/artifacts/belilovsky/private-repo/{SHA}/100/1/unit/qdev-test-run.json"
    first = client.put(path, content=body, headers=headers)
    assert first.status_code == 200, first.text
    assert first.json()["test_run"]["idempotent"] is False
    duplicate = client.put(path, content=body, headers=headers)
    assert duplicate.status_code == 200
    assert duplicate.json()["test_run"]["idempotent"] is True
    empty = _test_report()
    empty["result"] = {"status": "passed", "total": 0, "executed": 0, "failed": 0, "skipped": 0}
    empty_body = json.dumps(empty, separators=(",", ":")).encode()
    rejected = client.put(
        path,
        content=empty_body,
        headers={**headers, "X-Qdev-SHA256": hashlib.sha256(empty_body).hexdigest()},
    )
    assert rejected.status_code == 422


def test_registered_report_rejects_provider_sha_mismatch(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    github = FakeGitHub("b" * 40)
    settings, _store, client, _github = _claimed_client(tmp_path, policy_files, github)
    body = json.dumps(_test_report(), separators=(",", ":")).encode()
    response = client.put(
        f"/artifacts/belilovsky/private-repo/{SHA}/100/1/unit/qdev-test-run.json",
        content=body,
        headers={
            "X-Qdev-Artifact-Token": artifact_token(
                settings.worker_token, "belilovsky/private-repo", SHA, 100
            ),
            "X-Qdev-SHA256": hashlib.sha256(body).hexdigest(),
            "X-Qdev-Test-Format": "qdev-test-run",
            "X-Qdev-Test-Suite": "unit",
            "X-Qdev-Test-Workflow": WORKFLOW,
        },
    )
    assert response.status_code == 422


def test_infrastructure_failure_is_retried_once(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings, store, client, _github = _claimed_client(tmp_path, policy_files)
    store.set_status(100, "running")
    headers = {"X-Qdev-Worker-Token": settings.worker_token}
    complete = {
        "worker_name": "worker-1",
        "job_id": 100,
        "runner_exit_code": 125,
        "infrastructure_error": True,
        "detail": "sidecar unavailable",
    }
    first = client.post("/internal/v1/jobs/complete", headers=headers, json=complete)
    assert first.status_code == 204
    assert store.job_status(100) == "pending"
    assert store.claim("worker-2", ("qdev-ci",)) is not None
    second = client.post(
        "/internal/v1/jobs/complete", headers=headers, json={**complete, "worker_name": "worker-2"}
    )
    assert second.status_code == 204
    assert store.job_status(100) == "failed"


def test_operator_summary_retry_csrf_and_retry_idempotency(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings, store, client, github = _claimed_client(tmp_path, policy_files)
    assert client.get("/operator/v1/test-summary").status_code == 401
    assert (
        client.get(
            "/operator/v1/test-summary", headers={"X-Qdev-Operator-Token": settings.operator_token}
        ).status_code
        == 200
    )
    store.set_status(100, "failed", "assertion")
    body = {"reason": "recheck", "request_id": "retry-100"}
    evil = client.post(
        "/operator/v1/jobs/100/retry",
        headers={
            "X-Qdev-Operator-Token": settings.operator_token,
            "Origin": "https://evil.example",
        },
        json=body,
    )
    assert evil.status_code == 403
    headers = {"X-Qdev-Operator-Token": settings.operator_token, "Origin": "http://testserver"}
    first = client.post("/operator/v1/jobs/100/retry", headers=headers, json=body)
    assert first.status_code == 200, first.text
    duplicate = client.post("/operator/v1/jobs/100/retry", headers=headers, json=body)
    assert duplicate.status_code == 200
    assert duplicate.json()["idempotent"] is True
    assert github.rerun_calls == [(300, "belilovsky/private-repo", 100)]


def test_proxy_identity_requires_server_credential(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings = _app_settings(
        tmp_path,
        policy_files,
        operator_token=None,
        operator_receipt_key=None,
        operator_directive_key=None,
        operator_proxy_secret="proxy-secret",
        allow_legacy_local_oidc=False,
    )
    client = TestClient(create_app(settings, github=FakeGitHub()), client=("127.0.0.1", 12345))
    identity = {
        "X-Auth-Request-Email": "operator@example.test",
        "X-Auth-Request-Groups": "qdev-ci-operators",
        "X-Real-IP": "127.0.0.1",
    }
    assert client.get("/operator/v1/test-summary", headers=identity).status_code == 401
    accepted = client.get(
        "/operator/v1/test-summary",
        headers={**identity, "X-Qdev-Operator-Proxy-Auth": "proxy-secret"},
    )
    assert accepted.status_code == 200


def test_scheduler_uses_explicit_registration_and_dispatches_once(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings = _app_settings(tmp_path, policy_files)
    github = FakeGitHub()
    client = TestClient(create_app(settings, github=github))
    operator = {"X-Qdev-Operator-Token": settings.operator_token}
    registered = client.put(
        "/operator/v1/test-schedules",
        headers=operator,
        json={
            "repository": "belilovsky/private-repo",
            "workflow": WORKFLOW,
            "suite": "unit",
            "installation_id": 300,
            "ref": "main",
            "interval_seconds": 60,
            "next_run_at": 100,
        },
    )
    assert registered.status_code == 200, registered.text
    tick = {"X-Qdev-Worker-Token": settings.worker_token}
    first = client.post("/internal/v1/scheduler/tick", headers=tick, json={"now": 100})
    assert first.status_code == 200, first.text
    assert first.json()["dispatched"] == 1
    assert len(github.dispatch_calls) == 1
    second = client.post("/internal/v1/scheduler/tick", headers=tick, json={"now": 100})
    assert second.status_code == 200
    assert second.json()["items"] == []
    rejected = client.put(
        "/operator/v1/test-schedules",
        headers=operator,
        json={
            "repository": "belilovsky/private-repo",
            "workflow": ".github/workflows/release.yml",
            "installation_id": 300,
            "ref": "main",
        },
    )
    assert rejected.status_code == 403


def test_workflow_name_is_not_an_authorization_signal(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings = _app_settings(tmp_path, policy_files)
    client = TestClient(create_app(settings, github=FakeGitHub()))
    response = client.put(
        "/operator/v1/test-schedules",
        headers={"X-Qdev-Operator-Token": settings.operator_token},
        json={
            "repository": "belilovsky/private-repo",
            "workflow": WORKFLOW,
            "suite": "unit",
            "installation_id": 300,
            "ref": "main",
            "interval_seconds": 60,
        },
    )
    assert response.status_code == 200


def _upload_headers(settings: BrokerSettings, body: bytes, *, fmt: str) -> dict[str, str]:
    headers = {
        "X-Qdev-Artifact-Token": artifact_token(
            settings.worker_token, "belilovsky/private-repo", SHA, 100
        ),
        "X-Qdev-SHA256": hashlib.sha256(body).hexdigest(),
        "X-Qdev-Test-Format": fmt,
        "X-Qdev-Test-Suite": "unit",
        "X-Qdev-Test-Attempt": "1",
        "X-Qdev-Test-Workflow": WORKFLOW,
        "X-Qdev-Test-Profile": "qdev-ci",
    }
    return headers


def _require_native_reports(profiles: Path, *formats: str) -> None:
    document = yaml.safe_load(profiles.read_text(encoding="utf-8"))
    document["profiles"]["qdev-ci"]["required_test_report_formats"] = list(formats)
    profiles.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")


def test_native_reports_merge_in_either_delivery_order(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings, _store, client, _github = _claimed_client(tmp_path, policy_files)
    lcov = b"TN:\nSF:src/a.py\nLF:10\nLH:7\nend_of_record\n"
    lcov_response = client.put(
        f"/artifacts/belilovsky/private-repo/{SHA}/100/1/unit/coverage.info",
        content=lcov,
        headers=_upload_headers(settings, lcov, fmt="lcov"),
    )
    assert lcov_response.status_code == 200, lcov_response.text
    assert "test_run" not in lcov_response.json()

    junit = b"<testsuite><testcase name='ok'/></testsuite>"
    junit_response = client.put(
        f"/artifacts/belilovsky/private-repo/{SHA}/100/1/unit/junit.xml",
        content=junit,
        headers=_upload_headers(settings, junit, fmt="junit"),
    )
    assert junit_response.status_code == 200, junit_response.text
    assert junit_response.json()["test_run"]["status"] == "passed"

    detail = client.get(
        "/operator/v1/test-runs/100",
        headers={"X-Qdev-Operator-Token": settings.operator_token},
    )
    assert detail.status_code == 200, detail.text
    runs = detail.json()["runs"]
    assert len(runs) == 1
    assert runs[0]["coverage"] == [
        {
            "status": "measured",
            "kind": "line",
            "covered": 7,
            "denominator": 10,
            "percentage": 70.0,
        }
    ]
    assert {item["format"] for item in runs[0]["reports"]} == {"junit", "lcov"}
    assert all(item["url"].startswith("/artifacts/") for item in runs[0]["reports"])


def test_required_native_reports_are_order_independent_and_idempotent(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    _inventory, profiles = policy_files
    _require_native_reports(profiles, "junit", "cobertura")
    settings, _store, client, _github = _claimed_client(tmp_path, policy_files)
    junit = b"<testsuite><testcase name='ok'/></testsuite>"
    cobertura = b'<coverage line-rate="0.5" lines-valid="20" lines-covered="10" />'
    junit_path = f"/artifacts/belilovsky/private-repo/{SHA}/100/1/unit/junit.xml"
    coverage_path = f"/artifacts/belilovsky/private-repo/{SHA}/100/1/unit/coverage.xml"

    first_junit = client.put(
        junit_path,
        content=junit,
        headers=_upload_headers(settings, junit, fmt="junit"),
    )
    assert first_junit.status_code == 200, first_junit.text
    assert first_junit.json()["test_run"]["status"] == "incomplete"
    duplicate_junit = client.put(
        junit_path,
        content=junit,
        headers=_upload_headers(settings, junit, fmt="junit"),
    )
    assert duplicate_junit.status_code == 200, duplicate_junit.text
    assert duplicate_junit.json()["test_report"]["idempotent"] is True
    assert duplicate_junit.json()["test_run"]["status"] == "incomplete"

    complete = client.put(
        coverage_path,
        content=cobertura,
        headers=_upload_headers(settings, cobertura, fmt="cobertura"),
    )
    assert complete.status_code == 200, complete.text
    assert complete.json()["test_run"]["status"] == "passed"
    completed_digest = complete.json()["test_run"]["digest"]
    duplicate_coverage = client.put(
        coverage_path,
        content=cobertura,
        headers=_upload_headers(settings, cobertura, fmt="cobertura"),
    )
    assert duplicate_coverage.status_code == 200, duplicate_coverage.text
    assert duplicate_coverage.json()["test_report"]["idempotent"] is True
    assert duplicate_coverage.json()["test_run"]["digest"] == completed_digest

    reverse_root = tmp_path / "reverse-delivery"
    reverse_root.mkdir()
    reverse_settings, _reverse_store, reverse_client, _reverse_github = _claimed_client(
        reverse_root, policy_files
    )
    first_coverage = reverse_client.put(
        coverage_path,
        content=cobertura,
        headers=_upload_headers(reverse_settings, cobertura, fmt="cobertura"),
    )
    assert first_coverage.status_code == 200, first_coverage.text
    assert "test_run" not in first_coverage.json()
    complete_reverse = reverse_client.put(
        junit_path,
        content=junit,
        headers=_upload_headers(reverse_settings, junit, fmt="junit"),
    )
    assert complete_reverse.status_code == 200, complete_reverse.text
    assert complete_reverse.json()["test_run"]["status"] == "passed"
    assert complete_reverse.json()["test_run"]["digest"] == completed_digest


def test_conflicting_second_junit_is_rejected_without_overwriting_source(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings, _store, client, _github = _claimed_client(tmp_path, policy_files)
    path = f"/artifacts/belilovsky/private-repo/{SHA}/100/1/unit/junit.xml"
    first = b"<testsuite><testcase name='ok'/></testsuite>"
    assert (
        client.put(
            path,
            content=first,
            headers=_upload_headers(settings, first, fmt="junit"),
        ).status_code
        == 200
    )
    conflicting = b"<testsuite><testcase name='bad'><failure/></testcase></testsuite>"
    response = client.put(
        path,
        content=conflicting,
        headers=_upload_headers(settings, conflicting, fmt="junit"),
    )
    assert response.status_code == 409
    detail = client.get(
        "/operator/v1/test-runs/100",
        headers={"X-Qdev-Operator-Token": settings.operator_token},
    )
    assert detail.status_code == 200
    assert len(detail.json()["reports"]) == 1
    assert detail.json()["reports"][0]["sha256"] == hashlib.sha256(first).hexdigest()


def test_operator_report_download_is_id_bound_and_fail_closed(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    settings, _store, client, _github = _claimed_client(tmp_path, policy_files)
    body = b"<testsuite><testcase name='ok'/></testsuite>"
    uploaded = client.put(
        f"/artifacts/belilovsky/private-repo/{SHA}/100/1/unit/junit.xml",
        content=body,
        headers=_upload_headers(settings, body, fmt="junit"),
    )
    assert uploaded.status_code == 200, uploaded.text
    report_id = uploaded.json()["test_report"]["id"]
    operator = {"X-Qdev-Operator-Token": settings.operator_token}
    downloaded = client.get(f"/operator/v1/test-reports/{report_id}", headers=operator)
    assert downloaded.status_code == 200
    assert downloaded.content == body
    assert downloaded.headers["x-qdev-report-sha256"] == hashlib.sha256(body).hexdigest()
    assert client.get("/operator/v1/test-reports/999999", headers=operator).status_code == 404
    assert client.get(f"/operator/v1/test-reports/{report_id}").status_code == 401
    target = settings.artifact_root.joinpath(
        "belilovsky/private-repo", SHA, "100", "1", "unit", "junit.xml"
    )
    target.write_bytes(b"tampered")
    assert client.get(f"/operator/v1/test-reports/{report_id}", headers=operator).status_code == 409
