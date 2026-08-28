from __future__ import annotations

import hashlib
import hmac
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from qdev_runner.broker import (
    ClaimRequest,
    ClaimScope,
    ClaimScopeError,
    artifact_job_is_active,
    artifact_token,
    assign_required_profile,
    claim_scope_matches_job,
    completed_run_conclusion,
    registry_credentials,
    validate_claim_scope,
    verify_signature,
)
from qdev_runner.models import QueuedJob
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
        "username": "qdev-runner",
        "password": "registry-token",
    }


def test_completed_parent_run_is_terminal_even_when_job_api_stays_queued() -> None:
    assert completed_run_conclusion({"status": "completed", "conclusion": "cancelled"}) == (
        "cancelled"
    )
    assert completed_run_conclusion({"status": "completed", "conclusion": None}) == "unknown"
    assert completed_run_conclusion({"status": "in_progress", "conclusion": None}) is None


def test_policy_profile_assignment_replaces_the_dataclass_value() -> None:
    queued = QueuedJob(
        delivery_id="delivery",
        job_id=1,
        run_id=2,
        repository="belilovsky/repo",
        repository_id=3,
        installation_id=4,
        labels=("self-hosted", "qdev-ci-docker"),
        head_sha="a" * 40,
        head_branch="main",
        payload={},
    )

    assigned = assign_required_profile(queued, "qdev-ci-docker")

    assert queued.required_profile == ""
    assert assigned.required_profile == "qdev-ci-docker"
    assert assigned.job_id == queued.job_id


def _claim_scope(*, now: datetime, **overrides: object) -> ClaimScope:
    data: dict[str, object] = {
        "schema": "claim-scope-v1",
        "worker_name": "qdev-recovery-primary",
        "repository": "belilovsky/qazagents",
        "head_sha": "a" * 40,
        "job_ids": [101, 102],
        "expected_profiles": ["qdev-ci", "qdev-ci-docker"],
        "expires_at": now + timedelta(minutes=5),
    }
    data.update(overrides)
    return ClaimScope.model_validate(data)


def _claim_request(
    *, worker_name: str = "qdev-recovery-primary", profiles: list[str] | None = None
) -> ClaimRequest:
    return ClaimRequest(
        worker_name=worker_name,
        tier="primary",
        profiles=profiles or ["qdev-ci", "qdev-ci-docker"],
        disk_free_gib=100,
        min_disk_free_gib=30,
    )


def test_claim_scope_is_strict_and_bound_to_exact_request() -> None:
    now = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    scope = _claim_scope(now=now)
    validate_claim_scope(scope, _claim_request(), now=now)

    with pytest.raises(ClaimScopeError, match="different worker"):
        validate_claim_scope(
            scope, _claim_request(worker_name="other-worker"), now=now
        )
    with pytest.raises(ClaimScopeError, match="profiles"):
        validate_claim_scope(scope, _claim_request(profiles=["qdev-ci"]), now=now)
    with pytest.raises(ClaimScopeError, match="expired"):
        validate_claim_scope(scope, _claim_request(), now=now + timedelta(minutes=6))
    with pytest.raises(ClaimScopeError, match="short-lived"):
        validate_claim_scope(
            _claim_scope(now=now, expires_at=now + timedelta(minutes=16)),
            _claim_request(),
            now=now,
        )


@pytest.mark.parametrize(
    "field, value",
    [
        ("schema", "claim-scope-v0"),
        ("repository", "belilovsky/other"),
        ("head_sha", "A" * 40),
        ("job_ids", [101, 101]),
        ("job_ids", [0, 102]),
        ("expected_profiles", ["qdev-ci-browser"]),
        ("expected_profiles", ["qdev-ci", "qdev-ci"]),
        ("expires_at", "2026-08-28T12:05:00"),
    ],
)
def test_claim_scope_rejects_malformed_shape(field: str, value: object) -> None:
    now = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    with pytest.raises(ValidationError):
        _claim_scope(now=now, **{field: value})


def test_claim_scope_matches_only_exact_job_identity() -> None:
    now = datetime(2026, 8, 28, 12, 0, tzinfo=UTC)
    scope = _claim_scope(now=now)
    matching = {
        "job_id": 101,
        "repository": "belilovsky/qazagents",
        "head_sha": "a" * 40,
        "profile": "qdev-ci",
    }
    assert claim_scope_matches_job(matching, scope)
    for key, value in (
        ("job_id", 999),
        ("repository", "belilovsky/other"),
        ("head_sha", "b" * 40),
        ("profile", "qdev-ci-browser"),
    ):
        foreign = matching | {key: value}
        assert not claim_scope_matches_job(foreign, scope)
