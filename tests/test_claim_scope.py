from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qdev_runner.claim_scope import ClaimScopeError, resolve_bound_claim_scope, resolve_claim_scope


def write_scope(path: Path, *, expires_at: datetime, head_sha: str = "a" * 40) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "claim-scope-v1",
                "scopes": [
                    {
                        "scope_id": "maturity-20260828",
                        "worker_name": "qdev-maturity-primary",
                        "tier": "primary",
                        "repository": "belilovsky/qazagents",
                        "head_sha": head_sha,
                        "expires_at": expires_at.isoformat(),
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


def test_resolve_scope_requires_exact_worker_tier_and_profiles(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes.json"
    now = datetime.now(UTC)
    write_scope(path, expires_at=now + timedelta(minutes=10))

    scope = resolve_claim_scope(
        path,
        "maturity-20260828",
        "qdev-maturity-primary",
        "primary",
        ("qdev-ci", "qdev-ci-docker"),
        now=now,
    )

    assert scope is not None
    assert scope.permits(100, "belilovsky/qazagents", "a" * 40, "qdev-ci")
    assert not scope.permits(100, "belilovsky/qazagents", "b" * 40, "qdev-ci")
    assert not scope.permits(100, "belilovsky/qazagents", "a" * 40, "qdev-ci-docker")
    with pytest.raises(ClaimScopeError, match="worker identity"):
        resolve_claim_scope(
            path,
            "maturity-20260828",
            "ordinary-primary",
            "primary",
            ("qdev-ci", "qdev-ci-docker"),
            now=now,
        )
    with pytest.raises(ClaimScopeError, match="profiles"):
        resolve_claim_scope(
            path,
            "maturity-20260828",
            "qdev-maturity-primary",
            "primary",
            ("qdev-ci",),
            now=now,
        )
    with pytest.raises(ClaimScopeError, match="profiles"):
        resolve_claim_scope(
            path,
            "maturity-20260828",
            "qdev-maturity-primary",
            "primary",
            ("qdev-ci", "qdev-ci-docker", "qdev-ci-browser"),
            now=now,
        )


def test_scope_expiry_absence_and_malformed_document_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes.json"
    now = datetime.now(UTC)
    write_scope(path, expires_at=now - timedelta(seconds=1))

    with pytest.raises(ClaimScopeError, match="expired"):
        resolve_claim_scope(
            path,
            "maturity-20260828",
            "qdev-maturity-primary",
            "primary",
            ("qdev-ci", "qdev-ci-docker"),
            now=now,
        )
    with pytest.raises(ClaimScopeError, match="absent"):
        resolve_claim_scope(
            path,
            "not-present",
            "qdev-maturity-primary",
            "primary",
            ("qdev-ci", "qdev-ci-docker"),
            now=now,
        )
    path.write_text("not-json", encoding="utf-8")
    with pytest.raises(ClaimScopeError, match="unreadable"):
        resolve_claim_scope(
            path,
            "maturity-20260828",
            "qdev-maturity-primary",
            "primary",
            ("qdev-ci", "qdev-ci-docker"),
            now=now,
        )


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("repository", "belilovsky/other", "repository is not allowlisted"),
        ("worker_name", "../worker-primary", "worker_name contains unsafe"),
        ("worker_name", "worker-reserve", "worker_name must end with its tier"),
        ("head_sha", "A" * 40, "head_sha must be a lowercase"),
    ],
)
def test_scope_rejects_identity_and_path_traversal(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    path = tmp_path / "claim-scopes.json"
    now = datetime.now(UTC)
    document = {
        "schema": "claim-scope-v1",
        "scopes": [
            {
                "scope_id": "maturity-20260828",
                "worker_name": "qdev-maturity-primary",
                "tier": "primary",
                "repository": "belilovsky/qazagents",
                "head_sha": "a" * 40,
                "expires_at": (now + timedelta(minutes=5)).isoformat(),
                "jobs": [
                    {"job_id": 100, "profile": "qdev-ci"},
                    {"job_id": 101, "profile": "qdev-ci-docker"},
                ],
            }
        ],
    }
    document["scopes"][0][field] = value
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ClaimScopeError, match=message):
        resolve_claim_scope(
            path,
            "maturity-20260828",
            "qdev-maturity-primary",
            "primary",
            ("qdev-ci", "qdev-ci-docker"),
            now=now,
        )


def test_scope_requires_exact_two_jobs_profiles_and_short_expiry(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes.json"
    now = datetime.now(UTC)
    document = json.loads("{}")

    def write_jobs(jobs: list[dict[str, object]], expires_at: datetime) -> None:
        document.update(
            {
                "schema": "claim-scope-v1",
                "scopes": [
                    {
                        "scope_id": "maturity-20260828",
                        "worker_name": "qdev-maturity-primary",
                        "tier": "primary",
                        "repository": "belilovsky/qazagents",
                        "head_sha": "a" * 40,
                        "expires_at": expires_at.isoformat(),
                        "jobs": jobs,
                    }
                ],
            }
        )
        path.write_text(json.dumps(document), encoding="utf-8")

    write_jobs([{"job_id": 100, "profile": "qdev-ci"}], now + timedelta(minutes=5))
    with pytest.raises(ClaimScopeError, match="exactly two"):
        resolve_claim_scope(
            path,
            "maturity-20260828",
            "qdev-maturity-primary",
            "primary",
            ("qdev-ci", "qdev-ci-docker"),
            now=now,
        )

    write_jobs(
        [{"job_id": 100, "profile": "qdev-ci"}, {"job_id": 101, "profile": "qdev-ci"}],
        now + timedelta(minutes=5),
    )
    with pytest.raises(ClaimScopeError, match="cover both expected"):
        resolve_claim_scope(
            path,
            "maturity-20260828",
            "qdev-maturity-primary",
            "primary",
            ("qdev-ci", "qdev-ci-docker"),
            now=now,
        )

    write_jobs(
        [{"job_id": 100, "profile": "qdev-ci"}, {"job_id": 101, "profile": "qdev-ci-docker"}],
        now + timedelta(minutes=16),
    )
    with pytest.raises(ClaimScopeError, match="15 minute"):
        resolve_claim_scope(
            path,
            "maturity-20260828",
            "qdev-maturity-primary",
            "primary",
            ("qdev-ci", "qdev-ci-docker"),
            now=now,
        )


def test_unscoped_workers_preserve_existing_fifo_behavior(tmp_path: Path) -> None:
    path = tmp_path / "no-claim-scopes.json"

    assert (
        resolve_claim_scope(
            path,
            None,
            "ordinary-primary",
            "primary",
            ("qdev-ci",),
        )
        is None
    )


def test_certificate_bound_scope_requires_exact_lowercase_fingerprint(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes.json"
    now = datetime.now(UTC)
    write_scope(path, expires_at=now + timedelta(minutes=10))
    document = json.loads(path.read_text(encoding="utf-8"))
    document["scopes"][0]["worker_certificate_sha256"] = "a" * 64
    path.write_text(json.dumps(document), encoding="utf-8")

    scope = resolve_claim_scope(
        path,
        "maturity-20260828",
        "qdev-maturity-primary",
        "primary",
        ("qdev-ci", "qdev-ci-docker"),
        now=now,
    )
    assert scope is not None
    assert scope.certificate_matches("a" * 64)
    assert not scope.certificate_matches("A" * 64)
    assert not scope.certificate_matches("b" * 64)
    bound = resolve_bound_claim_scope(
        path,
        "maturity-20260828",
        worker_name="qdev-maturity-primary",
        job_id=100,
        repository="belilovsky/qazagents",
        head_sha="a" * 40,
        profile="qdev-ci",
    )
    assert bound.scope_id == scope.scope_id

    document["scopes"][0]["worker_certificate_sha256"] = "A" * 64
    path.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ClaimScopeError, match="lowercase SHA-256"):
        resolve_claim_scope(
            path,
            "maturity-20260828",
            "qdev-maturity-primary",
            "primary",
            ("qdev-ci", "qdev-ci-docker"),
            now=now,
        )


def test_bound_scope_remains_verifiable_after_admission_expiry(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes.json"
    write_scope(path, expires_at=datetime.now(UTC) - timedelta(seconds=1))

    scope = resolve_bound_claim_scope(
        path,
        "maturity-20260828",
        worker_name="qdev-maturity-primary",
        job_id=101,
        repository="belilovsky/qazagents",
        head_sha="a" * 40,
        profile="qdev-ci-docker",
    )

    assert scope.scope_id == "maturity-20260828"
