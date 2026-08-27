from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qdev_runner.claim_scope import ClaimScopeError, resolve_claim_scope


def write_scope(path: Path, *, expires_at: datetime, head_sha: str = "a" * 40) -> None:
    path.write_text(
        json.dumps(
            {
                "schema": "qdev-runner-claim-scopes-v1",
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


def test_unscoped_workers_preserve_existing_fifo_behavior(tmp_path: Path) -> None:
    path = tmp_path / "no-claim-scopes.json"

    assert resolve_claim_scope(
        path,
        None,
        "ordinary-primary",
        "primary",
        ("qdev-ci",),
    ) is None
