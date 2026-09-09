from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qdev_runner.claim_scope import (
    MANAGED_EXACT_CANDIDATE_FIFO_EXCEPTION,
    SCHEMA_V1,
    SCHEMA_V2,
    ClaimScope,
    ClaimScopeError,
    ScopedFifoSkip,
    ScopedJob,
    load_claim_scopes,
    resolve_bound_claim_scope,
    resolve_claim_scope,
    upsert_claim_scope,
)


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
    with pytest.raises(ClaimScopeError, match="900 second"):
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


def test_v2_scope_binds_the_complete_provider_tuple(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes-v2.json"
    now = datetime.now(UTC)
    document = {
        "schema": "claim-scope-v2",
        "scopes": [
            {
                "scope_id": "portfolio-canary-01",
                "worker_name": "qdev-portfolio-primary",
                "tier": "primary",
                "host": "controller-host-01",
                "runner": "qdev-portfolio-primary",
                "correlation_id": "corr-portfolio-canary-01",
                "expires_at": (now + timedelta(minutes=10)).isoformat(),
                "jobs": [
                    {
                        "repository": "belilovsky/avds",
                        "run_id": 33311126489,
                        "job_id": 99269988940,
                        "attempt": 1,
                        "exact_sha": "b" * 40,
                        "profile": "qdev-ci-docker",
                    }
                ],
            }
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    scope = resolve_claim_scope(
        path,
        "portfolio-canary-01",
        "qdev-portfolio-primary",
        "primary",
        ("qdev-ci", "qdev-ci-docker"),
        now=now,
    )

    assert scope is not None
    assert scope.permits(
        99269988940,
        "belilovsky/avds",
        "b" * 40,
        "qdev-ci-docker",
        run_id=33311126489,
        attempt=1,
    )
    assert not scope.permits(
        99269988940,
        "belilovsky/avds",
        "b" * 40,
        "qdev-ci-docker",
        run_id=33311126489,
        attempt=2,
    )
    assert not scope.permits(
        99269988940,
        "belilovsky/avds",
        "c" * 40,
        "qdev-ci-docker",
        run_id=33311126489,
        attempt=1,
    )
    bound = resolve_bound_claim_scope(
        path,
        "portfolio-canary-01",
        worker_name="qdev-portfolio-primary",
        job_id=99269988940,
        repository="belilovsky/avds",
        head_sha="b" * 40,
        profile="qdev-ci-docker",
        run_id=33311126489,
        attempt=1,
    )
    assert bound.host == "controller-host-01"


def test_managed_exact_candidate_fifo_exception_is_narrow_and_round_trips(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes-v2.json"
    now = datetime.now(UTC)
    sha = "b" * 40
    document = {
        "schema": "claim-scope-v2",
        "scopes": [
            {
                "scope_id": "qgeo-recovery-01",
                "worker_name": "qgeo-primary",
                "tier": "primary",
                "host": "controller-host-01",
                "runner": "qgeo-primary",
                "correlation_id": "corr-qgeo-recovery-01",
                "fifo_exception": MANAGED_EXACT_CANDIDATE_FIFO_EXCEPTION,
                "expires_at": (now + timedelta(minutes=10)).isoformat(),
                "jobs": [
                    {
                        "repository": "belilovsky/qazgeo",
                        "run_id": 1,
                        "job_id": 2,
                        "attempt": 1,
                        "exact_sha": sha,
                        "profile": "qdev-ci",
                    }
                ],
            }
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    scope = resolve_claim_scope(
        path, "qgeo-recovery-01", "qgeo-primary", "primary", ("qdev-ci",), now=now
    )
    assert scope is not None
    assert scope.fifo_exception == MANAGED_EXACT_CANDIDATE_FIFO_EXCEPTION
    upsert_claim_scope(path, scope)
    assert json.loads(path.read_text(encoding="utf-8"))["scopes"][0]["fifo_exception"] == (
        MANAGED_EXACT_CANDIDATE_FIFO_EXCEPTION
    )


def test_managed_exact_candidate_fifo_exception_rejects_foreign_jobs(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes-v2.json"
    now = datetime.now(UTC)
    document = {
        "schema": "claim-scope-v2",
        "scopes": [
            {
                "scope_id": "qgeo-recovery-02",
                "worker_name": "qgeo-primary",
                "tier": "primary",
                "host": "controller-host-01",
                "runner": "qgeo-primary",
                "correlation_id": "corr-qgeo-recovery-02",
                "fifo_exception": MANAGED_EXACT_CANDIDATE_FIFO_EXCEPTION,
                "expires_at": (now + timedelta(minutes=10)).isoformat(),
                "jobs": [
                    {
                        "repository": "belilovsky/qazgeo",
                        "run_id": 1,
                        "job_id": 2,
                        "attempt": 1,
                        "exact_sha": "b" * 40,
                        "profile": "qdev-ci",
                    },
                    {
                        "repository": "belilovsky/qazlake",
                        "run_id": 3,
                        "job_id": 4,
                        "attempt": 1,
                        "exact_sha": "b" * 40,
                        "profile": "qdev-ci-docker",
                    },
                ],
            }
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ClaimScopeError, match="requires one QGeo SHA"):
        load_claim_scopes(path)


def test_upsert_rejects_new_managed_scope_with_foreign_jobs(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes-v2.json"
    scope = ClaimScope(
        scope_id="qgeo-recovery-03",
        worker_name="qgeo-primary",
        tier="primary",
        repository="belilovsky/qazgeo",
        head_sha="b" * 40,
        expires_at=datetime.now(UTC) + timedelta(minutes=10),
        jobs=(
            ScopedJob(
                job_id=2,
                repository="belilovsky/qazgeo",
                run_id=1,
                attempt=1,
                exact_sha="b" * 40,
                profile="qdev-ci",
            ),
            ScopedJob(
                job_id=4,
                repository="belilovsky/qazlake",
                run_id=3,
                attempt=1,
                exact_sha="b" * 40,
                profile="qdev-ci-docker",
            ),
        ),
        schema=SCHEMA_V2,
        host="controller-host-01",
        runner="qgeo-primary",
        correlation_id="corr-qgeo-recovery-03",
        fifo_exception=MANAGED_EXACT_CANDIDATE_FIFO_EXCEPTION,
    )

    with pytest.raises(ClaimScopeError, match="requires one QGeo SHA"):
        upsert_claim_scope(path, scope)
    assert not path.exists()


def test_upsert_rejects_new_v1_scope_but_keeps_legacy_scopes_readable(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes.json"
    write_scope(path, expires_at=datetime.now(UTC) + timedelta(minutes=10))
    legacy = load_claim_scopes(path)["maturity-20260828"]
    assert legacy.schema == SCHEMA_V1

    with pytest.raises(ClaimScopeError, match="must use claim-scope-v2"):
        upsert_claim_scope(path, legacy)

    assert load_claim_scopes(path)["maturity-20260828"].schema == SCHEMA_V1


def test_v2_scope_rejects_missing_or_duplicate_immutable_tuple(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes-v2.json"
    now = datetime.now(UTC)
    document = {
        "schema": "claim-scope-v2",
        "scopes": [
            {
                "scope_id": "portfolio-canary-02",
                "worker_name": "qdev-portfolio-primary",
                "tier": "primary",
                "host": "controller-host-01",
                "runner": "qdev-portfolio-primary",
                "correlation_id": "corr-portfolio-canary-02",
                "expires_at": (now + timedelta(minutes=10)).isoformat(),
                "jobs": [
                    {
                        "repository": "belilovsky/avds",
                        "run_id": 33311126489,
                        "job_id": 99269988940,
                        "attempt": 1,
                        "exact_sha": "b" * 40,
                        "profile": "qdev-ci-docker",
                    },
                    {
                        "repository": "belilovsky/avds",
                        "run_id": 33311126489,
                        "job_id": 99269988940,
                        "attempt": 1,
                        "exact_sha": "b" * 40,
                        "profile": "qdev-ci-docker",
                    },
                ],
            }
        ],
    }
    path.write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(ClaimScopeError, match="job IDs must be unique"):
        resolve_claim_scope(
            path,
            "portfolio-canary-02",
            "qdev-portfolio-primary",
            "primary",
            ("qdev-ci-docker",),
            now=now,
        )


def test_upsert_v2_scope_preserves_legacy_scope_and_exact_binding(tmp_path: Path) -> None:
    path = tmp_path / "claim-scopes.json"
    now = datetime.now(UTC)
    write_scope(path, expires_at=now + timedelta(minutes=10))
    scope = ClaimScope(
        scope_id="portfolio-primary",
        worker_name="qdev-maturity-primary",
        tier="primary",
        repository="belilovsky/example",
        head_sha="b" * 40,
        expires_at=now + timedelta(minutes=10),
        jobs=(
            ScopedJob(
                job_id=222,
                profile="qdev-ci-docker",
                repository="belilovsky/example",
                run_id=71,
                attempt=1,
                exact_sha="b" * 40,
            ),
        ),
        worker_certificate_sha256="c" * 64,
        schema=SCHEMA_V2,
        host="srv1879763-light-primary",
        runner="qdev-runner-01",
        correlation_id="correlation-1",
        fifo_skipped=(
            ScopedFifoSkip(
                job_id=221,
                profile="qdev-ci-docker",
                repository="belilovsky/qazposter",
                run_id=70,
                attempt=1,
                exact_sha="a" * 40,
                managed_registry_entry="qazposter",
                reason="admin-platform-candidate-not-active",
            ),
        ),
    )

    upsert_claim_scope(path, scope)

    document = json.loads(path.read_text(encoding="utf-8"))
    assert document["schema"] == "qdev-runner-claim-scopes-v2"
    assert set(load_claim_scopes(path)) == {"maturity-20260828", "portfolio-primary"}
    legacy = resolve_claim_scope(
        path,
        "maturity-20260828",
        "qdev-maturity-primary",
        "primary",
        ("qdev-ci", "qdev-ci-docker"),
        now=now,
    )
    assert legacy is not None
    bound = resolve_bound_claim_scope(
        path,
        "portfolio-primary",
        worker_name="qdev-maturity-primary",
        job_id=222,
        repository="belilovsky/example",
        head_sha="b" * 40,
        profile="qdev-ci-docker",
        run_id=71,
        attempt=1,
    )
    assert bound.runner == "qdev-runner-01"
    assert bound.skips(
        221,
        "belilovsky/qazposter",
        "a" * 40,
        "qdev-ci-docker",
        run_id=70,
        attempt=1,
    )
    assert not bound.skips(
        221,
        "belilovsky/qazposter",
        "a" * 40,
        "qdev-ci-docker",
        run_id=70,
        attempt=2,
    )
