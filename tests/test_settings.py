from __future__ import annotations

from pathlib import Path

import pytest

from qdev_runner.settings import BrokerSettings, WorkerSettings


def set_broker_environment(
    monkeypatch: pytest.MonkeyPatch,
    *,
    surface: str,
) -> None:
    for name in (
        "QDEV_GITHUB_APP_ID",
        "QDEV_GITHUB_APP_PRIVATE_KEY",
        "QDEV_GITHUB_WEBHOOK_SECRET",
        "QDEV_WORKER_TOKEN",
        "QDEV_ARTIFACT_TOKEN_KEY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("QDEV_BROKER_SURFACE", surface)
    monkeypatch.setenv("QDEV_ARTIFACT_TOKEN_KEY", "artifact-key")


def test_public_broker_requires_only_public_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_broker_environment(monkeypatch, surface="public")
    monkeypatch.setenv("QDEV_GITHUB_WEBHOOK_SECRET", "webhook-secret")

    settings = BrokerSettings.from_env()

    assert settings.surface == "public"
    assert settings.webhook_secret == "webhook-secret"  # noqa: S105
    assert settings.worker_token is None
    assert settings.app_id is None
    assert settings.app_private_key_path is None
    assert settings.artifact_token_key == "artifact-key"  # noqa: S105


def test_internal_broker_requires_only_internal_authority(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    set_broker_environment(monkeypatch, surface="internal")
    monkeypatch.setenv("QDEV_GITHUB_APP_ID", "123")
    monkeypatch.setenv("QDEV_GITHUB_APP_PRIVATE_KEY", "/run/secrets/app.pem")
    monkeypatch.setenv("QDEV_WORKER_TOKEN", "worker-secret")

    settings = BrokerSettings.from_env()

    assert settings.surface == "internal"
    assert settings.webhook_secret == ""
    assert settings.worker_token == "worker-secret"  # noqa: S105
    assert settings.app_id == "123"
    assert settings.app_private_key_path == Path("/run/secrets/app.pem")
    assert settings.release_job_lease_ttl_seconds == 3600


@pytest.mark.parametrize("value", ["59", "86401"])
def test_release_job_lease_ttl_is_bounded(
    monkeypatch: pytest.MonkeyPatch,
    value: str,
) -> None:
    set_broker_environment(monkeypatch, surface="public")
    monkeypatch.setenv("QDEV_GITHUB_WEBHOOK_SECRET", "webhook-secret")
    monkeypatch.setenv("QDEV_RELEASE_JOB_LEASE_TTL_SECONDS", value)

    with pytest.raises(RuntimeError, match="must be between 60 and 86400"):
        BrokerSettings.from_env()


@pytest.mark.parametrize("surface", ["public", "internal"])
def test_production_broker_requires_separate_artifact_key(
    monkeypatch: pytest.MonkeyPatch,
    surface: str,
) -> None:
    set_broker_environment(monkeypatch, surface=surface)
    if surface == "public":
        monkeypatch.setenv("QDEV_GITHUB_WEBHOOK_SECRET", "webhook-secret")
    else:
        monkeypatch.setenv("QDEV_GITHUB_APP_ID", "123")
        monkeypatch.setenv("QDEV_GITHUB_APP_PRIVATE_KEY", "/run/secrets/app.pem")
        monkeypatch.setenv("QDEV_WORKER_TOKEN", "worker-secret")
    monkeypatch.delenv("QDEV_ARTIFACT_TOKEN_KEY")

    with pytest.raises(RuntimeError, match="QDEV_ARTIFACT_TOKEN_KEY"):
        BrokerSettings.from_env()


def set_required_runner_images(monkeypatch: pytest.MonkeyPatch) -> None:
    for name, digest in {
        "QDEV_RUNNER_IMAGE": "a",
        "QDEV_RUNNER_BROWSER_IMAGE": "b",
        "QDEV_RUNNER_DOCKER_IMAGE": "c",
        "QDEV_DOCKER_SIDECAR_IMAGE": "d",
    }.items():
        monkeypatch.setenv(name, f"registry.example/qdev/{name.lower()}@sha256:{digest * 64}")


def test_worker_tier_must_be_known(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QDEV_WORKER_NAME", "worker-standby")
    monkeypatch.setenv("QDEV_WORKER_TIER", "standby")
    with pytest.raises(RuntimeError, match="must be primary or reserve"):
        WorkerSettings.from_env()


def test_worker_name_must_match_tier(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("QDEV_WORKER_NAME", "mail-qdev-reserve")
    monkeypatch.setenv("QDEV_WORKER_TIER", "primary")
    with pytest.raises(RuntimeError, match="must end with -primary"):
        WorkerSettings.from_env()


def test_scoped_worker_can_omit_static_token_but_unscoped_worker_cannot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in {
        "QDEV_WORKER_NAME": "qdev-maturity-primary",
        "QDEV_WORKER_TIER": "primary",
        "QDEV_BROKER_URL": "https://worker.ci.qdev.run",
        "QDEV_CLAIM_SCOPE_ID": "maturity-20260831",
        "QDEV_MTLS_CA": "/var/lib/qdev-test/ca.pem",
        "QDEV_MTLS_CERT": "/var/lib/qdev-test/cert.pem",
        "QDEV_MTLS_KEY": "/var/lib/qdev-test/key.pem",
    }.items():
        monkeypatch.setenv(name, value)
    set_required_runner_images(monkeypatch)
    monkeypatch.delenv("QDEV_WORKER_TOKEN", raising=False)

    assert WorkerSettings.from_env().worker_token is None

    monkeypatch.delenv("QDEV_CLAIM_SCOPE_ID")
    with pytest.raises(RuntimeError, match="unscoped worker"):
        WorkerSettings.from_env()


def test_lower_runtime_capacity_gate_is_scoped_explicit_and_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in {
        "QDEV_WORKER_NAME": "qdev-maturity-primary",
        "QDEV_WORKER_TIER": "primary",
        "QDEV_BROKER_URL": "https://worker.ci.qdev.run",
        "QDEV_CLAIM_SCOPE_ID": "maturity-20260831",
        "QDEV_MTLS_CA": "/var/lib/qdev-test/ca.pem",
        "QDEV_MTLS_CERT": "/var/lib/qdev-test/cert.pem",
        "QDEV_MTLS_KEY": "/var/lib/qdev-test/key.pem",
        "QDEV_WORKER_MIN_FREE_GIB": "4",
        "QDEV_WORKER_MAX_DISK_USED_PCT": "90",
    }.items():
        monkeypatch.setenv(name, value)
    set_required_runner_images(monkeypatch)
    monkeypatch.delenv("QDEV_WORKER_TOKEN", raising=False)

    with pytest.raises(RuntimeError, match="scoped explicit override"):
        WorkerSettings.from_env()

    monkeypatch.setenv("QDEV_WORKER_ALLOW_RUNTIME_CAPACITY_OVERRIDE", "true")
    settings = WorkerSettings.from_env()
    assert settings.capacity_override_active is True
    assert settings.min_disk_free_gib == 4
    assert settings.max_disk_used_pct == 90

    monkeypatch.setenv("QDEV_WORKER_MIN_FREE_GIB", "3")
    with pytest.raises(RuntimeError, match="bounded range"):
        WorkerSettings.from_env()


def test_worker_settings_rejects_mutable_runner_image_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    for name, value in {
        "QDEV_WORKER_NAME": "qdev-maturity-primary",
        "QDEV_WORKER_TIER": "primary",
        "QDEV_BROKER_URL": "https://worker.ci.qdev.run",
        "QDEV_CLAIM_SCOPE_ID": "maturity-20260831",
        "QDEV_MTLS_CA": "/var/lib/qdev-test/ca.pem",
        "QDEV_MTLS_CERT": "/var/lib/qdev-test/cert.pem",
        "QDEV_MTLS_KEY": "/var/lib/qdev-test/key.pem",
    }.items():
        monkeypatch.setenv(name, value)
    set_required_runner_images(monkeypatch)
    monkeypatch.setenv("QDEV_RUNNER_IMAGE", "registry.ci.qdev.run/qdev/actions-runner:2.336.0-r2")

    with pytest.raises(RuntimeError, match="QDEV_RUNNER_IMAGE must be an OCI"):
        WorkerSettings.from_env()
