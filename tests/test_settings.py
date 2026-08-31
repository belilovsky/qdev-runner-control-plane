from __future__ import annotations

import pytest

from qdev_runner.settings import WorkerSettings


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
    monkeypatch.delenv("QDEV_WORKER_TOKEN", raising=False)

    assert WorkerSettings.from_env().worker_token is None

    monkeypatch.delenv("QDEV_CLAIM_SCOPE_ID")
    with pytest.raises(RuntimeError, match="unscoped worker"):
        WorkerSettings.from_env()
