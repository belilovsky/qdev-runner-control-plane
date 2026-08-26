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
