from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from qdev_runner.capacity import Capacity
from qdev_runner.operations import OperationStore
from qdev_runner.settings import WorkerSettings
from qdev_runner.worker import Worker


class CompletedRunnerProcess:
    returncode = 0

    async def communicate(self) -> tuple[bytes, None]:
        return b"runner completed", None

    async def wait(self) -> int:
        return self.returncode

    def send_signal(self, _: int) -> None:
        raise AssertionError("a valid signed override must not stop this runner")

    def kill(self) -> None:
        raise AssertionError("a valid signed override must not kill this runner")


class ExpiringRunnerProcess:
    def __init__(self) -> None:
        self.returncode: int | None = None
        self._done = asyncio.Event()

    async def communicate(self) -> tuple[bytes, None]:
        await self._done.wait()
        return b"runner stopped after directive expiry", None

    async def wait(self) -> int:
        await self._done.wait()
        assert self.returncode is not None
        return self.returncode

    def send_signal(self, _: int) -> None:
        self.returncode = 143
        self._done.set()

    def kill(self) -> None:
        raise AssertionError("a graceful expiry must not kill this runner")


def _worker(tmp_path: Path) -> Worker:
    return Worker(
        WorkerSettings(
            broker_url="https://worker.ci.qdev.run",
            worker_token="token",
            worker_name="srv1879763-light-primary",
            tier="primary",
            profiles=("qdev-ci", "qdev-ci-docker"),
            concurrency=1,
            poll_seconds=3,
            container_engine="docker",
            runner_images={
                "qdev-ci": "runner:test",
                "qdev-ci-docker": "runner-docker:test",
            },
            docker_sidecar_image="docker:dind-test",
            rootlesskit_path="/usr/bin/rootlesskit",
            buildkitd_path="/opt/buildkitd",
            buildctl_path="/opt/buildctl",
            buildkit_root=tmp_path,
            min_disk_free_gib=30,
            max_disk_used_pct=85,
            capacity_directive_key="worker-signing-key",
        )
    )


def _disk_blocked_raw() -> Capacity:
    return Capacity(
        allowed=True,
        disk_used_pct=88,
        disk_free_gib=20,
        memory_available_gib=8,
        load_15=0.2,
        cpu_psi_avg10=0,
        cpus=4,
        blockers=(),
    )


def _allowed_raw() -> Capacity:
    return Capacity(
        allowed=True,
        disk_used_pct=50,
        disk_free_gib=100,
        memory_available_gib=8,
        load_15=0.2,
        cpu_psi_avg10=0,
        cpus=4,
        blockers=(),
    )


async def test_worker_applies_only_valid_disk_scoped_override(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    store = OperationStore(
        tmp_path / "operations",
        worker_signing_key="worker-signing-key",
        receipt_signing_key="receipt-signing-key",
    )
    directive = store.create_capacity_override(
        worker_name="srv1879763-light-primary",
        repository="belilovsky/qazshield",
        head_sha="a" * 40,
        profiles=("qdev-ci-docker",),
        min_disk_free_gib=4.5,
        max_disk_used_pct=95,
        owner="qdev-fleet-operations",
        reason="bounded FIFO recovery",
        duration_seconds=900,
    )
    try:
        state = worker.admission_state(
            raw=_disk_blocked_raw(),
            directive_payload=directive.model_dump(mode="json", by_alias=True),
        )
        assert not state.baseline.allowed
        assert set(state.baseline.blockers) == {"disk_free_gib", "disk_used_pct"}
        assert state.effective.allowed
        assert state.profiles == ("qdev-ci-docker",)
        assert state.min_disk_free_gib == 4.5
        assert state.max_disk_used_pct == 95
        assert state.directive_id == directive.operation_id
        assert state.directive_repository == "belilovsky/qazshield"
        assert state.directive_head_sha == "a" * 40
        assert state.directive_expires_at is not None
    finally:
        await worker.close()


async def test_worker_uses_validated_override_for_running_job_floor(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    store = OperationStore(
        tmp_path / "operations",
        worker_signing_key="worker-signing-key",
        receipt_signing_key="receipt-signing-key",
    )
    directive = store.create_capacity_override(
        worker_name="srv1879763-light-primary",
        repository="belilovsky/qazshield",
        head_sha="a" * 40,
        profiles=("qdev-ci",),
        min_disk_free_gib=4.5,
        max_disk_used_pct=95,
        owner="qdev-fleet-operations",
        reason="bounded FIFO recovery",
        duration_seconds=900,
    )
    try:
        admission = worker.admission_state(
            raw=_disk_blocked_raw(),
            directive_payload=directive.model_dump(mode="json", by_alias=True),
        )
        assert admission.effective.allowed
        worker.capacity = _disk_blocked_raw
        output, detail = await worker.wait_for_runner(
            CompletedRunnerProcess(),  # type: ignore[arg-type]
            {"job_id": 123},
            timeout=60,
            admission=admission,
        )
        assert output == b"runner completed"
        assert detail == ""
    finally:
        await worker.close()


async def test_worker_stops_job_when_capacity_override_expires(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    store = OperationStore(
        tmp_path / "operations",
        worker_signing_key="worker-signing-key",
        receipt_signing_key="receipt-signing-key",
    )
    directive = store.create_capacity_override(
        worker_name="srv1879763-light-primary",
        repository="belilovsky/qazshield",
        head_sha="a" * 40,
        profiles=("qdev-ci",),
        min_disk_free_gib=4.5,
        max_disk_used_pct=95,
        owner="qdev-fleet-operations",
        reason="bounded FIFO recovery",
        duration_seconds=900,
    )
    try:
        admission = worker.admission_state(
            raw=_disk_blocked_raw(),
            directive_payload=directive.model_dump(mode="json", by_alias=True),
        )
        expired = replace(admission, directive_expires_at=datetime.now(UTC))
        output, detail = await worker.wait_for_runner(
            ExpiringRunnerProcess(),  # type: ignore[arg-type]
            {"job_id": 123},
            timeout=60,
            admission=expired,
        )
        assert output == b"runner stopped after directive expiry"
        assert detail == "capacity override expired during running job"
    finally:
        await worker.close()


async def test_worker_rejects_tampered_or_non_disk_override(tmp_path: Path) -> None:
    worker = _worker(tmp_path)
    store = OperationStore(
        tmp_path / "operations",
        worker_signing_key="worker-signing-key",
        receipt_signing_key="receipt-signing-key",
    )
    directive = store.create_capacity_override(
        worker_name="srv1879763-light-primary",
        repository="belilovsky/qazshield",
        head_sha="a" * 40,
        profiles=("qdev-ci-docker",),
        min_disk_free_gib=4.5,
        max_disk_used_pct=95,
        owner="qdev-fleet-operations",
        reason="bounded FIFO recovery",
        duration_seconds=900,
    ).model_dump(mode="json", by_alias=True)
    try:
        tampered = worker.admission_state(
            raw=_disk_blocked_raw(),
            directive_payload=directive | {"min_disk_free_gib": 5.0},
        )
        assert not tampered.effective.allowed
        assert tampered.directive_id is None

        non_disk_raw = Capacity(
            allowed=True,
            disk_used_pct=88,
            disk_free_gib=20,
            memory_available_gib=1,
            load_15=0.2,
            cpu_psi_avg10=0,
            cpus=4,
            blockers=(),
        )
        non_disk = worker.admission_state(
            raw=non_disk_raw,
            directive_payload=directive,
        )
        assert not non_disk.effective.allowed
        assert "memory_available_gib" in non_disk.effective.blockers
        assert non_disk.directive_id is None
    finally:
        await worker.close()


async def test_worker_accepts_legacy_empty_heartbeat_response(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    worker = _worker(tmp_path)
    monkeypatch.setattr("qdev_runner.worker.measure_raw", _allowed_raw)

    async def legacy_controller(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/internal/v1/workers/heartbeat"
        return httpx.Response(status_code=204)

    await worker.client.aclose()
    worker.client = httpx.AsyncClient(
        base_url=worker.settings.broker_url,
        transport=httpx.MockTransport(legacy_controller),
    )
    try:
        state = await worker.heartbeat()
        assert state.directive_id is None
        assert state.profiles == worker.settings.profiles
    finally:
        await worker.close()


async def test_worker_claim_sends_verified_capacity_binding(tmp_path: Path) -> None:
    worker = _worker(tmp_path)

    async def controller(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/internal/v1/jobs/claim"
        payload = json.loads(request.content)
        assert payload["profiles"] == ["qdev-ci-docker"]
        assert payload["capacity_directive_id"] == "operation-123"
        assert payload["capacity_repository"] == "belilovsky/qazlake"
        assert payload["capacity_head_sha"] == "b" * 40
        return httpx.Response(status_code=204)

    await worker.client.aclose()
    worker.client = httpx.AsyncClient(
        base_url=worker.settings.broker_url,
        transport=httpx.MockTransport(controller),
    )
    try:
        claimed = await worker.claim(
            _allowed_raw(),
            profiles=("qdev-ci-docker",),
            min_disk_free_gib=4.5,
            capacity_directive_id="operation-123",
            capacity_repository="belilovsky/qazlake",
            capacity_head_sha="b" * 40,
        )
        assert claimed is None
    finally:
        await worker.close()
