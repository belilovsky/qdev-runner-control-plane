from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from qdev_runner.capacity import Capacity
from qdev_runner.settings import WorkerSettings
from qdev_runner.worker import Worker


def test_container_command_has_no_host_socket_or_credentials(tmp_path: Path) -> None:
    worker = Worker(
        WorkerSettings(
            broker_url="https://worker.ci.qdev.run",
            worker_token="token",
            worker_name="worker-1",
            tier="primary",
            profiles=("qdev-ci",),
            concurrency=1,
            poll_seconds=3,
            container_engine="docker",
            runner_images={"qdev-ci": "runner:test"},
            docker_sidecar_image="docker:dind-test",
            rootlesskit_path="/usr/bin/rootlesskit",
            buildkitd_path="/opt/buildkitd",
            buildctl_path="/opt/buildctl",
            buildkit_root=tmp_path,
        )
    )
    command = worker.container_command(
        {
            "job_id": 1,
            "repository": "belilovsky/repo",
            "head_sha": "a" * 40,
            "runner_name": "runner-1",
            "jit_config": "encoded",
            "profile": {
                "name": "qdev-ci",
                "cpu": 1,
                "memory_mb": 3072,
                "pids_limit": 512,
                "timeout_minutes": 45,
            },
            "artifact": {"base_url": "https://ci.qdev.run/artifacts", "token": "token"},
        }
    )
    joined = " ".join(command)
    assert "/var/run/docker.sock" not in joined
    assert "--cap-drop ALL" in joined
    assert "no-new-privileges:true" in joined
    assert "QDEV_JIT_CONFIG" not in joined
    assert "QDEV_ARTIFACT_TOKEN" not in joined
    assert "--env-file" in joined
    assert command[-1] == "runner:test"


def test_runner_environment_is_job_scoped_and_private(tmp_path: Path) -> None:
    worker = Worker(
        WorkerSettings(
            broker_url="https://worker.ci.qdev.run",
            worker_token="token",
            worker_name="worker-1",
            tier="primary",
            profiles=("qdev-ci",),
            concurrency=1,
            poll_seconds=3,
            container_engine="docker",
            runner_images={"qdev-ci": "runner:test"},
            docker_sidecar_image="docker:dind-test",
            rootlesskit_path="/usr/bin/rootlesskit",
            buildkitd_path="/opt/buildkitd",
            buildctl_path="/opt/buildctl",
            buildkit_root=tmp_path,
        )
    )
    job = {
        "job_id": 1,
        "repository": "belilovsky/repo",
        "head_sha": "a" * 40,
        "runner_name": "runner-1",
        "jit_config": "encoded",
        "artifact": {"base_url": "https://ci.qdev.run/artifacts", "token": "token"},
        "registry": {
            "url": "registry.ci.qdev.run",
            "username": "qdev",
            "password": "registry-token",
        },
    }
    path = worker.write_runner_environment(job)
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert "QDEV_JIT_CONFIG=encoded" in path.read_text(encoding="utf-8")
    assert "QDEV_ARTIFACT_TOKEN=token" in path.read_text(encoding="utf-8")
    assert "QDEV_REGISTRY_URL=registry.ci.qdev.run" in path.read_text(encoding="utf-8")
    assert "QDEV_REGISTRY_USERNAME=qdev" in path.read_text(encoding="utf-8")
    assert "QDEV_REGISTRY_PASSWORD=registry-token" in path.read_text(encoding="utf-8")


def test_docker_profile_gets_isolated_job_docker_and_buildkit() -> None:
    worker = Worker(
        WorkerSettings(
            broker_url="https://worker.ci.qdev.run",
            worker_token="token",
            worker_name="worker-1",
            tier="primary",
            profiles=("qdev-ci-docker",),
            concurrency=1,
            poll_seconds=3,
            container_engine="docker",
            runner_images={"qdev-ci-docker": "runner-docker:test"},
            docker_sidecar_image="docker:dind-test",
            rootlesskit_path="/usr/bin/rootlesskit",
            buildkitd_path="/opt/buildkitd",
            buildctl_path="/opt/buildctl",
            buildkit_root=Path("/var/lib/qdev-runner-worker/jobs"),
        )
    )
    job = {
        "job_id": 1,
        "repository": "belilovsky/repo",
        "head_sha": "a" * 40,
        "runner_name": "runner-1",
        "jit_config": "encoded",
        "profile": {
            "name": "qdev-ci-docker",
            "cpu": 2,
            "memory_mb": 5120,
            "pids_limit": 1024,
            "timeout_minutes": 90,
        },
        "artifact": {"base_url": "https://ci.qdev.run/artifacts", "token": "token"},
    }
    runner_command = " ".join(worker.container_command(job))
    sidecar_command = " ".join(worker.docker_sidecar_command(job))
    assert "DOCKER_HOST=unix:///run/qdev-docker/docker.sock" in runner_command
    assert "DOCKER_BUILDKIT=1" in runner_command
    assert "/var/run/docker.sock" not in runner_command
    assert "--network container:runner-1-docker" in runner_command
    assert "--privileged" in sidecar_command
    assert "/var/run/docker.sock" not in sidecar_command
    assert "qdev-ci-egress" in sidecar_command
    assert "docker:dind-test" in sidecar_command
    assert worker.docker_sidecar_remove_command("runner-1-docker") == [
        "docker",
        "rm",
        "--force",
        "--volumes",
        "runner-1-docker",
    ]
    assert worker.runner_remove_command("runner-1") == [
        "docker",
        "rm",
        "--force",
        "--volumes",
        "runner-1",
    ]


def _scoped_worker(scope_path: Path) -> Worker:
    return Worker(
        WorkerSettings(
            broker_url="https://worker.ci.qdev.run",
            worker_token="token",
            worker_name="qdev-recovery-primary",
            tier="primary",
            profiles=("qdev-ci",),
            concurrency=1,
            poll_seconds=3,
            container_engine="docker",
            runner_images={"qdev-ci": "runner:test"},
            docker_sidecar_image="docker:dind-test",
            rootlesskit_path="/usr/bin/rootlesskit",
            buildkitd_path="/opt/buildkitd",
            buildctl_path="/opt/buildctl",
            buildkit_root=scope_path.parent,
            claim_scope_path=scope_path,
        )
    )


@pytest.mark.asyncio
async def test_worker_sends_scope_from_private_file_and_fails_closed(tmp_path: Path) -> None:
    scope_path = tmp_path / "claim-scope.json"
    scope_path.write_text(json.dumps({"schema": "claim-scope-v1"}), encoding="utf-8")
    worker = _scoped_worker(scope_path)
    await worker.client.aclose()
    captured: dict[str, object] = {}

    async def handler(request: httpx.Request) -> httpx.Response:
        captured.update(json.loads(request.content))
        return httpx.Response(204, request=request)

    worker.client = httpx.AsyncClient(
        transport=httpx.MockTransport(handler),
        base_url="https://worker.ci.qdev.run",
    )
    capacity = Capacity(True, 20, 100, 8, 0.1, 0, 2, ())
    assert await worker.claim(capacity) is None
    assert captured["scope"] == {"schema": "claim-scope-v1"}

    scope_path.write_text("[]", encoding="utf-8")
    with pytest.raises(RuntimeError, match="JSON object"):
        await worker.claim(capacity)
    await worker.close()
