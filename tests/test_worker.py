from __future__ import annotations

from qdev_runner.settings import WorkerSettings
from qdev_runner.worker import Worker


def test_container_command_has_no_host_socket() -> None:
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
            buildkit_image="buildkit:test",
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
    assert command[-1] == "runner:test"


def test_docker_profile_gets_isolated_rootless_buildkit() -> None:
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
            buildkit_image="buildkit:test",
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
    buildkit_command = " ".join(worker.buildkit_command(job))
    assert "BUILDKIT_HOST=unix:///run/buildkit/buildkitd.sock" in runner_command
    assert "/var/run/docker.sock" not in runner_command
    assert "--privileged" not in buildkit_command
    assert "--device /dev/fuse" in buildkit_command
    assert "buildkit:test" in buildkit_command
