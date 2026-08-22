from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import ssl
from pathlib import Path
from typing import Any, cast

import httpx

from .capacity import measure
from .settings import WorkerSettings

LOGGER = logging.getLogger("qdev-runner-worker")


class Worker:
    def __init__(self, settings: WorkerSettings) -> None:
        self.settings = settings
        tls: ssl.SSLContext | bool = True
        if settings.mtls_ca and settings.mtls_cert and settings.mtls_key:
            tls = ssl.create_default_context(cafile=settings.mtls_ca)
            tls.load_cert_chain(settings.mtls_cert, settings.mtls_key)
        self.client = httpx.AsyncClient(
            base_url=settings.broker_url,
            headers={"X-QDev-Worker-Token": settings.worker_token},
            timeout=45,
            verify=tls,
        )
        self.semaphore = asyncio.Semaphore(settings.concurrency)
        self.tasks: set[asyncio.Task[None]] = set()
        self.docker_sidecars: dict[int, str] = {}
        self.stopping = asyncio.Event()

    async def close(self) -> None:
        await self.client.aclose()

    async def heartbeat(self) -> None:
        capacity = measure()
        await self.client.post(
            "/internal/v1/workers/heartbeat",
            json={
                "worker_name": self.settings.worker_name,
                "tier": self.settings.tier,
                "profiles": self.settings.profiles,
                "active_jobs": len(self.tasks),
                "detail": capacity.__dict__,
            },
        )

    async def claim(self) -> dict[str, Any] | None:
        response = await self.client.post(
            "/internal/v1/jobs/claim",
            json={
                "worker_name": self.settings.worker_name,
                "tier": self.settings.tier,
                "profiles": self.settings.profiles,
            },
        )
        if response.status_code == 204:
            return None
        response.raise_for_status()
        return cast(dict[str, Any], response.json())

    def container_command(self, job: dict[str, Any]) -> list[str]:
        profile = job["profile"]
        profile_name = str(profile["name"])
        try:
            image = self.settings.runner_images[profile_name]
        except KeyError as error:
            raise RuntimeError(f"no runner image configured for profile: {profile_name}") from error
        memory = f"{int(profile['memory_mb'])}m"
        name = job["runner_name"]
        command = [
            self.settings.container_engine,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            (
                f"container:{self.docker_sidecar_name(job)}"
                if profile_name == "qdev-ci-docker"
                else "qdev-ci-egress"
            ),
            "--cpus",
            str(profile["cpu"]),
            "--memory",
            memory,
            "--memory-swap",
            memory,
            "--pids-limit",
            str(profile["pids_limit"]),
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "--env",
            f"QDEV_JIT_CONFIG={job['jit_config']}",
            "--env",
            f"QDEV_ARTIFACT_URL={job['artifact']['base_url']}",
            "--env",
            f"QDEV_ARTIFACT_TOKEN={job['artifact']['token']}",
            "--env",
            f"QDEV_JOB_ID={job['job_id']}",
            "--env",
            f"QDEV_REPOSITORY={job['repository']}",
            "--env",
            f"QDEV_HEAD_SHA={job['head_sha']}",
        ]
        if profile_name == "qdev-ci-docker":
            command.extend(
                [
                    "--mount",
                    f"type=bind,src={self.docker_run_dir(job)},dst=/run/qdev-docker",
                    "--env",
                    "DOCKER_HOST=unix:///run/qdev-docker/docker.sock",
                    "--env",
                    "DOCKER_BUILDKIT=1",
                ]
            )
        command.append(image)
        return command

    def docker_job_root(self, job: dict[str, Any]) -> Path:
        safe_name = "".join(
            character
            for character in str(job["runner_name"])[:48]
            if character.isalnum() or character in {"-", "_"}
        )
        if not safe_name:
            raise RuntimeError("invalid runner name for Docker isolation")
        return self.settings.buildkit_root / safe_name

    def docker_run_dir(self, job: dict[str, Any]) -> Path:
        return self.docker_job_root(job) / "run"

    def docker_sidecar_name(self, job: dict[str, Any]) -> str:
        return f"{job['runner_name']}-docker"

    def docker_sidecar_remove_command(self, name: str) -> list[str]:
        return [
            self.settings.container_engine,
            "rm",
            "--force",
            "--volumes",
            name,
        ]

    def docker_sidecar_command(self, job: dict[str, Any]) -> list[str]:
        job_root = self.docker_job_root(job)
        profile = job["profile"]
        return [
            self.settings.container_engine,
            "run",
            "--detach",
            "--rm",
            "--name",
            self.docker_sidecar_name(job),
            "--privileged",
            "--network",
            "qdev-ci-egress",
            "--cpus",
            str(profile["cpu"]),
            "--memory",
            f"{int(profile['memory_mb'])}m",
            "--memory-swap",
            f"{int(profile['memory_mb'])}m",
            "--pids-limit",
            str(profile["pids_limit"]),
            "--env",
            "DOCKER_TLS_CERTDIR=",
            "--mount",
            f"type=bind,src={job_root / 'run'},dst=/run/qdev",
            self.settings.docker_sidecar_image,
            "--host=unix:///run/qdev/docker.sock",
        ]

    async def start_docker_sidecar(self, job: dict[str, Any]) -> None:
        run_dir = self.docker_run_dir(job)
        run_dir.mkdir(parents=True, mode=0o777)
        run_dir.chmod(0o777)
        command = self.docker_sidecar_command(job)
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        output, _ = await process.communicate()
        if process.returncode != 0:
            detail = output.decode(errors="replace")[-2000:]
            raise RuntimeError(f"isolated Docker sidecar failed: {detail}")
        self.docker_sidecars[int(job["job_id"])] = self.docker_sidecar_name(job)
        for _ in range(45):
            socket = run_dir / "docker.sock"
            if socket.exists():
                socket.chmod(0o666)
            probe = await asyncio.create_subprocess_exec(
                self.settings.container_engine,
                "exec",
                self.docker_sidecar_name(job),
                "docker",
                "info",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            if await probe.wait() == 0:
                socket.chmod(0o666)
                return
            await asyncio.sleep(1)
        raise RuntimeError("isolated Docker/BuildKit sidecar did not become ready")

    async def stop_docker_sidecar(self, job: dict[str, Any]) -> None:
        name = self.docker_sidecars.pop(int(job["job_id"]), self.docker_sidecar_name(job))
        process = await asyncio.create_subprocess_exec(
            *self.docker_sidecar_remove_command(name),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await process.wait()
        shutil.rmtree(self.docker_job_root(job), ignore_errors=True)

    async def execute(self, job: dict[str, Any]) -> None:
        async with self.semaphore:
            detail = ""
            try:
                if job["profile"]["name"] == "qdev-ci-docker":
                    await self.start_docker_sidecar(job)
                command = self.container_command(job)
                LOGGER.info("starting job=%s runner=%s", job["job_id"], job["runner_name"])
                process = await asyncio.create_subprocess_exec(
                    *command,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.STDOUT,
                )
                timeout = int(job["profile"]["timeout_minutes"]) * 60
                try:
                    output, _ = await asyncio.wait_for(process.communicate(), timeout=timeout)
                    detail = output.decode("utf-8", errors="replace")[-2000:]
                except TimeoutError:
                    process.send_signal(signal.SIGTERM)
                    try:
                        await asyncio.wait_for(process.wait(), timeout=20)
                    except TimeoutError:
                        process.kill()
                        await process.wait()
                    detail = f"runner exceeded timeout={timeout}s"
                exit_code = process.returncode if process.returncode is not None else 124
            except Exception as error:
                LOGGER.exception("runner setup failed job=%s", job["job_id"])
                detail = str(error)[-2000:]
                exit_code = 125
            finally:
                if job["profile"]["name"] == "qdev-ci-docker":
                    await self.stop_docker_sidecar(job)
            await self.client.post(
                "/internal/v1/jobs/complete",
                json={
                    "worker_name": self.settings.worker_name,
                    "job_id": job["job_id"],
                    "runner_exit_code": exit_code,
                    "detail": detail,
                },
            )

    async def run(self) -> None:
        while not self.stopping.is_set():
            try:
                await self.heartbeat()
                capacity = measure()
                if capacity.allowed and len(self.tasks) < self.settings.concurrency:
                    job = await self.claim()
                    if job:
                        task = asyncio.create_task(self.execute(job))
                        self.tasks.add(task)
                        task.add_done_callback(self.tasks.discard)
                await asyncio.wait_for(self.stopping.wait(), timeout=self.settings.poll_seconds)
            except TimeoutError:
                continue
            except Exception:
                LOGGER.exception("worker loop failed")
                await asyncio.sleep(min(30, self.settings.poll_seconds * 2))
        if self.tasks:
            await asyncio.gather(*self.tasks, return_exceptions=True)


async def async_main() -> None:
    logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))
    worker = Worker(WorkerSettings.from_env())
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, worker.stopping.set)
    try:
        await worker.run()
    finally:
        await worker.close()


def main() -> None:
    asyncio.run(async_main())


if __name__ == "__main__":
    main()
