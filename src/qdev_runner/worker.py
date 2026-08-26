from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import ssl
from functools import partial
from pathlib import Path
from typing import Any, cast

import httpx

from .capacity import Capacity, measure
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
        self.active_job_ids: set[int] = set()
        self.docker_sidecars: dict[int, str] = {}
        self.stopping = asyncio.Event()

    async def close(self) -> None:
        await self.client.aclose()

    def job_task_done(self, task: asyncio.Task[None], *, job_id: int) -> None:
        self.tasks.discard(task)
        self.active_job_ids.discard(job_id)

    def capacity(self) -> Capacity:
        return measure(
            min_disk_free_gib=self.settings.min_disk_free_gib,
            max_disk_used_pct=self.settings.max_disk_used_pct,
            min_memory_available_gib=self.settings.min_memory_available_gib,
            max_load_per_cpu=self.settings.max_load_per_cpu,
            max_cpu_psi_avg10=self.settings.max_cpu_psi_avg10,
        )

    async def heartbeat(self) -> None:
        capacity = self.capacity()
        active_jobs = len(self.active_job_ids)
        await self.client.post(
            "/internal/v1/workers/heartbeat",
            json={
                "worker_name": self.settings.worker_name,
                "tier": self.settings.tier,
                "profiles": self.settings.profiles,
                "active_jobs": active_jobs,
                "active_job_ids": sorted(self.active_job_ids),
                "detail": capacity.__dict__
                | {
                    "concurrency": self.settings.concurrency,
                    "slots_available": max(0, self.settings.concurrency - active_jobs),
                    "min_disk_free_gib": self.settings.min_disk_free_gib,
                },
            },
        )

    async def claim(self, capacity: Capacity) -> dict[str, Any] | None:
        response = await self.client.post(
            "/internal/v1/jobs/claim",
            json={
                "worker_name": self.settings.worker_name,
                "tier": self.settings.tier,
                "profiles": self.settings.profiles,
                "disk_free_gib": capacity.disk_free_gib,
                "min_disk_free_gib": self.settings.min_disk_free_gib,
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
            "--env-file",
            str(self.runner_environment_path(job)),
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

    def runner_environment_path(self, job: dict[str, Any]) -> Path:
        return self.docker_job_root(job) / "runner.env"

    def write_runner_environment(self, job: dict[str, Any]) -> Path:
        values = {
            "QDEV_JIT_CONFIG": job["jit_config"],
            "QDEV_ARTIFACT_URL": job["artifact"]["base_url"],
            "QDEV_ARTIFACT_TOKEN": job["artifact"]["token"],
            "QDEV_JOB_ID": job["job_id"],
            "QDEV_REPOSITORY": job["repository"],
            "QDEV_HEAD_SHA": job["head_sha"],
        }
        registry = job.get("registry")
        if registry:
            values.update(
                {
                    "QDEV_REGISTRY_URL": registry["url"],
                    "QDEV_REGISTRY_USERNAME": registry["username"],
                    "QDEV_REGISTRY_PASSWORD": registry["password"],
                }
            )
        if any("\n" in str(value) or "\r" in str(value) for value in values.values()):
            raise RuntimeError("runner environment contains a newline")
        job_root = self.docker_job_root(job)
        job_root.mkdir(parents=True, mode=0o700, exist_ok=True)
        job_root.chmod(0o700)
        path = self.runner_environment_path(job)
        path.write_text(
            "".join(f"{key}={value}\n" for key, value in values.items()),
            encoding="utf-8",
        )
        path.chmod(0o600)
        return path

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

    def runner_remove_command(self, name: str) -> list[str]:
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

    async def stop_runner_container(self, job: dict[str, Any]) -> None:
        process = await asyncio.create_subprocess_exec(
            *self.runner_remove_command(str(job["runner_name"])),
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await process.wait()

    async def terminate_process(self, process: asyncio.subprocess.Process) -> None:
        if process.returncode is not None:
            return
        process.send_signal(signal.SIGTERM)
        try:
            await asyncio.wait_for(process.wait(), timeout=20)
        except TimeoutError:
            process.kill()
            await process.wait()

    async def wait_for_runner(
        self,
        process: asyncio.subprocess.Process,
        job: dict[str, Any],
        timeout: int,
    ) -> tuple[bytes, str]:
        communicate = asyncio.create_task(process.communicate())
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                await self.terminate_process(process)
                output, _ = await communicate
                return output, f"runner exceeded timeout={timeout}s"
            done, _ = await asyncio.wait({communicate}, timeout=min(5, remaining))
            if communicate in done:
                output, _ = communicate.result()
                return output, ""
            try:
                response = await self.client.get(f"/internal/v1/jobs/{int(job['job_id'])}/status")
                response.raise_for_status()
                status = str(response.json()["status"])
            except (httpx.HTTPError, KeyError, TypeError, ValueError):
                LOGGER.warning("job status check failed job=%s", job["job_id"])
                continue
            if status in {"completed", "failed", "rejected"}:
                await self.terminate_process(process)
                output, _ = await communicate
                return output, f"broker status={status}"

    async def execute(self, job: dict[str, Any]) -> None:
        async with self.semaphore:
            detail = ""
            try:
                self.write_runner_environment(job)
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
                output, stop_detail = await self.wait_for_runner(process, job, timeout)
                detail = (stop_detail + "\n" + output.decode("utf-8", errors="replace"))[-2000:]
                exit_code = process.returncode if process.returncode is not None else 124
            except Exception as error:
                LOGGER.exception("runner setup failed job=%s", job["job_id"])
                detail = str(error)[-2000:]
                exit_code = 125
            finally:
                await self.stop_runner_container(job)
                if job["profile"]["name"] == "qdev-ci-docker":
                    await self.stop_docker_sidecar(job)
                else:
                    shutil.rmtree(self.docker_job_root(job), ignore_errors=True)
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
                capacity = self.capacity()
                if capacity.allowed and len(self.tasks) < self.settings.concurrency:
                    job = await self.claim(capacity)
                    if job:
                        job_id = int(job["job_id"])
                        self.active_job_ids.add(job_id)
                        task = asyncio.create_task(self.execute(job))
                        self.tasks.add(task)
                        task.add_done_callback(partial(self.job_task_done, job_id=job_id))
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
