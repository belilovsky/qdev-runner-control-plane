from __future__ import annotations

import asyncio
import logging
import os
import signal
import ssl
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
        self.stopping = asyncio.Event()

    async def close(self) -> None:
        await self.client.aclose()

    async def heartbeat(self) -> None:
        capacity = measure()
        await self.client.post(
            "/internal/v1/workers/heartbeat",
            json={
                "worker_name": self.settings.worker_name,
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
        return [
            self.settings.container_engine,
            "run",
            "--rm",
            "--name",
            name,
            "--network",
            "qdev-ci-egress",
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
            image,
        ]

    async def execute(self, job: dict[str, Any]) -> None:
        async with self.semaphore:
            command = self.container_command(job)
            LOGGER.info("starting job=%s runner=%s", job["job_id"], job["runner_name"])
            process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT,
            )
            timeout = int(job["profile"]["timeout_minutes"]) * 60
            detail = ""
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
