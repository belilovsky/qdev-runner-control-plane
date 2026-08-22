from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import ssl
from pathlib import Path
from typing import IO, Any, cast

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
        self.buildkits: dict[int, tuple[asyncio.subprocess.Process, IO[bytes]]] = {}
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
        ]
        if profile_name == "qdev-ci-docker":
            command.extend(
                [
                    "--mount",
                    f"type=bind,src={self.buildkit_run_dir(job)},dst=/run/buildkit",
                    "--env",
                    "BUILDKIT_HOST=unix:///run/buildkit/buildkitd.sock",
                ]
            )
        command.append(image)
        return command

    def buildkit_job_root(self, job: dict[str, Any]) -> Path:
        safe_name = "".join(
            character
            for character in str(job["runner_name"])[:48]
            if character.isalnum() or character in {"-", "_"}
        )
        if not safe_name:
            raise RuntimeError("invalid runner name for BuildKit isolation")
        return self.settings.buildkit_root / safe_name

    def buildkit_run_dir(self, job: dict[str, Any]) -> Path:
        return self.buildkit_job_root(job) / "run"

    def buildkit_command(self, job: dict[str, Any]) -> list[str]:
        job_root = self.buildkit_job_root(job)
        return [
            self.settings.rootlesskit_path,
            "--state-dir",
            str(job_root / "rootlesskit"),
            "--net=slirp4netns",
            "--copy-up=/etc",
            "--copy-up=/run",
            "--disable-host-loopback",
            self.settings.buildkitd_path,
            "--addr",
            f"unix://{self.buildkit_run_dir(job)}/buildkitd.sock",
            "--root",
            str(job_root / "data"),
            "--rootless",
            "--oci-worker-no-process-sandbox",
        ]

    async def start_buildkit(self, job: dict[str, Any]) -> None:
        job_root = self.buildkit_job_root(job)
        run_dir = self.buildkit_run_dir(job)
        run_dir.mkdir(parents=True, mode=0o755)
        (job_root / "data").mkdir(mode=0o700)
        log_handle = (job_root / "buildkit.log").open("ab", buffering=0)
        command = self.buildkit_command(job)
        process = await asyncio.create_subprocess_exec(
            *command,
            stdout=log_handle,
            stderr=asyncio.subprocess.STDOUT,
            env=os.environ | {"XDG_RUNTIME_DIR": "/run/user/9021"},
        )
        self.buildkits[int(job["job_id"])] = (process, log_handle)
        for _ in range(30):
            if process.returncode is not None:
                detail = (job_root / "buildkit.log").read_text(errors="replace")[-2000:]
                raise RuntimeError(f"rootless BuildKit exited early: {detail}")
            probe = await asyncio.create_subprocess_exec(
                self.settings.buildctl_path,
                "--addr",
                f"unix://{run_dir}/buildkitd.sock",
                "debug",
                "workers",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            if await probe.wait() == 0:
                socket = run_dir / "buildkitd.sock"
                socket.chmod(0o666)
                return
            await asyncio.sleep(1)
        raise RuntimeError("rootless BuildKit did not become ready")

    async def stop_buildkit(self, job: dict[str, Any]) -> None:
        running = self.buildkits.pop(int(job["job_id"]), None)
        if running:
            process, log_handle = running
            if process.returncode is None:
                process.send_signal(signal.SIGTERM)
                try:
                    await asyncio.wait_for(process.wait(), timeout=20)
                except TimeoutError:
                    process.kill()
                    await process.wait()
            log_handle.close()
        shutil.rmtree(self.buildkit_job_root(job), ignore_errors=True)

    async def execute(self, job: dict[str, Any]) -> None:
        async with self.semaphore:
            detail = ""
            try:
                if job["profile"]["name"] == "qdev-ci-docker":
                    await self.start_buildkit(job)
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
                    await self.stop_buildkit(job)
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
