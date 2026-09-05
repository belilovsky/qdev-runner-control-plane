from __future__ import annotations

import asyncio
import logging
import os
import shutil
import signal
import ssl
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from functools import partial
from pathlib import Path
from typing import Any, cast

import httpx

from .capacity import Capacity, evaluate, measure, measure_raw
from .operations import (
    DISK_ONLY_BLOCKERS,
    CapacityOverrideDirective,
    parse_utc,
    verify_capacity_override,
)
from .settings import WorkerSettings
from .worker_runtime_audit import evaluate as evaluate_runtime

LOGGER = logging.getLogger("qdev-runner-worker")


@dataclass(frozen=True)
class AdmissionState:
    raw: Capacity
    baseline: Capacity
    effective: Capacity
    profiles: tuple[str, ...]
    min_disk_free_gib: float
    max_disk_used_pct: float
    directive_id: str | None = None
    directive_repository: str | None = None
    directive_head_sha: str | None = None
    directive_expires_at: datetime | None = None


class Worker:
    def __init__(self, settings: WorkerSettings) -> None:
        self.settings = settings
        tls: ssl.SSLContext | bool = True
        if settings.mtls_ca and settings.mtls_cert and settings.mtls_key:
            tls = ssl.create_default_context(cafile=settings.mtls_ca)
            tls.load_cert_chain(settings.mtls_cert, settings.mtls_key)
        headers = {}
        if settings.worker_token:
            headers["X-QDev-Worker-Token"] = settings.worker_token
        if settings.claim_scope_id:
            headers["X-QDev-Claim-Scope-Id"] = settings.claim_scope_id
        self.client = httpx.AsyncClient(
            base_url=settings.broker_url,
            headers=headers,
            timeout=45,
            verify=tls,
        )
        self.semaphore = asyncio.Semaphore(settings.concurrency)
        self.tasks: set[asyncio.Task[None]] = set()
        self.active_job_ids: set[int] = set()
        self.docker_sidecars: dict[int, str] = {}
        self.stopping = asyncio.Event()
        self.runtime_audit: dict[str, Any] = {}
        self.runtime_audit_deadline = 0.0
        self.runtime_audit_task: asyncio.Task[None] | None = None

    def inspect_runtime(self) -> dict[str, Any]:
        # Read the actual process settings, not a potentially shadowed env
        # file. No credential or arbitrary environment field enters evidence.
        settings = self.settings
        values = {
            "QDEV_WORKER_NAME": settings.worker_name,
            "QDEV_WORKER_TIER": settings.tier,
            "QDEV_WORKER_PROFILES": ",".join(settings.profiles),
            "QDEV_CONTAINER_ENGINE": settings.container_engine,
            "QDEV_RUNNER_IMAGE": settings.runner_images.get("qdev-ci", ""),
            "QDEV_RUNNER_BROWSER_IMAGE": settings.runner_images.get("qdev-ci-browser", ""),
            "QDEV_RUNNER_DOCKER_IMAGE": settings.runner_images.get("qdev-ci-docker", ""),
            "QDEV_DOCKER_SIDECAR_IMAGE": settings.docker_sidecar_image,
        }
        # Use the start time, so a slow/hung image inspection cannot refresh
        # old observations by recording the end of its timeout as freshness.
        observed_at = datetime.now(UTC).isoformat()
        result = evaluate_runtime(values, image_release_manifest=settings.image_release_manifest)
        return {
            **result,
            "schema": "qdev-runner-worker-runtime-audit-v1",
            "observed_at": observed_at,
            "profiles": list(settings.profiles),
            "status": "passed" if not result["errors"] else "failed",
        }

    async def refresh_runtime_audit(self) -> None:
        try:
            self.runtime_audit = await asyncio.to_thread(self.inspect_runtime)
        except Exception as error:
            # Runtime inspection must fail closed for new claims, without
            # interrupting lease heartbeats or leaking environment details.
            self.runtime_audit = {
                "schema": "qdev-runner-worker-runtime-audit-v1",
                "observed_at": datetime.now(UTC).isoformat(),
                "status": "failed",
                "errors": [f"runtime_inspection_failed:{type(error).__name__}"],
            }
        finally:
            self.runtime_audit_deadline = time.monotonic() + 30

    async def close(self) -> None:
        if self.runtime_audit_task is not None:
            self.runtime_audit_task.cancel()
            await asyncio.gather(self.runtime_audit_task, return_exceptions=True)
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

    def admission_state(
        self,
        *,
        raw: Capacity | None = None,
        directive_payload: object = None,
    ) -> AdmissionState:
        measured = raw or measure_raw()
        baseline = evaluate(
            measured,
            min_disk_free_gib=self.settings.min_disk_free_gib,
            max_disk_used_pct=self.settings.max_disk_used_pct,
            min_memory_available_gib=self.settings.min_memory_available_gib,
            max_load_per_cpu=self.settings.max_load_per_cpu,
            max_cpu_psi_avg10=self.settings.max_cpu_psi_avg10,
        )
        state = AdmissionState(
            raw=measured,
            baseline=baseline,
            effective=baseline,
            profiles=self.settings.profiles,
            min_disk_free_gib=self.settings.min_disk_free_gib,
            max_disk_used_pct=self.settings.max_disk_used_pct,
        )
        if not isinstance(directive_payload, dict):
            return state
        if not self.settings.capacity_directive_key:
            LOGGER.warning("capacity override ignored: worker signing key is not configured")
            return state
        if not baseline.blockers or not set(baseline.blockers).issubset(DISK_ONLY_BLOCKERS):
            LOGGER.warning("capacity override ignored: baseline blocker is not disk-only")
            return state
        try:
            directive: CapacityOverrideDirective = verify_capacity_override(
                directive_payload,
                signing_key=self.settings.capacity_directive_key,
                worker_name=self.settings.worker_name,
                registered_profiles=self.settings.profiles,
            )
        except ValueError as error:
            LOGGER.warning("capacity override ignored: %s", error)
            return state
        effective = evaluate(
            measured,
            min_disk_free_gib=directive.min_disk_free_gib,
            max_disk_used_pct=directive.max_disk_used_pct,
            min_memory_available_gib=self.settings.min_memory_available_gib,
            max_load_per_cpu=self.settings.max_load_per_cpu,
            max_cpu_psi_avg10=self.settings.max_cpu_psi_avg10,
        )
        return AdmissionState(
            raw=measured,
            baseline=baseline,
            effective=effective,
            profiles=directive.profiles,
            min_disk_free_gib=directive.min_disk_free_gib,
            max_disk_used_pct=directive.max_disk_used_pct,
            directive_id=directive.operation_id,
            directive_repository=directive.repository,
            directive_head_sha=directive.head_sha,
            directive_expires_at=parse_utc(directive.expires_at),
        )

    def heartbeat_payload(self, state: AdmissionState) -> dict[str, Any]:
        active_jobs = len(self.active_job_ids)
        return {
            "worker_name": self.settings.worker_name,
            "tier": self.settings.tier,
            "claim_scope_id": self.settings.claim_scope_id,
            "profiles": self.settings.profiles,
            "active_jobs": active_jobs,
            "active_job_ids": sorted(self.active_job_ids),
            "detail": asdict(state.effective)
            | {
                "raw_capacity": asdict(state.raw),
                "baseline_capacity": asdict(state.baseline),
                "effective_capacity": asdict(state.effective),
                "effective_profiles": list(state.profiles),
                "runtime_audit": self.runtime_audit,
                "configured_claim_scope_id": self.settings.claim_scope_id,
                "capacity_directive_id": state.directive_id,
                "capacity_directive_repository": state.directive_repository,
                "capacity_directive_head_sha": state.directive_head_sha,
                "capacity_override_active": state.directive_id is not None,
                "concurrency": self.settings.concurrency,
                "slots_available": max(0, self.settings.concurrency - active_jobs),
                "min_disk_free_gib": state.min_disk_free_gib,
                "max_disk_used_pct": state.max_disk_used_pct,
                "capacity_directive_expires_at": (
                    state.directive_expires_at.isoformat().replace("+00:00", "Z")
                    if state.directive_expires_at is not None
                    else None
                ),
            },
        }

    async def heartbeat(self) -> AdmissionState:
        if time.monotonic() >= self.runtime_audit_deadline and (
            self.runtime_audit_task is None or self.runtime_audit_task.done()
        ):
            # Image inspection can time out. Keep at most one inspection in
            # flight and never make an active job's lease depend on its speed.
            # Missing or expired evidence denies new claims at the controller.
            self.runtime_audit_task = asyncio.create_task(self.refresh_runtime_audit())
        measured = measure_raw()
        baseline_state = self.admission_state(raw=measured)
        response = await self.client.post(
            "/internal/v1/workers/heartbeat",
            json=self.heartbeat_payload(baseline_state),
        )
        response.raise_for_status()
        # Older controllers acknowledge heartbeats with 204 and no directive
        # document.  Keep upgraded workers compatible during a rolling rollout;
        # a missing or non-JSON body simply means that no override is active.
        payload: object = None
        if response.content:
            try:
                payload = response.json()
            except ValueError:
                LOGGER.warning("heartbeat directive response is not valid JSON; ignoring it")
        directive_payload = payload.get("capacity_override") if isinstance(payload, dict) else None
        effective_state = self.admission_state(
            raw=measured,
            directive_payload=directive_payload,
        )
        if effective_state.directive_id is not None:
            follow_up = await self.client.post(
                "/internal/v1/workers/heartbeat",
                json=self.heartbeat_payload(effective_state),
            )
            follow_up.raise_for_status()
        return effective_state

    async def claim(
        self,
        capacity: Capacity,
        *,
        profiles: tuple[str, ...] | None = None,
        min_disk_free_gib: float | None = None,
        capacity_directive_id: str | None = None,
        capacity_repository: str | None = None,
        capacity_head_sha: str | None = None,
    ) -> dict[str, Any] | None:
        response = await self.client.post(
            "/internal/v1/jobs/claim",
            json={
                "worker_name": self.settings.worker_name,
                "tier": self.settings.tier,
                "claim_scope_id": self.settings.claim_scope_id,
                "profiles": profiles or self.settings.profiles,
                "disk_free_gib": capacity.disk_free_gib,
                "min_disk_free_gib": (
                    self.settings.min_disk_free_gib
                    if min_disk_free_gib is None
                    else min_disk_free_gib
                ),
                "capacity_directive_id": capacity_directive_id,
                "capacity_repository": capacity_repository,
                "capacity_head_sha": capacity_head_sha,
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

    def disk_hard_floor_violation(
        self,
        capacity: Capacity,
        *,
        min_disk_free_gib: float | None = None,
        max_disk_used_pct: float | None = None,
    ) -> str:
        minimum = (
            self.settings.min_disk_free_gib
            if min_disk_free_gib is None
            else min_disk_free_gib
        )
        maximum = (
            self.settings.max_disk_used_pct
            if max_disk_used_pct is None
            else max_disk_used_pct
        )
        if capacity.disk_used_pct >= maximum:
            return (
                "worker disk hard floor reached: "
                f"used={capacity.disk_used_pct:.2f}% "
                f"maximum={maximum:.2f}%"
            )
        if capacity.disk_free_gib < minimum:
            return (
                "worker disk hard floor reached: "
                f"free={capacity.disk_free_gib:.2f}GiB "
                f"minimum={minimum:.2f}GiB"
            )
        return ""

    async def wait_for_runner(
        self,
        process: asyncio.subprocess.Process,
        job: dict[str, Any],
        timeout: int,
        admission: AdmissionState | None = None,
    ) -> tuple[bytes, str]:
        communicate = asyncio.create_task(process.communicate())
        deadline = asyncio.get_running_loop().time() + timeout
        while True:
            if (
                admission is not None
                and admission.directive_expires_at is not None
                and datetime.now(UTC) >= admission.directive_expires_at
            ):
                await self.terminate_process(process)
                output, _ = await communicate
                return output, "capacity override expired during running job"
            capacity_detail = self.disk_hard_floor_violation(
                self.capacity(),
                min_disk_free_gib=(
                    admission.min_disk_free_gib if admission is not None else None
                ),
                max_disk_used_pct=(
                    admission.max_disk_used_pct if admission is not None else None
                ),
            )
            if capacity_detail:
                await self.terminate_process(process)
                output, _ = await communicate
                return output, capacity_detail
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                await self.terminate_process(process)
                output, _ = await communicate
                return output, f"runner exceeded timeout={timeout}s"
            done, _ = await asyncio.wait(
                {communicate},
                timeout=min(5, max(1, self.settings.poll_seconds), remaining),
            )
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

    async def execute(
        self,
        job: dict[str, Any],
        *,
        admission: AdmissionState | None = None,
    ) -> None:
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
                output, stop_detail = await self.wait_for_runner(
                    process,
                    job,
                    timeout,
                    admission=admission,
                )
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
                admission = await self.heartbeat()
                if admission.effective.allowed and len(self.tasks) < self.settings.concurrency:
                    job = await self.claim(
                        admission.effective,
                        profiles=admission.profiles,
                        min_disk_free_gib=admission.min_disk_free_gib,
                        capacity_directive_id=admission.directive_id,
                        capacity_repository=admission.directive_repository,
                        capacity_head_sha=admission.directive_head_sha,
                    )
                    if job:
                        job_id = int(job["job_id"])
                        self.active_job_ids.add(job_id)
                        task = asyncio.create_task(self.execute(job, admission=admission))
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
