from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"required environment variable is missing: {name}")
    return value


def _worker_identity() -> tuple[str, str]:
    worker_name = _required("QDEV_WORKER_NAME")
    tier = os.environ.get("QDEV_WORKER_TIER", "primary").strip().lower()
    if tier not in {"primary", "reserve"}:
        raise RuntimeError("QDEV_WORKER_TIER must be primary or reserve")
    if not worker_name.endswith(f"-{tier}"):
        raise RuntimeError(
            f"QDEV_WORKER_NAME must end with -{tier} when QDEV_WORKER_TIER={tier}"
        )
    return worker_name, tier


@dataclass(frozen=True)
class BrokerSettings:
    app_id: str
    app_private_key_path: Path
    webhook_secret: str
    worker_token: str
    inventory_path: Path
    profiles_path: Path
    database_path: Path
    artifact_root: Path
    project_priority_path: Path = Path("/etc/qdev-runner/project-priority.json")
    claim_scopes_path: Path = Path("/etc/qdev-runner/claim-scopes.json")
    github_api_url: str = "https://api.github.com"
    github_api_version: str = "2026-03-10"
    registry_url: str = "registry.ci.qdev.run"
    registry_username: str = "qdev-runner"
    registry_password: str | None = None

    @classmethod
    def from_env(cls) -> BrokerSettings:
        return cls(
            app_id=_required("QDEV_GITHUB_APP_ID"),
            app_private_key_path=Path(_required("QDEV_GITHUB_APP_PRIVATE_KEY")),
            webhook_secret=_required("QDEV_GITHUB_WEBHOOK_SECRET"),
            worker_token=_required("QDEV_WORKER_TOKEN"),
            inventory_path=Path(os.environ.get("QDEV_INVENTORY", "/etc/qdev-runner/repos.json")),
            profiles_path=Path(os.environ.get("QDEV_PROFILES", "/etc/qdev-runner/profiles.yml")),
            project_priority_path=Path(
                os.environ.get(
                    "QDEV_PROJECT_PRIORITY_POLICY",
                    "/etc/qdev-runner/project-priority.json",
                )
            ),
            database_path=Path(os.environ.get("QDEV_DATABASE", "/var/lib/qdev-runner/broker.db")),
            artifact_root=Path(
                os.environ.get("QDEV_ARTIFACT_ROOT", "/var/lib/qdev-runner/artifacts")
            ),
            claim_scopes_path=Path(
                os.environ.get("QDEV_CLAIM_SCOPES", "/etc/qdev-runner/claim-scopes.json")
            ),
            github_api_url=os.environ.get("QDEV_GITHUB_API_URL", "https://api.github.com"),
            github_api_version=os.environ.get("QDEV_GITHUB_API_VERSION", "2026-03-10"),
            registry_url=os.environ.get("QDEV_REGISTRY_URL", "registry.ci.qdev.run").strip(),
            registry_username=os.environ.get("QDEV_REGISTRY_USERNAME", "qdev-runner").strip(),
            registry_password=os.environ.get("QDEV_REGISTRY_PASSWORD", "").strip() or None,
        )


@dataclass(frozen=True)
class WorkerSettings:
    broker_url: str
    worker_token: str
    worker_name: str
    tier: str
    profiles: tuple[str, ...]
    concurrency: int
    poll_seconds: float
    container_engine: str
    runner_images: dict[str, str]
    docker_sidecar_image: str
    rootlesskit_path: str
    buildkitd_path: str
    buildctl_path: str
    buildkit_root: Path
    claim_scope_id: str | None = None
    min_disk_free_gib: float = 30
    max_disk_used_pct: float = 85
    min_memory_available_gib: float = 4
    max_load_per_cpu: float = 2
    max_cpu_psi_avg10: float | None = None
    mtls_ca: str | None = None
    mtls_cert: str | None = None
    mtls_key: str | None = None

    @classmethod
    def from_env(cls) -> WorkerSettings:
        worker_name, tier = _worker_identity()
        return cls(
            broker_url=_required("QDEV_BROKER_URL").rstrip("/"),
            worker_token=_required("QDEV_WORKER_TOKEN"),
            worker_name=worker_name,
            tier=tier,
            profiles=tuple(
                part.strip()
                for part in os.environ.get(
                    "QDEV_WORKER_PROFILES", "qdev-ci,qdev-ci-browser,qdev-ci-docker"
                ).split(",")
                if part.strip()
            ),
            concurrency=max(1, int(os.environ.get("QDEV_WORKER_CONCURRENCY", "1"))),
            poll_seconds=max(1.0, float(os.environ.get("QDEV_WORKER_POLL_SECONDS", "3"))),
            container_engine=os.environ.get("QDEV_CONTAINER_ENGINE", "docker"),
            runner_images={
                "qdev-ci": os.environ.get(
                    "QDEV_RUNNER_IMAGE",
                    "registry.ci.qdev.run/qdev/actions-runner:2.336.0-r2",
                ),
                "qdev-ci-browser": os.environ.get(
                    "QDEV_RUNNER_BROWSER_IMAGE",
                    "registry.ci.qdev.run/qdev/actions-runner-browser:2.336.0-r2",
                ),
                "qdev-ci-docker": os.environ.get(
                    "QDEV_RUNNER_DOCKER_IMAGE",
                    "registry.ci.qdev.run/qdev/actions-runner-buildkit:2.336.0-r2",
                ),
                "qdev-ci-compose": os.environ.get(
                    "QDEV_RUNNER_DOCKER_IMAGE",
                    "registry.ci.qdev.run/qdev/actions-runner-buildkit:2.336.0-r2",
                ),
            },
            docker_sidecar_image=os.environ.get(
                "QDEV_DOCKER_SIDECAR_IMAGE",
                "docker.io/library/docker@sha256:2a232a42256f70d78e3cc5d2b5d6b3276710a0de0596c145f627ecfae90282ac",
            ),
            rootlesskit_path=os.environ.get("QDEV_ROOTLESSKIT", "/usr/bin/rootlesskit"),
            buildkitd_path=os.environ.get(
                "QDEV_BUILDKITD", "/opt/qdev-buildkit/0.32.2/bin/buildkitd"
            ),
            buildctl_path=os.environ.get("QDEV_BUILDCTL", "/opt/qdev-buildkit/0.32.2/bin/buildctl"),
            buildkit_root=Path(
                os.environ.get("QDEV_BUILDKIT_ROOT", "/var/lib/qdev-runner-worker/jobs")
            ),
            claim_scope_id=os.environ.get("QDEV_CLAIM_SCOPE_ID", "").strip() or None,
            min_disk_free_gib=float(os.environ.get("QDEV_WORKER_MIN_FREE_GIB", "30")),
            max_disk_used_pct=float(os.environ.get("QDEV_WORKER_MAX_DISK_USED_PCT", "85")),
            min_memory_available_gib=float(
                os.environ.get("QDEV_WORKER_MIN_MEMORY_AVAILABLE_GIB", "4")
            ),
            max_load_per_cpu=float(os.environ.get("QDEV_WORKER_MAX_LOAD_PER_CPU", "2")),
            max_cpu_psi_avg10=(
                float(value)
                if (value := os.environ.get("QDEV_WORKER_MAX_CPU_PSI_AVG10", "").strip())
                else None
            ),
            mtls_ca=_required("QDEV_MTLS_CA"),
            mtls_cert=_required("QDEV_MTLS_CERT"),
            mtls_key=_required("QDEV_MTLS_KEY"),
        )
