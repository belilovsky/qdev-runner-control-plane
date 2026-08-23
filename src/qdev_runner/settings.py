from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"required environment variable is missing: {name}")
    return value


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
    github_api_url: str = "https://api.github.com"
    github_api_version: str = "2026-03-10"
    registry_url: str = "registry.ci.qdev.run"
    registry_username: str = "qdev"
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
            database_path=Path(os.environ.get("QDEV_DATABASE", "/var/lib/qdev-runner/broker.db")),
            artifact_root=Path(
                os.environ.get("QDEV_ARTIFACT_ROOT", "/var/lib/qdev-runner/artifacts")
            ),
            github_api_url=os.environ.get("QDEV_GITHUB_API_URL", "https://api.github.com"),
            github_api_version=os.environ.get("QDEV_GITHUB_API_VERSION", "2026-03-10"),
            registry_url=os.environ.get("QDEV_REGISTRY_URL", "registry.ci.qdev.run").strip(),
            registry_username=os.environ.get("QDEV_REGISTRY_USERNAME", "qdev").strip(),
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
    mtls_ca: str | None = None
    mtls_cert: str | None = None
    mtls_key: str | None = None

    @classmethod
    def from_env(cls) -> WorkerSettings:
        return cls(
            broker_url=_required("QDEV_BROKER_URL").rstrip("/"),
            worker_token=_required("QDEV_WORKER_TOKEN"),
            worker_name=_required("QDEV_WORKER_NAME"),
            tier=os.environ.get("QDEV_WORKER_TIER", "primary").strip().lower(),
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
                    "registry.ci.qdev.run/qdev/actions-runner:2.336.0",
                ),
                "qdev-ci-browser": os.environ.get(
                    "QDEV_RUNNER_BROWSER_IMAGE",
                    "registry.ci.qdev.run/qdev/actions-runner-browser:2.336.0",
                ),
                "qdev-ci-docker": os.environ.get(
                    "QDEV_RUNNER_DOCKER_IMAGE",
                    "registry.ci.qdev.run/qdev/actions-runner-buildkit:2.336.0",
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
            mtls_ca=_required("QDEV_MTLS_CA"),
            mtls_cert=_required("QDEV_MTLS_CERT"),
            mtls_key=_required("QDEV_MTLS_KEY"),
        )
