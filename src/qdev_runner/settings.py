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
    buildkit_image: str
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
            buildkit_image=os.environ.get(
                "QDEV_BUILDKIT_IMAGE",
                "moby/buildkit@sha256:60d1f642e29dc938bd6c109ba5500849fccf41921927c5339788b8227f57feb9",
            ),
            mtls_ca=_required("QDEV_MTLS_CA"),
            mtls_cert=_required("QDEV_MTLS_CERT"),
            mtls_key=_required("QDEV_MTLS_KEY"),
        )
