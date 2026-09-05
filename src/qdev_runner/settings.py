from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

_IMMUTABLE_IMAGE_REFERENCE = re.compile(r"^[^\s@]+@sha256:[0-9a-f]{64}$")


def _required(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"required environment variable is missing: {name}")
    return value


def _required_immutable_image(name: str) -> str:
    """Read one worker image only when it is an OCI content-addressed reference.

    The worker accepts images from a private registry.  A release tag is a
    mutable registry pointer, so treating one as a release identity would let
    a later push alter the executable without changing the controller source
    or the worker receipt.
    """

    value = _required(name)
    if not _IMMUTABLE_IMAGE_REFERENCE.fullmatch(value):
        raise RuntimeError(f"{name} must be an OCI @sha256 content-addressed reference")
    return value


def _worker_identity() -> tuple[str, str]:
    worker_name = _required("QDEV_WORKER_NAME")
    tier = os.environ.get("QDEV_WORKER_TIER", "primary").strip().lower()
    if tier not in {"primary", "reserve"}:
        raise RuntimeError("QDEV_WORKER_TIER must be primary or reserve")
    if not worker_name.endswith(f"-{tier}"):
        raise RuntimeError(f"QDEV_WORKER_NAME must end with -{tier} when QDEV_WORKER_TIER={tier}")
    return worker_name, tier


@dataclass(frozen=True)
class BrokerSettings:
    app_id: str | None
    app_private_key_path: Path | None
    webhook_secret: str
    worker_token: str | None
    inventory_path: Path
    profiles_path: Path
    database_path: Path
    artifact_root: Path
    # Production brokers expose disjoint surfaces.  ``test`` is available only
    # to callers constructing settings directly; ``from_env`` deliberately
    # requires an explicit public/internal choice so a missing deployment
    # variable cannot recreate the historical combined broker.
    surface: Literal["public", "internal", "test"] = "test"
    # Artifact upload credentials are deliberately separate from the
    # worker-wide authentication secret.  The public upload surface receives
    # this bounded key but never receives QDEV_WORKER_TOKEN.
    artifact_token_key: str | None = None
    claim_scopes_path: Path = Path("/etc/qdev-runner/claim-scopes.json")
    github_api_url: str = "https://api.github.com"
    github_api_version: str = "2026-03-10"
    registry_url: str = "registry.ci.qdev.run"
    registry_username: str = "qdev-runner"
    registry_password: str | None = None
    operator_token: str | None = None
    operator_receipt_key: str | None = None
    operator_directive_key: str | None = None
    # Optional controller-to-broker claim key.  When configured, every v2
    # release admission must carry a controller-signed immutable claim.  The
    # key never travels in a request or appears in a receipt.
    controller_claim_key: str | None = None
    operations_root: Path = Path("/var/lib/qdev-runner/operations")
    controller_release_status_path: Path = Path(
        "/var/lib/qdev-runner/controller-status/controller-release.json"
    )
    release_lanes_path: Path = Path("/etc/qdev-runner/release-lanes.yml")
    managed_registry_path: Path = Path("/etc/qdev-runner/managed-registry.yml")
    admin_platform_ledger_path: Path = Path(
        "/var/lib/qdev-runner/admin-platform-state/admin-platform-ledger.yml"
    )
    admin_platform_receipt_root: Path = Path(
        "/var/lib/qdev-runner/admin-platform-receipts"
    )
    managed_release_ledger_path: Path = Path("/etc/qdev-runner/managed-release-ledger.yml")
    release_jobs_root: Path = Path("/var/lib/qdev-runner/release-jobs")
    release_host_dispatch_keys_file: Path = Path(
        "/etc/qdev-runner/release-host-dispatch-keys.json"
    )
    release_host_dispatch_claim_ttl_seconds: int = 120
    release_job_lease_ttl_seconds: int = 3600
    github_actions_oidc_issuer: str = "https://token.actions.githubusercontent.com"
    github_actions_oidc_jwks_url: str = (
        "https://token.actions.githubusercontent.com/.well-known/jwks"
    )
    github_actions_oidc_audience: str = "qdev-artifact-v1"
    fleet_bootstrap_policy_path: Path = Path("/etc/qdev-runner/fleet-bootstrap.yml")
    fleet_bootstrap_operation_root: Path = Path(
        "/var/lib/qdev-runner/operations/fleet-bootstrap"
    )
    fleet_bootstrap_receipt_root: Path = Path(
        "/var/lib/qdev-runner/operations/fleet-bootstrap-receipts"
    )
    fleet_host_dispatch_request_root: Path = Path(
        "/var/lib/qdev-runner/fleet-host-dispatch/incoming"
    )
    fleet_host_dispatch_result_root: Path = Path(
        "/var/lib/qdev-runner/fleet-host-dispatch/results"
    )
    # Recovery crosses the authenticated controller edge.  The shared secret
    # proves the edge hop while the edge-overwritten certificate fingerprint
    # selects one fixed operator or host-agent identity.
    operator_proxy_secret: str | None = None
    recovery_operator_certificate_sha256s: tuple[str, ...] = ()
    recovery_platform_agent_certificate_sha256: str | None = None
    recovery_qazstack_agent_certificate_sha256: str | None = None
    recovery_policy_digest: str | None = None
    recovery_agent_release_digest: str | None = None
    recovery_agent_signing_key: str | None = None
    recovery_proof_max_age_seconds: float = 120.0
    recovery_command_ttl_seconds: int = 120

    @classmethod
    def from_env(cls) -> BrokerSettings:
        surface = os.environ.get("QDEV_BROKER_SURFACE", "").strip().lower()
        if surface not in {"public", "internal"}:
            raise RuntimeError("QDEV_BROKER_SURFACE must be public or internal")
        # The public webhook/artifact process never calls the GitHub App API.
        # Do not make its container carry the private application key merely
        # because the internal broker uses the same settings type.
        app_id = (
            _required("QDEV_GITHUB_APP_ID")
            if surface == "internal"
            else (os.environ.get("QDEV_GITHUB_APP_ID", "").strip() or None)
        )
        app_private_key_path = (
            Path(_required("QDEV_GITHUB_APP_PRIVATE_KEY"))
            if surface == "internal"
            else None
        )
        release_host_dispatch_claim_ttl_seconds = int(
            os.environ.get("QDEV_RELEASE_HOST_DISPATCH_CLAIM_TTL_SECONDS", "120")
        )
        if not 30 <= release_host_dispatch_claim_ttl_seconds <= 300:
            raise RuntimeError(
                "QDEV_RELEASE_HOST_DISPATCH_CLAIM_TTL_SECONDS must be between 30 and 300"
            )
        release_job_lease_ttl_seconds = int(
            os.environ.get("QDEV_RELEASE_JOB_LEASE_TTL_SECONDS", "3600")
        )
        if not 60 <= release_job_lease_ttl_seconds <= 86400:
            raise RuntimeError(
                "QDEV_RELEASE_JOB_LEASE_TTL_SECONDS must be between 60 and 86400"
            )
        return cls(
            app_id=app_id,
            app_private_key_path=app_private_key_path,
            webhook_secret=(
                _required("QDEV_GITHUB_WEBHOOK_SECRET") if surface == "public" else ""
            ),
            worker_token=(
                _required("QDEV_WORKER_TOKEN") if surface == "internal" else None
            ),
            inventory_path=Path(os.environ.get("QDEV_INVENTORY", "/etc/qdev-runner/repos.json")),
            profiles_path=Path(os.environ.get("QDEV_PROFILES", "/etc/qdev-runner/profiles.yml")),
            database_path=Path(os.environ.get("QDEV_DATABASE", "/var/lib/qdev-runner/broker.db")),
            artifact_root=Path(
                os.environ.get("QDEV_ARTIFACT_ROOT", "/var/lib/qdev-runner/artifacts")
            ),
            surface=cast(Literal["public", "internal"], surface),
            artifact_token_key=_required("QDEV_ARTIFACT_TOKEN_KEY"),
            claim_scopes_path=Path(
                os.environ.get("QDEV_CLAIM_SCOPES", "/etc/qdev-runner/claim-scopes.json")
            ),
            github_api_url=os.environ.get("QDEV_GITHUB_API_URL", "https://api.github.com"),
            github_api_version=os.environ.get("QDEV_GITHUB_API_VERSION", "2026-03-10"),
            registry_url=os.environ.get("QDEV_REGISTRY_URL", "registry.ci.qdev.run").strip(),
            registry_username=os.environ.get("QDEV_REGISTRY_USERNAME", "qdev-runner").strip(),
            registry_password=os.environ.get("QDEV_REGISTRY_PASSWORD", "").strip() or None,
            operator_token=os.environ.get("QDEV_OPERATOR_TOKEN", "").strip() or None,
            operator_receipt_key=(os.environ.get("QDEV_OPERATOR_RECEIPT_KEY", "").strip() or None),
            operator_directive_key=(
                os.environ.get("QDEV_OPERATOR_DIRECTIVE_KEY", "").strip() or None
            ),
            controller_claim_key=(
                os.environ.get("QDEV_RELEASE_CLAIM_KEY", "").strip() or None
            ),
            operations_root=Path(
                os.environ.get("QDEV_OPERATIONS_ROOT", "/var/lib/qdev-runner/operations")
            ),
            controller_release_status_path=Path(
                os.environ.get(
                    "QDEV_CONTROLLER_RELEASE_STATUS",
                    "/var/lib/qdev-runner/controller-status/controller-release.json",
                )
            ),
            release_lanes_path=Path(
                os.environ.get("QDEV_RELEASE_LANES", "/etc/qdev-runner/release-lanes.yml")
            ),
            managed_registry_path=Path(
                os.environ.get("QDEV_MANAGED_REGISTRY", "/etc/qdev-runner/managed-registry.yml")
            ),
            admin_platform_ledger_path=Path(
                os.environ.get(
                    "QDEV_ADMIN_PLATFORM_LEDGER",
                    "/var/lib/qdev-runner/admin-platform-state/admin-platform-ledger.yml",
                )
            ),
            admin_platform_receipt_root=Path(
                os.environ.get(
                    "QDEV_ADMIN_PLATFORM_RECEIPT_ROOT",
                    "/var/lib/qdev-runner/admin-platform-receipts",
                )
            ),
            managed_release_ledger_path=Path(
                os.environ.get(
                    "QDEV_MANAGED_RELEASE_LEDGER",
                    "/etc/qdev-runner/managed-release-ledger.yml",
                )
            ),
            release_jobs_root=Path(
                os.environ.get("QDEV_RELEASE_JOBS_ROOT", "/var/lib/qdev-runner/release-jobs")
            ),
            release_host_dispatch_keys_file=Path(
                os.environ.get(
                    "QDEV_RELEASE_HOST_DISPATCH_KEYS_FILE",
                    "/etc/qdev-runner/release-host-dispatch-keys.json",
                )
            ),
            release_host_dispatch_claim_ttl_seconds=(
                release_host_dispatch_claim_ttl_seconds
            ),
            release_job_lease_ttl_seconds=release_job_lease_ttl_seconds,
            github_actions_oidc_issuer=os.environ.get(
                "QDEV_GITHUB_ACTIONS_OIDC_ISSUER",
                "https://token.actions.githubusercontent.com",
            ).strip(),
            github_actions_oidc_jwks_url=os.environ.get(
                "QDEV_GITHUB_ACTIONS_OIDC_JWKS_URL",
                "https://token.actions.githubusercontent.com/.well-known/jwks",
            ).strip(),
            github_actions_oidc_audience=os.environ.get(
                "QDEV_GITHUB_ACTIONS_OIDC_AUDIENCE", "qdev-artifact-v1"
            ).strip(),
            fleet_bootstrap_policy_path=Path(
                os.environ.get(
                    "QDEV_FLEET_BOOTSTRAP_POLICY",
                    "/etc/qdev-runner/fleet-bootstrap.yml",
                )
            ),
            fleet_bootstrap_operation_root=Path(
                os.environ.get(
                    "QDEV_FLEET_BOOTSTRAP_OPERATION_ROOT",
                    "/var/lib/qdev-runner/operations/fleet-bootstrap",
                )
            ),
            fleet_bootstrap_receipt_root=Path(
                os.environ.get(
                    "QDEV_FLEET_BOOTSTRAP_RECEIPT_ROOT",
                    "/var/lib/qdev-runner/operations/fleet-bootstrap-receipts",
                )
            ),
            fleet_host_dispatch_request_root=Path(
                os.environ.get(
                    "QDEV_FLEET_HOST_DISPATCH_REQUEST_ROOT",
                    "/var/lib/qdev-runner/fleet-host-dispatch/incoming",
                )
            ),
            fleet_host_dispatch_result_root=Path(
                os.environ.get(
                    "QDEV_FLEET_HOST_DISPATCH_RESULT_ROOT",
                    "/var/lib/qdev-runner/fleet-host-dispatch/results",
                )
            ),
            operator_proxy_secret=(
                os.environ.get("QDEV_OPERATOR_PROXY_SECRET", "").strip() or None
            ),
            recovery_operator_certificate_sha256s=tuple(
                item.strip().lower()
                for item in os.environ.get(
                    "QDEV_RECOVERY_OPERATOR_CERTIFICATE_SHA256S", ""
                ).split(",")
                if item.strip()
            ),
            recovery_platform_agent_certificate_sha256=(
                os.environ.get(
                    "QDEV_RECOVERY_PLATFORM_AGENT_CERTIFICATE_SHA256", ""
                )
                .strip()
                .lower()
                or None
            ),
            recovery_qazstack_agent_certificate_sha256=(
                os.environ.get(
                    "QDEV_RECOVERY_QAZSTACK_AGENT_CERTIFICATE_SHA256", ""
                )
                .strip()
                .lower()
                or None
            ),
            recovery_policy_digest=(
                os.environ.get("QDEV_RECOVERY_POLICY_DIGEST", "").strip().lower()
                or None
            ),
            recovery_agent_release_digest=(
                os.environ.get("QDEV_RECOVERY_AGENT_RELEASE_DIGEST", "")
                .strip()
                .lower()
                or None
            ),
            recovery_agent_signing_key=(
                os.environ.get("QDEV_RECOVERY_AGENT_SIGNING_KEY", "").strip()
                or None
            ),
            recovery_proof_max_age_seconds=max(
                1.0,
                min(
                    300.0,
                    float(
                        os.environ.get(
                            "QDEV_RECOVERY_PROOF_MAX_AGE_SECONDS", "120"
                        )
                    ),
                ),
            ),
            recovery_command_ttl_seconds=max(
                30,
                min(
                    300,
                    int(
                        os.environ.get(
                            "QDEV_RECOVERY_COMMAND_TTL_SECONDS", "120"
                        )
                    ),
                ),
            ),
        )


@dataclass(frozen=True)
class WorkerSettings:
    broker_url: str
    worker_token: str | None
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
    capacity_override_active: bool = False
    mtls_ca: str | None = None
    mtls_cert: str | None = None
    mtls_key: str | None = None
    capacity_directive_key: str | None = None

    @classmethod
    def from_env(cls) -> WorkerSettings:
        worker_name, tier = _worker_identity()
        claim_scope_id = os.environ.get("QDEV_CLAIM_SCOPE_ID", "").strip() or None
        worker_token = os.environ.get("QDEV_WORKER_TOKEN", "").strip() or None
        if not worker_token and not claim_scope_id:
            raise RuntimeError("QDEV_WORKER_TOKEN is required for an unscoped worker")
        min_disk_free_gib = float(os.environ.get("QDEV_WORKER_MIN_FREE_GIB", "30"))
        max_disk_used_pct = float(os.environ.get("QDEV_WORKER_MAX_DISK_USED_PCT", "85"))
        min_memory_available_gib = float(
            os.environ.get("QDEV_WORKER_MIN_MEMORY_AVAILABLE_GIB", "4")
        )
        max_load_per_cpu = float(os.environ.get("QDEV_WORKER_MAX_LOAD_PER_CPU", "2"))
        allow_capacity_override = (
            os.environ.get("QDEV_WORKER_ALLOW_RUNTIME_CAPACITY_OVERRIDE", "false").strip().lower()
        )
        if allow_capacity_override not in {"true", "false"}:
            raise RuntimeError("QDEV_WORKER_ALLOW_RUNTIME_CAPACITY_OVERRIDE must be true or false")
        capacity_override_active = min_disk_free_gib < 30 or max_disk_used_pct > 85
        if min_memory_available_gib < 4 or max_load_per_cpu > 2:
            raise RuntimeError("worker memory and load gates cannot be relaxed")
        if capacity_override_active:
            if not claim_scope_id or allow_capacity_override != "true":
                raise RuntimeError(
                    "a lower worker capacity gate requires a scoped explicit override"
                )
            if min_disk_free_gib < 4 or max_disk_used_pct > 90:
                raise RuntimeError("worker capacity override is outside the bounded range")
        elif allow_capacity_override == "true":
            raise RuntimeError("worker capacity override is not active")
        return cls(
            broker_url=_required("QDEV_BROKER_URL").rstrip("/"),
            worker_token=worker_token,
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
                "qdev-ci": _required_immutable_image("QDEV_RUNNER_IMAGE"),
                "qdev-ci-browser": _required_immutable_image("QDEV_RUNNER_BROWSER_IMAGE"),
                "qdev-ci-docker": _required_immutable_image("QDEV_RUNNER_DOCKER_IMAGE"),
            },
            docker_sidecar_image=_required_immutable_image("QDEV_DOCKER_SIDECAR_IMAGE"),
            rootlesskit_path=os.environ.get("QDEV_ROOTLESSKIT", "/usr/bin/rootlesskit"),
            buildkitd_path=os.environ.get(
                "QDEV_BUILDKITD", "/opt/qdev-buildkit/0.33.0/bin/buildkitd"
            ),
            buildctl_path=os.environ.get("QDEV_BUILDCTL", "/opt/qdev-buildkit/0.33.0/bin/buildctl"),
            buildkit_root=Path(
                os.environ.get("QDEV_BUILDKIT_ROOT", "/var/lib/qdev-runner-worker/jobs")
            ),
            claim_scope_id=claim_scope_id,
            min_disk_free_gib=min_disk_free_gib,
            max_disk_used_pct=max_disk_used_pct,
            min_memory_available_gib=min_memory_available_gib,
            max_load_per_cpu=max_load_per_cpu,
            max_cpu_psi_avg10=(
                float(value)
                if (value := os.environ.get("QDEV_WORKER_MAX_CPU_PSI_AVG10", "").strip())
                else None
            ),
            capacity_override_active=capacity_override_active,
            mtls_ca=_required("QDEV_MTLS_CA"),
            mtls_cert=_required("QDEV_MTLS_CERT"),
            mtls_key=_required("QDEV_MTLS_KEY"),
            capacity_directive_key=(
                os.environ.get("QDEV_CAPACITY_DIRECTIVE_KEY", "").strip() or None
            ),
        )
