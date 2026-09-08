from pathlib import Path

import pytest
import yaml

from qdev_runner.managed_registry import ManagedRegistry, ManagedRegistryError

RP_SOURCE_PATHS = (
    "qdev-reports-private.json",
    "qdev-rp-platform.json",
    "Dockerfile.reports",
    "docker-compose.reports.yml",
    "deploy/build-reports.sh",
    "deploy/publish-reports-image.sh",
)


def _registry_path() -> Path:
    return Path(__file__).parents[1] / "config" / "managed-registry.yml"


def test_managed_registry_separates_admin_wave_from_qazgeo_production() -> None:
    registry = ManagedRegistry(_registry_path())
    total = registry.entry_for_repository("belilovsky/total-kz")
    assert total is not None
    assert total.runtime_endpoints == (
        "https://total.qdev.run/health",
        "https://total.qdev.run/ready",
        "https://total.qdev.run/release.json",
    )
    assert registry.validate_claim_if_managed("belilovsky/av-platform-core", "qdev-ci")
    qazgeo = registry.entry_for_repository("belilovsky/qazgeo")
    assert qazgeo is not None
    assert qazgeo.admission_ledger == "managed-production"
    assert qazgeo.runtime_endpoints == (
        "https://qgeo.tech/health",
        "https://qgeo.tech/health/live",
        "https://qgeo.tech/health/ready",
        "https://qgeo.tech/health/quality",
    )


def test_managed_registry_rejects_secret_fields_and_profile_drift(tmp_path: Path) -> None:
    document = yaml.safe_load(_registry_path().read_text(encoding="utf-8"))
    document["entries"]["ortcom"]["credential"] = "not-allowed"
    path = tmp_path / "registry.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ManagedRegistryError, match="fields"):
        ManagedRegistry(path)

    registry = ManagedRegistry(_registry_path())
    with pytest.raises(ManagedRegistryError, match="profile"):
        registry.validate_claim_if_managed("belilovsky/av-platform-core", "qdev-ci-docker")


def test_reports_private_scope_keeps_generic_ipos_ci_unmanaged() -> None:
    registry = ManagedRegistry(_registry_path())

    # The source-scoped RP record cannot constrain ordinary IPOS jobs.
    assert registry.entry_for_repository("belilovsky/ipos") is None
    assert registry.validate_claim_if_managed("belilovsky/ipos", "qdev-ci") is None
    assert registry.validate_claim_if_managed("belilovsky/ipos", "qdev-ci-docker") is None

    entry = registry.entry_for_repository_scope("belilovsky/ipos", "reports-private")
    assert entry is not None
    assert entry.entry_id == "rp-reports-private"
    assert entry.is_scoped is True
    assert entry.activation_state == "pending_external_enrolment"
    assert entry.host_identity is None
    assert entry.rollback_reference is None
    assert entry.source_paths == RP_SOURCE_PATHS
    assert (
        registry.validate_release_scope(
            entry_id="rp-reports-private",
            repository="belilovsky/ipos",
            profile="qdev-ci-docker",
            source_scope="reports-private",
            source_paths=RP_SOURCE_PATHS,
        )
        == entry
    )

    with pytest.raises(ManagedRegistryError, match="profile"):
        registry.validate_release_scope(
            entry_id="rp-reports-private",
            repository="belilovsky/ipos",
            profile="qdev-ci",
            source_scope="reports-private",
            source_paths=RP_SOURCE_PATHS,
        )
    with pytest.raises(ManagedRegistryError, match="scope"):
        registry.validate_release_scope(
            entry_id="rp-reports-private",
            repository="belilovsky/ipos",
            profile="qdev-ci-docker",
            source_scope="reports-private",
            source_paths=RP_SOURCE_PATHS[:-1],
        )


def test_reports_private_registry_record_cannot_be_marked_active(tmp_path: Path) -> None:
    document = yaml.safe_load(_registry_path().read_text(encoding="utf-8"))
    document["entries"]["rp-reports-private"]["activation"]["state"] = "active"
    path = tmp_path / "registry.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    with pytest.raises(ManagedRegistryError, match="scoped admission"):
        ManagedRegistry(path)
