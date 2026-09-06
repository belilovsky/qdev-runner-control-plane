from pathlib import Path

import pytest
import yaml

from qdev_runner.managed_registry import ManagedRegistry, ManagedRegistryError


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
