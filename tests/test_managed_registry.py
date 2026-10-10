from pathlib import Path

import pytest
import yaml

from qdev_runner.managed_registry import ManagedRegistry, ManagedRegistryError


def _registry_path() -> Path:
    return Path(__file__).parents[1] / "config" / "managed-registry.yml"


def test_managed_registry_separates_admin_wave_qazgeo_and_qazagents_static() -> None:
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
    qazagents = registry.entry_for_repository("belilovsky/qazagents")
    assert qazagents is not None
    assert qazagents.admission_ledger == "managed-production"
    assert qazagents.native_release_profile == "qazagents-static-release-v1"
    assert qazagents.runtime_endpoints == (
        "https://qazagents.qdev.run/health.json",
        "https://qazagents.qdev.run/readiness.json",
        "https://qazagents.qdev.run/release.json",
        "https://qazagents.qdev.run/skills/index.json",
    )
    assert registry.validate_claim_if_managed("belilovsky/qazagents", "qdev-ci") == qazagents
    with pytest.raises(ManagedRegistryError, match="profile"):
        registry.validate_claim_if_managed("belilovsky/qazagents", "qdev-ci-docker")


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


def test_public_ipos_profile_preserves_rp_repository_claim_default() -> None:
    registry = ManagedRegistry(_registry_path())
    rp = registry.entry_for_id("rp")
    public = registry.entry_for_id("ipos")
    assert rp is not None and public is not None
    assert registry.entry_for_repository("belilovsky/ipos") == rp
    assert registry.validate_claim_if_managed("belilovsky/ipos", "qdev-ci") == rp
    assert public.project_id == "ipos"
    assert public.native_release_profile == "ipos-public-native-immutable-release-v1"
    assert public.repository_claim_default is False
    assert public.host_identity != rp.host_identity
    assert public.runtime_endpoints[-1] == "https://ipos.qdev.run/api/v1/system/release-identity"
    assert public.artifact_repository == "belilovsky/ipos-app"


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("repository_claim_default", True, "exactly one"),
        ("repository_claim_default", "false", "boolean"),
        ("canonical_ref", "other", "inconsistent"),
        ("allowed_profiles", ["qdev-ci"], "inconsistent"),
        ("host_identity", "qdev-release-agent:rp-private-runtime", "inconsistent"),
        ("native_release_profile", "rp-native-immutable-release-v1", "inconsistent"),
        ("project_id", "rp", "inconsistent"),
    ],
)
def test_shared_repository_rejects_ambiguous_or_drifting_profiles(
    tmp_path: Path, field: str, value: object, error: str
) -> None:
    document = yaml.safe_load(_registry_path().read_text(encoding="utf-8"))
    document["entries"]["ipos"][field] = value
    path = tmp_path / "registry.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    with pytest.raises(ManagedRegistryError, match=error):
        ManagedRegistry(path)
