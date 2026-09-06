from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "qdev_test_fleet_bootstrap_validate", ROOT / "scripts" / "fleet_bootstrap_validate.py"
)
assert _SPEC is not None and _SPEC.loader is not None
validator = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(validator)


def _job(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "id": 9001,
        "run_id": 42,
        "name": "bootstrap",
        "head_sha": "a" * 40,
        "status": "in_progress",
        "conclusion": None,
    }
    result.update(overrides)
    return result


def _prepare(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.delenv("BOOTSTRAP_JOB_ID", raising=False)
    monkeypatch.setattr(validator, "_job_list", lambda repository, run_id: [_job()])


def test_resolve_job_id_binds_numeric_job_to_current_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)

    assert validator.resolve_job_id("owner/repo", 42, expected_name="bootstrap") == 9001


def test_oidc_url_accepts_only_github_oidc_hosts() -> None:
    for host in validator._GITHUB_OIDC_HOSTS:
        value = validator._https_url(
            "oidc",
            f"https://{host}/token?x=1",
            allowed_hosts=validator._GITHUB_OIDC_HOSTS,
            allowed_host_suffixes=validator._GITHUB_OIDC_HOST_SUFFIXES,
        )
        assert value.startswith(f"https://{host}/")

    wildcard = validator._https_url(
        "oidc",
        "https://run-actions-3-azure-eastus.actions.githubusercontent.com/token",
        allowed_hosts=validator._GITHUB_OIDC_HOSTS,
        allowed_host_suffixes=validator._GITHUB_OIDC_HOST_SUFFIXES,
    )
    assert wildcard.startswith("https://run-actions-3-azure-eastus.")

    with pytest.raises(validator.BootstrapValidationError, match="not allowlisted"):
        validator._https_url(
            "oidc",
            "https://actions.githubusercontent.com/token",
            allowed_hosts=validator._GITHUB_OIDC_HOSTS,
            allowed_host_suffixes=validator._GITHUB_OIDC_HOST_SUFFIXES,
        )
    with pytest.raises(validator.BootstrapValidationError, match="not allowlisted"):
        validator._https_url(
            "oidc",
            "https://evil.githubusercontent.com/token",
            allowed_hosts=validator._GITHUB_OIDC_HOSTS,
            allowed_host_suffixes=validator._GITHUB_OIDC_HOST_SUFFIXES,
        )


def test_resolve_job_id_rejects_failed_completed_job(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)
    monkeypatch.setattr(
        validator,
        "_job_list",
        lambda repository, run_id: [_job(status="completed", conclusion="failure")],
    )

    with pytest.raises(validator.BootstrapValidationError, match="did not succeed"):
        validator.resolve_job_id("owner/repo", 42, expected_name="bootstrap")


def test_resolve_job_id_rejects_profile_label_as_supplied_job_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)
    monkeypatch.setenv("BOOTSTRAP_JOB_ID", "qdev-ci")

    with pytest.raises(validator.BootstrapValidationError, match="positive integer"):
        validator.resolve_job_id("owner/repo", 42, expected_name="bootstrap")


def test_resolve_job_id_rejects_non_unique_job_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)
    monkeypatch.setattr(
        validator,
        "_job_list",
        lambda repository, run_id: [_job(), _job(id=9002)],
    )

    with pytest.raises(validator.BootstrapValidationError, match="not uniquely"):
        validator.resolve_job_id("owner/repo", 42, expected_name="bootstrap")


def test_build_request_derives_controller_tuple_from_running_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_sha = "b" * 40
    release_digest = "sha256:" + "c" * 64
    policy = validator.FleetBootstrapPolicy(
        ROOT / "config" / "fleet-bootstrap.yml",
        ROOT / "config" / "release-lanes.yml",
    )
    monkeypatch.setenv("GITHUB_REPOSITORY", policy.identity.repository)
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "3")
    monkeypatch.setenv("GITHUB_SHA", source_sha)
    monkeypatch.setenv("BOOTSTRAP_JOB_NAME", "bootstrap")
    monkeypatch.setenv("BOOTSTRAP_ACTION", "activate-controller")
    # Obsolete caller-selected values must not be able to redirect activation.
    monkeypatch.setenv("BOOTSTRAP_CONTROLLER_REVISION", "d" * 40)
    monkeypatch.setenv("BOOTSTRAP_CONTROLLER_RELEASE_DIGEST", "sha256:" + "e" * 64)
    monkeypatch.setenv("BOOTSTRAP_CONTROLLER_IMAGE_DIGEST", "sha256:" + "f" * 64)
    monkeypatch.setenv("BOOTSTRAP_ACTIVATION_ENVELOPE_DIGEST", "sha256:" + "1" * 64)
    monkeypatch.setattr(validator, "resolve_job_id", lambda *args, **kwargs: 9001)
    monkeypatch.setattr(validator, "controller_release_digest", lambda root: release_digest)

    request = validator.build_request(policy)

    assert request.source_sha == source_sha
    assert request.controller_revision == source_sha
    assert request.controller_release_digest == release_digest
    assert request.controller_image_digest == "sha256:" + "f" * 64
    assert request.activation_envelope_digest == "sha256:" + "1" * 64
    assert request.run_id == 42
    assert request.job_id == 9001
    assert request.attempt == 3
