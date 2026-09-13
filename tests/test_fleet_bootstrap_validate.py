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
        "run_attempt": 3,
        "name": "bootstrap",
        "head_sha": "a" * 40,
        "status": "in_progress",
        "conclusion": None,
    }
    result.update(overrides)
    return result


def _prepare(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "3")
    monkeypatch.delenv("BOOTSTRAP_JOB_ID", raising=False)
    monkeypatch.setattr(validator, "_job_list", lambda repository, run_id: [_job()])


def test_resolve_job_id_binds_numeric_job_to_current_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)

    assert validator.resolve_job_id("owner/repo", 42, expected_name="bootstrap") == 9001


@pytest.mark.parametrize("attempt", [None, 1, 2, 4, True, "3"])
def test_resolve_job_rejects_other_or_invalid_attempt(
    monkeypatch: pytest.MonkeyPatch, attempt: object
) -> None:
    _prepare(monkeypatch)
    monkeypatch.setattr(
        validator, "_job_list", lambda repository, run_id: [_job(run_attempt=attempt)]
    )
    with pytest.raises(validator.BootstrapValidationError, match="does not match"):
        validator.resolve_job_id("owner/repo", 42, expected_name="bootstrap")


@pytest.mark.parametrize("total", [0, 1, 2, None, True])
def test_job_list_is_attempt_scoped_and_complete(
    monkeypatch: pytest.MonkeyPatch, total: object
) -> None:
    monkeypatch.setenv("GITHUB_TOKEN", "test-only")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "3")
    monkeypatch.setenv("GITHUB_API_URL", "https://api.github.com")

    def response(url: str, **kwargs: object) -> dict[str, object]:
        assert url.endswith("/repos/owner/repo/actions/runs/42/attempts/3/jobs?per_page=100")
        return {"jobs": [_job()], "total_count": total}

    monkeypatch.setattr(validator, "_json_request", response)
    if type(total) is int and total == 1:
        assert validator._job_list("owner/repo", 42) == [_job()]
    else:
        with pytest.raises(validator.BootstrapValidationError, match="incomplete"):
            validator._job_list("owner/repo", 42)


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


@pytest.mark.parametrize(
    "unexpected_field",
    [
        None,
        "BOOTSTRAP_CONTROLLER_REVISION",
        "BOOTSTRAP_CONTROLLER_RELEASE_DIGEST",
        "BOOTSTRAP_CONTROLLER_IMAGE_DIGEST",
        "BOOTSTRAP_CONTROLLER_INTERNAL_IMAGE_DIGEST",
        "BOOTSTRAP_ACTIVATION_ENVELOPE_DIGEST",
        "BOOTSTRAP_RELEASE_LANE",
    ],
)
def test_worker_restore_has_no_activation_tuple(
    monkeypatch: pytest.MonkeyPatch, unexpected_field: str | None
) -> None:
    policy = validator.FleetBootstrapPolicy(
        ROOT / "config" / "fleet-bootstrap.yml",
        ROOT / "config" / "release-lanes.yml",
    )
    for name in (
        "BOOTSTRAP_CONTROLLER_REVISION",
        "BOOTSTRAP_CONTROLLER_RELEASE_DIGEST",
        "BOOTSTRAP_CONTROLLER_IMAGE_DIGEST",
        "BOOTSTRAP_CONTROLLER_INTERNAL_IMAGE_DIGEST",
        "BOOTSTRAP_ACTIVATION_ENVELOPE_DIGEST",
        "BOOTSTRAP_RELEASE_LANE",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GITHUB_REPOSITORY", policy.identity.repository)
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "3")
    monkeypatch.setenv("GITHUB_SHA", "b" * 40)
    monkeypatch.setenv("BOOTSTRAP_JOB_NAME", "bootstrap")
    monkeypatch.setenv("BOOTSTRAP_ACTION", "restore-existing-worker")
    monkeypatch.setenv("BOOTSTRAP_WORKER_NAME", "qdev-qazstack-01")
    monkeypatch.setattr(validator, "resolve_job_id", lambda *args, **kwargs: 9001)

    def unexpected_release_hash(root: Path) -> str:
        pytest.fail("worker restoration must not compute an activation release")

    monkeypatch.setattr(validator, "controller_release_digest", unexpected_release_hash)
    if unexpected_field:
        monkeypatch.setenv(unexpected_field, "unexpected")
        with pytest.raises(validator.BootstrapValidationError, match="fields are invalid"):
            validator.build_request(policy)
        return

    request = validator.build_request(policy)
    assert request.worker_name == "qdev-qazstack-01"
    assert request.controller_revision is None
    assert request.controller_release_digest is None
    assert request.source_sha == "b" * 40
    assert request.attempt == 3


def test_workflow_exposes_only_registered_recovery_worker_choices() -> None:
    workflow = (ROOT / ".github" / "workflows" / "fleet-bootstrap.yml").read_text(
        encoding="utf-8"
    )

    assert "worker_name:" in workflow
    for worker_name in (
        "srv1879763-primary",
        "qdev-qazstack-01",
        "qdev-platform-ci-187",
    ):
        assert f"- {worker_name}" in workflow
    assert workflow.count(
        "BOOTSTRAP_WORKER_NAME: ${{ inputs.action == 'restore-existing-worker' && inputs.worker_name || '' }}"
    ) == 2
