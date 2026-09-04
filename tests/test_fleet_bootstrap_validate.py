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
