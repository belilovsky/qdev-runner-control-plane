from __future__ import annotations

import copy
from pathlib import Path

import pytest

from qdev_runner.admin_platform_release_binding import (
    AdminPlatformReleaseBindingError,
    sign_release_binding,
    verify_release_binding,
)
from qdev_runner.controller_admission import initialize_keypair

SOURCE_SHA = "1" * 40


def _keys(tmp_path: Path) -> tuple[Path, Path]:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    initialize_keypair(private, public)
    return private, public


def _payload() -> dict[str, object]:
    return {
        "subject": "qaz-admin-kit",
        "package": "qaz-admin-kit",
        "version": "0.4.9",
        "source_sha": SOURCE_SHA,
        "artifact_checksum": "2" * 64,
        "artifact_uri": "https://artifacts.qdev.run/qaz-admin-kit/0.4.9/qaz-admin-kit.whl",
        "workflow": {
            "name": "release-package",
            "run_id": "42",
            "job_id": "43",
            "attempt": "1",
            "head_sha": SOURCE_SHA,
        },
    }


def test_sign_and_verify_exact_immutable_binding(tmp_path: Path) -> None:
    private, public = _keys(tmp_path)
    binding = sign_release_binding(_payload(), private)

    verified = verify_release_binding(binding, public)

    assert verified["source_sha"] == SOURCE_SHA
    assert binding["signature"]["key_id"].startswith("sha256:")


def test_binding_rejects_tampering_and_unknown_authority(tmp_path: Path) -> None:
    private, public = _keys(tmp_path)
    binding = sign_release_binding(_payload(), private)
    tampered = copy.deepcopy(binding)
    tampered["payload"]["artifact_checksum"] = "3" * 64
    with pytest.raises(AdminPlatformReleaseBindingError, match="payload digest"):
        verify_release_binding(tampered, public)

    _other_private, other_public = _keys(tmp_path / "other")
    with pytest.raises(AdminPlatformReleaseBindingError, match="unknown authority"):
        verify_release_binding(binding, other_public)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("artifact_uri", "https://artifacts.qdev.run/qaz-admin-kit/latest.whl", "immutable"),
        ("artifact_uri", "file:///tmp/qaz-admin-kit.whl", "invalid"),
        ("artifact_checksum", "A" * 64, "invalid"),
        ("source_sha", "0" * 39, "invalid"),
    ],
)
def test_binding_rejects_nonimmutable_or_malformed_tuple(
    tmp_path: Path, field: str, value: str, message: str
) -> None:
    private, _public = _keys(tmp_path)
    payload = _payload()
    payload[field] = value
    with pytest.raises(AdminPlatformReleaseBindingError, match=message):
        sign_release_binding(payload, private)


def test_binding_rejects_workflow_drift_and_unsafe_asset_manifest(tmp_path: Path) -> None:
    private, _public = _keys(tmp_path)
    payload = _payload()
    workflow = payload["workflow"]
    assert isinstance(workflow, dict)
    workflow["head_sha"] = "4" * 40
    with pytest.raises(AdminPlatformReleaseBindingError, match="differs"):
        sign_release_binding(payload, private)

    payload = _payload()
    payload["asset_manifest"] = {"../admin-shell.js": "5" * 64}
    with pytest.raises(AdminPlatformReleaseBindingError, match="path is invalid"):
        sign_release_binding(payload, private)


def test_binding_accepts_signed_avds_asset_manifest(tmp_path: Path) -> None:
    private, public = _keys(tmp_path)
    payload = _payload()
    payload.update(
        {
            "subject": "avds-admin-shell",
            "package": "@av/admin-shell",
            "version": "0.2.2",
            "asset_manifest": {"admin-shell.css": "6" * 64},
        }
    )
    binding = sign_release_binding(payload, private)
    verified = verify_release_binding(binding, public)

    assert verified["asset_manifest"] == {"admin-shell.css": "6" * 64}
