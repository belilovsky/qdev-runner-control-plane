from __future__ import annotations

import copy
import json
import os
from collections.abc import Callable
from pathlib import Path

import pytest

from qdev_runner.admin_platform_package_issuer import (
    AdminPlatformPackageIssuerError,
    issue_binding,
)
from qdev_runner.admin_platform_release_binding import verify_release_binding
from qdev_runner.controller_admission import initialize_keypair

SOURCE_SHA = "1" * 40


def _write_json(path: Path, value: object, mode: int = 0o600) -> None:
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(mode)


def _setup(tmp_path: Path) -> tuple[Path, Path, Path, Path]:
    root = tmp_path / "spool"
    incoming = root / "incoming"
    issued = root / "issued"
    for path in (root, incoming, issued):
        path.mkdir()
        path.chmod(0o700)
    policy = tmp_path / "policy.json"
    _write_json(
        policy,
        {
            "schema_version": "qdev-admin-platform-package-binding-policy-v1",
            "subjects": {
                "qaz-admin-kit": {
                    "package": "qaz-admin-kit",
                    "repository": "belilovsky/qaz-admin-kit",
                    "workflow": "Publish federated admin package",
                    "artifact_uri_prefix": "https://ci.qdev.run/artifacts/belilovsky/qaz-admin-kit/",
                }
            },
        },
        0o644,
    )
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    initialize_keypair(private, public)
    return root, policy, private, public


def _request(request_id: str = "qak-049-0001") -> dict[str, object]:
    return {
        "schema_version": "qdev-admin-platform-package-binding-request-v1",
        "request_id": request_id,
        "repository": "belilovsky/qaz-admin-kit",
        "ci_receipt_sha256": "2" * 64,
        "payload": {
            "subject": "qaz-admin-kit",
            "package": "qaz-admin-kit",
            "version": "0.4.9",
            "source_sha": SOURCE_SHA,
            "artifact_checksum": "3" * 64,
            "artifact_uri": (
                "https://ci.qdev.run/artifacts/belilovsky/qaz-admin-kit/"
                f"{SOURCE_SHA}/42/qaz-admin-kit-0.4.9.tar.gz"
            ),
            "workflow": {
                "name": "Publish federated admin package",
                "run_id": "42",
                "job_id": "43",
                "attempt": "1",
                "head_sha": SOURCE_SHA,
            },
        },
    }


def _issue(root: Path, policy: Path, private: Path) -> dict[str, object]:
    return issue_binding(
        "qak-049-0001",
        policy_path=policy,
        private_key_path=private,
        request_root=root,
    )


def test_issuer_signs_only_policy_bound_immutable_request(tmp_path: Path) -> None:
    root, policy, private, public = _setup(tmp_path)
    request = _request()
    _write_json(root / "incoming" / "qak-049-0001.json", request)

    issued = _issue(root, policy, private)

    verified = verify_release_binding(issued["binding"], public)
    assert verified["source_sha"] == SOURCE_SHA
    assert (root / "issued" / "qak-049-0001.json").stat().st_mode & 0o777 == 0o600
    assert _issue(root, policy, private) == issued


@pytest.mark.parametrize(
    "mutator",
    [
        lambda value: value.__setitem__("repository", "belilovsky/other"),
        lambda value: value["payload"].__setitem__(
            "artifact_uri", "https://ci.qdev.run/artifacts/belilovsky/other/immutable.tar.gz"
        ),
        lambda value: value["payload"]["workflow"].__setitem__("name", "other workflow"),
    ],
)
def test_issuer_rejects_request_outside_static_policy(
    tmp_path: Path, mutator: Callable[[dict[str, object]], None]
) -> None:
    root, policy, private, _public = _setup(tmp_path)
    request = _request()
    mutator(request)
    _write_json(root / "incoming" / "qak-049-0001.json", request)

    with pytest.raises(AdminPlatformPackageIssuerError, match="does not match policy"):
        _issue(root, policy, private)


def test_issuer_rejects_changed_request_after_idempotent_issue(tmp_path: Path) -> None:
    root, policy, private, _public = _setup(tmp_path)
    request_path = root / "incoming" / "qak-049-0001.json"
    _write_json(request_path, _request())
    issue_binding("qak-049-0001", policy_path=policy, private_key_path=private, request_root=root)
    changed = copy.deepcopy(_request())
    changed["ci_receipt_sha256"] = "4" * 64
    _write_json(request_path, changed)

    with pytest.raises(AdminPlatformPackageIssuerError, match="conflicts"):
        _issue(root, policy, private)


def test_issuer_rejects_unsafe_spool_permissions(tmp_path: Path) -> None:
    root, policy, private, _public = _setup(tmp_path)
    _write_json(root / "incoming" / "qak-049-0001.json", _request())
    os.chmod(root / "issued", 0o500)

    with pytest.raises(AdminPlatformPackageIssuerError, match="unsafe"):
        _issue(root, policy, private)
