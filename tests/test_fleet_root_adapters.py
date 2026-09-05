from __future__ import annotations

import importlib.util
import json
import os
import stat
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


def _load(name: str) -> ModuleType:
    script = ROOT / "scripts" / f"{name}.py"
    spec = importlib.util.spec_from_file_location(name, script)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


ACTIVATION = _load("qdev_controller_activation_adapter")
ENROLMENT = _load("qdev_release_host_agent_enrol_adapter")
RECOVERY = _load("qdev_fleet_worker_recovery_adapter")
PROVISION = _load("provision_fleet_host_dispatch_state")
PREPARE = _load("prepare_controller_candidate")


def _request(action: str) -> dict[str, Any]:
    return {
        "schema": "qdev-fleet-bootstrap-request-v1",
        "action": action,
        "source_sha": SHA,
        "run_id": 101,
        "job_id": 202,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": SHA,
        "controller_release_digest": DIGEST,
        "release_lane": None,
        "worker_name": None,
    }


def _activation_envelope() -> dict[str, Any]:
    return {
        "schema": "qdev-fleet-bootstrap-adapter-request-v1",
        "request": _request("activate-controller"),
        "target": {
            "controller_revision": SHA,
            "controller_release_digest": DIGEST,
            "rollback_revision": "c" * 40,
            "rollback_release_digest": "sha256:" + "d" * 64,
        },
    }


def _enrolment_target() -> dict[str, str]:
    return {
        "release_lane": "qdev-release-ortcom",
        "project_id": "ortcom",
        "placement": "ortcom-production-controller",
        "host_agent_mtls_identity": "qdev-host-agent:ortcom-production-controller",
        "native_host_adapter": "ortcom-root-deploy-v1",
        "rollback_reference": "deploy/ortcom-deploy transactional rollback",
    }


def _recovery_target() -> dict[str, Any]:
    return {
        "worker_name": "qdev-platform-ci-187",
        "target_id": "actions.runner.belilovsky-platform-portal.qdev-platform-ci-187",
        "service_unit": ("actions.runner.belilovsky-platform-portal.qdev-platform-ci-187.service"),
        "host_binding": "controller-registry",
        "labels": ["self-hosted", "Linux", "X64", "qdev-platform-ci"],
    }


def test_activation_adapter_binds_source_target_and_anchor() -> None:
    envelope = _activation_envelope()
    request, target = ACTIVATION._validate_request(envelope)
    assert request["source_sha"] == target["controller_revision"]

    with pytest.raises(ACTIVATION.AdapterError, match="source_binding_invalid"):
        ACTIVATION._validate_request(
            {
                **envelope,
                "request": {**envelope["request"], "source_sha": "e" * 40},
            }
        )
    with pytest.raises(ACTIVATION.AdapterError, match="target_identity_invalid"):
        ACTIVATION._validate_request(
            {
                **envelope,
                "target": {
                    **envelope["target"],
                    "controller_release_digest": "sha256:" + "e" * 64,
                },
            }
        )


def test_activation_adapter_accepts_legacy_migration_anchor_and_measured_runtime(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status = tmp_path / "controller-release.json"
    status.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-release-status-v1",
                "state": "active",
                "revision": SHA,
                "release_digest": "b" * 64,
                "activated_at": "2026-09-05T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    status.chmod(0o600)
    monkeypatch.setattr(ACTIVATION, "STATUS_PATH", status)
    original_lstat = Path.lstat

    def root_owned(path: Path) -> Any:
        metadata = original_lstat(path)
        return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", root_owned)
    assert ACTIVATION._read_status() == (SHA, DIGEST)

    status.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-release-status-v2",
                "state": "active",
                "revision": SHA,
                "release_digest": DIGEST,
                "activated_at": "2026-09-05T00:00:00Z",
                "runtime_identity": {
                    "source_revision": SHA,
                    "source_digest": "sha256:" + "c" * 64,
                    "public_image_id": "sha256:" + "d" * 64,
                    "internal_image_id": "sha256:" + "e" * 64,
                },
                "dependency_identity": {
                    "requirements_digest": "sha256:" + "f" * 64,
                    "public_installed_digest": "sha256:" + "1" * 64,
                    "internal_installed_digest": "sha256:" + "1" * 64,
                },
            }
        ),
        encoding="utf-8",
    )
    assert ACTIVATION._read_status() == (SHA, DIGEST)


def test_candidate_preparation_requires_same_measured_runtime_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status = tmp_path / "controller-release.json"
    monkeypatch.setattr(PREPARE, "RELEASE_STATUS_PATH", status)
    original_lstat = Path.lstat

    def root_owned(path: Path) -> Any:
        metadata = original_lstat(path)
        return SimpleNamespace(
            st_mode=metadata.st_mode,
            st_uid=os.geteuid(),
            st_size=metadata.st_size,
        )

    monkeypatch.setattr(Path, "lstat", root_owned)

    status.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-release-status-v1",
                "state": "active",
                "revision": SHA,
                "release_digest": DIGEST,
                "activated_at": "2026-09-05T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    status.chmod(0o600)
    assert PREPARE._active_runtime_source_sha() == SHA

    measured = {
        "schema": "qdev-controller-release-status-v2",
        "state": "active",
        "revision": SHA,
        "release_digest": DIGEST,
        "activated_at": "2026-09-05T00:00:00Z",
        "runtime_identity": {
            "source_revision": "c" * 40,
            "source_digest": "sha256:" + "d" * 64,
            "public_image_id": "sha256:" + "e" * 64,
            "internal_image_id": "sha256:" + "f" * 64,
        },
        "dependency_identity": {
            "requirements_digest": "sha256:" + "1" * 64,
            "public_installed_digest": "sha256:" + "2" * 64,
            "internal_installed_digest": "sha256:" + "2" * 64,
        },
    }
    status.write_text(json.dumps(measured), encoding="utf-8")
    with pytest.raises(PREPARE.ControllerCandidateError, match="status is unsafe"):
        PREPARE._active_runtime_source_sha()

    measured["runtime_identity"]["source_revision"] = SHA
    status.write_text(json.dumps(measured), encoding="utf-8")
    assert PREPARE._active_runtime_source_sha() == SHA


def test_enrolment_adapter_rejects_extra_request_fields_and_registry_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _enrolment_target()
    request = _request("enrol-host-agent")
    request["release_lane"] = target["release_lane"]
    envelope = {
        "schema": "qdev-fleet-bootstrap-adapter-request-v1",
        "request": request,
        "target": target,
    }
    monkeypatch.setattr(
        ENROLMENT.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(envelope).encode())),
    )
    _, parsed_request, parsed_target = ENROLMENT._parse()
    assert parsed_request == request
    assert parsed_target == target

    extra = {**envelope, "request": {**request, "command": "ignored"}}
    monkeypatch.setattr(
        ENROLMENT.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(extra).encode())),
    )
    with pytest.raises(ENROLMENT.AdapterError, match="request_shape_invalid"):
        ENROLMENT._parse()

    monkeypatch.setattr(
        ENROLMENT,
        "_read_private_json",
        lambda _path: {
            "schema": "qdev-release-host-enrolment-targets-v1",
            "targets": {
                target["release_lane"]: {
                    **target,
                    "placement": "wrong-placement",
                    "adapter_path": "/usr/local/sbin/fixed-enrolment",
                }
            },
        },
    )
    with pytest.raises(ENROLMENT.AdapterError, match="registry_identity_mismatch"):
        ENROLMENT._registered_adapter(target)

    malformed = {
        **envelope,
        "target": {**target, "rollback_reference": "invalid\nreference"},
    }
    monkeypatch.setattr(
        ENROLMENT.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(malformed).encode())),
    )
    with pytest.raises(ENROLMENT.AdapterError, match="target_value_invalid"):
        ENROLMENT._parse()


class _PrivateRegistry:
    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def lstat(self) -> Any:
        return SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)

    def read_text(self, *, encoding: str) -> str:
        assert encoding == "utf-8"
        return json.dumps(self.payload)


def test_worker_recovery_is_zero_job_and_full_registry_identity_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _recovery_target()
    request = _request("restore-existing-worker")
    request["worker_name"] = target["worker_name"]
    envelope = {
        "schema": "qdev-fleet-worker-recovery-request-v1",
        "request": request,
        "target": target,
        "active_jobs": 0,
    }
    monkeypatch.setattr(
        RECOVERY.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(envelope).encode())),
    )
    assert RECOVERY._parse()[2] == target

    busy = {**envelope, "active_jobs": 1}
    monkeypatch.setattr(
        RECOVERY.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(busy).encode())),
    )
    with pytest.raises(RECOVERY.AdapterError, match="request_identity_invalid"):
        RECOVERY._parse()

    registry_target = {
        **target,
        "labels": ["wrong"],
        "adapter_path": "/usr/local/sbin/fixed-recovery",
    }
    monkeypatch.setattr(
        RECOVERY,
        "REGISTRY",
        _PrivateRegistry(
            {
                "schema": "qdev-fleet-worker-recovery-targets-v1",
                "targets": {target["target_id"]: registry_target},
            }
        ),
    )
    with pytest.raises(RECOVERY.AdapterError, match="registry_identity_mismatch"):
        RECOVERY._registry_entry(target)

    malformed = {**envelope, "target": {**target, "service_unit": "../../unsafe.service"}}
    monkeypatch.setattr(
        RECOVERY.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(malformed).encode())),
    )
    with pytest.raises(RECOVERY.AdapterError, match="target_value_invalid"):
        RECOVERY._parse()


def test_dispatch_state_provisioning_is_private_and_idempotent(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    config_root = tmp_path / "qdev-runner"
    secret_root = config_root / "host-dispatch-secrets"
    monkeypatch.setattr(PROVISION, "CONFIG_ROOT", config_root)
    monkeypatch.setattr(PROVISION, "SECRET_ROOT", secret_root)
    monkeypatch.setattr(PROVISION, "KEY_MAP", config_root / "keys.json")
    monkeypatch.setattr(PROVISION, "ENROLMENT_REGISTRY", config_root / "enrolment.json")
    monkeypatch.setattr(PROVISION, "RECOVERY_REGISTRY", config_root / "recovery.json")
    monkeypatch.setattr(PROVISION.os, "geteuid", lambda: 0)
    monkeypatch.setattr(PROVISION.os, "chown", lambda *_args: None)
    monkeypatch.setattr(
        PROVISION,
        "_root_directory",
        lambda path, mode, parents: path.mkdir(mode=mode, parents=parents, exist_ok=True),
    )
    monkeypatch.setattr(
        PROVISION,
        "_private_regular",
        lambda path: (
            None
            if path.is_file()
            and not path.is_symlink()
            and stat.S_IMODE(path.stat().st_mode) == 0o600
            else (_ for _ in ()).throw(PROVISION.ProvisionError("unsafe test file"))
        ),
    )

    assert PROVISION.main() == 0
    before = {path: path.read_bytes() for path in secret_root.iterdir()}
    assert len(before) == 4
    assert PROVISION.main() == 0
    assert {path: path.read_bytes() for path in secret_root.iterdir()} == before

    mapping = json.loads(PROVISION.KEY_MAP.read_text(encoding="utf-8"))
    assert set(mapping) == set(PROVISION.HOST_IDENTITIES)
    assert all(Path(value).parent == secret_root for value in mapping.values())
    for registry in (PROVISION.ENROLMENT_REGISTRY, PROVISION.RECOVERY_REGISTRY):
        assert json.loads(registry.read_text(encoding="utf-8"))["targets"] == {}


def test_dispatch_state_rejects_a_symlinked_private_root(tmp_path: Path) -> None:
    destination = tmp_path / "destination"
    destination.mkdir()
    link = tmp_path / "private-root"
    link.symlink_to(destination, target_is_directory=True)
    with pytest.raises(PROVISION.ProvisionError, match="unsafe private controller directory"):
        PROVISION._root_directory(link, mode=0o700, parents=False)


def test_dispatch_state_rejects_unknown_preserved_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key_map = tmp_path / "keys.json"
    key_map.write_text(
        json.dumps({"qdev-host-agent:unknown": "/private/unknown"}), encoding="utf-8"
    )
    monkeypatch.setattr(PROVISION, "KEY_MAP", key_map)
    monkeypatch.setattr(PROVISION, "_private_regular", lambda _path: None)

    with pytest.raises(PROVISION.ProvisionError, match="unknown identity"):
        PROVISION._read_map()


def test_root_adapters_do_not_accept_environment_selected_targets() -> None:
    for script_name in (
        "qdev_controller_activation_adapter.py",
        "qdev_release_host_agent_enrol_adapter.py",
        "qdev_fleet_worker_recovery_adapter.py",
    ):
        source = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
        assert "os.environ" not in source
        assert "shell=True" not in source
