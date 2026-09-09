from __future__ import annotations

import hashlib
import importlib.util
import json
import stat
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
IMAGE_DIGEST = "sha256:" + "c" * 64
ENVELOPE_DIGEST = "sha256:" + "d" * 64


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
FIXED_RECOVERY = _load("qdev_fixed_worker_recovery_dispatch")
CI_CONFIGURATION_RECOVERY = _load("qdev_ci_worker_configuration_recovery")
HOST_ENROL = _load("qdev_recovery_host_enrol_adapter")
HOST_APPLY = _load("qdev_recovery_host_apply")
PROVISION = _load("provision_fleet_host_dispatch_state")
ACTIVATION_TRUST = _load("provision_controller_activation_trust")


def _request(action: str) -> dict[str, Any]:
    return {
        "schema": "qdev-fleet-bootstrap-request-v2",
        "action": action,
        "source_sha": SHA,
        "run_id": 101,
        "job_id": 202,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": None,
        "controller_release_digest": None,
        "controller_image_digest": None,
        "controller_internal_image_digest": None,
        "activation_envelope_digest": None,
        "release_lane": None,
        "worker_name": None,
    }


def _bootstrap_request(action: str) -> dict[str, Any]:
    return {
        "schema": "qdev-fleet-bootstrap-request-v2",
        "action": action,
        "source_sha": SHA,
        "run_id": 101,
        "job_id": 202,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": SHA,
        "controller_release_digest": DIGEST,
        "controller_image_digest": IMAGE_DIGEST,
        "controller_internal_image_digest": IMAGE_DIGEST,
        "activation_envelope_digest": ENVELOPE_DIGEST,
        "release_lane": None,
        "worker_name": None,
    }


def _activation_envelope() -> dict[str, Any]:
    return {
        "schema": "qdev-fleet-bootstrap-adapter-request-v2",
        "request": _bootstrap_request("activate-controller"),
        "target": {
            "controller_revision": SHA,
            "controller_release_digest": DIGEST,
            "controller_image_digest": IMAGE_DIGEST,
            "activation_envelope_digest": ENVELOPE_DIGEST,
            "activation_mode": "signed-external-envelope",
            "activation_envelope_schema": "qdev-controller-activation-envelope-v1",
            "activation_public_key_binding": "controller-registry",
            "activation_max_envelope_ttl_seconds": 1800,
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


def _qazagents_enrolment_target() -> dict[str, str]:
    """A public logical target; private adapter registration is intentionally absent."""

    return {
        "release_lane": "qdev-release-qazagents-static",
        "project_id": "qazagents",
        "placement": "qazagents-static-runtime",
        "host_agent_mtls_identity": "qdev-host-agent:qazagents-static-runtime",
        "native_host_adapter": "qazagents-static-release-v1",
        "rollback_reference": "controller-verified immutable QazAgents static rollback receipt",
    }


def _recovery_target() -> dict[str, Any]:
    return {
        "worker_name": "qdev-platform-ci-187",
        "target_id": "actions.runner.belilovsky-platform-portal.qdev-platform-ci-187",
        "service_unit": ("actions.runner.belilovsky-platform-portal.qdev-platform-ci-187.service"),
        "host_binding": "controller-registry",
        "labels": ["self-hosted", "Linux", "X64", "qdev-platform-ci"],
    }


def test_activation_adapter_binds_source_target_and_signed_envelope() -> None:
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


def test_activation_adapter_accepts_and_validates_runtime_rollback_anchor() -> None:
    envelope = _activation_envelope()
    request = {
        **envelope["request"],
        "controller_internal_image_digest": IMAGE_DIGEST,
    }
    target = {
        **envelope["target"],
        "controller_internal_image_digest": IMAGE_DIGEST,
        "rollback_revision": "e" * 40,
        "rollback_release_digest": "sha256:" + "f" * 64,
    }
    parsed_request, parsed_target = ACTIVATION._validate_request(
        {**envelope, "request": request, "target": target}
    )
    assert parsed_request["controller_internal_image_digest"] == IMAGE_DIGEST
    assert parsed_target["rollback_revision"] == "e" * 40

    with pytest.raises(ACTIVATION.AdapterError, match="rollback_revision_invalid"):
        ACTIVATION._validate_request(
            {**envelope, "request": request, "target": {**target, "rollback_revision": "bad"}}
        )


def test_activation_adapter_rejects_legacy_runtime_status(
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
    with pytest.raises(ACTIVATION.AdapterError, match="runtime_status_invalid"):
        ACTIVATION._read_status()


def test_activation_adapter_accepts_measured_runtime_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status = tmp_path / "controller-release.json"
    status.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-release-status-v2",
                "state": "active",
                "revision": SHA,
                "release_digest": DIGEST,
                "activated_at": "2026-09-05T12:00:00Z",
                "runtime_identity": {
                    "source_revision": SHA,
                    "source_digest": "sha256:" + "e" * 64,
                    "public_image_id": IMAGE_DIGEST,
                    "internal_image_id": IMAGE_DIGEST,
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
    status.chmod(0o600)
    monkeypatch.setattr(ACTIVATION, "STATUS_PATH", status)
    original_lstat = Path.lstat

    def root_owned(path: Path) -> Any:
        metadata = original_lstat(path)
        return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", root_owned)
    assert ACTIVATION._read_status() == (SHA, DIGEST, IMAGE_DIGEST, IMAGE_DIGEST)


def test_activation_adapter_accepts_root_owned_current_symlink(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    releases = tmp_path / "releases"
    release = releases / SHA
    activation = release / "scripts" / "activate_controller_release.sh"
    identity = release / "src" / "qdev_runner" / "controller_release.py"
    activation.parent.mkdir(parents=True)
    identity.parent.mkdir(parents=True)
    activation.write_text("#!/bin/sh\n", encoding="utf-8")
    identity.write_text("", encoding="utf-8")
    for path in (releases, release, activation.parent, release / "src", identity.parent):
        path.chmod(0o755)
    activation.chmod(0o755)
    identity.chmod(0o644)
    current = tmp_path / "current"
    current.symlink_to(release, target_is_directory=True)

    monkeypatch.setattr(ACTIVATION, "RELEASES_ROOT", releases)
    monkeypatch.setattr(ACTIVATION, "CURRENT_RELEASE", current)
    original_lstat = Path.lstat

    def root_owned(path: Path) -> Any:
        metadata = original_lstat(path)
        mode = metadata.st_mode
        if path == current:
            mode = (mode & ~0o777) | 0o777
        return SimpleNamespace(st_mode=mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", root_owned)
    monkeypatch.setattr(ACTIVATION, "_validate_root_directory", lambda path: path.resolve())
    monkeypatch.setattr(
        ACTIVATION.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=DIGEST),
    )

    # Linux reports symlink permissions as 0777; ownership and target-chain
    # validation provide the actual trust boundary.
    assert stat.S_IMODE(root_owned(current).st_mode) == 0o777
    assert ACTIVATION._trusted_current(SHA, DIGEST) == (release, activation)


def test_activation_adapter_binds_committed_status_to_signed_candidate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    status = tmp_path / "activation-status.json"
    payload = {
        "schema": "qdev-controller-activation-status-v1",
        "state": "active",
        "generation": 8,
        "source_sha": SHA,
        "image_digest": IMAGE_DIGEST[7:],
        "policy_bundle_digest": "e" * 64,
        "previous": {
            "generation": 7,
            "source_sha": "f" * 40,
            "image_digest": "1" * 64,
            "policy_bundle_digest": "2" * 64,
        },
        "transaction_id": "transaction-0001",
        "activated_at": "2026-09-05T01:00:00Z",
    }
    status.write_text(json.dumps(payload), encoding="utf-8")
    status.chmod(0o600)
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_STATUS_PATH", status)
    original_lstat = Path.lstat

    def root_owned(path: Path) -> Any:
        metadata = original_lstat(path)
        return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", root_owned)
    assert ACTIVATION._read_activation_status(
        expected_source_sha=SHA,
        expected_public_image_digest=IMAGE_DIGEST[7:],
        expected_internal_image_digest=IMAGE_DIGEST[7:],
        expected_policy_digest="e" * 64,
        expected_transaction_id="transaction-0001",
    ) == (
        "f" * 40,
        "sha256:" + "1" * 64,
        "sha256:" + "1" * 64,
        "sha256:" + "2" * 64,
        7,
    )

    for field, value in (
        ("source_sha", "0" * 40),
        ("image_digest", "0" * 64),
        ("policy_bundle_digest", "0" * 64),
        ("transaction_id", "transaction-forged"),
    ):
        forged = {**payload, field: value}
        status.write_text(json.dumps(forged), encoding="utf-8")
        with pytest.raises(ACTIVATION.AdapterError, match="activation_status_invalid"):
            ACTIVATION._read_activation_status(
                expected_source_sha=SHA,
                expected_public_image_digest=IMAGE_DIGEST[7:],
                expected_internal_image_digest=IMAGE_DIGEST[7:],
                expected_policy_digest="e" * 64,
                expected_transaction_id="transaction-0001",
            )


def test_activation_adapter_resolves_core_raw_digest_assets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assets = tmp_path / "activation"
    envelopes = assets / "envelopes"
    artifacts = assets / "artifacts"
    envelopes.mkdir(parents=True)
    artifacts.mkdir()
    public_key = tmp_path / "activation.pub"
    admission_key = tmp_path / "admission.pub"
    binding_path = tmp_path / "activation-binding.json"
    public_key.write_text("trusted-key", encoding="utf-8")
    admission_key.write_text("trusted-key", encoding="utf-8")
    transaction_id = "transaction-0001"
    manifest_digest = "3" * 64
    policy_digest = "4" * 64
    envelope = {
        "schema": "qdev-controller-activation-envelope-v1",
        "transaction_id": transaction_id,
        "candidate": {
            "source_sha": SHA,
            "image_digest": IMAGE_DIGEST[7:],
            "policy_bundle_digest": policy_digest,
        },
        "candidate_release_digest": DIGEST[7:],
        "artifact_manifest_digest": manifest_digest,
    }
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    envelope_digest = "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    envelope_path = envelopes / f"{envelope_digest[7:]}.json"
    envelope_path.write_text(json.dumps(envelope), encoding="utf-8")
    manifest_path = artifacts / f"{manifest_digest}.json"
    manifest_path.write_text("{}", encoding="utf-8")
    for path in (envelope_path, manifest_path):
        path.chmod(0o600)
    public_key.chmod(0o644)
    admission_key.chmod(0o644)
    binding_path.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-activation-trust-binding-v1",
                "binding": "controller-registry",
                "authority": "controller-admission",
                "source_path": str(admission_key),
                "source_sha256": "sha256:" + hashlib.sha256(admission_key.read_bytes()).hexdigest(),
                "activation_public_key_path": str(public_key),
                "activation_public_key_sha256": "sha256:"
                + hashlib.sha256(public_key.read_bytes()).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    binding_path.chmod(0o644)
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_ASSETS_ROOT", assets)
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_PUBLIC_KEY", public_key)
    monkeypatch.setattr(ACTIVATION, "ADMISSION_PUBLIC_KEY", admission_key)
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_TRUST_BINDING", binding_path)
    original_lstat = Path.lstat

    def root_owned(path: Path) -> Any:
        metadata = original_lstat(path)
        return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", root_owned)
    request = {**_bootstrap_request("activate-controller")}
    request["activation_envelope_digest"] = envelope_digest
    assert ACTIVATION._activation_assets(request) == (
        envelope_path,
        manifest_path,
        public_key,
        policy_digest,
        transaction_id,
    )


def test_activation_adapter_rejects_unbound_or_different_activation_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    admission_key = tmp_path / "admission.pub"
    activation_key = tmp_path / "activation.pub"
    binding_path = tmp_path / "activation-binding.json"
    admission_key.write_text("admission-key", encoding="utf-8")
    activation_key.write_text("different-key", encoding="utf-8")
    binding_path.write_text("{}", encoding="utf-8")
    for path in (admission_key, activation_key, binding_path):
        path.chmod(0o644)
    monkeypatch.setattr(ACTIVATION, "ADMISSION_PUBLIC_KEY", admission_key)
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_PUBLIC_KEY", activation_key)
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_TRUST_BINDING", binding_path)
    original_lstat = Path.lstat

    def root_owned(path: Path) -> Any:
        metadata = original_lstat(path)
        return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", root_owned)
    with pytest.raises(ACTIVATION.AdapterError, match="activation_trust_binding_invalid"):
        ACTIVATION._activation_public_key()


def test_activation_trust_binding_is_fixed_to_controller_admission_key() -> None:
    admission_key = b"-----BEGIN PUBLIC KEY-----\nexample\n-----END PUBLIC KEY-----\n"
    binding = ACTIVATION_TRUST._binding(admission_key)

    assert binding == {
        "schema": "qdev-controller-activation-trust-binding-v1",
        "binding": "controller-registry",
        "authority": "controller-admission",
        "source_path": "/etc/qdev-runner/admission/ed25519-public.pem",
        "source_sha256": "sha256:" + hashlib.sha256(admission_key).hexdigest(),
        "activation_public_key_path": "/etc/qdev-runner/trust/controller-activation-ed25519.pub",
        "activation_public_key_sha256": "sha256:" + hashlib.sha256(admission_key).hexdigest(),
    }


def test_enrolment_adapter_rejects_extra_request_fields_and_registry_drift(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = _enrolment_target()
    request = _bootstrap_request("enrol-host-agent")
    request["release_lane"] = target["release_lane"]
    envelope = {
        "schema": "qdev-fleet-bootstrap-adapter-request-v2",
        "request": request,
        "target": target,
    }
    monkeypatch.setattr(
        ENROLMENT.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(envelope).encode())),
    )
    _, parsed_request, parsed_target = ENROLMENT._parse()
    assert parsed_request == {
        **request,
        "controller_internal_image_digest": IMAGE_DIGEST,
    }
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


def test_qazagents_enrolment_is_access_blocked_without_private_mapping(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    target = _qazagents_enrolment_target()
    request = _bootstrap_request("enrol-host-agent")
    request["release_lane"] = target["release_lane"]
    envelope = {
        "schema": "qdev-fleet-bootstrap-adapter-request-v2",
        "request": request,
        "target": target,
    }
    monkeypatch.setattr(
        ENROLMENT.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(envelope).encode())),
    )
    monkeypatch.setattr(ENROLMENT.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        ENROLMENT,
        "_controller_rollback",
        lambda _request: (SHA, DIGEST, IMAGE_DIGEST, IMAGE_DIGEST, 7),
    )
    monkeypatch.setattr(
        ENROLMENT,
        "_read_private_json",
        lambda _path: {"schema": "qdev-release-host-enrolment-targets-v1", "targets": {}},
    )

    assert ENROLMENT.main() == 0
    response = json.loads(capsys.readouterr().out)
    assert response["schema"] == "qdev-fleet-bootstrap-adapter-result-v2"
    assert response["status"] == "access_blocked"
    assert response["release_lane"] == target["release_lane"]
    assert response["host_agent_mtls_identity"] == target["host_agent_mtls_identity"]
    assert response["result"] == {"error_code": "target_unregistered"}


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
    assert len(before) == len(PROVISION.HOST_IDENTITIES)
    assert PROVISION.main() == 0
    assert {path: path.read_bytes() for path in secret_root.iterdir()} == before

    mapping = json.loads(PROVISION.KEY_MAP.read_text(encoding="utf-8"))
    assert set(mapping) == set(PROVISION.HOST_IDENTITIES)
    assert "qdev-host-agent:qazgeo-app-runtime" in mapping
    assert all(Path(value).parent == secret_root for value in mapping.values())
    assert json.loads(PROVISION.ENROLMENT_REGISTRY.read_text(encoding="utf-8"))["targets"] == {}
    assert (
        json.loads(PROVISION.RECOVERY_REGISTRY.read_text(encoding="utf-8"))["targets"]
        == PROVISION.RECOVERY_TARGETS
    )


def test_dispatch_state_rejects_conflicting_or_unknown_recovery_targets(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    registry = tmp_path / "recovery.json"
    monkeypatch.setattr(PROVISION, "RECOVERY_REGISTRY", registry)
    monkeypatch.setattr(PROVISION, "_private_regular", lambda _path: None)
    registry.write_text(
        json.dumps(
            {
                "schema": "qdev-fleet-worker-recovery-targets-v1",
                "targets": {"unknown": {}},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(PROVISION.ProvisionError, match="unknown target"):
        PROVISION._reconcile_recovery_registry()

    registry.write_text(
        json.dumps(
            {
                "schema": "qdev-fleet-worker-recovery-targets-v1",
                "targets": {next(iter(PROVISION.RECOVERY_TARGETS)): {"adapter_path": "wrong"}},
            }
        ),
        encoding="utf-8",
    )
    with pytest.raises(PROVISION.ProvisionError, match="conflicts with policy"):
        PROVISION._reconcile_recovery_registry()


def test_fixed_worker_dispatch_is_allowlisted_and_uses_exact_ssh_argv(
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
        FIXED_RECOVERY.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(envelope).encode())),
    )
    assert FIXED_RECOVERY._parse()[1]["host"] == "187.55.228.239"

    injected = {**envelope, "target": {**target, "host": "example.invalid"}}
    monkeypatch.setattr(
        FIXED_RECOVERY.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(injected).encode())),
    )
    with pytest.raises(FIXED_RECOVERY.DispatchError, match="target_identity_mismatch"):
        FIXED_RECOVERY._parse()

    calls: list[list[str]] = []
    monkeypatch.setattr(FIXED_RECOVERY.os, "geteuid", lambda: 0)
    monkeypatch.setattr(FIXED_RECOVERY, "_validate_private_identity", lambda **_kwargs: None)
    monkeypatch.setattr(
        FIXED_RECOVERY,
        "_enrol",
        lambda _target_id, _expected: {
            "schema": "qdev-recovery-host-enrol-result-v1",
            "status": "completed",
            "profile": "platform",
            "controller_revision": SHA,
            "controller_release_digest": DIGEST,
            "agent_release_digest": "sha256:" + "c" * 64,
            "agent_certificate_sha256": "d" * 64,
            "rollback_agent_release_digest": "none",
            "receipt_digest": "sha256:" + "e" * 64,
        },
    )
    monkeypatch.setattr(
        FIXED_RECOVERY.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(envelope).encode())),
    )

    def completed(command: list[str], **kwargs: Any) -> SimpleNamespace:
        calls.append(command)
        assert kwargs["stdin"] is FIXED_RECOVERY.subprocess.DEVNULL
        assert kwargs["stdout"] is FIXED_RECOVERY.subprocess.DEVNULL
        assert kwargs["stderr"] is FIXED_RECOVERY.subprocess.DEVNULL
        assert kwargs["check"] is False
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(FIXED_RECOVERY.subprocess, "run", completed)
    assert FIXED_RECOVERY.main() == 0
    assert calls == [
        [
            "/usr/bin/ssh",
            "-F",
            "/dev/null",
            "-i",
            "/etc/qdev-runner/worker-recovery-dispatch/id_ed25519",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            "UserKnownHostsFile=/etc/qdev-runner/worker-recovery-dispatch/known_hosts",
            "-o",
            "ConnectTimeout=15",
            "root@187.55.228.239",
            "/usr/bin/systemctl",
            "start",
            "qdev-runner-recovery-platform.service",
        ]
    ]


def test_fixed_worker_dispatch_sanitizes_ssh_failure(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
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
    monkeypatch.setattr(FIXED_RECOVERY.os, "geteuid", lambda: 0)
    monkeypatch.setattr(FIXED_RECOVERY, "_validate_private_identity", lambda **_kwargs: None)
    monkeypatch.setattr(
        FIXED_RECOVERY,
        "_enrol",
        lambda _target_id, _expected: {
            "schema": "qdev-recovery-host-enrol-result-v1",
            "status": "already_completed",
            "profile": "platform",
            "controller_revision": SHA,
            "controller_release_digest": DIGEST,
            "agent_release_digest": "sha256:" + "c" * 64,
            "agent_certificate_sha256": "d" * 64,
            "rollback_agent_release_digest": "none",
            "receipt_digest": "sha256:" + "e" * 64,
        },
    )
    monkeypatch.setattr(
        FIXED_RECOVERY.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(envelope).encode())),
    )
    monkeypatch.setattr(
        FIXED_RECOVERY.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            returncode=255, stderr="private diagnostic must not escape"
        ),
    )
    assert FIXED_RECOVERY.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "access_blocked"
    assert result["result"]["error_code"] == "fixed_host_dispatch_failed"
    assert "private diagnostic" not in json.dumps(result)


def test_fixed_worker_dispatch_fails_closed_before_service_start_when_enrol_fails(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
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
    monkeypatch.setattr(FIXED_RECOVERY.os, "geteuid", lambda: 0)
    monkeypatch.setattr(FIXED_RECOVERY, "_validate_private_identity", lambda **_kwargs: None)
    monkeypatch.setattr(
        FIXED_RECOVERY.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _: json.dumps(envelope).encode())),
    )
    monkeypatch.setattr(
        FIXED_RECOVERY,
        "_enrol",
        lambda *_args: (_ for _ in ()).throw(FIXED_RECOVERY.DispatchError("host_enrol_failed")),
    )
    monkeypatch.setattr(
        FIXED_RECOVERY.subprocess,
        "run",
        lambda *_args, **_kwargs: pytest.fail("service must not start"),
    )

    assert FIXED_RECOVERY.main() == 0
    result = json.loads(capsys.readouterr().out)
    assert result["status"] == "access_blocked"
    assert result["result"] == {
        "dispatch_binding": "controller-fixed-ssh-v1",
        "error_code": "host_enrol_failed",
        "native_status": "not_started",
        "recovery_service_unit": "qdev-runner-recovery-platform.service",
    }


def test_ci_configuration_target_is_bound_to_the_registered_worker() -> None:
    request = _request("restore-existing-worker")
    request["worker_name"] = "srv1879763-primary"
    target_id = "qdev-ci.srv1879763-primary"
    target = FIXED_RECOVERY.TARGETS[target_id]
    envelope = {
        "schema": "qdev-fleet-worker-recovery-request-v1",
        "request": request,
        "target": {
            "worker_name": request["worker_name"],
            "target_id": target_id,
            "service_unit": target["service_unit"],
            "host_binding": "controller-registry",
            "labels": target["labels"],
        },
        "active_jobs": 0,
    }

    original_stdin = FIXED_RECOVERY.sys.stdin
    try:
        FIXED_RECOVERY.sys.stdin = SimpleNamespace(
            buffer=SimpleNamespace(read=lambda _: json.dumps(envelope).encode())
        )
        _, parsed = FIXED_RECOVERY._parse()
        assert parsed["host"] == "186.240.148.129"
        assert parsed["profile"] == "ci-worker-configuration"

        envelope["target"]["target_id"] = "other"
        FIXED_RECOVERY.sys.stdin = SimpleNamespace(
            buffer=SimpleNamespace(read=lambda _: json.dumps(envelope).encode())
        )
        with pytest.raises(FIXED_RECOVERY.DispatchError, match="target_not_allowlisted"):
            FIXED_RECOVERY._parse()
    finally:
        FIXED_RECOVERY.sys.stdin = original_stdin


def test_ci_configuration_recovery_removes_only_reconciled_files(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dropin = tmp_path / "~~~~position-followup-qv-ci.conf"
    position_env = tmp_path / "worker.position-followup-qv-ci.env"
    dropin.write_text("[Service]\n", encoding="utf-8")
    position_env.write_text("QDEV_WORKER_TOKEN=redacted\n", encoding="utf-8")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()

    monkeypatch.setattr(CI_CONFIGURATION_RECOVERY.os, "geteuid", lambda: 0)
    monkeypatch.setattr(CI_CONFIGURATION_RECOVERY, "_base_environment", lambda: None)
    monkeypatch.setattr(CI_CONFIGURATION_RECOVERY, "_safe_stale_files", lambda *_args: [dropin])
    monkeypatch.setattr(CI_CONFIGURATION_RECOVERY, "_position_envs", lambda: [position_env])
    monkeypatch.setattr(
        CI_CONFIGURATION_RECOVERY,
        "_snapshot",
        lambda _files: (snapshot, {"files": []}),
    )
    monkeypatch.setattr(CI_CONFIGURATION_RECOVERY, "_restart_and_verify", lambda: True)

    result = CI_CONFIGURATION_RECOVERY.repair(
        CI_CONFIGURATION_RECOVERY._sha256(Path(CI_CONFIGURATION_RECOVERY.__file__))
    )

    assert result["status"] == "completed"
    assert not dropin.exists()
    assert not position_env.exists()
    assert result["removed_dropins"] == 1
    assert result["removed_position_envs"] == 1


def test_ci_configuration_recovery_rolls_back_when_worker_does_not_restart(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    dropin = tmp_path / "~position-followup-qv-ci.conf"
    dropin.write_text("[Service]\n", encoding="utf-8")
    snapshot = tmp_path / "snapshot"
    snapshot.mkdir()
    restored: list[Path] = []

    monkeypatch.setattr(CI_CONFIGURATION_RECOVERY.os, "geteuid", lambda: 0)
    monkeypatch.setattr(CI_CONFIGURATION_RECOVERY, "_base_environment", lambda: None)
    monkeypatch.setattr(CI_CONFIGURATION_RECOVERY, "_safe_stale_files", lambda *_args: [dropin])
    monkeypatch.setattr(CI_CONFIGURATION_RECOVERY, "_position_envs", lambda: [])
    monkeypatch.setattr(
        CI_CONFIGURATION_RECOVERY,
        "_snapshot",
        lambda _files: (snapshot, {"files": []}),
    )
    monkeypatch.setattr(CI_CONFIGURATION_RECOVERY, "_restart_and_verify", lambda: False)
    monkeypatch.setattr(
        CI_CONFIGURATION_RECOVERY,
        "_restore",
        lambda path, _manifest: restored.append(path) or True,
    )

    result = CI_CONFIGURATION_RECOVERY.repair(
        CI_CONFIGURATION_RECOVERY._sha256(Path(CI_CONFIGURATION_RECOVERY.__file__))
    )

    assert result["status"] == "failed"
    assert result["rollback_status"] == "restored"
    assert restored == [snapshot]


def test_host_enrol_uses_agent_command_signer_not_operator_receipt_key() -> None:
    payload = HOST_ENROL._config(
        "qazstack",
        SHA,
        DIGEST,
        DIGEST,
        DIGEST,
        "v1",
        "a" * 64,
        {"QDEV_OPERATOR_RECEIPT_KEY": "operator-receipt-key"},
        {"QDEV_RECOVERY_AGENT_SIGNING_KEY": "agent-command-key"},
    ).decode()
    values = dict(line.split("=", 1) for line in payload.splitlines())
    assert values["QDEV_RECOVERY_COMMAND_VERIFICATION_KEY"] == "agent-command-key"
    assert values["QDEV_RECOVERY_RECONCILE_SIGNING_KEY"] == "agent-command-key"
    assert "operator-receipt-key" not in payload


def test_host_enrol_response_is_exact_and_private_values_are_not_returned() -> None:
    expected = {
        "profile": "platform",
        "controller_revision": SHA,
        "controller_release_digest": DIGEST,
        "agent_release_digest": "sha256:" + "c" * 64,
        "agent_certificate_sha256": "d" * 64,
    }
    public = {
        "schema": "qdev-recovery-host-enrol-result-v1",
        "status": "completed",
        **expected,
        "rollback_agent_release_digest": "none",
    }
    assert HOST_ENROL._validate_response(json.dumps(public).encode(), expected) == public

    with pytest.raises(HOST_ENROL.EnrolError, match="host_response_invalid"):
        HOST_ENROL._validate_response(
            json.dumps({**public, "private_key": "must-not-escape"}).encode(), expected
        )


def test_recovery_host_enrol_accepts_public_read_only_release_status(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    releases = tmp_path / "releases"
    release = releases / SHA
    release.mkdir(parents=True)
    current = tmp_path / "current"
    current.symlink_to(release, target_is_directory=True)
    status = tmp_path / "controller-release.json"
    status.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-release-status-v2",
                "state": "active",
                "revision": SHA,
                "release_digest": DIGEST,
            }
        ),
        encoding="utf-8",
    )
    status.chmod(0o644)
    monkeypatch.setattr(HOST_ENROL, "ACTIVE", current)
    monkeypatch.setattr(HOST_ENROL, "STATUS", status)
    original_lstat = Path.lstat

    def root_owned(path: Path) -> Any:
        metadata = original_lstat(path)
        return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", root_owned)

    assert HOST_ENROL._active_release() == (release, SHA, DIGEST)


def test_host_apply_manifest_binds_all_and_only_release_payloads() -> None:
    files = {name: f"payload:{name}".encode() for name in HOST_APPLY.PAYLOAD_FILES}
    manifest = {
        "schema": HOST_APPLY.BUNDLE_SCHEMA,
        "profile": "qazstack",
        "controller_revision": SHA,
        "controller_release_digest": DIGEST,
        "policy_digest": "sha256:" + "c" * 64,
        "agent_release_digest": "sha256:" + "d" * 64,
        "interface_version": "qdev-worker-recovery-v3",
        "interface_digest": "e" * 64,
        "expected_agent_certificate_sha256": "f" * 64,
        "files": {name: f"sha256:{HOST_APPLY._sha256(payload)}" for name, payload in files.items()},
    }
    HOST_APPLY._validate_manifest(manifest, files, "qazstack")

    tampered = dict(files)
    tampered["payload/platform.env"] += b"\nchanged"
    with pytest.raises(HOST_APPLY.ApplyError, match="bundle_digest_mismatch"):
        HOST_APPLY._validate_manifest(manifest, tampered, "qazstack")

    with pytest.raises(HOST_APPLY.ApplyError, match="bundle_manifest_invalid"):
        HOST_APPLY._validate_manifest({**manifest, "unexpected": True}, files, "qazstack")


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
        "qdev_fixed_worker_recovery_dispatch.py",
        "qdev_recovery_host_enrol_adapter.py",
        "qdev_recovery_host_apply.py",
    ):
        source = (ROOT / "scripts" / script_name).read_text(encoding="utf-8")
        assert "os.environ" not in source
        assert "shell=True" not in source
