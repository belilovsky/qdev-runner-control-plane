from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib.util
import io
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


def test_activation_failure_receipt_is_closed_vocabulary_and_non_secret() -> None:
    ACTIVATION._FAILURE_CONTEXT.clear()
    ACTIVATION._FAILURE_CONTEXT.update(
        {
            "stage": "entrypoint",
            "transaction_id": "controller-eb9eea64-34515000659-r1",
            "controller_revision": SHA,
            "activation_envelope_digest": ENVELOPE_DIGEST,
            "entrypoint_returncode": 7,
            "entrypoint_stderr_digest": "sha256:" + "e" * 64,
        }
    )
    receipt = ACTIVATION.activation_failure_receipt(ACTIVATION.AdapterError("activation_failed"))
    assert set(receipt) == {
        "schema",
        "failure_code",
        "diagnostic_digest",
        "transaction_id",
        "permitted_action",
    }
    assert receipt["schema"] == "qdev-controller-activation-failure-v1"
    assert receipt["failure_code"] == "activation_failed"
    assert receipt["transaction_id"] == "controller-eb9eea64-34515000659-r1"
    assert receipt["permitted_action"] == "reconcile-controller-activation"
    assert receipt["diagnostic_digest"].startswith("sha256:")
    # A free-text internal error still maps to a safe closed vocabulary.
    unsafe = ACTIVATION.activation_failure_receipt(RuntimeError("raw /etc/passwd path"))
    assert unsafe["failure_code"] == "activation_adapter_internal_error"
    assert unsafe["permitted_action"] == "operator-review"
    # Pre-mutation validation failures never authorise a reconcile.
    retry = ACTIVATION.activation_failure_receipt(
        ACTIVATION.AdapterError("activation_envelope_digest_mismatch")
    )
    assert retry["permitted_action"] == "retry-fleet-bootstrap"


def test_activation_failure_receipt_is_persisted_without_raw_entrypoint_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ACTIVATION._FAILURE_CONTEXT.clear()
    ACTIVATION._FAILURE_CONTEXT.update(
        {
            "stage": "entrypoint",
            "transaction_id": "controller-eb9eea64-34515000659-r1",
            "controller_revision": SHA,
            "activation_envelope_digest": ENVELOPE_DIGEST,
            "entrypoint_returncode": 7,
            "entrypoint_stderr_digest": "sha256:" + "e" * 64,
        }
    )
    monkeypatch.setattr(ACTIVATION, "_activation_diagnostics_directory", lambda: tmp_path)
    receipt = ACTIVATION.persist_activation_failure_receipt(
        ACTIVATION.AdapterError("activation_failed")
    )
    persisted = json.loads(
        (tmp_path / "controller-eb9eea64-34515000659-r1.json").read_text(encoding="utf-8")
    )
    assert persisted == receipt
    assert "stderr" not in json.dumps(persisted)
    assert (
        stat.S_IMODE((tmp_path / "controller-eb9eea64-34515000659-r1.json").stat().st_mode) == 0o600
    )


def test_activation_payload_failure_stage_is_closed_vocabulary() -> None:
    assert (
        ACTIVATION._payload_failure_code(
            "untrusted detail\nqdev_activation_failure_stage=runtime_health\n"
        )
        == "activation_runtime_health_failed"
    )
    assert (
        ACTIVATION._payload_failure_code("qdev_activation_failure_stage=broker_state\n")
        == "activation_broker_state_failed"
    )
    assert (
        ACTIVATION._payload_failure_code(
            "qdev_activation_failure_stage=payload_preflight\n"
            "qdev_activation_failure_stage=runtime_health\n"
        )
        == "activation_runtime_health_failed"
    )
    assert (
        ACTIVATION._payload_failure_code("qdev_activation_failure_stage=entrypoint_envelope\n")
        == "activation_entrypoint_envelope_failed"
    )
    assert (
        ACTIVATION._payload_failure_code("qdev_activation_failure_stage=preflight_hook\n")
        == "activation_preflight_hook_failed"
    )
    assert ACTIVATION._payload_failure_code("qdev_activation_failure_stage=unknown\n") is None
    assert (
        ACTIVATION._payload_failure_code("qdev_activation_failure_stage=external_guard\n")
        == "activation_external_guard_failed"
    )
    assert ACTIVATION._payload_failure_code("untrusted detail\n") is None


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
    manifest_path = artifacts / manifest_digest / "controller-artifact-manifest.json"
    manifest_path.parent.mkdir()
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
    assert "qdev-host-agent:rp-private-runtime" in mapping
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


# --- controller activation reconciliation (signed root dispatch) -------------

RECONCILE_ACTION = "reconcile-controller-activation"
RECONCILE_TRANSACTION_ID = "controller-eb9eea64-34515000659-r1"
R2_TRANSACTION_ID = "controller-eb9eea64-34537511259-r2"
CONFIG_FILE_NAMES = (
    "repos.json",
    "profiles.yml",
    "admin-platform-package-bindings.json",
    "release-lanes.yml",
    "managed-registry.yml",
    "fleet-bootstrap.yml",
    "managed-release-ledger.yml",
)
EXECUTOR_RESULT_FIELDS = frozenset(
    {
        "schema",
        "status",
        "action",
        "controller_revision",
        "controller_release_digest",
        "controller_image_digest",
        "controller_internal_image_digest",
        "activation_envelope_digest",
        "release_lane",
        "host_agent_mtls_identity",
        "rollback_source_sha",
        "rollback_artifact_digest",
        "rollback_internal_artifact_digest",
        "rollback_policy_digest",
        "rollback_generation",
        "result",
    }
)
RECONCILIATION_RESULT_FIELDS = frozenset(
    {
        "schema",
        "outcome",
        "transaction_id",
        "envelope_digest",
        "expected_generation",
        "recovery_state",
        "reserved_status_digest",
        "committed_status_digest",
        "observed_status_digest",
        "activated_at",
        "transaction_closed",
        "previous_generation",
        "previous_source_sha",
        "previous_public_image_digest",
        "previous_internal_image_digest",
        "previous_policy_bundle_digest",
        "current_generation",
        "current_source_sha",
        "current_public_image_digest",
        "current_internal_image_digest",
        "current_policy_bundle_digest",
        "projection_digest",
    }
)


def _signed_reconcile_envelope(
    private_key: Any,
    *,
    transaction_id: str,
    expected_generation: int,
    expected_current: dict[str, str],
    candidate: dict[str, str],
    expected_current_status_digest: str,
    expected_current_config_digest: str,
    candidate_release_digest: str,
    candidate_config_digest: str,
    artifact_manifest_digest: str,
    entrypoint_reconciliation_digest: str,
) -> dict[str, Any]:
    unsigned = {
        "schema": "qdev-controller-activation-envelope-v1",
        "transaction_id": transaction_id,
        "issued_at": "2026-09-10T18:41:41Z",
        "expires_at": "2026-09-10T18:51:56Z",
        "expected_generation": expected_generation,
        "expected_current": expected_current,
        "expected_current_status_digest": expected_current_status_digest,
        "expected_current_config_digest": expected_current_config_digest,
        "candidate": candidate,
        "candidate_release_digest": candidate_release_digest,
        "candidate_config_digest": candidate_config_digest,
        "artifact_manifest_digest": artifact_manifest_digest,
        "entrypoint_reconciliation_digest": entrypoint_reconciliation_digest,
    }
    signature = (
        base64.urlsafe_b64encode(private_key.sign(ACTIVATION._canonical(unsigned)))
        .rstrip(b"=")
        .decode("ascii")
    )
    assert len(signature) == 86
    return {**unsigned, "signature": signature}


def _reconcile_world(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    include_rollback_anchor: bool = True,
    envelope_expected_generation: int = 7,
    envelope_transaction_id: str = RECONCILE_TRANSACTION_ID,
) -> SimpleNamespace:
    """Stage one exact expired-but-committed controller activation transaction."""

    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    original_lstat = Path.lstat

    def root_owned(path: Path) -> Any:
        metadata = original_lstat(path)
        return SimpleNamespace(st_mode=metadata.st_mode, st_uid=0)

    monkeypatch.setattr(Path, "lstat", root_owned)
    monkeypatch.setattr(ACTIVATION, "_validate_root_directory", lambda path: path.resolve())

    candidate_revision = SHA
    candidate_public = "1" * 64
    candidate_internal = "2" * 64
    candidate_policy = "3" * 64
    candidate_release_digest = "sha256:" + "4" * 64
    previous_revision = "b" * 40
    previous_public = "5" * 64
    previous_internal = "6" * 64
    previous_policy = "7" * 64
    manifest_digest = "8" * 64
    entrypoint_digest = "9" * 64
    expected_current_status_digest = "e" * 64
    expected_current_config_digest = "f" * 64

    config_paths: dict[str, Path] = {}
    for name in CONFIG_FILE_NAMES:
        path = tmp_path / "config" / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"{name}\n", encoding="utf-8")
        path.chmod(0o644)
        config_paths[name] = path
    monkeypatch.setattr(ACTIVATION, "CONTROLLER_CONFIG_FILES", config_paths)
    candidate_config_digest = ACTIVATION._fingerprint_config_files(config_paths)

    status_path = tmp_path / "controller-release.json"
    status_path.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-release-status-v2",
                "state": "active",
                "revision": candidate_revision,
                "release_digest": candidate_release_digest,
                "activated_at": "2026-09-10T18:41:00Z",
                "runtime_identity": {
                    "source_revision": candidate_revision,
                    "source_digest": "sha256:" + "a" * 64,
                    "public_image_id": "sha256:" + candidate_public,
                    "internal_image_id": "sha256:" + candidate_internal,
                },
                "dependency_identity": {
                    "requirements_digest": "sha256:" + "c" * 64,
                    "public_installed_digest": "sha256:" + "d" * 64,
                    "internal_installed_digest": "sha256:" + "d" * 64,
                },
            }
        ),
        encoding="utf-8",
    )
    status_path.chmod(0o600)
    monkeypatch.setattr(ACTIVATION, "STATUS_PATH", status_path)

    ledger_path = tmp_path / "activation-status.json"
    ledger_bytes = json.dumps(
        {
            "schema": "qdev-controller-activation-status-v2",
            "state": "active",
            "generation": 8,
            "source_sha": candidate_revision,
            "public_image_digest": candidate_public,
            "internal_image_digest": candidate_internal,
            "policy_bundle_digest": candidate_policy,
            "previous": {
                "generation": 7,
                "source_sha": previous_revision,
                "public_image_digest": previous_public,
                "internal_image_digest": previous_internal,
                "policy_bundle_digest": previous_policy,
            },
            "transaction_id": RECONCILE_TRANSACTION_ID,
            "activated_at": "2026-09-10T18:43:22.913319Z",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    ledger_path.write_bytes(ledger_bytes)
    ledger_path.chmod(0o600)
    ledger_digest = hashlib.sha256(ledger_bytes).hexdigest()
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_STATUS_PATH", ledger_path)

    assets = tmp_path / "activation"
    (assets / "envelopes").mkdir(parents=True)
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_ASSETS_ROOT", assets)

    private_key = Ed25519PrivateKey.generate()
    candidate = {
        "source_sha": candidate_revision,
        "public_image_digest": candidate_public,
        "internal_image_digest": candidate_internal,
        "policy_bundle_digest": candidate_policy,
    }
    expected_current = {
        "source_sha": previous_revision,
        "public_image_digest": previous_public,
        "internal_image_digest": previous_internal,
        "policy_bundle_digest": previous_policy,
    }
    envelope_document = _signed_reconcile_envelope(
        private_key,
        transaction_id=envelope_transaction_id,
        expected_generation=envelope_expected_generation,
        expected_current=expected_current,
        candidate=candidate,
        expected_current_status_digest=expected_current_status_digest,
        expected_current_config_digest=expected_current_config_digest,
        candidate_release_digest=candidate_release_digest[7:],
        candidate_config_digest=candidate_config_digest,
        artifact_manifest_digest=manifest_digest,
        entrypoint_reconciliation_digest=entrypoint_digest,
    )
    envelope_digest = (
        "sha256:" + hashlib.sha256(ACTIVATION._canonical(envelope_document)).hexdigest()
    )
    envelope_path = assets / "envelopes" / f"{envelope_digest[7:]}.json"
    envelope_path.write_text(
        json.dumps(envelope_document, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )
    envelope_path.chmod(0o600)

    manifest_path = assets / "artifacts" / manifest_digest / "controller-artifact-manifest.json"
    manifest_path.parent.mkdir(parents=True)
    manifest_path.write_text("{}", encoding="utf-8")
    manifest_path.chmod(0o600)

    public_key_path = tmp_path / "controller-activation-ed25519.pub"
    public_key_path.write_bytes(
        private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    public_key_path.chmod(0o644)
    admission_key_path = tmp_path / "ed25519-public.pem"
    admission_key_path.write_bytes(public_key_path.read_bytes())
    admission_key_path.chmod(0o644)
    binding_path = tmp_path / "controller-activation-trust-binding.json"
    binding_path.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-activation-trust-binding-v1",
                "binding": "controller-registry",
                "authority": "controller-admission",
                "source_path": str(admission_key_path),
                "source_sha256": "sha256:"
                + hashlib.sha256(admission_key_path.read_bytes()).hexdigest(),
                "activation_public_key_path": str(public_key_path),
                "activation_public_key_sha256": "sha256:"
                + hashlib.sha256(public_key_path.read_bytes()).hexdigest(),
            }
        ),
        encoding="utf-8",
    )
    binding_path.chmod(0o644)
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_PUBLIC_KEY", public_key_path)
    monkeypatch.setattr(ACTIVATION, "ADMISSION_PUBLIC_KEY", admission_key_path)
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_TRUST_BINDING", binding_path)

    transaction_path = ledger_path.with_suffix(".json.transaction")
    transaction_bytes = json.dumps(
        {
            "schema": "qdev-controller-activation-transaction-v1",
            "transaction_id": envelope_transaction_id,
            "envelope_digest": envelope_digest[7:],
            "expected_generation": envelope_expected_generation,
            "expected_current": expected_current,
            "expected_current_status_digest": expected_current_status_digest,
            "expected_current_config_digest": expected_current_config_digest,
            "candidate": candidate,
            "candidate_release_digest": candidate_release_digest[7:],
            "candidate_config_digest": candidate_config_digest,
            "artifact_manifest_digest": manifest_digest,
            "entrypoint_reconciliation_digest": entrypoint_digest,
            "reserved_status_digest": "0" * 64,
            "committed_status_digest": ledger_digest,
            "committed_activated_at": "2026-09-10T18:43:22.913319Z",
            "expires_at": "2026-09-10T18:51:56Z",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    transaction_path.write_bytes(transaction_bytes)
    transaction_path.chmod(0o600)

    releases = tmp_path / "releases"
    release = releases / candidate_revision
    activation_script = release / "scripts" / "activate_controller_release.sh"
    identity = release / "src" / "qdev_runner" / "controller_release.py"
    activation_script.parent.mkdir(parents=True)
    identity.parent.mkdir(parents=True)
    activation_script.write_text("#!/bin/sh\n", encoding="utf-8")
    identity.write_text("", encoding="utf-8")
    for path in (releases, release, activation_script.parent, release / "src", identity.parent):
        path.chmod(0o755)
    activation_script.chmod(0o755)
    identity.chmod(0o644)
    current = tmp_path / "current"
    current.symlink_to(release, target_is_directory=True)
    monkeypatch.setattr(ACTIVATION, "RELEASES_ROOT", releases)
    monkeypatch.setattr(ACTIVATION, "CURRENT_RELEASE", current)
    monkeypatch.setattr(
        ACTIVATION.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(returncode=0, stdout=candidate_release_digest),
    )

    projection_path = tmp_path / "controller-activation.json"
    monkeypatch.setattr(ACTIVATION, "ACTIVATION_PROJECTION_PATH", projection_path)

    request = {
        "schema": "qdev-fleet-bootstrap-request-v2",
        "action": RECONCILE_ACTION,
        "source_sha": candidate_revision,
        "run_id": 101,
        "job_id": 202,
        "attempt": 1,
        "claim_ttl_seconds": 300,
        "controller_revision": candidate_revision,
        "controller_release_digest": candidate_release_digest,
        "controller_image_digest": "sha256:" + candidate_public,
        "controller_internal_image_digest": "sha256:" + candidate_internal,
        "activation_envelope_digest": envelope_digest,
        "release_lane": None,
        "worker_name": None,
    }
    target = {
        "controller_revision": candidate_revision,
        "controller_release_digest": candidate_release_digest,
        "controller_image_digest": "sha256:" + candidate_public,
        "controller_internal_image_digest": "sha256:" + candidate_internal,
        "activation_envelope_digest": envelope_digest,
        "activation_mode": "signed-external-envelope",
        "activation_envelope_schema": "qdev-controller-activation-envelope-v1",
        "activation_public_key_binding": "controller-registry",
        "activation_max_envelope_ttl_seconds": 1800,
    }
    if include_rollback_anchor:
        target["rollback_revision"] = candidate_revision
        target["rollback_release_digest"] = candidate_release_digest
    return SimpleNamespace(
        request=request,
        target=target,
        payload={
            "schema": "qdev-fleet-bootstrap-adapter-request-v2",
            "request": request,
            "target": target,
        },
        envelope_path=envelope_path,
        envelope_digest=envelope_digest,
        status_path=status_path,
        ledger_path=ledger_path,
        ledger_bytes=ledger_bytes,
        transaction_path=transaction_path,
        transaction_bytes=transaction_bytes,
        projection_path=projection_path,
        candidate_config_digest=candidate_config_digest,
        candidate_release_digest=candidate_release_digest,
        previous_revision=previous_revision,
    )


def _invoke_activation_main(
    monkeypatch: pytest.MonkeyPatch, payload: dict[str, Any]
) -> dict[str, Any]:
    monkeypatch.setattr(ACTIVATION.os, "geteuid", lambda: 0)
    encoded = json.dumps(payload).encode("utf-8")
    monkeypatch.setattr(
        ACTIVATION.sys,
        "stdin",
        SimpleNamespace(buffer=SimpleNamespace(read=lambda _size=0: encoded)),
    )
    buffer = io.StringIO()
    with contextlib.redirect_stdout(buffer):
        assert ACTIVATION.main() == 0
    return json.loads(buffer.getvalue())


def _assert_reconcile_fails_closed(
    monkeypatch: pytest.MonkeyPatch,
    world: SimpleNamespace,
    *,
    expected_error: str,
) -> None:
    transaction_before = world.transaction_path.read_bytes()
    ledger_before = world.ledger_path.read_bytes()
    with pytest.raises(ACTIVATION.AdapterError, match=expected_error):
        _invoke_activation_main(monkeypatch, world.payload)
    assert world.transaction_path.exists()
    assert world.transaction_path.read_bytes() == transaction_before
    assert world.ledger_path.read_bytes() == ledger_before
    assert not world.projection_path.exists()


def _write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_text(json.dumps(value, sort_keys=True, separators=(",", ":")), encoding="utf-8")


def test_reconcile_controller_activation_finalizes_expired_commit_and_replays(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _reconcile_world(tmp_path, monkeypatch)
    anchor = tmp_path / "controller-rollback-anchor.json"
    anchor.write_text("stale foreign anchor\n", encoding="utf-8")
    monkeypatch.setattr(ACTIVATION, "ROLLBACK_ANCHOR_PATH", anchor)

    response = _invoke_activation_main(monkeypatch, world.payload)

    assert set(response) == EXECUTOR_RESULT_FIELDS
    assert response["schema"] == "qdev-fleet-bootstrap-adapter-result-v2"
    assert response["action"] == RECONCILE_ACTION
    assert response["status"] == "completed"
    assert response["release_lane"] is None
    assert response["host_agent_mtls_identity"] is None
    assert response["rollback_source_sha"] == world.previous_revision
    assert response["rollback_generation"] == 7
    assert response["rollback_artifact_digest"].startswith("sha256:")
    assert set(response["result"]) == RECONCILIATION_RESULT_FIELDS
    for key in response["result"]:
        assert not any(
            marker in key.lower()
            for marker in ("token", "secret", "private", "password", "credential", "pin", "claim")
        )
    result = response["result"]
    assert result["outcome"] == "finalized"
    assert result["transaction_closed"] is True
    assert result["transaction_id"] == RECONCILE_TRANSACTION_ID
    assert result["expected_generation"] == 7
    assert result["recovery_state"] == "committed"
    assert result["current_generation"] == 8
    assert result["current_source_sha"] == SHA
    assert result["previous_generation"] == 7
    assert result["observed_status_digest"] == result["committed_status_digest"]
    # Reconciliation closes the durable transaction without rewriting the ledger
    # and never reads or writes the stale live rollback anchor.
    assert not world.transaction_path.exists()
    assert world.ledger_path.read_bytes() == world.ledger_bytes
    assert anchor.read_text(encoding="utf-8") == "stale foreign anchor\n"

    projection = json.loads(world.projection_path.read_text(encoding="utf-8"))
    assert projection["schema"] == "qdev-controller-activation-projection-v1"
    assert projection["state"] == "active"
    assert projection["generation"] == 8
    assert projection["source_revision"] == SHA
    assert result["projection_digest"] == projection["projection_digest"]

    replay = _invoke_activation_main(monkeypatch, world.payload)
    assert replay["status"] == "already_completed"
    assert replay["result"]["outcome"] == "already-finalized"
    assert replay["result"]["transaction_closed"] is False
    assert replay["result"]["reserved_status_digest"] is None
    assert replay["result"]["current_generation"] == 8
    assert replay["result"]["observed_status_digest"] == replay["result"]["committed_status_digest"]
    assert not world.transaction_path.exists()
    assert world.ledger_path.read_bytes() == world.ledger_bytes


def test_reconcile_rejects_foreign_transaction_and_anchor_chain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _reconcile_world(tmp_path, monkeypatch)

    tampered = json.loads(world.transaction_bytes)
    tampered["transaction_id"] = "controller-foreign-00000000000-r9"
    _write_json(world.transaction_path, tampered)
    _assert_reconcile_fails_closed(
        monkeypatch, world, expected_error="activation_transaction_ownership_failed"
    )

    world.transaction_path.write_bytes(world.transaction_bytes)
    tampered = json.loads(world.transaction_bytes)
    tampered["envelope_digest"] = "f" * 64
    _write_json(world.transaction_path, tampered)
    _assert_reconcile_fails_closed(
        monkeypatch, world, expected_error="activation_transaction_ownership_failed"
    )

    world.transaction_path.write_bytes(world.transaction_bytes)
    tampered = json.loads(world.transaction_bytes)
    tampered["committed_status_digest"] = "0" * 64
    _write_json(world.transaction_path, tampered)
    _assert_reconcile_fails_closed(
        monkeypatch, world, expected_error="reconciliation_status_fingerprint_mismatch"
    )

    world.transaction_path.write_bytes(world.transaction_bytes)
    ledger = json.loads(world.ledger_bytes)
    ledger["source_sha"] = "0" * 40
    _write_json(world.ledger_path, ledger)
    _assert_reconcile_fails_closed(
        monkeypatch, world, expected_error="reconciliation_committed_shape_invalid"
    )
    world.ledger_path.write_bytes(world.ledger_bytes)

    ledger = json.loads(world.ledger_bytes)
    ledger["generation"] = 9
    _write_json(world.ledger_path, ledger)
    _assert_reconcile_fails_closed(
        monkeypatch, world, expected_error="reconciliation_committed_shape_invalid"
    )


def test_reconcile_rejects_r2_historical_envelope_without_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    world = _reconcile_world(
        tmp_path,
        monkeypatch,
        envelope_expected_generation=11,
        envelope_transaction_id=R2_TRANSACTION_ID,
    )

    _assert_reconcile_fails_closed(
        monkeypatch, world, expected_error="reconciliation_committed_shape_invalid"
    )


def test_reconcile_rejects_wrong_runtime_identity(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A runtime whose measured revision is not the trusted current release link
    # can never be reconciled, even with a matching anchor-free request.
    identity_root = tmp_path / "identity"
    world = _reconcile_world(identity_root, monkeypatch, include_rollback_anchor=False)
    status = json.loads(world.status_path.read_text(encoding="utf-8"))
    status["revision"] = "0" * 40
    status["runtime_identity"]["source_revision"] = "0" * 40
    _write_json(world.status_path, status)
    _assert_reconcile_fails_closed(
        monkeypatch, world, expected_error="current_release_identity_invalid"
    )

    monkeypatch.undo()
    image_root = tmp_path / "image"
    world = _reconcile_world(image_root, monkeypatch)
    status = json.loads(world.status_path.read_text(encoding="utf-8"))
    status["runtime_identity"]["public_image_id"] = "sha256:" + "0" * 64
    _write_json(world.status_path, status)
    _assert_reconcile_fails_closed(
        monkeypatch, world, expected_error="reconciliation_runtime_mismatch"
    )

    monkeypatch.undo()
    config_root = tmp_path / "config-drift"
    world = _reconcile_world(config_root, monkeypatch)
    (config_root / "config" / "release-lanes.yml").write_text("drifted\n", encoding="utf-8")
    _assert_reconcile_fails_closed(
        monkeypatch, world, expected_error="reconciliation_runtime_mismatch"
    )


def test_reconcile_target_shape_and_activate_anchor_contract() -> None:
    anchor_free_target = {
        "controller_revision": SHA,
        "controller_release_digest": DIGEST,
        "controller_image_digest": IMAGE_DIGEST,
        "controller_internal_image_digest": IMAGE_DIGEST,
        "activation_envelope_digest": ENVELOPE_DIGEST,
        "activation_mode": "signed-external-envelope",
        "activation_envelope_schema": "qdev-controller-activation-envelope-v1",
        "activation_public_key_binding": "controller-registry",
        "activation_max_envelope_ttl_seconds": 1800,
    }
    reconcile = {
        "schema": "qdev-fleet-bootstrap-adapter-request-v2",
        "request": _bootstrap_request(RECONCILE_ACTION),
        "target": anchor_free_target,
    }
    request, target = ACTIVATION._validate_request(reconcile)
    assert request["action"] == RECONCILE_ACTION
    assert frozenset(target) == frozenset(anchor_free_target)

    with pytest.raises(ACTIVATION.AdapterError, match="rollback_revision_invalid"):
        ACTIVATION._validate_request(
            {
                **reconcile,
                "target": {
                    **anchor_free_target,
                    "rollback_revision": "bad",
                    "rollback_release_digest": DIGEST,
                },
            }
        )

    # Activation still requires the compare-and-swap rollback anchor; the
    # reconciliation target shape is never accepted for an activation payload.
    with pytest.raises(ACTIVATION.AdapterError, match="target_shape_invalid"):
        ACTIVATION._validate_request(
            {**reconcile, "request": _bootstrap_request("activate-controller")}
        )


def test_reconcile_never_references_the_live_rollback_anchor() -> None:
    source = (ROOT / "scripts" / "qdev_controller_activation_adapter.py").read_text(
        encoding="utf-8"
    )
    # The stale-anchor republication design was dropped: the path is declared
    # once and never read or written by reconciliation.
    assert source.count("ROLLBACK_ANCHOR_PATH") == 1
