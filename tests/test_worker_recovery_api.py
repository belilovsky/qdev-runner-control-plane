from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from fastapi.testclient import TestClient

from qdev_runner.broker import create_app
from qdev_runner.github import GitHubAppClient
from qdev_runner.models import (
    GitHubRegistrationToken,
    GitHubRunnerObservation,
    RecoveryReconcileRequest,
    RecoveryTargetId,
)
from qdev_runner.policy import Policy
from qdev_runner.settings import BrokerSettings
from qdev_runner.store import Store
from qdev_runner.worker_recovery import (
    INTERFACE_DIGEST,
    INTERFACE_VERSION,
    POLICY_DIGEST,
    RECOVERY_TARGETS,
    WorkerRecoveryController,
    WorkerRecoveryError,
    canonical_json,
)

OPERATOR_TOKEN = "operator-token"  # noqa: S105 - deterministic test credential
PROXY_SECRET = "edge-overwritten-proxy-secret"  # noqa: S105 - deterministic test credential
RECEIPT_KEY = "r" * 64
DIRECTIVE_KEY = "d" * 64
AGENT_SIGNING_KEY = "s" * 64
OPERATOR_CERTIFICATE = "a" * 64
OTHER_OPERATOR_CERTIFICATE = "f" * 64
PLATFORM_AGENT_CERTIFICATE = "b" * 64
QAZSTACK_AGENT_CERTIFICATE = "c" * 64
CONTROLLER_REVISION = "1" * 40
CONTROLLER_RELEASE_DIGEST = "2" * 64
ACTIVE_CONTROLLER_RELEASE_DIGEST = "sha256:" + CONTROLLER_RELEASE_DIGEST
AGENT_RELEASE_DIGEST = "sha256:" + "3" * 64
REGISTRATION_TOKEN = "github-registration-token-must-stay-agent-only"  # noqa: S105

OPERATOR_HEADERS = {
    "X-QDev-Operator-Token": OPERATOR_TOKEN,
    "X-QDev-Operator-Proxy-Auth": PROXY_SECRET,
    "X-QDev-Verified-Client-Certificate-SHA256": OPERATOR_CERTIFICATE,
}


class FakeRecoveryGitHub:
    def __init__(self, target_id: RecoveryTargetId) -> None:
        self.target = RECOVERY_TARGETS[target_id]
        self.runner_id = 187 if target_id == "qdev-platform-ci-187" else 901
        self.status = "offline"
        self.busy = False
        self.active_job_ids: tuple[int, ...] = ()
        self.observation_calls = 0
        self.registration_token_calls = 0
        self.dispatch_calls = 0
        self.dispatch_status_code = 204

    def repository_installation_id(self, repository: str) -> int:
        assert repository == self.target.repository
        return 71

    def repository_runners(self, installation_id: int, repository: str) -> list[dict[str, Any]]:
        assert installation_id == 71
        assert repository == self.target.repository
        return [
            {
                "id": self.runner_id,
                "name": self.target.worker_name,
                "status": self.status,
                "busy": self.busy,
                "labels": [{"name": label} for label in self.target.labels],
            }
        ]

    def observe_repository_runner(self, repository: str, runner_id: int) -> GitHubRunnerObservation:
        assert repository == self.target.repository
        assert runner_id == self.runner_id
        self.observation_calls += 1
        return GitHubRunnerObservation(
            repository=repository,
            runner_id=runner_id,
            name=self.target.worker_name,
            status=self.status,
            busy=self.busy,
            labels=self.target.labels,
            active_job_ids=self.active_job_ids,
            observed_at=time.time(),
        )

    def runner_registration_token(self, repository: str) -> GitHubRegistrationToken:
        assert repository == self.target.repository
        self.registration_token_calls += 1
        return GitHubRegistrationToken(
            token=REGISTRATION_TOKEN,
            expires_at=datetime.now(UTC) + timedelta(minutes=5),
        )

    def workflow_runs_complete(
        self,
        installation_id: int,
        repository: str,
        *,
        workflow: str,
        branch: str,
        event: str,
    ) -> list[dict[str, Any]]:
        assert installation_id == 71
        assert repository == self.target.repository
        assert workflow == self.target.workflow
        assert branch == self.target.ref
        assert event == "workflow_dispatch"
        return []

    def ref_sha(self, installation_id: int, repository: str, ref: str) -> str:
        assert installation_id == 71
        assert repository == self.target.repository
        assert ref == self.target.ref
        return "5" * 40

    def dispatch_workflow(
        self,
        installation_id: int,
        repository: str,
        workflow: str,
        ref: str,
        inputs: dict[str, str],
    ) -> dict[str, Any]:
        assert installation_id == 71
        assert repository == self.target.repository
        assert workflow == self.target.workflow
        assert ref == self.target.ref
        assert inputs["operation_id"]
        assert inputs["dispatch_correlation"] == f"qdev-recovery-{inputs['operation_id']}"
        assert inputs["runner_label"] == f"qdev-job-recovery-{inputs['operation_id']}"
        self.dispatch_calls += 1
        return {"status_code": self.dispatch_status_code}


@dataclass(frozen=True)
class RecoveryHarness:
    client: TestClient
    github: FakeRecoveryGitHub
    settings: BrokerSettings


def _settings(
    tmp_path: Path,
    policy_files: tuple[Path, Path],
    *,
    policy_digest: str = POLICY_DIGEST,
) -> BrokerSettings:
    inventory, profiles = policy_files
    release_status = tmp_path / "controller-release.json"
    release_status.write_text(
        json.dumps(
            {
                "schema": "qdev-controller-release-status-v1",
                "state": "active",
                "revision": CONTROLLER_REVISION,
                "release_digest": ACTIVE_CONTROLLER_RELEASE_DIGEST,
                "activated_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
            }
        ),
        encoding="utf-8",
    )
    return BrokerSettings(
        app_id="1",
        app_private_key_path=tmp_path / "github-app.pem",
        webhook_secret="webhook-secret",
        worker_token="worker-token",
        inventory_path=inventory,
        profiles_path=profiles,
        database_path=tmp_path / "broker.db",
        artifact_root=tmp_path / "artifacts",
        claim_scopes_path=tmp_path / "claim-scopes.json",
        operator_token=OPERATOR_TOKEN,
        operator_receipt_key=RECEIPT_KEY,
        operator_directive_key=DIRECTIVE_KEY,
        operations_root=tmp_path / "operations",
        controller_release_status_path=release_status,
        operator_proxy_secret=PROXY_SECRET,
        recovery_operator_certificate_sha256s=(
            OPERATOR_CERTIFICATE,
            OTHER_OPERATOR_CERTIFICATE,
        ),
        recovery_platform_agent_certificate_sha256=PLATFORM_AGENT_CERTIFICATE,
        recovery_qazstack_agent_certificate_sha256=QAZSTACK_AGENT_CERTIFICATE,
        recovery_policy_digest=policy_digest,
        recovery_agent_release_digest=AGENT_RELEASE_DIGEST,
        recovery_agent_signing_key=AGENT_SIGNING_KEY,
    )


def _harness(
    tmp_path: Path,
    policy_files: tuple[Path, Path],
    *,
    target_id: RecoveryTargetId = "qdev-platform-ci-187",
    policy_digest: str = POLICY_DIGEST,
) -> RecoveryHarness:
    settings = _settings(tmp_path, policy_files, policy_digest=policy_digest)
    github = FakeRecoveryGitHub(target_id)
    app = create_app(
        settings,
        store=Store(settings.database_path),
        policy=Policy(settings.inventory_path, settings.profiles_path),
        github=cast(GitHubAppClient, github),
    )
    return RecoveryHarness(client=TestClient(app), github=github, settings=settings)


def _provenance(*, nonce: str = "nonce-0001") -> dict[str, Any]:
    issued_at = datetime.now(UTC) - timedelta(seconds=1)
    return {
        "schema": "qdev-runner-recovery-provenance-v1",
        "nonce": nonce,
        "issued_at": issued_at.isoformat().replace("+00:00", "Z"),
        "expires_at": (issued_at + timedelta(seconds=60)).isoformat().replace("+00:00", "Z"),
        "controller_revision": CONTROLLER_REVISION,
        "controller_release_digest": CONTROLLER_RELEASE_DIGEST,
        "policy_digest": POLICY_DIGEST,
        "agent_release_digest": AGENT_RELEASE_DIGEST,
    }


def _prepare_body(
    target_id: RecoveryTargetId = "qdev-platform-ci-187",
    *,
    idempotency_key: str = "recovery-request-0001",
) -> dict[str, Any]:
    return {
        "schema": "qdev-runner-recovery-prepare-v1",
        "target_id": target_id,
        "idempotency_key": idempotency_key,
        "reason": "Recover the fixed runner after confirmed provider outage.",
        "provenance": _provenance(),
    }


def _agent_headers(target_id: RecoveryTargetId) -> dict[str, str]:
    certificate = (
        PLATFORM_AGENT_CERTIFICATE
        if target_id == "qdev-platform-ci-187"
        else QAZSTACK_AGENT_CERTIFICATE
    )
    return {
        "X-QDev-Operator-Proxy-Auth": PROXY_SECRET,
        "X-QDev-Verified-Client-Certificate-SHA256": certificate,
    }


def _status_body(operation: dict[str, Any], *, nonce: str = "nonce-0002") -> dict[str, Any]:
    return {
        "schema": "qdev-runner-recovery-status-v1",
        "operation_id": operation["operation_id"],
        "request_fingerprint": operation["request_fingerprint"],
        "provenance": _provenance(nonce=nonce),
    }


def _claim(
    harness: RecoveryHarness,
    operation: dict[str, Any],
    target_id: RecoveryTargetId,
) -> dict[str, Any]:
    response = harness.client.post(
        "/internal/v1/worker-recovery/claim",
        json={
            "schema": "qdev-runner-recovery-agent-claim-v1",
            "operation_id": operation["operation_id"],
        },
        headers=_agent_headers(target_id),
    )
    assert response.status_code == 200
    return cast(dict[str, Any], response.json())


def _reconcile_body(envelope: dict[str, Any]) -> dict[str, Any]:
    command = envelope["command"]
    return {
        "schema": "qdev-runner-recovery-reconcile-v1",
        "operation_id": command["operation_id"],
        "request_fingerprint": command["request_fingerprint"],
        "target_id": command["target_id"],
        "recovery_action": command["recovery_action"],
        "request_nonce": command["request_nonce"],
        "provider_reconciliation_digest": command["provider_reconciliation_digest"],
        "outcome": "completed",
        "outcome_digest": "sha256:" + "4" * 64,
        "agent_release_digest": command["agent_release_digest"],
        "observed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    }


def _reconcile_headers(body: dict[str, Any], target_id: RecoveryTargetId) -> dict[str, str]:
    request = RecoveryReconcileRequest.model_validate(body)
    signature = hmac.new(
        AGENT_SIGNING_KEY.encode("utf-8"),
        canonical_json(request.model_dump(mode="json", by_alias=True)),
        hashlib.sha256,
    ).hexdigest()
    return _agent_headers(target_id) | {"X-QDev-Recovery-Agent-Signature": f"sha256={signature}"}


def test_prepare_is_provider_observed_and_exactly_idempotent(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    harness = _harness(tmp_path, policy_files)
    body = _prepare_body()
    first = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=body,
        headers=OPERATOR_HEADERS,
    )
    assert first.status_code == 200
    operation = first.json()
    assert operation == {
        "schema": "qdev-runner-recovery-operation-v1",
        "operation_id": operation["operation_id"],
        "request_fingerprint": operation["request_fingerprint"],
        "target_id": "qdev-platform-ci-187",
        "worker_name": "qdev-platform-ci-187",
        "repository": "belilovsky/platform-portal",
        "provider_runner_id": 187,
        "state": "prepared",
        "native_outcome": None,
        "controller_revision": CONTROLLER_REVISION,
        "controller_release_digest": CONTROLLER_RELEASE_DIGEST,
        "policy_digest": POLICY_DIGEST,
        "agent_release_digest": AGENT_RELEASE_DIGEST,
        "idempotent_replay": False,
    }
    assert len(operation["operation_id"]) == 64
    assert len(operation["request_fingerprint"]) == 64
    assert harness.github.observation_calls == 1

    replay = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=body,
        headers=OPERATOR_HEADERS,
    )
    assert replay.status_code == 200
    assert replay.json() == operation | {"idempotent_replay": True}
    assert harness.github.observation_calls == 1


def test_bindings_are_live_source_bound_and_non_secret(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    harness = _harness(tmp_path, policy_files)
    response = harness.client.post(
        "/internal/v1/operations/worker-recovery/bindings",
        headers=OPERATOR_HEADERS,
    )

    assert response.status_code == 200
    body = response.json()
    assert body["controller_revision"] == CONTROLLER_REVISION
    assert body["controller_release_digest"] == CONTROLLER_RELEASE_DIGEST
    assert body["policy_digest"] == POLICY_DIGEST
    assert body["agent_release_digest"] == AGENT_RELEASE_DIGEST
    assert body["interface_version"] == INTERFACE_VERSION
    assert body["interface_digest"] == INTERFACE_DIGEST
    assert body["proof_max_age_seconds"] == 120
    assert set(body) == {
        "schema",
        "controller_revision",
        "controller_release_digest",
        "policy_digest",
        "agent_release_digest",
        "interface_version",
        "interface_digest",
        "observed_at",
        "proof_max_age_seconds",
    }
    assert "token" not in json.dumps(body).lower()
    assert OPERATOR_CERTIFICATE not in json.dumps(body)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("active_jobs", 0),
        ("repository", "belilovsky/platform-portal"),
        ("labels", ["self-hosted"]),
        ("action", "restore_saved_configuration"),
        ("host", "runner-host"),
        ("service", "actions.runner.service"),
        ("shell", "systemctl restart anything"),
        ("token", "secret"),
    ],
)
def test_prepare_rejects_every_caller_owned_recovery_field(
    tmp_path: Path,
    policy_files: tuple[Path, Path],
    field: str,
    value: object,
) -> None:
    harness = _harness(tmp_path, policy_files)
    response = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=_prepare_body() | {field: value},
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 422
    assert harness.github.observation_calls == 0


def test_recovery_auth_trusts_only_edge_overwritten_certificate(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    harness = _harness(tmp_path, policy_files)
    self_asserted = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=_prepare_body(),
        headers={
            "X-QDev-Operator-Token": OPERATOR_TOKEN,
            "X-QDev-Operator-mTLS-Identity": "qdev-fleet-operations",
            "X-QDev-Verified-Client-Certificate-SHA256": OPERATOR_CERTIFICATE,
        },
    )
    assert self_asserted.status_code == 401

    disallowed = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=_prepare_body(),
        headers=OPERATOR_HEADERS | {"X-QDev-Verified-Client-Certificate-SHA256": "9" * 64},
    )
    assert disallowed.status_code == 403
    assert harness.github.observation_calls == 0


def test_source_bound_policy_digest_fails_closed(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    harness = _harness(
        tmp_path,
        policy_files,
        policy_digest="sha256:" + "0" * 64,
    )
    response = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=_prepare_body(),
        headers=OPERATOR_HEADERS,
    )
    assert response.status_code == 503
    assert harness.github.observation_calls == 0


def test_status_and_accept_are_bound_to_the_preparing_operator_certificate(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    harness = _harness(tmp_path, policy_files)
    prepared = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=_prepare_body(),
        headers=OPERATOR_HEADERS,
    ).json()
    status_body = _status_body(prepared)

    wrong_owner = harness.client.post(
        "/internal/v1/operations/worker-recovery/status",
        json=status_body,
        headers=OPERATOR_HEADERS
        | {"X-QDev-Verified-Client-Certificate-SHA256": OTHER_OPERATOR_CERTIFICATE},
    )
    assert wrong_owner.status_code == 409
    status = harness.client.post(
        "/internal/v1/operations/worker-recovery/status",
        json=status_body,
        headers=OPERATOR_HEADERS,
    )
    assert status.status_code == 200
    assert status.json()["state"] == "prepared"

    not_ready = harness.client.post(
        "/internal/v1/operations/worker-recovery/accept",
        json={
            "schema": "qdev-runner-recovery-accept-v1",
            "operation_id": prepared["operation_id"],
            "request_fingerprint": prepared["request_fingerprint"],
            "provenance": _provenance(nonce="nonce-accept-0001"),
        },
        headers=OPERATOR_HEADERS,
    )
    assert not_ready.status_code == 409


def test_platform_claim_and_reconcile_have_exact_signed_shapes_and_replay(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    harness = _harness(tmp_path, policy_files)
    prepared = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=_prepare_body(),
        headers=OPERATOR_HEADERS,
    ).json()
    envelope = _claim(harness, prepared, "qdev-platform-ci-187")
    command = envelope["command"]
    assert set(envelope) == {"schema", "command", "command_digest", "signature"}
    assert envelope["schema"] == "qdev-runner-recovery-agent-envelope-v1"
    assert command["schema"] == "qdev-runner-recovery-agent-command-v1"
    assert command["target_id"] == "qdev-platform-ci-187"
    assert command["recovery_action"] == "restore_saved_configuration"
    assert command["interface_version"] == INTERFACE_VERSION
    assert command["interface_digest"] == INTERFACE_DIGEST
    assert command["registration_token"] is None
    assert command["registration_token_expires_at"] is None
    assert (
        envelope["command_digest"]
        == "sha256:" + hashlib.sha256(canonical_json(command)).hexdigest()
    )
    assert (
        envelope["signature"]
        == hmac.new(
            AGENT_SIGNING_KEY.encode("utf-8"), canonical_json(command), hashlib.sha256
        ).hexdigest()
    )

    arbitrary = harness.client.post(
        "/internal/v1/worker-recovery/claim",
        json={
            "schema": "qdev-runner-recovery-agent-claim-v1",
            "operation_id": prepared["operation_id"],
            "action": "arbitrary",
            "shell": "id",
        },
        headers=_agent_headers("qdev-platform-ci-187"),
    )
    assert arbitrary.status_code == 422

    body = _reconcile_body(envelope)
    headers = _reconcile_headers(body, "qdev-platform-ci-187")
    reconciled = harness.client.post(
        "/internal/v1/worker-recovery/reconcile", json=body, headers=headers
    )
    assert reconciled.status_code == 200
    assert reconciled.json()["state"] == "awaiting_acceptance"
    assert reconciled.json()["native_outcome"] == "completed"
    assert reconciled.json()["idempotent_replay"] is False

    replay = harness.client.post(
        "/internal/v1/worker-recovery/reconcile", json=body, headers=headers
    )
    assert replay.status_code == 200
    assert replay.json() == reconciled.json() | {"idempotent_replay": True}


def test_reconcile_rejects_wrong_signature_certificate_and_operation_binding(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    harness = _harness(tmp_path, policy_files)
    prepared = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=_prepare_body(),
        headers=OPERATOR_HEADERS,
    ).json()
    envelope = _claim(harness, prepared, "qdev-platform-ci-187")
    body = _reconcile_body(envelope)

    bad_signature = harness.client.post(
        "/internal/v1/worker-recovery/reconcile",
        json=body,
        headers=_agent_headers("qdev-platform-ci-187")
        | {"X-QDev-Recovery-Agent-Signature": "sha256=" + "0" * 64},
    )
    assert bad_signature.status_code == 409

    wrong_certificate = harness.client.post(
        "/internal/v1/worker-recovery/reconcile",
        json=body,
        headers=_reconcile_headers(body, "qdev-qazstack-01"),
    )
    assert wrong_certificate.status_code == 409

    changed = body | {"request_nonce": "nonce-tampered-0001"}
    changed_binding = harness.client.post(
        "/internal/v1/worker-recovery/reconcile",
        json=changed,
        headers=_reconcile_headers(changed, "qdev-platform-ci-187"),
    )
    assert changed_binding.status_code == 409


def test_qazstack_registration_token_is_minted_only_for_agent_claim(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    harness = _harness(tmp_path, policy_files, target_id="qdev-qazstack-01")
    prepare_response = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=_prepare_body("qdev-qazstack-01", idempotency_key="recovery-qazstack-0001"),
        headers=OPERATOR_HEADERS,
    )
    assert prepare_response.status_code == 200
    assert REGISTRATION_TOKEN not in prepare_response.text
    prepared = prepare_response.json()
    assert harness.github.registration_token_calls == 0

    envelope = _claim(harness, prepared, "qdev-qazstack-01")
    command = envelope["command"]
    assert command["target_id"] == "qdev-qazstack-01"
    assert command["worker_name"] == "qdev-qazstack-01"
    assert command["recovery_action"] == "replace_existing_registration"
    assert command["registration_token"] == REGISTRATION_TOKEN
    assert command["registration_token_expires_at"] is not None
    assert harness.github.registration_token_calls == 1

    status = harness.client.post(
        "/internal/v1/operations/worker-recovery/status",
        json=_status_body(prepared, nonce="nonce-qazstack-status"),
        headers=OPERATOR_HEADERS,
    )
    assert status.status_code == 200
    assert REGISTRATION_TOKEN not in status.text


def test_project_maps_released_completion_and_validates_target_lookup(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    harness = _harness(tmp_path, policy_files)
    prepared = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=_prepare_body(),
        headers=OPERATOR_HEADERS,
    ).json()
    store: Store = harness.client.app.state.store
    controller: WorkerRecoveryController = harness.client.app.state.worker_recovery
    row = store.worker_recovery(prepared["operation_id"])
    assert row is not None
    released = row | {"state": "released", "native_outcome": "completed"}
    assert controller._project(released, idempotent_replay=False).state == "completed"
    assert controller._project(released, idempotent_replay=True).state == "already_completed"

    with pytest.raises(WorkerRecoveryError, match="target is invalid"):
        controller._project(
            released | {"worker_name": "unregistered-runner"},
            idempotent_replay=False,
        )


def test_accept_requires_owner_supplied_exact_canary_sha_and_never_dispatches(
    tmp_path: Path, policy_files: tuple[Path, Path]
) -> None:
    harness = _harness(tmp_path, policy_files)
    prepared = harness.client.post(
        "/internal/v1/operations/worker-recovery/prepare",
        json=_prepare_body(),
        headers=OPERATOR_HEADERS,
    ).json()
    envelope = _claim(harness, prepared, "qdev-platform-ci-187")
    reconcile_body = _reconcile_body(envelope)
    reconciled = harness.client.post(
        "/internal/v1/worker-recovery/reconcile",
        json=reconcile_body,
        headers=_reconcile_headers(reconcile_body, "qdev-platform-ci-187"),
    )
    assert reconciled.status_code == 200

    harness.github.status = "online"
    accept_body = {
        "schema": "qdev-runner-recovery-accept-v1",
        "operation_id": prepared["operation_id"],
        "request_fingerprint": prepared["request_fingerprint"],
        "provenance": _provenance(nonce="nonce-accept-dispatch"),
    }
    failed = harness.client.post(
        "/internal/v1/operations/worker-recovery/accept",
        json=accept_body,
        headers=OPERATOR_HEADERS,
    )
    assert failed.status_code == 409
    assert failed.json()["detail"] == "worker recovery request rejected"
    assert harness.github.dispatch_calls == 0
    assert harness.client.app.state.store.worker_recovery_canary(
        prepared["operation_id"]
    ) is None

    accept_body["canary_head_sha"] = "5" * 40
    pending = harness.client.post(
        "/internal/v1/operations/worker-recovery/accept",
        json=accept_body,
        headers=OPERATOR_HEADERS,
    )
    assert pending.status_code == 200
    assert pending.json()["state"] == "pending_canary"
    assert harness.github.dispatch_calls == 0

    canary = harness.client.app.state.store.worker_recovery_canary(prepared["operation_id"])
    assert canary is not None
    assert canary["phase"] == "dispatch_intent"
    assert canary["head_sha"] == "5" * 40
    assert canary["dispatched_at"] is None

    replay = harness.client.post(
        "/internal/v1/operations/worker-recovery/accept",
        json=accept_body,
        headers=OPERATOR_HEADERS,
    )
    assert replay.status_code == 200
    assert replay.json()["state"] == "pending_canary"
    assert harness.github.dispatch_calls == 0


def test_platform_recovery_canary_targets_the_real_default_branch() -> None:
    target = RECOVERY_TARGETS["qdev-platform-ci-187"]
    assert target.ref == "master"
    assert target.workflow == ".github/workflows/runner-smoke.yml"
