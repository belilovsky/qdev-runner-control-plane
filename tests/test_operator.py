from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

import pytest

from qdev_runner import operator


def _settings() -> operator.OperatorSettings:
    return operator.OperatorSettings(
        controller_url="https://broker.invalid",
        operator_token="inert-operator-token",
        receipt_key="inert-receipt-key",
        mtls_ca="/inert/ca.pem",
        mtls_cert="/inert/cert.pem",
        mtls_key="/inert/key.pem",
    )


def test_pending_terminal_reconciliation_is_explicit(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))

    def fake_request(settings: operator.OperatorSettings, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {}

    monkeypatch.setattr(operator, "controller_request", fake_request)
    operator.run(
        [
            "recover-stale",
            "42",
            "--owner",
            "fleet",
            "--reason",
            "provider completed",
            "--pending-terminal-only",
        ]
    )
    assert captured["path"] == "/internal/v1/operations/jobs/42/recover-stale"
    assert captured["body"]["pending_terminal_only"] is True


def test_claim_scope_uses_fifo_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))

    def fake_request(settings: operator.OperatorSettings, **kwargs: Any) -> dict[str, Any]:
        captured["settings"] = settings
        captured.update(kwargs)
        return {"schema": "qdev-controller-receipt-v2"}

    monkeypatch.setattr(operator, "controller_request", fake_request)

    result = operator.run(
        [
            "claim-scope",
            "42",
            "--worker",
            "srv1879763-light-primary",
            "--tier",
            "primary",
            "--scope-id",
            "08DDBA6B-DD4C-467E-9F74-91D81860AC83",
            "--host",
            "srv1879763-light-primary",
            "--runner",
            "qdev-ci-docker",
            "--worker-certificate-sha256",
            "A" * 64,
            "--correlation-id",
            "qazlake-claim-42",
        ]
    )

    assert result == {"schema": "qdev-controller-receipt-v2"}
    assert captured["method"] == "POST"
    assert captured["path"] == "/internal/v1/operations/jobs/42/claim-scope"
    assert captured["body"] == {
        "job_id": 42,
        "worker_name": "srv1879763-light-primary",
        "tier": "primary",
        "scope_id": "08DDBA6B-DD4C-467E-9F74-91D81860AC83",
        "host": "srv1879763-light-primary",
        "runner": "qdev-ci-docker",
        "worker_certificate_sha256": "a" * 64,
        "correlation_id": "qazlake-claim-42",
        "duration_seconds": 900,
    }


def test_capacity_override_sends_exact_source_binding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))

    def fake_request(settings: operator.OperatorSettings, **kwargs: Any) -> dict[str, Any]:
        captured["settings"] = settings
        captured.update(kwargs)
        return {"schema": "qdev-controller-receipt-v2"}

    monkeypatch.setattr(operator, "controller_request", fake_request)
    result = operator.run(
        [
            "override",
            "srv1879763-light-primary",
            "--repository",
            "belilovsky/qazlake",
            "--head-sha",
            "b" * 40,
            "--claim-scope-id",
            "qazlake-claim-scope-1",
            "--profile",
            "qdev-ci-docker",
            "--owner",
            "portfolio-ci",
            "--reason",
            "bounded exact-SHA recovery",
        ]
    )

    assert result == {"schema": "qdev-controller-receipt-v2"}
    assert captured["method"] == "POST"
    assert captured["path"].endswith("/workers/srv1879763-light-primary/capacity-override")
    assert captured["body"] == {
        "repository": "belilovsky/qazlake",
        "head_sha": "b" * 40,
        "claim_scope_id": "qazlake-claim-scope-1",
        "profiles": ["qdev-ci-docker"],
        "min_disk_free_gib": 4.5,
        "max_disk_used_pct": 90.0,
        "duration_seconds": 900,
        "owner": "portfolio-ci",
        "reason": "bounded exact-SHA recovery",
    }


def test_failed_worker_recovery_uses_provider_reconciled_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))

    def fake_request(settings: operator.OperatorSettings, **kwargs: Any) -> dict[str, Any]:
        captured["settings"] = settings
        captured.update(kwargs)
        return {"schema": "qdev-controller-receipt-v2"}

    monkeypatch.setattr(operator, "controller_request", fake_request)
    result = operator.run(
        [
            "recover-failed",
            "42",
            "--owner",
            "portfolio-ci",
            "--reason",
            "provider remains queued",
        ]
    )

    assert result == {"schema": "qdev-controller-receipt-v2"}
    assert captured["method"] == "POST"
    assert captured["path"] == ("/internal/v1/operations/jobs/42/recover-failed-worker-exit")
    assert captured["body"] == {
        "owner": "portfolio-ci",
        "reason": "provider remains queued",
    }


def test_capacity_override_cancel_requires_exact_operation_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))

    def fake_request(settings: operator.OperatorSettings, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"schema": "qdev-controller-receipt-v2"}

    monkeypatch.setattr(operator, "controller_request", fake_request)
    result = operator.run(
        [
            "cancel",
            "srv1879763-light-primary",
            "--operation-id",
            "operation-123",
        ]
    )

    assert result == {"schema": "qdev-controller-receipt-v2"}
    assert captured["method"] == "DELETE"
    assert captured["path"].endswith(
        "/workers/srv1879763-light-primary/capacity-override?operation_id=operation-123"
    )


def test_queue_audit_uses_signed_durable_queue_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))

    def fake_request(settings: operator.OperatorSettings, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"schema": "qdev-controller-receipt-v2"}

    monkeypatch.setattr(operator, "controller_request", fake_request)

    assert operator.run(["queue-audit"]) == {"schema": "qdev-controller-receipt-v2"}
    assert captured == {
        "method": "GET",
        "path": "/internal/v1/operations/jobs/pending",
    }


def test_recovery_prepare_uses_live_bindings_and_typed_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: list[dict[str, Any]] = []
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))
    monkeypatch.setattr(operator.secrets, "token_hex", lambda size: "9" * (size * 2))

    def fake_request(
        settings: operator.OperatorSettings, **kwargs: Any
    ) -> operator.RecoveryBindingsResponse | operator.RecoveryOperationResponse:
        captured.append(kwargs)
        if kwargs["path"].endswith("/bindings"):
            return operator.RecoveryBindingsResponse.model_validate(
                {
                    "schema": "qdev-runner-recovery-bindings-v1",
                    "controller_revision": "1" * 40,
                    "controller_release_digest": "2" * 64,
                    "policy_digest": "sha256:" + "3" * 64,
                    "agent_release_digest": "sha256:" + "4" * 64,
                    "interface_version": operator.INTERFACE_VERSION,
                    "interface_digest": operator.INTERFACE_DIGEST,
                    "observed_at": datetime(2026, 9, 5, 10, 0, tzinfo=UTC),
                    "proof_max_age_seconds": 120,
                }
            )
        body = kwargs["body"]
        return operator.RecoveryOperationResponse.model_validate(
            {
                "schema": "qdev-runner-recovery-operation-v1",
                "operation_id": "5" * 64,
                "request_fingerprint": "6" * 64,
                "target_id": body["target_id"],
                "worker_name": body["target_id"],
                "repository": "belilovsky/platform-portal",
                "provider_runner_id": 187,
                "state": "prepared",
                "native_outcome": None,
                "controller_revision": "1" * 40,
                "controller_release_digest": "2" * 64,
                "policy_digest": "sha256:" + "3" * 64,
                "agent_release_digest": "sha256:" + "4" * 64,
                "idempotent_replay": False,
            }
        )

    monkeypatch.setattr(operator, "recovery_request", fake_request)
    result = operator.run(
        [
            "recovery-prepare",
            "qdev-platform-ci-187",
            "--idempotency-key",
            "worker-recovery-001",
            "--reason",
            "Restore the fixed Platform CI runner after provider outage.",
        ]
    )
    assert result["state"] == "prepared"
    assert captured[0]["path"] == "/internal/v1/operations/worker-recovery/bindings"
    assert captured[1]["path"] == "/internal/v1/operations/worker-recovery/prepare"
    body = captured[1]["body"]
    assert body["target_id"] == "qdev-platform-ci-187"
    assert body["idempotency_key"] == "worker-recovery-001"
    assert body["provenance"] == {
        "schema": "qdev-runner-recovery-provenance-v1",
        "nonce": "recovery-" + "9" * 32,
        "issued_at": "2026-09-05T10:00:00Z",
        "expires_at": "2026-09-05T10:01:00Z",
        "controller_revision": "1" * 40,
        "controller_release_digest": "2" * 64,
        "policy_digest": "sha256:" + "3" * 64,
        "agent_release_digest": "sha256:" + "4" * 64,
    }


def test_recovery_accept_binds_owner_supplied_exact_canary_sha(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))
    monkeypatch.setattr(
        operator,
        "_fresh_recovery_provenance",
        lambda settings: {"schema": "qdev-runner-recovery-provenance-v1"},
    )

    def fake_request(
        settings: operator.OperatorSettings, **kwargs: Any
    ) -> operator.RecoveryOperationResponse:
        captured.update(kwargs)
        return operator.RecoveryOperationResponse.model_validate(
            {
                "schema": "qdev-runner-recovery-operation-v1",
                "operation_id": "5" * 64,
                "request_fingerprint": "6" * 64,
                "target_id": "qdev-platform-ci-187",
                "worker_name": "qdev-platform-ci-187",
                "repository": "belilovsky/platform-portal",
                "provider_runner_id": 187,
                "state": "pending_canary",
                "native_outcome": "completed",
                "controller_revision": "1" * 40,
                "controller_release_digest": "2" * 64,
                "policy_digest": "sha256:" + "3" * 64,
                "agent_release_digest": "sha256:" + "4" * 64,
                "idempotent_replay": False,
            }
        )

    monkeypatch.setattr(operator, "recovery_request", fake_request)
    result = operator.run(
        [
            "recovery-accept",
            "--operation-id",
            "5" * 64,
            "--request-fingerprint",
            "6" * 64,
            "--canary-head-sha",
            "7" * 40,
        ]
    )

    assert result["state"] == "pending_canary"
    assert captured["path"] == "/internal/v1/operations/worker-recovery/accept"
    assert captured["body"]["canary_head_sha"] == "7" * 40


def test_retired_recovery_command_is_not_exposed() -> None:
    with pytest.raises(SystemExit):
        operator.build_parser().parse_args(["recover-existing-worker"])


@pytest.mark.parametrize(
    ("command", "expected_path", "expected_body"),
    [
        (
            "register-ci",
            "/internal/v1/operations/releases/qazgeo/ci-registration",
            {
                "repository": "belilovsky/qazgeo",
                "source_sha": "a" * 40,
                "run_id": 33870997811,
                "attempt": 1,
                "job_id": 101016693706,
            },
        ),
        (
            "reconcile-ci",
            "/internal/v1/operations/releases/qazgeo/ci-reconcile",
            {"source_sha": "a" * 40},
        ),
    ],
)
def test_qgeo_ci_commands_use_managed_endpoints(
    monkeypatch: pytest.MonkeyPatch,
    command: str,
    expected_path: str,
    expected_body: dict[str, Any],
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))

    def fake_request(settings: operator.OperatorSettings, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"schema": "qdev-controller-receipt-v2"}

    monkeypatch.setattr(operator, "controller_request", fake_request)
    arguments = [command, "--source-sha", "a" * 40]
    if command == "register-ci":
        arguments.extend(["--run-id", "33870997811", "--job-id", "101016693706"])

    assert operator.run(arguments) == {"schema": "qdev-controller-receipt-v2"}
    assert captured["method"] == "POST"
    assert captured["path"] == expected_path
    assert captured["body"] == expected_body


@pytest.mark.parametrize("command", ["register-ci", "reconcile-ci"])
def test_qgeo_ci_commands_reject_non_lowercase_sha(
    monkeypatch: pytest.MonkeyPatch, command: str
) -> None:
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))
    arguments = [command, "--source-sha", "A" * 40]
    if command == "register-ci":
        arguments.extend(["--run-id", "1", "--job-id", "2"])
    with pytest.raises(ValueError, match="invalid Git source SHA"):
        operator.run(arguments)


@pytest.mark.parametrize(
    ("flag", "value", "message"),
    [
        ("--scope-id", "../scope", "invalid claim scope ID"),
        ("--host", "host/name", "invalid host"),
        ("--runner", "runner/name", "invalid runner"),
        ("--worker-certificate-sha256", "not-a-digest", "invalid worker certificate SHA-256"),
    ],
)
def test_claim_scope_rejects_untrusted_identity_inputs(
    monkeypatch: pytest.MonkeyPatch, flag: str, value: str, message: str
) -> None:
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))
    arguments = [
        "claim-scope",
        "42",
        "--worker",
        "srv1879763-light-primary",
        "--tier",
        "primary",
        "--scope-id",
        "scope-42",
        "--host",
        "srv1879763-light-primary",
        "--runner",
        "qdev-ci-docker",
        "--worker-certificate-sha256",
        "a" * 64,
        "--correlation-id",
        "qazlake-claim-42",
    ]
    arguments[arguments.index(flag) + 1] = value

    with pytest.raises(ValueError, match=message):
        operator.run(arguments)


def test_tls_context_keeps_system_roots_and_adds_controller_ca(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class StubContext:
        def __init__(self) -> None:
            self.verify_locations: list[str] = []
            self.cert_chain: tuple[str, str] | None = None

        def load_verify_locations(self, *, cafile: str) -> None:
            self.verify_locations.append(cafile)

        def load_cert_chain(self, certfile: str, keyfile: str) -> None:
            self.cert_chain = (certfile, keyfile)

    created: list[StubContext] = []

    def fake_create_default_context() -> StubContext:
        context = StubContext()
        created.append(context)
        return context

    monkeypatch.setattr(operator.ssl, "create_default_context", fake_create_default_context)
    settings = operator.OperatorSettings(
        controller_url="https://broker.invalid",
        operator_token="inert-operator-token",
        receipt_key="inert-receipt-key",
        mtls_ca="/inert/controller-ca.pem",
        mtls_cert="/inert/operator-cert.pem",
        mtls_key="/inert/operator-key.pem",
    )

    context = operator._tls_context(settings)

    assert context is created[0]
    assert context.verify_locations == ["/inert/controller-ca.pem"]
    assert context.cert_chain == ("/inert/operator-cert.pem", "/inert/operator-key.pem")


def test_controller_request_binds_the_fixed_fleet_mtls_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class StubResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"schema": "qdev-controller-receipt-v2"}

    class StubClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs

        def __enter__(self) -> StubClient:
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def request(self, method: str, path: str, *, json: dict[str, str]) -> StubResponse:
            captured["method"] = method
            captured["path"] = path
            captured["body"] = json
            return StubResponse()

    monkeypatch.setattr(operator, "_tls_context", lambda settings: object())
    monkeypatch.setattr(operator.httpx, "Client", StubClient)
    monkeypatch.setattr(
        operator,
        "verify_controller_receipt",
        lambda document, *, receipt_key: document,
    )

    result = operator.controller_request(
        _settings(),
        method="GET",
        path="/internal/v1/operations/workers",
    )

    assert result == {"schema": "qdev-controller-receipt-v2"}
    assert captured["method"] == "GET"
    assert captured["path"] == "/internal/v1/operations/workers"
    assert captured["body"] is None
    assert captured["client_kwargs"]["headers"] == {
        "X-QDev-Operator-Token": "inert-operator-token",
        "X-QDev-Operator-mTLS-Identity": operator.OPERATOR_MTLS_IDENTITY,
    }


def test_recovery_request_never_self_asserts_edge_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    class StubResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, Any]:
            return {
                "schema": "qdev-runner-recovery-bindings-v1",
                "controller_revision": "1" * 40,
                "controller_release_digest": "2" * 64,
                "policy_digest": "sha256:" + "3" * 64,
                "agent_release_digest": "sha256:" + "4" * 64,
                "interface_version": operator.INTERFACE_VERSION,
                "interface_digest": operator.INTERFACE_DIGEST,
                "observed_at": "2026-09-05T10:00:00Z",
                "proof_max_age_seconds": 120,
            }

    class StubClient:
        def __init__(self, **kwargs: Any) -> None:
            captured["client_kwargs"] = kwargs

        def __enter__(self) -> StubClient:
            return self

        def __exit__(self, *args: Any) -> None:
            return None

        def request(
            self,
            method: str,
            path: str,
            *,
            json: dict[str, Any] | None,
        ) -> StubResponse:
            captured["method"] = method
            captured["path"] = path
            captured["body"] = json
            return StubResponse()

    monkeypatch.setattr(operator, "_tls_context", lambda settings: object())
    monkeypatch.setattr(operator.httpx, "Client", StubClient)

    response = operator.recovery_request(
        _settings(),
        method="POST",
        path="/internal/v1/operations/worker-recovery/bindings",
        response_model=operator.RecoveryBindingsResponse,
    )

    assert response.interface_version == operator.INTERFACE_VERSION
    assert captured["client_kwargs"]["headers"] == {"X-QDev-Operator-Token": "inert-operator-token"}
    assert "X-QDev-Operator-Proxy-Auth" not in captured["client_kwargs"]["headers"]
    assert "X-QDev-Verified-Client-Certificate-SHA256" not in captured["client_kwargs"]["headers"]
