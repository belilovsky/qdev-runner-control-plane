from __future__ import annotations

import json
from pathlib import Path
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


def test_claim_scope_uses_fifo_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, Any] = {}

    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))

    def fake_request(
        settings: operator.OperatorSettings, **kwargs: Any
    ) -> dict[str, Any]:
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
    assert captured["path"].endswith(
        "/workers/srv1879763-light-primary/capacity-override"
    )
    assert captured["body"] == {
        "repository": "belilovsky/qazlake",
        "head_sha": "b" * 40,
        "profiles": ["qdev-ci-docker"],
        "min_disk_free_gib": 4.5,
        "max_disk_used_pct": 95.0,
        "duration_seconds": 900,
        "owner": "portfolio-ci",
        "reason": "bounded exact-SHA recovery",
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
        "/workers/srv1879763-light-primary/capacity-override"
        "?operation_id=operation-123"
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


def test_recover_existing_worker_uses_controller_execution_endpoint(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    captured: dict[str, Any] = {}
    monkeypatch.setenv("QDEV_BOOTSTRAP_OIDC_TOKEN", "synthetic-oidc")
    request_path = tmp_path / "bootstrap-request.json"
    request_path.write_text(
        json.dumps(
            {
                "schema": "qdev-fleet-bootstrap-request-v1",
                "action": "restore-existing-worker",
                "source_sha": "a" * 40,
                "run_id": 123,
                "job_id": 456,
                "attempt": 1,
                "claim_ttl_seconds": 300,
                "controller_revision": "d" * 40,
                "controller_release_digest": "sha256:" + "e" * 64,
                "worker_name": "qdev-platform-ci-187",
                "release_lane": None,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setattr(operator.OperatorSettings, "from_env", classmethod(lambda cls: _settings()))

    def fake_request(settings: operator.OperatorSettings, **kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {"schema": "qdev-controller-receipt-v2"}

    monkeypatch.setattr(operator, "controller_request", fake_request)
    result = operator.run(
        [
            "recover-existing-worker",
            "--request",
            str(request_path),
            "--idempotency-key",
            "worker-recovery-001",
        ]
    )
    assert result == {"schema": "qdev-controller-receipt-v2"}
    assert captured["method"] == "POST"
    assert captured["path"] == "/internal/v1/operations/fleet-bootstrap/recover-existing-worker"
    assert captured["body"]["idempotency_key"] == "worker-recovery-001"
    assert "active_jobs" not in captured["body"]
    assert captured["bootstrap_oidc"] == "synthetic-oidc"


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
