from __future__ import annotations

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


def test_claim_scope_uses_fifo_endpoint_with_bound_operator_identity(
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
    assert captured["mtls_identity"] == "qdev-fleet-operations"
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
