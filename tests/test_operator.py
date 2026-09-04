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
