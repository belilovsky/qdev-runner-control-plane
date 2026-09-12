from __future__ import annotations

import importlib.util
import urllib.error
from pathlib import Path
from typing import Any

import pytest

from qdev_runner.fleet_bootstrap import (
    REQUEST_SCHEMA,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    bootstrap_ingress_operation_key,
    bootstrap_request_fingerprint,
)
from qdev_runner.fleet_bootstrap_executor import BOOTSTRAP_EXECUTION_RECEIPT_SCHEMA

ROOT = Path(__file__).resolve().parents[1]
HANDOFF = ROOT / "scripts" / "fleet_bootstrap_handoff.py"


def _module() -> Any:
    spec = importlib.util.spec_from_file_location("fleet_bootstrap_handoff_test", HANDOFF)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request() -> FleetBootstrapRequest:
    return FleetBootstrapRequest.model_validate(
        {
            "schema": REQUEST_SCHEMA,
            "action": "activate-controller",
            "source_sha": "a" * 40,
            "run_id": 123,
            "job_id": 456,
            "attempt": 1,
            "claim_ttl_seconds": 300,
            "controller_revision": "a" * 40,
            "controller_release_digest": "sha256:" + "b" * 64,
            "controller_image_digest": "sha256:" + "c" * 64,
            "activation_envelope_digest": "sha256:" + "d" * 64,
            "release_lane": None,
            "worker_name": None,
        }
    )


def _policy() -> FleetBootstrapPolicy:
    return FleetBootstrapPolicy(
        ROOT / "config" / "fleet-bootstrap.yml",
        ROOT / "config" / "release-lanes.yml",
    )


def _acknowledgement(
    policy: FleetBootstrapPolicy,
    request: FleetBootstrapRequest,
    correlation_id: str,
) -> dict[str, object]:
    return {
        "schema": "qdev-fleet-bootstrap-ingress-v1",
        "correlation_id": correlation_id,
        "execution": {
            "schema": BOOTSTRAP_EXECUTION_RECEIPT_SCHEMA,
            "status": "queued",
            "operation_status": "pending",
            "action": request.action,
            "idempotency_key": bootstrap_ingress_operation_key(policy, request),
            "request_fingerprint": bootstrap_request_fingerprint(request),
            "controller_revision": request.controller_revision,
            "controller_release_digest": request.controller_release_digest,
            "controller_image_digest": request.controller_image_digest,
            "controller_internal_image_digest": request.controller_internal_image_digest,
            "activation_envelope_digest": request.activation_envelope_digest,
            "release_lane": request.release_lane,
            "host_agent_mtls_identity": None,
            "error_code": None,
            "result": None,
        },
    }


def test_handoff_uses_fixed_allowlisted_origin_despite_environment_override(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    monkeypatch.setenv("QDEV_FLEET_BOOTSTRAP_INGRESS_ORIGIN", "https://untrusted.example")

    assert module.ingress_endpoint("activate-controller") == (
        "https://ci.qdev.run/internal/v1/ingress/fleet-bootstrap/activate-controller"
    )
    assert module.ingress_endpoint("enrol-host-agent") == (
        "https://ci.qdev.run/internal/v1/ingress/fleet-bootstrap/enrol-host-agent"
    )
    assert module.ingress_endpoint("restore-existing-worker") == (
        "https://ci.qdev.run/internal/v1/ingress/fleet-bootstrap/restore-existing-worker"
    )


def test_handoff_payload_and_submit_cannot_carry_dispatch_knobs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()
    credential_proof = "-".join(("test", "oidc", "value"))
    request = _request()
    policy = _policy()
    payload = module.handoff_payload(request, "handoff-submit-001")
    intent = payload["request"]

    assert set(payload) == {"request", "idempotency_key"}
    assert "schema" not in intent
    assert intent["worker_name"] is None
    assert not {"active_jobs", "timeout_seconds"} & set(intent)

    posted: dict[str, object] = {}
    monkeypatch.setattr(
        module,
        "FleetBootstrapPolicy",
        lambda _policy, _lanes: policy,
    )
    monkeypatch.setattr(module, "build_request", lambda _policy: request)
    monkeypatch.setattr(module, "_required", lambda _name: "handoff-submit-001")
    monkeypatch.setattr(module, "_oidc_token", lambda _audience: credential_proof)
    monkeypatch.setattr(
        module,
        "_post",
        lambda endpoint, body, token: (
            posted.update({"endpoint": endpoint, "body": body, "token": token})
            or _acknowledgement(policy, request, "handoff-submit-001")
        ),
    )

    result = module.submit()

    assert result["status"] == "queued"
    assert result["operation_status"] == "pending"
    assert result["idempotency_key"] == bootstrap_ingress_operation_key(policy, request)
    assert result["correlation_id"] == "handoff-submit-001"
    assert posted["endpoint"] == module.ingress_endpoint("activate-controller")
    assert posted["token"] == credential_proof
    assert posted["body"] == payload


def test_handoff_rejects_a_non_durable_or_malformed_execution_acknowledgement() -> None:
    module = _module()
    request = _request()
    policy = _policy()
    acknowledgement = _acknowledgement(policy, request, "handoff-submit-001")
    execution = acknowledgement["execution"]
    assert isinstance(execution, dict)
    execution["status"] = "access_blocked"
    execution["error_code"] = "host_dispatch_unavailable"

    with pytest.raises(module.BootstrapHandoffError, match="acknowledgement is invalid"):
        module.validate_execution_acknowledgement(
            acknowledgement,
            policy,
            request,
            "handoff-submit-001",
        )


def test_handoff_reports_only_http_status_for_rejected_ingress(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _module()

    class RejectingOpener:
        def open(self, _request: object, *, timeout: float) -> object:
            raise urllib.error.HTTPError(
                "https://ci.qdev.run/internal/v1/ingress/fleet-bootstrap/activate-controller",
                503,
                "Service Unavailable",
                None,
                None,
            )

    monkeypatch.setattr(module.urllib.request, "build_opener", lambda *_args: RejectingOpener())

    with pytest.raises(module.BootstrapHandoffError, match="HTTP 503"):
        module._post(
            "https://ci.qdev.run/internal/v1/ingress/fleet-bootstrap/activate-controller",
            {},
            "test",
        )
