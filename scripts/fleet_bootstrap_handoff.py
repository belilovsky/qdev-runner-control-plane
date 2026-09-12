#!/usr/bin/env python3
"""Submit one already policy-shaped GitHub bootstrap intent to the broker.

The action workflow has no ability to choose an endpoint path, a worker, a
host, a command, a CA, or an OIDC audience. This client derives the fixed
route, controller origin, and policy audience from checked-in policy. The
broker repeats all identity checks before it can write to the protected
host-dispatch spool.
"""

from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from pydantic import ValidationError

_SCRIPTS = Path(__file__).resolve().parent
if str(_SCRIPTS) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS))

from fleet_bootstrap_validate import (  # noqa: E402
    _IDEMPOTENCY_KEY,
    ROOT,
    BootstrapValidationError,
    _oidc_token,
    _required,
    build_request,
)

from qdev_runner.fleet_bootstrap import (  # noqa: E402
    FleetBootstrapError,
    FleetBootstrapPolicy,
    FleetBootstrapRequest,
    bootstrap_ingress_operation_key,
    bootstrap_request_fingerprint,
)
from qdev_runner.fleet_bootstrap_executor import BOOTSTRAP_EXECUTION_RECEIPT_SCHEMA  # noqa: E402

_ROUTES = {
    "activate-controller": "/internal/v1/ingress/fleet-bootstrap/activate-controller",
    "reconcile-controller-activation": (
        "/internal/v1/ingress/fleet-bootstrap/reconcile-controller-activation"
    ),
    "enrol-host-agent": "/internal/v1/ingress/fleet-bootstrap/enrol-host-agent",
    "restore-existing-worker": "/internal/v1/ingress/fleet-bootstrap/restore-existing-worker",
}
# GitHub-hosted Actions cannot present the worker mTLS certificate.  The
# narrowly typed public edge ingress is the only allowlisted bridge; it keeps
# the OIDC assertion intact for the broker's independent verification.
_INGRESS_ORIGIN = "https://ci.qdev.run"
_INGRESS_RESPONSE_FIELDS = frozenset({"schema", "correlation_id", "execution"})
_EXECUTION_FIELDS = frozenset(
    {
        "schema",
        "status",
        "operation_status",
        "action",
        "idempotency_key",
        "request_fingerprint",
        "controller_revision",
        "controller_release_digest",
        "controller_image_digest",
        "controller_internal_image_digest",
        "activation_envelope_digest",
        "release_lane",
        "host_agent_mtls_identity",
        "error_code",
        "result",
    }
)


class BootstrapHandoffError(RuntimeError):
    """A handoff cannot be safely submitted."""


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        request: urllib.request.Request,
        fp: Any,
        code: int,
        message: str,
        headers: Any,
        newurl: str,
    ) -> None:
        return None


def ingress_endpoint(action: str) -> str:
    """Return one route-frozen endpoint for a controller bootstrap action."""

    try:
        route = _ROUTES[action]
    except KeyError as error:
        raise BootstrapHandoffError("bootstrap ingress action is not allowed") from error
    return f"{_INGRESS_ORIGIN}{route}"


def handoff_payload(request: FleetBootstrapRequest, idempotency_key: str) -> dict[str, object]:
    """Serialize only the typed, policy-bound intent accepted by broker."""

    if request.action not in _ROUTES:
        raise BootstrapHandoffError("bootstrap ingress action is not allowed")
    if not _IDEMPOTENCY_KEY.fullmatch(idempotency_key):
        raise BootstrapHandoffError("bootstrap idempotency key is invalid")
    fields = {
        "action": request.action,
        "source_sha": request.source_sha,
        "run_id": request.run_id,
        "job_id": request.job_id,
        "attempt": request.attempt,
        "claim_ttl_seconds": request.claim_ttl_seconds,
        "controller_revision": request.controller_revision,
        "controller_release_digest": request.controller_release_digest,
        "controller_image_digest": request.controller_image_digest,
        "controller_internal_image_digest": request.controller_internal_image_digest,
        "activation_envelope_digest": request.activation_envelope_digest,
        "release_lane": request.release_lane,
    }
    # The incumbent ingress predates worker restoration and rejects unknown
    # fields.  Keep controller activation and enrolment wire-compatible during
    # the bootstrap transition; only the restoration route needs this field.
    if request.action == "restore-existing-worker":
        fields["worker_name"] = request.worker_name
    return {"request": fields, "idempotency_key": idempotency_key}


def _post(endpoint: str, payload: dict[str, object], oidc_token: str) -> dict[str, object]:
    body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - endpoint is validated above
        endpoint,
        data=body,
        headers={
            "Content-Type": "application/json",
            "Accept": "application/json",
            "X-QDev-GitHub-OIDC": oidc_token,
        },
        method="POST",
    )
    try:
        opener = urllib.request.build_opener(_NoRedirect())
        with opener.open(request, timeout=10.0) as response:  # noqa: S310
            raw = response.read()
    except urllib.error.HTTPError as error:
        # The status class is enough to distinguish edge, identity and broker
        # admission failures.  Do not expose a response body or JWT in logs.
        raise BootstrapHandoffError(f"bootstrap ingress rejected with HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError) as error:
        # Neither JWTs nor broker response bodies are safe Action-log content.
        raise BootstrapHandoffError("bootstrap ingress submission failed") from error
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise BootstrapHandoffError("bootstrap ingress response is invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != _INGRESS_RESPONSE_FIELDS
        or value.get("schema") != "qdev-fleet-bootstrap-ingress-v1"
        or not isinstance(value.get("execution"), dict)
        or not isinstance(value.get("correlation_id"), str)
    ):
        raise BootstrapHandoffError("bootstrap ingress response is invalid")
    return value


def validate_execution_acknowledgement(
    value: dict[str, object],
    policy: FleetBootstrapPolicy,
    request: FleetBootstrapRequest,
    correlation_id: str,
) -> dict[str, object]:
    """Accept only a durable queued/completed server acknowledgement.

    A successful HTTP response is not proof that the protected spool accepted
    an executable operation.  Check the complete receipt and all policy-bound
    values so an access-blocked or malformed broker response fails the action.
    """

    if value.get("correlation_id") != correlation_id:
        raise BootstrapHandoffError("bootstrap ingress acknowledgement is invalid")
    execution = value.get("execution")
    if not isinstance(execution, dict) or set(execution) != _EXECUTION_FIELDS:
        raise BootstrapHandoffError("bootstrap ingress acknowledgement is invalid")

    expected_lane = request.release_lane
    expected_host_identity = (
        policy.release_lane(expected_lane).host_agent_mtls_identity
        if request.action == "enrol-host-agent" and expected_lane is not None
        else None
    )
    expected_values = {
        "schema": BOOTSTRAP_EXECUTION_RECEIPT_SCHEMA,
        "action": request.action,
        "idempotency_key": bootstrap_ingress_operation_key(policy, request),
        "request_fingerprint": bootstrap_request_fingerprint(request),
        "controller_revision": request.controller_revision,
        "controller_release_digest": request.controller_release_digest,
        "controller_image_digest": request.controller_image_digest,
        "controller_internal_image_digest": request.controller_internal_image_digest,
        "activation_envelope_digest": request.activation_envelope_digest,
        "release_lane": expected_lane,
        "host_agent_mtls_identity": expected_host_identity,
        "error_code": None,
    }
    if any(execution.get(name) != expected for name, expected in expected_values.items()):
        raise BootstrapHandoffError("bootstrap ingress acknowledgement is invalid")

    status = execution.get("status")
    operation_status = execution.get("operation_status")
    result = execution.get("result")
    if status == "queued" and operation_status == "pending" and result is None:
        return execution
    if status == "completed" and operation_status == "completed" and isinstance(result, dict):
        return execution
    raise BootstrapHandoffError("bootstrap ingress did not durably accept the operation")


def submit() -> dict[str, str]:
    """Build and submit a policy-bound intent without trusting a proof marker."""

    policy_path = Path(
        os.environ.get("FLEET_BOOTSTRAP_POLICY", ROOT / "config/fleet-bootstrap.yml")
    )
    lanes_path = Path(os.environ.get("FLEET_RELEASE_LANES", ROOT / "config/release-lanes.yml"))
    try:
        policy = FleetBootstrapPolicy(policy_path, lanes_path)
        request = build_request(policy)
    except (FleetBootstrapError, ValidationError) as error:
        raise BootstrapHandoffError("bootstrap request fields are invalid") from error
    idempotency_key = _required("BOOTSTRAP_IDEMPOTENCY_KEY")
    payload = handoff_payload(request, idempotency_key)
    endpoint = ingress_endpoint(request.action)
    # This is deliberately a fresh policy-audience token.  The earlier
    # validation marker is audit evidence only and is never a dispatch input.
    acknowledgement = validate_execution_acknowledgement(
        _post(endpoint, payload, _oidc_token(policy.identity.audience)),
        policy,
        request,
        idempotency_key,
    )
    return {
        "status": str(acknowledgement["status"]),
        "operation_status": str(acknowledgement["operation_status"]),
        "request_fingerprint": str(acknowledgement["request_fingerprint"]),
        "idempotency_key": str(acknowledgement["idempotency_key"]),
        "correlation_id": idempotency_key,
    }


def main() -> int:
    try:
        result = submit()
    except (BootstrapValidationError, BootstrapHandoffError) as error:
        print(f"fleet_bootstrap_handoff_failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
