from __future__ import annotations

import importlib.util
import io
import json
import urllib.parse
import urllib.request
import urllib.response
from email.message import Message
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from bootstrap_support import candidate_receipt

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "qdev_test_fleet_bootstrap_validate", ROOT / "scripts" / "fleet_bootstrap_validate.py"
)
assert _SPEC is not None and _SPEC.loader is not None
validator = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(validator)


def _job(**overrides: object) -> dict[str, object]:
    result: dict[str, object] = {
        "id": 9001,
        "run_id": 42,
        "run_attempt": 2,
        "name": "bootstrap",
        "head_sha": "a" * 40,
        "status": "in_progress",
        "conclusion": None,
    }
    result.update(overrides)
    return result


def _prepare(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_SHA", "a" * 40)
    monkeypatch.delenv("BOOTSTRAP_SOURCE_SHA", raising=False)
    monkeypatch.delenv("BOOTSTRAP_JOB_ID", raising=False)
    monkeypatch.setattr(validator, "_job_list", lambda repository, run_id, attempt: [_job()])


def test_resolve_job_id_binds_numeric_job_to_current_attempt(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)

    assert validator.resolve_job_id("owner/repo", 42, attempt=2, expected_name="bootstrap") == 9001


@pytest.mark.parametrize(
    "overrides",
    [
        {"run_attempt": 1},
        {"run_attempt": None},
        {"run_attempt": "2"},
        {"run_attempt": True},
        {"run_id": 43},
        {"run_id": "42"},
        {"run_id": True},
        {"head_sha": "b" * 40},
        {"status": "queued"},
        {"status": "completed", "conclusion": "success"},
        {"status": "completed", "conclusion": "failure"},
        {"status": "in_progress", "conclusion": "success"},
    ],
)
def test_resolve_job_id_rejects_job_not_running_in_this_attempt(
    monkeypatch: pytest.MonkeyPatch, overrides: dict[str, object]
) -> None:
    _prepare(monkeypatch)
    monkeypatch.setattr(
        validator,
        "_job_list",
        lambda repository, run_id, attempt: [_job(**overrides)],
    )

    with pytest.raises(validator.BootstrapValidationError, match="does not match this attempt"):
        validator.resolve_job_id("owner/repo", 42, attempt=2, expected_name="bootstrap")


def test_resolve_job_id_rejects_profile_label_as_supplied_job_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)
    monkeypatch.setenv("BOOTSTRAP_JOB_ID", "qdev-ci")

    with pytest.raises(validator.BootstrapValidationError, match="positive integer"):
        validator.resolve_job_id("owner/repo", 42, attempt=2, expected_name="bootstrap")


def test_resolve_job_id_rejects_non_unique_job_name(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _prepare(monkeypatch)
    monkeypatch.setattr(
        validator,
        "_job_list",
        lambda repository, run_id, attempt: [_job(), _job(id=9002)],
    )

    with pytest.raises(validator.BootstrapValidationError, match="not uniquely"):
        validator.resolve_job_id("owner/repo", 42, attempt=2, expected_name="bootstrap")


@pytest.mark.parametrize("job_id", [None, True, 0, -1, "9001"])
def test_resolve_job_id_requires_positive_numeric_identity(
    monkeypatch: pytest.MonkeyPatch, job_id: object
) -> None:
    _prepare(monkeypatch)
    monkeypatch.setattr(
        validator, "_job_list", lambda repository, run_id, attempt: [_job(id=job_id)]
    )
    with pytest.raises(validator.BootstrapValidationError, match="invalid numeric job ID"):
        validator.resolve_job_id("owner/repo", 42, attempt=2, expected_name="bootstrap")


def test_build_request_passes_exact_attempt_to_lookup(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.setenv("GITHUB_RUN_ATTEMPT", "2")
    monkeypatch.setenv("BOOTSTRAP_JOB_NAME", "bootstrap")
    seen = []

    def lookup(repository: str, run_id: int, *, attempt: int, expected_name: str) -> int:
        seen.append((repository, run_id, attempt, expected_name))
        raise RuntimeError("lookup reached")

    monkeypatch.setattr(validator, "resolve_job_id", lookup)
    policy = SimpleNamespace(identity=SimpleNamespace(repository="owner/repo"))
    with pytest.raises(RuntimeError, match="lookup reached"):
        validator.build_request(policy)
    assert seen == [("owner/repo", 42, 2, "bootstrap")]


@pytest.mark.parametrize("attempt", [None, "", "0", "-1", "not-an-attempt"])
def test_build_request_requires_current_attempt(
    monkeypatch: pytest.MonkeyPatch, attempt: str | None
) -> None:
    monkeypatch.setenv("GITHUB_REPOSITORY", "owner/repo")
    monkeypatch.setenv("GITHUB_RUN_ID", "42")
    monkeypatch.delenv("GITHUB_RUN_ATTEMPT", raising=False)
    if attempt is not None:
        monkeypatch.setenv("GITHUB_RUN_ATTEMPT", attempt)
    policy = SimpleNamespace(identity=SimpleNamespace(repository="owner/repo"))
    with pytest.raises(validator.BootstrapValidationError, match="GITHUB_RUN_ATTEMPT"):
        validator.build_request(policy)


def _capture_requests(
    monkeypatch: pytest.MonkeyPatch, body: Any
) -> list[tuple[str, dict[str, str]]]:
    seen: list[tuple[str, dict[str, str]]] = []

    def request(url: str, *, headers: dict[str, str]) -> Any:
        seen.append((url, headers))
        return body

    monkeypatch.setattr(validator, "_json_request", request)
    return seen


@pytest.mark.parametrize(
    "host",
    [
        "pipelinesghubeus13.actions.githubusercontent.com",
        "pipelinesghubeus10.actions.githubusercontent.com",
        "vstoken.actions.githubusercontent.com",
        "token.actions.githubusercontent.com",
    ],
)
def test_oidc_accepts_github_regional_mint_hosts(
    monkeypatch: pytest.MonkeyPatch, host: str
) -> None:
    endpoint = (
        f"https://{host}/org/_apis/distributedtask/hubs/build/plans/plan/jobs/job/idtoken"
        "?api-version=2.0&audience=old&audience=other&empty="
    )
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", endpoint)
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "synthetic-runtime-bearer")
    seen = _capture_requests(monkeypatch, {"value": "synthetic-oidc-jwt"})

    assert validator._oidc_token("qdev:bootstrap") == "synthetic-oidc-jwt"
    assert len(seen) == 1
    parsed = urllib.parse.urlsplit(seen[0][0])
    assert parsed.hostname == host
    assert parsed.path == urllib.parse.urlsplit(endpoint).path
    assert urllib.parse.parse_qsl(parsed.query, keep_blank_values=True) == [
        ("api-version", "2.0"),
        ("empty", ""),
        ("audience", "qdev:bootstrap"),
    ]
    assert seen[0][1]["Authorization"] == "Bearer synthetic-runtime-bearer"


@pytest.mark.parametrize(
    "endpoint",
    [
        "https://attacker.invalid/idtoken",
        "https://actions.githubusercontent.com/idtoken",
        "https://evilactions.githubusercontent.com/idtoken",
        "https://token.actions.githubusercontent.com.attacker.invalid/idtoken",
        "https://token.actions.githubusercontent.com@attacker.invalid/idtoken",
        "https://attacker.invalid@token.actions.githubusercontent.com/idtoken",
        "https://@token.actions.githubusercontent.com/idtoken",
        "http://token.actions.githubusercontent.com/idtoken",
        "https://token.actions.githubusercontent.com:444/idtoken",
        "https://token.actions.githubusercontent.com:invalid/idtoken",
        "https://token.actions.githubusercontent.com/idtoken#fragment",
        "https://token.actions.githubusercontent.com\\@attacker.invalid/idtoken",
        "https://token.actions.githubuser\ncontent.com/idtoken",
    ],
)
def test_oidc_rejects_untrusted_endpoint_before_sending_bearer(
    monkeypatch: pytest.MonkeyPatch, endpoint: str
) -> None:
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_URL", endpoint)
    monkeypatch.setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "synthetic-runtime-bearer")
    seen = _capture_requests(monkeypatch, {"value": "synthetic-oidc-jwt"})
    with pytest.raises(validator.BootstrapValidationError):
        validator._oidc_token("qdev:bootstrap")
    assert seen == []


@pytest.mark.parametrize(
    "origin",
    [None, "https://api.github.com", "https://api.github.com/", "https://api.github.com:443"],
)
def test_job_list_uses_fixed_origin_and_attempt_endpoint(
    monkeypatch: pytest.MonkeyPatch, origin: str | None
) -> None:
    monkeypatch.delenv("GITHUB_API_URL", raising=False)
    if origin is not None:
        monkeypatch.setenv("GITHUB_API_URL", origin)
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-github-bearer")
    seen = _capture_requests(monkeypatch, {"jobs": [_job()]})

    assert validator._job_list("owner/repo", 42, 2) == [_job()]
    assert seen[0][0] == (
        "https://api.github.com/repos/owner/repo/actions/runs/42/attempts/2/jobs?per_page=100"
    )
    assert seen[0][1]["Authorization"] == "Bearer synthetic-github-bearer"


@pytest.mark.parametrize(
    "origin",
    [
        "https://attacker.invalid",
        "https://api.github.com.attacker.invalid",
        "http://api.github.com",
        "https://api.github.com:444",
        "https://api.github.com:invalid",
        "https://attacker.invalid@api.github.com",
        "https://@api.github.com",
        "https://api.github.com/untrusted-prefix",
        "https://api.github.com?untrusted=query",
        "https://api.github.com#fragment",
        "https://api.git\nhub.com",
    ],
)
def test_job_list_rejects_origin_override_before_sending_bearer(
    monkeypatch: pytest.MonkeyPatch, origin: str
) -> None:
    monkeypatch.setenv("GITHUB_API_URL", origin)
    monkeypatch.setenv("GITHUB_TOKEN", "synthetic-github-bearer")
    seen = _capture_requests(monkeypatch, {"jobs": [_job()]})
    with pytest.raises(validator.BootstrapValidationError):
        validator._job_list("owner/repo", 42, 2)
    assert seen == []


@pytest.mark.parametrize("status", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "target", ["https://attacker.invalid/leak", "http://attacker.invalid/leak", "/same-origin"]
)
def test_json_request_never_follows_bearer_redirect(
    monkeypatch: pytest.MonkeyPatch, status: int, target: str
) -> None:
    seen: list[tuple[str, str | None]] = []

    def response(request: urllib.request.Request) -> Any:
        seen.append((request.full_url, request.get_header("Authorization")))
        headers = Message()
        headers["Location"] = target
        reply = urllib.response.addinfourl(
            io.BytesIO(b"sensitive response body"), headers, request.full_url, status
        )
        reply.msg = "Redirect"
        return reply

    class StubHTTPS(urllib.request.HTTPSHandler):
        def https_open(self, request: urllib.request.Request) -> Any:
            return response(request)

    class StubHTTP(urllib.request.HTTPHandler):
        def http_open(self, request: urllib.request.Request) -> Any:
            return response(request)

    build_opener = urllib.request.build_opener
    monkeypatch.setattr(
        urllib.request,
        "build_opener",
        lambda *handlers: build_opener(
            *handlers, StubHTTPS(), StubHTTP(), urllib.request.ProxyHandler({})
        ),
    )
    with pytest.raises(
        validator.BootstrapValidationError, match="endpoint is unavailable"
    ) as error:
        validator._json_request(
            "https://api.github.com/original", headers={"Authorization": "Bearer synthetic-bearer"}
        )
    assert seen == [("https://api.github.com/original", "Bearer synthetic-bearer")]
    assert "sensitive" not in str(error.value)
    assert "synthetic-bearer" not in str(error.value)


def _bootstrap_request() -> Any:
    return validator.FleetBootstrapRequest.model_validate(
        {
            "schema": validator.REQUEST_SCHEMA,
            "action": "activate-controller",
            "source_sha": "a" * 40,
            "run_id": 42,
            "job_id": 9001,
            "attempt": 2,
            "claim_ttl_seconds": 900,
            "controller_revision": "a" * 40,
            "controller_release_digest": "sha256:" + "b" * 64,
            "controller_candidate_receipt": candidate_receipt(),
            "release_lane": None,
            "worker_name": None,
        }
    )


def test_execute_submits_exact_validated_request_and_scrubs_oidc(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _bootstrap_request()
    fingerprint = validator.bootstrap_request_fingerprint(request)
    seen: dict[str, Any] = {}
    monkeypatch.setattr(
        validator,
        "_validated_operation",
        lambda: (request, "bootstrap-once-001", "short-lived-oidc"),
    )
    previous_value = "existing-value"
    monkeypatch.setenv("QDEV_BOOTSTRAP_OIDC_TOKEN", previous_value)

    def run(arguments: list[str]) -> dict[str, Any]:
        seen["arguments"] = arguments
        seen["oidc"] = validator.os.environ["QDEV_BOOTSTRAP_OIDC_TOKEN"]
        request_path = Path(arguments[arguments.index("--request") + 1])
        seen["request_path"] = request_path
        seen["request"] = request_path.read_text(encoding="utf-8")
        return {
            "schema": "qdev-controller-receipt-v2",
            "payload": {
                "kind": "fleet-bootstrap",
                "status": "completed",
                "operation_status": "completed",
                "action": "activate-controller",
                "idempotency_key": "bootstrap-once-001",
                "request_fingerprint": fingerprint,
            },
        }

    monkeypatch.setattr(validator, "operator_run", run)

    result = validator.execute()

    assert result["status"] == "completed"
    assert seen["oidc"] == "short-lived-oidc"
    assert json.loads(seen["request"]) == request.model_dump(mode="json", by_alias=True)
    assert not seen["request_path"].exists()
    assert validator.os.environ["QDEV_BOOTSTRAP_OIDC_TOKEN"] == previous_value


def test_execute_fails_when_controller_does_not_complete_exact_request(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    request = _bootstrap_request()
    monkeypatch.setattr(
        validator,
        "_validated_operation",
        lambda: (request, "bootstrap-once-001", "short-lived-oidc"),
    )
    monkeypatch.setattr(
        validator,
        "operator_run",
        lambda arguments: {
            "payload": {
                "kind": "fleet-bootstrap",
                "status": "access_blocked",
                "operation_status": "pending",
                "action": "activate-controller",
                "idempotency_key": "bootstrap-once-001",
                "request_fingerprint": validator.bootstrap_request_fingerprint(request),
            }
        },
    )

    with pytest.raises(validator.BootstrapValidationError, match="did not complete the exact"):
        validator.execute()

    assert "QDEV_BOOTSTRAP_OIDC_TOKEN" not in validator.os.environ
