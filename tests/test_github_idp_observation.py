import logging
from concurrent.futures import ThreadPoolExecutor

import httpx
import pytest

from qdev_runner.github import GitHubAppClient, GitHubError


def client_for(tmp_path, handler):
    client = GitHubAppClient("1", tmp_path / "unused.pem", transport=httpx.MockTransport(handler))
    client.installation_token = lambda _: "fixture-installation-credential"
    return client


def test_run_attempt_uses_exact_provider_endpoint(tmp_path):
    def handler(request):
        assert request.url.path == "/repos/belilovsky/id-qdev-run/actions/runs/17/attempts/3"
        assert request.headers["Authorization"] == "Bearer fixture-installation-credential"
        return httpx.Response(200, json={"id": 17, "run_attempt": 3})

    client = client_for(tmp_path, handler)
    try:
        assert client.workflow_run_attempt(7, "belilovsky/id-qdev-run", 17, 3)["run_attempt"] == 3
    finally:
        client.close()


@pytest.mark.parametrize(
    "status,content", [(503, b"fixture-sensitive-value"), (200, b"invalid"), (200, b"[]")]
)
def test_run_attempt_errors_are_redacted(tmp_path, status, content):
    client = client_for(tmp_path, lambda _: httpx.Response(status, content=content))
    try:
        with pytest.raises(GitHubError) as error:
            client.workflow_run_attempt(7, "belilovsky/id-qdev-run", 17, 3)
        assert "fixture-sensitive-value" not in str(error.value)
    finally:
        client.close()


def test_job_log_redirect_does_not_forward_authorization_or_cookies(tmp_path):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            assert request.url.path.endswith("/actions/jobs/23/logs")
            assert "Authorization" in request.headers
            return httpx.Response(
                302,
                headers={
                    "Location": "https://results.blob.core.windows.net/job/log?sig=fixture-url-credential"
                },
            )
        assert "Authorization" not in request.headers
        assert "Cookie" not in request.headers
        return httpx.Response(200, content=b"fixture log\n")

    client = client_for(tmp_path, handler)
    client._client.cookies.set("fixture-cookie", "fixture-value", domain=".blob.core.windows.net")
    try:
        assert client.workflow_job_log(7, "belilovsky/id-qdev-run", 23) == b"fixture log\n"
    finally:
        client.close()
    assert len(calls) == 2


@pytest.mark.parametrize(
    "location",
    [
        "https://attacker.test/?sig=fixture-sensitive-value",
        "http://results.blob.core.windows.net/",
        "https://results.blob.core.windows.net.attacker.test/",
        "https://127.0.0.1/",
        "https://user:fixture-sensitive-value@results.blob.core.windows.net/",
        "https://results.blob.core.windows.net:444/",
        "https://results.blob.core.windows.net/#fragment",
        "",
        "https://results.blob.core.windows.net/\n",
    ],
)
def test_job_log_rejects_unexpected_location_before_download(tmp_path, location):
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(302, headers={"Location": location})

    client = client_for(tmp_path, handler)
    try:
        with pytest.raises(GitHubError) as error:
            client.workflow_job_log(7, "belilovsky/id-qdev-run", 23)
        assert "fixture-sensitive-value" not in str(error.value)
    finally:
        client.close()
    assert len(calls) == 1


@pytest.mark.parametrize("outcome", ["redirect", "failed", "transport", "oversized"])
def test_job_log_fails_closed_without_url_or_content_leak(tmp_path, outcome):
    calls = []

    def handler(request):
        calls.append(request)
        if len(calls) == 1:
            return httpx.Response(
                302,
                headers={
                    "Location": "https://results.blob.core.windows.net/log?sig=fixture-sensitive-value"
                },
            )
        if outcome == "redirect":
            return httpx.Response(302, headers={"Location": "https://attacker.test/"})
        if outcome == "failed":
            return httpx.Response(403, content=b"fixture-sensitive-value")
        if outcome == "transport":
            raise httpx.ConnectError("fixture-sensitive-value", request=request)
        return httpx.Response(200, content=b"x" * (16 * 1024 * 1024 + 1))

    client = client_for(tmp_path, handler)
    try:
        with pytest.raises(GitHubError) as error:
            client.workflow_job_log(7, "belilovsky/id-qdev-run", 23)
        assert "fixture-sensitive-value" not in str(error.value)
        assert error.value.__cause__ is None
    finally:
        client.close()
    assert len(calls) == 2


@pytest.mark.parametrize("failure", [False, True])
def test_transport_logging_cannot_record_credentials_or_signed_urls(tmp_path, caplog, failure):
    caplog.set_level(logging.DEBUG)
    calls = []

    def handler(request):
        calls.append(request)
        # Model the actual HTTPX INFO URL and HTTPCore DEBUG header log sites.
        logging.getLogger("httpx").info("request %s", request.url)
        logging.getLogger("httpcore.http11").debug("headers %s", request.headers)
        logging.getLogger("httpcore.http2").debug("fixture-sensitive-value")
        if len(calls) == 1:
            return httpx.Response(
                302,
                headers={
                    "Location": "https://results.blob.core.windows.net/log?sig=fixture-sensitive-value"
                },
            )
        # Another thread's unrelated diagnostics must not be globally disabled.
        with ThreadPoolExecutor(max_workers=1) as executor:
            executor.submit(logging.getLogger("httpx").info, "unrelated transport").result()
        if failure:
            raise httpx.ConnectError("fixture-sensitive-value", request=request)
        return httpx.Response(200, content=b"fixture log")

    client = client_for(tmp_path, handler)
    try:
        if failure:
            with pytest.raises(GitHubError):
                client.workflow_job_log(7, "belilovsky/id-qdev-run", 23)
        else:
            assert client.workflow_job_log(7, "belilovsky/id-qdev-run", 23) == b"fixture log"
    finally:
        client.close()
    logging.getLogger("httpx").info("context restored")
    assert "fixture-sensitive-value" not in caplog.text
    assert "fixture-installation-credential" not in caplog.text
    assert "unrelated transport" in caplog.text
    assert "context restored" in caplog.text
