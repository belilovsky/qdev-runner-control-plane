from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from qdev_runner.github import GitHubAppClient, GitHubError
from qdev_runner.models import RecoveryAgentCommand


def _client(tmp_path: Path, handler: httpx.MockTransport) -> GitHubAppClient:
    return GitHubAppClient("1", tmp_path / "unused.pem", transport=handler)


def _private_directory(tmp_path: Path) -> Path:
    directory = tmp_path / "controller-private"
    directory.mkdir(mode=0o700)
    directory.chmod(0o700)
    return directory


def test_actions_artifact_download_streams_provider_location_without_installation_token(
    tmp_path: Path,
) -> None:
    requests: list[httpx.Request] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.host == "api.github.com":
            assert request.headers["authorization"] == "Bearer installation-token"
            return httpx.Response(
                302,
                headers={
                    "location": (
                        "https://pipelines.actions.githubusercontent.com/"
                        "download?one-time-signature=opaque"
                    )
                },
            )
        assert request.headers.get("authorization") is None
        assert request.headers["user-agent"] == "qdev-runner-control-plane/0.1"
        return httpx.Response(200, content=b"release-archive")

    client = _client(tmp_path, httpx.MockTransport(respond))
    client.installation_token = lambda _installation_id: "installation-token"  # type: ignore[method-assign]
    destination = _private_directory(tmp_path) / "archive.zip"
    try:
        client.download_actions_artifact_to_file(
            7,
            "belilovsky/qazpolit",
            11,
            destination,
            maximum_bytes=1024,
        )
    finally:
        client.close()

    assert destination.read_bytes() == b"release-archive"
    assert destination.stat().st_mode & 0o777 == 0o600
    assert len(requests) == 2


@pytest.mark.parametrize(
    "location",
    [
        "http://pipelines.actions.githubusercontent.com/archive",
        "https://github.example.invalid/archive",
        "https://user@pipelines.actions.githubusercontent.com/archive",
    ],
)
def test_actions_artifact_download_rejects_unsafe_provider_location(
    tmp_path: Path, location: str
) -> None:
    client = _client(
        tmp_path,
        httpx.MockTransport(lambda _request: httpx.Response(302, headers={"location": location})),
    )
    client.installation_token = lambda _installation_id: "installation-token"  # type: ignore[method-assign]
    destination = _private_directory(tmp_path) / "archive.zip"
    try:
        with pytest.raises(GitHubError, match="location is unsafe"):
            client.download_actions_artifact_to_file(
                7,
                "belilovsky/qazpolit",
                11,
                destination,
                maximum_bytes=1024,
            )
    finally:
        client.close()

    assert not destination.exists()


def test_actions_artifact_download_removes_partial_file_after_size_limit(tmp_path: Path) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "api.github.com":
            return httpx.Response(
                302,
                headers={
                    "location": "https://pipelines.actions.githubusercontent.com/download?signature=x"
                },
            )
        return httpx.Response(200, content=b"too-large")

    client = _client(tmp_path, httpx.MockTransport(respond))
    client.installation_token = lambda _installation_id: "installation-token"  # type: ignore[method-assign]
    destination = _private_directory(tmp_path) / "archive.zip"
    try:
        with pytest.raises(GitHubError, match="exceeds its permitted size"):
            client.download_actions_artifact_to_file(
                7,
                "belilovsky/qazpolit",
                11,
                destination,
                maximum_bytes=1,
            )
    finally:
        client.close()

    assert not destination.exists()


def test_paginated_collection_traverses_more_than_one_page(tmp_path: Path) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        start = 1 if page == 1 else 101
        count = 100 if page == 1 else 1
        return httpx.Response(
            200,
            json={
                "total_count": 101,
                "items": [{"id": value} for value in range(start, start + count)],
            },
        )

    client = _client(tmp_path, httpx.MockTransport(respond))
    try:
        result = client._paginated_collection(
            path="/items",
            token="installation-token",
            key="items",
            description="items",
        )
    finally:
        client.close()

    assert [item["id"] for item in result] == list(range(1, 102))


def test_paginated_collection_rejects_duplicate_identity_during_churn(
    tmp_path: Path,
) -> None:
    def respond(request: httpx.Request) -> httpx.Response:
        page = int(request.url.params["page"])
        return httpx.Response(
            200,
            json={"total_count": 2, "items": [{"id": 1 if page == 1 else 1}]},
        )

    client = _client(tmp_path, httpx.MockTransport(respond))
    try:
        with pytest.raises(GitHubError, match="changed during pagination"):
            client._paginated_collection(
                path="/items",
                token="installation-token",
                key="items",
                description="items",
            )
    finally:
        client.close()


def test_paginated_collection_rejects_duplicate_identity_on_one_page(tmp_path: Path) -> None:
    client = _client(
        tmp_path,
        httpx.MockTransport(
            lambda _request: httpx.Response(
                200,
                json={"total_count": 2, "items": [{"id": 1}, {"id": 1}]},
            )
        ),
    )
    try:
        with pytest.raises(GitHubError, match="changed during pagination"):
            client._paginated_collection(
                path="/items",
                token="installation-token",
                key="items",
                description="items",
            )
    finally:
        client.close()


@pytest.mark.parametrize("sha", ["a" * 39, "a" * 41, "not-a-git-revision"])
def test_ref_sha_rejects_non_exact_provider_revision(tmp_path: Path, sha: str) -> None:
    observed_paths: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        observed_paths.append(str(request.url))
        return httpx.Response(200, json={"sha": sha})

    client = _client(tmp_path, httpx.MockTransport(respond))
    client.installation_token = lambda _installation_id: "installation-token"  # type: ignore[method-assign]
    try:
        assert client.ref_sha(7, "owner/repository", "feature/recovery") is None
    finally:
        client.close()

    assert observed_paths == [
        "https://api.github.com/repos/owner/repository/commits/feature%2Frecovery"
    ]


def _replacement_command(
    *,
    expires_at: datetime,
    token_expires_at: datetime,
    provider_runner_id: int | None = 21,
) -> dict[str, object]:
    return {
        "operation_id": "a" * 64,
        "request_fingerprint": "b" * 64,
        "target_id": "qdev-qazstack-01",
        "worker_name": "qdev-qazstack-01",
        "repository": "belilovsky/qazstack",
        "provider_runner_id": provider_runner_id,
        "provider_status": None if provider_runner_id is None else "offline",
        "labels": ("self-hosted", "Linux", "X64", "qdev-ci"),
        "recovery_action": "replace_existing_registration",
        "execution_disposition": "replace_existing_registration",
        "operator_certificate_sha256": "c" * 64,
        "expected_agent_certificate_sha256": "d" * 64,
        "interface_version": "recovery-v1",
        "interface_digest": "e" * 64,
        "controller_revision": "f" * 40,
        "controller_release_digest": "1" * 64,
        "controller_receipt_id": "2" * 64,
        "policy_digest": "sha256:" + "3" * 64,
        "agent_release_digest": "sha256:" + "4" * 64,
        "provider_idle_proof_digest": "sha256:" + "5" * 64,
        "provider_reconciliation_digest": "sha256:" + "6" * 64,
        "request_nonce": "nonce-001",
        "issued_at": datetime(2026, 9, 5, tzinfo=UTC),
        "expires_at": expires_at,
        "registration_token": "one-use-secret",
        "registration_token_expires_at": token_expires_at,
    }


def test_agent_command_cannot_outlive_registration_token() -> None:
    issued_at = datetime(2026, 9, 5, tzinfo=UTC)
    with pytest.raises(ValidationError, match="cannot outlive"):
        RecoveryAgentCommand.model_validate(
            _replacement_command(
                expires_at=issued_at + timedelta(minutes=2),
                token_expires_at=issued_at + timedelta(minutes=1),
            )
        )


def test_agent_command_may_expire_with_registration_token() -> None:
    issued_at = datetime(2026, 9, 5, tzinfo=UTC)
    command = RecoveryAgentCommand.model_validate(
        _replacement_command(
            expires_at=issued_at + timedelta(minutes=1),
            token_expires_at=issued_at + timedelta(minutes=1),
        )
    )

    assert command.registration_token is not None
    assert command.registration_token.get_secret_value() == "one-use-secret"


def test_replacement_agent_command_allows_absent_provider_registration() -> None:
    issued_at = datetime(2026, 9, 5, tzinfo=UTC)
    command = RecoveryAgentCommand.model_validate(
        _replacement_command(
            expires_at=issued_at + timedelta(minutes=1),
            token_expires_at=issued_at + timedelta(minutes=1),
            provider_runner_id=None,
        )
    )

    assert command.provider_runner_id is None


def test_agent_command_rejects_contradictory_execution_disposition() -> None:
    issued_at = datetime(2026, 9, 5, tzinfo=UTC)
    body = _replacement_command(
        expires_at=issued_at + timedelta(minutes=1),
        token_expires_at=issued_at + timedelta(minutes=1),
    )
    body["execution_disposition"] = "verify_only"

    with pytest.raises(ValidationError, match="execution disposition contradicts"):
        RecoveryAgentCommand.model_validate(body)
