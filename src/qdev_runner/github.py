from __future__ import annotations

import base64
import json
import logging
import re
import time
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .models import GitHubRegistrationToken, GitHubRunnerObservation

_PRIVATE_HTTP: ContextVar[bool] = ContextVar("qdev_private_github_http", default=False)
_TRANSPORT_LOGGERS = (
    "httpx", "httpcore.connection", "httpcore.http11", "httpcore.http2",
    "httpcore.proxy", "httpcore.socks",
)


class _PrivateHTTPFilter(logging.Filter):
    """Suppress credential-bearing transport traces only in this call context."""

    def filter(self, record: logging.LogRecord) -> bool:
        return not _PRIVATE_HTTP.get()


_PRIVATE_HTTP_FILTER = _PrivateHTTPFilter()


class GitHubError(RuntimeError):
    pass


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class GitHubAppClient:
    def __init__(
        self,
        app_id: str,
        private_key_path: Path,
        api_url: str = "https://api.github.com",
        api_version: str = "2026-03-10",
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        self.app_id = app_id
        self.private_key_path = private_key_path
        self.api_url = api_url.rstrip("/")
        self.api_version = api_version
        for name in _TRANSPORT_LOGGERS:
            logging.getLogger(name).addFilter(_PRIVATE_HTTP_FILTER)
        self._client = httpx.Client(timeout=30, transport=transport)
        self._token_cache: dict[int, tuple[str, float]] = {}

    def close(self) -> None:
        self._client.close()

    def _app_jwt(self) -> str:
        now = int(time.time())
        header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
        payload = _b64url(
            json.dumps({"iat": now - 30, "exp": now + 540, "iss": self.app_id}).encode()
        )
        unsigned = f"{header}.{payload}".encode()
        key = serialization.load_pem_private_key(self.private_key_path.read_bytes(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise GitHubError("GitHub App private key must be RSA")
        signature = key.sign(unsigned, padding.PKCS1v15(), hashes.SHA256())
        return f"{unsigned.decode()}.{_b64url(signature)}"

    def _headers(self, token: str) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {token}",
            "X-GitHub-Api-Version": self.api_version,
            "User-Agent": "qdev-runner-control-plane/0.1",
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        """Make a GitHub API request with a broker-recoverable error boundary."""
        context = _PRIVATE_HTTP.set(True)
        try:
            return self._client.request(method, f"{self.api_url}{path}", **kwargs)
        except httpx.HTTPError as error:
            raise GitHubError(f"GitHub API transport failure: {error}") from error
        finally:
            _PRIVATE_HTTP.reset(context)

    def installation_token(self, installation_id: int) -> str:
        cached = self._token_cache.get(installation_id)
        if cached and cached[1] > time.time() + 120:
            return cached[0]
        response = self._request(
            "POST",
            f"/app/installations/{installation_id}/access_tokens",
            headers=self._headers(self._app_jwt()),
        )
        if response.status_code != 201:
            raise GitHubError(f"installation token request failed: {response.status_code}")
        data = response.json()
        token = str(data["token"])
        self._token_cache[installation_id] = (token, time.time() + 3300)
        return token

    def repository_installation_id(self, repository: str) -> int:
        """Resolve the GitHub App installation for one fixed repository."""

        response = self._request(
            "GET",
            f"/repos/{repository}/installation",
            headers=self._headers(self._app_jwt()),
        )
        if response.status_code != 200:
            raise GitHubError(f"repository installation request failed: {response.status_code}")
        data = response.json()
        installation_id = data.get("id") if isinstance(data, dict) else None
        if isinstance(installation_id, bool) or not isinstance(installation_id, int):
            raise GitHubError("repository installation response is malformed")
        if installation_id <= 0:
            raise GitHubError("repository installation response is malformed")
        return installation_id

    def _paginated_collection(
        self,
        *,
        path: str,
        token: str,
        key: str,
        description: str,
        params: dict[str, str | int] | None = None,
        max_items: int = 10_000,
    ) -> list[dict[str, Any]]:
        """Traverse a complete provider collection with a defensive upper bound."""

        expected_total: int | None = None
        collected: list[dict[str, Any]] = []
        seen_ids: set[int] = set()
        page = 1
        while True:
            request_params = dict(params or {}) | {"per_page": 100, "page": page}
            response = self._request(
                "GET",
                path,
                headers=self._headers(token),
                params=request_params,
            )
            if response.status_code != 200:
                raise GitHubError(f"{description} request failed: {response.status_code}")
            data = response.json()
            total_count = data.get("total_count") if isinstance(data, dict) else None
            items = data.get(key) if isinstance(data, dict) else None
            if (
                isinstance(total_count, bool)
                or not isinstance(total_count, int)
                or total_count < 0
                or total_count > max_items
                or not isinstance(items, list)
                or len(items) > 100
                or any(not isinstance(item, dict) for item in items)
            ):
                raise GitHubError(f"{description} response is malformed")
            if expected_total is None:
                expected_total = total_count
            elif total_count != expected_total:
                raise GitHubError(f"{description} changed during pagination")
            typed_items = cast(list[dict[str, Any]], items)
            page_ids: set[int] = set()
            for item in typed_items:
                item_id = item.get("id")
                if isinstance(item_id, bool) or not isinstance(item_id, int) or item_id <= 0:
                    raise GitHubError(f"{description} response is malformed")
                if item_id in seen_ids or item_id in page_ids:
                    raise GitHubError(f"{description} changed during pagination")
                page_ids.add(item_id)
            seen_ids.update(page_ids)
            collected.extend(typed_items)
            if len(collected) == expected_total:
                return collected
            if not items or len(collected) > expected_total:
                raise GitHubError(f"{description} response is incomplete")
            page += 1

    def repository_runner(
        self,
        installation_id: int,
        repository: str,
        runner_id: int,
    ) -> dict[str, Any]:
        response = self._request(
            "GET",
            f"/repos/{repository}/actions/runners/{runner_id}",
            headers=self._headers(self.installation_token(installation_id)),
        )
        if response.status_code != 200:
            raise GitHubError(f"repository runner request failed: {response.status_code}")
        data = response.json()
        if not isinstance(data, dict):
            raise GitHubError("repository runner response is malformed")
        return cast(dict[str, Any], data)

    def repository_runners(
        self,
        installation_id: int,
        repository: str,
    ) -> list[dict[str, Any]]:
        """Return the complete repository-runner set or fail closed."""

        return self._paginated_collection(
            path=f"/repos/{repository}/actions/runners",
            token=self.installation_token(installation_id),
            key="runners",
            description="repository runners",
        )

    def repository_runners_named(
        self,
        repository: str,
        name: str,
    ) -> tuple[dict[str, Any], ...]:
        installation_id = self.repository_installation_id(repository)
        matches: list[dict[str, Any]] = []
        for runner in self.repository_runners(installation_id, repository):
            runner_name = runner.get("name")
            runner_id = runner.get("id")
            if (
                not isinstance(runner_name, str)
                or isinstance(runner_id, bool)
                or not isinstance(runner_id, int)
            ):
                raise GitHubError("repository runners response is malformed")
            if runner_name == name:
                matches.append(runner)
        return tuple(matches)

    def replace_runner_labels(
        self,
        installation_id: int,
        repository: str,
        runner_id: int,
        labels: tuple[str, ...],
    ) -> None:
        """Replace labels on one exact runner; callers retain the permanent set."""

        if not labels or len(labels) != len(set(labels)):
            raise GitHubError("runner label set is invalid")
        response = self._request(
            "PUT",
            f"/repos/{repository}/actions/runners/{runner_id}/labels",
            headers=self._headers(self.installation_token(installation_id)),
            json={"labels": list(labels)},
        )
        if response.status_code != 200:
            raise GitHubError(f"runner label update failed: {response.status_code}")

    def runner_active_jobs(
        self,
        installation_id: int,
        repository: str,
        runner_id: int,
    ) -> tuple[int, ...]:
        """Enumerate every non-completed provider job bound to an exact runner.

        GitHub does not expose a runner-specific jobs collection.  Recovery
        therefore walks every page of both queued and in-progress run sets and
        every referenced jobs collection.  An incomplete or changing view can
        never be interpreted as idle.
        """

        token = self.installation_token(installation_id)
        run_ids: set[int] = set()
        for status in ("queued", "in_progress"):
            for run in self._paginated_collection(
                path=f"/repos/{repository}/actions/runs",
                token=token,
                key="workflow_runs",
                description="active workflow runs",
                params={"status": status},
            ):
                run_id = run.get("id")
                if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
                    raise GitHubError("active workflow runs response is malformed")
                run_ids.add(run_id)

        active_job_ids: set[int] = set()
        for run_id in sorted(run_ids):
            for job in self._paginated_collection(
                path=f"/repos/{repository}/actions/runs/{run_id}/jobs",
                token=token,
                key="jobs",
                description="workflow jobs",
                params={"filter": "latest"},
            ):
                if job.get("runner_id") != runner_id or job.get("status") == "completed":
                    continue
                job_id = job.get("id")
                if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id <= 0:
                    raise GitHubError("workflow jobs response is malformed")
                active_job_ids.add(job_id)
        return tuple(sorted(active_job_ids))

    def runner_name_active_jobs(
        self,
        installation_id: int,
        repository: str,
        runner_name: str,
    ) -> tuple[int, ...]:
        """Enumerate non-completed jobs that still name an absent runner."""

        token = self.installation_token(installation_id)
        run_ids: set[int] = set()
        for status in ("queued", "in_progress"):
            for run in self._paginated_collection(
                path=f"/repos/{repository}/actions/runs",
                token=token,
                key="workflow_runs",
                description="active workflow runs",
                params={"status": status},
            ):
                run_id = run.get("id")
                if isinstance(run_id, bool) or not isinstance(run_id, int) or run_id <= 0:
                    raise GitHubError("active workflow runs response is malformed")
                run_ids.add(run_id)
        active_job_ids: set[int] = set()
        for run_id in sorted(run_ids):
            for job in self._paginated_collection(
                path=f"/repos/{repository}/actions/runs/{run_id}/jobs",
                token=token,
                key="jobs",
                description="workflow jobs",
                params={"filter": "latest"},
            ):
                if job.get("runner_name") != runner_name or job.get("status") == "completed":
                    continue
                job_id = job.get("id")
                if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id <= 0:
                    raise GitHubError("workflow jobs response is malformed")
                active_job_ids.add(job_id)
        return tuple(sorted(active_job_ids))

    def observe_repository_runner(
        self,
        repository: str,
        runner_id: int,
    ) -> GitHubRunnerObservation:
        installation_id = self.repository_installation_id(repository)
        runner = self.repository_runner(installation_id, repository, runner_id)
        provider_runner_id = runner.get("id")
        name = runner.get("name")
        status = runner.get("status")
        busy = runner.get("busy")
        raw_labels = runner.get("labels")
        if (
            provider_runner_id != runner_id
            or not isinstance(name, str)
            or not name
            or status not in {"online", "offline"}
            or not isinstance(busy, bool)
            or not isinstance(raw_labels, list)
        ):
            raise GitHubError("repository runner response is malformed")
        labels: list[str] = []
        for raw_label in raw_labels:
            label = raw_label.get("name") if isinstance(raw_label, dict) else None
            if not isinstance(label, str) or not label:
                raise GitHubError("repository runner labels are malformed")
            labels.append(label)
        return GitHubRunnerObservation(
            repository=repository,
            runner_id=runner_id,
            name=name,
            status=status,
            busy=busy,
            labels=tuple(labels),
            active_job_ids=self.runner_active_jobs(
                installation_id,
                repository,
                runner_id,
            ),
            observed_at=time.time(),
        )

    def runner_registration_token(self, repository: str) -> GitHubRegistrationToken:
        """Mint a short-lived registration token without logging or caching it."""

        installation_id = self.repository_installation_id(repository)
        response = self._request(
            "POST",
            f"/repos/{repository}/actions/runners/registration-token",
            headers=self._headers(self.installation_token(installation_id)),
        )
        if response.status_code != 201:
            # The provider body can contain credential-adjacent diagnostics;
            # it is intentionally excluded from this exception.
            raise GitHubError(f"runner registration token request failed: {response.status_code}")
        data = response.json()
        token = data.get("token") if isinstance(data, dict) else None
        raw_expires_at = data.get("expires_at") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token or not isinstance(raw_expires_at, str):
            raise GitHubError("runner registration token response is malformed")
        try:
            expires_at = datetime.fromisoformat(raw_expires_at.replace("Z", "+00:00"))
        except ValueError as error:
            raise GitHubError("runner registration token expiry is malformed") from error
        if expires_at.tzinfo is None or expires_at <= datetime.now(UTC) + timedelta(seconds=60):
            raise GitHubError("runner registration token is not sufficiently fresh")
        return GitHubRegistrationToken(token=token, expires_at=expires_at)

    def workflow_run(self, installation_id: int, repository: str, run_id: int) -> dict[str, Any]:
        response = self._request(
            "GET",
            f"/repos/{repository}/actions/runs/{run_id}",
            headers=self._headers(self.installation_token(installation_id)),
        )
        if response.status_code != 200:
            raise GitHubError(f"workflow run request failed: {response.status_code}")
        data = response.json()
        if not isinstance(data, dict):
            raise GitHubError("workflow run response is malformed")
        return cast(dict[str, Any], data)

    def workflow_job(self, installation_id: int, repository: str, job_id: int) -> dict[str, Any]:
        response = self._request(
            "GET",
            f"/repos/{repository}/actions/jobs/{job_id}",
            headers=self._headers(self.installation_token(installation_id)),
        )
        if response.status_code != 200:
            raise GitHubError(f"workflow job request failed: {response.status_code}")
        data = response.json()
        if not isinstance(data, dict):
            raise GitHubError("workflow job response is malformed")
        return cast(dict[str, Any], data)

    def workflow_run_attempt(
        self, installation_id: int, repository: str, run_id: int, attempt: int
    ) -> dict[str, Any]:
        response = self._request(
            "GET",
            f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}",
            headers=self._headers(self.installation_token(installation_id)),
        )
        if response.status_code != 200:
            raise GitHubError(f"workflow attempt request failed: {response.status_code}")
        try:
            data = response.json()
        except ValueError:
            raise GitHubError("workflow attempt response is malformed") from None
        if not isinstance(data, dict):
            raise GitHubError("workflow attempt response is malformed")
        return cast(dict[str, Any], data)

    def workflow_job_log(
        self, installation_id: int, repository: str, job_id: int
    ) -> bytes:
        """Read bounded ephemeral logs; never return signed URLs in errors.

        GitHub's REST endpoint redirects once to its log store. The second
        request carries neither installation authorization nor client cookies.
        Unknown storage hosts fail closed instead of accepting caller URLs.
        """
        limit = 16 * 1024 * 1024
        response: httpx.Response | None = None
        context = _PRIVATE_HTTP.set(True)
        try:
            request = self._client.build_request(
                "GET", f"{self.api_url}/repos/{repository}/actions/jobs/{job_id}/logs",
                headers=self._headers(self.installation_token(installation_id)),
            )
            response = self._client.send(request, stream=True, follow_redirects=False)
            if response.status_code != 302:
                raise GitHubError("workflow log locator request was rejected")
            location = response.headers.get("Location", "")
            if any(ord(character) < 33 for character in location):
                raise GitHubError("workflow log storage location was rejected")
            url = httpx.URL(location)
            if (
                url.scheme != "https" or url.port not in (None, 443)
                or url.userinfo or url.fragment
                or not any(
                    url.host.endswith(suffix)
                    for suffix in (".blob.core.windows.net", ".actions.githubusercontent.com")
                )
            ):
                raise GitHubError("workflow log storage location was rejected")
            response.close()
            response = None
            request = self._client.build_request("GET", url, headers={"Accept": "text/plain"})
            request.headers.pop("Authorization", None)
            request.headers.pop("Cookie", None)
            response = self._client.send(request, stream=True, follow_redirects=False)
            if response.status_code != 200:
                raise GitHubError("workflow log download was rejected")
            chunks = bytearray()
            for chunk in response.iter_bytes(chunk_size=64 * 1024):
                if len(chunks) + len(chunk) > limit:
                    raise GitHubError("workflow log exceeds the bounded read limit")
                chunks.extend(chunk)
            return bytes(chunks)
        except (httpx.HTTPError, httpx.InvalidURL, ValueError):
            raise GitHubError("workflow log transport or response failure") from None
        finally:
            try:
                if response is not None:
                    response.close()
            finally:
                _PRIVATE_HTTP.reset(context)

    def workflow_jobs(
        self,
        installation_id: int,
        repository: str,
        run_id: int,
    ) -> list[dict[str, Any]]:
        """Return every job for one run, failing closed on incomplete pagination."""

        return self._paginated_collection(
            path=f"/repos/{repository}/actions/runs/{run_id}/jobs",
            token=self.installation_token(installation_id),
            key="jobs",
            description="workflow jobs",
            params={"filter": "latest"},
        )

    def generate_jit_config(
        self,
        installation_id: int,
        repository: str,
        name: str,
        labels: tuple[str, ...],
    ) -> str:
        response = self._request(
            "POST",
            f"/repos/{repository}/actions/runners/generate-jitconfig",
            headers=self._headers(self.installation_token(installation_id)),
            json={
                "name": name,
                "runner_group_id": 1,
                "labels": list(labels),
                "work_folder": "_work",
            },
        )
        if response.status_code != 201:
            raise GitHubError(
                f"JIT configuration failed: {response.status_code} {response.text[:300]}"
            )
        return str(response.json()["encoded_jit_config"])

    def rerun_job(self, installation_id: int, repository: str, job_id: int) -> dict[str, Any]:
        """Ask GitHub to rerun one already-registered test job.

        The broker validates the job identity and repository policy before
        calling this method; this method intentionally accepts only a job id,
        never an arbitrary workflow file or shell command.
        """

        response = self._client.post(
            f"{self.api_url}/repos/{repository}/actions/jobs/{job_id}/rerun",
            headers=self._headers(self.installation_token(installation_id)),
        )
        if response.status_code not in {201, 202}:
            raise GitHubError(
                f"job rerun request failed: {response.status_code} {response.text[:300]}"
            )
        return {
            "status_code": response.status_code,
            "location": response.headers.get("location"),
            "request_id": response.headers.get("x-github-request-id"),
        }

    def dispatch_workflow(
        self,
        installation_id: int,
        repository: str,
        workflow: str,
        ref: str,
        inputs: dict[str, str] | None = None,
    ) -> dict[str, Any]:
        """Dispatch a registered workflow file on an exact branch/ref."""

        response = self._client.post(
            (
                f"{self.api_url}/repos/{repository}/actions/workflows/"
                f"{quote(workflow, safe='')}/dispatches"
            ),
            headers=self._headers(self.installation_token(installation_id)),
            json={"ref": ref, "inputs": inputs or {}},
        )
        if response.status_code != 204:
            raise GitHubError(f"workflow dispatch failed: {response.status_code}")
        return {
            "status_code": response.status_code,
            "request_id": response.headers.get("x-github-request-id"),
        }

    def workflow_runs(
        self,
        installation_id: int,
        repository: str,
        *,
        workflow: str | None = None,
        branch: str | None = None,
        event: str | None = None,
        per_page: int = 20,
    ) -> list[dict[str, Any]]:
        """List recent runs for provider-side retry/dispatch reconciliation."""

        path = (
            f"/repos/{repository}/actions/workflows/{quote(workflow, safe='')}/runs"
            if workflow
            else f"/repos/{repository}/actions/runs"
        )
        params: dict[str, str | int] = {"per_page": max(1, min(per_page, 100))}
        if branch:
            params["branch"] = branch
        if event:
            params["event"] = event
        response = self._client.get(
            f"{self.api_url}{path}",
            headers=self._headers(self.installation_token(installation_id)),
            params=params,
        )
        if response.status_code != 200:
            raise GitHubError(f"workflow runs request failed: {response.status_code}")
        data = response.json()
        if not isinstance(data, dict) or not isinstance(data.get("workflow_runs"), list):
            raise GitHubError("workflow runs response is malformed")
        return cast(list[dict[str, Any]], data["workflow_runs"])

    def workflow_runs_complete(
        self,
        installation_id: int,
        repository: str,
        *,
        workflow: str,
        branch: str,
        event: str,
        max_items: int = 10_000,
    ) -> list[dict[str, Any]]:
        """Return the full filtered run set used for recovery-canary correlation."""

        return self._paginated_collection(
            path=(f"/repos/{repository}/actions/workflows/{quote(workflow, safe='')}/runs"),
            token=self.installation_token(installation_id),
            key="workflow_runs",
            description="recovery canary workflow runs",
            params={"branch": branch, "event": event},
            max_items=max_items,
        )

    def ref_sha(self, installation_id: int, repository: str, ref: str) -> str | None:
        """Resolve a branch/ref to the provider's current commit SHA.

        The value is advisory for legacy inventories, but strict test
        registrations persist it in the dispatch intent so a restart can
        reconcile the exact commit instead of guessing from a branch.
        """

        response = self._client.get(
            f"{self.api_url}/repos/{repository}/commits/{quote(ref, safe='')}",
            headers=self._headers(self.installation_token(installation_id)),
        )
        if response.status_code != 200:
            raise GitHubError(f"ref lookup failed: {response.status_code}")
        data = response.json()
        sha = data.get("sha") if isinstance(data, dict) else None
        if not isinstance(sha, str):
            return None
        normalized_sha = sha.lower()
        return normalized_sha if re.fullmatch(r"[0-9a-f]{40}", normalized_sha) else None
