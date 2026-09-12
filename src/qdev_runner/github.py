from __future__ import annotations

import base64
import json
import os
import re
import stat
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote, urlsplit

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from .models import GitHubRegistrationToken, GitHubRunnerObservation


class GitHubError(RuntimeError):
    pass


_ACTIONS_ARTIFACT_CHUNK_BYTES = 1024 * 1024
_ACTIONS_ARTIFACT_HOST_SUFFIXES = (
    "actions.githubusercontent.com",
    "githubusercontent.com",
    "blob.core.windows.net",
)


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
        try:
            return self._client.request(method, f"{self.api_url}{path}", **kwargs)
        except httpx.HTTPError as error:
            raise GitHubError(f"GitHub API transport failure: {error}") from error

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

    def workflow_run_artifacts(
        self, installation_id: int, repository: str, run_id: int
    ) -> list[dict[str, Any]]:
        """Return the complete artifact set for one exact workflow run."""

        if run_id < 1:
            raise GitHubError("workflow run artifact request identity is invalid")
        return self._paginated_collection(
            path=f"/repos/{repository}/actions/runs/{run_id}/artifacts",
            token=self.installation_token(installation_id),
            key="artifacts",
            description="workflow run artifacts",
        )

    def download_actions_artifact_to_file(
        self,
        installation_id: int,
        repository: str,
        artifact_id: int,
        destination: Path,
        *,
        maximum_bytes: int,
    ) -> None:
        """Stream one Actions artifact into a controller-private temporary file.

        GitHub responds to the authenticated API request with a one-time
        download location. The installation token is deliberately never sent
        to that location, and redirects there are rejected so a provider
        response cannot turn this into a general-purpose downloader.
        """

        if artifact_id < 1 or maximum_bytes < 1:
            raise GitHubError("Actions artifact download identity is invalid")
        self._validate_private_destination(destination)
        response = self._request(
            "GET",
            f"/repos/{repository}/actions/artifacts/{artifact_id}/zip",
            headers=self._headers(self.installation_token(installation_id)),
            follow_redirects=False,
        )
        if response.status_code != 302:
            raise GitHubError(f"Actions artifact download request failed: {response.status_code}")
        location = response.headers.get("location")
        download_url = self._validate_actions_artifact_location(location)
        descriptor: int | None = None
        wrote_destination = False
        try:
            try:
                with self._client.stream(
                    "GET",
                    download_url,
                    headers={"User-Agent": "qdev-runner-control-plane/0.1"},
                    follow_redirects=False,
                ) as streamed:
                    if streamed.status_code != 200:
                        raise GitHubError(
                            "Actions artifact content request failed: "
                            f"{streamed.status_code}"
                        )
                    content_length = streamed.headers.get("content-length")
                    if content_length is not None:
                        try:
                            declared_size = int(content_length)
                        except ValueError as error:
                            raise GitHubError(
                                "Actions artifact content length is invalid"
                            ) from error
                        if declared_size < 0 or declared_size > maximum_bytes:
                            raise GitHubError("Actions artifact exceeds its permitted size")
                    descriptor = os.open(
                        destination,
                        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                        0o600,
                    )
                    wrote_destination = True
                    with os.fdopen(descriptor, "wb") as stream:
                        descriptor = None
                        received = 0
                        for chunk in streamed.iter_bytes(_ACTIONS_ARTIFACT_CHUNK_BYTES):
                            received += len(chunk)
                            if received > maximum_bytes:
                                raise GitHubError("Actions artifact exceeds its permitted size")
                            stream.write(chunk)
                        stream.flush()
                        os.fsync(stream.fileno())
            except httpx.HTTPError as error:
                raise GitHubError(
                    f"Actions artifact download transport failure: {error}"
                ) from error
        except BaseException:
            if wrote_destination:
                try:
                    destination.unlink()
                except FileNotFoundError:
                    pass
                except OSError as error:
                    raise GitHubError(
                        "Actions artifact temporary file cannot be removed"
                    ) from error
            raise
        finally:
            if descriptor is not None:
                os.close(descriptor)

    @staticmethod
    def _validate_private_destination(destination: Path) -> None:
        try:
            parent_metadata = destination.parent.lstat()
        except OSError as error:
            raise GitHubError("Actions artifact destination is unavailable") from error
        if (
            stat.S_ISLNK(parent_metadata.st_mode)
            or not stat.S_ISDIR(parent_metadata.st_mode)
            or stat.S_IMODE(parent_metadata.st_mode) & 0o077
        ):
            raise GitHubError("Actions artifact destination must be controller-private")
        try:
            destination.lstat()
        except FileNotFoundError:
            return
        except OSError as error:
            raise GitHubError("Actions artifact destination cannot be inspected") from error
        raise GitHubError("Actions artifact destination already exists")

    @staticmethod
    def _validate_actions_artifact_location(location: str | None) -> str:
        if not location:
            raise GitHubError("Actions artifact download location is missing")
        parsed = urlsplit(location)
        host = parsed.hostname.lower() if parsed.hostname else None
        valid_host = host is not None and any(
            host == suffix or host.endswith(f".{suffix}")
            for suffix in _ACTIONS_ARTIFACT_HOST_SUFFIXES
        )
        if (
            parsed.scheme != "https"
            or not valid_host
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or (parsed.port is not None and parsed.port != 443)
        ):
            raise GitHubError("Actions artifact download location is unsafe")
        return location

    def workflow_run_jobs(
        self,
        installation_id: int,
        repository: str,
        run_id: int,
        attempt: int,
    ) -> list[dict[str, Any]]:
        """Return the complete job set for one exact workflow-run attempt."""

        if run_id < 1 or attempt < 1:
            raise GitHubError("workflow run job request identity is invalid")
        token = self.installation_token(installation_id)
        jobs: list[dict[str, Any]] = []
        total_count: int | None = None
        page = 1
        while True:
            response = self._request(
                "GET",
                f"/repos/{repository}/actions/runs/{run_id}/attempts/{attempt}/jobs",
                headers=self._headers(token),
                params={"filter": "all", "per_page": 100, "page": page},
            )
            if response.status_code != 200:
                raise GitHubError(
                    "workflow run jobs request failed: "
                    f"{response.status_code} {response.text[:300]}"
                )
            value = response.json()
            if not isinstance(value, dict) or set(value) < {"total_count", "jobs"}:
                raise GitHubError("workflow run jobs response is invalid")
            page_total = value["total_count"]
            page_jobs = value["jobs"]
            if (
                not isinstance(page_total, int)
                or isinstance(page_total, bool)
                or page_total < 0
                or not isinstance(page_jobs, list)
                or any(not isinstance(item, dict) for item in page_jobs)
            ):
                raise GitHubError("workflow run jobs response is invalid")
            if total_count is None:
                total_count = page_total
            elif page_total != total_count:
                raise GitHubError("workflow run jobs response changed during pagination")
            jobs.extend(cast(list[dict[str, Any]], page_jobs))
            if len(jobs) >= total_count:
                break
            if not page_jobs or page >= 100:
                raise GitHubError("workflow run jobs response is incomplete")
            page += 1
        if len(jobs) != total_count:
            raise GitHubError("workflow run jobs response count is invalid")
        job_ids = [item.get("id") for item in jobs]
        if any(
            not isinstance(job_id, int) or isinstance(job_id, bool) or job_id < 1
            for job_id in job_ids
        ):
            raise GitHubError("workflow run jobs response identity is invalid")
        if len(job_ids) != len(set(job_ids)):
            raise GitHubError("workflow run jobs response is duplicated")
        return jobs

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

        response = self._request(
            "POST",
            f"/repos/{repository}/actions/jobs/{job_id}/rerun",
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

        response = self._request(
            "POST",
            f"/repos/{repository}/actions/workflows/{quote(workflow, safe='')}/dispatches",
            headers=self._headers(self.installation_token(installation_id)),
            json={"ref": ref, "inputs": inputs or {}},
        )
        if response.status_code != 204:
            raise GitHubError(
                f"workflow dispatch failed: {response.status_code} {response.text[:300]}"
            )
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
        response = self._request(
            "GET",
            path,
            headers=self._headers(self.installation_token(installation_id)),
            params=params,
        )
        if response.status_code != 200:
            raise GitHubError(
                f"workflow runs request failed: {response.status_code} {response.text[:300]}"
            )
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

        response = self._request(
            "GET",
            f"/repos/{repository}/commits/{quote(ref, safe='')}",
            headers=self._headers(self.installation_token(installation_id)),
        )
        if response.status_code != 200:
            raise GitHubError(f"ref lookup failed: {response.status_code} {response.text[:300]}")
        data = response.json()
        sha = data.get("sha") if isinstance(data, dict) else None
        if not isinstance(sha, str):
            return None
        normalized_sha = sha.lower()
        return normalized_sha if re.fullmatch(r"[0-9a-f]{40}", normalized_sha) else None
