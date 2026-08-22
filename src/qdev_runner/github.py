from __future__ import annotations

import base64
import json
import time
from pathlib import Path
from typing import Any, cast

import httpx
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


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

    def installation_token(self, installation_id: int) -> str:
        cached = self._token_cache.get(installation_id)
        if cached and cached[1] > time.time() + 120:
            return cached[0]
        response = self._client.post(
            f"{self.api_url}/app/installations/{installation_id}/access_tokens",
            headers=self._headers(self._app_jwt()),
        )
        if response.status_code != 201:
            raise GitHubError(
                f"installation token request failed: {response.status_code} {response.text[:300]}"
            )
        data = response.json()
        token = str(data["token"])
        self._token_cache[installation_id] = (token, time.time() + 3300)
        return token

    def workflow_run(self, installation_id: int, repository: str, run_id: int) -> dict[str, Any]:
        response = self._client.get(
            f"{self.api_url}/repos/{repository}/actions/runs/{run_id}",
            headers=self._headers(self.installation_token(installation_id)),
        )
        if response.status_code != 200:
            raise GitHubError(
                f"workflow run request failed: {response.status_code} {response.text[:300]}"
            )
        return cast(dict[str, Any], response.json())

    def generate_jit_config(
        self,
        installation_id: int,
        repository: str,
        name: str,
        labels: tuple[str, ...],
    ) -> str:
        response = self._client.post(
            f"{self.api_url}/repos/{repository}/actions/runners/generate-jitconfig",
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
