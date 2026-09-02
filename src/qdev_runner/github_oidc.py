"""Verification for GitHub Actions OIDC artifact uploads.

GitHub-hosted jobs cannot receive the controller's short-lived worker token:
that token is bound to a claimed self-hosted job.  This module accepts the
GitHub-issued identity only after binding it to the exact repository, commit
and workflow run named by the artifact path.
"""

from __future__ import annotations

import base64
import json
import math
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from typing import Any

import httpx
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"
GITHUB_ACTIONS_OIDC_JWKS_URL = (
    "https://token.actions.githubusercontent.com/.well-known/jwks"
)
GITHUB_ACTIONS_ARTIFACT_AUDIENCE = "qdev-artifact-v1"
_CLOCK_SKEW_SECONDS = 60
_MAX_TOKEN_AGE_SECONDS = 15 * 60


class GitHubActionsOIDCError(ValueError):
    """The GitHub Actions identity cannot authorize an artifact upload."""


def _b64url_json(value: str, label: str) -> dict[str, Any]:
    try:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        parsed = json.loads(decoded)
    except (UnicodeEncodeError, ValueError, json.JSONDecodeError) as error:
        raise GitHubActionsOIDCError(f"invalid OIDC {label}") from error
    if not isinstance(parsed, dict):
        raise GitHubActionsOIDCError(f"invalid OIDC {label}")
    return parsed


def _b64url_bytes(value: str, label: str) -> bytes:
    try:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))
    except (UnicodeEncodeError, ValueError) as error:
        raise GitHubActionsOIDCError(f"invalid OIDC {label}") from error


def _numeric_date(claims: Mapping[str, Any], name: str) -> float:
    value = claims.get(name)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise GitHubActionsOIDCError(f"OIDC claim {name} is invalid")
    result = float(value)
    if not math.isfinite(result):
        raise GitHubActionsOIDCError(f"OIDC claim {name} is invalid")
    return result


def _audience_matches(value: object, expected: str) -> bool:
    if isinstance(value, str):
        return value == expected
    return (
        isinstance(value, list)
        and all(isinstance(item, str) for item in value)
        and expected in value
    )


def _rsa_key(jwk: Mapping[str, Any]) -> rsa.RSAPublicKey:
    if (
        jwk.get("kty") != "RSA"
        or jwk.get("use") not in {None, "sig"}
        or not isinstance(jwk.get("n"), str)
        or not isinstance(jwk.get("e"), str)
    ):
        raise GitHubActionsOIDCError("OIDC signing key is invalid")
    modulus = int.from_bytes(_b64url_bytes(jwk["n"], "modulus"), "big")
    exponent = int.from_bytes(_b64url_bytes(jwk["e"], "exponent"), "big")
    if modulus.bit_length() < 2048 or exponent < 3 or exponent % 2 == 0:
        raise GitHubActionsOIDCError("OIDC signing key is invalid")
    try:
        return rsa.RSAPublicNumbers(exponent, modulus).public_key()
    except ValueError as error:
        raise GitHubActionsOIDCError("OIDC signing key is invalid") from error


class GitHubActionsArtifactOIDCVerifier:
    """Verify repository-scoped GitHub Actions OIDC tokens with a bounded JWKS cache."""

    def __init__(
        self,
        *,
        issuer: str = GITHUB_ACTIONS_OIDC_ISSUER,
        audience: str = GITHUB_ACTIONS_ARTIFACT_AUDIENCE,
        jwks_url: str = GITHUB_ACTIONS_OIDC_JWKS_URL,
        fetch_jwks: Callable[[], Mapping[str, Any]] | None = None,
        now: Callable[[], datetime] | None = None,
    ) -> None:
        self.issuer = issuer
        self.audience = audience
        self.jwks_url = jwks_url
        self._fetch_jwks = fetch_jwks or self._request_jwks
        self._now = now or (lambda: datetime.now(UTC))
        self._cached_jwks: Mapping[str, Any] | None = None
        self._cached_until = 0.0

    def _request_jwks(self) -> Mapping[str, Any]:
        try:
            response = httpx.get(self.jwks_url, timeout=5.0)
            response.raise_for_status()
            body = response.json()
        except (httpx.HTTPError, ValueError) as error:
            raise GitHubActionsOIDCError("OIDC signing keys are unavailable") from error
        if not isinstance(body, Mapping):
            raise GitHubActionsOIDCError("OIDC signing keys are invalid")
        return body

    def _jwks(self) -> Mapping[str, Any]:
        if self._cached_jwks is None or time.monotonic() >= self._cached_until:
            self._cached_jwks = self._fetch_jwks()
            self._cached_until = time.monotonic() + 300
        return self._cached_jwks

    def verify(self, token: str, *, repository: str, sha: str, run_id: int) -> None:
        parts = token.split(".")
        if len(parts) != 3 or not all(parts):
            raise GitHubActionsOIDCError("OIDC token is malformed")
        header = _b64url_json(parts[0], "header")
        claims = _b64url_json(parts[1], "claims")
        signature = _b64url_bytes(parts[2], "signature")
        kid = header.get("kid")
        if header.get("alg") != "RS256" or not isinstance(kid, str) or not kid:
            raise GitHubActionsOIDCError("OIDC token algorithm is invalid")
        keys = self._jwks().get("keys")
        if not isinstance(keys, list):
            raise GitHubActionsOIDCError("OIDC signing keys are invalid")
        jwk = next(
            (
                candidate
                for candidate in keys
                if isinstance(candidate, Mapping) and candidate.get("kid") == kid
            ),
            None,
        )
        if jwk is None:
            raise GitHubActionsOIDCError("OIDC signing key is unknown")
        try:
            _rsa_key(jwk).verify(
                signature,
                f"{parts[0]}.{parts[1]}".encode("ascii"),
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        except ValueError as error:
            raise GitHubActionsOIDCError("OIDC signing key is invalid") from error
        except InvalidSignature as error:
            raise GitHubActionsOIDCError("OIDC signature is invalid") from error

        now = self._now().astimezone(UTC).timestamp()
        expires = _numeric_date(claims, "exp")
        not_before = _numeric_date(claims, "nbf")
        issued = _numeric_date(claims, "iat")
        if (
            expires <= now - _CLOCK_SKEW_SECONDS
            or not_before > now + _CLOCK_SKEW_SECONDS
            or issued > now + _CLOCK_SKEW_SECONDS
            or now - issued > _MAX_TOKEN_AGE_SECONDS
        ):
            raise GitHubActionsOIDCError("OIDC token is expired or not active")
        if (
            claims.get("iss") != self.issuer
            or not _audience_matches(claims.get("aud"), self.audience)
            or claims.get("repository") != repository
            or claims.get("sha") != sha
            or str(claims.get("run_id")) != str(run_id)
            or claims.get("event_name") == "pull_request"
        ):
            raise GitHubActionsOIDCError("OIDC token scope is invalid")
