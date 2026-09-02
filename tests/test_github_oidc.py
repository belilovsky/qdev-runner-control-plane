from __future__ import annotations

import base64
import json
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from qdev_runner.github_oidc import GitHubActionsArtifactOIDCVerifier, GitHubActionsOIDCError


def _b64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _jwk(key: rsa.RSAPrivateKey) -> dict[str, str]:
    public_numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "kid": "test-key",
        "use": "sig",
        "n": _b64url(public_numbers.n.to_bytes((public_numbers.n.bit_length() + 7) // 8)),
        "e": _b64url(public_numbers.e.to_bytes((public_numbers.e.bit_length() + 7) // 8)),
    }


def _token(key: rsa.RSAPrivateKey, claims: dict[str, Any]) -> str:
    header = _b64url(json.dumps({"alg": "RS256", "kid": "test-key"}).encode("utf-8"))
    payload = _b64url(json.dumps(claims, sort_keys=True).encode("utf-8"))
    signed = f"{header}.{payload}".encode("ascii")
    signature = key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    return f"{header}.{payload}.{_b64url(signature)}"


def _verifier(key: rsa.RSAPrivateKey, now: datetime) -> GitHubActionsArtifactOIDCVerifier:
    return GitHubActionsArtifactOIDCVerifier(
        fetch_jwks=lambda: {"keys": [_jwk(key)]},
        now=lambda: now,
    )


def _claims(now: datetime) -> dict[str, Any]:
    return {
        "iss": "https://token.actions.githubusercontent.com",
        "aud": "qdev-artifact-v1",
        "repository": "belilovsky/private-repo",
        "sha": "a" * 40,
        "run_id": "123",
        "event_name": "push",
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=5)).timestamp()),
    }


def test_accepts_exact_github_actions_scope() -> None:
    now = datetime(2026, 9, 3, tzinfo=UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    _verifier(key, now).verify(
        _token(key, _claims(now)),
        repository="belilovsky/private-repo",
        sha="a" * 40,
        run_id=123,
    )


def test_rejects_wrong_path_scope_and_pull_request() -> None:
    now = datetime(2026, 9, 3, tzinfo=UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = _verifier(key, now)

    with pytest.raises(GitHubActionsOIDCError, match="scope"):
        verifier.verify(
            _token(key, _claims(now)),
            repository="belilovsky/other-repo",
            sha="a" * 40,
            run_id=123,
        )
    pull_request = _claims(now)
    pull_request["event_name"] = "pull_request"
    with pytest.raises(GitHubActionsOIDCError, match="scope"):
        verifier.verify(
            _token(key, pull_request),
            repository="belilovsky/private-repo",
            sha="a" * 40,
            run_id=123,
        )


def test_rejects_tampered_or_expired_token() -> None:
    now = datetime(2026, 9, 3, tzinfo=UTC)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    verifier = _verifier(key, now)
    token = _token(key, _claims(now))
    header, payload, signature = token.split(".")
    tampered_signature = ("A" if signature[0] != "A" else "B") + signature[1:]
    tampered = f"{header}.{payload}.{tampered_signature}"
    with pytest.raises(GitHubActionsOIDCError, match="signature"):
        verifier.verify(
            tampered,
            repository="belilovsky/private-repo",
            sha="a" * 40,
            run_id=123,
        )
    expired = _claims(now)
    expired["exp"] = int((now - timedelta(minutes=2)).timestamp())
    with pytest.raises(GitHubActionsOIDCError, match="expired"):
        verifier.verify(
            _token(key, expired),
            repository="belilovsky/private-repo",
            sha="a" * 40,
            run_id=123,
        )
