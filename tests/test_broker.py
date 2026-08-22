from __future__ import annotations

import hashlib
import hmac

from qdev_runner.broker import artifact_token, verify_signature


def test_webhook_signature() -> None:
    body = b'{"action":"queued"}'
    signature = "sha256=" + hmac.new(b"secret", body, hashlib.sha256).hexdigest()
    assert verify_signature("secret", body, signature)
    assert not verify_signature("secret", body + b"x", signature)
    assert not verify_signature("secret", body, None)


def test_artifact_token_is_scoped() -> None:
    token = artifact_token("secret", "belilovsky/repo", "abc", 1)
    assert token == artifact_token("secret", "belilovsky/repo", "abc", 1)
    assert token != artifact_token("secret", "belilovsky/repo", "abc", 2)
