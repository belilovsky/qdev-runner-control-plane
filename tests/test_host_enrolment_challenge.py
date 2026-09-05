from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from qdev_runner.host_enrolment_challenge import (
    HostEnrolmentChallenge,
    create_host_enrolment_ack,
    verify_host_enrolment_ack,
)

KEY = "host-enrolment-test-key-" + "x" * 32


def _challenge() -> HostEnrolmentChallenge:
    return HostEnrolmentChallenge.model_validate(
        {
            "schema": "qdev-host-enrolment-challenge-v1",
            "release_lane": "qdev-release-qmt",
            "project_id": "kaztilshi",
            "placement": "srv138jump",
            "controller_revision": "a" * 40,
            "operation_fence": "fence-" + "b" * 32,
            "certificate_fingerprint_sha256": "c" * 64,
            "nonce": "d" * 64,
        }
    )


def test_ack_is_bound_to_exact_challenge_and_identity() -> None:
    now = datetime(2026, 9, 5, 10, 0, tzinfo=UTC)
    challenge = _challenge()
    acknowledgement = create_host_enrolment_ack(
        challenge,
        mtls_identity="qdev-host-agent:srv138jump",
        signing_key=KEY,
        now=now,
    )

    verified = verify_host_enrolment_ack(
        acknowledgement,
        request=challenge,
        expected_mtls_identity="qdev-host-agent:srv138jump",
        signing_key=KEY,
        now=now + timedelta(minutes=1),
    )

    assert verified == acknowledgement


def test_ack_rejects_tamper_and_expiry() -> None:
    now = datetime(2026, 9, 5, 10, 0, tzinfo=UTC)
    challenge = _challenge()
    acknowledgement = create_host_enrolment_ack(
        challenge,
        mtls_identity="qdev-host-agent:srv138jump",
        signing_key=KEY,
        now=now,
    )
    tampered = {**acknowledgement, "controller_revision": "e" * 40}

    with pytest.raises(ValueError, match="signature is invalid"):
        verify_host_enrolment_ack(
            tampered,
            request=challenge,
            expected_mtls_identity="qdev-host-agent:srv138jump",
            signing_key=KEY,
            now=now,
        )
    with pytest.raises(ValueError, match="expired or invalid"):
        verify_host_enrolment_ack(
            acknowledgement,
            request=challenge,
            expected_mtls_identity="qdev-host-agent:srv138jump",
            signing_key=KEY,
            now=now + timedelta(minutes=6),
        )


def test_historical_replay_still_verifies_signed_shape() -> None:
    now = datetime(2026, 9, 5, 10, 0, tzinfo=UTC)
    challenge = _challenge()
    acknowledgement = create_host_enrolment_ack(
        challenge,
        mtls_identity="qdev-host-agent:srv138jump",
        signing_key=KEY,
        now=now,
    )

    assert (
        verify_host_enrolment_ack(
            acknowledgement,
            request=challenge,
            expected_mtls_identity="qdev-host-agent:srv138jump",
            signing_key=KEY,
            now=now + timedelta(days=1),
            require_current=False,
        )["status"]
        == "verified"
    )
