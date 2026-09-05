from __future__ import annotations

from types import SimpleNamespace
from typing import Any

import pytest

from qdev_runner import qmt_host_agent_enrol_native as native
from qdev_runner.host_agent_enrolment_adapter import QMT_TARGET


def _envelope() -> dict[str, Any]:
    return {
        "schema": "qdev-fleet-bootstrap-adapter-request-v1",
        "operation": {"payload": {"fence": "fence-" + "1" * 32}},
        "request": {
            "action": "enrol-host-agent",
            "release_lane": "qdev-release-qmt",
            "worker_name": None,
            "controller_revision": "a" * 40,
        },
        "target": QMT_TARGET,
        "active_jobs": None,
    }


def test_challenge_nonce_is_stable_for_retry_and_bound_to_identity() -> None:
    values = {
        "controller_revision": "a" * 40,
        "operation_fence": "fence-" + "1" * 32,
        "certificate_fingerprint_sha256": "b" * 64,
    }
    first = native._challenge_nonce(**values)  # noqa: SLF001
    assert native._challenge_nonce(**values) == first  # noqa: SLF001
    assert (
        native._challenge_nonce(  # noqa: SLF001
            **{**values, "certificate_fingerprint_sha256": "c" * 64}
        )
        != first
    )


def test_enrolment_verifies_existing_identity_and_fixed_units(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[list[str]] = []
    results = iter(
        [
            SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
            SimpleNamespace(returncode=0, stdout=b"", stderr=b""),
            SimpleNamespace(returncode=0, stdout=b"success\n", stderr=b""),
        ]
    )
    monkeypatch.setattr(native.os, "geteuid", lambda: 0)
    config = {
        "controller_url": "https://worker.ci.qdev.run",
        "certificate": native.CONFIG,
        "key": native.CONFIG,
        "ca": native.CONFIG,
    }
    acknowledgement = {"schema": "qdev-host-enrolment-ack-v1", "nonce": "b" * 64}
    monkeypatch.setattr(native, "_config", lambda: config)
    monkeypatch.setattr(native, "_verify_certificate", lambda paths: "a" * 64)
    monkeypatch.setattr(
        native,
        "_controller_challenge",
        lambda value, **kwargs: acknowledgement,
    )

    def run(arguments: list[str], **kwargs: Any) -> Any:
        calls.append(arguments)
        return next(results)

    monkeypatch.setattr(native.subprocess, "run", run)

    result = native.enrol(_envelope())

    assert result["status"] == "completed"
    assert result["result"]["certificate_fingerprint_sha256"] == "a" * 64
    assert result["result"]["enrolment_ack"] == acknowledgement
    assert calls == [
        ["/usr/bin/systemctl", "enable", "--now", "qdev-release-qmt.timer"],
        ["/usr/bin/systemctl", "start", "qdev-release-qmt.service"],
        [
            "/usr/bin/systemctl",
            "show",
            "--property=Result",
            "--value",
            "qdev-release-qmt.service",
        ],
    ]


def test_enrolment_requires_root(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(native.os, "geteuid", lambda: 1000)

    with pytest.raises(native.QmtHostEnrolmentError, match="requires root"):
        native.enrol(_envelope())


def test_enrolment_rejects_changed_target(monkeypatch: pytest.MonkeyPatch) -> None:
    envelope = _envelope()
    envelope["target"] = {**QMT_TARGET, "placement": "other"}
    monkeypatch.setattr(native.os, "geteuid", lambda: 0)

    with pytest.raises(native.QmtHostEnrolmentError, match="not allowlisted"):
        native.enrol(envelope)


def test_failed_service_is_not_reported_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(native.os, "geteuid", lambda: 0)
    monkeypatch.setattr(
        native,
        "_config",
        lambda: {
            "controller_url": "https://worker.ci.qdev.run",
            "certificate": native.CONFIG,
            "key": native.CONFIG,
            "ca": native.CONFIG,
        },
    )
    monkeypatch.setattr(native, "_verify_certificate", lambda paths: "a" * 64)
    monkeypatch.setattr(
        native.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=b"failed\n", stderr=b""),
    )

    with pytest.raises(native.QmtHostEnrolmentError, match="not active"):
        native.enrol(_envelope())
