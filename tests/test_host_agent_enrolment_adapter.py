from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from qdev_runner import host_agent_enrolment_adapter as adapter


def _envelope() -> dict[str, Any]:
    return {
        "schema": "qdev-fleet-bootstrap-adapter-request-v1",
        "operation": {"payload": {"fence": "fence-" + "1" * 32}},
        "request": {
            "action": "enrol-host-agent",
            "release_lane": "qdev-release-qmt",
            "worker_name": None,
        },
        "target": adapter.QMT_TARGET,
        "active_jobs": None,
    }


def _result() -> dict[str, Any]:
    return {
        "schema": adapter.RESULT_SCHEMA,
        "status": "completed",
        "action": "enrol-host-agent",
        "target_id": adapter.QMT_TARGET["target_id"],
        "result": {
            "release_lane": "qdev-release-qmt",
            "host_agent_identity": "qdev-host-agent:srv138jump",
            "certificate_fingerprint_sha256": "a" * 64,
            "service_status": "active",
            "enrolment_ack": {"schema": "qdev-host-enrolment-ack-v1"},
        },
        "operation_fence": "fence-" + "1" * 32,
    }


def test_enrolment_uses_only_fixed_ssh_target(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[list[str], str]] = []

    def run(command: list[str], **kwargs: Any) -> Any:
        calls.append((command, kwargs["input"]))
        return SimpleNamespace(returncode=0, stdout=json.dumps(_result()), stderr="")

    monkeypatch.setattr(adapter.subprocess, "run", run)

    assert adapter.enrol(_envelope()) == _result()
    command, stdin = calls[0]
    assert command == [
        "/usr/bin/ssh",
        "-T",
        "-o",
        "BatchMode=yes",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "UserKnownHostsFile=/etc/qdev-runner/bootstrap-known-hosts",
        "-F",
        "/etc/qdev-runner/bootstrap-ssh-config",
        "qdev-bootstrap-srv138jump",
        "/opt/qdev-release-bootstrap/current/venv/bin/qdev-qmt-host-agent-enrol-native",
    ]
    assert json.loads(stdin) == _envelope()


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target", {**adapter.QMT_TARGET, "placement": "attacker"}),
        ("active_jobs", 0),
    ],
)
def test_enrolment_rejects_caller_target_changes(field: str, value: object) -> None:
    envelope = _envelope()
    envelope[field] = value

    with pytest.raises(adapter.HostEnrolmentError, match="not allowlisted"):
        adapter.enrol(envelope)


def test_enrolment_rejects_changed_remote_result(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result = _result()
    result["operation_fence"] = "other"
    monkeypatch.setattr(
        adapter.subprocess,
        "run",
        lambda *args, **kwargs: SimpleNamespace(returncode=0, stdout=json.dumps(result), stderr=""),
    )

    with pytest.raises(adapter.HostEnrolmentError, match="identity mismatch"):
        adapter.enrol(_envelope())
