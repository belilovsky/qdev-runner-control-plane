from __future__ import annotations

import copy
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qdev_runner.controller_admission import (
    ControllerAdmissionError,
    canonical_payload,
    initialize_keypair,
    load_json_strict,
    main,
    sign_payload,
    verify_and_consume_receipt,
    verify_receipt,
)

NOW = datetime(2026, 9, 5, 12, 0, tzinfo=UTC)
SOURCE_SHA = "1" * 40
CONTROLLER_SHA = "2" * 40


def _payload() -> dict[str, object]:
    return {
        "repository": {"id": 1_357_887_516, "full_name": "belilovsky/qazcoop"},
        "protected_ref": "refs/heads/codex/qazcoop-mvp",
        "functional_source_sha": SOURCE_SHA,
        "workflow": {"run_id": 33_949_265_063, "run_attempt": 2},
        "required_jobs": [
            {
                "name": "reuse-first",
                "controller_profile": "qdev-ci",
                "job_id": 101,
                "conclusion": "success",
            },
            {
                "name": "postgres-migrations",
                "controller_profile": "qdev-ci-docker",
                "job_id": 102,
                "conclusion": "success",
            },
        ],
        "controller_revision": CONTROLLER_SHA,
        "admission": {"id": "admission-20260905", "claim_id": "claim-20260905"},
        "issued_at": "2026-09-05T11:55:00Z",
        "expires_at": "2026-09-05T13:00:00Z",
    }


def _keys(tmp_path: Path) -> tuple[Path, Path]:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    initialize_keypair(private, public)
    return private, public


def test_canonical_payload_has_stable_golden_bytes() -> None:
    assert canonical_payload({"z": "Қ", "a": [2, {"b": True}]}) == (
        '{"a":[2,{"b":true}],"z":"Қ"}'.encode()
    )


def test_sign_and_verify_exact_admission(tmp_path: Path) -> None:
    private, public = _keys(tmp_path)
    receipt = sign_payload(_payload(), private)

    verified = verify_receipt(
        receipt,
        public,
        now=NOW,
        expected_repository_id=1_357_887_516,
        expected_repository="belilovsky/qazcoop",
        expected_ref="refs/heads/codex/qazcoop-mvp",
        expected_sha=SOURCE_SHA,
        expected_controller_revision=CONTROLLER_SHA,
        expected_jobs={"reuse-first": "qdev-ci", "postgres-migrations": "qdev-ci-docker"},
    )

    assert verified["functional_source_sha"] == SOURCE_SHA
    assert receipt["signature"]["algorithm"] == "Ed25519"


@pytest.mark.parametrize(
    ("field", "expected"),
    [
        ("expected_repository_id", 7),
        ("expected_repository", "belilovsky/other"),
        ("expected_ref", "refs/heads/main"),
        ("expected_sha", "f" * 40),
        ("expected_controller_revision", "e" * 40),
    ],
)
def test_verify_rejects_wrong_exact_binding(tmp_path: Path, field: str, expected: object) -> None:
    private, public = _keys(tmp_path)
    receipt = sign_payload(_payload(), private)

    with pytest.raises(ControllerAdmissionError, match="does not match expected value"):
        verify_receipt(
            receipt,
            public,
            now=NOW,
            **cast(Any, {field: expected}),
        )


def test_verify_rejects_tampered_payload_and_signature(tmp_path: Path) -> None:
    private, public = _keys(tmp_path)
    receipt = sign_payload(_payload(), private)
    tampered = copy.deepcopy(receipt)
    tampered["payload"]["functional_source_sha"] = "f" * 40
    with pytest.raises(ControllerAdmissionError, match="payload digest does not match"):
        verify_receipt(tampered, public, now=NOW)

    tampered = copy.deepcopy(receipt)
    tampered["signature"]["value"] = "A" * 86
    with pytest.raises(ControllerAdmissionError, match="signature verification failed"):
        verify_receipt(tampered, public, now=NOW)


def test_verify_rejects_unknown_key(tmp_path: Path) -> None:
    private, _public = _keys(tmp_path)
    receipt = sign_payload(_payload(), private)
    other_private = Ed25519PrivateKey.generate()
    other_public = tmp_path / "other-public.pem"
    other_public.write_bytes(
        other_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    with pytest.raises(ControllerAdmissionError, match="unknown admission key"):
        verify_receipt(receipt, other_public, now=NOW)


@pytest.mark.parametrize(
    ("issued_at", "expires_at", "message"),
    [
        ("2026-09-05T12:02:00Z", "2026-09-05T13:00:00Z", "not yet valid"),
        ("2026-09-05T10:00:00Z", "2026-09-05T12:00:00Z", "expired"),
    ],
)
def test_verify_rejects_invalid_observation_time(
    tmp_path: Path, issued_at: str, expires_at: str, message: str
) -> None:
    private, public = _keys(tmp_path)
    payload = _payload()
    payload["issued_at"] = issued_at
    payload["expires_at"] = expires_at
    receipt = sign_payload(payload, private)
    with pytest.raises(ControllerAdmissionError, match=message):
        verify_receipt(receipt, public, now=NOW)


def test_sign_rejects_failed_or_duplicate_jobs(tmp_path: Path) -> None:
    private, _public = _keys(tmp_path)
    payload = _payload()
    jobs = payload["required_jobs"]
    assert isinstance(jobs, list)
    jobs[0]["conclusion"] = "failure"
    with pytest.raises(ControllerAdmissionError, match="conclusion success"):
        sign_payload(payload, private)

    payload = _payload()
    jobs = payload["required_jobs"]
    assert isinstance(jobs, list)
    jobs.append(copy.deepcopy(jobs[0]))
    with pytest.raises(ControllerAdmissionError, match="duplicate job"):
        sign_payload(payload, private)


def test_sign_rejects_excessive_or_invalid_validity(tmp_path: Path) -> None:
    private, _public = _keys(tmp_path)
    payload = _payload()
    payload["expires_at"] = "2026-09-06T12:00:01Z"
    with pytest.raises(ControllerAdmissionError, match="exceeds 24 hours"):
        sign_payload(payload, private)

    payload["expires_at"] = payload["issued_at"]
    with pytest.raises(ControllerAdmissionError, match="must be after"):
        sign_payload(payload, private)


def test_private_key_permissions_fail_closed(tmp_path: Path) -> None:
    private, _public = _keys(tmp_path)
    private.chmod(0o644)
    with pytest.raises(ControllerAdmissionError, match="owner-only"):
        sign_payload(_payload(), private)


def test_load_json_rejects_duplicate_keys_and_constants(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"a":1,"a":2}', encoding="utf-8")
    with pytest.raises(ControllerAdmissionError, match="duplicate key"):
        load_json_strict(duplicate)

    constant = tmp_path / "constant.json"
    constant.write_text('{"a":NaN}', encoding="utf-8")
    with pytest.raises(ControllerAdmissionError, match="constant is not permitted"):
        load_json_strict(constant)


def test_cli_sign_and_verify(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    private, public = _keys(tmp_path)
    payload = tmp_path / "payload.json"
    receipt = tmp_path / "receipt.json"
    current = datetime.now(UTC).replace(microsecond=0)
    current_payload = _payload()
    current_payload["issued_at"] = (current - timedelta(minutes=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    current_payload["expires_at"] = (current + timedelta(minutes=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    payload.write_text(json.dumps(current_payload), encoding="utf-8")

    assert (
        main(
            [
                "sign",
                "--payload",
                str(payload),
                "--private-key",
                str(private),
                "--output",
                str(receipt),
            ]
        )
        == 0
    )
    assert main(
        [
            "verify",
            "--receipt",
            str(receipt),
            "--public-key",
            str(public),
            "--repository-id",
            "1357887516",
            "--repository",
            "belilovsky/qazcoop",
            "--protected-ref",
            "refs/heads/codex/qazcoop-mvp",
            "--functional-source-sha",
            SOURCE_SHA,
            "--controller-revision",
            CONTROLLER_SHA,
            "--require-job",
            "reuse-first=qdev-ci",
            "--require-job",
            "postgres-migrations=qdev-ci-docker",
        ]
    ) == 0
    output = capsys.readouterr()
    assert "controller admission rejected" not in output.err
    assert '"state":"verified"' in output.out


def test_receipt_expires_at_boundary(tmp_path: Path) -> None:
    private, public = _keys(tmp_path)
    receipt = sign_payload(_payload(), private)
    with pytest.raises(ControllerAdmissionError, match="expired"):
        verify_receipt(receipt, public, now=NOW + timedelta(hours=1))


def test_consume_receipt_rejects_replay(tmp_path: Path) -> None:
    private, public = _keys(tmp_path)
    receipt = sign_payload(_payload(), private)
    replay_store = tmp_path / "state" / "consumed.sqlite3"

    verify_and_consume_receipt(
        receipt,
        public,
        replay_store,
        consumer="qazcoop-release-1",
        now=NOW,
    )
    assert replay_store.stat().st_mode & 0o777 == 0o600
    with pytest.raises(ControllerAdmissionError, match="already been consumed"):
        verify_and_consume_receipt(
            receipt,
            public,
            replay_store,
            consumer="qazcoop-release-2",
            now=NOW,
        )


def test_cli_requires_complete_consumption_arguments(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private, public = _keys(tmp_path)
    payload = _payload()
    payload["issued_at"] = (datetime.now(UTC) - timedelta(minutes=1)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    payload["expires_at"] = (datetime.now(UTC) + timedelta(minutes=10)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(canonical_payload(sign_payload(payload, private)) + b"\n")

    assert (
        main(
            [
                "verify",
                "--receipt",
                str(receipt_path),
                "--public-key",
                str(public),
                "--consume-ledger",
                str(tmp_path / "ledger.sqlite3"),
            ]
        )
        == 1
    )
    assert "must be provided together" in capsys.readouterr().err
