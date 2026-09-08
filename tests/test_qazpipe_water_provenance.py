from __future__ import annotations

import copy
import json
import os
import sqlite3
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from qdev_runner.qazpipe_water_provenance import (
    SCHEMA,
    QazPipeWaterProvenanceError,
    canonical_payload,
    envelope_digest,
    initialize_keypair,
    load_json_strict,
    main,
    sign_payload,
    verify_and_consume_receipt,
    verify_receipt,
)

NOW = datetime(2026, 9, 8, 12, 0, tzinfo=UTC)
SOURCE_SHA = "1" * 40
CONTROLLER_SHA = "2" * 40
ARTIFACT_SHA256 = "sha256:" + "3" * 64
QUERY_PLAN_SHA256 = "sha256:" + "4" * 64
MANIFEST_SHA256 = "sha256:" + "5" * 64
RECORDS_SHA256 = "sha256:" + "6" * 64


def _payload() -> dict[str, object]:
    return {
        "repository": {"id": 1_202_131_289, "full_name": "belilovsky/qazpipe"},
        "protected_ref": "refs/heads/main",
        "source_sha": SOURCE_SHA,
        "collector": {"id": "geo-003"},
        "workflow": {
            "name": "CI",
            "run_id": 33_949_265_063,
            "run_attempt": 2,
            "job_id": 725_144_011,
            "profile": "qazpipe.geo-003.v1",
        },
        "artifact": {
            "uri": "qazpipe://artifacts/water/2026-09-08/manifest.json",
            "sha256": ARTIFACT_SHA256,
            "size_bytes": 4096,
        },
        "result": {
            "water_run_id": "water-20260908-001",
            "state": "complete",
            "query_plan_sha256": QUERY_PLAN_SHA256,
            "expected_query_count": 18,
            "completed_query_count": 18,
            "manifest_sha256": MANIFEST_SHA256,
            "records_sha256": RECORDS_SHA256,
            "record_count": 413,
            "source_observed_at": "2026-09-08T11:20:00Z",
            "started_at": "2026-09-08T11:25:00Z",
            "completed_at": "2026-09-08T11:30:00Z",
        },
        "controller_revision": CONTROLLER_SHA,
        "receipt": {"id": "water-receipt-20260908", "claim_id": "water-claim-20260908"},
        "issued_at": "2026-09-08T11:35:00Z",
        "expires_at": "2026-09-08T12:35:00Z",
    }


def _keys(tmp_path: Path) -> tuple[Path, Path, str]:
    private = tmp_path / "private.pem"
    public = tmp_path / "public.pem"
    key_id = initialize_keypair(private, public)
    return private, public, key_id


def _verify_args(receipt_path: Path, public: Path, key_id: str, receipt_digest: str) -> list[str]:
    return [
        "--receipt",
        str(receipt_path),
        "--trusted-key-pem",
        str(public),
        "--trusted-key-id",
        key_id,
        "--repository-id",
        "1202131289",
        "--repository-full-name",
        "belilovsky/qazpipe",
        "--protected-ref",
        "refs/heads/main",
        "--source-sha",
        SOURCE_SHA,
        "--collector-id",
        "geo-003",
        "--workflow-name",
        "CI",
        "--workflow-run-id",
        "33949265063",
        "--workflow-run-attempt",
        "2",
        "--workflow-job-id",
        "725144011",
        "--workflow-profile",
        "qazpipe.geo-003.v1",
        "--artifact-uri",
        "qazpipe://artifacts/water/2026-09-08/manifest.json",
        "--artifact-sha256",
        ARTIFACT_SHA256,
        "--artifact-size-bytes",
        "4096",
        "--water-run-id",
        "water-20260908-001",
        "--water-state",
        "complete",
        "--query-plan-sha256",
        QUERY_PLAN_SHA256,
        "--expected-query-count",
        "18",
        "--completed-query-count",
        "18",
        "--manifest-sha256",
        MANIFEST_SHA256,
        "--records-sha256",
        RECORDS_SHA256,
        "--record-count",
        "413",
        "--source-observed-at",
        "2026-09-08T11:20:00Z",
        "--started-at",
        "2026-09-08T11:25:00Z",
        "--completed-at",
        "2026-09-08T11:30:00Z",
        "--controller-revision",
        CONTROLLER_SHA,
        "--receipt-id",
        "water-receipt-20260908",
        "--claim-id",
        "water-claim-20260908",
        "--issued-at",
        "2026-09-08T11:35:00Z",
        "--expires-at",
        "2026-09-08T12:35:00Z",
        "--expected-receipt-sha256",
        receipt_digest,
    ]


def test_sign_and_verify_full_exact_water_provenance(tmp_path: Path) -> None:
    private, public, key_id = _keys(tmp_path)
    payload = _payload()
    receipt = sign_payload(payload, private)

    verified = verify_receipt(
        receipt,
        public,
        trusted_key_id=key_id,
        now=NOW,
        expected_payload=payload,
        expected_receipt_sha256=envelope_digest(receipt),
    )

    assert receipt["schema"] == SCHEMA
    assert set(receipt) == {"schema", "payload", "signature"}
    assert set(receipt["signature"]) == {"algorithm", "key_id", "payload_sha256", "value"}
    assert verified["artifact"]["sha256"] == ARTIFACT_SHA256
    assert verified["result"]["records_sha256"] == RECORDS_SHA256


def test_canonical_json_and_envelope_digest_are_stable() -> None:
    assert canonical_payload({"z": "Қ", "a": [2, {"b": True}]}) == (
        '{"a":[2,{"b":true}],"z":"Қ"}'.encode()
    )
    assert envelope_digest({"z": 1, "a": 2}) == envelope_digest({"a": 2, "z": 1})


@pytest.mark.parametrize(
    ("path", "value", "message"),
    [
        (("collector", "id"), "geo-002", "must be geo-003"),
        (("result", "state"), "partial", "must be complete"),
        (("result", "completed_query_count"), 17, "must equal"),
        (("result", "started_at"), "2026-09-08T11:31:00Z", "must not be after"),
        (("issued_at",), "2026-09-08T11:29:00Z", "must not be before"),
    ],
)
def test_sign_rejects_incomplete_or_non_causal_payload(
    tmp_path: Path, path: tuple[str, ...], value: object, message: str
) -> None:
    private, _public, _key_id = _keys(tmp_path)
    payload: dict[str, object] = _payload()
    target: dict[str, object] = payload
    for key in path[:-1]:
        nested = target[key]
        assert isinstance(nested, dict)
        target = nested
    target[path[-1]] = value

    with pytest.raises(QazPipeWaterProvenanceError, match=message):
        sign_payload(payload, private)


def test_verify_rejects_tamper_key_id_and_exact_bindings(tmp_path: Path) -> None:
    private, public, key_id = _keys(tmp_path)
    receipt = sign_payload(_payload(), private)

    tampered = copy.deepcopy(receipt)
    tampered["payload"]["artifact"]["sha256"] = "sha256:" + "f" * 64
    with pytest.raises(QazPipeWaterProvenanceError, match="payload digest"):
        verify_receipt(tampered, public, trusted_key_id=key_id, now=NOW)

    expected_artifact = _payload()
    expected_artifact["artifact"]["sha256"] = "sha256:" + "f" * 64
    with pytest.raises(QazPipeWaterProvenanceError, match="artifact.sha256"):
        verify_receipt(
            receipt,
            public,
            trusted_key_id=key_id,
            now=NOW,
            expected_payload=expected_artifact,
            expected_receipt_sha256=envelope_digest(receipt),
        )

    expected = _payload()
    expected["result"]["records_sha256"] = "sha256:" + "f" * 64
    with pytest.raises(QazPipeWaterProvenanceError, match="records_sha256"):
        verify_receipt(
            receipt,
            public,
            trusted_key_id=key_id,
            now=NOW,
            expected_payload=expected,
            expected_receipt_sha256=envelope_digest(receipt),
        )
    expected_profile = _payload()
    expected_profile["workflow"]["profile"] = "qazpipe.geo-003.v2"
    with pytest.raises(QazPipeWaterProvenanceError, match="workflow.profile"):
        verify_receipt(
            receipt,
            public,
            trusted_key_id=key_id,
            now=NOW,
            expected_payload=expected_profile,
            expected_receipt_sha256=envelope_digest(receipt),
        )
    with pytest.raises(QazPipeWaterProvenanceError, match="envelope digest"):
        verify_receipt(
            receipt,
            public,
            trusted_key_id=key_id,
            now=NOW,
            expected_payload=_payload(),
            expected_receipt_sha256="sha256:" + "f" * 64,
        )
    with pytest.raises(QazPipeWaterProvenanceError, match="does not match trusted PEM"):
        verify_receipt(receipt, public, trusted_key_id="sha256:" + "f" * 64, now=NOW)


def test_verify_rejects_unknown_ed25519_key_and_unsafe_pem(tmp_path: Path) -> None:
    private, _public, _key_id = _keys(tmp_path)
    receipt = sign_payload(_payload(), private)
    other_private = Ed25519PrivateKey.generate()
    other_public = tmp_path / "other-public.pem"
    other_public.write_bytes(
        other_private.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    other_key_id = "sha256:" + "0" * 64
    with pytest.raises(QazPipeWaterProvenanceError, match="does not match trusted PEM"):
        verify_receipt(receipt, other_public, trusted_key_id=other_key_id, now=NOW)

    _private, public, public_key_id = _keys(tmp_path / "unsafe")
    safe_receipt = sign_payload(_payload(), _private)
    public.chmod(0o666)
    with pytest.raises(QazPipeWaterProvenanceError, match="group/world writable"):
        verify_receipt(safe_receipt, public, trusted_key_id=public_key_id, now=NOW)


def test_strict_json_rejects_duplicate_keys_and_constants(tmp_path: Path) -> None:
    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"a":1,"a":2}', encoding="utf-8")
    with pytest.raises(QazPipeWaterProvenanceError, match="duplicate key"):
        load_json_strict(duplicate)
    constant = tmp_path / "constant.json"
    constant.write_text('{"a":NaN}', encoding="utf-8")
    with pytest.raises(QazPipeWaterProvenanceError, match="constant is not permitted"):
        load_json_strict(constant)


def test_consumption_rejects_replay_and_key_rotation(tmp_path: Path) -> None:
    first_private, first_public, first_key_id = _keys(tmp_path / "first")
    second_private, second_public, second_key_id = _keys(tmp_path / "second")
    payload = _payload()
    first_receipt = sign_payload(payload, first_private)
    second_receipt = sign_payload(payload, second_private)
    ledger = tmp_path / "ledger" / "consumed.sqlite3"

    verify_and_consume_receipt(
        first_receipt,
        first_public,
        ledger,
        consumer="qazlake-water-publication",
        trusted_key_id=first_key_id,
        now=NOW,
        expected_payload=payload,
        expected_receipt_sha256=envelope_digest(first_receipt),
    )
    with pytest.raises(QazPipeWaterProvenanceError, match="already been consumed"):
        verify_and_consume_receipt(
            first_receipt,
            first_public,
            ledger,
            consumer="qazlake-water-publication",
            trusted_key_id=first_key_id,
            now=NOW,
            expected_payload=payload,
            expected_receipt_sha256=envelope_digest(first_receipt),
        )
    with pytest.raises(QazPipeWaterProvenanceError, match="already been consumed"):
        verify_and_consume_receipt(
            second_receipt,
            second_public,
            ledger,
            consumer="qazlake-water-publication-rotated",
            trusted_key_id=second_key_id,
            now=NOW,
            expected_payload=payload,
            expected_receipt_sha256=envelope_digest(second_receipt),
        )
    assert ledger.stat().st_mode & 0o777 == 0o600


def test_consumption_requires_exact_payload_digest_and_safe_ledger(tmp_path: Path) -> None:
    private, public, key_id = _keys(tmp_path)
    receipt = sign_payload(_payload(), private)
    with pytest.raises(QazPipeWaterProvenanceError, match="requires an exact payload"):
        verify_and_consume_receipt(
            receipt,
            public,
            tmp_path / "ledger.sqlite3",
            consumer="qazlake-water-publication",
            trusted_key_id=key_id,
            now=NOW,
        )

    insecure = tmp_path / "insecure" / "ledger.sqlite3"
    insecure.parent.mkdir()
    insecure.touch(mode=0o600)
    insecure.chmod(0o666)
    with pytest.raises(QazPipeWaterProvenanceError, match="owner-controlled file"):
        verify_and_consume_receipt(
            receipt,
            public,
            insecure,
            consumer="qazlake-water-publication",
            trusted_key_id=key_id,
            now=NOW,
            expected_payload=_payload(),
            expected_receipt_sha256=envelope_digest(receipt),
        )


def test_consumption_rejects_substituted_replay_schema(tmp_path: Path) -> None:
    private, public, key_id = _keys(tmp_path)
    receipt = sign_payload(_payload(), private)
    ledger = tmp_path / "ledger" / "consumed.sqlite3"
    ledger.parent.mkdir()
    with sqlite3.connect(ledger) as connection:
        connection.execute("CREATE TABLE consumed_qazpipe_water_provenance (bad TEXT)")
    os.chmod(ledger, 0o600)
    with pytest.raises(QazPipeWaterProvenanceError, match="schema is invalid"):
        verify_and_consume_receipt(
            receipt,
            public,
            ledger,
            consumer="qazlake-water-publication",
            trusted_key_id=key_id,
            now=NOW,
            expected_payload=_payload(),
            expected_receipt_sha256=envelope_digest(receipt),
        )


def test_cli_verifier_is_read_only_then_consumes_once(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    private, public, key_id = _keys(tmp_path)
    payload = _payload()
    current = datetime.now(UTC).replace(microsecond=0)
    payload["result"] = {
        **payload["result"],
        "source_observed_at": (current - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "started_at": (current - timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completed_at": (current - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    payload["issued_at"] = (current - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload["expires_at"] = (current + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload_path = tmp_path / "payload.json"
    receipt_path = tmp_path / "receipt.json"
    payload_path.write_text(json.dumps(payload), encoding="utf-8")
    sign_args = [
        "sign",
        "--payload",
        str(payload_path),
        "--private-key",
        str(private),
        "--output",
        str(receipt_path),
    ]
    assert main(sign_args) == 0
    capsys.readouterr()
    receipt = load_json_strict(receipt_path)
    assert isinstance(receipt, dict)
    args = _verify_args(receipt_path, public, key_id, envelope_digest(receipt))
    result = payload["result"]
    assert isinstance(result, dict)
    args[args.index("--source-observed-at") + 1] = str(result["source_observed_at"])
    args[args.index("--started-at") + 1] = str(result["started_at"])
    args[args.index("--completed-at") + 1] = str(result["completed_at"])
    args[args.index("--issued-at") + 1] = str(payload["issued_at"])
    args[args.index("--expires-at") + 1] = str(payload["expires_at"])

    assert main(["verify", *args]) == 0
    verified = json.loads(capsys.readouterr().out)
    assert verified["state"] == "verified"
    assert verified["receipt_sha256"] == envelope_digest(receipt)

    ledger = tmp_path / "ledger.sqlite3"
    consume_args = [
        "verify",
        *args,
        "--consume-ledger",
        str(ledger),
        "--consumer",
        "qazlake-water-publication",
    ]
    assert main(consume_args) == 0
    assert json.loads(capsys.readouterr().out)["state"] == "consumed"
    assert main(consume_args) == 1
    assert "already been consumed" in capsys.readouterr().err


def test_standalone_verifier_emits_the_qazlake_stdout_contract(tmp_path: Path) -> None:
    private, public, key_id = _keys(tmp_path)
    payload = _payload()
    current = datetime.now(UTC).replace(microsecond=0)
    payload["result"] = {
        **payload["result"],
        "source_observed_at": (current - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "started_at": (current - timedelta(minutes=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "completed_at": (current - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    payload["issued_at"] = (current - timedelta(minutes=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
    payload["expires_at"] = (current + timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
    receipt = sign_payload(payload, private)
    receipt_path = tmp_path / "receipt.json"
    receipt_path.write_bytes(canonical_payload(receipt))
    args = _verify_args(receipt_path, public, key_id, envelope_digest(receipt))
    result = payload["result"]
    assert isinstance(result, dict)
    args[args.index("--source-observed-at") + 1] = str(result["source_observed_at"])
    args[args.index("--started-at") + 1] = str(result["started_at"])
    args[args.index("--completed-at") + 1] = str(result["completed_at"])
    args[args.index("--issued-at") + 1] = str(payload["issued_at"])
    args[args.index("--expires-at") + 1] = str(payload["expires_at"])
    wrapper = Path(__file__).parents[1] / "scripts/verify_qazpipe_water_provenance.py"
    completed = subprocess.run(  # noqa: S603 -- fixed local test wrapper and generated fixture paths
        [sys.executable, str(wrapper), *args],
        check=False,
        capture_output=True,
        text=True,
    )
    assert completed.returncode == 0, completed.stderr
    assert json.loads(completed.stdout) == {
        "artifact_sha256": ARTIFACT_SHA256,
        "claim_id": "water-claim-20260908",
        "receipt_id": "water-receipt-20260908",
        "receipt_sha256": envelope_digest(receipt),
        "records_sha256": RECORDS_SHA256,
        "state": "verified",
        "water_run_id": "water-20260908-001",
    }


def test_schema_is_dedicated_and_matches_fixed_payload_shape() -> None:
    schema_path = (
        Path(__file__).parents[1] / "docs/schemas/qdev-qazpipe-water-provenance-v1.schema.json"
    )
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    assert schema["$id"].endswith("qdev-qazpipe-water-provenance-v1.schema.json")
    assert schema["properties"]["schema"]["const"] == SCHEMA
    assert set(schema["$defs"]["payload"]["required"]) == set(_payload())
