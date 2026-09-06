import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from qdev_runner.admin_platform import (
    ORDER_V3,
    AdminPlatformCandidate,
    AdminPlatformLedger,
    AdminPlatformLedgerError,
)
from qdev_runner.operations import OperationStore

RECEIPT_KEY = "admin-platform-test-receipt-key"


def _write_receipt(root: Path, filename: str, payload: dict[str, object]) -> tuple[str, str]:
    receipt_dir = root / "receipts"
    receipt_dir.mkdir(exist_ok=True)
    store = OperationStore(
        root / "operation-store",
        worker_signing_key="unused-worker-key",
        receipt_signing_key=RECEIPT_KEY,
    )
    raw = (
        json.dumps(store.receipt(payload), sort_keys=True, separators=(",", ":")) + "\n"
    ).encode()
    (receipt_dir / filename).write_bytes(raw)
    return f"receipts/{filename}", hashlib.sha256(raw).hexdigest()


def _evidence_payload(
    *,
    stage: str,
    release_id: str,
    source_sha: str,
    observed_at: str,
    evidence_type: str,
    lane: str | None,
    outcome: str,
) -> dict[str, object]:
    return {
        "kind": "admin-platform-evidence",
        "observed_at": observed_at,
        "program_id": "qdev-admin-platform-wave-1",
        "stage": stage,
        "release_id": release_id,
        "source_sha": source_sha,
        "evidence_type": evidence_type,
        "lane": lane,
        "outcome": outcome,
    }


def _ledger_path() -> Path:
    return Path(__file__).parents[1] / "config" / "admin-platform-ledger.yml"


def _ledger_v3_path() -> Path:
    return Path(__file__).parents[1] / "config" / "admin-platform-ledger-v2.yml"


def test_canonical_ledger_rejects_legacy_admission_state() -> None:
    with pytest.raises(AdminPlatformLedgerError, match="must use schema v3"):
        AdminPlatformLedger(_ledger_path())


def test_v3_ledger_rejects_a_nonterminal_predecessor(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["program"]["updated_at"] = "2026-09-05T01:00:00Z"
    document["active_stage"] = "avds-admin-shell"
    document["active_candidate"] = {
        "release_id": "avds-candidate-1",
        "repository": "belilovsky/av-platform-core",
        "source_sha": "a" * 40,
        "reference": "refs/heads/codex/avds-candidate-1",
    }
    entry = document["entries"]["avds-admin-shell"]
    entry.update(
        {
            "source_sha": "a" * 40,
            "reference": "refs/heads/codex/avds-candidate-1",
            "status": "candidate",
            "attempts": [
                {
                    "release_id": "avds-candidate-1",
                    "source_sha": "a" * 40,
                    "reference": "refs/heads/codex/avds-candidate-1",
                    "started_at": "2026-09-05T01:00:00Z",
                    "finished_at": None,
                    "terminal_state": None,
                    "receipt_uri": None,
                    "receipt_sha256": None,
                }
            ],
            "results": [],
        }
    )
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(AdminPlatformLedgerError, match="prior stage"):
        AdminPlatformLedger(path)


def test_v3_ledger_does_not_admit_an_unsigned_pending_source_tuple() -> None:
    ledger = AdminPlatformLedger(_ledger_v3_path())

    assert ledger.classify_admission("controller", "21b23e25ed45a547ad460e4bc412a4949a909c3f") == (
        False,
        "admin-platform-candidate-tuple-not-admitted",
    )
    assert ledger.classify_admission("qazposter", "9ebf6718c2085d1a58f59323f37b1e1dd707225f") == (
        False,
        "admin-platform-candidate-not-active",
    )
    assert ledger.classify_admission("controller", "a" * 40) == (
        False,
        "admin-platform-candidate-tuple-not-admitted",
    )
    with pytest.raises(AdminPlatformLedgerError, match="tuple"):
        ledger.validate_admission("controller", "21b23e25ed45a547ad460e4bc412a4949a909c3f")
    with pytest.raises(AdminPlatformLedgerError, match="not active"):
        ledger.validate_admission("ortcom", "a" * 40)
    with pytest.raises(AdminPlatformLedgerError, match="tuple"):
        ledger.validate_admission("controller", "a" * 40)


def test_v3_ledger_admits_only_a_receipt_bound_active_source_tuple(
    tmp_path: Path,
) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["program"]["updated_at"] = "2026-09-05T00:01:00Z"
    controller = document["entries"]["controller"]
    uri, checksum = _write_receipt(
        tmp_path,
        "controller-source.json",
        _evidence_payload(
            stage="controller",
            release_id=controller["attempts"][0]["release_id"],
            source_sha=controller["source_sha"],
            observed_at="2026-09-05T00:01:00Z",
            evidence_type="lane_result",
            lane="source",
            outcome="passed",
        ),
    )
    controller["results"][0].update(
        {
            "outcome": "passed",
            "recorded_at": "2026-09-05T00:01:00Z",
            "receipt_uri": uri,
            "receipt_sha256": checksum,
        }
    )
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    ledger = AdminPlatformLedger(
        path,
        receipt_key=RECEIPT_KEY,
        receipt_root=tmp_path / "receipts",
    )

    assert ledger.classify_admission("controller", controller["source_sha"]) == (
        True,
        None,
    )
    assert (
        ledger.validate_admission("controller", controller["source_sha"]).project_id
        == "qdev-runner-control-plane"
    )


def test_v3_uses_the_frozen_order_and_exact_active_candidate() -> None:
    ledger = AdminPlatformLedger(_ledger_v3_path())

    assert ledger.schema_version == "qdev-admin-platform-ledger-v3"
    assert ledger.active_stage == "controller"
    assert tuple(entry.entry_id for entry in ledger.entries) == ORDER_V3
    assert ledger.active_candidate == AdminPlatformCandidate(
        release_id="controller-v3-21b23e25",
        repository="belilovsky/qdev-runner-control-plane",
        source_sha="21b23e25ed45a547ad460e4bc412a4949a909c3f",
        reference="refs/heads/codex/admin-platform-controller-v3-20260905",
    )


def test_v3_snapshot_is_json_serializable_when_yaml_resolves_timestamps() -> None:
    ledger = AdminPlatformLedger(_ledger_v3_path())

    encoded = json.dumps(ledger.snapshot(), sort_keys=True)

    assert "2026-09-05T00:00:00Z" in encoded


def test_v3_active_candidate_can_be_null_only_when_program_is_complete(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["active_candidate"] = None
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(AdminPlatformLedgerError, match="only when the program is complete"):
        AdminPlatformLedger(path)


def test_v3_rolled_back_stage_cannot_be_used_as_an_advanced_prerequisite(
    tmp_path: Path,
) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["program"]["updated_at"] = "2026-09-05T01:00:00Z"
    controller = document["entries"]["controller"]
    controller["status"] = "rolled_back"
    controller["attempts"][-1]["terminal_state"] = "rolled_back"
    controller["attempts"][-1]["finished_at"] = "2026-09-05T00:30:00Z"
    controller["attempts"][-1]["receipt_uri"] = "receipts/controller-rollback.json"
    controller["attempts"][-1]["receipt_sha256"] = "0" * 64
    controller["results"] = [
        {
            "release_id": "controller-v3-21b23e25",
            "lane": lane,
            "outcome": "passed",
            "recorded_at": f"2026-09-05T00:{minute:02d}:00Z",
            "receipt_uri": f"receipts/controller-{lane}.json",
            "receipt_sha256": "0" * 64,
        }
        for minute, lane in enumerate(
            ("source", "ci", "publication", "deploy", "rollback"), start=1
        )
    ]
    avds = document["entries"]["avds-admin-shell"]
    avds["source_sha"] = "a" * 40
    avds["reference"] = "refs/heads/codex/avds-admin-shell"
    avds["status"] = "candidate"
    avds["attempts"] = [
        {
            "release_id": "avds-candidate-1",
            "source_sha": "a" * 40,
            "reference": "refs/heads/codex/avds-admin-shell",
            "started_at": "2026-09-05T01:00:00Z",
            "finished_at": None,
            "terminal_state": None,
            "receipt_uri": None,
            "receipt_sha256": None,
        }
    ]
    avds["results"] = [
        {
            "release_id": "avds-candidate-1",
            "lane": "source",
            "outcome": "pending",
            "recorded_at": "2026-09-05T01:00:00Z",
            "receipt_uri": None,
            "receipt_sha256": None,
        }
    ]
    document["active_stage"] = "avds-admin-shell"
    document["active_candidate"] = {
        "release_id": "avds-candidate-1",
        "repository": "belilovsky/av-platform-core",
        "source_sha": "a" * 40,
        "reference": "refs/heads/codex/avds-admin-shell",
    }
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(AdminPlatformLedgerError, match="rolled_back cannot advance"):
        AdminPlatformLedger(path)


def test_v3_rejects_prerequisite_and_result_reference_drift(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["entries"]["qaz-admin-kit"]["prerequisites"] = ["controller"]
    path = tmp_path / "bad-prerequisite.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with pytest.raises(AdminPlatformLedgerError, match="prerequisites"):
        AdminPlatformLedger(path)

    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["entries"]["controller"]["results"][0]["release_id"] = "unknown-release"
    path = tmp_path / "bad-result-reference.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with pytest.raises(AdminPlatformLedgerError, match="unknown attempt"):
        AdminPlatformLedger(path)


def test_v3_keeps_release_evidence_in_distinct_lanes(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    controller = document["entries"]["controller"]
    controller["results"] = [
        {
            "release_id": "controller-v3-21b23e25",
            "lane": lane,
            "outcome": "pending",
            "recorded_at": "2026-09-05T00:00:00Z",
            "receipt_uri": None,
            "receipt_sha256": None,
        }
        for lane in (
            "source",
            "ci",
            "publication",
            "deploy",
            "browser",
            "rollback",
            "observation",
        )
    ]
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    AdminPlatformLedger(path)

    controller["results"].append(dict(controller["results"][0]))
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with pytest.raises(AdminPlatformLedgerError, match="transition pending -> pending is invalid"):
        AdminPlatformLedger(path)


def test_v3_terminal_attempt_and_live_acceptance_require_immutable_receipts(
    tmp_path: Path,
) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["program"]["updated_at"] = "2026-09-05T02:01:00Z"
    controller = document["entries"]["controller"]
    controller["status"] = "live_accepted"
    controller["attempts"][-1].update(
        {
            "finished_at": "2026-09-05T01:00:00Z",
            "terminal_state": "live_accepted",
            "receipt_uri": "receipts/controller-terminal.json",
            "receipt_sha256": "0" * 64,
        }
    )
    controller["results"] = [
        {
            "release_id": "controller-v3-21b23e25",
            "lane": lane,
            "outcome": ("not_applicable" if lane in {"browser", "observation"} else "passed"),
            "recorded_at": "2026-09-05T01:00:00Z",
            "receipt_uri": f"receipts/controller-{lane}.json",
            "receipt_sha256": "0" * 64,
        }
        for lane in (
            "source",
            "ci",
            "publication",
            "deploy",
            "browser",
            "rollback",
            "observation",
        )
    ]
    document["program"]["status"] = "blocked"
    document["active_stage"] = "avds-admin-shell"
    avds = document["entries"]["avds-admin-shell"]
    avds.update(
        {
            "source_sha": "a" * 40,
            "reference": "refs/heads/codex/avds-admin-shell",
            "status": "blocked",
            "attempts": [
                {
                    "release_id": "avds-blocked-1",
                    "source_sha": "a" * 40,
                    "reference": "refs/heads/codex/avds-admin-shell",
                    "started_at": "2026-09-05T02:00:00Z",
                    "finished_at": "2026-09-05T02:01:00Z",
                    "terminal_state": "blocked",
                    "receipt_uri": "receipts/avds-blocked.json",
                    "receipt_sha256": "0" * 64,
                }
            ],
            "results": [
                {
                    "release_id": "avds-blocked-1",
                    "lane": "source",
                    "outcome": "passed",
                    "recorded_at": "2026-09-05T02:00:00Z",
                    "receipt_uri": "receipts/avds-source.json",
                    "receipt_sha256": "0" * 64,
                },
                {
                    "release_id": "avds-blocked-1",
                    "lane": "ci",
                    "outcome": "blocked",
                    "recorded_at": "2026-09-05T02:01:00Z",
                    "receipt_uri": "receipts/avds-ci-blocked.json",
                    "receipt_sha256": "0" * 64,
                },
            ],
        }
    )
    document["active_candidate"] = {
        "release_id": "avds-blocked-1",
        "repository": "belilovsky/av-platform-core",
        "source_sha": "a" * 40,
        "reference": "refs/heads/codex/avds-admin-shell",
    }
    path = tmp_path / "ledger.yml"

    controller_terminal = _write_receipt(
        tmp_path,
        "controller-terminal.json",
        _evidence_payload(
            stage="controller",
            release_id="controller-v3-21b23e25",
            source_sha="21b23e25ed45a547ad460e4bc412a4949a909c3f",
            observed_at="2026-09-05T01:00:00Z",
            evidence_type="attempt_terminal",
            lane=None,
            outcome="live_accepted",
        ),
    )
    controller["attempts"][-1]["receipt_uri"], controller["attempts"][-1]["receipt_sha256"] = (
        controller_terminal
    )
    for result in controller["results"]:
        lane = result["lane"]
        receipt = _write_receipt(
            tmp_path,
            f"controller-{lane}.json",
            _evidence_payload(
                stage="controller",
                release_id="controller-v3-21b23e25",
                source_sha="21b23e25ed45a547ad460e4bc412a4949a909c3f",
                observed_at="2026-09-05T01:00:00Z",
                evidence_type="lane_result",
                lane=lane,
                outcome=result["outcome"],
            ),
        )
        result["receipt_uri"], result["receipt_sha256"] = receipt
    avds_terminal = _write_receipt(
        tmp_path,
        "avds-blocked.json",
        _evidence_payload(
            stage="avds-admin-shell",
            release_id="avds-blocked-1",
            source_sha="a" * 40,
            observed_at="2026-09-05T02:01:00Z",
            evidence_type="attempt_terminal",
            lane=None,
            outcome="blocked",
        ),
    )
    avds["attempts"][-1]["receipt_uri"], avds["attempts"][-1]["receipt_sha256"] = avds_terminal
    for result in avds["results"]:
        lane = result["lane"]
        avds_lane = _write_receipt(
            tmp_path,
            f"avds-{lane}.json",
            _evidence_payload(
                stage="avds-admin-shell",
                release_id="avds-blocked-1",
                source_sha="a" * 40,
                observed_at=result["recorded_at"],
                evidence_type="lane_result",
                lane=lane,
                outcome=result["outcome"],
            ),
        )
        result["receipt_uri"], result["receipt_sha256"] = avds_lane
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    AdminPlatformLedger(path, receipt_key=RECEIPT_KEY)

    controller["results"][0]["receipt_uri"] = None
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with pytest.raises(AdminPlatformLedgerError, match="non-pending lane result"):
        AdminPlatformLedger(path, receipt_key=RECEIPT_KEY)


def test_generated_v1_compatibility_projection_is_explicitly_read_only() -> None:
    result = subprocess.run(  # noqa: S603
        [
            sys.executable,
            "scripts/project_admin_platform_ledger_v1.py",
            str(_ledger_v3_path()),
        ],
        cwd=Path(__file__).parents[1],
        check=True,
        capture_output=True,
        text=True,
    )

    projection = json.loads(result.stdout)
    assert projection["schema"] == "qdev-admin-platform-ledger-compatibility-v1"
    assert projection["source_schema"] == "qdev-admin-platform-ledger-v3"
    assert projection["read_only"] is True
    assert projection["admission"] == "disabled"


def test_v3_historical_result_receipt_uses_its_attempt_source_sha(
    tmp_path: Path,
) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["program"]["updated_at"] = "2026-09-05T00:20:00Z"
    controller = document["entries"]["controller"]
    first = controller["attempts"][0]
    first.update(
        {
            "finished_at": "2026-09-05T00:10:00Z",
            "terminal_state": "blocked",
            "receipt_uri": "receipts/controller-first-terminal.json",
            "receipt_sha256": "0" * 64,
        }
    )
    first_result = controller["results"][0]
    first_result.update(
        {
            "outcome": "blocked",
            "recorded_at": "2026-09-05T00:10:00Z",
            "receipt_uri": "receipts/controller-first-source.json",
            "receipt_sha256": "0" * 64,
        }
    )
    first_terminal_receipt = _write_receipt(
        tmp_path,
        "controller-first-terminal.json",
        _evidence_payload(
            stage="controller",
            release_id=first["release_id"],
            source_sha=first["source_sha"],
            observed_at="2026-09-05T00:10:00Z",
            evidence_type="attempt_terminal",
            lane=None,
            outcome="blocked",
        ),
    )
    first["receipt_uri"], first["receipt_sha256"] = first_terminal_receipt
    first_lane_receipt = _write_receipt(
        tmp_path,
        "controller-first-source.json",
        _evidence_payload(
            stage="controller",
            release_id=first["release_id"],
            source_sha=first["source_sha"],
            observed_at="2026-09-05T00:10:00Z",
            evidence_type="lane_result",
            lane="source",
            outcome="blocked",
        ),
    )
    first_result["receipt_uri"], first_result["receipt_sha256"] = first_lane_receipt

    second_sha = "b" * 40
    controller["source_sha"] = second_sha
    controller["reference"] = "refs/heads/codex/controller-retry"
    controller["attempts"].append(
        {
            "release_id": "controller-retry-2",
            "source_sha": second_sha,
            "reference": "refs/heads/codex/controller-retry",
            "started_at": "2026-09-05T00:20:00Z",
            "finished_at": None,
            "terminal_state": None,
            "receipt_uri": None,
            "receipt_sha256": None,
        }
    )
    controller["results"].append(
        {
            "release_id": "controller-retry-2",
            "lane": "source",
            "outcome": "pending",
            "recorded_at": "2026-09-05T00:20:00Z",
            "receipt_uri": None,
            "receipt_sha256": None,
        }
    )
    document["active_candidate"] = {
        "release_id": "controller-retry-2",
        "repository": controller["repository"],
        "source_sha": second_sha,
        "reference": "refs/heads/codex/controller-retry",
    }
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    AdminPlatformLedger(path, receipt_key=RECEIPT_KEY)


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        ("checksum", "checksum does not match"),
        ("payload", "does not match the ledger evidence tuple"),
        ("missing-key", "verification key is unavailable"),
    ],
)
def test_v3_receipt_verification_fails_closed(
    tmp_path: Path,
    mutation: str,
    message: str,
) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["program"]["updated_at"] = "2026-09-05T00:01:00Z"
    controller = document["entries"]["controller"]
    result = controller["results"][0]
    result.update(
        {
            "outcome": "blocked",
            "recorded_at": "2026-09-05T00:01:00Z",
            "receipt_uri": "receipts/controller-source.json",
            "receipt_sha256": "0" * 64,
        }
    )
    payload = _evidence_payload(
        stage="controller",
        release_id=controller["attempts"][0]["release_id"],
        source_sha=controller["source_sha"],
        observed_at="2026-09-05T00:01:00Z",
        evidence_type="lane_result",
        lane="source",
        outcome="blocked" if mutation != "payload" else "failed",
    )
    uri, checksum = _write_receipt(tmp_path, "controller-source.json", payload)
    result["receipt_uri"] = uri
    result["receipt_sha256"] = "f" * 64 if mutation == "checksum" else checksum
    document["program"]["status"] = "blocked"
    controller["status"] = "blocked"
    terminal = controller["attempts"][0]
    terminal.update(
        {
            "finished_at": "2026-09-05T00:01:00Z",
            "terminal_state": "blocked",
            "receipt_uri": "receipts/controller-terminal.json",
            "receipt_sha256": "0" * 64,
        }
    )
    terminal_uri, terminal_checksum = _write_receipt(
        tmp_path,
        "controller-terminal.json",
        _evidence_payload(
            stage="controller",
            release_id=terminal["release_id"],
            source_sha=terminal["source_sha"],
            observed_at="2026-09-05T00:01:00Z",
            evidence_type="attempt_terminal",
            lane=None,
            outcome="blocked",
        ),
    )
    terminal["receipt_uri"] = terminal_uri
    terminal["receipt_sha256"] = terminal_checksum
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(AdminPlatformLedgerError, match=message):
        AdminPlatformLedger(
            path,
            receipt_key=None if mutation == "missing-key" else RECEIPT_KEY,
        )


def test_v3_rejects_unsafe_ledger_files_and_invalid_program_id(tmp_path: Path) -> None:
    source = tmp_path / "source.yml"
    source.write_text(_ledger_v3_path().read_text(encoding="utf-8"), encoding="utf-8")
    symlink = tmp_path / "ledger.yml"
    symlink.symlink_to(source)
    with pytest.raises(AdminPlatformLedgerError, match="unavailable"):
        AdminPlatformLedger(symlink)

    oversized = tmp_path / "oversized.yml"
    oversized.write_bytes(b" " * (4 * 1024 * 1024 + 1))
    with pytest.raises(AdminPlatformLedgerError, match="unsafe"):
        AdminPlatformLedger(oversized)

    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["program"]["id"] = "contains spaces"
    invalid = tmp_path / "invalid.yml"
    invalid.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")
    with pytest.raises(AdminPlatformLedgerError, match="program id"):
        AdminPlatformLedger(invalid)


def test_v3_rejects_non_chronological_attempt_evidence(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    controller = document["entries"]["controller"]
    controller["results"][0]["recorded_at"] = "2026-09-04T23:59:59Z"
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(AdminPlatformLedgerError, match="outside its attempt"):
        AdminPlatformLedger(path)


def test_v3_program_updated_at_must_match_the_latest_event(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["program"]["updated_at"] = "2026-09-05T00:00:01Z"
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(AdminPlatformLedgerError, match="latest event"):
        AdminPlatformLedger(path)


@pytest.mark.parametrize(
    ("lane", "outcome", "message"),
    [
        ("source", "queued", "source cannot be queued"),
        ("ci", "auth_blocked", "ci cannot be auth_blocked"),
        ("source", "not_applicable", "source cannot be not_applicable"),
    ],
)
def test_v3_rejects_semantically_invalid_lane_outcomes(
    tmp_path: Path,
    lane: str,
    outcome: str,
    message: str,
) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    result = document["entries"]["controller"]["results"][0]
    result["lane"] = lane
    result["outcome"] = outcome
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(AdminPlatformLedgerError, match=message):
        AdminPlatformLedger(path)


def test_v3_requires_prior_source_and_ci_evidence_between_lanes(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_v3_path().read_text(encoding="utf-8"))
    document["program"]["updated_at"] = "2026-09-05T00:01:00Z"
    controller = document["entries"]["controller"]
    controller["results"].append(
        {
            "release_id": "controller-v3-21b23e25",
            "lane": "publication",
            "outcome": "passed",
            "recorded_at": "2026-09-05T00:01:00Z",
            "receipt_uri": "receipts/controller-publication.json",
            "receipt_sha256": "0" * 64,
        }
    )
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(AdminPlatformLedgerError, match="requires passing source evidence"):
        AdminPlatformLedger(path)
