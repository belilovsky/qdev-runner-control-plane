from pathlib import Path

import pytest
import yaml

from qdev_runner.managed_release_ledger import (
    ManagedReleaseLedger,
    ManagedReleaseLedgerError,
)


def _ledger_path() -> Path:
    return Path(__file__).parents[1] / "config" / "managed-release-ledger.yml"


def test_qazgeo_ledger_admits_only_its_exact_candidate_and_existing_runs() -> None:
    ledger = ManagedReleaseLedger(_ledger_path())

    entry = ledger.validate_admission(
        "qazgeo",
        "932883aeed522500d03b0a56e2d1798a3ea9c910",
        run_id=33908036125,
        run_attempt=1,
    )

    assert entry.project_id == "qazgeo"
    assert entry.status == "ci_queued"
    assert entry.ci_runs == (
        {"run_id": "33908036125", "run_attempt": "1", "state": "queued"},
    )
    with pytest.raises(ManagedReleaseLedgerError, match="tuple"):
        ledger.validate_admission(
            "qazgeo",
            "d65cd62a4c96786d9d5c35ebea8af872dcc3cb69",
            run_id=33908036125,
            run_attempt=1,
        )
    with pytest.raises(ManagedReleaseLedgerError, match="CI run"):
        ledger.validate_admission(
            "qazgeo",
            "932883aeed522500d03b0a56e2d1798a3ea9c910",
            run_id=33908036126,
            run_attempt=1,
        )
    with pytest.raises(ManagedReleaseLedgerError, match="CI run"):
        ledger.validate_admission(
            "qazgeo",
            "932883aeed522500d03b0a56e2d1798a3ea9c910",
            run_id=33908036125,
            run_attempt=2,
        )


def test_qazgeo_ledger_classifies_fifo_admission_without_mutation(tmp_path: Path) -> None:
    ledger = ManagedReleaseLedger(_ledger_path())
    exact_sha = "932883aeed522500d03b0a56e2d1798a3ea9c910"

    assert ledger.classify_admission(
        "qazgeo", exact_sha, run_id=33908036125, run_attempt=1
    ) == (True, None)
    assert ledger.classify_admission(
        "missing", exact_sha, run_id=33908036125, run_attempt=1
    ) == (
        False,
        "managed-production-candidate-not-active",
    )
    assert ledger.classify_admission(
        "qazgeo", "d" * 40, run_id=33908036125, run_attempt=1
    ) == (
        False,
        "managed-production-candidate-tuple-not-admitted",
    )
    assert ledger.classify_admission(
        "qazgeo", exact_sha, run_id=33908036126, run_attempt=1
    ) == (
        False,
        "managed-production-candidate-tuple-not-admitted",
    )
    assert ledger.classify_admission(
        "qazgeo", exact_sha, run_id=33908036125, run_attempt=2
    ) == (
        False,
        "managed-production-candidate-tuple-not-admitted",
    )

    document = yaml.safe_load(_ledger_path().read_text(encoding="utf-8"))
    document["entries"]["qazgeo"]["status"] = "live_accepted"
    inactive_path = tmp_path / "inactive-ledger.yml"
    inactive_path.write_text(yaml.safe_dump(document), encoding="utf-8")

    assert ManagedReleaseLedger(inactive_path).classify_admission(
        "qazgeo", exact_sha, run_id=33908036125, run_attempt=1
    ) == (
        False,
        "managed-production-candidate-not-active",
    )

    document["entries"]["qazgeo"]["status"] = "ci_queued"
    document["entries"]["qazgeo"]["ci_runs"][0]["state"] = "terminal"
    terminal_path = tmp_path / "terminal-run-ledger.yml"
    terminal_path.write_text(yaml.safe_dump(document), encoding="utf-8")
    terminal = ManagedReleaseLedger(terminal_path)
    assert terminal.classify_admission(
        "qazgeo", exact_sha, run_id=33908036125, run_attempt=1
    ) == (
        False,
        "managed-production-candidate-tuple-not-admitted",
    )
    with pytest.raises(ManagedReleaseLedgerError, match="CI run"):
        terminal.validate_admission(
            "qazgeo", exact_sha, run_id=33908036125, run_attempt=1
        )


def test_qazgeo_ledger_rejects_a_replacement_or_duplicate_ci_run(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_path().read_text(encoding="utf-8"))
    document["entries"]["qazgeo"]["ci_runs"].append(
        {"run_id": "33908036125", "run_attempt": "1", "state": "terminal"}
    )
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    with pytest.raises(ManagedReleaseLedgerError, match="CI run"):
        ManagedReleaseLedger(path)
