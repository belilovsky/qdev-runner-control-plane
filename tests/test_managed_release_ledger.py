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

    entry = ledger.validate_admission("qazgeo", "932883aeed522500d03b0a56e2d1798a3ea9c910")

    assert entry.project_id == "qazgeo"
    assert entry.status == "ci_queued"
    assert entry.ci_runs == ({"run_id": "33908036125", "state": "queued"},)
    with pytest.raises(ManagedReleaseLedgerError, match="tuple"):
        ledger.validate_admission("qazgeo", "d65cd62a4c96786d9d5c35ebea8af872dcc3cb69")


def test_qazgeo_ledger_rejects_a_replacement_or_duplicate_ci_run(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_path().read_text(encoding="utf-8"))
    document["entries"]["qazgeo"]["ci_runs"].append({"run_id": "33908036125", "state": "terminal"})
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    with pytest.raises(ManagedReleaseLedgerError, match="CI run"):
        ManagedReleaseLedger(path)


def test_qazgeo_ledger_classifies_stale_queue_tuples_without_admitting_them() -> None:
    ledger = ManagedReleaseLedger(_ledger_path())

    assert ledger.classify_admission(
        "qazgeo", "932883aeed522500d03b0a56e2d1798a3ea9c910"
    ) == (True, None)
    assert ledger.classify_admission(
        "qazgeo", "d65cd62a4c96786d9d5c35ebea8af872dcc3cb69"
    ) == (False, "managed-release-candidate-tuple-not-admitted")
    assert ledger.classify_admission("missing", "d" * 40) == (
        False,
        "managed-release-candidate-not-active",
    )
