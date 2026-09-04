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
        "8bfd4e5bb7da5c7c99fd12865fb56d88fc5c9d7d",
        repository="belilovsky/qazgeo",
        run_id="33838251934",
        attempt="1",
        job_id="100915082535",
    )

    assert entry.project_id == "qazgeo"
    assert entry.status == "ci_queued"
    assert entry.ci_runs == (
        {
            "run_id": "33838251934",
            "state": "queued",
            "repository": "belilovsky/qazgeo",
            "job_id": "100915082535",
            "attempt": "1",
        },
        {
            "run_id": "33838251867",
            "state": "queued",
            "repository": "belilovsky/qazgeo",
            "job_id": "100915081363",
            "attempt": "1",
        },
    )
    with pytest.raises(ManagedReleaseLedgerError, match="tuple"):
        ledger.validate_admission(
            "qazgeo",
            "d65cd62a4c96786d9d5c35ebea8af872dcc3cb69",
            repository="belilovsky/qazgeo",
            run_id="33838251934",
            attempt="1",
            job_id="100915082535",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("repository", "attacker/qazgeo"),
        ("run_id", "33838251867"),
        ("attempt", "2"),
        ("job_id", "100915081363"),
    ],
)
def test_qazgeo_ledger_rejects_wrong_provider_binding(field: str, value: str) -> None:
    ledger = ManagedReleaseLedger(_ledger_path())
    binding = {
        "repository": "belilovsky/qazgeo",
        "run_id": "33838251934",
        "attempt": "1",
        "job_id": "100915082535",
    }
    binding[field] = value

    with pytest.raises(ManagedReleaseLedgerError, match="provider binding"):
        ledger.validate_admission(
            "qazgeo",
            "8bfd4e5bb7da5c7c99fd12865fb56d88fc5c9d7d",
            **binding,
        )


def test_qazgeo_ledger_rejects_a_replacement_or_duplicate_ci_run(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_path().read_text(encoding="utf-8"))
    document["entries"]["qazgeo"]["ci_runs"].append({"run_id": "33838251934", "state": "terminal"})
    path = tmp_path / "ledger.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")

    with pytest.raises(ManagedReleaseLedgerError, match="CI run"):
        ManagedReleaseLedger(path)


def test_qazgeo_candidate_ci_requires_the_complete_terminal_run_set(tmp_path: Path) -> None:
    document = yaml.safe_load(_ledger_path().read_text(encoding="utf-8"))
    entry = document["entries"]["qazgeo"]
    entry["status"] = "ci_passed"
    entry["ci"]["state"] = "ci_passed"
    for run in entry["ci_runs"]:
        run["state"] = "terminal"
    path = tmp_path / "terminal-ledger.yml"
    path.write_text(yaml.safe_dump(document), encoding="utf-8")
    ledger = ManagedReleaseLedger(path)

    admitted = ledger.validate_candidate_ci_runs(
        "qazgeo",
        "8bfd4e5bb7da5c7c99fd12865fb56d88fc5c9d7d",
        ["33838251934", "33838251867"],
    )
    assert admitted.status == "ci_passed"
    with pytest.raises(ManagedReleaseLedgerError, match="run set"):
        ledger.validate_candidate_ci_runs(
            "qazgeo",
            "8bfd4e5bb7da5c7c99fd12865fb56d88fc5c9d7d",
            ["33838251934"],
        )


def test_qazgeo_candidate_ci_rejects_queued_runs(tmp_path: Path) -> None:
    ledger = ManagedReleaseLedger(_ledger_path())
    with pytest.raises(ManagedReleaseLedgerError, match="not terminal"):
        ledger.validate_candidate_ci_runs(
            "qazgeo",
            "8bfd4e5bb7da5c7c99fd12865fb56d88fc5c9d7d",
            ["33838251934", "33838251867"],
        )
