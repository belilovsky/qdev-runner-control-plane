from __future__ import annotations

import copy
from pathlib import Path
from typing import Any

import pytest
import yaml

from qdev_runner.managed_release_ledger import (
    QGEO_REQUIRED_JOB_PROFILES,
    ManagedReleaseLedger,
    ManagedReleaseLedgerError,
    qgeo_dynamic_job_label,
)

REPOSITORY = "belilovsky/qazgeo"
SOURCE_SHA = "9" * 40
PR_CHECKOUT_SHA = "8" * 40
PR_BRANCH = "codex/qgeo-final"


def _source_path() -> Path:
    return Path(__file__).parents[1] / "config" / "managed-release-ledger.yml"


def _ledger_path(tmp_path: Path) -> Path:
    path = tmp_path / "managed-release-ledger.yml"
    path.write_bytes(_source_path().read_bytes())
    return path


def _labels(run_id: str, attempt: str, job_name: str, profile: str) -> list[str]:
    return sorted(
        [
            "self-hosted",
            "Linux",
            "X64",
            profile,
            qgeo_dynamic_job_label(run_id, attempt, job_name),
        ]
    )


def _phase_bindings(
    phase: str,
    *,
    state: str = "terminal",
    conclusion: str | None = "success",
) -> list[dict[str, Any]]:
    checkout_sha = PR_CHECKOUT_SHA if phase == "pull_request" else SOURCE_SHA
    ref = "refs/pull/63/merge" if phase == "pull_request" else "refs/heads/main"
    branch = PR_BRANCH if phase == "pull_request" else "main"
    workflow_runs = {
        ".github/workflows/ci.yml": "41001" if phase == "pull_request" else "42001",
        ".github/workflows/qdev-runner-contract.yml": (
            "41002" if phase == "pull_request" else "42002"
        ),
    }
    result: list[dict[str, Any]] = []
    job_id = 51000 if phase == "pull_request" else 52000
    for workflow_path, jobs in QGEO_REQUIRED_JOB_PROFILES[phase].items():
        run_id = workflow_runs[workflow_path]
        for job_name, profile in jobs.items():
            job_id += 1
            result.append(
                {
                    "repository": REPOSITORY,
                    "candidate_sha": SOURCE_SHA,
                    "checkout_sha": checkout_sha,
                    "run_id": run_id,
                    "attempt": "1",
                    "job_id": str(job_id),
                    "workflow_path": workflow_path,
                    "event": phase,
                    "ref": ref,
                    "head_branch": branch,
                    "profile": profile,
                    "labels": _labels(run_id, "1", job_name, profile),
                    "job_name": job_name,
                    "state": state,
                    "conclusion": conclusion if state == "terminal" else None,
                }
            )
    return result


def _register(ledger_path: Path, binding: dict[str, Any]) -> dict[str, Any]:
    return ManagedReleaseLedger(ledger_path).register_qgeo_ci_binding(
        repository=binding["repository"],
        source_sha=binding["candidate_sha"],
        checkout_sha=binding["checkout_sha"],
        run_id=binding["run_id"],
        attempt=binding["attempt"],
        job_id=binding["job_id"],
        workflow_path=binding["workflow_path"],
        event=binding["event"],
        ref=binding["ref"],
        head_branch=binding["head_branch"],
        profile=binding["profile"],
        labels=binding["labels"],
        job_name=binding["job_name"],
        state=binding["state"],
        conclusion=binding["conclusion"],
    )


def _register_all(ledger_path: Path, bindings: list[dict[str, Any]]) -> None:
    for binding in bindings:
        _register(ledger_path, binding)


def _seal(ledger_path: Path, bindings: list[dict[str, Any]]) -> None:
    _register_all(ledger_path, bindings)
    ManagedReleaseLedger(ledger_path).reconcile_qgeo_ci_terminal(
        source_sha=SOURCE_SHA,
        verified_bindings=bindings,
    )


def test_qazgeo_seed_is_a_closed_registration_without_historical_evidence() -> None:
    ledger = ManagedReleaseLedger(_source_path())
    entry = ledger.entries[0]

    assert entry.project_id == "qazgeo"
    assert entry.source_sha is None
    assert entry.status == "registration"
    assert entry.registration_state == "closed"
    assert entry.registration_phase is None
    assert entry.ci_runs == ()
    assert "8bfd4e5" not in _source_path().read_text(encoding="utf-8")


def test_closed_registration_does_not_admit_a_claim_or_release() -> None:
    ledger = ManagedReleaseLedger(_source_path())

    with pytest.raises(ManagedReleaseLedgerError, match="not open"):
        ledger.validate_admission(
            "qazgeo",
            PR_CHECKOUT_SHA,
            repository=REPOSITORY,
            run_id="41001",
            attempt="1",
            job_id="51001",
        )
    with pytest.raises(ManagedReleaseLedgerError, match="candidate tuple"):
        ledger.validate_candidate_ci_runs("qazgeo", SOURCE_SHA, ["42001", "42002"])


def test_first_exact_pr_binding_opens_dynamic_candidate_and_is_idempotent(
    tmp_path: Path,
) -> None:
    path = _ledger_path(tmp_path)
    binding = _phase_bindings("pull_request", state="queued", conclusion=None)[0]

    first = _register(path, binding)
    repeated = _register(path, binding)
    ledger = ManagedReleaseLedger(path)
    admitted = ledger.validate_admission(
        "qazgeo",
        PR_CHECKOUT_SHA,
        repository=REPOSITORY,
        run_id=binding["run_id"],
        attempt=binding["attempt"],
        job_id=binding["job_id"],
    )

    assert first["idempotent"] is False
    assert repeated["idempotent"] is True
    assert admitted.source_sha == SOURCE_SHA
    assert admitted.registration_phase == "pull_request"
    assert admitted.registration_state == "open"


@pytest.mark.parametrize(
    ("field", "value", "error"),
    [
        ("repository", "attacker/qazgeo", "candidate identity"),
        ("checkout_sha", SOURCE_SHA, "pull request identity"),
        ("ref", "refs/heads/main", "pull request identity"),
        ("event", "push", "main push identity"),
        ("profile", "qdev-ci-browser", "profile"),
        ("conclusion", "neutral", "conclusion"),
    ],
)
def test_registration_rejects_foreign_or_forged_binding(
    tmp_path: Path, field: str, value: str, error: str
) -> None:
    path = _ledger_path(tmp_path)
    binding = _phase_bindings("pull_request")[0]
    binding[field] = value

    with pytest.raises(ManagedReleaseLedgerError, match=error):
        _register(path, binding)


@pytest.mark.parametrize("mutation", ["missing", "extra", "forged", "duplicate"])
def test_registration_requires_exact_dynamic_job_label(tmp_path: Path, mutation: str) -> None:
    path = _ledger_path(tmp_path)
    binding = _phase_bindings("pull_request")[0]
    labels = list(binding["labels"])
    dynamic_index = next(
        index for index, label in enumerate(labels) if label.startswith("qdev-job-")
    )
    if mutation == "missing":
        labels.pop(dynamic_index)
    elif mutation == "extra":
        labels.append("extra")
    elif mutation == "forged":
        labels[dynamic_index] = labels[dynamic_index].replace("-1-", "-2-")
    else:
        labels.append(labels[dynamic_index])
    binding["labels"] = labels

    with pytest.raises(ManagedReleaseLedgerError, match="labels"):
        _register(path, binding)


def test_pr_reconciliation_requires_exact_successful_job_set(tmp_path: Path) -> None:
    path = _ledger_path(tmp_path)
    bindings = _phase_bindings("pull_request")
    _register_all(path, bindings)

    with pytest.raises(ManagedReleaseLedgerError, match="incomplete"):
        ManagedReleaseLedger(path).reconcile_qgeo_ci_terminal(
            source_sha=SOURCE_SHA,
            verified_bindings=bindings[:-1],
        )

    forged = copy.deepcopy(bindings)
    forged[0]["job_id"] = "99999"
    with pytest.raises(ManagedReleaseLedgerError, match="does not match"):
        ManagedReleaseLedger(path).reconcile_qgeo_ci_terminal(
            source_sha=SOURCE_SHA,
            verified_bindings=forged,
        )


def test_pr_job_set_is_sealed_and_cannot_be_extended_or_downgraded(
    tmp_path: Path,
) -> None:
    path = _ledger_path(tmp_path)
    bindings = _phase_bindings("pull_request")
    _seal(path, bindings)
    ledger = ManagedReleaseLedger(path)
    entry = ledger.entries[0]

    assert entry.registration_state == "sealed"
    assert entry.registration_phase == "pull_request"
    assert entry.pr_verified is True
    assert entry.job_set_digest is not None
    assert _register(path, bindings[0])["idempotent"] is True

    extra = copy.deepcopy(bindings[0])
    extra["job_id"] = "59999"
    with pytest.raises(ManagedReleaseLedgerError, match="sealed"):
        _register(path, extra)

    downgraded = copy.deepcopy(bindings[0])
    downgraded["state"] = "queued"
    downgraded["conclusion"] = None
    with pytest.raises(ManagedReleaseLedgerError, match="sealed"):
        _register(path, downgraded)


def test_main_push_cannot_open_before_exact_pr_success(tmp_path: Path) -> None:
    path = _ledger_path(tmp_path)

    with pytest.raises(ManagedReleaseLedgerError, match="begin with pull request"):
        _register(path, _phase_bindings("push")[0])


def test_verified_pr_transitions_to_same_sha_main_push_and_release_admission(
    tmp_path: Path,
) -> None:
    path = _ledger_path(tmp_path)
    _seal(path, _phase_bindings("pull_request"))
    push_bindings = _phase_bindings("push")
    _seal(path, push_bindings)
    ledger = ManagedReleaseLedger(path)
    bound_job = push_bindings[-1]
    receipt_scope = {
        "repository": bound_job["repository"],
        "workflow": bound_job["workflow_path"],
        "job": bound_job["job_name"],
        "runner_profile": bound_job["profile"],
        "run_id": int(bound_job["run_id"]),
        "job_id": int(bound_job["job_id"]),
        "attempt": int(bound_job["attempt"]),
    }
    entry = ledger.validate_candidate_ci_runs(
        "qazgeo",
        SOURCE_SHA,
        ["42001", "42002"],
        receipt_scope=receipt_scope,
    )

    assert entry.registration_state == "sealed"
    assert entry.registration_phase == "push"
    assert entry.pr_verified is True
    assert len(entry.ci_runs) == 5
    assert {item["checkout_sha"] for item in entry.ci_runs} == {SOURCE_SHA}
    with pytest.raises(ManagedReleaseLedgerError, match="run set"):
        ledger.validate_candidate_ci_runs("qazgeo", SOURCE_SHA, ["42001"])
    with pytest.raises(ManagedReleaseLedgerError, match="tuple"):
        ledger.validate_candidate_ci_runs("qazgeo", "7" * 40, ["42001", "42002"])
    for field, value in (
        ("repository", "attacker/qazgeo"),
        ("workflow", ".github/workflows/forged.yml"),
        ("job", "forged-job"),
        ("runner_profile", "qdev-ci" if bound_job["profile"] != "qdev-ci" else "qdev-ci-docker"),
        ("run_id", 99999),
        ("job_id", 99999),
        ("attempt", 2),
    ):
        forged_scope = {**receipt_scope, field: value}
        with pytest.raises(ManagedReleaseLedgerError, match="scope|provider ledger"):
            ledger.validate_candidate_ci_runs(
                "qazgeo",
                SOURCE_SHA,
                ["42001", "42002"],
                receipt_scope=forged_scope,
            )


def test_qazgeo_ledger_classifies_fifo_admission_without_mutation(tmp_path: Path) -> None:
    path = _ledger_path(tmp_path)
    binding = _phase_bindings("pull_request", state="queued", conclusion=None)[0]
    _register(path, binding)
    ledger = ManagedReleaseLedger(path)
    run_id = int(binding["run_id"])

    assert ledger.classify_admission("qazgeo", PR_CHECKOUT_SHA, run_id=run_id, run_attempt=1) == (
        True,
        None,
    )
    assert ledger.classify_admission("missing", SOURCE_SHA, run_id=run_id, run_attempt=1) == (
        False,
        "managed-production-candidate-not-active",
    )
    assert ledger.classify_admission("qazgeo", SOURCE_SHA, run_id=run_id, run_attempt=1) == (
        False,
        "managed-production-candidate-tuple-not-admitted",
    )
    assert ledger.classify_admission(
        "qazgeo", PR_CHECKOUT_SHA, run_id=run_id + 1, run_attempt=1
    ) == (
        False,
        "managed-production-candidate-tuple-not-admitted",
    )
    assert ledger.classify_admission("qazgeo", PR_CHECKOUT_SHA, run_id=run_id, run_attempt=2) == (
        False,
        "managed-production-candidate-tuple-not-admitted",
    )

    assert ManagedReleaseLedger(_source_path()).classify_admission(
        "qazgeo",
        SOURCE_SHA,
        run_id=run_id,
        run_attempt=1,
    ) == (
        False,
        "managed-production-candidate-not-active",
    )


def test_verified_pr_does_not_allow_a_different_main_sha(tmp_path: Path) -> None:
    path = _ledger_path(tmp_path)
    _seal(path, _phase_bindings("pull_request"))
    binding = _phase_bindings("push")[0]
    binding["candidate_sha"] = "7" * 40
    binding["checkout_sha"] = "7" * 40

    with pytest.raises(ManagedReleaseLedgerError, match="candidate tuple"):
        _register(path, binding)


def test_duplicate_provider_job_and_multiple_runs_for_workflow_fail_closed(
    tmp_path: Path,
) -> None:
    path = _ledger_path(tmp_path)
    bindings = _phase_bindings("pull_request")
    _register_all(path, bindings)
    document = yaml.safe_load(path.read_text(encoding="utf-8"))
    duplicate = copy.deepcopy(document["entries"]["qazgeo"]["ci_runs"][0])
    duplicate["run_id"] = "49999"
    duplicate["job_id"] = "59999"
    dynamic = qgeo_dynamic_job_label(
        duplicate["run_id"], duplicate["attempt"], duplicate["job_name"]
    )
    duplicate["labels"] = sorted(
        [label for label in duplicate["labels"] if not label.startswith("qdev-job-")] + [dynamic]
    )
    document["entries"]["qazgeo"]["ci_runs"].append(duplicate)
    path.write_text(yaml.safe_dump(document, sort_keys=False), encoding="utf-8")

    with pytest.raises(ManagedReleaseLedgerError, match="multiple runs"):
        ManagedReleaseLedger(path)


def test_stale_state_transition_and_non_success_terminal_are_rejected(
    tmp_path: Path,
) -> None:
    path = _ledger_path(tmp_path)
    binding = _phase_bindings("pull_request", state="in_progress", conclusion=None)[0]
    _register(path, binding)
    stale = copy.deepcopy(binding)
    stale["state"] = "queued"
    with pytest.raises(ManagedReleaseLedgerError, match="stale"):
        _register(path, stale)

    failed = copy.deepcopy(binding)
    failed["state"] = "terminal"
    failed["conclusion"] = "failure"
    with pytest.raises(ManagedReleaseLedgerError, match="conclusion"):
        _register(path, failed)
