from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta

import pytest

from qdev_runner.test_reports import (
    MAX_REPORT_BYTES,
    MAX_REPORTS,
    normalize_test_run,
    parse_cobertura,
    parse_junit,
    parse_lcov,
    report_digest,
)
from qdev_runner.test_reports import TestReportError as ReportError


def payload(**overrides: object) -> dict[str, object]:
    value: dict[str, object] = {
        "schema": "qdev-test-run-v1",
        "contract_version": 1,
        "project": "private-repo",
        "repository": "belilovsky/private-repo",
        "commit_sha": "A" * 40,
        "suite": "unit",
        "workflow": "tests.yml",
        "job_id": 100,
        "attempt": 1,
        "execution": {
            "environment": "self-hosted:qdev-ci",
            "started_at": "2026-09-04T00:00:00Z",
            "finished_at": "2026-09-04T00:00:03Z",
            "status": "completed",
        },
        "result": {"status": "passed", "total": 2, "executed": 2, "failed": 0, "skipped": 0},
        "coverage": [{"status": "measured", "kind": "line", "covered": 8, "denominator": 10}],
        "critical_scenarios": [{"id": "login", "status": "passed"}],
        "reports": [
            {
                "path": "reports/junit.xml",
                "format": "junit",
                "sha256": "b" * 64,
                "size": 10,
            }
        ],
        "flags": {"flaky": False, "quarantined": False},
    }
    value.update(overrides)
    return value


def test_normalize_binds_identity_and_unknown_coverage() -> None:
    normalized = normalize_test_run(
        payload(coverage=None),
        expected={
            "repository": "belilovsky/private-repo",
            "commit_sha": "a" * 40,
            "job_id": 100,
        },
    )
    assert normalized["commit_sha"] == "a" * 40
    assert normalized["coverage"] == [{"status": "unknown"}]
    assert report_digest(normalized) == report_digest(normalized)


@pytest.mark.parametrize(
    ("result", "message"),
    [
        ({"status": "passed", "total": 0, "executed": 0, "failed": 0, "skipped": 0}, "passed"),
        ({"status": "passed", "total": 1, "executed": 1, "failed": 1, "skipped": 0}, "passed"),
        ({"status": "failed", "total": 1, "executed": 1, "failed": 0, "skipped": 0}, "failed"),
        ({"status": "not_run", "total": 1, "executed": 1, "failed": 0, "skipped": 0}, "not_run"),
    ],
)
def test_empty_or_inconsistent_results_cannot_be_passed(
    result: dict[str, object], message: str
) -> None:
    with pytest.raises(ReportError, match=message):
        normalize_test_run(payload(result=result))


def test_identity_and_unknown_field_mismatch_are_rejected() -> None:
    with pytest.raises(ReportError, match="identity mismatch"):
        normalize_test_run(payload(), expected={"commit_sha": "c" * 40})
    with pytest.raises(ReportError, match="unsupported fields"):
        normalize_test_run(payload(extra="not allowed"))


def test_commit_sha_must_be_a_full_git_object_name() -> None:
    with pytest.raises(ReportError, match="commit_sha"):
        normalize_test_run(payload(commit_sha="a" * 39))
    with pytest.raises(ReportError, match="commit_sha"):
        normalize_test_run(payload(commit_sha="g" * 40))


def test_execution_finished_at_is_required_but_may_be_null() -> None:
    execution = dict(payload()["execution"])
    execution.pop("finished_at")
    with pytest.raises(ReportError, match="execution.finished_at is required"):
        normalize_test_run(payload(execution=execution))

    execution["finished_at"] = None
    execution["status"] = "error"
    failed_payload = payload(
        execution=execution,
        result={"status": "failed", "total": 1, "executed": 1, "failed": 1, "skipped": 0},
        critical_scenarios=[],
    )
    normalized = normalize_test_run(failed_payload)
    assert normalized["execution"]["finished_at"] is None


def test_passed_result_cannot_hide_a_failed_critical_scenario() -> None:
    with pytest.raises(ReportError, match="critical scenario"):
        normalize_test_run(
            payload(critical_scenarios=[{"id": "checkout", "status": "failed"}])
        )


def test_quarantine_requires_bounded_owner_and_noncritical_scope() -> None:
    expiry = (datetime.now(UTC) + timedelta(days=1)).isoformat()
    with pytest.raises(ReportError, match="reason, owner and expiry"):
        normalize_test_run(payload(flags={"quarantined": True}))
    with pytest.raises(ReportError, match="only for suites without critical scenarios"):
        normalize_test_run(
            payload(
                result={"status": "failed", "total": 2, "executed": 2, "failed": 1, "skipped": 0},
                flags={
                    "flaky": True,
                    "quarantined": True,
                    "quarantine_reason": "intermittent dependency",
                    "quarantine_owner": "qa@example.invalid",
                    "quarantine_until": expiry,
                },
            )
        )


def test_junit_success_failure_empty_and_dangerous_xml() -> None:
    context = {
        "repository": "belilovsky/private-repo",
        "commit_sha": "a" * 40,
        "suite": "unit",
        "workflow": "tests.yml",
        "job_id": 100,
        "started_at": "2026-09-04T00:00:00Z",
    }
    success = parse_junit(
        b'<testsuite><testcase name="ok"/><testcase name="skip"><skipped/></testcase></testsuite>',
        context=context,
    )
    assert success["result"]["status"] == "passed"
    assert success["result"]["executed"] == 1
    failure = parse_junit(
        b'<testsuite><testcase name="bad"><failure/></testcase></testsuite>', context=context
    )
    assert failure["result"]["status"] == "failed"
    empty = parse_junit(b"<testsuite />", context=context)
    assert empty["result"]["status"] == "not_run"
    with pytest.raises(ReportError, match="DTD"):
        parse_junit(
            b'<!DOCTYPE testsuite [<!ENTITY xxe "file:///etc/passwd">]><testsuite />',
            context=context,
        )


def test_lcov_and_cobertura_preserve_unknown_when_unmeasurable() -> None:
    context = {
        "repository": "belilovsky/private-repo",
        "commit_sha": "a" * 40,
        "suite": "unit",
        "workflow": "tests.yml",
        "job_id": 100,
        "started_at": "2026-09-04T00:00:00Z",
    }
    lcov = parse_lcov(b"TN:\nSF:src/a.py\nLF:10\nLH:7\nend_of_record\n", context=context)
    assert lcov["coverage"][0]["percentage"] == 70.0
    unknown = parse_lcov(b"TN:\n", context=context)
    assert unknown["coverage"] == [{"status": "unknown"}]
    cobertura = parse_cobertura(
        b'<coverage line-rate="0.5" lines-valid="20" lines-covered="10" />', context=context
    )
    assert cobertura["coverage"][0]["denominator"] == 20
    with pytest.raises(ReportError, match="invalid LCOV"):
        parse_lcov(b"\xff", context=context)


def test_report_checksum_is_standard_sha256() -> None:
    report = parse_junit(
        b"<testsuite><testcase /></testsuite>",
        context={
            "repository": "belilovsky/private-repo",
            "commit_sha": "a" * 40,
            "suite": "unit",
            "workflow": "tests.yml",
            "job_id": 100,
        },
        report_path="junit.xml",
    )
    assert (
        report["reports"][0]["sha256"]
        == hashlib.sha256(b"<testsuite><testcase /></testsuite>").hexdigest()
    )


def test_report_metadata_is_bounded_even_before_artifact_upload() -> None:
    reports = [
        {"path": f"report-{index}.xml", "format": "junit", "sha256": "a" * 64, "size": 1}
        for index in range(MAX_REPORTS + 1)
    ]
    with pytest.raises(ReportError, match="more than"):
        normalize_test_run(payload(reports=reports))

    with pytest.raises(ReportError, match="maximum report size"):
        normalize_test_run(
            payload(
                reports=[
                    {
                        "path": "report.xml",
                        "format": "junit",
                        "sha256": "a" * 64,
                        "size": MAX_REPORT_BYTES + 1,
                    }
                ]
            )
        )

    with pytest.raises(ReportError, match="relative safe path"):
        normalize_test_run(
            payload(
                reports=[
                    {
                        "path": "reports\\junit.xml",
                        "format": "junit",
                        "sha256": "a" * 64,
                        "size": 1,
                    }
                ]
            )
        )
