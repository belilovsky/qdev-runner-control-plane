"""Validation and normalization for the shared qdev test-result contract.

Projects continue to run their native test commands.  This module only turns
their standard reports into a small, deterministic envelope that the broker
can store and query.  It deliberately does not execute tests or implement a
test runner.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any, cast

from defusedxml import ElementTree as ET  # type: ignore[import-untyped]

CONTRACT = "qdev-test-run-v1"
MAX_REPORT_BYTES = 10 * 1024 * 1024
MAX_REPORTS = 64
# GitHub's commit identity is a full object name.  Short refs are useful in
# human-facing logs, but cannot bind an uploaded result to a particular job.
_SHA_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_STATUSES = {"passed", "failed", "not_run"}
_EXECUTION_STATUSES = {"queued", "running", "completed", "error", "timeout", "cancelled"}
_TOP_LEVEL_FIELDS = {
    "schema",
    "contract_version",
    "project",
    "repository",
    "commit_sha",
    "suite",
    "workflow",
    "job_id",
    "attempt",
    "execution",
    "result",
    "coverage",
    "critical_scenarios",
    "reports",
    "flags",
    # These optional identity fields are added by the runner/workflow and are
    # checked against GitHub data by the broker.  Keeping them optional makes
    # the v1 envelope backwards compatible for historical receipts.
    "run_id",
    "repository_id",
    "project_id",
    "profile",
    "runner",
    "host",
}


class TestReportError(ValueError):
    """Raised when a test result cannot be trusted or normalized."""


def _text(value: Any, field: str, *, max_length: int = 512) -> str:
    if not isinstance(value, str) or not value.strip():
        raise TestReportError(f"{field} must be a non-empty string")
    value = value.strip()
    if len(value) > max_length:
        raise TestReportError(f"{field} is too long")
    return cast(str, value)


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise TestReportError(f"{field} must be an integer >= {minimum}")
    return cast(int, value)


def _iso_timestamp(value: Any, field: str) -> str:
    text = _text(value, field, max_length=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise TestReportError(f"{field} must be an ISO-8601 timestamp") from error
    if parsed.tzinfo is None:
        raise TestReportError(f"{field} must include a timezone")
    return parsed.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _repository(value: Any) -> str:
    repository = _text(value, "repository", max_length=256)
    if (
        repository.count("/") != 1
        or any(part in {"", ".", ".."} for part in repository.split("/"))
        or not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
    ):
        raise TestReportError("repository must be owner/name")
    return repository


def _reject_unknown(value: dict[str, Any], allowed: set[str], field: str) -> None:
    unknown = set(value).difference(allowed)
    if unknown:
        raise TestReportError(f"{field} has unsupported fields: {', '.join(sorted(unknown))}")


def _sha(value: Any) -> str:
    sha = _text(value, "commit_sha", max_length=128)
    if not _SHA_RE.fullmatch(sha):
        raise TestReportError("commit_sha must be a hexadecimal commit identifier")
    return sha.lower()


def _coverage(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return [{"status": "unknown"}]
    entries = value if isinstance(value, list) else [value]
    normalized: list[dict[str, Any]] = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise TestReportError("coverage entries must be objects")
        _reject_unknown(
            entry,
            {"status", "kind", "type", "covered", "denominator", "percentage"},
            "coverage",
        )
        status = entry.get("status", "measured")
        if status == "unknown":
            normalized.append({"status": "unknown"})
            continue
        if status != "measured":
            raise TestReportError("coverage status must be measured or unknown")
        kind = _text(entry.get("kind") or entry.get("type"), "coverage.kind", max_length=64)
        denominator = _integer(entry.get("denominator"), "coverage.denominator", minimum=1)
        covered = _integer(entry.get("covered"), "coverage.covered")
        if covered > denominator:
            raise TestReportError("coverage.covered cannot exceed denominator")
        percentage = entry.get("percentage")
        calculated = round(covered * 100 / denominator, 4)
        if percentage is None:
            percentage = calculated
        if isinstance(percentage, bool) or not isinstance(percentage, (int, float)):
            raise TestReportError("coverage.percentage must be numeric")
        if percentage < 0 or percentage > 100:
            raise TestReportError("coverage.percentage must be between 0 and 100")
        if abs(float(percentage) - calculated) > 0.0001:
            raise TestReportError("coverage.percentage contradicts covered/denominator")
        normalized.append(
            {
                "status": "measured",
                "kind": kind,
                "covered": covered,
                "denominator": denominator,
                "percentage": float(percentage),
            }
        )
    return normalized or [{"status": "unknown"}]


def _result(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise TestReportError("result must be an object")
    _reject_unknown(value, {"status", "total", "executed", "failed", "skipped"}, "result")
    status = value.get("status")
    if status not in _STATUSES:
        raise TestReportError("result.status must be passed, failed or not_run")
    total = _integer(value.get("total"), "result.total")
    executed = _integer(value.get("executed"), "result.executed")
    failed = _integer(value.get("failed"), "result.failed")
    skipped = _integer(value.get("skipped", 0), "result.skipped")
    if executed > total or failed > executed or skipped > total:
        raise TestReportError("result counts are inconsistent")
    if status == "passed" and (total == 0 or executed == 0 or failed != 0):
        raise TestReportError("a passed result must contain at least one executed test")
    if status == "failed" and failed == 0:
        raise TestReportError("a failed result must contain a failed test")
    if status == "not_run" and executed != 0:
        raise TestReportError("not_run cannot contain executed tests")
    return {
        "status": status,
        "total": total,
        "executed": executed,
        "failed": failed,
        "skipped": skipped,
    }


def _critical_scenarios(value: Any) -> list[dict[str, str]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TestReportError("critical_scenarios must be a list")
    result: list[dict[str, str]] = []
    seen: set[str] = set()
    for entry in value:
        if not isinstance(entry, dict):
            raise TestReportError("critical_scenarios entries must be objects")
        _reject_unknown(entry, {"id", "status"}, "critical_scenarios")
        scenario_id = _text(entry.get("id"), "critical_scenarios.id", max_length=128)
        if scenario_id in seen:
            raise TestReportError("critical_scenarios.id must be unique")
        seen.add(scenario_id)
        status = entry.get("status")
        if status not in _STATUSES:
            raise TestReportError("critical_scenarios.status is invalid")
        result.append({"id": scenario_id, "status": status})
    return result


def _reports(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TestReportError("reports must be a list")
    if len(value) > MAX_REPORTS:
        raise TestReportError(f"reports cannot contain more than {MAX_REPORTS} entries")
    reports: list[dict[str, Any]] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise TestReportError("reports entries must be objects")
        _reject_unknown(entry, {"path", "format", "sha256", "size", "url"}, "reports")
        path = _text(entry.get("path"), "reports.path", max_length=512)
        path_parts = path.replace("\\", "/").split("/")
        if (
            "\\" in path
            or
            path.startswith(("/", "\\"))
            or any(part in {"", ".", ".."} for part in path_parts)
            or any(ord(char) < 32 for char in path)
        ):
            raise TestReportError("reports.path must be a relative safe path")
        digest = _text(entry.get("sha256"), "reports.sha256", max_length=64).lower()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise TestReportError("reports.sha256 must be a SHA-256 digest")
        size = _integer(entry.get("size", 0), "reports.size")
        if size > MAX_REPORT_BYTES:
            raise TestReportError("reports.size exceeds the maximum report size")
        item: dict[str, Any] = {
            "path": path,
            "format": _text(entry.get("format", "unknown"), "reports.format", max_length=32),
            "sha256": digest,
            "size": size,
        }
        if entry.get("url") is not None:
            url = _text(entry["url"], "reports.url", max_length=1024)
            if (
                any(ord(char) < 32 for char in url)
                or url.startswith("//")
                or not (url.startswith("https://") or url.startswith("/"))
            ):
                raise TestReportError("reports.url must be an HTTPS or relative URL")
            item["url"] = url
        reports.append(item)
    return reports


def normalize_test_run(
    payload: dict[str, Any], *, expected: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Validate and return a canonical qdev-test-run-v1 dictionary.

    ``expected`` is supplied by the broker and binds the report to the active
    GitHub job. A report with a different repository, SHA or job is rejected.
    """

    if not isinstance(payload, dict) or payload.get("schema") != CONTRACT:
        raise TestReportError(f"schema must be {CONTRACT}")
    unknown = set(payload).difference(_TOP_LEVEL_FIELDS)
    if unknown:
        raise TestReportError(f"unsupported fields: {', '.join(sorted(unknown))}")
    repository = _repository(payload.get("repository"))
    commit_sha = _sha(payload.get("commit_sha"))
    suite = _text(payload.get("suite"), "suite", max_length=128)
    workflow = _text(payload.get("workflow"), "workflow", max_length=256)
    project = _text(payload.get("project", repository), "project", max_length=256)
    job_id = _integer(payload.get("job_id"), "job_id", minimum=1)
    attempt = _integer(payload.get("attempt"), "attempt", minimum=1)
    contract_version = payload.get("contract_version", 1)
    if contract_version != 1:
        raise TestReportError("unsupported contract_version")
    execution = payload.get("execution")
    if not isinstance(execution, dict):
        raise TestReportError("execution must be an object")
    _reject_unknown(
        execution,
        {"environment", "started_at", "finished_at", "status"},
        "execution",
    )
    execution_status = execution.get("status", "completed")
    if execution_status not in _EXECUTION_STATUSES:
        raise TestReportError("execution.status is invalid")
    environment = _text(
        execution.get("environment", "self-hosted"), "execution.environment", max_length=128
    )
    started_at = _iso_timestamp(execution.get("started_at"), "execution.started_at")
    if "finished_at" not in execution:
        raise TestReportError("execution.finished_at is required")
    finished_raw = execution["finished_at"]
    finished_at = (
        None if finished_raw is None else _iso_timestamp(finished_raw, "execution.finished_at")
    )
    if finished_at and finished_at < started_at:
        raise TestReportError("execution.finished_at precedes started_at")
    result = _result(payload.get("result"))
    critical_scenarios = _critical_scenarios(payload.get("critical_scenarios"))
    if result["status"] == "passed" and any(
        scenario["status"] != "passed" for scenario in critical_scenarios
    ):
        raise TestReportError(
            "a passed result cannot contain a failed or not_run critical scenario"
        )
    normalized = {
        "schema": CONTRACT,
        "contract_version": 1,
        "project": project,
        "repository": repository,
        "commit_sha": commit_sha,
        "suite": suite,
        "workflow": workflow,
        "job_id": job_id,
        "attempt": attempt,
        "execution": {
            "environment": environment,
            "started_at": started_at,
            "finished_at": finished_at,
            "status": execution_status,
        },
        "result": result,
        "coverage": _coverage(payload.get("coverage")),
        "critical_scenarios": critical_scenarios,
        "reports": _reports(payload.get("reports")),
    }
    for field, max_length in (
        ("profile", 128),
        ("runner", 256),
        ("host", 256),
        ("project_id", 256),
    ):
        if payload.get(field) is not None:
            normalized[field] = _text(payload[field], field, max_length=max_length)
    for field in ("run_id", "repository_id"):
        if payload.get(field) is not None:
            normalized[field] = _integer(payload[field], field, minimum=1)
    flags = payload.get("flags")
    if flags is not None:
        if not isinstance(flags, dict):
            raise TestReportError("flags must be an object")
        _reject_unknown(
            flags,
            {"flaky", "quarantined", "quarantine_reason", "quarantine_owner", "quarantine_until"},
            "flags",
        )
        for key in ("flaky", "quarantined"):
            if not isinstance(flags.get(key, False), bool):
                raise TestReportError(f"flags.{key} must be boolean")
        normalized_flags: dict[str, Any] = {
            "flaky": flags.get("flaky", False),
            "quarantined": flags.get("quarantined", False),
        }
        for key in ("quarantine_reason", "quarantine_owner", "quarantine_until"):
            if flags.get(key) is not None:
                normalized_flags[key] = _text(flags[key], f"flags.{key}", max_length=256)
        if normalized_flags.get("quarantine_until") is not None:
            expiry = _iso_timestamp(normalized_flags["quarantine_until"], "flags.quarantine_until")
            if datetime.fromisoformat(expiry.replace("Z", "+00:00")) > datetime.now(
                UTC
            ) + timedelta(days=7):
                raise TestReportError("quarantine expiry cannot exceed seven days")
            normalized_flags["quarantine_until"] = expiry
        if normalized_flags["quarantined"] and not all(
            normalized_flags.get(key)
            for key in ("quarantine_reason", "quarantine_owner", "quarantine_until")
        ):
            raise TestReportError("quarantined results require reason, owner and expiry")
        if normalized_flags["quarantined"] and critical_scenarios:
            raise TestReportError(
                "quarantine is allowed only for suites without critical scenarios"
            )
        normalized["flags"] = normalized_flags
    else:
        normalized["flags"] = {"flaky": False, "quarantined": False}

    for field, expected_value in (expected or {}).items():
        if field not in normalized:
            raise TestReportError(f"report identity mismatch: {field}")
        actual = normalized[field]
        if field == "commit_sha":
            actual = str(actual).lower()
            expected_value = str(expected_value).lower()
        if actual != expected_value:
            raise TestReportError(f"report identity mismatch: {field}")
    return normalized


def report_digest(payload: dict[str, Any]) -> str:
    rendered = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode()
    return hashlib.sha256(rendered).hexdigest()


def parse_junit(
    data: bytes, *, context: dict[str, Any], report_path: str = "junit.xml"
) -> dict[str, Any]:
    """Normalize a JUnit XML report without allowing entity expansion."""

    _check_report_size(data)
    lowered = data[:4096].lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise TestReportError("DTD and external entities are not allowed")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise TestReportError("invalid JUnit XML") from error
    cases = list(root.iter("testcase"))
    total = len(cases)
    failed = sum(
        1 for case in cases if case.find("failure") is not None or case.find("error") is not None
    )
    skipped = sum(1 for case in cases if case.find("skipped") is not None)
    executed = total - skipped
    status = "not_run" if total == 0 or executed == 0 else "failed" if failed else "passed"
    digest = hashlib.sha256(data).hexdigest()
    payload = _base_payload(
        context=context,
        status=status,
        total=total,
        executed=executed,
        failed=failed,
        skipped=skipped,
    )
    payload["reports"] = [
        {"path": report_path, "format": "junit", "sha256": digest, "size": len(data)}
    ]
    return normalize_test_run(payload)


def parse_lcov(
    data: bytes, *, context: dict[str, Any], report_path: str = "lcov.info"
) -> dict[str, Any]:
    _check_report_size(data)
    try:
        lines = data.decode("utf-8", errors="strict").splitlines()
    except UnicodeDecodeError as error:
        raise TestReportError("invalid LCOV encoding") from error
    found = False
    total = covered = 0
    for line in lines:
        try:
            if line.startswith("LF:"):
                total += int(line[3:])
                found = True
            elif line.startswith("LH:"):
                covered += int(line[3:])
        except ValueError as error:
            raise TestReportError("invalid LCOV counter") from error
    if not found or total <= 0 or covered < 0 or covered > total:
        coverage: list[dict[str, Any]] = [{"status": "unknown"}]
    else:
        coverage = [
            {"status": "measured", "kind": "line", "covered": covered, "denominator": total}
        ]
    payload = _base_payload(
        context=context, status="not_run", total=0, executed=0, failed=0, skipped=0
    )
    payload["coverage"] = coverage
    payload["reports"] = [
        {
            "path": report_path,
            "format": "lcov",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
    ]
    return normalize_test_run(payload)


def parse_cobertura(
    data: bytes, *, context: dict[str, Any], report_path: str = "coverage.xml"
) -> dict[str, Any]:
    _check_report_size(data)
    lowered = data[:4096].lower()
    if b"<!doctype" in lowered or b"<!entity" in lowered:
        raise TestReportError("DTD and external entities are not allowed")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as error:
        raise TestReportError("invalid Cobertura XML") from error
    raw_rate = root.attrib.get("line-rate")
    try:
        rate = float(raw_rate) if raw_rate is not None else -1
    except ValueError:
        rate = -1
    if not 0 <= rate <= 1:
        coverage: list[dict[str, Any]] = [{"status": "unknown"}]
    else:
        try:
            denominator = int(root.attrib.get("lines-valid", "0"))
            covered = int(root.attrib.get("lines-covered", str(round(rate * denominator))))
        except ValueError as error:
            raise TestReportError("invalid Cobertura counters") from error
        coverage = (
            [{"status": "measured", "kind": "line", "covered": covered, "denominator": denominator}]
            if denominator > 0 and 0 <= covered <= denominator
            else [{"status": "unknown"}]
        )
    payload = _base_payload(
        context=context, status="not_run", total=0, executed=0, failed=0, skipped=0
    )
    payload["coverage"] = coverage
    payload["reports"] = [
        {
            "path": report_path,
            "format": "cobertura",
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        }
    ]
    return normalize_test_run(payload)


def _base_payload(
    *, context: dict[str, Any], status: str, total: int, executed: int, failed: int, skipped: int
) -> dict[str, Any]:
    started = context.get("started_at", _now())
    finished = context.get("finished_at", started)
    payload: dict[str, Any] = {
        "schema": CONTRACT,
        "contract_version": 1,
        "project": context.get("project", context.get("repository", "unknown")),
        "repository": context["repository"],
        "commit_sha": context["commit_sha"],
        "suite": context["suite"],
        "workflow": context["workflow"],
        "job_id": context["job_id"],
        "attempt": context.get("attempt", 1),
        "execution": {
            "environment": context.get("environment", "self-hosted"),
            "started_at": started,
            "finished_at": finished,
            "status": "completed",
        },
        "result": {
            "status": status,
            "total": total,
            "executed": executed,
            "failed": failed,
            "skipped": skipped,
        },
        "coverage": [{"status": "unknown"}],
        "critical_scenarios": [],
        "reports": [],
    }
    for key in ("run_id", "repository_id", "project_id", "profile", "runner", "host"):
        if context.get(key) is not None:
            payload[key] = context[key]
    return payload


def _check_report_size(data: bytes) -> None:
    if len(data) > MAX_REPORT_BYTES:
        raise TestReportError("test report exceeds the maximum size")
