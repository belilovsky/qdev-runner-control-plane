"""Default-branch workflow audit receipts must be identity and SHA bound."""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parents[1]


def load_audit() -> ModuleType:
    path = ROOT / "scripts" / "qdev_default_branch_audit.py"
    spec = importlib.util.spec_from_file_location("qdev_default_branch_audit", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def inventory(path: Path, *, branch: str = "main") -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": "qdev-runner-inventory-v1",
                "repositories": [
                    {
                        "id": 7,
                        "full_name": "belilovsky/example",
                        "default_branch": branch,
                        "archived": False,
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return path


def test_report_uses_fresh_default_sha_and_canonical_auditor(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = load_audit()
    sha = "a" * 40
    calls: list[str] = []

    def gh_api(endpoint: str) -> object:
        calls.append(endpoint)
        if endpoint == "/repos/belilovsky/example":
            return {"id": 7, "full_name": "belilovsky/example", "default_branch": "main"}
        assert endpoint == "/repos/belilovsky/example/git/ref/heads/main"
        return {"object": {"type": "commit", "sha": sha}}

    def audit_repository(repo: dict[str, str], ref: str) -> dict[str, object]:
        assert repo == {"full_name": "belilovsky/example", "default_branch": "main"}
        assert ref == sha
        return {"violations": []}

    monkeypatch.setattr(
        module,
        "load_auditor",
        lambda: SimpleNamespace(gh_api=gh_api, audit_repository=audit_repository),
    )
    report = module.build_report(inventory(tmp_path / "repos.json"), workers=1)

    assert calls == [
        "/repos/belilovsky/example",
        "/repos/belilovsky/example/git/ref/heads/main",
    ]
    assert report["repositories"] == 1
    assert report["critical_violations"] == 0
    assert report["results"] == [
        {
            "repository": "belilovsky/example",
            "repository_id": 7,
            "default_branch": "main",
            "revision": sha,
            "status": "passed",
            "violations": [],
        }
    ]


def test_branch_or_identity_drift_is_unverifiable(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = load_audit()
    monkeypatch.setattr(
        module,
        "load_auditor",
        lambda: SimpleNamespace(
            gh_api=lambda _endpoint: {
                "id": 7,
                "full_name": "belilovsky/example",
                "default_branch": "trunk",
            },
            audit_repository=lambda *_args: pytest.fail("must not audit a drifted default branch"),
        ),
    )

    report = module.build_report(inventory(tmp_path / "repos.json"), workers=1)

    assert report["critical_violations"] == 1
    assert report["results"][0]["status"] == "unverifiable"
    assert report["results"][0]["error"] == "inventory default branch drift"


def test_branch_names_are_encoded_and_receipts_reject_symlinks(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    module = load_audit()
    sha = "b" * 40
    endpoints: list[str] = []

    def gh_api(endpoint: str) -> object:
        endpoints.append(endpoint)
        if endpoint == "/repos/belilovsky/example":
            return {
                "id": 7,
                "full_name": "belilovsky/example",
                "default_branch": "release/2026.09",
            }
        return {"object": {"type": "commit", "sha": sha}}

    monkeypatch.setattr(
        module,
        "load_auditor",
        lambda: SimpleNamespace(gh_api=gh_api, audit_repository=lambda *_args: {"violations": []}),
    )
    report = module.build_report(
        inventory(tmp_path / "repos.json", branch="release/2026.09"), workers=1
    )
    assert endpoints[-1].endswith("heads/release%2F2026.09")

    target = tmp_path / "target.json"
    target.write_text("keep", encoding="utf-8")
    output = tmp_path / "receipt.json"
    output.symlink_to(target)
    with pytest.raises(module.AuditError, match="must not be a symlink"):
        module.write_report(output, report)
