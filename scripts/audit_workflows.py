#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import json
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HOSTED = re.compile(r"\b(?:ubuntu|windows|macos)-(?:latest|\d[\w.-]*)\b", re.I)
FORBIDDEN = {
    "actions/cache@": "github-cache",
    "actions/upload-artifact@": "github-artifact",
    "ghcr.io": "ghcr",
}


def gh_api(endpoint: str) -> Any:
    completed = subprocess.run(["gh", "api", endpoint], check=True, capture_output=True, text=True)
    return json.loads(completed.stdout)


def audit_repository(repo: dict[str, Any]) -> dict[str, Any]:
    violations: list[dict[str, Any]] = []
    full_name = repo["full_name"]
    for workflow in repo["workflow_files"]:
        data = gh_api(f"/repos/{full_name}/contents/{workflow['path']}")
        text = base64.b64decode(data["content"]).decode("utf-8", errors="replace")
        for line_number, line in enumerate(text.splitlines(), start=1):
            if "runs-on:" in line and HOSTED.search(line):
                violations.append(
                    {"path": workflow["path"], "line": line_number, "kind": "hosted-runner"}
                )
            for marker, kind in FORBIDDEN.items():
                if marker in line:
                    violations.append({"path": workflow["path"], "line": line_number, "kind": kind})
    return {"repository": full_name, "violations": violations}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--allow-migration", action="store_true")
    parser.add_argument("--workers", type=int, default=8)
    args = parser.parse_args()
    inventory = json.loads((ROOT / "inventory/repos.json").read_text(encoding="utf-8"))
    results: list[dict[str, Any]] = []
    with ThreadPoolExecutor(max_workers=args.workers) as executor:
        futures = [executor.submit(audit_repository, repo) for repo in inventory["repositories"]]
        for future in as_completed(futures):
            results.append(future.result())
    results.sort(key=lambda item: item["repository"].lower())
    violations = sum(len(item["violations"]) for item in results)
    report = {
        "schema_version": "qdev-runner-workflow-audit-v1",
        "repositories": len(results),
        "violations": violations,
        "results": results,
    }
    print(json.dumps(report, indent=2))
    if violations and not args.allow_migration:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
