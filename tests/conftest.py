from __future__ import annotations

import json
from pathlib import Path

import pytest


@pytest.fixture
def policy_files(tmp_path: Path) -> tuple[Path, Path]:
    inventory = tmp_path / "repos.json"
    inventory.write_text(
        json.dumps(
            {
                "repositories": [
                    {
                        "id": 1,
                        "full_name": "belilovsky/private-repo",
                        "private": True,
                        "archived": False,
                        "default_branch": "main",
                        "profiles": ["qdev-ci", "qdev-ci-browser", "qdev-ci-compose"],
                    },
                    {
                        "id": 2,
                        "full_name": "belilovsky/public-repo",
                        "private": False,
                        "archived": False,
                        "default_branch": "main",
                        "profiles": ["qdev-ci"],
                    },
                ]
            }
        ),
        encoding="utf-8",
    )
    profiles = tmp_path / "profiles.yml"
    profiles.write_text(
        """
profiles:
  qdev-ci:
    labels: [self-hosted, Linux, X64, qdev-ci]
    resources: {cpu: 1, memory_mb: 3072, disk_mb: 12288, pids_limit: 512}
    timeout_minutes: 45
    allow_public_pr: true
  qdev-ci-browser:
    labels: [self-hosted, Linux, X64, qdev-ci-browser]
    resources: {cpu: 2, memory_mb: 4096, disk_mb: 15360, pids_limit: 768}
    timeout_minutes: 60
    allow_public_pr: true
  qdev-ci-compose:
    labels: [self-hosted, Linux, X64, qdev-ci-compose]
    resources: {cpu: 1, memory_mb: 2048, disk_mb: 4096, pids_limit: 512}
    timeout_minutes: 15
    allow_public_pr: true
""".strip()
        + "\n",
        encoding="utf-8",
    )
    return inventory, profiles
