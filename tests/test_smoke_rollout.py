from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType


def load_script() -> ModuleType:
    path = Path(__file__).resolve().parents[1] / "scripts/run_smoke_rollout.py"
    spec = importlib.util.spec_from_file_location("run_smoke_rollout", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_select_new_run_matches_sha_and_excludes_baseline() -> None:
    script = load_script()
    runs = [
        {"id": 10, "head_sha": "target"},
        {"id": 11, "head_sha": "other"},
        {"id": 12, "head_sha": "target"},
    ]

    assert script.select_new_run(runs, head_sha="target", previous_ids={10}) == runs[2]
    assert script.select_new_run(runs, head_sha="missing", previous_ids=set()) is None


def test_queue_seconds_uses_run_creation_and_runner_start() -> None:
    script = load_script()
    run = {"created_at": "2026-08-24T01:00:00Z"}
    job = {"started_at": "2026-08-24T01:03:12Z"}

    assert script.queue_seconds(run, job) == 192.0
    assert script.queue_seconds({}, job) is None
