from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType
from typing import Any


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


def test_controller_dispatch_payload_includes_exact_recovery_inputs() -> None:
    script = load_script()

    assert script.workflow_dispatch_payload(
        "belilovsky/qdev-runner-control-plane", "main", "a" * 40
    ) == {
        "ref": "main",
        "inputs": {
            "execution_lane": "recovery",
            "expected_sha": "a" * 40,
            "owner_recovery": True,
        },
    }


def test_product_dispatch_payload_preserves_existing_contract() -> None:
    script = load_script()

    assert script.workflow_dispatch_payload("belilovsky/qazgeo", "main", "b" * 40) == {
        "ref": "main"
    }


def test_dispatch_batch_posts_controller_recovery_inputs() -> None:
    script = load_script()

    class FakeGitHub:
        def __init__(self) -> None:
            self.requests: list[tuple[str, str, dict[str, Any]]] = []
            self.dispatched = False

        def json(self, method: str, endpoint: str, **kwargs: Any) -> dict[str, Any] | None:
            self.requests.append((method, endpoint, kwargs))
            if endpoint.endswith("/branches/main"):
                return {"commit": {"sha": "c" * 40}}
            if endpoint.endswith("/dispatches"):
                self.dispatched = True
                return None
            if "runner-smoke.yml/runs" in endpoint:
                if not self.dispatched:
                    return {"workflow_runs": []}
                return {
                    "workflow_runs": [
                        {
                            "id": 42,
                            "head_sha": "c" * 40,
                            "status": "completed",
                            "conclusion": "success",
                            "html_url": "https://example.invalid/run/42",
                        }
                    ]
                }
            if endpoint.endswith("/actions/runs/42/jobs?per_page=20"):
                return {
                    "jobs": [
                        {
                            "name": "runner-smoke",
                            "runner_name": "ephemeral-42",
                            "conclusion": "success",
                        }
                    ]
                }
            raise AssertionError((method, endpoint, kwargs))

    github = FakeGitHub()
    receipts = script.dispatch_batch(
        github,
        [
            {
                "full_name": "belilovsky/qdev-runner-control-plane",
                "default_branch": "main",
            }
        ],
        poll_seconds=0,
        timeout_seconds=1,
    )

    dispatch = next(request for request in github.requests if request[1].endswith("/dispatches"))
    assert dispatch[2]["json"] == {
        "ref": "main",
        "inputs": {
            "execution_lane": "recovery",
            "expected_sha": "c" * 40,
            "owner_recovery": True,
        },
    }
    assert receipts[0]["sha"] == "c" * 40
    assert receipts[0]["conclusion"] == "success"
