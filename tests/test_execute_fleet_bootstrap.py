from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location(
    "qdev_test_execute_fleet_bootstrap", ROOT / "scripts" / "execute_fleet_bootstrap.py"
)
assert _SPEC is not None and _SPEC.loader is not None
executor = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(executor)


@pytest.mark.parametrize("active_jobs", [None, "0", "1", "-1"])
def test_legacy_worker_recovery_cannot_trust_caller_activity(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], active_jobs: str | None
) -> None:
    request = tmp_path / "request.json"
    request.write_text(
        json.dumps(
            {
                "schema": "qdev-fleet-bootstrap-request-v2",
                "action": "restore-existing-worker",
                "source_sha": "a" * 40,
                "run_id": 42,
                "job_id": 9001,
                "attempt": 1,
                "claim_ttl_seconds": 900,
                "worker_name": "qdev-qazstack-01",
            }
        ),
        encoding="utf-8",
    )
    state = tmp_path / "operation.json"
    receipt = tmp_path / "receipt.json"
    args = [
        "--request",
        str(request),
        "--idempotency-key",
        "legacy-recovery-test",
        "--operation-state",
        str(state),
        "--receipt",
        str(receipt),
    ]
    if active_jobs is not None:
        args.extend(["--active-jobs", active_jobs])
    assert executor.run(args) == 1
    assert "legacy worker recovery is retired" in capsys.readouterr().err
    assert not state.exists()
    assert not receipt.exists()
