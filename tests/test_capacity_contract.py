"""One published capacity contract across code, scripts and documentation."""

from __future__ import annotations

import importlib.util
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from qdev_runner.claim_scope import MAX_TTL
from qdev_runner.operations import (
    HARD_MAX_DISK_USED_PCT,
    HARD_MIN_FREE_GIB,
    MAX_OVERRIDE_SECONDS,
    OperationStore,
)

ROOT = Path(__file__).resolve().parents[1]
GATE = ROOT / "scripts" / "controller_capacity_gate.py"
CAPACITY_CONFIG = ROOT / "config" / "controller-capacity.json"


def _load_gate():
    spec = importlib.util.spec_from_file_location("controller_capacity_gate", GATE)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run_gate(
    *, max_disk_used_pct: int, min_free_gib: float, disk_used_pct: float = 50
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [
            sys.executable,
            str(GATE),
            "--capacity-config",
            str(CAPACITY_CONFIG),
            "--disk-used-pct",
            str(disk_used_pct),
            "--disk-free-kib",
            str(64 * 1024 * 1024),
            "--memory-kib",
            str(16 * 1024 * 1024),
            "--cpu-count",
            "4",
            "--load-15",
            "1",
            "--max-disk-used-pct",
            str(max_disk_used_pct),
            "--min-free-gib",
            str(min_free_gib),
            "--min-memory-gib",
            "4",
            "--max-load-per-cpu",
            "2",
            "--no-build",
            "true",
        ],
        capture_output=True,
        text=True,
        check=False,
    )


def test_published_bounds_are_identical_in_operations_and_the_activation_gate() -> None:
    gate = _load_gate()

    assert gate.HARD_MIN_FREE_GIB == HARD_MIN_FREE_GIB == 4.5
    assert gate.HARD_MAX_DISK_USED_PCT == HARD_MAX_DISK_USED_PCT == 90.0
    assert MAX_OVERRIDE_SECONDS == 900
    assert int(MAX_TTL.total_seconds()) == 900


@pytest.mark.parametrize("ceiling", (91, 95, 97))
def test_activation_gate_rejects_usage_above_ninety_percent(ceiling: int) -> None:
    result = _run_gate(max_disk_used_pct=ceiling, min_free_gib=8)

    assert result.returncode != 0
    assert "must not exceed 90" in result.stderr


@pytest.mark.parametrize("floor", (4, 4.4))
def test_activation_gate_rejects_free_space_below_the_hard_floor(floor: float) -> None:
    result = _run_gate(max_disk_used_pct=90, min_free_gib=floor)

    assert result.returncode != 0
    assert "at least 4.5 GiB" in result.stderr


def test_activation_gate_accepts_only_the_published_bound() -> None:
    assert _run_gate(max_disk_used_pct=90, min_free_gib=4.5).returncode == 0
    assert _run_gate(max_disk_used_pct=85, min_free_gib=30).returncode == 0


def test_activation_gate_clamps_only_the_legacy_incumbent_ceiling() -> None:
    """The immutable incumbent (eb9eea64) payload transmits 96 percent.

    A candidate release must stay activatable from that incumbent, so exactly
    that legacy default is clamped to the published ceiling while every other
    above-ceiling override keeps failing closed.
    """

    accepted = _run_gate(max_disk_used_pct=96, min_free_gib=8)
    assert accepted.returncode == 0
    assert "legacy incumbent ceiling 96 clamped to 90%" in accepted.stderr

    # The clamp really is the published ceiling: usage above it is refused.
    assert _run_gate(max_disk_used_pct=96, min_free_gib=8, disk_used_pct=91).returncode == 1

    for ceiling in (92, 93, 94):
        rejected = _run_gate(max_disk_used_pct=ceiling, min_free_gib=8)
        assert rejected.returncode != 0
        assert "must not exceed 90" in rejected.stderr


def test_published_legacy_incumbent_ceiling_constant() -> None:
    gate = _load_gate()

    # Release eb9eea64's payload ships this unset default; it must never be a
    # value an operator or a release may request as a real ceiling.
    assert gate.LEGACY_INCUMBENT_MAX_DISK_USED_PCT == 96
    assert gate.LEGACY_INCUMBENT_MAX_DISK_USED_PCT > gate.HARD_MAX_DISK_USED_PCT


def test_shell_activation_and_provisioning_share_the_same_ceiling() -> None:
    payload = (ROOT / "scripts/activate_controller_release_payload.sh").read_text(encoding="utf-8")
    provision = (ROOT / "scripts/provision_worker.sh").read_text(encoding="utf-8")

    assert "QDEV_CONTROLLER_MAX_DISK_USED_PCT:-90" in payload
    assert "max_disk_used_pct > 90" in payload
    assert "min_free_gib < 5" in payload
    assert "provision_max_disk_used_pct > 90" in provision
    assert "> 95" not in provision
    assert "tier_max_disk_used_pct=90" in provision


def test_ttl_longer_than_nine_hundred_seconds_is_rejected(tmp_path: Path) -> None:
    store = OperationStore(
        tmp_path / "operations",
        worker_signing_key="worker-signing-key",
        receipt_signing_key="receipt-signing-key",
    )
    issued = datetime(2026, 9, 11, 12, 0, tzinfo=UTC)

    with pytest.raises(ValueError, match="outside the allowed range"):
        store.create_capacity_override(
            worker_name="srv1879763-primary",
            repository="belilovsky/qazgeo",
            head_sha="a" * 40,
            profiles=("qdev-ci",),
            min_disk_free_gib=HARD_MIN_FREE_GIB,
            max_disk_used_pct=HARD_MAX_DISK_USED_PCT,
            owner="owner",
            reason="reason",
            duration_seconds=901,
            now=issued,
        )

    directive = store.create_capacity_override(
        worker_name="srv1879763-primary",
        repository="belilovsky/qazgeo",
        head_sha="a" * 40,
        profiles=("qdev-ci",),
        min_disk_free_gib=HARD_MIN_FREE_GIB,
        max_disk_used_pct=HARD_MAX_DISK_USED_PCT,
        owner="owner",
        reason="bounded exact-SHA FIFO recovery",
        duration_seconds=900,
        now=issued,
    )
    assert directive.min_disk_free_gib == 4.5
    assert directive.max_disk_used_pct == 90.0
    assert datetime.fromisoformat(
        directive.expires_at.replace("Z", "+00:00")
    ) - datetime.fromisoformat(directive.issued_at.replace("Z", "+00:00")) == timedelta(seconds=900)


def test_repository_documentation_states_the_same_bounds() -> None:
    recovery = (ROOT / "docs/controller-capacity-recovery.md").read_text(encoding="utf-8")
    operating = (ROOT / "docs/github-actions-operating-model.md").read_text(encoding="utf-8")

    assert "4.5 GiB free and 90% maximum use" in recovery
    assert "within 900 seconds" in recovery
    assert "clamps it to the published 90% ceiling" in recovery
    assert "30 GiB free and 85% used" in operating
    assert "10 GiB/90%" in operating
