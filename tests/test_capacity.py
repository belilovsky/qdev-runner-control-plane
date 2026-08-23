from __future__ import annotations

from pathlib import Path

import qdev_runner.capacity as capacity_module
from qdev_runner.capacity import measure


def _write_meminfo(path: Path, available_kib: int = 8 * 1024**2) -> None:
    path.write_text(f"MemAvailable: {available_kib} kB\n", encoding="utf-8")


def test_measure_enforces_configured_floor_load_and_psi(tmp_path: Path, monkeypatch) -> None:
    meminfo = tmp_path / "meminfo"
    psi = tmp_path / "cpu.pressure"
    _write_meminfo(meminfo)
    psi.write_text("some avg10=20.00 avg60=1.00 avg300=1.00 total=1\n", encoding="utf-8")
    monkeypatch.setattr(
        capacity_module,
        "Path",
        lambda value: meminfo if value == "/proc/meminfo" else Path(value),
    )
    monkeypatch.setattr(capacity_module.os, "getloadavg", lambda: (1.0, 1.0, 6.0))
    monkeypatch.setattr(capacity_module.os, "cpu_count", lambda: 4)

    result = measure(
        tmp_path,
        min_disk_free_gib=10_000,
        max_disk_used_pct=101,
        max_load_per_cpu=1.5,
        max_cpu_psi_avg10=20,
        cpu_psi_path=psi,
    )

    assert result.allowed is False
    assert result.blockers == ("disk_free_gib", "load_15", "cpu_psi_avg10")
    assert result.cpu_psi_avg10 == 20.0


def test_measure_allows_missing_cpu_psi_file(tmp_path: Path, monkeypatch) -> None:
    meminfo = tmp_path / "meminfo"
    _write_meminfo(meminfo)
    monkeypatch.setattr(
        capacity_module,
        "Path",
        lambda value: meminfo if value == "/proc/meminfo" else Path(value),
    )
    monkeypatch.setattr(capacity_module.os, "getloadavg", lambda: (0.1, 0.1, 0.1))
    monkeypatch.setattr(capacity_module.os, "cpu_count", lambda: 4)

    result = measure(
        tmp_path,
        min_disk_free_gib=0,
        max_disk_used_pct=101,
        max_cpu_psi_avg10=20,
        cpu_psi_path=tmp_path / "missing",
    )

    assert result.allowed is True
    assert result.cpu_psi_avg10 == 0.0
