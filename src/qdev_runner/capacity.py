from __future__ import annotations

import math
import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Capacity:
    allowed: bool
    disk_used_pct: float
    disk_free_gib: float
    memory_available_gib: float
    load_15: float
    cpu_psi_avg10: float
    cpus: int
    blockers: tuple[str, ...]


def evaluate(
    measured: Capacity,
    *,
    min_disk_free_gib: float,
    max_disk_used_pct: float,
    min_memory_available_gib: float,
    max_load_per_cpu: float,
    max_cpu_psi_avg10: float | None,
) -> Capacity:
    """Re-evaluate measured host metrics against explicit admission thresholds."""
    blockers: list[str] = []
    metrics = (
        measured.disk_used_pct, measured.disk_free_gib, measured.memory_available_gib,
        measured.load_15, measured.cpu_psi_avg10, measured.cpus,
    )
    if (
        any(not math.isfinite(value) or value < 0 for value in metrics)
        or measured.cpus < 1 or measured.cpus != int(measured.cpus)
        or measured.disk_used_pct > 100 or measured.cpu_psi_avg10 > 100
    ):
        blockers.append("resource_measurements_missing_or_invalid")
    if measured.disk_used_pct >= max_disk_used_pct:
        blockers.append("disk_used_pct")
    if measured.disk_free_gib < min_disk_free_gib:
        blockers.append("disk_free_gib")
    if measured.memory_available_gib < min_memory_available_gib:
        blockers.append("memory_available_gib")
    if measured.load_15 >= measured.cpus * max_load_per_cpu:
        blockers.append("load_15")
    if max_cpu_psi_avg10 is not None and measured.cpu_psi_avg10 >= max_cpu_psi_avg10:
        blockers.append("cpu_psi_avg10")
    return Capacity(
        allowed=not blockers,
        disk_used_pct=measured.disk_used_pct,
        disk_free_gib=measured.disk_free_gib,
        memory_available_gib=measured.memory_available_gib,
        load_15=measured.load_15,
        cpu_psi_avg10=measured.cpu_psi_avg10,
        cpus=measured.cpus,
        blockers=tuple(blockers),
    )


def _cpu_psi_avg10(path: Path | None = None) -> float:
    path = path or Path("/proc/pressure/cpu")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return -1.0
    for line in lines:
        if not line.startswith("some "):
            continue
        for field in line.split()[1:]:
            name, _, raw_value = field.partition("=")
            if name == "avg10":
                try:
                    value = float(raw_value)
                except ValueError:
                    return -1.0
                return value if math.isfinite(value) and 0 <= value <= 100 else -1.0
    return -1.0


def measure_raw(
    path: Path | None = None,
    *,
    meminfo_path: Path | None = None,
    cpu_psi_path: Path | None = None,
) -> Capacity:
    """Measure host capacity without applying any admission policy."""
    path = path or Path("/")
    meminfo_path = meminfo_path or Path("/proc/meminfo")
    disk = os.statvfs(path)
    disk_total = disk.f_blocks * disk.f_frsize
    disk_free = disk.f_bavail * disk.f_frsize
    disk_used_pct = 100.0 * (disk_total - disk_free) / max(1, disk_total)
    memory_available_kib = 0
    for line in meminfo_path.read_text(encoding="utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            memory_available_kib = int(line.split()[1])
            break
    load_15 = os.getloadavg()[2]
    cpu_psi_avg10 = _cpu_psi_avg10(cpu_psi_path)
    cpus = os.cpu_count() or 0
    disk_free_gib = disk_free / 1024**3
    memory_available_gib = memory_available_kib / 1024**2
    return Capacity(
        allowed=True,
        disk_used_pct=round(disk_used_pct, 2),
        disk_free_gib=round(disk_free_gib, 2),
        memory_available_gib=round(memory_available_gib, 2),
        load_15=round(load_15, 2),
        cpu_psi_avg10=round(cpu_psi_avg10, 2),
        cpus=cpus,
        blockers=(),
    )


def measure(
    path: Path | None = None,
    *,
    min_disk_free_gib: float = 30,
    max_disk_used_pct: float = 85,
    min_memory_available_gib: float = 4,
    max_load_per_cpu: float = 2,
    max_cpu_psi_avg10: float | None = None,
    meminfo_path: Path | None = None,
    cpu_psi_path: Path | None = None,
) -> Capacity:
    measured = measure_raw(
        path,
        meminfo_path=meminfo_path,
        cpu_psi_path=cpu_psi_path,
    )
    return evaluate(
        measured,
        min_disk_free_gib=min_disk_free_gib,
        max_disk_used_pct=max_disk_used_pct,
        min_memory_available_gib=min_memory_available_gib,
        max_load_per_cpu=max_load_per_cpu,
        max_cpu_psi_avg10=max_cpu_psi_avg10,
    )
