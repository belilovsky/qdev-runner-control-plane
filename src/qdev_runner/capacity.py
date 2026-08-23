from __future__ import annotations

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


def _cpu_psi_avg10(path: Path = Path("/proc/pressure/cpu")) -> float:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return 0.0
    for line in lines:
        if not line.startswith("some "):
            continue
        for field in line.split()[1:]:
            name, _, raw_value = field.partition("=")
            if name == "avg10":
                return float(raw_value)
    return 0.0


def measure(
    path: Path = Path("/"),
    *,
    min_disk_free_gib: float = 30,
    max_disk_used_pct: float = 85,
    min_memory_available_gib: float = 4,
    max_load_per_cpu: float = 2,
    max_cpu_psi_avg10: float | None = None,
    cpu_psi_path: Path = Path("/proc/pressure/cpu"),
) -> Capacity:
    disk = os.statvfs(path)
    disk_total = disk.f_blocks * disk.f_frsize
    disk_free = disk.f_bavail * disk.f_frsize
    disk_used_pct = 100.0 * (disk_total - disk_free) / max(1, disk_total)
    memory_available_kib = 0
    for line in Path("/proc/meminfo").read_text(encoding="utf-8").splitlines():
        if line.startswith("MemAvailable:"):
            memory_available_kib = int(line.split()[1])
            break
    load_15 = os.getloadavg()[2]
    cpu_psi_avg10 = _cpu_psi_avg10(cpu_psi_path)
    cpus = os.cpu_count() or 1
    blockers: list[str] = []
    disk_free_gib = disk_free / 1024**3
    memory_available_gib = memory_available_kib / 1024**2
    if disk_used_pct >= max_disk_used_pct:
        blockers.append("disk_used_pct")
    if disk_free_gib < min_disk_free_gib:
        blockers.append("disk_free_gib")
    if memory_available_gib < min_memory_available_gib:
        blockers.append("memory_available_gib")
    if load_15 >= cpus * max_load_per_cpu:
        blockers.append("load_15")
    if max_cpu_psi_avg10 is not None and cpu_psi_avg10 >= max_cpu_psi_avg10:
        blockers.append("cpu_psi_avg10")
    return Capacity(
        allowed=not blockers,
        disk_used_pct=round(disk_used_pct, 2),
        disk_free_gib=round(disk_free_gib, 2),
        memory_available_gib=round(memory_available_gib, 2),
        load_15=round(load_15, 2),
        cpu_psi_avg10=round(cpu_psi_avg10, 2),
        cpus=cpus,
        blockers=tuple(blockers),
    )
