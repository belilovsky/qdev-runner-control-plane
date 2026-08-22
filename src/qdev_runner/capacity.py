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
    cpus: int
    blockers: tuple[str, ...]


def measure(path: Path = Path("/")) -> Capacity:
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
    cpus = os.cpu_count() or 1
    blockers: list[str] = []
    disk_free_gib = disk_free / 1024**3
    memory_available_gib = memory_available_kib / 1024**2
    if disk_used_pct > 85:
        blockers.append("disk_used_pct")
    if disk_free_gib < 30:
        blockers.append("disk_free_gib")
    if memory_available_gib < 4:
        blockers.append("memory_available_gib")
    if load_15 > cpus * 2:
        blockers.append("load_15")
    return Capacity(
        allowed=not blockers,
        disk_used_pct=round(disk_used_pct, 2),
        disk_free_gib=round(disk_free_gib, 2),
        memory_available_gib=round(memory_available_gib, 2),
        load_15=round(load_15, 2),
        cpus=cpus,
        blockers=tuple(blockers),
    )
