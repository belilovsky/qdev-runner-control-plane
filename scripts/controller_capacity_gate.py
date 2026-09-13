#!/usr/bin/env python3
"""Evaluate controller activation capacity without mutating host state."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

KIB = 1024
GIB = 1024**3

# Single published capacity contract for the exact, TTL-bounded controller
# claim.  These mirror ``qdev_runner.operations`` (which owns the operator
# directive bounds) and are duplicated here because this gate must stay
# import-free so it can run straight from the immutable release tree.
HARD_MIN_FREE_GIB = 4.5
HARD_MAX_DISK_USED_PCT = 90.0

# A controller update may be needed to restore the QazPolit release lane while
# the controller host is just above its normal 90% ceiling.  This is not a
# general override: the activation payload additionally pins the exception to
# one immutable release revision and removes it after activation.  The gate
# accepts it only for a no-build activation that keeps a materially larger
# reserve than the ordinary contract.
QAZPOLIT_BOOTSTRAP_CAPACITY_EXCEPTION = "qazpolit-controller-bootstrap-20260913"
QAZPOLIT_BOOTSTRAP_MAX_DISK_USED_PCT = 91
QAZPOLIT_BOOTSTRAP_MIN_FREE_GIB = 18
QAZPOLIT_BOOTSTRAP_MIN_MEMORY_GIB = 8
QAZPOLIT_BOOTSTRAP_MAX_LOAD_PER_CPU = 2

# The immutable incumbent activation payload (release eb9eea64...) transmits
# its unset ceiling default as 96 percent.  A candidate release has to stay
# activatable from that incumbent, so exactly that legacy default is accepted
# and clamped to the published ceiling below.  Every other value above the
# ceiling, including the 91, 95 and 97 percent overrides seen on hosts, is
# still rejected outright.
LEGACY_INCUMBENT_MAX_DISK_USED_PCT = 96


def capacity_allowed(
    *,
    disk_used_pct: float,
    disk_free_kib: int,
    memory_kib: int,
    cpu_count: int,
    load_15: float,
    max_disk_used_pct: int,
    min_free_gib: float,
    min_memory_gib: int,
    max_load_per_cpu: int,
    estimated_peak_incremental_bytes: int,
    no_build: bool,
) -> bool:
    required_free_bytes = min_free_gib * GIB
    if not no_build:
        required_free_bytes += estimated_peak_incremental_bytes
    return (
        disk_used_pct <= max_disk_used_pct
        and disk_free_kib * KIB >= required_free_bytes
        and memory_kib * KIB >= min_memory_gib * GIB
        and load_15 <= max_load_per_cpu * cpu_count
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--capacity-config", type=Path, required=True)
    parser.add_argument("--disk-used-pct", type=float, required=True)
    parser.add_argument("--disk-free-kib", type=int, required=True)
    parser.add_argument("--memory-kib", type=int, required=True)
    parser.add_argument("--cpu-count", type=int, required=True)
    parser.add_argument("--load-15", type=float, required=True)
    parser.add_argument("--max-disk-used-pct", type=int, required=True)
    parser.add_argument("--min-free-gib", type=float, required=True)
    parser.add_argument("--min-memory-gib", type=int, required=True)
    parser.add_argument("--max-load-per-cpu", type=int, required=True)
    parser.add_argument("--no-build", choices=("true", "false"), required=True)
    parser.add_argument("--capacity-exception", default="")
    args = parser.parse_args()

    # The absolute hard bounds are never overridable, except for the one
    # narrowly pinned QazPolit bootstrap described above.  Any other 91/95/97
    # percent request keeps failing closed.
    if args.min_free_gib < HARD_MIN_FREE_GIB:
        raise SystemExit(
            f"controller capacity minimum free space must be at least {HARD_MIN_FREE_GIB} GiB"
        )
    bootstrap_exception = (
        args.capacity_exception == QAZPOLIT_BOOTSTRAP_CAPACITY_EXCEPTION
        and args.max_disk_used_pct == QAZPOLIT_BOOTSTRAP_MAX_DISK_USED_PCT
        and args.min_free_gib == QAZPOLIT_BOOTSTRAP_MIN_FREE_GIB
        and args.min_memory_gib == QAZPOLIT_BOOTSTRAP_MIN_MEMORY_GIB
        and args.max_load_per_cpu == QAZPOLIT_BOOTSTRAP_MAX_LOAD_PER_CPU
        and args.no_build == "true"
    )
    if args.capacity_exception and not bootstrap_exception:
        raise SystemExit("controller capacity exception is invalid for this activation")
    if args.max_disk_used_pct > HARD_MAX_DISK_USED_PCT:
        if bootstrap_exception:
            max_disk_used_pct = QAZPOLIT_BOOTSTRAP_MAX_DISK_USED_PCT
        elif args.max_disk_used_pct == LEGACY_INCUMBENT_MAX_DISK_USED_PCT:
            print(
                "controller capacity legacy incumbent ceiling "
                f"{LEGACY_INCUMBENT_MAX_DISK_USED_PCT} clamped to {HARD_MAX_DISK_USED_PCT:g}%",
                file=sys.stderr,
            )
            max_disk_used_pct = int(HARD_MAX_DISK_USED_PCT)
        else:
            raise SystemExit(
                f"controller capacity disk usage must not exceed {HARD_MAX_DISK_USED_PCT:g}%"
            )
    else:
        max_disk_used_pct = args.max_disk_used_pct

    document = json.loads(args.capacity_config.read_text(encoding="utf-8"))
    peak = document.get("estimated_peak_incremental_bytes")
    if isinstance(peak, bool) or not isinstance(peak, int) or peak < 0:
        raise SystemExit("controller capacity estimated peak is invalid")
    admitted = capacity_allowed(
        disk_used_pct=args.disk_used_pct,
        disk_free_kib=args.disk_free_kib,
        memory_kib=args.memory_kib,
        cpu_count=args.cpu_count,
        load_15=args.load_15,
        max_disk_used_pct=max_disk_used_pct,
        min_free_gib=args.min_free_gib,
        min_memory_gib=args.min_memory_gib,
        max_load_per_cpu=args.max_load_per_cpu,
        estimated_peak_incremental_bytes=peak,
        no_build=args.no_build == "true",
    )
    return 0 if admitted else 1


if __name__ == "__main__":
    raise SystemExit(main())
