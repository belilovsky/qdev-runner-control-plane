#!/usr/bin/python3
"""Drain the fixed root-owned fleet bootstrap dispatch spool.

This entrypoint intentionally accepts no arguments or environment-selected
paths.  Its source comes from the root-owned active controller release and
every mutable target is derived again from root-owned policy by the dispatcher.
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

RELEASES_ROOT = Path("/opt/qdev-runner-control-plane/releases")
ACTIVE_SOURCE = Path("/opt/qdev-runner-control-plane/current/src")


def _active_source() -> Path:
    try:
        releases_root = RELEASES_ROOT.resolve(strict=True)
        source = ACTIVE_SOURCE.resolve(strict=True)
    except OSError as error:
        raise RuntimeError("active controller release is unavailable") from error
    if source.parent.parent != releases_root:
        raise RuntimeError("active controller source is outside the release root")
    for path in (releases_root, source.parent, source):
        metadata = path.stat()
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise RuntimeError("active controller release ownership is unsafe")
    return source


def main() -> int:
    if os.geteuid() != 0:
        raise RuntimeError("fleet host dispatcher must run as root")
    sys.path.insert(0, str(_active_source()))

    # Import only after binding sys.path to the validated root-owned release.
    from qdev_runner.fleet_host_dispatch import FleetHostDispatcher

    dispatcher = FleetHostDispatcher(
        request_root=Path("/var/lib/qdev-runner/fleet-host-dispatch/incoming"),
        processing_root=Path("/var/lib/qdev-runner/fleet-host-dispatch/processing"),
        result_root=Path("/var/lib/qdev-runner/fleet-host-dispatch/results"),
        policy_path=Path("/etc/qdev-runner/fleet-bootstrap.yml"),
        release_lanes_path=Path("/etc/qdev-runner/release-lanes.yml"),
    )
    results = dispatcher.drain()
    print(
        json.dumps(
            {
                "schema": "qdev-fleet-host-dispatch-run-v1",
                "processed": len(results),
                "statuses": [result.status for result in results],
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
