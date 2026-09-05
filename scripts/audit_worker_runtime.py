#!/usr/bin/env python3
"""Compatibility entrypoint for the packaged worker runtime audit."""

from qdev_runner.worker_runtime_audit import main

if __name__ == "__main__":
    raise SystemExit(main())
