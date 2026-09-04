#!/usr/bin/env python3
"""Validate a non-secret immutable runner-image release manifest."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from qdev_runner.runner_image_release import RunnerImageReleaseError, load


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--expected-revision")
    parser.add_argument("--verify-evidence", action="store_true")
    args = parser.parse_args()
    try:
        references, manifest_digest = load(
            args.manifest,
            expected_revision=args.expected_revision,
            strict_evidence=args.verify_evidence,
        )
    except RunnerImageReleaseError as error:
        print(f"runner_image_release=failed reason={error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {
                "schema": "qdev-runner-image-release-validation-v1",
                "status": "passed",
                "manifest_digest": manifest_digest,
                "artifacts": sorted(references),
                "evidence_verified": args.verify_evidence,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
