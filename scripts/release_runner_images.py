#!/usr/bin/env python3
"""Create a cryptographically verified runner-image release manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from qdev_runner.runner_image_publisher import ImageInput, initialize_key, publish


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", type=Path, default=Path.cwd())
    parser.add_argument("--revision", required=True)
    parser.add_argument("--evidence-root", required=True, type=Path)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--public-key", required=True, type=Path)
    parser.add_argument("--initialize-signing-key", action="store_true")
    parser.add_argument("--source-ci-run", required=True)
    parser.add_argument("--source-ci-status", required=True)
    parser.add_argument("--general", required=True)
    parser.add_argument("--browser", required=True)
    parser.add_argument("--docker", required=True)
    parser.add_argument("--sidecar", required=True)
    parser.add_argument("--general-remediation", type=Path)
    parser.add_argument("--browser-remediation", type=Path)
    parser.add_argument("--docker-remediation", type=Path)
    parser.add_argument("--sidecar-remediation", type=Path)
    args = parser.parse_args()
    if args.initialize_signing_key:
        initialize_key(args.private_key, args.public_key)
    manifest = publish(
        repo=args.repo.resolve(),
        revision=args.revision,
        images=[
            ImageInput(
                "QDEV_RUNNER_IMAGE",
                "general",
                args.general,
                "images/runner/Dockerfile",
                args.general_remediation,
            ),
            ImageInput(
                "QDEV_RUNNER_BROWSER_IMAGE",
                "browser",
                args.browser,
                "images/runner/Dockerfile",
                args.browser_remediation,
            ),
            ImageInput(
                "QDEV_RUNNER_DOCKER_IMAGE",
                "docker",
                args.docker,
                "images/runner/Dockerfile",
                args.docker_remediation,
            ),
            ImageInput(
                "QDEV_DOCKER_SIDECAR_IMAGE",
                "sidecar",
                args.sidecar,
                "images/runner/Dockerfile",
                args.sidecar_remediation,
            ),
        ],
        evidence_root=args.evidence_root,
        manifest_path=args.manifest,
        private_key_path=args.private_key,
        public_key_path=args.public_key,
        source_ci_run=args.source_ci_run,
        source_ci_status=args.source_ci_status,
    )
    print(json.dumps({"status": "passed", "schema": manifest["schema"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
