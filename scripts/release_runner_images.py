#!/usr/bin/env python3
"""Create a cryptographically verified runner-image release manifest."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from qdev_runner.runner_image_publisher import ImageInput, initialize_key, publish
from qdev_runner.runner_image_release import (
    PROFILE_IMAGES,
    REQUIRED_IMAGES,
    required_images_for_profiles,
)


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
    parser.add_argument("--profile", action="append", choices=sorted(PROFILE_IMAGES))
    parser.add_argument("--general")
    parser.add_argument("--browser")
    parser.add_argument("--docker")
    parser.add_argument("--sidecar")
    parser.add_argument("--general-remediation", type=Path)
    parser.add_argument("--browser-remediation", type=Path)
    parser.add_argument("--docker-remediation", type=Path)
    parser.add_argument("--sidecar-remediation", type=Path)
    args = parser.parse_args()
    required = (
        required_images_for_profiles(args.profile) if args.profile is not None else REQUIRED_IMAGES
    )
    images = []
    for environment_key, prefix in (
        ("QDEV_RUNNER_IMAGE", "general"),
        ("QDEV_RUNNER_BROWSER_IMAGE", "browser"),
        ("QDEV_RUNNER_DOCKER_IMAGE", "docker"),
        ("QDEV_DOCKER_SIDECAR_IMAGE", "sidecar"),
    ):
        reference = getattr(args, prefix)
        remediation = getattr(args, prefix + "_remediation")
        if environment_key in required:
            if not reference:
                parser.error(f"--{prefix} is required for the selected release scope")
            images.append(
                ImageInput(
                    environment_key, prefix, reference, "images/runner/Dockerfile", remediation
                )
            )
        elif reference or remediation:
            parser.error(f"--{prefix} is outside the selected release scope")
    if args.initialize_signing_key:
        initialize_key(args.private_key, args.public_key)
    manifest = publish(
        repo=args.repo.resolve(),
        revision=args.revision,
        images=images,
        profiles=args.profile,
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
