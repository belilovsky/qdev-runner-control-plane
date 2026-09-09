#!/usr/bin/python3
"""Issue and stage fixed, root-owned controller activation assets.

The fleet adapter reads only its fixed activation spool. This CLI captures the
current activation state under the same lock as activation, produces an
unsigned offline-signing input, and stages only verified signed assets there.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

# This CLI can run from a candidate release immediately before that release is
# activated. Do not allow imports to alter the release-tree fingerprint.
sys.dont_write_bytecode = True

RELEASES_ROOT = Path("/opt/qdev-runner-control-plane/releases")
CURRENT_RELEASE = Path("/opt/qdev-runner-control-plane/current")
ASSETS_ROOT = Path("/var/lib/qdev-runner/controller-activation")
ACTIVATION_STATUS_PATH = ASSETS_ROOT / "activation-status.json"
MEASURED_STATUS_PATH = Path("/var/lib/qdev-runner/controller-status/controller-release.json")
ACTIVATION_LOCK_PATH = Path("/run/lock/qdev-controller-activation.lock")
ACTIVATION_PUBLIC_KEY = Path("/etc/qdev-runner/trust/controller-activation-ed25519.pub")
ADMISSION_PUBLIC_KEY = Path("/etc/qdev-runner/admission/ed25519-public.pem")
TRUST_BINDING = Path("/etc/qdev-runner/trust/controller-activation-trust-binding.json")
INSTALLED_ACTIVATION_ADAPTER = Path("/usr/local/sbin/qdev-controller-activate")
ADAPTER_REPAIRS_ROOT = ASSETS_ROOT / "adapter-repairs"
CURRENT_CONFIG_FILES = {
    "repos.json": Path("/etc/qdev-runner/repos.json"),
    "profiles.yml": Path("/etc/qdev-runner/profiles.yml"),
    "release-lanes.yml": Path("/etc/qdev-runner/release-lanes.yml"),
    "managed-registry.yml": Path("/etc/qdev-runner/managed-registry.yml"),
    "fleet-bootstrap.yml": Path("/etc/qdev-runner/fleet-bootstrap.yml"),
    "managed-release-ledger.yml": Path("/etc/qdev-runner/managed-release-ledger.yml"),
}
_SHA = re.compile(r"^[0-9a-f]{40}$")


def _source_root() -> Path:
    """Locate this release's source, or the active release for installed use."""

    local_release = Path(__file__).resolve().parents[1]
    local = local_release / "src"
    # The installed helper lives at /usr/local/sbin.  Some hosts also have a
    # generic /usr/local/src directory; that must never be mistaken for a
    # controller candidate.  A candidate is only a root-owned, exact-SHA
    # directory directly below the fixed release archive.
    is_candidate_location = (
        local_release.parent == RELEASES_ROOT and _SHA.fullmatch(local_release.name) is not None
    )
    if is_candidate_location:
        try:
            releases = RELEASES_ROOT.resolve(strict=True)
            releases_metadata = releases.lstat()
            metadata = local_release.lstat()
        except OSError as exc:
            raise RuntimeError("candidate controller source is unavailable") from exc
        if (
            local_release.parent != releases
            or not stat.S_ISDIR(releases_metadata.st_mode)
            or stat.S_ISLNK(releases_metadata.st_mode)
            or releases_metadata.st_uid != 0
            or stat.S_IMODE(releases_metadata.st_mode) & 0o022
            or not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise RuntimeError("candidate controller source is unsafe")
        return local
    try:
        current = CURRENT_RELEASE.resolve(strict=True)
        metadata = current.lstat()
    except OSError as exc:
        raise RuntimeError("active controller source is unavailable") from exc
    source = current / "src"
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not source.is_dir()
    ):
        raise RuntimeError("active controller source is unsafe")
    return source


SOURCE_ROOT = _source_root()
sys.path.insert(0, str(SOURCE_ROOT))

from qdev_runner.controller_activation_assets import (  # noqa: E402
    ControllerActivationAssetsError,
    activation_lifecycle_lock,
    repair_installed_activation_adapter,
    snapshot_and_issue_unsigned_activation_envelope,
    stage_activation_assets,
)


def _git(release: Path, *arguments: str) -> str:
    try:
        result = subprocess.run(  # noqa: S603
            ["/usr/bin/git", "-C", str(release), *arguments],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        raise ControllerActivationAssetsError(
            "controller release Git identity is unavailable"
        ) from exc
    return result.stdout.strip()


def _exact_release(argument: Path) -> tuple[Path, str]:
    """Accept only a clean root-owned release directory named for its HEAD SHA."""

    try:
        releases = RELEASES_ROOT.resolve(strict=True)
        release = argument.resolve(strict=True)
    except OSError as exc:
        raise ControllerActivationAssetsError("controller release is unavailable") from exc
    if release.parent != releases or not _SHA.fullmatch(release.name):
        raise ControllerActivationAssetsError("controller release is outside the release archive")
    for path in (releases, release):
        try:
            metadata = path.lstat()
        except OSError as exc:
            raise ControllerActivationAssetsError("controller release is unavailable") from exc
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or stat.S_ISLNK(metadata.st_mode)
            or metadata.st_uid != 0
            or stat.S_IMODE(metadata.st_mode) & 0o022
        ):
            raise ControllerActivationAssetsError("controller release ownership is unsafe")
    try:
        root = Path(_git(release, "rev-parse", "--show-toplevel")).resolve(strict=True)
    except OSError as exc:
        raise ControllerActivationAssetsError(
            "controller release Git identity is unavailable"
        ) from exc
    source_sha = _git(release, "rev-parse", "HEAD")
    if root != release or release.name != source_sha or not _SHA.fullmatch(source_sha):
        raise ControllerActivationAssetsError(
            "controller release path is not bound to its exact SHA"
        )
    if _git(release, "status", "--porcelain=v1", "--untracked-files=all"):
        raise ControllerActivationAssetsError("controller release contains uncommitted files")
    return release, source_sha


def _current_status_path() -> Path:
    """Use durable activation state when present, otherwise generation-zero status."""

    if ACTIVATION_STATUS_PATH.exists() or ACTIVATION_STATUS_PATH.is_symlink():
        return ACTIVATION_STATUS_PATH
    return MEASURED_STATUS_PATH


def issue(args: argparse.Namespace) -> dict[str, object]:
    release, source_sha = _exact_release(args.release)
    with activation_lifecycle_lock(ACTIVATION_LOCK_PATH):
        return snapshot_and_issue_unsigned_activation_envelope(
            release_root=release,
            source_sha=source_sha,
            artifact_manifest=args.artifact_manifest,
            assets_root=ASSETS_ROOT,
            current_status_path=_current_status_path(),
            current_config_files=CURRENT_CONFIG_FILES,
            transaction_id=args.transaction_id,
            ttl_seconds=args.ttl_seconds,
        )


def stage(args: argparse.Namespace) -> dict[str, object]:
    release, source_sha = _exact_release(args.release)
    with activation_lifecycle_lock(ACTIVATION_LOCK_PATH):
        return stage_activation_assets(
            release_root=release,
            source_sha=source_sha,
            artifact_manifest=args.artifact_manifest,
            signed_envelope=args.signed_envelope,
            assets_root=ASSETS_ROOT,
            activation_public_key=ACTIVATION_PUBLIC_KEY,
            admission_public_key=ADMISSION_PUBLIC_KEY,
            trust_binding=TRUST_BINDING,
        )


def repair_adapter(args: argparse.Namespace) -> dict[str, object]:
    release, source_sha = _exact_release(args.release)
    return repair_installed_activation_adapter(
        release_root=release,
        source_sha=source_sha,
        artifact_manifest=args.artifact_manifest,
        transaction_id=args.transaction_id,
        installed_adapter=INSTALLED_ACTIVATION_ADAPTER,
        expected_installed_sha256=args.expected_installed_sha256,
        expected_candidate_sha256=args.expected_candidate_sha256,
        repairs_root=ADAPTER_REPAIRS_ROOT,
    )


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser()
    commands = result.add_subparsers(dest="command", required=True)

    issue_parser = commands.add_parser("issue-unsigned")
    issue_parser.add_argument("--release", type=Path, required=True)
    issue_parser.add_argument("--artifact-manifest", type=Path, required=True)
    issue_parser.add_argument("--transaction-id", required=True)
    issue_parser.add_argument("--ttl-seconds", type=int, default=600)
    issue_parser.set_defaults(handler=issue)

    stage_parser = commands.add_parser("stage")
    stage_parser.add_argument("--release", type=Path, required=True)
    stage_parser.add_argument("--artifact-manifest", type=Path, required=True)
    stage_parser.add_argument("--signed-envelope", type=Path, required=True)
    stage_parser.set_defaults(handler=stage)

    repair_parser = commands.add_parser("repair-adapter")
    repair_parser.add_argument("--release", type=Path, required=True)
    repair_parser.add_argument("--artifact-manifest", type=Path, required=True)
    repair_parser.add_argument("--transaction-id", required=True)
    repair_parser.add_argument("--expected-installed-sha256", required=True)
    repair_parser.add_argument("--expected-candidate-sha256", required=True)
    repair_parser.set_defaults(handler=repair_adapter)
    return result


def main() -> int:
    args = parser().parse_args()
    if os.geteuid() != 0:
        raise SystemExit("controller activation asset preparation requires root")
    try:
        receipt = args.handler(args)
    except (ControllerActivationAssetsError, OSError) as exc:
        raise SystemExit(f"controller activation assets failed: {exc}") from exc
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
