#!/usr/bin/env python3
"""Build an immutable QazCoop verifier bundle from an exact controller revision."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

REPOSITORY_ID = 1_357_887_516
REPOSITORY = "belilovsky/qazcoop"
PROTECTED_REF = "refs/heads/codex/qazcoop-mvp"


def digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def require_regular(path: Path, label: str) -> None:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} is unavailable")
    info = path.stat()
    if info.st_mode & 0o022:
        raise ValueError(f"{label} is writable by group or other users")


def build_bundle(root: Path, revision: str, public_key: Path, output: Path) -> None:
    observed = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=root, check=True, capture_output=True, text=True
    ).stdout.strip()
    if observed != revision or len(revision) != 40:
        raise ValueError("bundle revision must equal the exact source HEAD")
    require_regular(public_key, "controller public key")
    if output.exists() or output.is_symlink():
        raise ValueError("bundle output already exists")
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = Path(tempfile.mkdtemp(prefix=f".{output.name}.", dir=output.parent))
    try:
        layout = {
            "public.pem": (public_key, temporary / "trust/public.pem", 0o644),
            "admission.schema.json": (
                root / "docs/schemas/qdev-ci-controller-admission-v1.schema.json",
                temporary / "trust/admission.schema.json",
                0o644,
            ),
            "controller_admission.py": (
                root / "src/qdev_runner/controller_admission.py",
                temporary / "lib/qdev_runner/controller_admission.py",
                0o644,
            ),
            "qazcoop_release_guard.py": (
                root / "src/qdev_runner/qazcoop_release_guard.py",
                temporary / "lib/qdev_runner/qazcoop_release_guard.py",
                0o644,
            ),
            "qazcoop-update": (
                root / "scripts/qazcoop_update_hook.py",
                temporary / "bin/qazcoop-update",
                0o755,
            ),
        }
        for source, target, mode in layout.values():
            label = (
                str(source.relative_to(root))
                if source.is_relative_to(root)
                else str(source)
            )
            require_regular(source, label)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
            target.chmod(mode)
        package = temporary / "lib/qdev_runner/__init__.py"
        package.write_text("\"\"\"QDev controller release guard runtime.\"\"\"\n", encoding="utf-8")
        package.chmod(0o644)
        launcher = temporary / "bin/qdev-controller-verify-admission"
        launcher.write_text(
            "#!/usr/bin/env bash\n"
            "set -euo pipefail\n"
            f"guard_root=/usr/local/lib/qazcoop-release-guard/{revision}\n"
            "export PYTHONPATH=\"$guard_root/lib\"\n"
            "export QAZCOOP_GUARD_LAUNCHER=/usr/local/sbin/qdev-controller-verify-admission\n"
            "export QAZCOOP_GUARD_HOOK=/opt/qazcoop.git/hooks/update\n"
            "exec python3 -m qdev_runner.qazcoop_release_guard \"$@\"\n",
            encoding="utf-8",
        )
        launcher.chmod(0o755)
        files = {
            name: digest(
                {
                    "public.pem": temporary / "trust/public.pem",
                    "admission.schema.json": temporary / "trust/admission.schema.json",
                    "controller_admission.py": temporary
                    / "lib/qdev_runner/controller_admission.py",
                    "qazcoop_release_guard.py": temporary
                    / "lib/qdev_runner/qazcoop_release_guard.py",
                    "qdev-controller-verify-admission": launcher,
                    "qazcoop-update": temporary / "bin/qazcoop-update",
                }[name]
            )
            for name in (
                "public.pem",
                "admission.schema.json",
                "controller_admission.py",
                "qazcoop_release_guard.py",
                "qdev-controller-verify-admission",
                "qazcoop-update",
            )
        }
        manifest = {
            "contract": "qazcoop-release-guard-trust-bundle/v1",
            "controller_revision": revision,
            "repository": {
                "id": REPOSITORY_ID,
                "full_name": REPOSITORY,
                "protected_ref": PROTECTED_REF,
            },
            "files": files,
        }
        (temporary / "bundle.json").write_text(
            json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        (temporary / "bundle.json").chmod(0o644)
        os.replace(temporary, output)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--controller-repository", type=Path, required=True)
    parser.add_argument("--controller-revision", required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    build_bundle(
        args.controller_repository.resolve(strict=True),
        args.controller_revision,
        args.public_key.resolve(strict=True),
        args.output,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
