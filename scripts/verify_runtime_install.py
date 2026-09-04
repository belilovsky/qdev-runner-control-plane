#!/usr/bin/env python3
"""Exercise the Docker runtime dependency path, isolated from development extras."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
import venv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    # Match Dockerfile.broker: lock first, package without dependency resolution.
    # A dev environment must never conceal a missing runtime requirement.
    with tempfile.TemporaryDirectory(prefix="qdev-runtime-install-") as temporary:
        source = Path(temporary) / "source"
        source.mkdir()
        for name in ("pyproject.toml", "requirements.runtime.txt", "README.md"):
            shutil.copy2(ROOT / name, source / name)
        shutil.copytree(
            ROOT / "src", source / "src", ignore=shutil.ignore_patterns("*.egg-info", "__pycache__")
        )
        environment = Path(temporary) / "venv"
        venv.EnvBuilder(with_pip=True).create(environment)
        python = str(environment / "bin/python")
        clean_env = dict(os.environ)
        clean_env.pop("PYTHONPATH", None)
        clean_env.pop("PYTHONHOME", None)
        commands = [
            [
                python,
                "-m",
                "pip",
                "install",
                "--no-cache-dir",
                "-r",
                str(source / "requirements.runtime.txt"),
            ],
            [python, "-m", "pip", "install", "--no-deps", str(source)],
            [python, "-m", "pip", "check"],
            [
                python,
                "-I",
                "-c",
                (
                    "import importlib, pkgutil, qdev_runner; "
                    "modules = sorted(m.name for m in pkgutil.walk_packages("
                    "qdev_runner.__path__, qdev_runner.__name__ + '.')); "
                    "[importlib.import_module(name) for name in modules]; "
                    "print('runtime_imports_ok', len(modules))"
                ),
            ],
        ]
        for command in commands:
            subprocess.run(command, cwd=temporary, env=clean_env, check=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
