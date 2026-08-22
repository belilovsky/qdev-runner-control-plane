from __future__ import annotations

import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "rewrite_github_dependencies.py"
SPEC = importlib.util.spec_from_file_location("rewrite_github_dependencies", SCRIPT)
assert SPEC and SPEC.loader
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def test_rewrites_cache_and_artifact_steps() -> None:
    source = """steps:
      - uses: actions/setup-python@abc
        with:
          cache: pip
          cache-dependency-path: |
            requirements.txt
            requirements-dev.txt
      - name: Cache pip
        uses: actions/cache@abc
        with:
          path: ~/.cache/pip
      - name: Upload proof
        if: always()
        uses: actions/upload-artifact@abc
        with:
          name: proof-${{ github.sha }}
          path: |
            output/proof.json
            output/SHA256SUMS
          if-no-files-found: warn
"""
    rewritten = MODULE.rewrite(source)
    assert "actions/cache" not in rewritten
    assert "actions/upload-artifact" not in rewritten
    assert "cache: pip" not in rewritten
    assert "requirements-dev.txt" not in rewritten
    assert "QDEV_IF_NO_FILES: warn" in rewritten
    assert ".github/scripts/qdev-upload-artifact.sh 'proof-${{ github.sha }}'" in rewritten
    assert "output/proof.json output/SHA256SUMS" in rewritten
