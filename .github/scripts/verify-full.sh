#!/usr/bin/env bash
set -euo pipefail

# This is the single repository-local verification entrypoint shared by the
# hosted CI lane and the bounded self-hosted recovery lane.  Keeping the
# commands here identical prevents a recovery pass from proving a weaker
# contract than the normal provider check.
ruff check .
mypy
pytest -q
python .github/scripts/qdev-runner-policy.py --root .
git diff --check
