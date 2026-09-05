#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'usage: %s EXACT_RELEASE_SHA\n' "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
target="/opt/qdev-runner-control-plane/releases/$1"
status_path="${QDEV_CONTROLLER_RELEASE_STATUS:-/var/lib/qdev-runner/controller-status/controller-release.json}"
current_revision="$(python3 - "$status_path" <<'PY'
import json
import pathlib
import re
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
revision = payload.get("revision")
if (
    payload.get("schema") not in {
        "qdev-controller-release-status-v1", "qdev-controller-release-status-v2"
    }
    or payload.get("state") != "active"
    or not isinstance(revision, str)
    or re.fullmatch(r"[0-9a-f]{40}", revision) is None
):
    raise SystemExit("active controller release status is invalid")
print(revision)
PY
)"
QDEV_CONTROLLER_NO_BUILD=true \
QDEV_CONTROLLER_ROLLBACK=true \
QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION="$current_revision" \
  "$script_dir/activate_controller_release.sh" "$target"
