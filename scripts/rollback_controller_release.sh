#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9a-f]{7,40}$ ]]; then
  printf 'usage: %s RELEASE_ID\n' "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
target="/opt/qdev-runner-control-plane/releases/$1"
legacy_rollback=false
if [[ ! -f "$target/config/admin-platform-ledger-v2.yml" ]]; then
  # Older controller releases predate the Admin Platform v2 ledger and the
  # product adapters.  This flag is only derived by this controller-owned
  # rollback path; forward activation remains fail-closed on v2.
  legacy_rollback=true
fi
QDEV_CONTROLLER_NO_BUILD=true \
QDEV_CONTROLLER_LEGACY_ROLLBACK="$legacy_rollback" \
  "$script_dir/activate_controller_release.sh" "$target"
