#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9a-f]{7,40}$ ]]; then
  printf 'usage: %s RELEASE_ID\n' "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
target="/opt/qdev-runner-control-plane/releases/$1"
QDEV_CONTROLLER_NO_BUILD=true "$script_dir/activate_controller_release.sh" "$target"
