#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || ! "$1" =~ ^[a-z0-9][a-z0-9-]{7,79}$ ]]; then
  printf 'usage: %s TRANSACTION_ID\n' "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
# A revision alone cannot identify the old image/configuration pair. Restore
# only the durable transaction made by release_controller_exact.py.
exec python3 "$script_dir/release_controller_exact.py" --rollback-transaction "$1"
