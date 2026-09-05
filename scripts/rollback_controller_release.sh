#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi
if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9a-f]{32}$ ]]; then
  printf 'usage: %s TRANSACTION_ID\n' "$0" >&2
  exit 64
fi

current="$(realpath -e -- /opt/qdev-runner-control-plane/current)"
case "$current" in
  /opt/qdev-runner-control-plane/releases/*) ;;
  *)
    printf 'active controller release is outside the registered root\n' >&2
    exit 1
    ;;
esac

# The trusted active release interprets the root-private snapshot. The caller
# selects only the latest accepted transaction ID, never an arbitrary SHA/path.
PYTHONPATH="$current/src" exec /usr/bin/python3 -m qdev_runner.controller_transaction \
  --rollback "$1"
