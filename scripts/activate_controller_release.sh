#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi
if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s /opt/qdev-runner-control-plane/releases/RELEASE\n' "$0" >&2
  exit 64
fi

# Import only from the root-owned, immutable release selected by the verified
# activation request. The Python transaction retains the old images/config and
# recovers an interrupted native activation before accepting another one.
release="$(realpath -e -- "$1")"
case "$release" in
  /opt/qdev-runner-control-plane/releases/*) ;;
  *)
    printf 'release must be below /opt/qdev-runner-control-plane/releases\n' >&2
    exit 64
    ;;
esac
PYTHONPATH="$release/src" exec /usr/bin/python3 -m qdev_runner.controller_transaction "$release"
