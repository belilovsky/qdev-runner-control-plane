#!/usr/bin/env bash
set -euo pipefail

# The controller's in-container operator runs as the unprivileged qdev-runner
# account (uid/gid 9020).  The operator certificate is issued externally; this
# helper deliberately never creates, reads, copies, rotates, chmods, or chowns
# key material. Activation is validation-only: identity bytes and metadata are
# provisioned out of band and must already be exact before the cycle starts.

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi

operator_dir=/etc/qdev-runner/mtls/operator
if [[ ! -d "$operator_dir" || -L "$operator_dir" ]]; then
  printf 'operator mTLS directory is missing or unsafe: %s\n' "$operator_dir" >&2
  exit 66
fi

if [[ "$(stat -c '%u:%g:%a' -- "$operator_dir")" != "0:9020:750" ]]; then
  printf 'operator mTLS directory ownership or mode is invalid: %s\n' "$operator_dir" >&2
  exit 77
fi

for credential in ca.pem operator-cert.pem operator-key.pem; do
  path="$operator_dir/$credential"
  if [[ ! -f "$path" || -L "$path" ]]; then
    printf 'operator mTLS credential is missing or unsafe: %s\n' "$path" >&2
    exit 66
  fi
  if [[ "$(stat -c '%u:%g:%a' -- "$path")" != "0:9020:640" ]]; then
    printf 'operator mTLS credential ownership or mode is invalid: %s\n' "$path" >&2
    exit 77
  fi
done

printf 'operator mTLS identity metadata validated without mutation\n'
