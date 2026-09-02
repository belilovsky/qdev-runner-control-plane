#!/usr/bin/env bash
set -euo pipefail

# The controller's in-container operator runs as the unprivileged qdev-runner
# account (uid/gid 9020).  The operator certificate is issued externally; this
# helper deliberately never creates, reads, copies, or rotates key material.
# It only restores the minimum traversal/read permissions needed for the
# controller to present its own mTLS identity to the broker.

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi

operator_dir=/etc/qdev-runner/mtls/operator
if [[ ! -d "$operator_dir" || -L "$operator_dir" ]]; then
  printf 'operator mTLS directory is missing or unsafe: %s\n' "$operator_dir" >&2
  exit 66
fi

for credential in ca.pem operator-cert.pem operator-key.pem; do
  path="$operator_dir/$credential"
  if [[ ! -f "$path" || -L "$path" ]]; then
    printf 'operator mTLS credential is missing or unsafe: %s\n' "$path" >&2
    exit 66
  fi
done

install -d -o root -g 9020 -m 0750 -- "$operator_dir"
for credential in ca.pem operator-cert.pem operator-key.pem; do
  path="$operator_dir/$credential"
  chown root:9020 -- "$path"
  chmod 0640 -- "$path"
done

printf 'operator mTLS identity permissions are ready for controller runtime uid/gid 9020\n'
