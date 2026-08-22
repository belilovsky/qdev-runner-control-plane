#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi

disk_used="$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
disk_free_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
memory_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
cpu_count="$(nproc)"
load_15="$(awk '{print $3}' /proc/loadavg)"

awk -v used="$disk_used" -v free="$disk_free_kib" -v mem="$memory_kib" \
  -v cpus="$cpu_count" -v load15="$load_15" 'BEGIN {
    if (used > 85 || free < 31457280 || mem < 4194304 || load15 > (2 * cpus)) exit 1
  }' || {
    printf 'capacity gate rejected controller provisioning\n' >&2
    exit 1
  }

install -d -o root -g root -m 0755 /opt/qdev-runner-control-plane
install -d -o root -g root -m 0755 /opt/qdev-runner-control-plane/releases
install -d -o root -g root -m 0750 /etc/qdev-runner
install -d -o root -g root -m 0755 /etc/qdev-runner/mtls
install -d -o root -g root -m 0700 /etc/qdev-runner/mtls/controller
install -d -o 9020 -g 9020 -m 0750 /var/lib/qdev-runner
install -d -o 9020 -g 9020 -m 0750 /var/lib/qdev-runner/artifacts
install -d -o root -g root -m 0750 /var/lib/qdev-runner/registry
install -d -o 9020 -g 9020 -m 0750 /var/log/qdev-runner
install -m 0644 deploy/qdev-runner-broker.service /etc/systemd/system/qdev-runner-broker.service
install -m 0644 deploy/qdev-artifact-retention.service /etc/systemd/system/qdev-artifact-retention.service
install -m 0644 deploy/qdev-artifact-retention.timer /etc/systemd/system/qdev-artifact-retention.timer
systemctl daemon-reload
systemctl enable qdev-artifact-retention.timer
printf 'controller provisioning complete; install broker.env, GitHub App key and mTLS files before start\n'
