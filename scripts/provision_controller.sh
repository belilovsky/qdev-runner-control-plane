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
    if (used > 94 || free < 8388608 || mem < 4194304 || load15 > (2 * cpus)) exit 1
  }' || {
    printf 'capacity gate rejected controller provisioning\n' >&2
    exit 1
  }

install -d -o root -g root -m 0755 /opt/qdev-runner-control-plane
install -d -o root -g root -m 0755 /opt/qdev-runner-control-plane/releases
install -d -o root -g root -m 0755 /etc/qdev-runner
install -d -o root -g root -m 0755 /etc/qdev-runner/mtls
install -d -o root -g 9020 -m 0750 /etc/qdev-runner/mtls/controller
install -d -o root -g 9020 -m 0750 /etc/qdev-runner/mtls/operator
install -d -o root -g 9020 -m 0750 /var/lib/qdev-runner
install -d -o 9020 -g 9020 -m 0750 /var/lib/qdev-runner/artifacts
install -d -o 9020 -g 9020 -m 0700 /var/lib/qdev-runner/broker-state
install -d -o 9020 -g 9020 -m 0700 /var/lib/qdev-runner/control-state
install -d -o 9020 -g 9020 -m 0700 /var/lib/qdev-runner/admin-platform-receipts
install -d -o root -g root -m 0755 /var/lib/qdev-runner/controller-status
install -d -o root -g root -m 0755 /var/lib/qdev-runner/admin-platform-state
install -d -o root -g root -m 0700 /var/lib/qdev-runner/controller-status-migrations
install -d -o root -g root -m 0700 /var/lib/qdev-runner/admin-platform-bootstrap
install -d -o root -g root -m 0700 /var/lib/qdev-runner/admin-platform-ledger-migrations
install -d -o 9020 -g 9020 -m 0700 /var/lib/qdev-runner/release-jobs
install -d -o 9020 -g 9020 -m 0700 /var/lib/qdev-runner/operations
install -d -o 9020 -g 9020 -m 0700 /var/lib/qdev-runner/operations/fleet-bootstrap
install -d -o 9020 -g 9020 -m 0700 /var/lib/qdev-runner/operations/fleet-bootstrap-receipts
# The broker can create immutable requests only in incoming and can read only
# results.  Claimed requests and started markers stay in the root-only
# processing directory across dispatcher crashes and broker restarts.
install -d -o root -g root -m 0755 /var/lib/qdev-runner/fleet-host-dispatch
install -d -o 9020 -g 9020 -m 0700 /var/lib/qdev-runner/fleet-host-dispatch/incoming
install -d -o root -g root -m 0700 /var/lib/qdev-runner/fleet-host-dispatch/processing
install -d -o root -g 9020 -m 0750 /var/lib/qdev-runner/fleet-host-dispatch/results
install -d -o root -g root -m 0750 /var/lib/qdev-runner/registry
install -d -o 9020 -g 9020 -m 0750 /var/log/qdev-runner
install -d -o root -g root -m 0755 /usr/local/libexec
install -o root -g root -m 0755 scripts/dispatch_fleet_bootstrap.py \
  /usr/local/libexec/qdev-fleet-host-dispatch
install -d -o root -g root -m 0755 /usr/local/sbin
install -o root -g root -m 0755 scripts/bootstrap_admin_platform_ledger_v3.py \
  /usr/local/sbin/qdev-admin-platform-ledger-bootstrap
install -o root -g root -m 0755 scripts/qdev_controller_activation_adapter.py \
  /usr/local/sbin/qdev-controller-activate
install -o root -g root -m 0755 scripts/qdev_release_host_agent_enrol_adapter.py \
  /usr/local/sbin/qdev-release-host-agent-enrol
install -o root -g root -m 0755 scripts/qdev_fleet_worker_recovery_adapter.py \
  /usr/local/sbin/qdev-fleet-worker-recovery
install -o root -g root -m 0755 scripts/provision_fleet_host_dispatch_state.py \
  /usr/local/sbin/qdev-fleet-host-dispatch-state-provision
/usr/local/sbin/qdev-fleet-host-dispatch-state-provision
install -m 0644 deploy/qdev-runner-broker.service /etc/systemd/system/qdev-runner-broker.service
install -m 0644 deploy/qdev-artifact-retention.service /etc/systemd/system/qdev-artifact-retention.service
install -m 0644 deploy/qdev-artifact-retention.timer /etc/systemd/system/qdev-artifact-retention.timer
install -m 0644 deploy/qdev-fleet-host-dispatch.service \
  /etc/systemd/system/qdev-fleet-host-dispatch.service
install -m 0644 deploy/qdev-fleet-host-dispatch.path \
  /etc/systemd/system/qdev-fleet-host-dispatch.path
systemctl daemon-reload
systemctl enable qdev-artifact-retention.timer
systemctl enable --now qdev-fleet-host-dispatch.path
# Reconcile any processing record that survived a dispatcher or host crash.
systemctl start qdev-fleet-host-dispatch.service
printf 'controller provisioning complete; install broker.env, GitHub App key and mTLS files before start\n'
