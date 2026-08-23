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

release_root=/opt/qdev-runner-control-plane
release="$(realpath -e -- "$1")"
case "$release" in
  "$release_root"/releases/*) ;;
  *)
    printf 'release must be below %s/releases\n' "$release_root" >&2
    exit 64
    ;;
esac
for required in deploy/compose.yml inventory/repos.json deploy/Dockerfile.broker; do
  [[ -f "$release/$required" ]] || {
    printf 'release is missing %s\n' "$required" >&2
    exit 66
  }
done

disk_used="$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
disk_free_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
memory_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
cpu_count="$(nproc)"
load_15="$(awk '{print $3}' /proc/loadavg)"
awk -v used="$disk_used" -v free="$disk_free_kib" -v mem="$memory_kib" \
  -v cpus="$cpu_count" -v load15="$load_15" 'BEGIN {
    if (used >= 85 || free < 41943040 || mem < 4194304 || load15 > (2 * cpus)) exit 1
  }' || {
    printf 'capacity gate rejected controller activation\n' >&2
    exit 75
  }

current="$release_root/current"
previous="$(readlink -f -- "$current" 2>/dev/null || true)"
temporary_link="$release_root/.current.$$"
trap 'rm -f -- "$temporary_link"' EXIT

activate_link() {
  local target="$1"
  ln -s -- "$target" "$temporary_link"
  mv -Tf -- "$temporary_link" "$current"
}

install -m 0644 -- "$release/inventory/repos.json" /etc/qdev-runner/repos.json
activate_link "$release"

compose=(docker compose -p deploy -f "$release/deploy/compose.yml")
if [[ "${QDEV_CONTROLLER_NO_BUILD:-false}" == true ]]; then
  compose_action=(up -d --no-build --no-deps broker-public broker-internal)
else
  compose_action=(up -d --build --no-deps broker-public broker-internal)
fi

rollback() {
  [[ -n "$previous" && -d "$previous" ]] || return 0
  install -m 0644 -- "$previous/inventory/repos.json" /etc/qdev-runner/repos.json
  activate_link "$previous"
  docker compose -p deploy -f "$previous/deploy/compose.yml" \
    up -d --no-build --no-deps broker-public broker-internal
}

if ! "${compose[@]}" "${compose_action[@]}"; then
  rollback
  exit 1
fi

healthy=false
for _ in $(seq 1 30); do
  if curl --fail --silent --show-error https://ci.qdev.run/health >/dev/null; then
    healthy=true
    break
  fi
  sleep 1
done
if [[ "$healthy" != true ]]; then
  printf 'broker health check failed; restoring previous release\n' >&2
  rollback
  exit 1
fi

docker inspect qdev-runner-broker-public deploy-broker-internal-1 \
  --format '{{.Name}} {{.Image}}'
printf 'controller_release_active=%s previous=%s\n' "$release" "${previous:-none}"
