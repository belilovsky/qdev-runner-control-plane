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
for required in \
  deploy/compose.yml \
  inventory/repos.json \
  config/profiles.yml \
  deploy/Dockerfile.broker; do
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
no_build="${QDEV_CONTROLLER_NO_BUILD:-false}"
max_disk_used_pct="${QDEV_CONTROLLER_MAX_DISK_USED_PCT:-85}"
min_free_gib="${QDEV_CONTROLLER_MIN_FREE_GIB:-30}"
min_memory_gib="${QDEV_CONTROLLER_MIN_MEMORY_AVAILABLE_GIB:-4}"
max_load_per_cpu="${QDEV_CONTROLLER_MAX_LOAD_PER_CPU:-2}"
for value in "$max_disk_used_pct" "$min_free_gib" "$min_memory_gib" "$max_load_per_cpu"; do
  [[ "$value" =~ ^[0-9]+$ ]] || {
    printf 'controller capacity overrides must be non-negative integers\n' >&2
    exit 64
  }
done
if [[ "$no_build" != true ]] && {
  [[ "$max_disk_used_pct" != 85 ]] || [[ "$min_free_gib" != 30 ]] ||
    [[ "$min_memory_gib" != 4 ]] || [[ "$max_load_per_cpu" != 2 ]]
}; then
  printf 'controller capacity overrides require QDEV_CONTROLLER_NO_BUILD=true\n' >&2
  exit 64
fi
awk -v used="$disk_used" -v free="$disk_free_kib" -v mem="$memory_kib" \
  -v cpus="$cpu_count" -v load15="$load_15" -v max_used="$max_disk_used_pct" \
  -v min_free_gib="$min_free_gib" -v min_mem_gib="$min_memory_gib" \
  -v max_load_per_cpu="$max_load_per_cpu" 'BEGIN {
    if (used > max_used || free < (min_free_gib * 1048576) ||
        mem < (min_mem_gib * 1048576) || load15 > (max_load_per_cpu * cpus)) exit 1
  }' || {
    printf 'capacity gate rejected controller activation used=%s free_kib=%s memory_kib=%s load15=%s\n' \
      "$disk_used" "$disk_free_kib" "$memory_kib" "$load_15" >&2
    exit 75
  }

current="$release_root/current"
previous="$(readlink -f -- "$current" 2>/dev/null || true)"
temporary_link="$release_root/.current.$$"
profiles_backup="$(mktemp /tmp/qdev-runner-profiles.XXXXXX)"
profiles_were_present=false
if [[ -f /etc/qdev-runner/profiles.yml ]]; then
  install -m 0600 -- /etc/qdev-runner/profiles.yml "$profiles_backup"
  profiles_were_present=true
fi
trap 'rm -f -- "$temporary_link" "$profiles_backup"' EXIT

# Compose's implicit service image tags are mutable. Preserve both the exact
# image IDs and their configured tags so a failed activation can restore the
# previous broker binary, not merely the previous compose file.
previous_public_image="$(docker inspect qdev-runner-broker-public --format '{{.Image}}' 2>/dev/null || true)"
previous_public_ref="$(docker inspect qdev-runner-broker-public --format '{{.Config.Image}}' 2>/dev/null || true)"
previous_internal_image="$(docker inspect qdev-runner-broker-internal --format '{{.Image}}' 2>/dev/null || true)"
previous_internal_ref="$(docker inspect qdev-runner-broker-internal --format '{{.Config.Image}}' 2>/dev/null || true)"

activate_link() {
  local target="$1"
  ln -s -- "$target" "$temporary_link"
  mv -Tf -- "$temporary_link" "$current"
}

install -m 0644 -- "$release/inventory/repos.json" /etc/qdev-runner/repos.json
install -m 0644 -- "$release/config/profiles.yml" /etc/qdev-runner/profiles.yml
activate_link "$release"

compose=(docker compose -p qdev-runner -f "$release/deploy/compose.yml")
if [[ "$no_build" == true ]]; then
  compose_action=(up -d --force-recreate --no-build --no-deps broker-public broker-internal)
else
  compose_action=(up -d --force-recreate --build --no-deps broker-public broker-internal)
fi

rollback() {
  [[ -n "$previous" && -d "$previous" ]] || return 0
  install -m 0644 -- "$previous/inventory/repos.json" /etc/qdev-runner/repos.json
  if [[ "$profiles_were_present" == true ]]; then
    install -m 0644 -- "$profiles_backup" /etc/qdev-runner/profiles.yml
  else
    rm -f -- /etc/qdev-runner/profiles.yml
  fi
  activate_link "$previous"
  if [[ -n "$previous_public_image" && -n "$previous_public_ref" ]]; then
    docker image tag "$previous_public_image" "$previous_public_ref"
  fi
  if [[ -n "$previous_internal_image" && -n "$previous_internal_ref" ]]; then
    docker image tag "$previous_internal_image" "$previous_internal_ref"
  fi
  docker compose -p qdev-runner -f "$previous/deploy/compose.yml" \
    up -d --force-recreate --no-build --no-deps broker-public broker-internal
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

docker inspect qdev-runner-broker-public qdev-runner-broker-internal \
  --format '{{.Name}} {{.Image}}'
printf 'controller_release_active=%s previous=%s\n' "$release" "${previous:-none}"
