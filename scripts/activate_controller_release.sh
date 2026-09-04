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

rollback_mode="${QDEV_CONTROLLER_ROLLBACK:-false}"
if [[ "$rollback_mode" == true && "${QDEV_CONTROLLER_NO_BUILD:-false}" != true ]]; then
  printf 'rollback requires QDEV_CONTROLLER_NO_BUILD=true\n' >&2
  exit 64
fi
if [[ "$rollback_mode" != true ]]; then
  disk_used="$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
  disk_free_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
  memory_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
  cpu_count="$(nproc)"
  load_15="$(awk '{print $3}' /proc/loadavg)"
  # Defaults remain conservative. A bounded, explicitly logged administrative
  # recovery may lower the disk floor when the host has measured headroom but
  # cannot satisfy the historical 30 GiB gate. Values below 10 GiB or above 93%
  # used are rejected so an operator cannot turn this into an unbounded bypass.
  min_free_gib="${QDEV_CONTROLLER_MIN_FREE_GIB:-30}"
  max_used_pct="${QDEV_CONTROLLER_MAX_DISK_USED_PCT:-85}"
  awk -v used="$disk_used" -v free="$disk_free_kib" -v mem="$memory_kib" \
    -v cpus="$cpu_count" -v load15="$load_15" -v minfree="$min_free_gib" \
    -v maxused="$max_used_pct" 'BEGIN {
      if (minfree < 10 || maxused > 93 || maxused < 1 || used > maxused || free < (minfree * 1048576) || mem < 4194304 || load15 > (2 * cpus)) exit 1
    }' || {
      printf 'capacity gate rejected controller activation\n' >&2
      exit 75
    }
fi

current="$release_root/current"
previous="$(readlink -f -- "$current" 2>/dev/null || true)"
temporary_link="$release_root/.current.$$"

# Compose's implicit service image tags are mutable. Preserve both the exact
# image IDs and their configured tags so a failed activation can restore the
# previous broker binary, not merely the previous compose file.
previous_public_image="$(docker inspect qdev-runner-broker-public --format '{{.Image}}' 2>/dev/null || true)"
previous_public_ref="$(docker inspect qdev-runner-broker-public --format '{{.Config.Image}}' 2>/dev/null || true)"
previous_internal_image="$(docker inspect qdev-runner-broker-internal --format '{{.Image}}' 2>/dev/null || true)"
previous_internal_ref="$(docker inspect qdev-runner-broker-internal --format '{{.Config.Image}}' 2>/dev/null || true)"
backup_tag_prefix="qdev-runner-rollback:${BASHPID}"
previous_public_backup_ref="${backup_tag_prefix}-public"
previous_internal_backup_ref="${backup_tag_prefix}-internal"
if [[ -n "$previous_public_image" ]]; then
  docker image tag "$previous_public_image" "$previous_public_backup_ref"
fi
if [[ -n "$previous_internal_image" ]]; then
  docker image tag "$previous_internal_image" "$previous_internal_backup_ref"
fi
cleanup_backup_tags() {
  docker image rm "$previous_public_backup_ref" "$previous_internal_backup_ref" >/dev/null 2>&1 || true
}
trap 'cleanup_backup_tags; rm -f -- "$temporary_link"' EXIT

activate_link() {
  local target="$1"
  ln -s -- "$target" "$temporary_link"
  mv -Tf -- "$temporary_link" "$current"
}

install -m 0644 -- "$release/inventory/repos.json" /etc/qdev-runner/repos.json
activate_link "$release"

compose=(docker compose -p qdev-runner -f "$release/deploy/compose.yml")
if [[ "${QDEV_CONTROLLER_NO_BUILD:-false}" == true ]]; then
  compose_action=(up -d --no-build --no-deps broker-public broker-internal)
else
  compose_action=(up -d --build --no-deps broker-public broker-internal)
fi

rollback() {
  [[ -n "$previous" && -d "$previous" ]] || return 0
  install -m 0644 -- "$previous/inventory/repos.json" /etc/qdev-runner/repos.json
  activate_link "$previous"
  if [[ -n "$previous_public_backup_ref" && -n "$previous_public_ref" ]]; then
    docker image tag "$previous_public_backup_ref" "$previous_public_ref"
  fi
  if [[ -n "$previous_internal_backup_ref" && -n "$previous_internal_ref" ]]; then
    docker image tag "$previous_internal_backup_ref" "$previous_internal_ref"
  fi
  docker compose -p qdev-runner -f "$previous/deploy/compose.yml" \
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

docker inspect qdev-runner-broker-public qdev-runner-broker-internal \
  --format '{{.Name}} {{.Image}}'
printf 'controller_release_active=%s previous=%s\n' "$release" "${previous:-none}"
