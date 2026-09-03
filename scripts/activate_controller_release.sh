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
operations_root="${QDEV_OPERATIONS_ROOT:-/var/lib/qdev-runner/operations}"
release_jobs_root="${QDEV_RELEASE_JOBS_ROOT:-/var/lib/qdev-runner/release-jobs}"
release_status_path="${QDEV_CONTROLLER_RELEASE_STATUS:-/etc/qdev-runner/controller-release.json}"
runtime_uid="${QDEV_CONTROLLER_RUNTIME_UID:-9020}"
runtime_gid="${QDEV_CONTROLLER_RUNTIME_GID:-9020}"
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
  config/release-lanes.yml \
  scripts/provision_operator_identity.sh \
  scripts/qaz_tours_release_host_agent.py \
  scripts/qdev_product_release_host_agent.py \
  deploy/qdev-release-qaz-tours.service \
  deploy/qdev-release-qaz-fund.service \
  deploy/qdev-release-qaz-events.service \
  deploy/Dockerfile.broker; do
  [[ -f "$release/$required" ]] || {
    printf 'release is missing %s\n' "$required" >&2
    exit 66
  }
done
release_status_directory="$(dirname -- "$release_status_path")"
[[ -d "$release_status_directory" ]] || {
  printf 'controller release status directory is missing: %s\n' "$release_status_directory" >&2
  exit 73
}

# The broker runs rootless. Prepare its persistent operation store before any
# container is recreated so a valid release cannot fail after the old broker
# has already been replaced. Numeric IDs are intentional: the runtime image
# owns this UID/GID even when the host has no matching passwd entry.
[[ "$runtime_uid" =~ ^[0-9]+$ && "$runtime_gid" =~ ^[0-9]+$ ]] || {
  printf 'controller runtime uid/gid must be numeric\n' >&2
  exit 64
}
for durable_root in "$operations_root" "$release_jobs_root"; do
  install -d -o "$runtime_uid" -g "$runtime_gid" -m 0700 -- "$durable_root"
  if [[ "$(stat -c %u -- "$durable_root")" != "$runtime_uid" ||
        "$(stat -c %g -- "$durable_root")" != "$runtime_gid" ]]; then
    printf 'controller durable-store ownership check failed for %s\n' "$durable_root" >&2
    exit 73
  fi
done

disk_used="$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
disk_free_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
memory_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
cpu_count="$(nproc)"
load_15="$(awk '{print $3}' /proc/loadavg)"
no_build="${QDEV_CONTROLLER_NO_BUILD:-false}"
allow_build_capacity_override="${QDEV_CONTROLLER_ALLOW_BUILD_CAPACITY_OVERRIDE:-false}"
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
if [[ "$allow_build_capacity_override" != true && "$allow_build_capacity_override" != false ]]; then
  printf 'QDEV_CONTROLLER_ALLOW_BUILD_CAPACITY_OVERRIDE must be true or false\n' >&2
  exit 64
fi
if [[ "$no_build" != true && "$allow_build_capacity_override" != true ]] && {
  [[ "$max_disk_used_pct" != 85 ]] || [[ "$min_free_gib" != 30 ]] ||
    [[ "$min_memory_gib" != 4 ]] || [[ "$max_load_per_cpu" != 2 ]]
}; then
  printf 'controller capacity overrides require QDEV_CONTROLLER_NO_BUILD=true or an explicit build override\n' >&2
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
release_lanes_backup="$(mktemp /tmp/qdev-runner-release-lanes.XXXXXX)"
release_status_backup="$(mktemp /tmp/qdev-runner-controller-release-status.XXXXXX)"
profiles_were_present=false
release_lanes_were_present=false
release_status_was_present=false
operator_identity_metadata_backup="$(mktemp /tmp/qdev-runner-operator-mtls-metadata.XXXXXX)"
operator_identity_was_present=false
if [[ -f /etc/qdev-runner/profiles.yml ]]; then
  install -m 0600 -- /etc/qdev-runner/profiles.yml "$profiles_backup"
  profiles_were_present=true
fi
if [[ -f /etc/qdev-runner/release-lanes.yml ]]; then
  install -m 0600 -- /etc/qdev-runner/release-lanes.yml "$release_lanes_backup"
  release_lanes_were_present=true
fi
if [[ -f "$release_status_path" ]]; then
  install -m 0644 -- "$release_status_path" "$release_status_backup"
  release_status_was_present=true
fi
operator_identity_dir=/etc/qdev-runner/mtls/operator
if [[ -d "$operator_identity_dir" && ! -L "$operator_identity_dir" ]]; then
  operator_identity_was_present=true
  for operator_identity_path in \
    "$operator_identity_dir" \
    "$operator_identity_dir/ca.pem" \
    "$operator_identity_dir/operator-cert.pem" \
    "$operator_identity_dir/operator-key.pem"; do
    if [[ ! -e "$operator_identity_path" || -L "$operator_identity_path" ]]; then
      operator_identity_was_present=false
      break
    fi
    stat -c '%a %u %g %n' -- "$operator_identity_path" >> "$operator_identity_metadata_backup"
  done
fi
# Compose's implicit service image tags are mutable. Preserve both the exact
# image IDs and their configured tags so a failed activation can restore the
# previous broker binary, not merely the previous compose file.
previous_public_image="$(docker inspect qdev-runner-broker-public --format '{{.Image}}' 2>/dev/null || true)"
previous_public_ref="$(docker inspect qdev-runner-broker-public --format '{{.Config.Image}}' 2>/dev/null || true)"
previous_internal_image="$(docker inspect qdev-runner-broker-internal --format '{{.Image}}' 2>/dev/null || true)"
previous_internal_ref="$(docker inspect qdev-runner-broker-internal --format '{{.Config.Image}}' 2>/dev/null || true)"
rollback_public_ref="qdev-runner-rollback-public:$$"
rollback_internal_ref="qdev-runner-rollback-internal:$$"
if [[ -n "$previous_public_image" ]]; then
  docker image tag "$previous_public_image" "$rollback_public_ref"
fi
if [[ -n "$previous_internal_image" ]]; then
  docker image tag "$previous_internal_image" "$rollback_internal_ref"
fi

cleanup_rollback_images() {
  docker image rm "$rollback_public_ref" "$rollback_internal_ref" >/dev/null 2>&1 || true
}
trap 'rm -f -- "$temporary_link" "$profiles_backup" "$release_lanes_backup" "$release_status_backup" "$operator_identity_metadata_backup"; cleanup_rollback_images' EXIT

activate_link() {
  local target="$1"
  ln -s -- "$target" "$temporary_link"
  mv -Tf -- "$temporary_link" "$current"
}

release_revision="${QDEV_CONTROLLER_RELEASE_REVISION:-}"
if [[ -z "$release_revision" ]]; then
  release_revision="$(git -C "$release" rev-parse --verify HEAD 2>/dev/null || true)"
fi
if [[ ! "$release_revision" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'release must expose an exact git revision via HEAD or QDEV_CONTROLLER_RELEASE_REVISION\n' >&2
  exit 66
fi
release_digest="$(
  for release_file in \
    "$release/deploy/compose.yml" \
    "$release/inventory/repos.json" \
    "$release/config/profiles.yml" \
    "$release/config/release-lanes.yml" \
    "$release/scripts/provision_operator_identity.sh" \
    "$release/scripts/qaz_tours_release_host_agent.py" \
    "$release/deploy/qdev-release-qaz-tours.service" \
    "$release/scripts/qdev_product_release_host_agent.py" \
    "$release/deploy/qdev-release-qaz-fund.service" \
    "$release/deploy/qdev-release-qaz-events.service" \
    "$release/deploy/Dockerfile.broker"
  do
    sha256sum -- "$release_file" | awk '{print $1}'
  done | sha256sum | awk '{print $1}'
)"

write_release_status() {
  local temporary_status
  temporary_status="$(mktemp "$release_status_directory/.controller-release-status.XXXXXX")"
  printf '{"schema":"qdev-controller-release-status-v1","state":"active","revision":"%s","release_digest":"%s","activated_at":"%s"}\n' \
    "$release_revision" "$release_digest" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$temporary_status"
  chmod 0644 "$temporary_status"
  mv -f -- "$temporary_status" "$release_status_path"
}

restore_release_status() {
  if [[ "$release_status_was_present" == true ]]; then
    install -m 0644 -- "$release_status_backup" "$release_status_path"
  else
    rm -f -- "$release_status_path"
  fi
}

restore_operator_identity_metadata() {
  [[ "$operator_identity_was_present" == true ]] || return 0
  while read -r mode uid gid path; do
    chown "$uid:$gid" -- "$path"
    chmod "$mode" -- "$path"
  done < "$operator_identity_metadata_backup"
}

install -m 0644 -- "$release/inventory/repos.json" /etc/qdev-runner/repos.json
install -m 0644 -- "$release/config/profiles.yml" /etc/qdev-runner/profiles.yml
install -m 0644 -- "$release/config/release-lanes.yml" /etc/qdev-runner/release-lanes.yml
activate_link "$release"

compose=(docker compose -p qdev-runner -f "$release/deploy/compose.yml")
if [[ "$no_build" == true ]]; then
  compose_action=(up -d --force-recreate --no-build --no-deps broker-public broker-internal)
else
  compose_action=(up -d --force-recreate --build --no-deps broker-public broker-internal)
fi

rollback() {
  restore_release_status
  restore_operator_identity_metadata
  [[ -n "$previous" && -d "$previous" ]] || return 0
  install -m 0644 -- "$previous/inventory/repos.json" /etc/qdev-runner/repos.json
  if [[ "$profiles_were_present" == true ]]; then
    install -m 0644 -- "$profiles_backup" /etc/qdev-runner/profiles.yml
  else
    rm -f -- /etc/qdev-runner/profiles.yml
  fi
  if [[ "$release_lanes_were_present" == true ]]; then
    install -m 0644 -- "$release_lanes_backup" /etc/qdev-runner/release-lanes.yml
  else
    rm -f -- /etc/qdev-runner/release-lanes.yml
  fi
  activate_link "$previous"
  if [[ -n "$previous_public_image" && -n "$previous_public_ref" ]]; then
    docker image tag "$rollback_public_ref" "$previous_public_ref"
  fi
  if [[ -n "$previous_internal_image" && -n "$previous_internal_ref" ]]; then
    docker image tag "$rollback_internal_ref" "$previous_internal_ref"
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

if ! "$release/scripts/provision_operator_identity.sh"; then
  printf '%s\n' 'Controller is healthy, but its operator mTLS identity is not usable; restoring the prior release.' >&2
  rollback
  exit 1
fi

if ! write_release_status; then
  printf '%s\n' 'Controller is healthy, but the activation receipt could not be persisted; restoring the prior release.' >&2
  rollback
  exit 1
fi

docker inspect qdev-runner-broker-public qdev-runner-broker-internal \
  --format '{{.Name}} {{.Image}}'
printf 'controller_release_active=%s previous=%s\n' "$release" "${previous:-none}"
printf 'controller_release_receipt=active revision=%s digest=%s\n' "$release_revision" "$release_digest"
