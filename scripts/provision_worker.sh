#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi

if systemctl is-active --quiet qdev-runner-worker.service; then
  printf 'refusing to provision while qdev-runner-worker.service is active\n' >&2
  exit 75
fi

worker_uid=9021
worker_user=qdev-runner
install_root=/opt/qdev-runner-worker
buildkit_version=0.33.0
buildkit_source_sha256=c365476e1b10e27a2ab809e3a7a6dcd0647a60fa6e8917799b894d4127af7306
buildkit_source_revision=dddd5621af04ea57823085c93a063383f71d3173
buildkit_root="/opt/qdev-buildkit/${buildkit_version}"
buildkit_artifact_root="${QDEV_BUILDKIT_ARTIFACT_ROOT:-/var/lib/qdev-runner-worker/buildkit-artifacts/${buildkit_version}}"
buildkit_image_ref="${QDEV_BUILDKIT_IMAGE_REF:-}"
buildkit_stage=""
buildkit_container=""
buildkit_release_stage=""

cleanup_buildkit_materialization() {
  if [[ -n "$buildkit_container" ]]; then
    runuser -u "$worker_user" -- env \
      HOME="/home/${worker_user}" \
      XDG_RUNTIME_DIR="/run/user/${worker_uid}" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${worker_uid}/bus" \
      DOCKER_HOST="unix:///run/user/${worker_uid}/docker.sock" \
      docker rm --force "$buildkit_container" >/dev/null 2>&1 || true
  fi
  if [[ -n "$buildkit_stage" ]]; then
    rm -rf -- "$buildkit_stage"
  fi
  if [[ -n "$buildkit_release_stage" ]]; then
    rm -rf -- "$buildkit_release_stage"
  fi
}

trap cleanup_buildkit_materialization EXIT

disk_used="$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
disk_free_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
memory_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
cpu_count="$(nproc)"
load_15="$(awk '{print $3}' /proc/loadavg)"
# One published capacity contract.  A normal shared worker installs at 30 GiB
# free / 85% used; a durable (continuously monitored) shared worker is allowed
# the 10 GiB / 90% bound.  The 90% ceiling is absolute for both tiers.
provision_durable="${QDEV_WORKER_PROVISION_DURABLE:-false}"
if [[ "$provision_durable" != "true" && "$provision_durable" != "false" ]]; then
  printf 'QDEV_WORKER_PROVISION_DURABLE must be true or false\n' >&2
  exit 1
fi
if [[ "$provision_durable" == "true" ]]; then
  tier_min_free_gib=10
  tier_max_disk_used_pct=90
else
  tier_min_free_gib=30
  tier_max_disk_used_pct=85
fi
for retired_capacity_variable in \
  QDEV_WORKER_PROVISION_MIN_FREE_GIB \
  QDEV_WORKER_PROVISION_MAX_DISK_USED_PCT \
  QDEV_WORKER_ALLOW_PROVISION_CAPACITY_OVERRIDE; do
  if [[ -n "${!retired_capacity_variable:-}" ]]; then
    printf '%s is retired; provisioning uses the sealed tier gate and runtime relief requires a controller-signed claim-scope-v2 directive\n' "$retired_capacity_variable" >&2
    exit 1
  fi
done
provision_min_free_gib="$tier_min_free_gib"
provision_max_disk_used_pct="$tier_max_disk_used_pct"
provision_min_free_kib=$((provision_min_free_gib * 1024 * 1024))

awk -v used="$disk_used" -v free="$disk_free_kib" -v mem="$memory_kib" \
  -v cpus="$cpu_count" -v load15="$load_15" -v min_free="$provision_min_free_kib" \
  -v max_used="$provision_max_disk_used_pct" 'BEGIN {
    if (used > max_used || free < min_free || mem < 4194304 || load15 > (2 * cpus)) exit 1
  }' || {
    printf 'capacity gate rejected worker provisioning (used=%s%% max_used=%s%% free_kib=%s min_free_kib=%s memory_kib=%s cpus=%s load15=%s)\n' \
      "$disk_used" "$provision_max_disk_used_pct" "$disk_free_kib" "$provision_min_free_kib" "$memory_kib" "$cpu_count" "$load_15" >&2
    exit 1
  }

apt-get update
apt-get install -y --no-install-recommends \
  ca-certificates curl dbus-user-session fuse-overlayfs python3 python3-venv \
  slirp4netns uidmap

if ! id "$worker_user" >/dev/null 2>&1; then
  useradd --create-home --uid "$worker_uid" --shell /bin/bash "$worker_user"
fi
if [[ "$(id -u "$worker_user")" != "$worker_uid" ]]; then
  printf 'unexpected uid for %s\n' "$worker_user" >&2
  exit 1
fi

grep -q "^${worker_user}:" /etc/subuid || usermod --add-subuids 100000-165535 "$worker_user"
grep -q "^${worker_user}:" /etc/subgid || usermod --add-subgids 100000-165535 "$worker_user"
loginctl enable-linger "$worker_user"

install -d -o "$worker_user" -g "$worker_user" "/run/user/${worker_uid}"
install -d -o "$worker_user" -g "$worker_user" "/home/${worker_user}/.config/systemd/user"
systemctl start "user@${worker_uid}.service"
if [[ ! -S "/run/user/${worker_uid}/docker.sock" ]]; then
  runuser -u "$worker_user" -- env \
    HOME="/home/${worker_user}" \
    XDG_RUNTIME_DIR="/run/user/${worker_uid}" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${worker_uid}/bus" \
    dockerd-rootless-setuptool.sh install --force
fi
runuser -u "$worker_user" -- env \
  HOME="/home/${worker_user}" \
  XDG_RUNTIME_DIR="/run/user/${worker_uid}" \
  DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${worker_uid}/bus" \
  systemctl --user enable --now docker.service

validate_buildkit_materialization() {
  local root="$1"
  local marker value mode owner
  [[ -d "$root" && ! -L "$root" ]] || return 1
  mode="$(stat -c '%a' "$root")"
  owner="$(stat -c '%u:%g' "$root")"
  [[ "$mode" == "755" && "$owner" == "0:0" ]] || return 1
  [[ -d "$root/bin" && ! -L "$root/bin" ]] || return 1
  mode="$(stat -c '%a' "$root/bin")"
  owner="$(stat -c '%u:%g' "$root/bin")"
  [[ "$mode" == "755" && "$owner" == "0:0" ]] || return 1
  for binary in buildkitd buildctl; do
    [[ -f "$root/bin/$binary" && ! -L "$root/bin/$binary" && -x "$root/bin/$binary" ]] || return 1
    mode="$(stat -c '%a' "$root/bin/$binary")"
    owner="$(stat -c '%u:%g' "$root/bin/$binary")"
    [[ "$mode" == "555" && "$owner" == "0:0" ]] || return 1
  done
  for marker in source-revision source-sha256; do
    [[ -f "$root/$marker" && ! -L "$root/$marker" ]] || return 1
    mode="$(stat -c '%a' "$root/$marker")"
    owner="$(stat -c '%u:%g' "$root/$marker")"
    [[ "$mode" == "444" && "$owner" == "0:0" ]] || return 1
  done
  value="$(tr -d '\r\n' < "$root/source-revision")"
  [[ "$value" == "$buildkit_source_revision" ]] || return 1
  value="$(tr -d '\r\n' < "$root/source-sha256")"
  [[ "$value" == "$buildkit_source_sha256" ]] || return 1
}

materialize_buildkit_from_image() {
  local image_ref="$1"
  local incoming="$2"
  local path target
  [[ "$image_ref" =~ ^[^[:space:]@]+@sha256:[0-9a-f]{64}$ ]] || {
    printf 'QDEV_BUILDKIT_IMAGE_REF must be an immutable digest reference\n' >&2
    return 1
  }
  install -d -o "$worker_user" -g "$worker_user" -m 0700 "$incoming/bin"
  buildkit_container="$(runuser -u "$worker_user" -- env \
    HOME="/home/${worker_user}" \
    XDG_RUNTIME_DIR="/run/user/${worker_uid}" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${worker_uid}/bus" \
    DOCKER_HOST="unix:///run/user/${worker_uid}/docker.sock" \
    docker create --entrypoint /bin/true "$image_ref")"
  [[ -n "$buildkit_container" ]] || return 1
  for path in /usr/local/bin/buildkitd /usr/local/bin/buildctl \
    /usr/local/share/qdev-buildkit/source-revision /usr/local/share/qdev-buildkit/source-sha256; do
    if [[ "$path" == /usr/local/bin/* ]]; then
      target="$incoming/bin/$(basename "$path")"
    else
      target="$incoming/$(basename "$path")"
    fi
    runuser -u "$worker_user" -- env \
      HOME="/home/${worker_user}" \
      XDG_RUNTIME_DIR="/run/user/${worker_uid}" \
      DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${worker_uid}/bus" \
      DOCKER_HOST="unix:///run/user/${worker_uid}/docker.sock" \
      docker cp "$buildkit_container:$path" "$target"
  done
  runuser -u "$worker_user" -- env \
    HOME="/home/${worker_user}" \
    XDG_RUNTIME_DIR="/run/user/${worker_uid}" \
    DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/${worker_uid}/bus" \
    DOCKER_HOST="unix:///run/user/${worker_uid}/docker.sock" \
    docker rm "$buildkit_container" >/dev/null
  buildkit_container=""
  chown root:root "$incoming" "$incoming/bin" \
    "$incoming/bin/buildkitd" "$incoming/bin/buildctl" \
    "$incoming/source-revision" "$incoming/source-sha256"
  chmod 0755 "$incoming" "$incoming/bin"
  chmod 0555 "$incoming/bin/buildkitd" "$incoming/bin/buildctl"
  chmod 0444 "$incoming/source-revision" "$incoming/source-sha256"
}

if [[ -e "$buildkit_root" || -L "$buildkit_root" ]]; then
  validate_buildkit_materialization "$buildkit_root" || {
    printf 'existing BuildKit materialization is not source-bound; refusing to replace it\n' >&2
    exit 1
  }
else
  [[ "$buildkit_artifact_root" = /* ]] || {
    printf 'QDEV_BUILDKIT_ARTIFACT_ROOT must be an absolute path\n' >&2
    exit 1
  }
  buildkit_stage="$(mktemp -d /tmp/qdev-buildkit-stage.XXXXXX)"
  buildkit_incoming="$buildkit_stage/incoming"
  if [[ -n "$buildkit_image_ref" ]]; then
    materialize_buildkit_from_image "$buildkit_image_ref" "$buildkit_incoming"
  else
    [[ -d "$buildkit_artifact_root" && ! -L "$buildkit_artifact_root" ]] || {
      printf 'source-bound BuildKit artifact is required at %s or set QDEV_BUILDKIT_IMAGE_REF\n' \
        "$buildkit_artifact_root" >&2
      exit 1
    }
    buildkit_incoming="$buildkit_artifact_root"
  fi
  validate_buildkit_materialization "$buildkit_incoming" || {
    printf 'source-bound BuildKit artifact failed validation\n' >&2
    exit 1
  }
  buildkit_parent="$(dirname "$buildkit_root")"
  install -d -o root -g root -m 0755 "$buildkit_parent"
  buildkit_release_stage="$(mktemp -d "${buildkit_parent}/.${buildkit_version}.staging.XXXXXX")"
  install -d -o root -g root -m 0755 "$buildkit_release_stage/bin"
  install -o root -g root -m 0555 "$buildkit_incoming/bin/buildkitd" \
    "$buildkit_release_stage/bin/buildkitd"
  install -o root -g root -m 0555 "$buildkit_incoming/bin/buildctl" \
    "$buildkit_release_stage/bin/buildctl"
  install -o root -g root -m 0444 "$buildkit_incoming/source-revision" \
    "$buildkit_release_stage/source-revision"
  install -o root -g root -m 0444 "$buildkit_incoming/source-sha256" \
    "$buildkit_release_stage/source-sha256"
  chmod 0755 "$buildkit_release_stage" "$buildkit_release_stage/bin"
  if [[ -e "$buildkit_root" || -L "$buildkit_root" ]]; then
    printf 'BuildKit destination appeared during materialization; refusing replacement\n' >&2
    exit 1
  fi
  mv -- "$buildkit_release_stage" "$buildkit_root"
  buildkit_release_stage=""
  validate_buildkit_materialization "$buildkit_root" || {
    printf 'new BuildKit materialization failed post-install validation\n' >&2
    exit 1
  }
fi

install -d -o root -g root -m 0755 "$install_root"
# Older releases may have installed the active virtualenv as a relative symlink
# into a versioned release directory. Reusing that link would mutate rollback
# state, while python -m venv refuses to replace it. Archive only the link (not
# its target) before creating the current, independently owned environment.
if [[ -L "${install_root}/.venv" ]]; then
  venv_link_backup="${install_root}/backups/venv-link-$(date -u +%Y%m%dT%H%M%SZ)"
  install -d -o root -g root -m 0700 "$venv_link_backup"
  mv -- "${install_root}/.venv" "$venv_link_backup/.venv"
  printf 'previous worker virtualenv link archived at %s\n' "$venv_link_backup/.venv"
fi
python3 -m venv "${install_root}/.venv"
"${install_root}/.venv/bin/pip" install --disable-pip-version-check --no-cache-dir \
  -r requirements.runtime.txt
"${install_root}/.venv/bin/pip" install --disable-pip-version-check --no-deps .
install -d -o "$worker_user" -g "$worker_user" -m 0700 /var/lib/qdev-runner-worker
install -d -o "$worker_user" -g "$worker_user" -m 0700 /var/lib/qdev-runner-worker/jobs
install -d -o root -g root -m 0755 /etc/qdev-runner/mtls
install -d -o "$worker_user" -g "$worker_user" -m 0700 /etc/qdev-runner/mtls/worker
install -m 0644 deploy/qdev-runner-worker.service /etc/systemd/system/qdev-runner-worker.service
install -m 0755 scripts/manage_worker_gate.py /usr/local/sbin/qdev-runner-worker-gate

# The owner-bound gate supersedes the earlier existence-only rollout permit.
# Preserve, rather than delete, those exact legacy controls so an upgrade cannot
# leave an otherwise valid release permanently skipped or tempt an operator to
# manufacture an empty compatibility permit.
legacy_gate_paths=(
  /etc/systemd/system/qdev-runner-worker.service.d/zzzzzzz-runner-rollout-lock.conf
  /etc/qdev/qdev-runner-worker.rollout-permit
)
legacy_gate_backup=""
for legacy_path in "${legacy_gate_paths[@]}"; do
  [[ -e "$legacy_path" ]] || continue
  if [[ -z "$legacy_gate_backup" ]]; then
    legacy_gate_backup="${install_root}/backups/legacy-gate-$(date -u +%Y%m%dT%H%M%SZ)"
    install -d -o root -g root -m 0700 "$legacy_gate_backup"
  fi
  mv -- "$legacy_path" "$legacy_gate_backup/"
done
if [[ -n "$legacy_gate_backup" ]]; then
  printf 'legacy worker gate controls archived at %s\n' "$legacy_gate_backup"
fi

runuser -u "$worker_user" -- env \
  DOCKER_HOST="unix:///run/user/${worker_uid}/docker.sock" \
  docker network inspect qdev-ci-egress >/dev/null 2>&1 || \
runuser -u "$worker_user" -- env \
  DOCKER_HOST="unix:///run/user/${worker_uid}/docker.sock" \
  docker network create qdev-ci-egress >/dev/null

systemctl daemon-reload
printf '%s\n' \
  'worker provisioning complete; install worker.env and mTLS files,' \
  'run the config-bound runtime audit, then release the owned worker gate'
