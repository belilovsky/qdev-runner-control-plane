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
buildkit_version=0.32.2
buildkit_sha256=2975d0f651ad96ba8b80b9992ae1f9a964f4408569af5b6dc36544165c3926af
buildkit_root="/opt/qdev-buildkit/${buildkit_version}"

disk_used="$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
disk_free_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
memory_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
cpu_count="$(nproc)"
load_15="$(awk '{print $3}' /proc/loadavg)"
provision_min_free_gib="${QDEV_WORKER_PROVISION_MIN_FREE_GIB:-30}"
provision_max_disk_used_pct="${QDEV_WORKER_PROVISION_MAX_DISK_USED_PCT:-85}"
allow_capacity_override="${QDEV_WORKER_ALLOW_PROVISION_CAPACITY_OVERRIDE:-false}"

if [[ ! "$provision_min_free_gib" =~ ^[0-9]+$ ]] || (( provision_min_free_gib < 5 || provision_min_free_gib > 30 )); then
  printf 'QDEV_WORKER_PROVISION_MIN_FREE_GIB must be an integer from 5 to 30\n' >&2
  exit 1
fi
if [[ ! "$provision_max_disk_used_pct" =~ ^[0-9]+$ ]] || (( provision_max_disk_used_pct < 85 || provision_max_disk_used_pct > 95 )); then
  printf 'QDEV_WORKER_PROVISION_MAX_DISK_USED_PCT must be an integer from 85 to 95\n' >&2
  exit 1
fi
if [[ "$allow_capacity_override" != "true" && "$allow_capacity_override" != "false" ]]; then
  printf 'QDEV_WORKER_ALLOW_PROVISION_CAPACITY_OVERRIDE must be true or false\n' >&2
  exit 1
fi
if (( provision_min_free_gib != 30 || provision_max_disk_used_pct != 85 )) && [[ "$allow_capacity_override" != "true" ]]; then
  printf 'a relaxed provisioning capacity gate requires QDEV_WORKER_ALLOW_PROVISION_CAPACITY_OVERRIDE=true\n' >&2
  exit 1
fi
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

if [[ ! -x "${buildkit_root}/bin/buildkitd" ]]; then
  buildkit_archive="$(mktemp /tmp/qdev-buildkit.XXXXXX.tar.gz)"
  trap 'rm -f -- "$buildkit_archive"' EXIT
  curl --fail --location --retry 5 \
    "https://github.com/moby/buildkit/releases/download/v${buildkit_version}/buildkit-v${buildkit_version}.linux-amd64.tar.gz" \
    --output "$buildkit_archive"
  printf '%s  %s\n' "$buildkit_sha256" "$buildkit_archive" | sha256sum --check -
  install -d -o root -g root -m 0755 "$buildkit_root"
  tar -xzf "$buildkit_archive" -C "$buildkit_root"
  rm -f -- "$buildkit_archive"
  trap - EXIT
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
