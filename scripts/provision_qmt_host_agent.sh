#!/usr/bin/env bash
set -euo pipefail

# One-time installation of controller-owned code on the already registered QMT
# host. Existing mTLS material is verified later by the forced enrol command;
# this script neither issues nor rotates credentials and never deploys QMT.
if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi
if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s /opt/qdev-runner-control-plane/releases/RELEASE\n' "$0" >&2
  exit 64
fi

controller_root=/opt/qdev-runner-control-plane
agent_root=/opt/qdev-release-bootstrap
config=/etc/qdev-release-agents/qmt.env
service=qdev-release-qmt.service
timer=qdev-release-qmt.timer
release="$(realpath -e -- "$1")"
case "$release" in
  "$controller_root"/releases/*) ;;
  *)
    printf 'release must be below %s/releases\n' "$controller_root" >&2
    exit 64
    ;;
esac

read -r revision bundle_digest < <(
  PYTHONPATH="$release/src" /usr/bin/python3 - "$release" <<'PY'
import pathlib
import sys
from qdev_runner.controller_release_bundle import verify

manifest = verify(pathlib.Path(sys.argv[1]))
print(manifest["source_revision"], manifest["bundle_digest"])
PY
)
[[ "$revision" =~ ^[0-9a-f]{40}$ && "$bundle_digest" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'controller bundle identity is invalid\n' >&2
  exit 66
}
for path in \
  "$config" \
  "$release/src/qdev_runner" \
  "$release/scripts/qdev_product_release_host_agent.py" \
  "$release/deploy/$service" \
  "$release/deploy/$timer"; do
  [[ -e "$path" && ! -L "$path" ]] || {
    printf 'QMT host-agent input is unavailable\n' >&2
    exit 66
  }
done
[[ "$(stat -c %u -- "$config")" == 0 && $((8#$(stat -c %a -- "$config") & 8#077)) == 0 ]] || {
  printf 'QMT host-agent config permissions are unsafe\n' >&2
  exit 66
}

install -d -o root -g root -m 0755 -- "$agent_root/releases"
final="$agent_root/releases/$revision-$bundle_digest"
staging="$(mktemp -d "$agent_root/releases/.incoming.XXXXXX")"
cleanup() { rm -rf -- "$staging"; }
trap cleanup EXIT

/usr/bin/python3 -m venv --system-site-packages "$staging/venv"
site_packages="$($staging/venv/bin/python -c 'import sysconfig; print(sysconfig.get_paths()["purelib"])')"
install -d -o root -g root -m 0755 -- "$site_packages" "$staging/scripts"
cp -a -- "$release/src/qdev_runner" "$site_packages/qdev_runner"
install -o root -g root -m 0755 -- \
  "$release/scripts/qdev_product_release_host_agent.py" \
  "$staging/scripts/qdev_product_release_host_agent.py"
find "$site_packages/qdev_runner" -type d -exec chmod 0755 {} +
find "$site_packages/qdev_runner" -type f -exec chmod 0644 {} +
wrapper="$staging/venv/bin/qdev-qmt-host-agent-enrol-native"
printf '#!/bin/sh\nexec "$(dirname -- "$0")/python" -m qdev_runner.qmt_host_agent_enrol_native "$@"\n' > "$wrapper"
chmod 0755 "$wrapper"
printf '%s\n' "$revision" > "$staging/source-revision"
printf '%s\n' "$bundle_digest" > "$staging/bundle-digest"
chmod 0444 "$staging/source-revision" "$staging/bundle-digest"
chown -R root:root -- "$staging"
if [[ -e "$final" || -L "$final" ]]; then
  [[ "$(<"$final/source-revision")" == "$revision" && \
      "$(<"$final/bundle-digest")" == "$bundle_digest" ]] || {
    printf 'installed QMT host-agent release identity mismatch\n' >&2
    exit 66
  }
  rm -rf -- "$staging"
else
  mv -- "$staging" "$final"
fi

temporary_link="$agent_root/.current.$$"
ln -s -- "$final" "$temporary_link"
mv -Tf -- "$temporary_link" "$agent_root/current"
install -o root -g root -m 0644 -- "$release/deploy/$service" "/etc/systemd/system/$service"
install -o root -g root -m 0644 -- "$release/deploy/$timer" "/etc/systemd/system/$timer"
systemctl daemon-reload

printf 'qmt_host_agent_installed revision=%s bundle_digest=%s\n' "$revision" "$bundle_digest"
