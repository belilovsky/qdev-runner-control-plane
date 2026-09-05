#!/usr/bin/env bash
set -euo pipefail

profile=""
digest_only=false
while [[ "$#" -gt 0 ]]; do
  case "$1" in
    --profile)
      [[ "$#" -ge 2 ]] || { printf '%s\n' 'missing --profile value' >&2; exit 64; }
      profile="$2"
      shift 2
      ;;
    --digest-only)
      digest_only=true
      shift
      ;;
    *)
      printf 'unknown argument: %s\n' "$1" >&2
      exit 64
      ;;
  esac
done

case "$profile" in
  platform|qazstack) ;;
  *)
    printf '%s\n' '--profile must be platform or qazstack' >&2
    exit 64
    ;;
esac

source_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
artifacts=(
  deploy/qdev-runner-recovery-platform.service
  deploy/qdev-runner-recovery-qazstack.service
  scripts/install_qdev_runner_recovery_host_agent.sh
  scripts/qdev_runner_recovery_host_agent.py
)
for relative_path in "${artifacts[@]}"; do
  artifact="$source_root/$relative_path"
  if [[ ! -f "$artifact" || -L "$artifact" ]]; then
    printf 'recovery release artifact is missing or unsafe: %s\n' "$relative_path" >&2
    exit 66
  fi
done

release_manifest="$({
  for relative_path in "${artifacts[@]}"; do
    printf '%s\t%s\n' "$relative_path" "$(sha256sum -- "$source_root/$relative_path" | awk '{print $1}')"
  done
} | python3 -c '
import json
import sys

artifacts = []
for line in sys.stdin:
    path, digest = line.rstrip("\n").split("\t", 1)
    artifacts.append({"path": path, "sha256": f"sha256:{digest}"})
manifest = {
    "schema": "qdev-runner-recovery-agent-release-v1",
    "artifacts": sorted(artifacts, key=lambda item: item["path"]),
}
print(json.dumps(manifest, ensure_ascii=False, separators=(",", ":"), sort_keys=True))
')"
release_digest="sha256:$(printf '%s' "$release_manifest" | sha256sum | awk '{print $1}')"

if [[ "$digest_only" == true ]]; then
  printf '%s\n' "$release_digest"
  exit 0
fi
if [[ "$EUID" -ne 0 ]]; then
  printf '%s\n' 'run as root' >&2
  exit 1
fi

config="/etc/qdev-runner-recovery/${profile}.env"
if [[ ! -f "$config" || -L "$config" || "$(stat -c %u -- "$config")" != 0 || $((8#$(stat -c %a -- "$config") & 8#077)) -ne 0 ]]; then
  printf 'private recovery config is missing or unsafe: %s\n' "$config" >&2
  exit 66
fi
configured_digest="$(awk -F= '
  $1 == "QDEV_RECOVERY_EXPECTED_AGENT_RELEASE_DIGEST" {print substr($0, index($0, "=") + 1); found += 1}
  END {if (found != 1) exit 1}
' "$config")" || {
  printf '%s\n' 'recovery config has no unique agent release digest' >&2
  exit 66
}
if [[ "$configured_digest" != "$release_digest" ]]; then
  printf '%s\n' 'recovery config is bound to another host-agent release' >&2
  exit 65
fi

install_root=/opt/qdev-runner-recovery
release_id="${release_digest#sha256:}"
release_root="$install_root/releases/$release_id"
unit="qdev-runner-recovery-${profile}.service"
if systemctl is-active --quiet "$unit"; then
  printf 'refusing to replace an active recovery agent: %s\n' "$unit" >&2
  exit 75
fi

install -d -o root -g root -m 0755 "$install_root"
for directory in "$install_root" "$install_root/releases"; do
  if [[ "$directory" == "$install_root/releases" && ! -e "$directory" ]]; then
    install -d -o root -g root -m 0755 "$directory"
  fi
  if [[ ! -d "$directory" || -L "$directory" || "$(stat -c %u -- "$directory")" != 0 ||
        $((8#$(stat -c %a -- "$directory") & 8#022)) -ne 0 ]]; then
    printf 'recovery install directory is unsafe: %s\n' "$directory" >&2
    exit 73
  fi
done
if [[ -e "$release_root" ]]; then
  if [[ ! -d "$release_root" || -L "$release_root" ||
        "$(stat -c %u -- "$release_root")" != 0 ||
        $((8#$(stat -c %a -- "$release_root") & 8#022)) -ne 0 ]]; then
    printf '%s\n' 'recovery release target exists but is unsafe' >&2
    exit 73
  fi
fi
install -d -o root -g root -m 0755 "$release_root/deploy" "$release_root/scripts"
for relative_path in "${artifacts[@]}"; do
  mode=0644
  [[ "$relative_path" == scripts/* ]] && mode=0755
  destination="$release_root/$relative_path"
  if [[ -e "$destination" ]]; then
    if [[ ! -f "$destination" || -L "$destination" ||
          "$(sha256sum -- "$destination" | awk '{print $1}')" != "$(sha256sum -- "$source_root/$relative_path" | awk '{print $1}')" ]]; then
      printf 'immutable recovery artifact differs: %s\n' "$relative_path" >&2
      exit 73
    fi
  else
    install -o root -g root -m "$mode" -- "$source_root/$relative_path" "$destination"
  fi
  chown root:root "$destination"
  chmod "$mode" "$destination"
done
manifest_path="$release_root/release-manifest.json"
if [[ -e "$manifest_path" ]]; then
  if [[ ! -f "$manifest_path" || -L "$manifest_path" || "$(cat -- "$manifest_path")" != "$release_manifest" ]]; then
    printf '%s\n' 'immutable recovery release manifest differs' >&2
    exit 73
  fi
else
  printf '%s\n' "$release_manifest" > "$manifest_path"
  chown root:root "$manifest_path"
  chmod 0644 "$manifest_path"
fi

temporary_link="$install_root/.current.$$"
trap 'rm -f -- "$temporary_link"' EXIT
ln -s -- "$release_root" "$temporary_link"
mv -Tf -- "$temporary_link" "$install_root/current"
install -o root -g root -m 0644 -- "$release_root/deploy/$unit" "/etc/systemd/system/$unit"
systemctl daemon-reload

python3 - "$profile" "$release_digest" <<'PY'
import json
import sys

print(json.dumps({
    "schema": "qdev-runner-recovery-agent-install-v1",
    "profile": sys.argv[1],
    "agent_release_digest": sys.argv[2],
    "status": "installed",
}, separators=(",", ":"), sort_keys=True))
PY
