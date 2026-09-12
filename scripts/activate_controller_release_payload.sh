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
broker_state_root="/var/lib/qdev-runner/broker-state"
control_state_root="/var/lib/qdev-runner/control-state"
managed_release_state_root="/var/lib/qdev-runner/managed-release-state"
admin_platform_receipt_root="/var/lib/qdev-runner/admin-platform-receipts"
artifact_root="/var/lib/qdev-runner/artifacts"
controller_activation_root="/var/lib/qdev-runner/controller-activation"
host_dispatch_root="/var/lib/qdev-runner/fleet-host-dispatch"
host_dispatch_incoming="$host_dispatch_root/incoming"
host_dispatch_processing="$host_dispatch_root/processing"
host_dispatch_results="$host_dispatch_root/results"
broker_env_path="/etc/qdev-runner/broker.env"
default_admin_platform_ledger_path="/var/lib/qdev-runner/admin-platform-state/admin-platform-ledger.yml"
admin_platform_ledger_path="${QDEV_ADMIN_PLATFORM_LEDGER:-$default_admin_platform_ledger_path}"
default_release_status_path="/var/lib/qdev-runner/controller-status/controller-release.json"
release_status_path="${QDEV_CONTROLLER_RELEASE_STATUS:-$default_release_status_path}"
rollback_anchor_path="${QDEV_CONTROLLER_ROLLBACK_ANCHOR:-/etc/qdev-runner/controller-rollback-anchor.json}"
release_lock_path="${QDEV_CONTROLLER_RELEASE_LOCK:-/run/lock/qdev-controller-release.lock}"
qazcoop_guard_private_key="${QDEV_QAZCOOP_GUARD_PRIVATE_KEY:-/etc/qdev-runner/qazcoop-release-signing/ed25519-private.pem}"
qazcoop_guard_public_key="${QDEV_QAZCOOP_GUARD_PUBLIC_KEY:-/etc/qdev-runner/qazcoop-release-signing/ed25519-public.pem}"
qazcoop_guard_host="${QDEV_QAZCOOP_GUARD_HOST:-root@187.55.228.239}"
qazcoop_repository="${QDEV_QAZCOOP_REPOSITORY:-/opt/qazcoop.git}"
runtime_uid="${QDEV_CONTROLLER_RUNTIME_UID:-9020}"
runtime_gid="${QDEV_CONTROLLER_RUNTIME_GID:-9020}"
script_root="$(cd -- "$(dirname -- "$0")/.." && pwd)"
transaction_hook="${QDEV_CONTROLLER_TRANSACTION_HOOK:-}"
trusted_transaction_hook="$script_root/scripts/activate_controller_release.sh"
if [[ -z "$transaction_hook" || ! -f "$transaction_hook" || -L "$transaction_hook" ||
      "$(realpath -e -- "$transaction_hook")" != "$(realpath -e -- "$trusted_transaction_hook")" ||
      "$(stat -c %u -- "$transaction_hook")" != 0 ||
      $((8#$(stat -c %a -- "$transaction_hook") & 8#022)) -ne 0 ]]; then
  printf 'controller activation requires the exact trusted transaction hook\n' >&2
  exit 77
fi
release="$(realpath -e -- "$1")"
case "$release" in
  "$release_root"/releases/*) ;;
  *)
    printf 'release must be below %s/releases\n' "$release_root" >&2
    exit 64
    ;;
esac
rollback_mode="${QDEV_CONTROLLER_ROLLBACK:-false}"
if [[ "$rollback_mode" != true && "$rollback_mode" != false ]]; then
  printf 'QDEV_CONTROLLER_ROLLBACK must be true or false\n' >&2
  exit 64
fi
expected_current_revision="${QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION:-}"
if [[ ! "$expected_current_revision" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'activation requires QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION\n' >&2
  exit 64
fi
candidate_public_image_digest="${QDEV_CONTROLLER_CANDIDATE_PUBLIC_IMAGE_DIGEST:-}"
candidate_internal_image_digest="${QDEV_CONTROLLER_CANDIDATE_INTERNAL_IMAGE_DIGEST:-}"
candidate_release_digest="${QDEV_CONTROLLER_CANDIDATE_RELEASE_DIGEST:-}"
if [[ ! "$candidate_public_image_digest" =~ ^[0-9a-f]{64}$ ||
      ! "$candidate_internal_image_digest" =~ ^[0-9a-f]{64}$ ||
      ! "$candidate_release_digest" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'activation requires exact candidate public/internal image and release digests\n' >&2
  exit 64
fi
transaction_root="${QDEV_CONTROLLER_TRANSACTION_ROOT:-/var/lib/qdev-runner/controller-activation-transactions}"
transaction_dir="${QDEV_CONTROLLER_TRANSACTION_DIR:-}"
transaction_id="${QDEV_CONTROLLER_TRANSACTION_ID:-}"
envelope_digest="${QDEV_CONTROLLER_ENVELOPE_DIGEST:-}"
recovery_state="${QDEV_CONTROLLER_RECOVERY_STATE:-}"
envelope_expired="${QDEV_CONTROLLER_ENVELOPE_EXPIRED:-false}"
material_helper="$script_root/scripts/controller_activation_material.py"
if [[ ! "$transaction_id" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ||
      ! "$envelope_digest" =~ ^[0-9a-f]{64}$ ]]; then
  printf 'activation transaction identity is invalid\n' >&2
  exit 64
fi
if [[ -z "$transaction_dir" || ! -d "$transaction_root" || -L "$transaction_root" ||
      ! -f "$material_helper" || -L "$material_helper" ||
      "$(stat -c %u -- "$transaction_root")" != 0 ||
      $((8#$(stat -c %a -- "$transaction_root") & 8#022)) -ne 0 ]]; then
  printf 'activation requires exact durable root-owned transaction material\n' >&2
  exit 64
fi
expected_transaction_dir="$transaction_root/$transaction_id-$envelope_digest"
if [[ "$transaction_dir" != "$expected_transaction_dir" ]]; then
  printf 'activation transaction material path does not match its signed identity\n' >&2
  exit 64
fi
if [[ -n "$recovery_state" ]] && {
  [[ ! -d "$transaction_dir" ]] || [[ -L "$transaction_dir" ]] ||
  [[ "$(stat -c %u -- "$transaction_dir")" != 0 ]] ||
  [[ "$(stat -c %a -- "$transaction_dir")" != 700 ]]
}; then
  printf 'recovery requires existing exact durable transaction material\n' >&2
  exit 64
fi
if [[ -n "$recovery_state" &&
      "$recovery_state" != pending-mutating &&
      "$recovery_state" != pending-config-transition &&
      "$recovery_state" != pending-config-installed &&
      "$recovery_state" != pending-candidate-active &&
      "$recovery_state" != committed ]]; then
  printf 'unsupported controller activation recovery state\n' >&2
  exit 64
fi
if [[ "$envelope_expired" != true && "$envelope_expired" != false ]]; then
  printf 'QDEV_CONTROLLER_ENVELOPE_EXPIRED must be true or false\n' >&2
  exit 64
fi
no_build="${QDEV_CONTROLLER_NO_BUILD:-false}"
health_check_attempts="${QDEV_CONTROLLER_HEALTH_CHECK_ATTEMPTS:-90}"
if [[ ! "$runtime_uid" =~ ^[0-9]+$ || ! "$runtime_gid" =~ ^[0-9]+$ ]]; then
  printf 'controller runtime uid/gid must be numeric\n' >&2
  exit 64
fi

anchor_revision=""
anchor_release_digest=""
anchor_release_path=""
anchor_public_image_id=""
anchor_internal_image_id=""
anchor_public_image_ref=""
anchor_internal_image_ref=""
anchor_public_saved_ref=""
anchor_internal_saved_ref=""

load_rollback_anchor() {
  local anchor_output
  anchor_output="$(python3 - "$rollback_anchor_path" "$release_root" <<'PY'
import json
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
release_root = pathlib.Path(sys.argv[2]).resolve(strict=True)
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or stat.S_ISLNK(metadata.st_mode)
    or metadata.st_uid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
):
    raise SystemExit("controller rollback anchor ownership or permissions are unsafe")
payload = json.loads(path.read_text(encoding="utf-8"))
expected = {
    "schema", "revision", "release_digest", "release_path",
    "public_image_id", "internal_image_id", "public_image_ref",
    "internal_image_ref", "public_saved_ref", "internal_saved_ref", "recorded_at",
}
if not isinstance(payload, dict) or set(payload) != expected:
    raise SystemExit("controller rollback anchor schema is invalid")
if payload.get("schema") != "qdev-controller-rollback-anchor-v1":
    raise SystemExit("controller rollback anchor version is invalid")
sha = re.compile(r"^[0-9a-f]{40}$")
digest = re.compile(r"^sha256:[0-9a-f]{64}$")
image_ref = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/:@-]{0,255}$")
if not sha.fullmatch(str(payload.get("revision", ""))):
    raise SystemExit("controller rollback anchor revision is invalid")
for key in ("release_digest", "public_image_id", "internal_image_id"):
    if not digest.fullmatch(str(payload.get(key, ""))):
        raise SystemExit(f"controller rollback anchor {key} is invalid")
for key in (
    "public_image_ref", "internal_image_ref", "public_saved_ref", "internal_saved_ref"
):
    if not image_ref.fullmatch(str(payload.get(key, ""))):
        raise SystemExit(f"controller rollback anchor {key} is invalid")
release_path = pathlib.Path(str(payload.get("release_path", ""))).resolve(strict=True)
releases = (release_root / "releases").resolve(strict=True)
if release_path.parent != releases or not release_path.is_dir():
    raise SystemExit("controller rollback anchor release path is invalid")
for key in (
    "revision", "release_digest", "release_path", "public_image_id",
    "internal_image_id", "public_image_ref", "internal_image_ref",
    "public_saved_ref", "internal_saved_ref",
):
    value = str(release_path) if key == "release_path" else str(payload[key])
    if "\\n" in value or "\\r" in value:
        raise SystemExit("controller rollback anchor contains an unsafe value")
    print(value)
PY
)" || return 1
  mapfile -t anchor_fields <<< "$anchor_output"
  if [[ "${#anchor_fields[@]}" -ne 9 ]]; then
    printf 'controller rollback anchor is incomplete\n' >&2
    return 1
  fi
  anchor_revision="${anchor_fields[0]}"
  anchor_release_digest="${anchor_fields[1]}"
  anchor_release_path="${anchor_fields[2]}"
  anchor_public_image_id="${anchor_fields[3]}"
  anchor_internal_image_id="${anchor_fields[4]}"
  anchor_public_image_ref="${anchor_fields[5]}"
  anchor_internal_image_ref="${anchor_fields[6]}"
  anchor_public_saved_ref="${anchor_fields[7]}"
  anchor_internal_saved_ref="${anchor_fields[8]}"
  if [[ "$release" != "$anchor_release_path" ]]; then
    printf 'rollback target is not the saved controller anchor\n' >&2
    return 1
  fi
}

if [[ "$rollback_mode" == true ]]; then
  load_rollback_anchor || exit 66
fi

# Serialize activation and rollback so two otherwise valid release
# transactions cannot change the current symlink or its evidence concurrently.
exec 9>"$release_lock_path"
if ! flock -n 9; then
  printf 'another controller release transaction owns %s\n' "$release_lock_path" >&2
  exit 75
fi

# Docker preserves the inode of a single-file bind mount.  Migrate the two
# atomically replaced controller records into dedicated directory-mounted
# stores before reading the active revision.  The helper leaves fixed /etc
# compatibility symlinks so the saved v1 rollback runtime observes the same
# records.  Explicit test/maintenance path overrides remain untouched.
durable_state_names=()
if [[ "$release_status_path" == "$default_release_status_path" ]]; then
  durable_state_names+=(status)
fi
if [[ "$admin_platform_ledger_path" == "$default_admin_platform_ledger_path" ]]; then
  durable_state_names+=(ledger)
fi
if [[ -z "$recovery_state" ]] && (( ${#durable_state_names[@]} > 0 )); then
  # The old installation owned this parent as the broker UID.  Harden it
  # before creating root-controlled children so that runtime code cannot
  # rename or replace the status and ledger directories from the host mount.
  install -d -o root -g "$runtime_gid" -m 0750 /var/lib/qdev-runner
  if [[ "$(stat -c '%u:%g:%a' -- /var/lib/qdev-runner)" != "0:$runtime_gid:750" ]]; then
    printf 'controller durable-state parent ownership or permissions are unsafe\n' >&2
    exit 73
  fi
  durable_state_helper="$script_root/src/qdev_runner/durable_state.py"
  if [[ ! -f "$durable_state_helper" ]] ||
    ! python3 -I "$durable_state_helper" "${durable_state_names[@]}"; then
    printf 'controller status/ledger durable-state migration failed\n' >&2
    exit 73
  fi
fi

read_active_release_revision() {
  python3 - "$release_status_path" <<'PY'
import json
import re
import sys
from pathlib import Path

try:
    payload = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
except (OSError, json.JSONDecodeError):
    raise SystemExit(1)

revision = payload.get("revision")
if (
    payload.get("schema") not in {
        "qdev-controller-release-status-v1",
        "qdev-controller-release-status-v2",
    }
    or payload.get("state") != "active"
    or not isinstance(revision, str)
    or re.fullmatch(r"[0-9a-f]{40}", revision) is None
):
    raise SystemExit(1)
print(revision)
PY
}

assert_expected_current_revision() {
  local observed_revision
  if ! observed_revision="$(read_active_release_revision)"; then
    printf 'active controller release status is unavailable or invalid\n' >&2
    exit 75
  fi
  if [[ "$observed_revision" != "$expected_current_revision" ]]; then
    printf 'controller release compare-and-swap rejected expected=%s observed=%s\n' \
      "$expected_current_revision" "$observed_revision" >&2
    exit 75
  fi
}

# Fail before capacity work, backups or any configuration mutation if this
# transaction was prepared against a controller runtime that is no longer live.
if [[ -z "$recovery_state" ]]; then
  assert_expected_current_revision
fi
# Forward activation is fail-closed on the durable, runtime-readable Admin Platform
# v3 ledger and its fixed product adapters.  Packaged ledger snapshots are not
# activation inputs: they can be stale by construction because the ledger
# binds the exact candidate being activated. Rollback is accepted only for the
# root-owned exact runtime anchor and also preserves the durable ledger.
required=(
  pyproject.toml \
  requirements.runtime.txt \
  src/qdev_runner/__init__.py \
  deploy/compose.yml \
  inventory/repos.json \
  config/profiles.yml \
  config/admin-platform-package-bindings.json \
  config/release-lanes.yml \
  config/fleet-bootstrap.yml \
  config/managed-registry.yml \
  config/managed-release-ledger.yml \
  scripts/provision_operator_identity.sh \
  scripts/qaz_tours_release_host_agent.py \
  scripts/qdev_product_release_host_agent.py \
  deploy/qdev-release-qaz-tours.service \
  deploy/qdev-release-qaz-fund.service \
  deploy/qdev-release-qaz-events.service \
  deploy/qdev-release-qmt.service \
  deploy/qdev-release-qazpolit.service \
  deploy/qdev-release-qmt.compose.yml \
  deploy/Dockerfile.broker
)
if [[ "$rollback_mode" != true ]]; then
  required+=(
    config/controller-capacity.json
    scripts/controller_capacity_gate.py
    scripts/validate_controller_image_binding.py
    src/qdev_runner/durable_state.py
    src/qdev_runner/controller_candidate.py
    scripts/bootstrap_admin_platform_ledger_v3.py
    scripts/prepare_controller_candidate.py
    src/qdev_runner/controller_activation_assets.py
    scripts/controller_activation_assets.py
    scripts/dispatch_fleet_bootstrap.py
    scripts/build_qazcoop_release_guard_bundle.py
    scripts/install_qazcoop_release_guard.py
    scripts/qazcoop_update_hook.py
    src/qdev_runner/qazcoop_release_guard.py
    scripts/qdev_admin_platform_release_host_agent.py
    scripts/qmt_native_release_adapter.py
    scripts/qazpolit_native_release_adapter.py
    scripts/qdev_controller_activation_adapter.py
    scripts/provision_controller_activation_trust.py
    scripts/qdev_release_host_agent_enrol_adapter.py
    scripts/qdev_fleet_worker_recovery_adapter.py
    scripts/qdev_fixed_worker_recovery_dispatch.py
    scripts/qdev_recovery_host_enrol_adapter.py
    scripts/qdev_recovery_host_apply.py
    scripts/qdev_runner_recovery_host_agent.py
    scripts/install_qdev_runner_recovery_host_agent.sh
    scripts/issue_scoped_worker_certificate.sh
    scripts/provision_fleet_host_dispatch_state.py
    scripts/qdev_controller_admission_host.sh
    deploy/qdev-runner-recovery-platform.service
    deploy/qdev-runner-recovery-qazstack.service
    deploy/qdev-release-ortcom.service
    deploy/qdev-release-cmnt.service
    deploy/qdev-release-total.service
    deploy/qdev-release-qazposter.service
    deploy/qdev-fleet-host-dispatch.service
    deploy/qdev-fleet-host-dispatch.path
  )
fi
for required_file in "${required[@]}"; do
  [[ -f "$release/$required_file" ]] || {
    printf 'release is missing %s\n' "$required_file" >&2
    exit 66
  }
done
release_status_directory="$(dirname -- "$release_status_path")"
[[ -d "$release_status_directory" ]] || {
  printf 'controller release status directory is missing: %s\n' "$release_status_directory" >&2
  exit 73
}

target_has_runtime_health=false
if grep -Fq '@app.get("/health/runtime"' "$release/src/qdev_runner/broker.py"; then
  target_has_runtime_health=true
elif [[ "$rollback_mode" != true ]]; then
  printf 'forward controller release lacks measured runtime health\n' >&2
  exit 66
fi

# The broker runs rootless. Prepare its persistent operation store before any
# container is recreated so a valid release cannot fail after the old broker
# has already been replaced. Numeric IDs are intentional: the runtime image
# owns this UID/GID even when the host has no matching passwd entry.
if [[ -z "$recovery_state" ]]; then
for durable_root in \
  "$operations_root" \
  "$release_jobs_root" \
  "$broker_state_root" \
  "$control_state_root" \
  "$managed_release_state_root" \
    "$admin_platform_receipt_root" \
    "$artifact_root"; do
  install -d -o "$runtime_uid" -g "$runtime_gid" -m 0700 -- "$durable_root"
  if [[ "$(stat -c %u -- "$durable_root")" != "$runtime_uid" ||
        "$(stat -c %g -- "$durable_root")" != "$runtime_gid" ]]; then
    printf 'controller durable-store ownership check failed for %s\n' "$durable_root" >&2
    exit 73
  fi
done

# The host activation CLI owns this state; the rootless broker only reads it.
install -d -o root -g "$runtime_gid" -m 0750 -- "$controller_activation_root"

# The request/result bridge is deliberately split by ownership.  Results and
# in-flight markers are outside the broker container lifecycle, so recreating
# the brokers cannot erase the outcome that the next poll must reconcile.
install -d -o root -g root -m 0755 -- "$host_dispatch_root"
install -d -o "$runtime_uid" -g "$runtime_gid" -m 0700 -- \
  "$host_dispatch_incoming"
install -d -o root -g root -m 0700 -- "$host_dispatch_processing"
install -d -o root -g "$runtime_gid" -m 0750 -- "$host_dispatch_results"
if [[ "$(stat -c '%u:%g:%a' -- "$host_dispatch_incoming")" != \
      "$runtime_uid:$runtime_gid:700" ||
      "$(stat -c '%u:%g:%a' -- "$host_dispatch_processing")" != "0:0:700" ||
      "$(stat -c '%u:%g:%a' -- "$host_dispatch_results")" != \
      "0:$runtime_gid:750" ]]; then
  printf 'controller host-dispatch ownership or permissions are unsafe\n' >&2
  exit 73
fi

ensure_artifact_token_key() {
  local line_count artifact_key temporary_env
  if [[ ! -f "$broker_env_path" || -L "$broker_env_path" ||
        "$(stat -c %u -- "$broker_env_path")" != 0 ]]; then
    printf 'broker environment must be a root-owned regular file\n' >&2
    return 1
  fi
  if (( (8#$(stat -c %a -- "$broker_env_path") & 8#077) != 0 )); then
    printf 'broker environment permissions expose controller secrets\n' >&2
    return 1
  fi
  line_count="$(
    awk -F= '$1 == "QDEV_ARTIFACT_TOKEN_KEY" {count += 1} END {print count + 0}' \
      "$broker_env_path"
  )"
  if [[ "$line_count" == 1 ]]; then
    artifact_key="$(
      awk -F= '$1 == "QDEV_ARTIFACT_TOKEN_KEY" {sub(/^[^=]*=/, ""); print}' \
        "$broker_env_path"
    )"
    if [[ ! "$artifact_key" =~ ^[A-Za-z0-9_-]{32,256}$ ]]; then
      printf 'QDEV_ARTIFACT_TOKEN_KEY has an unsafe format\n' >&2
      return 1
    fi
    unset artifact_key
    return 0
  fi
  if [[ "$line_count" != 0 ]]; then
    printf 'broker environment contains duplicate artifact token keys\n' >&2
    return 1
  fi
  artifact_key="$(openssl rand -hex 32)"
  temporary_env="$(mktemp /etc/qdev-runner/.broker.env.XXXXXX)"
  install -m 0600 -- "$broker_env_path" "$temporary_env"
  printf 'QDEV_ARTIFACT_TOKEN_KEY=%s\n' "$artifact_key" >> "$temporary_env"
  chown root:root -- "$temporary_env"
  chmod 0600 -- "$temporary_env"
  mv -f -- "$temporary_env" "$broker_env_path"
  unset artifact_key
}

if ! ensure_artifact_token_key; then
  exit 66
fi

disk_used="$(df -P / | awk 'NR==2 {gsub(/%/, "", $5); print $5}')"
disk_free_kib="$(df -Pk / | awk 'NR==2 {print $4}')"
memory_kib="$(awk '/MemAvailable:/ {print $2}' /proc/meminfo)"
cpu_count="$(nproc)"
load_15="$(awk '{print $3}' /proc/loadavg)"
no_build="${QDEV_CONTROLLER_NO_BUILD:-false}"
allow_build_capacity_override="${QDEV_CONTROLLER_ALLOW_BUILD_CAPACITY_OVERRIDE:-false}"
# 90% is the absolute published ceiling for the exact TTL-bounded claim and is
# never overridable; 4.5 GiB is the matching free-space floor (rounded up to a
# whole GiB here because this gate is integer-only).
max_disk_used_pct="${QDEV_CONTROLLER_MAX_DISK_USED_PCT:-90}"
min_free_gib="${QDEV_CONTROLLER_MIN_FREE_GIB:-8}"
min_memory_gib="${QDEV_CONTROLLER_MIN_MEMORY_AVAILABLE_GIB:-4}"
max_load_per_cpu="${QDEV_CONTROLLER_MAX_LOAD_PER_CPU:-2}"
health_check_attempts="${QDEV_CONTROLLER_HEALTH_CHECK_ATTEMPTS:-90}"
if [[ "$no_build" != true && "$no_build" != false ]]; then
  printf 'QDEV_CONTROLLER_NO_BUILD must be true or false\n' >&2
  exit 64
fi
if [[ "$rollback_mode" == true && "$no_build" != true ]]; then
  printf 'controller rollback requires QDEV_CONTROLLER_NO_BUILD=true\n' >&2
  exit 64
fi
for value in "$max_disk_used_pct" "$min_free_gib" "$min_memory_gib" "$max_load_per_cpu" "$health_check_attempts"; do
  [[ "$value" =~ ^[0-9]+$ ]] || {
    printf 'controller capacity overrides must be non-negative integers\n' >&2
    exit 64
  }
done
if (( max_disk_used_pct > 90 )); then
  printf 'QDEV_CONTROLLER_MAX_DISK_USED_PCT must not exceed 90 (91/95/97 are rejected)\n' >&2
  exit 64
fi
if (( min_free_gib < 5 )); then
  printf 'QDEV_CONTROLLER_MIN_FREE_GIB must be at least 5 (4.5 GiB hard floor)\n' >&2
  exit 64
fi
if [[ "$allow_build_capacity_override" != true && "$allow_build_capacity_override" != false ]]; then
  printf 'QDEV_CONTROLLER_ALLOW_BUILD_CAPACITY_OVERRIDE must be true or false\n' >&2
  exit 64
fi
if (( health_check_attempts < 30 || health_check_attempts > 180 )); then
  printf 'QDEV_CONTROLLER_HEALTH_CHECK_ATTEMPTS must be an integer from 30 to 180\n' >&2
  exit 64
fi
if [[ "$no_build" != true && "$allow_build_capacity_override" != true ]] && {
  [[ "$max_disk_used_pct" != 90 ]] || [[ "$min_free_gib" != 8 ]] ||
    [[ "$min_memory_gib" != 4 ]] || [[ "$max_load_per_cpu" != 2 ]]
}; then
  printf 'controller capacity overrides require QDEV_CONTROLLER_NO_BUILD=true or an explicit build override\n' >&2
  exit 64
fi
python3 "$release/scripts/controller_capacity_gate.py" \
  --capacity-config "$release/config/controller-capacity.json" \
  --disk-used-pct "$disk_used" \
  --disk-free-kib "$disk_free_kib" \
  --memory-kib "$memory_kib" \
  --cpu-count "$cpu_count" \
  --load-15 "$load_15" \
  --max-disk-used-pct "$max_disk_used_pct" \
  --min-free-gib "$min_free_gib" \
  --min-memory-gib "$min_memory_gib" \
  --max-load-per-cpu "$max_load_per_cpu" \
  --no-build "$no_build" || {
    printf 'capacity gate rejected controller activation used=%s free_kib=%s memory_kib=%s load15=%s\n' \
      "$disk_used" "$disk_free_kib" "$memory_kib" "$load_15" >&2
    exit 75
  }
fi

current="$release_root/current"
admission_host_tool_path=/usr/local/sbin/qdev-controller-admission
qazcoop_guard_temporary=""
operator_identity_dir=/etc/qdev-runner/mtls/operator

material_json_value() {
  python3 -c 'import json,sys; value=json.load(sys.stdin); print(eval(sys.argv[1], {"__builtins__": {}}, {"v": value}))' "$1"
}

dispatcher_enabled="$(systemctl is-enabled qdev-fleet-host-dispatch.path 2>/dev/null || true)"
dispatcher_active="$(systemctl is-active qdev-fleet-host-dispatch.path 2>/dev/null || true)"
if [[ -z "$recovery_state" ]]; then
  previous="$(readlink -f -- "$current" 2>/dev/null || true)"
  previous_public_image="$(docker inspect qdev-runner-broker-public --format '{{.Image}}' 2>/dev/null || true)"
  previous_public_ref="$(docker inspect qdev-runner-broker-public --format '{{.Config.Image}}' 2>/dev/null || true)"
  previous_internal_image="$(docker inspect qdev-runner-broker-internal --format '{{.Image}}' 2>/dev/null || true)"
  previous_internal_ref="$(docker inspect qdev-runner-broker-internal --format '{{.Config.Image}}' 2>/dev/null || true)"
  rollback_public_ref="qdev-runner-rollback-public:${envelope_digest:0:32}"
  rollback_internal_ref="qdev-runner-rollback-internal:${envelope_digest:0:32}"
  material="$({
    python3 "$material_helper" prepare \
      --root "$transaction_root" \
      --transaction-id "$transaction_id" \
      --envelope-digest "$envelope_digest" \
      --release-path "$release" \
      --previous-release-path "$previous" \
      --previous-public-image "$previous_public_image" \
      --previous-public-ref "$previous_public_ref" \
      --previous-internal-image "$previous_internal_image" \
      --previous-internal-ref "$previous_internal_ref" \
      --rollback-public-ref "$rollback_public_ref" \
      --rollback-internal-ref "$rollback_internal_ref" \
      --dispatcher-enabled "$dispatcher_enabled" \
      --dispatcher-active "$dispatcher_active" \
      --snapshot "configuration=/etc/qdev-runner/repos.json" \
      --snapshot "configuration=/etc/qdev-runner/profiles.yml" \
      --snapshot "configuration=/etc/qdev-runner/admin-platform-package-bindings.json" \
      --snapshot "configuration=/etc/qdev-runner/release-lanes.yml" \
      --snapshot "configuration=/etc/qdev-runner/fleet-bootstrap.yml" \
      --snapshot "configuration=/etc/qdev-runner/managed-registry.yml" \
      --snapshot "configuration=/etc/qdev-runner/managed-release-ledger.yml" \
      --snapshot "status=$release_status_path" \
      --snapshot "anchor=$rollback_anchor_path" \
      --snapshot "operator=$operator_identity_dir/ca.pem" \
      --snapshot "operator=$operator_identity_dir/operator-cert.pem" \
      --snapshot "operator=$operator_identity_dir/operator-key.pem" \
      --snapshot "dispatcher=/usr/local/sbin/qdev-admin-platform-ledger-bootstrap" \
      --snapshot "dispatcher=/usr/local/libexec/qdev-fleet-host-dispatch" \
      --snapshot "dispatcher=/usr/local/sbin/qdev-controller-activate" \
      --snapshot "dispatcher=/usr/local/sbin/qdev-controller-admission" \
      --snapshot "dispatcher=/usr/local/sbin/qdev-release-host-agent-enrol" \
      --snapshot "dispatcher=/usr/local/sbin/qdev-fleet-worker-recovery" \
      --snapshot "dispatcher=/usr/local/sbin/qdev-fleet-host-dispatch-state-provision" \
      --snapshot "dispatcher=/etc/systemd/system/qdev-fleet-host-dispatch.service" \
      --snapshot "dispatcher=/etc/systemd/system/qdev-fleet-host-dispatch.path"
  })" || exit 66
  if [[ -n "$previous_public_image" ]]; then
    docker image tag "$previous_public_image" "$rollback_public_ref"
  fi
  if [[ -n "$previous_internal_image" ]]; then
    docker image tag "$previous_internal_image" "$rollback_internal_ref"
  fi
else
  material="$(python3 "$material_helper" show --directory "$transaction_dir")" || exit 66
  if [[ "$(printf '%s' "$material" | material_json_value 'v["transaction_id"]')" != "$transaction_id" ||
        "$(printf '%s' "$material" | material_json_value 'v["envelope_digest"]')" != "$envelope_digest" ||
        "$(printf '%s' "$material" | material_json_value 'v["release_path"]')" != "$release" ]]; then
    printf 'durable activation material does not match the recovery transaction\n' >&2
    exit 78
  fi
  previous="$(printf '%s' "$material" | material_json_value 'v["previous_release_path"]')"
  previous_public_image="$(printf '%s' "$material" | material_json_value 'v["previous_public_image"]')"
  previous_public_ref="$(printf '%s' "$material" | material_json_value 'v["previous_public_ref"]')"
  previous_internal_image="$(printf '%s' "$material" | material_json_value 'v["previous_internal_image"]')"
  previous_internal_ref="$(printf '%s' "$material" | material_json_value 'v["previous_internal_ref"]')"
  rollback_public_ref="$(printf '%s' "$material" | material_json_value 'v["rollback_public_ref"]')"
  rollback_internal_ref="$(printf '%s' "$material" | material_json_value 'v["rollback_internal_ref"]')"
  dispatcher_enabled="$(printf '%s' "$material" | material_json_value 'v["dispatcher_enabled"]')"
  dispatcher_active="$(printf '%s' "$material" | material_json_value 'v["dispatcher_active"]')"
fi

release_status_backup="$(mktemp /run/qdev-controller-release-status.XXXXXX)"
release_status_was_present=false
if python3 "$material_helper" extract --directory "$transaction_dir" \
  --destination "$release_status_path" --output "$release_status_backup" >/dev/null 2>&1; then
  release_status_was_present=true
fi
operator_identity_was_present=true

cleanup_rollback_images() {
  docker image rm "$rollback_public_ref" "$rollback_internal_ref" >/dev/null 2>&1 || true
}

cleanup_staged_anchor_images() {
  local staged_public staged_internal
  staged_public="$(printf '%s' "$material" | material_json_value 'v.get("staged_public_saved_ref", "")')"
  staged_internal="$(printf '%s' "$material" | material_json_value 'v.get("staged_internal_saved_ref", "")')"
  [[ -z "$staged_public" ]] || docker image rm "$staged_public" >/dev/null 2>&1 || true
  [[ -z "$staged_internal" ]] || docker image rm "$staged_internal" >/dev/null 2>&1 || true
}

finish_transaction_material() {
  local outcome="$1"
  cleanup_rollback_images
  if [[ "$outcome" == rolled-back ]]; then
    cleanup_staged_anchor_images || return 1
  fi
  python3 "$material_helper" finish --directory "$transaction_dir" \
    --outcome "$outcome" >/dev/null
}

set_transaction_phase() {
  python3 "$material_helper" phase --directory "$transaction_dir" \
    --phase "$1" >/dev/null
}

activation_mutated=false
activation_finished=false
rollback_started=false
material_phase="$(printf '%s' "$material" | material_json_value 'v["phase"]')"
external_guard_reconciliation_started=false
if [[ "$material_phase" == external-guard-reconciling ||
      "$material_phase" == external-guard-reconciled ]]; then
  external_guard_reconciliation_started=true
fi

cleanup_qazcoop_guard_temporary() {
  [[ -n "$qazcoop_guard_temporary" ]] || return 0
  if [[ ! "$qazcoop_guard_temporary" =~ ^/tmp/qazcoop-release-guard\.[A-Za-z0-9]+$ ||
        -L "$qazcoop_guard_temporary" ]]; then
    printf 'QazCoop temporary bundle path is invalid\n' >&2
    return 1
  fi
  rm -rf -- "$qazcoop_guard_temporary" || return 1
  qazcoop_guard_temporary=""
}

cleanup_activation_payload() {
  local status=$?
  trap - EXIT
  if [[ "$activation_mutated" == true && "$activation_finished" != true &&
        "$rollback_started" != true &&
        "$external_guard_reconciliation_started" != true ]]; then
    rollback_started=true
    if ! rollback; then
      printf 'automatic controller rollback failed during payload exit\n' >&2
      status=1
    fi
  fi
  cleanup_qazcoop_guard_temporary || status=1
  rm -f -- "$release_status_backup"
  exit "$status"
}
trap cleanup_activation_payload EXIT

admission_host_tool_path=/usr/local/sbin/qdev-controller-admission
qazcoop_guard_temporary=""

activate_link() {
  local target="$1"
  python3 "$material_helper" activate-link --directory "$transaction_dir" \
    --link "$current" --target "$target" >/dev/null
}

atomic_install() {
  local source="$1" destination="$2" mode="$3"
  python3 "$material_helper" install --directory "$transaction_dir" \
    --source "$source" --destination "$destination" --mode "$mode" >/dev/null
}

release_revision="${QDEV_CONTROLLER_RELEASE_REVISION:-}"
detected_release_revision="$(git -C "$release" rev-parse --verify HEAD 2>/dev/null || true)"
detected_release_root="$(git -C "$release" rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -n "$release_revision" && -n "$detected_release_revision" &&
      "$release_revision" != "$detected_release_revision" ]]; then
  printf 'declared controller revision does not match the release checkout\n' >&2
  exit 66
fi
if [[ -z "$release_revision" ]]; then
  release_revision="$detected_release_revision"
fi
if [[ ! "$release_revision" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'release must expose an exact git revision via HEAD or QDEV_CONTROLLER_RELEASE_REVISION\n' >&2
  exit 66
fi
if [[ "$rollback_mode" == true && "$release_revision" != "$anchor_revision" ]]; then
  printf 'rollback checkout does not match the saved controller anchor revision\n' >&2
  exit 66
fi
if [[ -z "$detected_release_root" ||
      "$(realpath -e -- "$detected_release_root")" != "$release" ]]; then
  printf 'controller activation requires a source-bound git release checkout\n' >&2
  exit 66
fi
if ! git -C "$release" diff --quiet "$release_revision" -- .; then
  printf 'controller release differs from the declared exact revision\n' >&2
  exit 66
fi
untracked_release_source="$(
  git -C "$release" ls-files --others --exclude-standard -- .
)"
if [[ -n "$untracked_release_source" ]]; then
  printf 'controller release contains untracked files\n' >&2
  exit 66
fi

validate_durable_admin_platform_ledger() {
  local validation_program
  validation_program='import os
import pathlib
import stat
import sys

from qdev_runner.admin_platform import AdminPlatformLedger

ledger_path = pathlib.Path(sys.argv[1])
receipt_root = pathlib.Path(sys.argv[2])
broker_env_path = pathlib.Path(sys.argv[3])
revision = sys.argv[4]
require_candidate = sys.argv[5] == "true"
runtime_uid = int(sys.argv[6])
runtime_gid = int(sys.argv[7])

metadata = ledger_path.lstat()
if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
    raise SystemExit("durable admin platform ledger is not a regular file")
if (
    metadata.st_uid != runtime_uid
    or metadata.st_gid != runtime_gid
    or stat.S_IMODE(metadata.st_mode) != 0o600
):
    raise SystemExit("durable admin platform ledger ownership or permissions are unsafe")

receipt_key = None
if broker_env_path.exists():
    env_metadata = broker_env_path.lstat()
    if (
        not stat.S_ISREG(env_metadata.st_mode)
        or stat.S_ISLNK(env_metadata.st_mode)
        or env_metadata.st_uid != 0
        or stat.S_IMODE(env_metadata.st_mode) & 0o077
    ):
        raise SystemExit("broker environment ownership or permissions are unsafe")
    matches = []
    for line in broker_env_path.read_text(encoding="utf-8").splitlines():
        name, separator, value = line.partition("=")
        if separator and name == "QDEV_OPERATOR_RECEIPT_KEY":
            matches.append(value)
    if len(matches) > 1:
        raise SystemExit("broker environment contains duplicate operator receipt keys")
    if matches:
        receipt_key = matches[0]

ledger = AdminPlatformLedger(
    ledger_path,
    receipt_key=receipt_key,
    receipt_root=receipt_root,
)
if require_candidate:
    candidate = ledger.active_candidate
    if (
        ledger.active_stage != "controller"
        or candidate is None
        or candidate.source_sha != revision
    ):
        raise SystemExit(
            "durable admin platform ledger does not admit the exact controller candidate"
        )'
  if [[ ! -e "$admin_platform_ledger_path" ]]; then
    printf '%s\n' \
      'durable Admin Platform v3 ledger is missing; seed it with the root-controlled exact-candidate migration before activation' >&2
    return 1
  fi
  local validation_root="$release"
  if [[ "$rollback_mode" == true ]]; then
    validation_root="$script_root"
  fi
  PYTHONPATH="$validation_root/src" python3 -c "$validation_program" \
    "$admin_platform_ledger_path" "$admin_platform_receipt_root" \
    "$broker_env_path" "$release_revision" \
    "$([[ "$rollback_mode" == true ]] && printf false || printf true)" \
    "$runtime_uid" "$runtime_gid"
}

if [[ -z "$recovery_state" ]] && ! validate_durable_admin_platform_ledger; then
  printf '%s\n' \
    'controller activation preserves the existing ledger and will not install a packaged snapshot' >&2
  exit 66
fi
if [[ "$rollback_mode" == true ]]; then
  release_digest="$anchor_release_digest"
else
  release_digest="$(
    PYTHONPATH="$release/src" python3 -m qdev_runner.controller_release "$release"
  )"
fi
if [[ "${release_digest#sha256:}" != "$candidate_release_digest" ]]; then
  printf 'controller release bytes do not match the signed candidate digest\n' >&2
  exit 78
fi

source_digest_program='import hashlib
import pathlib
import sys

root = pathlib.Path(sys.argv[1])
files = [root / "pyproject.toml", root / "requirements.runtime.txt"]
files.extend(sorted((root / "src" / "qdev_runner").rglob("*.py")))
if any(not path.is_file() for path in files):
    raise SystemExit("controller runtime source is incomplete")
digest = hashlib.sha256()
for path in files:
    relative = path.relative_to(root).as_posix().encode("utf-8")
    digest.update(relative)
    digest.update(b"\\0")
    digest.update(hashlib.sha256(path.read_bytes()).digest())
    digest.update(b"\\0")
print("sha256:" + digest.hexdigest())'

dependency_digest_program='import hashlib
import importlib.metadata

rows = []
for distribution in importlib.metadata.distributions():
    name = (distribution.metadata.get("Name") or "").strip().lower()
    if name:
        rows.append(f"{name}=={distribution.version}")
payload = ("\\n".join(sorted(rows)) + "\\n").encode("utf-8")
print("sha256:" + hashlib.sha256(payload).hexdigest())'

runtime_source_digest="$(python3 -c "$source_digest_program" "$release")"
runtime_requirements_digest="sha256:$(sha256sum -- "$release/requirements.runtime.txt" | awk '{print $1}')"
runtime_public_image_id=""
runtime_internal_image_id=""
runtime_public_dependencies_digest=""
runtime_internal_dependencies_digest=""

require_sha256_identity() {
  local label="$1"
  local value="$2"
  if [[ ! "$value" =~ ^sha256:[0-9a-f]{64}$ ]]; then
    printf '%s is not a measured sha256 identity\n' "$label" >&2
    return 1
  fi
}

measure_runtime_identity() {
  local public_source_digest internal_source_digest
  local public_requirements_digest internal_requirements_digest
  local public_running internal_running

  public_running="$(docker inspect qdev-runner-broker-public --format '{{.State.Running}}')" || return 1
  internal_running="$(docker inspect qdev-runner-broker-internal --format '{{.State.Running}}')" || return 1
  if [[ "$public_running" != true || "$internal_running" != true ]]; then
    printf 'controller runtime identity requires both brokers to be running\n' >&2
    return 1
  fi

  runtime_public_image_id="$(docker inspect qdev-runner-broker-public --format '{{.Image}}')" || return 1
  runtime_internal_image_id="$(docker inspect qdev-runner-broker-internal --format '{{.Image}}')" || return 1
  require_sha256_identity "public broker image" "$runtime_public_image_id" || return 1
  require_sha256_identity "internal broker image" "$runtime_internal_image_id" || return 1

  public_source_digest="$(
    docker exec qdev-runner-broker-public python -c "$source_digest_program" /app
  )" || return 1
  internal_source_digest="$(
    docker exec qdev-runner-broker-internal python -c "$source_digest_program" /app
  )" || return 1
  require_sha256_identity "release source" "$runtime_source_digest" || return 1
  require_sha256_identity "public broker source" "$public_source_digest" || return 1
  require_sha256_identity "internal broker source" "$internal_source_digest" || return 1
  if [[ "$public_source_digest" != "$runtime_source_digest" ||
        "$internal_source_digest" != "$runtime_source_digest" ]]; then
    printf 'running controller source does not match the activated release\n' >&2
    return 1
  fi

  public_requirements_digest="$(
    docker exec qdev-runner-broker-public sha256sum /app/requirements.runtime.txt |
      awk '{print "sha256:" $1}'
  )" || return 1
  internal_requirements_digest="$(
    docker exec qdev-runner-broker-internal sha256sum /app/requirements.runtime.txt |
      awk '{print "sha256:" $1}'
  )" || return 1
  require_sha256_identity "release requirements" "$runtime_requirements_digest" || return 1
  require_sha256_identity "public broker requirements" "$public_requirements_digest" || return 1
  require_sha256_identity "internal broker requirements" "$internal_requirements_digest" || return 1
  if [[ "$public_requirements_digest" != "$runtime_requirements_digest" ||
        "$internal_requirements_digest" != "$runtime_requirements_digest" ]]; then
    printf 'running controller requirements do not match the activated release\n' >&2
    return 1
  fi

  runtime_public_dependencies_digest="$(
    docker exec qdev-runner-broker-public python -c "$dependency_digest_program"
  )" || return 1
  runtime_internal_dependencies_digest="$(
    docker exec qdev-runner-broker-internal python -c "$dependency_digest_program"
  )" || return 1
  require_sha256_identity \
    "public broker installed distributions" "$runtime_public_dependencies_digest" || return 1
  require_sha256_identity \
    "internal broker installed distributions" "$runtime_internal_dependencies_digest" || return 1
  if [[ "$runtime_public_dependencies_digest" != "$runtime_internal_dependencies_digest" ]]; then
    printf 'controller brokers do not have the same installed dependencies\n' >&2
    return 1
  fi
}

write_release_status() {
  local legacy_digest temporary_status
  temporary_status="$(mktemp "$release_status_directory/.controller-release-status.XXXXXX")"
  if [[ "$target_has_runtime_health" == true ]]; then
    printf '%s\n' \
      "{\"schema\":\"qdev-controller-release-status-v2\",\"state\":\"active\",\"revision\":\"$release_revision\",\"release_digest\":\"$release_digest\",\"activated_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"runtime_identity\":{\"source_revision\":\"$release_revision\",\"source_digest\":\"$runtime_source_digest\",\"public_image_id\":\"$runtime_public_image_id\",\"internal_image_id\":\"$runtime_internal_image_id\"},\"dependency_identity\":{\"requirements_digest\":\"$runtime_requirements_digest\",\"public_installed_digest\":\"$runtime_public_dependencies_digest\",\"internal_installed_digest\":\"$runtime_internal_dependencies_digest\"}}" \
      > "$temporary_status"
  else
    # The saved v1 broker deliberately rejects unknown status fields and a
    # sha256: prefix.  Runtime/source/dependency measurements are still made
    # and retained by the signed rollback operation; this projection is only
    # the compatibility shape the old runtime can expose through /health.
    legacy_digest="${release_digest#sha256:}"
    printf '%s\n' \
      "{\"schema\":\"qdev-controller-release-status-v1\",\"state\":\"active\",\"revision\":\"$release_revision\",\"release_digest\":\"$legacy_digest\",\"activated_at\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\"}" \
      > "$temporary_status"
  fi
  chmod 0644 "$temporary_status"
  mv -f -- "$temporary_status" "$release_status_path"
}

verify_controller_runtime_health() {
  local health_program
  if [[ "$target_has_runtime_health" == true ]]; then
    health_program='import json
import sys
import urllib.request

revision, release_digest, public_image, internal_image = sys.argv[1:]
with urllib.request.urlopen(
    "http://127.0.0.1:9443/health/runtime", timeout=5
) as response:
    if response.status != 200:
        raise SystemExit("internal runtime health returned a non-success status")
    document = json.load(response)
if document.get("schema") != "qdev-controller-runtime-health-v1":
    raise SystemExit("internal runtime health schema is invalid")
if document.get("state") != "active" or document.get("revision") != revision:
    raise SystemExit("internal runtime health is not bound to the active revision")
if document.get("digest") != release_digest:
    raise SystemExit("internal runtime health is not bound to the release digest")
runtime = document.get("runtime_identity")
if not isinstance(runtime, dict):
    raise SystemExit("internal runtime health omitted measured identity")
if runtime.get("public_image_id") != public_image or runtime.get(
    "internal_image_id"
) != internal_image:
    raise SystemExit("internal runtime health image identity is invalid")'
    docker exec qdev-runner-broker-internal python -c "$health_program" \
      "$release_revision" "$release_digest" \
      "$runtime_public_image_id" "$runtime_internal_image_id"
    return
  fi

  [[ "$rollback_mode" == true ]] || return 1
  health_program='import json
import sys
import urllib.request

revision, release_digest = sys.argv[1:]
with urllib.request.urlopen("https://ci.qdev.run/health", timeout=5) as response:
    if response.status != 200:
        raise SystemExit("legacy public health returned a non-success status")
    document = json.load(response)
controller = document.get("controller_release")
if not isinstance(controller, dict):
    raise SystemExit("legacy public health omitted controller release identity")
if controller.get("schema") != "qdev-controller-release-status-v1":
    raise SystemExit("legacy public health status schema is invalid")
if controller.get("state") != "active" or controller.get("revision") != revision:
    raise SystemExit("legacy public health is not bound to the active revision")
if controller.get("release_digest") != release_digest:
    raise SystemExit("legacy public health is not bound to the release digest")'
  python3 -c "$health_program" "$release_revision" "${release_digest#sha256:}"
}

restore_release_status() {
  python3 "$material_helper" restore --directory "$transaction_dir" \
    --group status >/dev/null
}

install_qazcoop_release_guard() {
  # The remote guard is monotonic and remains compatible with the previous
  # controller.  Once its installer can have run, local rollback is forbidden:
  # recovery must idempotently reconcile the candidate controller and guard to
  # the same generation instead of manufacturing an A-controller/B-guard split,
  # so the currently deployed product remains available throughout recovery.
  [[ "$rollback_mode" != true ]] || return 0
  if [[ ! "$qazcoop_guard_host" =~ ^root@[A-Za-z0-9.-]+$ ]]; then
    printf 'QazCoop guard host is invalid\n' >&2
    return 1
  fi
  if [[ "$qazcoop_repository" != /opt/qazcoop.git ]]; then
    printf 'QazCoop production repository path is invalid\n' >&2
    return 1
  fi
  for key_path in "$qazcoop_guard_private_key" "$qazcoop_guard_public_key"; do
    if [[ ! -f "$key_path" || -L "$key_path" ]]; then
      printf 'QazCoop release signing key is unavailable: %s\n' "$key_path" >&2
      return 1
    fi
  done
  qazcoop_guard_temporary="$(mktemp -d /tmp/qazcoop-release-guard.XXXXXXXX)" || return 1
  local bundle="$qazcoop_guard_temporary/bundle"
  if ! python3 "$release/scripts/build_qazcoop_release_guard_bundle.py" \
    --controller-repository "$release" \
    --controller-revision "$release_revision" \
    --private-key "$qazcoop_guard_private_key" \
    --public-key "$qazcoop_guard_public_key" \
    --output "$bundle"; then
    return 1
  fi
  local remote_stage
  remote_stage="$(
    ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -- "$qazcoop_guard_host" \
      'mktemp -d /run/qazcoop-release-guard.XXXXXXXX'
  )" || return 1
  if [[ ! "$remote_stage" =~ ^/run/qazcoop-release-guard\.[A-Za-z0-9]+$ ]]; then
    printf 'QazCoop remote staging path is invalid\n' >&2
    return 1
  fi
  local remote_cleanup=true output=""
  if scp -q -o BatchMode=yes -o StrictHostKeyChecking=yes -r -- \
      "$bundle" "$release/scripts/install_qazcoop_release_guard.py" \
      "$qazcoop_guard_host:$remote_stage/"; then
    if ! set_transaction_phase external-guard-reconciling; then
      printf 'QazCoop guard reconciliation phase could not be recorded\n' >&2
      return 1
    fi
    external_guard_reconciliation_started=true
    output="$(
      ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -- "$qazcoop_guard_host" \
        python3 "$remote_stage/install_qazcoop_release_guard.py" \
        --candidate-repository "$qazcoop_repository" \
        --controller-bundle "$remote_stage/bundle"
    )" || output=""
  fi
  ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -- "$qazcoop_guard_host" \
    rm -rf -- "$remote_stage" >/dev/null 2>&1 || remote_cleanup=false
  if [[ "$remote_cleanup" != true ||
        "$output" != "qazcoop_release_guard_installed=$release_revision" ]]; then
    printf 'QazCoop product release guard activation failed\n' >&2
    return 1
  fi
  if ! set_transaction_phase external-guard-reconciled; then
    printf 'QazCoop guard reconciliation completion could not be recorded\n' >&2
    return 1
  fi
  cleanup_qazcoop_guard_temporary
  qazcoop_guard_temporary=""
}

previous_status_validation_program='import datetime
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
public_image_id, internal_image_id = sys.argv[2:]
sha = re.compile(r"^[0-9a-f]{40}$")
digest = re.compile(r"^sha256:[0-9a-f]{64}$")
legacy_digest = re.compile(r"^(?:sha256:)?[0-9a-f]{64}$")
if not digest.fullmatch(public_image_id) or not digest.fullmatch(internal_image_id):
    raise SystemExit("previous controller images are not measurable")
try:
    receipt = json.loads(path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit("previous controller status is unreadable") from error
if not isinstance(receipt, dict) or receipt.get("state") != "active":
    raise SystemExit("previous controller status is invalid")
schema = receipt.get("schema")
legacy_keys = {"schema", "state", "revision", "release_digest", "activated_at"}
measured_keys = legacy_keys | {"runtime_identity", "dependency_identity"}
expected_keys = legacy_keys if schema == "qdev-controller-release-status-v1" else measured_keys
if schema not in {"qdev-controller-release-status-v1", "qdev-controller-release-status-v2"}:
    raise SystemExit("previous controller status schema is invalid")
if set(receipt) != expected_keys or not sha.fullmatch(str(receipt.get("revision", ""))):
    raise SystemExit("previous controller source revision is invalid")
release_digest = receipt.get("release_digest")
if not isinstance(release_digest, str) or not (
    digest.fullmatch(release_digest) if schema.endswith("v2") else legacy_digest.fullmatch(release_digest)
):
    raise SystemExit("previous controller release digest is invalid")
try:
    activated = datetime.datetime.fromisoformat(
        str(receipt.get("activated_at", "")).replace("Z", "+00:00")
    )
except ValueError as error:
    raise SystemExit("previous controller activation timestamp is invalid") from error
if activated.tzinfo is None:
    raise SystemExit("previous controller activation timestamp is not timezone-aware")
if schema.endswith("v1"):
    raise SystemExit(0)
runtime_identity = receipt.get("runtime_identity")
dependency_identity = receipt.get("dependency_identity")
if not isinstance(runtime_identity, dict) or set(runtime_identity) != {
    "source_revision", "source_digest", "public_image_id", "internal_image_id"
}:
    raise SystemExit("previous controller runtime identity is invalid")
if not isinstance(dependency_identity, dict) or set(dependency_identity) != {
    "requirements_digest", "public_installed_digest", "internal_installed_digest"
}:
    raise SystemExit("previous controller dependency identity is invalid")
if runtime_identity.get("source_revision") != receipt["revision"]:
    raise SystemExit("previous controller source binding is invalid")
measured = [
    runtime_identity.get("source_digest"),
    runtime_identity.get("public_image_id"),
    runtime_identity.get("internal_image_id"),
    dependency_identity.get("requirements_digest"),
    dependency_identity.get("public_installed_digest"),
    dependency_identity.get("internal_installed_digest"),
]
if any(not isinstance(value, str) or not digest.fullmatch(value) for value in measured):
    raise SystemExit("previous controller measurements are invalid")
if dependency_identity["public_installed_digest"] != dependency_identity["internal_installed_digest"]:
    raise SystemExit("previous controller dependency binding is invalid")
print(runtime_identity["public_image_id"])
print(runtime_identity["internal_image_id"])'

validate_controller_image_binding() {
  local expected_image_id="$1"
  local runtime_image_id="$2"
  local container_name="$3"
  local platform_manifest
  if [[ "$expected_image_id" == "$runtime_image_id" ]]; then
    return 0
  fi
  platform_manifest="$(
    docker inspect "$container_name" \
      --format '{{index .Config.Labels "com.docker.compose.image"}}'
  )" || return 1
  python3 "$script_root/scripts/validate_controller_image_binding.py" \
    --expected-index "$expected_image_id" \
    --runtime-index "$runtime_image_id" \
    --platform-manifest "$platform_manifest"
}

validate_previous_release_status() {
  local public_image_id="$1"
  local internal_image_id="$2"
  local validation_output
  local -a expected_images
  [[ "$release_status_was_present" == true ]] || return 0
  validation_output="$(
    python3 -c "$previous_status_validation_program" \
      "$release_status_backup" "$public_image_id" "$internal_image_id"
  )" || return 1
  [[ -n "$validation_output" ]] || return 0
  mapfile -t expected_images <<< "$validation_output"
  if [[ "${#expected_images[@]}" -ne 2 ]]; then
    printf 'previous controller image identity is incomplete\n' >&2
    return 1
  fi
  validate_controller_image_binding \
    "${expected_images[0]}" "$public_image_id" qdev-runner-broker-public || return 1
  validate_controller_image_binding \
    "${expected_images[1]}" "$internal_image_id" qdev-runner-broker-internal
}

write_rollback_anchor() {
  [[ "$rollback_mode" != true ]] || return 0
  local anchor_directory previous_revision previous_digest staged_anchor
  local saved_public_ref saved_internal_ref
  anchor_directory="$(dirname -- "$rollback_anchor_path")"
  if [[ -z "$previous" || ! -d "$previous" ]]; then
    printf 'current controller release path is unavailable for rollback anchoring\n' >&2
    return 1
  fi
  [[ -d "$anchor_directory" ]] || {
    printf 'controller rollback anchor directory is missing: %s\n' "$anchor_directory" >&2
    return 1
  }
  previous_revision="$(python3 - "$release_status_backup" <<'PY'
import json
import pathlib
import re
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
revision = payload.get("revision")
if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{40}", revision) is None:
    raise SystemExit("previous controller revision is invalid")
print(revision)
PY
  )" || return 1
  previous_digest="$(python3 - "$release_status_backup" <<'PY'
import json
import pathlib
import re
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
value = payload.get("release_digest")
if not isinstance(value, str) or re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", value) is None:
    raise SystemExit("previous controller digest is invalid")
print(value if value.startswith("sha256:") else f"sha256:{value}")
PY
  )" || return 1
  saved_public_ref="qdev-runner-controller-anchor-public:$previous_revision"
  saved_internal_ref="qdev-runner-controller-anchor-internal:$previous_revision"
  docker image tag "$previous_public_image" "$saved_public_ref" || return 1
  if ! docker image tag "$previous_internal_image" "$saved_internal_ref"; then
    docker image rm "$saved_public_ref" >/dev/null 2>&1 || true
    return 1
  fi
  staged_anchor="$(mktemp /run/qdev-controller-rollback-anchor.XXXXXX)" || return 1
  python3 - "$staged_anchor" "$previous_revision" "$previous_digest" \
    "$previous" "$previous_public_image" "$previous_internal_image" \
    "$previous_public_ref" "$previous_internal_ref" \
    "$saved_public_ref" "$saved_internal_ref" <<'PY'
import datetime
import json
import os
import pathlib
import tempfile
import sys

(
    destination, revision, release_digest, release_path, public_image_id,
    internal_image_id, public_image_ref, internal_image_ref, public_saved_ref,
    internal_saved_ref,
) = sys.argv[1:]
payload = {
    "schema": "qdev-controller-rollback-anchor-v1",
    "revision": revision,
    "release_digest": release_digest,
    "release_path": release_path,
    "public_image_id": public_image_id,
    "internal_image_id": internal_image_id,
    "public_image_ref": public_image_ref,
    "internal_image_ref": internal_image_ref,
    "public_saved_ref": public_saved_ref,
    "internal_saved_ref": internal_saved_ref,
    "recorded_at": datetime.datetime.now(datetime.UTC).isoformat().replace("+00:00", "Z"),
}
target = pathlib.Path(destination)
descriptor, temporary_name = tempfile.mkstemp(
    dir=target.parent, prefix=".controller-rollback-anchor."
)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chown(temporary_name, 0, 0)
    os.chmod(temporary_name, 0o600)
    os.replace(temporary_name, target)
except BaseException:
    pathlib.Path(temporary_name).unlink(missing_ok=True)
    raise
PY
  local anchor_status=$?
  if ((anchor_status != 0)); then
    rm -f -- "$staged_anchor"
    docker image rm "$saved_public_ref" "$saved_internal_ref" >/dev/null 2>&1 || true
    return "$anchor_status"
  fi
  if ! python3 "$material_helper" stage-anchor --directory "$transaction_dir" \
    --source "$staged_anchor" >/dev/null; then
    rm -f -- "$staged_anchor"
    docker image rm "$saved_public_ref" "$saved_internal_ref" >/dev/null 2>&1 || true
    return 1
  fi
  rm -f -- "$staged_anchor"
}

publish_rollback_anchor() {
  [[ "$rollback_mode" != true ]] || return 0
  python3 "$material_helper" publish-anchor --directory "$transaction_dir" \
    --destination "$rollback_anchor_path" >/dev/null
}

prepare_saved_rollback_images() {
  [[ "$rollback_mode" == true ]] || return 0
  local saved_public_id saved_internal_id
  saved_public_id="$(docker image inspect "$anchor_public_saved_ref" --format '{{.Id}}')" ||
    return 1
  saved_internal_id="$(docker image inspect "$anchor_internal_saved_ref" --format '{{.Id}}')" ||
    return 1
  if [[ "$saved_public_id" != "$anchor_public_image_id" ||
        "$saved_internal_id" != "$anchor_internal_image_id" ||
        "$anchor_public_image_id" != "sha256:$candidate_public_image_digest" ||
        "$anchor_internal_image_id" != "sha256:$candidate_internal_image_digest" ]]; then
    printf 'saved controller rollback images do not match the anchor\n' >&2
    return 1
  fi
  docker image tag "$anchor_public_saved_ref" "$anchor_public_image_ref" || return 1
  docker image tag "$anchor_internal_saved_ref" "$anchor_internal_image_ref" || return 1
}

restore_operator_identity_metadata() {
  python3 "$material_helper" restore --directory "$transaction_dir" \
    --group operator >/dev/null
}

restore_rollback_anchor() {
  python3 "$material_helper" restore --directory "$transaction_dir" \
    --group anchor >/dev/null
}

install_fleet_host_dispatch() {
  install -d -o root -g root -m 0755 /usr/local/sbin || return 1
  atomic_install \
    "$release/scripts/bootstrap_admin_platform_ledger_v3.py" \
    /usr/local/sbin/qdev-admin-platform-ledger-bootstrap 0755 || return 1
  install -d -o root -g root -m 0755 /usr/local/libexec || return 1
  atomic_install \
    "$release/scripts/dispatch_fleet_bootstrap.py" \
    /usr/local/libexec/qdev-fleet-host-dispatch 0755 || return 1
  atomic_install \
    "$release/scripts/qdev_controller_activation_adapter.py" \
    /usr/local/sbin/qdev-controller-activate 0755 || return 1
  atomic_install \
    "$release/scripts/controller_activation_assets.py" \
    /usr/local/sbin/qdev-controller-activation-assets 0755 || return 1
  atomic_install \
    "$release/scripts/provision_controller_activation_trust.py" \
    /usr/local/sbin/qdev-controller-activation-trust-provision 0755 || return 1
  if [[ -f /etc/qdev-runner/admission/ed25519-public.pem ]]; then
    /usr/local/sbin/qdev-controller-activation-trust-provision || return 1
  fi
  atomic_install \
    "$release/scripts/qdev_release_host_agent_enrol_adapter.py" \
    /usr/local/sbin/qdev-release-host-agent-enrol 0755 || return 1
  atomic_install \
    "$release/scripts/qdev_fleet_worker_recovery_adapter.py" \
    /usr/local/sbin/qdev-fleet-worker-recovery 0755 || return 1
  atomic_install \
    "$release/scripts/qdev_fixed_worker_recovery_dispatch.py" \
    /usr/local/sbin/qdev-fixed-worker-recovery-dispatch 0755 || return 1
  atomic_install \
    "$release/scripts/qdev_recovery_host_enrol_adapter.py" \
    /usr/local/sbin/qdev-recovery-host-enrol 0755 || return 1
  atomic_install \
    "$release/scripts/provision_worker_recovery_bindings.py" \
    /usr/local/sbin/qdev-worker-recovery-bindings-provision 0755 || return 1
  atomic_install \
    "$release/scripts/provision_fleet_host_dispatch_state.py" \
    /usr/local/sbin/qdev-fleet-host-dispatch-state-provision 0755 || return 1
  atomic_install \
    "$release/scripts/start_controller_broker.sh" \
    /usr/local/sbin/qdev-start-controller-broker 0755 || return 1
  atomic_install \
    "$release/deploy/qdev-runner-broker.service" \
    /etc/systemd/system/qdev-runner-broker.service 0644 || return 1
  /usr/local/sbin/qdev-fleet-host-dispatch-state-provision || return 1
  atomic_install \
    "$release/deploy/qdev-fleet-host-dispatch.service" \
    /etc/systemd/system/qdev-fleet-host-dispatch.service 0644 || return 1
  atomic_install \
    "$release/deploy/qdev-fleet-host-dispatch.path" \
    /etc/systemd/system/qdev-fleet-host-dispatch.path 0644 || return 1
  systemctl daemon-reload || return 1
  # Starting only the watcher is safe when activation itself is executing as
  # the current oneshot.  That invocation writes its durable result before a
  # subsequently queued service run can begin.
  systemctl enable --now qdev-fleet-host-dispatch.path || return 1
}

admission_host_tool_path=/usr/local/sbin/qdev-controller-admission
qazcoop_guard_temporary=""
compose=(docker compose -p qdev-runner -f "$release/deploy/compose.yml")
if [[ "$no_build" == true ]]; then
  compose_action=(up -d --force-recreate --no-build --no-deps broker-public broker-internal)
else
  compose_action=(up -d --force-recreate --build --no-deps broker-public broker-internal)
fi

restore_controller_configuration() {
  python3 "$material_helper" restore --directory "$transaction_dir" \
    --group configuration >/dev/null
}

validate_transition_configuration() {
  local temporary current candidate backup index pair
  temporary="$(mktemp -d /run/qdev-controller-config-transition.XXXXXXXX)" || return 1
  index=0

  while IFS= read -r pair; do
    current="${pair%%|*}"
    candidate="${pair#*|}"
    backup="${temporary}/${index}"
    if [[ ! -f "$current" || -L "$current" ||
          ! -f "$candidate" || -L "$candidate" ]]; then
      rm -rf -- "$temporary"
      return 1
    fi
    if ! cmp --silent -- "$current" "$candidate"; then
      if ! python3 "$material_helper" extract \
        --directory "$transaction_dir" \
        --destination "$current" \
        --output "$backup" >/dev/null 2>&1 ||
        ! cmp --silent -- "$current" "$backup"; then
        rm -rf -- "$temporary"
        return 1
      fi
    fi
    index=$((index + 1))
  done <<EOF
/etc/qdev-runner/repos.json|${release}/inventory/repos.json
/etc/qdev-runner/profiles.yml|${release}/config/profiles.yml
/etc/qdev-runner/admin-platform-package-bindings.json|${release}/config/admin-platform-package-bindings.json
/etc/qdev-runner/release-lanes.yml|${release}/config/release-lanes.yml
/etc/qdev-runner/fleet-bootstrap.yml|${release}/config/fleet-bootstrap.yml
/etc/qdev-runner/managed-registry.yml|${release}/config/managed-registry.yml
/etc/qdev-runner/managed-release-ledger.yml|${release}/config/managed-release-ledger.yml
EOF

  rm -rf -- "$temporary"
}

restore_fleet_host_dispatch() {
  python3 "$material_helper" restore --directory "$transaction_dir" \
    --group dispatcher >/dev/null || return 1
  systemctl daemon-reload || return 1
  case "$dispatcher_enabled" in
    enabled) systemctl enable qdev-fleet-host-dispatch.path >/dev/null || return 1 ;;
    disabled) systemctl disable qdev-fleet-host-dispatch.path >/dev/null || return 1 ;;
    masked) systemctl mask qdev-fleet-host-dispatch.path >/dev/null || return 1 ;;
    static|indirect|generated|transient|not-found|"") ;;
    *) printf 'saved dispatcher enablement state is invalid\n' >&2; return 1 ;;
  esac
  case "$dispatcher_active" in
    active|activating) systemctl start qdev-fleet-host-dispatch.path || return 1 ;;
    inactive|failed|deactivating|unknown|"")
      systemctl stop qdev-fleet-host-dispatch.path >/dev/null 2>&1 || true
      ;;
    *) printf 'saved dispatcher activity state is invalid\n' >&2; return 1 ;;
  esac
}

canonicalize_state_link() {
  local legacy_path="$1"
  local canonical_path="$2"
  local link_target="$3"
  local backup_path
  if [[ -L "$legacy_path" ]]; then
    if [[ "$(realpath -e -- "$legacy_path" 2>/dev/null || true)" != "$canonical_path" ]]; then
      printf 'legacy state link does not resolve to the canonical store: %s\n' \
        "$legacy_path" >&2
      return 1
    fi
    return 0
  fi
  if [[ -e "$legacy_path" ]]; then
    if [[ ! -f "$legacy_path" || ! -f "$canonical_path" ]] || \
      ! cmp --silent -- "$legacy_path" "$canonical_path"; then
      printf 'legacy and canonical controller state conflict: %s\n' "$legacy_path" >&2
      return 1
    fi
    backup_path="${legacy_path}.pre-admin-platform-v3.$(date -u +%Y%m%dT%H%M%SZ)"
    mv -- "$legacy_path" "$backup_path"
  fi
  ln -s -- "$link_target" "$legacy_path"
}

prepare_broker_state() {
  local legacy_database canonical_database source_path
  local canonical_claims canonical_managed_release_ledger legacy_claims candidate
  legacy_database=/var/lib/qdev-runner/broker.db
  canonical_database="$broker_state_root/broker.db"
  canonical_claims="$control_state_root/claim-scopes.json"
  canonical_managed_release_ledger="$managed_release_state_root/managed-release-ledger.yml"

  # SQLite must be quiescent before its database is relocated.  Stopping only
  # the two brokers leaves the registry and every worker untouched.
  docker stop qdev-runner-broker-public qdev-runner-broker-internal >/dev/null 2>&1 || true

  if [[ ! -e "$canonical_database" ]]; then
    if [[ -L "$legacy_database" ]]; then
      printf 'legacy broker database is a dangling link\n' >&2
      return 1
    elif [[ -f "$legacy_database" ]]; then
      mv -- "$legacy_database" "$canonical_database"
    elif [[ -e "$legacy_database" ]]; then
      printf 'legacy broker database is not a regular file\n' >&2
      return 1
    else
      install -o "$runtime_uid" -g "$runtime_gid" -m 0600 /dev/null "$canonical_database"
    fi
  fi
  if [[ ! -f "$canonical_database" || -L "$canonical_database" ]]; then
    printf 'canonical broker database is not a regular file\n' >&2
    return 1
  fi
  chown "$runtime_uid:$runtime_gid" -- "$canonical_database"
  chmod 0600 -- "$canonical_database"
  for suffix in -wal -shm; do
    if [[ -e "${legacy_database}${suffix}" && ! -L "${legacy_database}${suffix}" ]]; then
      if [[ -e "${canonical_database}${suffix}" ]]; then
        if ! cmp --silent -- "${legacy_database}${suffix}" "${canonical_database}${suffix}"; then
          printf 'legacy and canonical SQLite sidecars conflict: %s\n' "$suffix" >&2
          return 1
        fi
        mv -- "${legacy_database}${suffix}" \
          "${legacy_database}${suffix}.pre-admin-platform-v3.$(date -u +%Y%m%dT%H%M%SZ)"
      else
        mv -- "${legacy_database}${suffix}" "${canonical_database}${suffix}"
      fi
    fi
    if [[ -e "${canonical_database}${suffix}" ]]; then
      chown "$runtime_uid:$runtime_gid" -- "${canonical_database}${suffix}"
      chmod 0600 -- "${canonical_database}${suffix}"
    fi
  done
  canonicalize_state_link \
    "$legacy_database" "$canonical_database" broker-state/broker.db || return 1

  source_path=""
  for candidate in \
    /var/lib/qdev-runner/claim-scopes.json \
    /etc/qdev-runner/claim-scopes.json; do
    if [[ -L "$candidate" ]]; then
      candidate="$(realpath -e -- "$candidate" 2>/dev/null || true)"
    fi
    [[ -n "$candidate" && -f "$candidate" ]] || continue
    if [[ -z "$source_path" ]]; then
      source_path="$candidate"
    elif ! cmp --silent -- "$source_path" "$candidate"; then
      printf 'legacy claim-scope stores disagree\n' >&2
      return 1
    fi
  done
  if [[ ! -e "$canonical_claims" ]]; then
    if [[ -z "$source_path" ]]; then
      printf 'controller claim-scope state is unavailable\n' >&2
      return 1
    fi
    install -o "$runtime_uid" -g "$runtime_gid" -m 0600 -- \
      "$source_path" "$canonical_claims"
  fi
  if [[ ! -f "$canonical_claims" || -L "$canonical_claims" ]]; then
    printf 'canonical claim-scope store is not a regular file\n' >&2
    return 1
  fi
  chown "$runtime_uid:$runtime_gid" -- "$canonical_claims"
  chmod 0600 -- "$canonical_claims"
  canonicalize_state_link \
    /var/lib/qdev-runner/claim-scopes.json "$canonical_claims" \
    control-state/claim-scopes.json || return 1
  canonicalize_state_link \
    /etc/qdev-runner/claim-scopes.json "$canonical_claims" \
    /var/lib/qdev-runner/control-state/claim-scopes.json || return 1

  # The packaged file is an immutable seed.  The internal broker appends
  # provider-bound CI state to a separate durable copy, which must survive
  # controller upgrades and rollbacks.  Seed only the first installation;
  # never replace an existing authoritative ledger with a release snapshot.
  if [[ ! -e "$canonical_managed_release_ledger" ]]; then
    install -o "$runtime_uid" -g "$runtime_gid" -m 0600 -- \
      /etc/qdev-runner/managed-release-ledger.yml \
      "$canonical_managed_release_ledger"
  fi
  if [[ ! -f "$canonical_managed_release_ledger" ||
        -L "$canonical_managed_release_ledger" ]]; then
    printf 'canonical managed-release ledger is not a regular file\n' >&2
    return 1
  fi
  chown "$runtime_uid:$runtime_gid" -- "$canonical_managed_release_ledger"
  chmod 0600 -- "$canonical_managed_release_ledger"
  PYTHONPATH="$release/src" python3 -c \
    'from pathlib import Path; from qdev_runner.managed_release_ledger import ManagedReleaseLedger; ManagedReleaseLedger(Path(__import__("sys").argv[1]))' \
    "$canonical_managed_release_ledger" || {
    printf 'canonical managed-release ledger is invalid\n' >&2
    return 1
  }
}

rollback() {
  local rollback_public_id rollback_internal_id transition_config_safe=false
  rollback_started=true
  if validate_transition_configuration; then
    transition_config_safe=true
  else
    printf '%s\n' \
      'controller rollback refused: configuration is neither the snapshot nor the signed candidate' >&2
    return 1
  fi
  QDEV_ACT_CONFIG_TRANSITION_SAFE="$transition_config_safe" \
    "$transaction_hook" __transaction_hook__ authorize-rollback >/dev/null || {
    printf 'controller rollback was not authorized by the activation transaction\n' >&2
    return 1
  }
  # Do not expose the old receipt until the corresponding containers have
  # actually been restored and measured by their immutable image IDs.
  # Freeze the candidate watcher before restoring the host-side snapshot. Its
  # saved enablement/activity state is restored only after the previous
  # controller runtime has passed immutable identity and health validation.
  systemctl stop qdev-fleet-host-dispatch.path >/dev/null 2>&1 || true
  restore_controller_configuration || return 1
  restore_operator_identity_metadata || return 1
  restore_rollback_anchor || return 1
  if [[ -z "$previous" || ! -d "$previous" ]]; then
    docker compose -p qdev-runner -f "$release/deploy/compose.yml" \
      stop broker-public broker-internal >/dev/null 2>&1 || true
    docker rm -f qdev-runner-broker-public qdev-runner-broker-internal \
      >/dev/null 2>&1 || true
    if [[ -L "$current" &&
          "$(readlink -f -- "$current" 2>/dev/null || true)" == "$release" ]]; then
      rm -f -- "$current"
    fi
    restore_release_status || return 1
    restore_fleet_host_dispatch || return 1
    "$transaction_hook" __transaction_hook__ complete-rollback >/dev/null || return 1
    finish_transaction_material rolled-back || return 1
    activation_finished=true
    activation_mutated=false
    return 0
  fi
  activate_link "$previous" || return 1
  if [[ -n "$previous_public_image" && -n "$previous_public_ref" ]]; then
    rollback_public_id="$(docker image inspect "$rollback_public_ref" --format '{{.Id}}')" || return 1
    [[ "$rollback_public_id" == "$previous_public_image" ]] || {
      printf 'durable public rollback image no longer matches the saved image ID\n' >&2
      return 1
    }
    docker image tag "$rollback_public_ref" "$previous_public_ref" || return 1
  fi
  if [[ -n "$previous_internal_image" && -n "$previous_internal_ref" ]]; then
    rollback_internal_id="$(docker image inspect "$rollback_internal_ref" --format '{{.Id}}')" || return 1
    [[ "$rollback_internal_id" == "$previous_internal_image" ]] || {
      printf 'durable internal rollback image no longer matches the saved image ID\n' >&2
      return 1
    }
    docker image tag "$rollback_internal_ref" "$previous_internal_ref" || return 1
  fi
  # Compose otherwise falls back to its mutable ``:local`` default.  Bind the
  # saved immutable image explicitly so rollback restores the exact image ID
  # captured in activation material before the runtime identity check below.
  QDEV_CONTROLLER_IMAGE_REF="$previous_public_ref" \
    docker compose -p qdev-runner -f "$previous/deploy/compose.yml" \
      up -d --force-recreate --no-build --no-deps broker-public broker-internal || return 1
  if [[ -n "$previous_public_image" &&
        "$(docker inspect qdev-runner-broker-public --format '{{.Image}}')" != "$previous_public_image" ]]; then
    printf 'rollback restored an unexpected public broker image\n' >&2
    return 1
  fi
  if [[ -n "$previous_internal_image" &&
        "$(docker inspect qdev-runner-broker-internal --format '{{.Image}}')" != "$previous_internal_image" ]]; then
    printf 'rollback restored an unexpected internal broker image\n' >&2
    return 1
  fi
  restored_public_image="$(docker inspect qdev-runner-broker-public --format '{{.Image}}')" || return 1
  restored_internal_image="$(docker inspect qdev-runner-broker-internal --format '{{.Image}}')" || return 1
  if ! validate_previous_release_status "$restored_public_image" "$restored_internal_image"; then
    printf 'rollback runtime does not satisfy the previous controller receipt\n' >&2
    return 1
  fi
  restore_release_status || return 1
  restore_fleet_host_dispatch || return 1
  "$transaction_hook" __transaction_hook__ complete-rollback >/dev/null || return 1
  finish_transaction_material rolled-back || return 1
  activation_finished=true
  activation_mutated=false
}

if [[ -n "$recovery_state" ]]; then
  activation_mutated=true
  case "$recovery_state" in
    pending-mutating|pending-config-transition|pending-config-installed|pending-candidate-active)
      rollback || exit 1
      printf 'controller activation recovery restored the previous runtime\n'
      exit 0
      ;;
    committed)
      if [[ "$envelope_expired" == true ]]; then
        if [[ "$external_guard_reconciliation_started" != true ]]; then
          rollback || exit 1
          printf 'expired committed controller recovery restored the previous runtime\n'
          exit 0
        fi
      fi
      if ! measure_runtime_identity || ! verify_controller_runtime_health; then
        printf 'committed controller runtime is unhealthy during recovery\n' >&2
        if [[ "$external_guard_reconciliation_started" == true ]]; then
          exit 78
        fi
        rollback || exit 1
        exit 1
      fi
      publish_rollback_anchor || {
        printf 'committed controller rollback anchor could not be published during recovery\n' >&2
        if [[ "$external_guard_reconciliation_started" == true ]]; then
          exit 78
        fi
        rollback || exit 1
        exit 1
      }
      if ! install_qazcoop_release_guard; then
        printf 'committed controller product guard could not be installed during recovery\n' >&2
        if [[ "$external_guard_reconciliation_started" == true ]]; then
          exit 78
        fi
        rollback || exit 1
        exit 1
      fi
      if ! "$transaction_hook" __transaction_hook__ finalize-candidate >/dev/null; then
        printf 'committed controller activation could not be finalized during recovery\n' >&2
        exit 78
      fi
      activation_finished=true
      if ! finish_transaction_material finalized; then
        printf 'warning: finalized controller activation material could not be retired\n' >&2
      fi
      printf 'controller activation recovery finalized the measured candidate runtime\n'
      exit 0
      ;;
  esac
fi

# Recheck at the last non-mutating boundary. The process lock prevents another
# conforming activation from racing any configuration or runtime mutation.
set_transaction_phase preflight-cas || exit 1
assert_expected_current_revision
set_transaction_phase preflight-hook || exit 1
"$transaction_hook" __transaction_hook__ pre-flip >/dev/null
set_transaction_phase preflight-status || exit 1
if ! validate_previous_release_status "$previous_public_image" "$previous_internal_image"; then
  printf 'existing controller status is not bound to a recoverable runtime\n' >&2
  exit 66
fi
set_transaction_phase preflight-validated || exit 1

# From this point every non-zero exit is transactionally rolled back while the
# exact configuration and image backups are still retained by this process.
activation_mutated=true
set_transaction_phase mutating || {
  printf 'controller durable mutating phase could not be recorded\n' >&2
  rollback
  exit 1
}
if ! write_rollback_anchor; then
  printf 'controller rollback anchor could not be persisted\n' >&2
  exit 66
fi
if ! prepare_saved_rollback_images; then
  printf 'controller rollback anchor images are unavailable\n' >&2
  exit 66
fi
atomic_install "$release/inventory/repos.json" /etc/qdev-runner/repos.json 0644
atomic_install "$release/config/profiles.yml" /etc/qdev-runner/profiles.yml 0644
atomic_install "$release/config/admin-platform-package-bindings.json" \
  /etc/qdev-runner/admin-platform-package-bindings.json 0644
atomic_install "$release/config/release-lanes.yml" /etc/qdev-runner/release-lanes.yml 0644
atomic_install "$release/config/fleet-bootstrap.yml" /etc/qdev-runner/fleet-bootstrap.yml 0644
atomic_install "$release/config/managed-registry.yml" /etc/qdev-runner/managed-registry.yml 0644
# The live Admin Platform ledger is durable authoritative state.  It was
# independently validated above and is intentionally neither installed nor
# restored from this release checkout.
atomic_install "$release/config/managed-release-ledger.yml" \
  /etc/qdev-runner/managed-release-ledger.yml 0644
if [[ "$rollback_mode" != true ]]; then
  install -d -o root -g root -m 0700 /etc/qdev-runner/admission /run/qdev-controller
  install -d -o root -g root -m 0700 /run/qdev-controller/admin-platform-package-bindings
  install -d -o root -g root -m 0700 /run/qdev-controller/admin-platform-package-bindings/incoming
  install -d -o root -g root -m 0700 /run/qdev-controller/admin-platform-package-bindings/issued
  atomic_install "$release/scripts/qdev_controller_admission_host.sh" \
    "$admission_host_tool_path" 0755
fi
activate_link "$release"

set +e
(set -e; prepare_broker_state)
prepare_state_status=$?
set -e
if ((prepare_state_status != 0)); then
  printf 'controller durable-state migration failed; restoring previous release\n' >&2
  rollback
  exit 1
fi

if [[ "$rollback_mode" != true ]]; then
  # A rollback target can predate the managed dispatcher. Keep the already
  # installed, controller-owned recovery path intact instead of sourcing
  # modern host binaries from an immutable historical release.
  set +e
  (set -e; install_fleet_host_dispatch)
  install_dispatch_status=$?
  set -e
  if ((install_dispatch_status != 0)); then
    printf 'fleet host dispatcher installation failed; restoring previous release\n' >&2
    rollback
    exit 1
  fi
fi

set_transaction_phase config-installed || {
  printf 'controller durable transaction phase could not be recorded\n' >&2
  rollback
  exit 1
}

if ! "${compose[@]}" "${compose_action[@]}"; then
  rollback
  exit 1
fi

healthy=false
for _ in $(seq 1 "$health_check_attempts"); do
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

if ! measure_runtime_identity; then
  printf '%s\n' 'Controller is healthy, but measured runtime identity is invalid; restoring the prior release.' >&2
  rollback
  exit 1
fi

if ! write_release_status; then
  printf '%s\n' 'Controller is healthy, but the activation receipt could not be persisted; restoring the prior release.' >&2
  rollback
  exit 1
fi

if ! verify_controller_runtime_health; then
  printf '%s\n' \
    'Controller receipt is not observable from the activated runtime; restoring the prior release.' >&2
  rollback
  exit 1
fi

set_transaction_phase candidate-active || {
  printf 'controller candidate-active phase could not be recorded\n' >&2
  rollback
  exit 1
}
if ! "$transaction_hook" __transaction_hook__ commit-candidate >/dev/null; then
  printf '%s\n' \
    'Controller activation could not be committed; restoring the prior release.' >&2
  rollback
  exit 1
fi
set_transaction_phase committed || {
  printf 'controller committed phase could not be recorded\n' >&2
  rollback
  exit 1
}
if ! publish_rollback_anchor; then
  printf '%s\n' \
    'Controller rollback anchor could not be published after commit; restoring the prior release.' >&2
  rollback
  exit 1
fi
if ! docker inspect qdev-runner-broker-public qdev-runner-broker-internal \
  --format '{{.Name}} {{.Image}}'; then
  printf '%s\n' \
    'Controller runtime identity could not be inspected after commit; restoring the prior release.' >&2
  rollback
  exit 1
fi
if ! install_qazcoop_release_guard; then
  printf '%s\n' \
    'Controller is healthy, but the QazCoop release guard is not yet reconciled.' >&2
  if [[ "$external_guard_reconciliation_started" == true ]]; then
    exit 78
  fi
  rollback
  exit 1
fi
if ! "$transaction_hook" __transaction_hook__ finalize-candidate >/dev/null; then
  printf '%s\n' \
    'Controller activation could not be publicly finalized; recovery must reconcile the committed generation.' >&2
  exit 78
fi
activation_finished=true
if ! finish_transaction_material finalized; then
  printf 'warning: finalized controller activation material could not be retired\n' >&2
fi
printf 'controller_release_active=%s previous=%s\n' "$release" "${previous:-none}"
printf 'controller_release_receipt=active revision=%s digest=%s public_image=%s internal_image=%s dependencies=%s\n' \
  "$release_revision" "$release_digest" "$runtime_public_image_id" \
  "$runtime_internal_image_id" "$runtime_public_dependencies_digest"
