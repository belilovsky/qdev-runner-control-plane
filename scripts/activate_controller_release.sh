#!/usr/bin/env bash
set -euo pipefail

# Root-owned transaction wrapper for the mature controller release payload.
# The wrapper owns the host-wide lock and signed CAS state. The payload owns
# the measured runtime migration, Admin Platform v3 state, dual-image restore,
# service installation, health checks, and release-status projection.

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi

entrypoint="$(realpath -e -- "$0")"
if [[ -L "$0" || "$(stat -c %u -- "$entrypoint")" != 0 ||
      $((8#$(stat -c %a -- "$entrypoint") & 8#022)) -ne 0 ]]; then
  printf 'controller activation entrypoint ownership is unsafe\n' >&2
  exit 77
fi

script_dir="$(cd -- "$(dirname -- "$entrypoint")" && pwd)"
release_root=/opt/qdev-runner-control-plane
activation_helper="$script_dir/controller_activation.py"
activation_python=/usr/bin/python3
activation_pythonpath="$(cd -- "$script_dir/../src" && pwd)"
activation_cli=(env "PYTHONDONTWRITEBYTECODE=1" "PYTHONPATH=$activation_pythonpath" "$activation_python" "$activation_helper")
activation_status="${QDEV_CONTROLLER_ACTIVATION_STATUS:-/var/lib/qdev-runner/controller-activation/activation-status.json}"
activation_projection="${QDEV_CONTROLLER_ACTIVATION_PROJECTION:-/var/lib/qdev-runner/controller-status/controller-activation.json}"

# The raw activation ledger carries internal transaction identity, rollback
# tuples and configuration fingerprints.  Only this derived aggregate enters
# the public broker mount namespace, so refresh it whenever the CAS ledger
# reaches a new durable state.
publish_activation_projection() {
  "${activation_cli[@]}" publish-projection --status "$activation_status" \
    --projection "$activation_projection" >/dev/null
}

json_value() {
  "$activation_python" -c \
    'import json,sys; value=json.load(sys.stdin); print(eval(sys.argv[1], {"__builtins__": {}}, {"v": value}))' \
    "$1"
}
strip_digest_prefix() { printf '%s\n' "${1#sha256:}"; }

config_args_for_current() {
  printf '%s\n' \
    'repos.json=/etc/qdev-runner/repos.json' \
    'profiles.yml=/etc/qdev-runner/profiles.yml' \
    'admin-platform-package-bindings.json=/etc/qdev-runner/admin-platform-package-bindings.json' \
    'release-lanes.yml=/etc/qdev-runner/release-lanes.yml' \
    'managed-registry.yml=/etc/qdev-runner/managed-registry.yml' \
    'fleet-bootstrap.yml=/etc/qdev-runner/fleet-bootstrap.yml' \
    'managed-release-ledger.yml=/etc/qdev-runner/managed-release-ledger.yml'
}

fingerprint_config() {
  local -a args=(fingerprint-config)
  local item
  while IFS= read -r item; do args+=(--config-file "$item"); done
  "${activation_cli[@]}" "${args[@]}" | json_value 'v["digest"]'
}

running_images() {
  local public internal
  public="$(strip_digest_prefix "$(docker inspect qdev-runner-broker-public --format '{{.Image}}')")"
  internal="$(strip_digest_prefix "$(docker inspect qdev-runner-broker-internal --format '{{.Image}}')")"
  [[ "$public" =~ ^[0-9a-f]{64}$ && "$internal" =~ ^[0-9a-f]{64}$ ]] || return 1
  printf '%s\n%s\n' "$public" "$internal"
}

verify_oci_tuple() {
  local image_ref="$1" expected_revision="$2" expected_policy="$3"
  local revision policy
  revision="$(docker image inspect "$image_ref" \
    --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')" || return 1
  policy="$(docker image inspect "$image_ref" \
    --format '{{index .Config.Labels "run.qdev.controller.policy-bundle-digest"}}')" || return 1
  [[ "$revision" == "$expected_revision" &&
     "$policy" == "$expected_policy" ]] || {
    printf 'controller OCI labels do not match signed candidate tuple\n' >&2
    return 1
  }
}

envelope_identity() {
  printf '%s\n' \
    --envelope "$QDEV_ACT_ENVELOPE" \
    --key "$QDEV_ACT_PUBLIC_KEY" \
    --candidate-source "$QDEV_ACT_CANDIDATE_SOURCE" \
    --candidate-public-image "$QDEV_ACT_CANDIDATE_PUBLIC_IMAGE" \
    --candidate-internal-image "$QDEV_ACT_CANDIDATE_INTERNAL_IMAGE" \
    --candidate-policy "$QDEV_ACT_CANDIDATE_POLICY" \
    --candidate-release-digest "$QDEV_ACT_CANDIDATE_RELEASE_DIGEST" \
    --candidate-config-digest "$QDEV_ACT_CANDIDATE_CONFIG" \
    --artifact-manifest-digest "$QDEV_ACT_ARTIFACT_DIGEST" \
    --entrypoint-reconciliation-digest "$QDEV_ACT_ENTRYPOINT_DIGEST"
}

transaction_hook() {
  local action="$1" public_image internal_image config public_status_temp
  local -a identity=()
  local -a images=()
  local -a config_state=()
  while IFS= read -r item; do identity+=("$item"); done < <(envelope_identity)
  mapfile -t images < <(running_images) || {
    printf 'controller images are unavailable during transaction hook\n' >&2
    return 74
  }
  [[ "${#images[@]}" -eq 2 ]] || return 74
  public_image="${images[0]}"
  internal_image="${images[1]}"
  config="$(config_args_for_current | fingerprint_config)"
  case "$action" in
    pre-flip)
      if [[ "$config" == "$QDEV_ACT_CANDIDATE_CONFIG" ]]; then
        config_state=(--candidate-config-active)
      fi
      "${activation_cli[@]}" assert-current --status "$activation_status" \
        "${identity[@]}" --observed-current-public-image "$public_image" \
        --observed-current-internal-image "$internal_image" \
        --observed-current-config "$config" "${config_state[@]}"
      ;;
    authorize-rollback)
      local -a transition_args=()
      if [[ "${QDEV_ACT_CONFIG_TRANSITION_SAFE:-false}" == true ]]; then
        transition_args=(--allow-config-transition)
      fi
      "${activation_cli[@]}" authorize-rollback --status "$activation_status" \
        "${identity[@]}" --observed-current-public-image "$public_image" \
        --observed-current-internal-image "$internal_image" \
        --observed-current-config "$config" \
        --rollback-config "$QDEV_ACT_EXPECTED_CONFIG" "${transition_args[@]}"
      ;;
    complete-rollback)
      "${activation_cli[@]}" complete-rollback --status "$activation_status" \
        "${identity[@]}" --observed-current-public-image "$public_image" \
        --observed-current-internal-image "$internal_image" \
        --observed-current-config "$config"
      publish_activation_projection
      ;;
    commit-candidate)
      [[ "$public_image" == "$QDEV_ACT_CANDIDATE_PUBLIC_IMAGE" &&
         "$internal_image" == "$QDEV_ACT_CANDIDATE_INTERNAL_IMAGE" &&
         "$config" == "$QDEV_ACT_CANDIDATE_CONFIG" ]] || {
        printf 'controller candidate changed before transactional commit\n' >&2
        return 78
      }
      "${activation_cli[@]}" commit --status "$activation_status" \
        "${identity[@]}" --observed-current-public-image "$public_image" \
        --observed-current-internal-image "$internal_image" \
        --observed-current-config "$config"
      publish_activation_projection
      ;;
    finalize-candidate)
      [[ "$public_image" == "$QDEV_ACT_CANDIDATE_PUBLIC_IMAGE" &&
         "$internal_image" == "$QDEV_ACT_CANDIDATE_INTERNAL_IMAGE" &&
         "$config" == "$QDEV_ACT_CANDIDATE_CONFIG" ]] || {
        printf 'controller candidate changed before transactional finalize\n' >&2
        return 78
      }
      public_status_temp="$(mktemp /run/qdev-controller-public-status.XXXXXX)" || return
      chown root:root -- "$public_status_temp"
      chmod 0600 -- "$public_status_temp"
      if ! curl --fail --silent --show-error --proto '=https' --tlsv1.2 \
        --connect-timeout 5 --max-time 15 \
        https://ci.qdev.run/health --output "$public_status_temp"; then
        rm -f -- "$public_status_temp"
        return 1
      fi
      if [[ "$QDEV_ACT_ROLLBACK_MODE" == true ]]; then
        "${activation_cli[@]}" finalize-historical --status "$activation_status" \
          "${identity[@]}" --measured-status "$QDEV_ACT_MEASURED_STATUS" \
          --public-status "$public_status_temp" \
          --observed-current-public-image "$public_image" \
          --observed-current-internal-image "$internal_image" \
          --observed-current-config "$config" >/dev/null || {
          rm -f -- "$public_status_temp"
          return 1
        }
      else
        "${activation_cli[@]}" finalize-measured --status "$activation_status" \
          "${identity[@]}" --measured-status "$QDEV_ACT_MEASURED_STATUS" \
          --public-status "$public_status_temp" \
          --observed-current-public-image "$public_image" \
          --observed-current-internal-image "$internal_image" \
          --observed-current-config "$config" >/dev/null || {
          rm -f -- "$public_status_temp"
          return 1
        }
      fi
      rm -f -- "$public_status_temp"
      publish_activation_projection
      ;;
    *)
      printf 'unknown controller transaction hook\n' >&2
      return 64
      ;;
  esac
}

if [[ "$#" -eq 2 && "$1" == __transaction_hook__ ]]; then
  transaction_hook "$2"
  exit $?
fi
if [[ "$#" -ne 1 ]]; then
  printf 'usage: %s /opt/qdev-runner-control-plane/releases/RELEASE\n' "$0" >&2
  exit 64
fi

install -d -o root -g root -m 0755 -- /run/lock
exec 9>/run/lock/qdev-controller-activation.lock
if ! flock -n 9; then
  printf 'another controller activation owns the complete host lifecycle\n' >&2
  exit 75
fi

release="$(realpath -e -- "$1")"
case "$release" in
  "$release_root"/releases/*) ;;
  *) printf 'release must be below %s/releases\n' "$release_root" >&2; exit 64 ;;
esac
if [[ "$(stat -c %u -- "$release")" != 0 ||
      $((8#$(stat -c %a -- "$release") & 8#022)) -ne 0 ]]; then
  printf 'release directory ownership is unsafe\n' >&2
  exit 77
fi

activation_envelope="${QDEV_CONTROLLER_ACTIVATION_ENVELOPE:-}"
activation_public_key="${QDEV_CONTROLLER_ACTIVATION_PUBLIC_KEY:-/etc/qdev-runner/trust/controller-activation-ed25519.pub}"
artifact_manifest="${QDEV_CONTROLLER_ARTIFACT_MANIFEST:-}"
allow_legacy_import="${QDEV_CONTROLLER_ALLOW_STATUS_V1_IMPORT:-false}"
legacy_status="${QDEV_CONTROLLER_LEGACY_RELEASE_STATUS:-/var/lib/qdev-runner/controller-status/controller-release.json}"
allow_measured_bootstrap="${QDEV_CONTROLLER_ALLOW_MEASURED_STATUS_BOOTSTRAP:-false}"
measured_status="${QDEV_CONTROLLER_MEASURED_RELEASE_STATUS:-/var/lib/qdev-runner/controller-status/controller-release.json}"
rollback_mode="${QDEV_CONTROLLER_ROLLBACK:-false}"
if [[ "$rollback_mode" != true && "$rollback_mode" != false ]]; then
  printf 'QDEV_CONTROLLER_ROLLBACK must be true or false\n' >&2
  exit 64
fi
payload_path="$script_dir/activate_controller_release_payload.sh"
for required_input in "$activation_envelope" "$activation_public_key" "$artifact_manifest" \
  "$payload_path" "$activation_helper"; do
  [[ -n "$required_input" && -f "$required_input" && ! -L "$required_input" ]] || {
    printf 'signed envelope, public key, artifact manifest, and payload are required\n' >&2
    exit 66
  }
done
payload="$(realpath -e -- "$payload_path")"
if [[ "$(stat -c %u -- "$payload")" != 0 ||
      $((8#$(stat -c %a -- "$payload") & 8#022)) -ne 0 ]]; then
  printf 'controller activation payload ownership is unsafe\n' >&2
  exit 77
fi
if [[ "$(stat -c %u -- "$activation_helper")" != 0 ||
      $((8#$(stat -c %a -- "$activation_helper") & 8#022)) -ne 0 ]]; then
  printf 'controller activation helper ownership is unsafe\n' >&2
  exit 77
fi
if [[ "$allow_legacy_import" != true && "$allow_legacy_import" != false ]]; then
  printf 'legacy import switch must be true or false\n' >&2
  exit 64
fi
if [[ "$allow_measured_bootstrap" != true && "$allow_measured_bootstrap" != false ]]; then
  printf 'measured bootstrap switch must be true or false\n' >&2
  exit 64
fi
if [[ "$allow_legacy_import" == true && "$allow_measured_bootstrap" == true ]]; then
  printf 'legacy import and measured bootstrap are mutually exclusive\n' >&2
  exit 64
fi

verified_artifact="$("${activation_cli[@]}" verify-artifact --artifact-manifest "$artifact_manifest")"
artifact_digest="$(printf '%s' "$verified_artifact" | json_value 'v["manifest_digest"]')"
candidate_source="$(printf '%s' "$verified_artifact" | json_value 'v["source_sha"]')"
candidate_image="$(printf '%s' "$verified_artifact" | json_value 'v["image_digest"]')"
candidate_public_image="$candidate_image"
candidate_internal_image="$candidate_image"
candidate_policy="$(printf '%s' "$verified_artifact" | json_value 'v["policy_bundle_digest"]')"
candidate_archive="$(printf '%s' "$verified_artifact" | json_value 'v["image_archive"]')"
entrypoint_digest="$(printf '%s' "$verified_artifact" | json_value 'v["entrypoint_reconciliation_digest"]')"
observed_entrypoint="$("${activation_cli[@]}" fingerprint-release --release-root "$release" | json_value 'v["digest"]')"
[[ "$observed_entrypoint" == "$entrypoint_digest" ]] || {
  printf 'release tree does not match attested entrypoint reconciliation\n' >&2
  exit 78
}

candidate_config="$({
  printf '%s\n' \
    "repos.json=$release/inventory/repos.json" \
    "profiles.yml=$release/config/profiles.yml" \
    "admin-platform-package-bindings.json=$release/config/admin-platform-package-bindings.json" \
    "release-lanes.yml=$release/config/release-lanes.yml" \
    "managed-registry.yml=$release/config/managed-registry.yml" \
    "fleet-bootstrap.yml=$release/config/fleet-bootstrap.yml" \
    "managed-release-ledger.yml=$release/config/managed-release-ledger.yml"
} | fingerprint_config)"
current_config="$(config_args_for_current | fingerprint_config)"
if [[ "$rollback_mode" == true ]]; then
  rollback_anchor="${QDEV_CONTROLLER_ROLLBACK_ANCHOR:-/etc/qdev-runner/controller-rollback-anchor.json}"
  rollback_identity="$("$activation_python" - "$rollback_anchor" <<'PY'
import json
import pathlib
import re
import stat
import sys

path = pathlib.Path(sys.argv[1])
metadata = path.lstat()
if (
    not stat.S_ISREG(metadata.st_mode)
    or stat.S_ISLNK(metadata.st_mode)
    or metadata.st_uid != 0
    or stat.S_IMODE(metadata.st_mode) != 0o600
):
    raise SystemExit("controller rollback anchor ownership or permissions are unsafe")
document = json.loads(path.read_text(encoding="utf-8"))
required = {
    "schema", "revision", "release_digest", "release_path",
    "public_image_id", "internal_image_id", "public_image_ref",
    "internal_image_ref", "public_saved_ref", "internal_saved_ref", "recorded_at",
}
if not isinstance(document, dict) or set(document) != required:
    raise SystemExit("controller rollback anchor schema is invalid")
if document.get("schema") != "qdev-controller-rollback-anchor-v1":
    raise SystemExit("controller rollback anchor version is invalid")
digest = re.compile(r"^sha256:[0-9a-f]{64}$")
for key in ("release_digest", "public_image_id", "internal_image_id"):
    if not isinstance(document.get(key), str) or not digest.fullmatch(document[key]):
        raise SystemExit(f"controller rollback anchor {key} is invalid")
for key in ("release_digest", "release_path", "public_image_id", "internal_image_id"):
    print(document[key])
PY
)" || exit 66
  mapfile -t rollback_fields <<< "$rollback_identity"
  if [[ "${#rollback_fields[@]}" -ne 4 ||
        "$(realpath -e -- "${rollback_fields[1]}")" != "$release" ]]; then
    printf 'signed rollback candidate does not match the exact saved controller bytes\n' >&2
    exit 78
  fi
  candidate_public_image="$(strip_digest_prefix "${rollback_fields[2]}")"
  candidate_internal_image="$(strip_digest_prefix "${rollback_fields[3]}")"
  candidate_release_digest="$(strip_digest_prefix "${rollback_fields[0]}")"
else
  [[ "$candidate_public_image" == "$candidate_internal_image" ]] || {
    printf 'forward controller activation requires one immutable broker artifact\n' >&2
    exit 78
  }
  candidate_release_digest="$(
    "${activation_cli[@]}" fingerprint-source --release-root "$release" |
      json_value 'v["digest"]'
  )"
fi
[[ "$candidate_release_digest" =~ ^[0-9a-f]{64}$ ]] || {
  printf 'candidate release digest is invalid\n' >&2
  exit 78
}

export QDEV_ACT_ENVELOPE="$activation_envelope"
export QDEV_ACT_PUBLIC_KEY="$activation_public_key"
export QDEV_ACT_CANDIDATE_SOURCE="$candidate_source"
export QDEV_ACT_CANDIDATE_PUBLIC_IMAGE="$candidate_public_image"
export QDEV_ACT_CANDIDATE_INTERNAL_IMAGE="$candidate_internal_image"
export QDEV_ACT_CANDIDATE_POLICY="$candidate_policy"
export QDEV_ACT_CANDIDATE_RELEASE_DIGEST="$candidate_release_digest"
export QDEV_ACT_CANDIDATE_CONFIG="$candidate_config"
export QDEV_ACT_ARTIFACT_DIGEST="$artifact_digest"
export QDEV_ACT_ENTRYPOINT_DIGEST="$entrypoint_digest"
export QDEV_ACT_MEASURED_STATUS="$measured_status"
export QDEV_ACT_ROLLBACK_MODE="$rollback_mode"

identity=(
  --envelope "$activation_envelope" --key "$activation_public_key"
  --candidate-source "$candidate_source"
  --candidate-public-image "$candidate_public_image"
  --candidate-internal-image "$candidate_internal_image"
  --candidate-policy "$candidate_policy" --candidate-config-digest "$candidate_config"
  --candidate-release-digest "$candidate_release_digest"
  --artifact-manifest-digest "$artifact_digest"
  --entrypoint-reconciliation-digest "$entrypoint_digest"
)
mapfile -t observed_images < <(running_images) || {
  printf 'controller images are unavailable\n' >&2
  exit 74
}
[[ "${#observed_images[@]}" -eq 2 ]] || exit 74
observed_public_image="${observed_images[0]}"
observed_internal_image="${observed_images[1]}"

recovery_state=""
transaction_state_path="${activation_status}.transaction"
if verified_envelope="$("${activation_cli[@]}" verify-envelope "${identity[@]}" 2>/dev/null)"; then
  :
elif [[ -e "$transaction_state_path" || -L "$transaction_state_path" ]]; then
  verified_envelope="$("${activation_cli[@]}" verify-recovery-envelope \
      --status "$activation_status" "${identity[@]}" \
      --observed-current-public-image "$observed_public_image" \
      --observed-current-internal-image "$observed_internal_image" \
      --observed-current-config "$current_config" \
      --allow-config-transition)" || exit
  recovery_state="$(printf '%s' "$verified_envelope" | json_value 'v["recovery_state"]')"
else
  verified_envelope="$("${activation_cli[@]}" verify-envelope "${identity[@]}")" || exit
fi
expected_source="$(printf '%s' "$verified_envelope" | json_value 'v["expected_current"]["source_sha"]')"
expected_public_image="$(printf '%s' "$verified_envelope" | json_value 'v["expected_current"]["public_image_digest"]')"
expected_internal_image="$(printf '%s' "$verified_envelope" | json_value 'v["expected_current"]["internal_image_digest"]')"
expected_config="$(printf '%s' "$verified_envelope" | json_value 'v["expected_current_config_digest"]')"
envelope_expires_at="$(printf '%s' "$verified_envelope" | json_value 'v["expires_at"]')"
envelope_expired="$("$activation_python" - "$envelope_expires_at" <<'PY'
import datetime
import sys

expires_at = datetime.datetime.fromisoformat(sys.argv[1].replace("Z", "+00:00"))
print("true" if expires_at <= datetime.datetime.now(datetime.UTC) else "false")
PY
)"
export QDEV_ACT_EXPECTED_CONFIG="$expected_config"
if [[ "$observed_public_image" != "$expected_public_image" &&
      "$observed_public_image" != "$candidate_public_image" ]] ||
   [[ "$observed_internal_image" != "$expected_internal_image" &&
      "$observed_internal_image" != "$candidate_internal_image" ]]; then
  printf 'running image is foreign to signed transaction\n' >&2
  exit 78
fi
legacy_args=()
if [[ "$allow_legacy_import" == true ]]; then
  legacy_args=(--allow-legacy-import --legacy-status "$legacy_status")
fi
if [[ -z "$recovery_state" && ! -e "$activation_status" &&
      "$allow_measured_bootstrap" == true ]]; then
  "${activation_cli[@]}" bootstrap-measured --status "$activation_status" \
    "${identity[@]}" --measured-status "$measured_status" \
    --observed-current-public-image "$observed_public_image" \
    --observed-current-internal-image "$observed_internal_image" \
    --observed-current-config "$current_config" >/dev/null
fi
reservation=""
if [[ -z "$recovery_state" ]]; then
  reservation="$("${activation_cli[@]}" reserve --status "$activation_status" \
    "${identity[@]}" "${legacy_args[@]}" \
    --observed-current-public-image "$observed_public_image" \
    --observed-current-internal-image "$observed_internal_image" \
    --observed-current-config "$current_config" \
    --allow-config-transition)"
  reservation_state="$(printf '%s' "$reservation" | json_value 'v["reservation_state"]')"
  if [[ "$reservation_state" != new ]]; then
    recovery_state="$reservation_state"
  fi
else
  reservation_state="$recovery_state"
fi
transaction_id="$(printf '%s' "$verified_envelope" | json_value 'v["transaction_id"]')"
envelope_digest="$(printf '%s' "$verified_envelope" | json_value 'v["envelope_digest"]')"
transaction_root=/var/lib/qdev-runner/controller-activation-transactions
transaction_dir="$transaction_root/$transaction_id-$envelope_digest"
material_helper="$script_dir/controller_activation_material.py"
material=""
material_phase=""
if [[ -e "$transaction_dir" || -L "$transaction_dir" ]]; then
  if [[ ! -d "$transaction_root" || -L "$transaction_root" ||
        "$(stat -c %u -- "$transaction_root")" != 0 ||
        "$(stat -c %a -- "$transaction_root")" != 700 ||
        ! -d "$transaction_dir" || -L "$transaction_dir" ||
        "$(stat -c %u -- "$transaction_dir")" != 0 ||
        "$(stat -c %a -- "$transaction_dir")" != 700 ||
        ! -f "$material_helper" || -L "$material_helper" ]]; then
    printf 'activation replay found unsafe durable material\n' >&2
    exit 77
  fi
  material="$("$activation_python" "$material_helper" show \
    --directory "$transaction_dir")" || exit
  if [[ "$(printf '%s' "$material" | json_value 'v["transaction_id"]')" != "$transaction_id" ||
        "$(printf '%s' "$material" | json_value 'v["envelope_digest"]')" != "$envelope_digest" ||
        "$(printf '%s' "$material" | json_value 'v["release_path"]')" != "$release" ]]; then
    printf 'activation material does not match the signed transaction\n' >&2
    exit 78
  fi
  material_phase="$(printf '%s' "$material" | json_value 'v["phase"]')"
fi
if [[ "$reservation_state" == pending-before-mutation &&
      -n "$material_phase" && "$material_phase" != prepared ]]; then
  reservation_state=pending-mutating
  recovery_state=pending-mutating
fi
if [[ "$reservation_state" == pending-mutating && -z "$material" ]]; then
  printf 'mutating activation recovery material is unavailable\n' >&2
  exit 78
fi
if [[ "$reservation_state" == finalized || "$reservation_state" == rolled-back ]]; then
  if [[ -e "$transaction_dir" || -L "$transaction_dir" ]]; then
    rollback_public_ref="$(printf '%s' "$material" | json_value 'v["rollback_public_ref"]')"
    rollback_internal_ref="$(printf '%s' "$material" | json_value 'v["rollback_internal_ref"]')"
    docker image rm "$rollback_public_ref" "$rollback_internal_ref" >/dev/null 2>&1 || true
    "$activation_python" "$material_helper" finish --directory "$transaction_dir" \
      --outcome "$reservation_state" >/dev/null
  fi
  if [[ "$reservation_state" == rolled-back ]]; then
    "${activation_cli[@]}" verify-rollback-terminal --status "$activation_status" \
      "${identity[@]}" --observed-current-public-image "$observed_public_image" \
      --observed-current-internal-image "$observed_internal_image" \
      --observed-current-config "$current_config" >/dev/null
  fi
  printf '%s\n' "$verified_envelope"
  printf 'controller activation replay is already %s\n' "$reservation_state"
  exit 0
fi

public_status_temp=""
cleanup_activation() {
  local status=$?
  if [[ -n "$public_status_temp" ]]; then
    rm -f -- "$public_status_temp"
  fi
  if ((status != 0)); then
    local public_image internal_image config
    local -a images=()
    mapfile -t images < <(running_images 2>/dev/null || true)
    public_image="${images[0]:-}"
    internal_image="${images[1]:-}"
    config="$(config_args_for_current | fingerprint_config 2>/dev/null || true)"
    if [[ "$public_image" == "$expected_public_image" &&
          "$internal_image" == "$expected_internal_image" &&
          "$config" == "$expected_config" ]]; then
      "${activation_cli[@]}" abort --status "$activation_status" \
        "${identity[@]}" --observed-current-public-image "$public_image" \
        --observed-current-internal-image "$internal_image" \
        --observed-current-config "$config" >/dev/null 2>&1 || true
    fi
  fi
  return "$status"
}
trap cleanup_activation EXIT

if [[ -z "$recovery_state" ]]; then
  if [[ -e "$transaction_root" || -L "$transaction_root" ]]; then
    if [[ ! -d "$transaction_root" || -L "$transaction_root" ||
          "$(stat -c %u -- "$transaction_root")" != 0 ||
          "$(stat -c %a -- "$transaction_root")" != 700 ]]; then
      printf 'controller activation material root is unsafe\n' >&2
      exit 77
    fi
  else
    install -d -o root -g root -m 0700 -- "$transaction_root"
  fi
elif [[ ! -d "$transaction_root" || -L "$transaction_root" ||
        "$(stat -c %u -- "$transaction_root")" != 0 ||
        "$(stat -c %a -- "$transaction_root")" != 700 ]]; then
  printf 'controller activation recovery material root is unsafe\n' >&2
  exit 77
fi
if [[ "$reservation_state" == pending-before-mutation ]]; then
  "${activation_cli[@]}" abort --status "$activation_status" \
    "${identity[@]}" --observed-current-public-image "$observed_public_image" \
    --observed-current-internal-image "$observed_internal_image" \
    --observed-current-config "$current_config" >/dev/null
  if [[ -n "$material" ]]; then
    rollback_public_ref="$(printf '%s' "$material" | json_value 'v["rollback_public_ref"]')"
    rollback_internal_ref="$(printf '%s' "$material" | json_value 'v["rollback_internal_ref"]')"
    docker image rm "$rollback_public_ref" "$rollback_internal_ref" >/dev/null 2>&1 || true
    "$activation_python" "$material_helper" finish --directory "$transaction_dir" \
      --outcome rolled-back >/dev/null || exit
  fi
  printf 'controller activation recovery aborted before host mutation\n'
  exit 0
fi

candidate_ref="qdev-runner-broker:controller-$candidate_source"
if [[ "$rollback_mode" != true && -z "$recovery_state" ]]; then
  docker load --input "$candidate_archive" >/dev/null
  [[ "$(strip_digest_prefix "$(docker image inspect "sha256:$candidate_image" --format '{{.Id}}')")" == "$candidate_image" ]] || {
    printf 'imported image bytes do not match attested digest\n' >&2
    exit 78
  }
  verify_oci_tuple "sha256:$candidate_image" "$candidate_source" "$candidate_policy" || exit 78
  docker image tag "sha256:$candidate_image" "$candidate_ref"
fi

if [[ -z "$recovery_state" ]]; then
  "${activation_cli[@]}" assert-current --status "$activation_status" "${identity[@]}" \
    --observed-current-public-image "$observed_public_image" \
    --observed-current-internal-image "$observed_internal_image" \
    --observed-current-config "$current_config"
fi

payload_result=0
payload_environment=(
  "QDEV_CONTROLLER_RELEASE_LOCK=/run/lock/qdev-controller-release-payload.lock"
  "QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION=$expected_source"
  "QDEV_CONTROLLER_NO_BUILD=true"
  "QDEV_CONTROLLER_RELEASE_REVISION=$candidate_source"
  "QDEV_CONTROLLER_POLICY_BUNDLE_DIGEST=$candidate_policy"
  "QDEV_CONTROLLER_CANDIDATE_PUBLIC_IMAGE_DIGEST=$candidate_public_image"
  "QDEV_CONTROLLER_CANDIDATE_INTERNAL_IMAGE_DIGEST=$candidate_internal_image"
  "QDEV_CONTROLLER_CANDIDATE_RELEASE_DIGEST=$candidate_release_digest"
  "QDEV_CONTROLLER_TRANSACTION_HOOK=$entrypoint"
  "QDEV_CONTROLLER_TRANSACTION_ID=$transaction_id"
  "QDEV_CONTROLLER_ENVELOPE_DIGEST=$envelope_digest"
  "QDEV_CONTROLLER_TRANSACTION_ROOT=$transaction_root"
  "QDEV_CONTROLLER_TRANSACTION_DIR=$transaction_dir"
  "QDEV_CONTROLLER_RECOVERY_STATE=$recovery_state"
  "QDEV_CONTROLLER_ENVELOPE_EXPIRED=$envelope_expired"
)
if [[ "$rollback_mode" == true ]]; then
  env -u QDEV_CONTROLLER_IMAGE_REF "${payload_environment[@]}" \
    QDEV_CONTROLLER_ROLLBACK=true "$payload" "$release" || payload_result=$?
else
  env "${payload_environment[@]}" QDEV_CONTROLLER_ROLLBACK=false \
    "QDEV_CONTROLLER_IMAGE_REF=$candidate_ref" \
    "$payload" "$release" || payload_result=$?
fi

if ((payload_result != 0)); then
  exit "$payload_result"
fi

mapfile -t active_images < <(running_images)
[[ "${#active_images[@]}" -eq 2 ]] || exit 74
active_public_image="${active_images[0]}"
active_internal_image="${active_images[1]}"
active_config="$(config_args_for_current | fingerprint_config)"
if [[ "$active_public_image" == "$expected_public_image" &&
      "$active_internal_image" == "$expected_internal_image" &&
      "$active_config" == "$expected_config" ]]; then
  recovery_terminal_outcome=rolled-back
  rollback_receipt="$("${activation_cli[@]}" verify-rollback-terminal \
    --status "$activation_status" "${identity[@]}" \
    --observed-current-public-image "$active_public_image" \
    --observed-current-internal-image "$active_internal_image" \
    --observed-current-config "$active_config")" || exit
  printf '%s\n' "$rollback_receipt"
  printf 'controller_activation_receipt=recovery-%s revision=%s public_image=%s internal_image=%s config=%s\n' \
    "$recovery_terminal_outcome" "$expected_source" "$active_public_image" \
    "$active_internal_image" "$active_config"
  exit 0
fi
[[ "$active_public_image" == "$candidate_public_image" &&
   "$active_internal_image" == "$candidate_internal_image" &&
   "$active_config" == "$candidate_config" ]] || {
  printf 'activated runtime does not match signed candidate\n' >&2
  exit 78
}
replay="$("${activation_cli[@]}" reserve --status "$activation_status" \
  "${identity[@]}" --observed-current-public-image "$active_public_image" \
  --observed-current-internal-image "$active_internal_image" \
  --observed-current-config "$active_config")"
[[ "$(printf '%s' "$replay" | json_value 'v["reservation_state"]')" == finalized ]] || {
  printf 'payload returned without a finalized activation transaction\n' >&2
  exit 78
}
printf '%s\n' "$replay"
printf 'controller_activation_receipt=active revision=%s public_image=%s internal_image=%s policy=%s config=%s artifact=%s\n' \
  "$candidate_source" "$candidate_public_image" "$candidate_internal_image" \
  "$candidate_policy" "$candidate_config" "$artifact_digest"
