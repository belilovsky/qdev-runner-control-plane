#!/usr/bin/env bash
set -euo pipefail

# Upgrades must run from the already trusted root-owned runtime. The explicit
# owner override is reserved for the single historical bootstrap replacement.
if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi
if [[ "$#" -ne 3 ]]; then
  printf 'usage: %s RELEASE EXPECTED_REVISION EXPECTED_BUNDLE_DIGEST\n' "$0" >&2
  exit 64
fi

release_root=/opt/qdev-runner-control-plane
bootstrap_root=/opt/qdev-runner-bootstrap
broker_env=/etc/qdev-runner/broker.env
directive_key=/etc/qdev-runner/bootstrap-directive.key
unit=qdev-bootstrap-privileged-executor.service
release="$(realpath -e -- "$1")"
expected_revision="$2"
expected_bundle_digest="$3"
[[ "$expected_revision" =~ ^[0-9a-f]{40}$ ]] || exit 64
[[ "$expected_bundle_digest" =~ ^[0-9a-f]{64}$ ]] || exit 64
case "$release" in
  "$release_root"/releases/*) ;;
  *)
    printf 'release must be below %s/releases\n' "$release_root" >&2
    exit 64
    ;;
esac

self_path="$(realpath -e -- "$0")"
trusted_current="$(readlink -f -- "$bootstrap_root/current" 2>/dev/null || true)"
if [[ -z "$trusted_current" || "$self_path" != "$trusted_current/provision-bootstrap-executor.sh" ]]; then
  [[ "${QDEV_BOOTSTRAP_OWNER_OVERRIDE:-}" == "owner-authorized-once" ]] || {
    printf 'installer must run from the current trusted bootstrap runtime\n' >&2
    exit 77
  }
fi

for path in "$broker_env" "$release/controller-release-bundle.json" \
  "$release/requirements.runtime.txt" "$release/wheelhouse/bootstrap-wheelhouse.json" \
  "$release/scripts/provision_bootstrap_executor.sh" "$release/deploy/$unit"; do
  [[ -f "$path" && ! -L "$path" ]] || {
    printf 'bootstrap input is unavailable\n' >&2
    exit 66
  }
done
[[ "$(stat -c %u -- "$broker_env")" == 0 && $((8#$(stat -c %a -- "$broker_env") & 8#077)) == 0 ]] || {
  printf 'broker environment permissions are unsafe\n' >&2
  exit 66
}

# Candidate Python is never executed to verify itself. This verifier is part
# of the previously trusted installer and accepts the expected identity only
# from the privileged caller.
verify_release() {
  /usr/bin/python3 - "$release" "$expected_revision" "$expected_bundle_digest" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys

root = pathlib.Path(sys.argv[1]).resolve(strict=True)
revision, expected_digest = sys.argv[2:]
manifest = json.loads((root / "controller-release-bundle.json").read_text(encoding="utf-8"))
if set(manifest) != {"schema", "source_revision", "files", "bundle_digest"}:
    raise SystemExit("bundle manifest shape is invalid")
if manifest["schema"] != "qdev-controller-release-bundle-v1":
    raise SystemExit("bundle schema is invalid")
if manifest["source_revision"] != revision or manifest["bundle_digest"] != expected_digest:
    raise SystemExit("externally supplied bundle identity differs")
files = manifest["files"]
if not isinstance(files, dict):
    raise SystemExit("bundle file inventory is invalid")
actual = {}
for current, directories, names in os.walk(root, followlinks=False):
    current_path = pathlib.Path(current)
    for name in directories:
        path = current_path / name
        if path.is_symlink() or not path.is_dir():
            raise SystemExit("bundle directory is unsafe")
    for name in names:
        path = current_path / name
        relative = path.relative_to(root).as_posix()
        if relative == "controller-release-bundle.json":
            continue
        metadata = path.lstat()
        if path.is_symlink() or not stat.S_ISREG(metadata.st_mode):
            raise SystemExit("bundle file is unsafe")
        actual[relative] = {
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "mode": stat.S_IMODE(metadata.st_mode),
        }
if actual != files:
    raise SystemExit("bundle file inventory differs")
identity = {"schema": manifest["schema"], "source_revision": revision, "files": actual}
canonical = json.dumps(identity, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
if hashlib.sha256(canonical).hexdigest() != expected_digest:
    raise SystemExit("bundle digest differs")

def normalise(value):
    return re.sub(r"[-_.]+", "-", value).lower()

requirements_path = root / "requirements.runtime.txt"
requirements = {}
for raw in requirements_path.read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    match = re.fullmatch(
        r"([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)"
        r" --hash=sha256:([0-9a-f]{64})",
        line,
    )
    if match is None or normalise(match.group(1)) in requirements:
        raise SystemExit("runtime requirement is not uniquely pinned")
    requirements[normalise(match.group(1))] = (match.group(2), match.group(3))
if not requirements:
    raise SystemExit("runtime requirements are empty")

wheel_root = root / "wheelhouse"
wheel_records, packages = {}, {}
for path in sorted(wheel_root.iterdir()):
    if path.name == "bootstrap-wheelhouse.json":
        continue
    match = re.fullmatch(r"([A-Za-z0-9_.]+)-([A-Za-z0-9_.+!]+)-.+\.whl", path.name)
    if path.is_symlink() or not path.is_file() or match is None:
        raise SystemExit("wheelhouse entry is unsafe")
    package, version = normalise(match.group(1)), match.group(2)
    if package in packages:
        raise SystemExit("wheelhouse distribution is duplicated")
    packages[package] = version
    wheel_records[path.name] = {
        "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        "distribution": package,
        "version": version,
    }
if set(packages) != set(requirements) | {"qdev-runner-control-plane"}:
    raise SystemExit("wheelhouse distribution set differs")
if any(
    packages.get(name) != version
    or next(record for record in wheel_records.values() if record["distribution"] == name)[
        "sha256"
    ] != expected_hash
    for name, (version, expected_hash) in requirements.items()
):
    raise SystemExit("wheelhouse versions differ from pins")
wheel_manifest = json.loads((wheel_root / "bootstrap-wheelhouse.json").read_text(encoding="utf-8"))
if set(wheel_manifest) != {
    "schema", "python", "requirements_sha256", "wheels", "sbom", "sbom_sha256",
    "wheelhouse_digest",
}:
    raise SystemExit("wheelhouse manifest shape is invalid")
if wheel_manifest["schema"] != "qdev-bootstrap-wheelhouse-v1" or wheel_manifest["python"] != "3.12":
    raise SystemExit("wheelhouse identity is invalid")
if wheel_manifest["requirements_sha256"] != hashlib.sha256(requirements_path.read_bytes()).hexdigest():
    raise SystemExit("wheelhouse requirements digest differs")
if wheel_manifest["wheels"] != wheel_records:
    raise SystemExit("wheelhouse records differ")
sbom_bytes = json.dumps(wheel_manifest["sbom"], ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
if wheel_manifest["sbom_sha256"] != hashlib.sha256(sbom_bytes).hexdigest():
    raise SystemExit("wheelhouse SBOM differs")
wheel_identity = {key: wheel_manifest[key] for key in (
    "schema", "python", "requirements_sha256", "wheels", "sbom", "sbom_sha256"
)}
wheel_bytes = json.dumps(wheel_identity, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode()
if wheel_manifest["wheelhouse_digest"] != hashlib.sha256(wheel_bytes).hexdigest():
    raise SystemExit("wheelhouse digest differs")
PY
}
verify_release

install -d -o root -g root -m 0755 -- "$bootstrap_root/releases"
final="$bootstrap_root/releases/$expected_revision-$expected_bundle_digest"
staging="$(mktemp -d "$bootstrap_root/releases/.incoming.XXXXXX")"
temporary_key=""
unit_backup=""
temporary_link=""
directive_key_created=false
cleanup() {
  [[ -z "$temporary_key" ]] || rm -f -- "$temporary_key"
  [[ -z "$unit_backup" ]] || rm -f -- "$unit_backup"
  [[ -z "$temporary_link" ]] || rm -f -- "$temporary_link"
  rm -rf -- "$staging"
}
trap cleanup EXIT

/usr/bin/python3 -m venv "$staging/venv"
mapfile -d '' wheels < <(find "$release/wheelhouse" -maxdepth 1 -type f -name '*.whl' -print0 | sort -z)
[[ "${#wheels[@]}" -gt 0 ]] || exit 66
mapfile -d '' app_wheels < <(find "$release/wheelhouse" -maxdepth 1 -type f \
  -name 'qdev_runner_control_plane-*.whl' -print0)
[[ "${#app_wheels[@]}" -eq 1 ]] || exit 66
"$staging/venv/bin/python" -m pip install --disable-pip-version-check --no-index --no-deps \
  --require-hashes --find-links "$release/wheelhouse" -r "$release/requirements.runtime.txt"
"$staging/venv/bin/python" -m pip install --disable-pip-version-check --no-index --no-deps \
  "${app_wheels[0]}"
"$staging/venv/bin/python" - <<'PY'
import pathlib
import sys
import qdev_runner

configuration = pathlib.Path(sys.prefix, "pyvenv.cfg").read_text(encoding="utf-8").lower()
if "include-system-site-packages = false" not in configuration:
    raise SystemExit("bootstrap virtual environment is not isolated")
package = pathlib.Path(qdev_runner.__file__).resolve()
if not package.is_relative_to(pathlib.Path(sys.prefix).resolve()):
    raise SystemExit("bootstrap package escaped its isolated environment")
PY
install -o root -g root -m 0555 -- "$release/scripts/provision_bootstrap_executor.sh" \
  "$staging/provision-bootstrap-executor.sh"
printf '%s\n' "$expected_revision" > "$staging/source-revision"
printf '%s\n' "$expected_bundle_digest" > "$staging/bundle-digest"
chmod 0444 "$staging/source-revision" "$staging/bundle-digest"
chown -R root:root -- "$staging"

# Recheck after staging and immediately before activation.
verify_release
if [[ -e "$final" || -L "$final" ]]; then
  [[ -d "$final" && ! -L "$final" ]] || exit 66
  [[ "$(<"$final/source-revision")" == "$expected_revision" ]] || exit 66
  [[ "$(<"$final/bundle-digest")" == "$expected_bundle_digest" ]] || exit 66
  rm -rf -- "$staging"
else
  mv -- "$staging" "$final"
fi

# Extract exactly one existing value without sourcing the environment file.
temporary_key="$(mktemp /etc/qdev-runner/.bootstrap-directive-key.XXXXXX)"
/usr/bin/python3 - "$broker_env" "$temporary_key" <<'PY'
import os
import pathlib
import sys

source = pathlib.Path(sys.argv[1])
target = pathlib.Path(sys.argv[2])
values = [line.partition("=")[2] for line in source.read_text(encoding="utf-8").splitlines()
          if line.startswith("QDEV_OPERATOR_DIRECTIVE_KEY=")]
if len(values) != 1 or not 32 <= len(values[0].encode()) <= 4096:
    raise SystemExit("existing directive key is unavailable")
descriptor = os.open(target, os.O_WRONLY | os.O_TRUNC)
with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
    stream.write(values[0] + "\n")
    stream.flush()
    os.fsync(stream.fileno())
PY
chmod 0600 "$temporary_key"
chown root:root "$temporary_key"
if [[ -f "$directive_key" ]]; then
  cmp -s -- "$temporary_key" "$directive_key" || exit 66
  rm -f -- "$temporary_key"
  temporary_key=""
else
  mv -- "$temporary_key" "$directive_key"
  temporary_key=""
  directive_key_created=true
fi

previous=""
if [[ -e "$bootstrap_root/current" || -L "$bootstrap_root/current" ]]; then
  [[ -L "$bootstrap_root/current" ]] || exit 66
  previous="$(readlink -f -- "$bootstrap_root/current" 2>/dev/null || true)"
  case "$previous" in
    "$bootstrap_root"/releases/*) ;;
    *) exit 66 ;;
  esac
  [[ -d "$previous" && ! -L "$previous" ]] || exit 66
fi
temporary_link="$bootstrap_root/.current.$$"
unit_path="/etc/systemd/system/$unit"
unit_backup="$(mktemp /etc/systemd/system/.${unit}.XXXXXX)"
unit_existed=false
if [[ -f "$unit_path" && ! -L "$unit_path" ]]; then
  cp --preserve=mode,ownership,timestamps -- "$unit_path" "$unit_backup"
  unit_existed=true
elif [[ -e "$unit_path" || -L "$unit_path" ]]; then
  exit 66
fi

previous_active=false
previous_enabled=false
previous_invocation=""
if systemctl is-active --quiet "$unit"; then
  previous_active=true
  previous_invocation="$(systemctl show --property=InvocationID --value "$unit")"
fi
if systemctl is-enabled --quiet "$unit"; then
  previous_enabled=true
fi

runtime_identity=/run/qdev-runner-bootstrap/executor-identity.json
activation_armed=false
rollback_activation() {
  local original_status="$1"
  local rollback_failed=false
  trap - ERR
  set +e
  [[ "$activation_armed" == true ]] || exit "$original_status"

  rm -f -- "$runtime_identity" "$temporary_link"
  if [[ "$unit_existed" == true ]]; then
    install -o root -g root -m 0644 -- "$unit_backup" "$unit_path" || rollback_failed=true
  else
    rm -f -- "$unit_path" || rollback_failed=true
  fi
  if [[ -n "$previous" ]]; then
    ln -s -- "$previous" "$temporary_link" || rollback_failed=true
    if [[ -L "$temporary_link" ]]; then
      mv -Tf -- "$temporary_link" "$bootstrap_root/current" || rollback_failed=true
    fi
  else
    rm -f -- "$bootstrap_root/current" || rollback_failed=true
  fi
  systemctl daemon-reload || rollback_failed=true
  if [[ "$unit_existed" == true ]]; then
    if [[ "$previous_enabled" == true ]]; then
      systemctl enable "$unit" || rollback_failed=true
    fi
    if [[ "$previous_active" == true ]]; then
      systemctl restart "$unit" || rollback_failed=true
    else
      systemctl stop "$unit" || rollback_failed=true
    fi
    if [[ "$previous_enabled" != true ]]; then
      systemctl disable "$unit" || rollback_failed=true
    fi
  else
    systemctl stop "$unit" >/dev/null 2>&1 || true
  fi
  if [[ "$directive_key_created" == true ]]; then
    rm -f -- "$directive_key" || rollback_failed=true
  fi
  if [[ "$rollback_failed" == true ]]; then
    printf 'privileged bootstrap executor activation and rollback failed\n' >&2
  else
    printf 'privileged bootstrap executor activation failed; previous runtime restored\n' >&2
  fi
  exit "$original_status"
}
activation_failure() {
  printf '%s\n' "$1" >&2
  return 70
}

activation_armed=true
trap 'rollback_activation "$?"' ERR
ln -s -- "$final" "$temporary_link"
mv -Tf -- "$temporary_link" "$bootstrap_root/current"
temporary_link=""
install -o root -g root -m 0644 -- "$release/deploy/$unit" "$unit_path"
systemctl daemon-reload
systemctl enable "$unit"
rm -f -- "$runtime_identity"
systemctl restart "$unit"
systemctl is-active --quiet "$unit"

main_pid="$(systemctl show --property=MainPID --value "$unit")"
invocation="$(systemctl show --property=InvocationID --value "$unit")"
[[ "$main_pid" =~ ^[1-9][0-9]*$ ]] || activation_failure "new executor PID is invalid"
[[ "$invocation" =~ ^[0-9a-f]{32}$ ]] || activation_failure "new invocation is invalid"
if [[ "$previous_active" == true && -n "$previous_invocation" ]]; then
  [[ "$invocation" != "$previous_invocation" ]] || \
    activation_failure "executor was not restarted"
fi

identity_ready=false
for _attempt in {1..30}; do
  if [[ -s "$runtime_identity" ]]; then
    identity_ready=true
    break
  fi
  sleep 1
done
[[ "$identity_ready" == true ]] || activation_failure "new executor identity is unavailable"

# The trusted installer verifies the newly running process rather than asking
# candidate code to attest to itself.
/usr/bin/python3 - "$runtime_identity" "$final" "$expected_revision" \
  "$expected_bundle_digest" "$main_pid" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys

identity_path = pathlib.Path(sys.argv[1])
expected_root = pathlib.Path(sys.argv[2]).resolve(strict=True)
revision, bundle_digest, expected_pid_raw = sys.argv[3:]
metadata = identity_path.lstat()
if (
    identity_path.is_symlink()
    or not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or stat.S_IMODE(metadata.st_mode) & 0o077
):
    raise SystemExit("runtime identity file is unsafe")
identity = json.loads(identity_path.read_text(encoding="utf-8"))
if set(identity) != {
    "schema", "source_revision", "bundle_digest", "pid", "boot_id",
    "process_start_ticks", "release_root", "package_path",
}:
    raise SystemExit("runtime identity shape is invalid")
expected_pid = int(expected_pid_raw)
if (
    identity["schema"] != "qdev-bootstrap-executor-runtime-identity-v1"
    or identity["source_revision"] != revision
    or identity["bundle_digest"] != bundle_digest
    or identity["pid"] != expected_pid
    or identity["release_root"] != str(expected_root)
):
    raise SystemExit("runtime identity differs from activated release")
boot_id = pathlib.Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip().lower()
if identity["boot_id"] != boot_id or not re.fullmatch(
    r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", boot_id
):
    raise SystemExit("runtime boot identity differs")
stat_value = pathlib.Path(f"/proc/{expected_pid}/stat").read_text(encoding="utf-8")
fields = stat_value[stat_value.rindex(") ") + 2:].split()
if identity["process_start_ticks"] != int(fields[19]):
    raise SystemExit("runtime process identity differs")
package_path = pathlib.Path(identity["package_path"]).resolve(strict=True)
if not package_path.is_relative_to(expected_root):
    raise SystemExit("runtime package escaped activated release")
if os.stat(package_path).st_uid != 0:
    raise SystemExit("runtime package ownership is unsafe")
PY

activation_armed=false
trap - ERR

printf 'bootstrap_executor_active revision=%s bundle_digest=%s\n' \
  "$expected_revision" "$expected_bundle_digest"
