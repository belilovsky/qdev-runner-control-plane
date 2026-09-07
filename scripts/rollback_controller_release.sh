#!/usr/bin/env bash
set -euo pipefail

if [[ "$#" -ne 1 || ! "$1" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'usage: %s EXACT_RELEASE_SHA\n' "$0" >&2
  exit 64
fi

script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
target="/opt/qdev-runner-control-plane/releases/$1"
status_path="${QDEV_CONTROLLER_RELEASE_STATUS:-/var/lib/qdev-runner/controller-status/controller-release.json}"
rollback_anchor_path="${QDEV_CONTROLLER_ROLLBACK_ANCHOR:-/etc/qdev-runner/controller-rollback-anchor.json}"
current_fields="$(python3 - "$status_path" <<'PY'
import json
import pathlib
import re
import sys

payload = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
revision = payload.get("revision")
if (
    payload.get("schema") not in {
        "qdev-controller-release-status-v1", "qdev-controller-release-status-v2"
    }
    or payload.get("state") != "active"
    or not isinstance(revision, str)
    or re.fullmatch(r"[0-9a-f]{40}", revision) is None
):
    raise SystemExit("active controller release status is invalid")
print(revision)
release_digest = payload.get("release_digest")
if not isinstance(release_digest, str) or re.fullmatch(r"sha256:[0-9a-f]{64}", release_digest) is None:
    raise SystemExit("active controller release digest is invalid")
print(release_digest)
PY
)"
mapfile -t current_identity <<< "$current_fields"
if [[ "${#current_identity[@]}" -ne 2 ]]; then
  printf 'active controller release identity is incomplete\n' >&2
  exit 66
fi
current_revision="${current_identity[0]}"
current_release_digest="${current_identity[1]}"
current_release_path="$(realpath -e -- "/opt/qdev-runner-control-plane/releases/$current_revision")"
current_public_image_id="$(docker inspect qdev-runner-broker-public --format '{{.Image}}')"
current_internal_image_id="$(docker inspect qdev-runner-broker-internal --format '{{.Image}}')"
current_public_image_ref="$(docker inspect qdev-runner-broker-public --format '{{.Config.Image}}')"
current_internal_image_ref="$(docker inspect qdev-runner-broker-internal --format '{{.Config.Image}}')"
current_public_saved_ref="qdev-runner-controller-anchor-public:$current_revision"
current_internal_saved_ref="qdev-runner-controller-anchor-internal:$current_revision"

# Preserve the exact forward runtime before rollback.  These tags are additive;
# the durable reverse anchor is not published until activation has succeeded.
docker image tag "$current_public_image_id" "$current_public_saved_ref"
docker image tag "$current_internal_image_id" "$current_internal_saved_ref"

QDEV_CONTROLLER_NO_BUILD=true \
QDEV_CONTROLLER_ROLLBACK=true \
QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION="$current_revision" \
  "$script_dir/activate_controller_release.sh" "$target"

# A successful rollback must remain recoverable.  Flip the anchor to the exact
# runtime that was active before this transaction, using an atomic root-owned
# replacement.  If activation fails, set -e exits before the old anchor moves.
python3 - "$rollback_anchor_path" "$current_revision" "$current_release_digest" \
  "$current_release_path" "$current_public_image_id" "$current_internal_image_id" \
  "$current_public_image_ref" "$current_internal_image_ref" \
  "$current_public_saved_ref" "$current_internal_saved_ref" <<'PY'
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
target_path = pathlib.Path(destination)
descriptor, temporary_name = tempfile.mkstemp(
    dir=target_path.parent, prefix=".controller-rollback-anchor."
)
try:
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chown(temporary_name, 0, 0)
    os.chmod(temporary_name, 0o600)
    os.replace(temporary_name, target_path)
except BaseException:
    pathlib.Path(temporary_name).unlink(missing_ok=True)
    raise
PY
