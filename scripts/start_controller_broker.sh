#!/usr/bin/env bash
# Start the broker from the durable, signed controller activation status.
#
# A service restart must never silently rebuild ``qdev-runner-broker:local``:
# doing so disconnects the runtime from the tuple that activation approved.
set -euo pipefail

status=/var/lib/qdev-runner/controller-activation/activation-status.json
current=/opt/qdev-runner-control-plane/current

read -r source public_image internal_image policy < <(python3 - "$status" <<'PY'
import json
import re
import sys

path = sys.argv[1]
try:
    value = json.load(open(path, encoding="utf-8"))
except (OSError, ValueError) as error:
    raise SystemExit("active controller status is unavailable") from error

required = {
    "schema",
    "state",
    "source_sha",
    "public_image_digest",
    "internal_image_digest",
    "policy_bundle_digest",
}
if not required.issubset(value) or value.get("schema") != "qdev-controller-activation-status-v2":
    raise SystemExit("active controller status is invalid")
if value.get("state") != "active":
    raise SystemExit("controller activation is not active")
source = value["source_sha"]
digests = [
    value["public_image_digest"],
    value["internal_image_digest"],
    value["policy_bundle_digest"],
]
if not isinstance(source, str) or re.fullmatch(r"[0-9a-f]{40}", source) is None:
    raise SystemExit("active controller source identity is invalid")
if any(not isinstance(item, str) or re.fullmatch(r"[0-9a-f]{64}", item) is None for item in digests):
    raise SystemExit("active controller digest is invalid")
if value["public_image_digest"] != value["internal_image_digest"]:
    raise SystemExit("active controller images do not match")
print(source, *digests)
PY
)

release="/opt/qdev-runner-control-plane/releases/$source"
[[ -d "$release" && ! -L "$release" ]]
[[ "$(readlink -f "$current")" == "$release" ]]

reference="qdev-runner-broker:controller-$source"
observed="$(docker image inspect "$reference" --format '{{.Id}}')"
[[ "$observed" == "sha256:$public_image" ]]
[[ "$public_image" == "$internal_image" ]]

exec env \
  QDEV_CONTROLLER_IMAGE_REF="$reference" \
  QDEV_CONTROLLER_RELEASE_REVISION="$source" \
  QDEV_CONTROLLER_POLICY_BUNDLE_DIGEST="$policy" \
  docker compose --project-name qdev-runner -f "$release/deploy/compose.yml" \
  up -d --force-recreate --no-build --no-deps broker-public broker-internal
