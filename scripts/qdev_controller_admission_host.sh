#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi

admission_dir=/etc/qdev-runner/admission
receipt_dir=/run/qdev-controller
for directory in "$admission_dir" "$receipt_dir"; do
  if [[ ! -d "$directory" || -L "$directory" ]]; then
    printf 'trusted admission directory is unavailable: %s\n' "$directory" >&2
    exit 73
  fi
  if [[ "$(stat -c %u:%g -- "$directory")" != "0:0" ||
        "$(stat -c %a -- "$directory")" != "700" ]]; then
    printf 'trusted admission directory has invalid ownership or mode: %s\n' "$directory" >&2
    exit 73
  fi
done

image_id="$(docker inspect qdev-runner-broker-internal --format '{{.Image}}' 2>/dev/null || true)"
if [[ ! "$image_id" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  printf 'active controller admission image is unavailable\n' >&2
  exit 69
fi

exec docker run --rm \
  --network none \
  --read-only \
  --user 0:0 \
  --cap-drop ALL \
  --security-opt no-new-privileges \
  --tmpfs /tmp:size=16m,mode=1777 \
  --mount "type=bind,src=$admission_dir,dst=$admission_dir" \
  --mount "type=bind,src=$receipt_dir,dst=$receipt_dir" \
  --entrypoint qdev-controller-admission \
  "$image_id" "$@"
