#!/usr/bin/env bash
set -euo pipefail

root=/var/lib/qdev-runner/artifacts
retention_days="${QDEV_ARTIFACT_RETENTION_DAYS:-7}"

[[ -d "$root" ]] || exit 0
while IFS= read -r -d '' candidate; do
  directory="$(dirname "$candidate")"
  retained=false
  while [[ "$directory" == "$root"/* ]]; do
    if [[ -e "$directory/.qdev-retain" ]]; then
      retained=true
      break
    fi
    directory="$(dirname "$directory")"
  done
  if [[ "$retained" == false ]]; then
    printf '%s\n' "$candidate"
    rm -- "$candidate"
  fi
done < <(find "$root" -type f ! -name .qdev-retain -mtime "+$retention_days" -print0)
find "$root" -depth -type d -empty -delete
