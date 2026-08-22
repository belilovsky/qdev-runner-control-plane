#!/usr/bin/env bash
set -euo pipefail

name="${1:?artifact name is required}"
shift
files=()
for path in "$@"; do
  if [[ -e "$path" ]]; then
    files+=("$path")
  fi
done
if [[ "${#files[@]}" -eq 0 ]]; then
  if [[ "${QDEV_IF_NO_FILES:-error}" == "warn" ]]; then
    printf 'qdev artifact %s has no files\n' "$name" >&2
    exit 0
  fi
  printf 'qdev artifact %s has no files\n' "$name" >&2
  exit 1
fi

archive="$(mktemp "${RUNNER_TEMP:-/tmp}/qdev-artifact.XXXXXX.tar.gz")"
trap 'rm -f -- "$archive"' EXIT
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -czf "$archive" -- "${files[@]}"
digest="$(sha256sum "$archive" | awk '{print $1}')"
curl --fail --silent --show-error --request PUT \
  --header "X-QDev-Artifact-Token: ${QDEV_ARTIFACT_TOKEN:?}" \
  --header "X-QDev-SHA256: ${digest}" \
  --data-binary "@${archive}" \
  "${QDEV_ARTIFACT_URL:?}/${GITHUB_REPOSITORY:?}/${GITHUB_SHA:?}/${QDEV_JOB_ID:?}/${name}.tar.gz"
printf '\nqdev_artifact_ok name=%s sha256=%s\n' "$name" "$digest"
