#!/usr/bin/env bash
set -euo pipefail

name="${1:?artifact name is required}"
if [[ ! "$name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$ ]]; then
  printf 'invalid qdev artifact name: %s\n' "$name" >&2
  exit 2
fi
shift
files=()
for path in "$@"; do
  if [[ -e "$path" || -L "$path" ]]; then
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
tar --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner \
  --exclude="$archive" --exclude="${archive#/}" \
  -czf "$archive" -- "${files[@]}"
digest="$(sha256sum "$archive" | awk '{print $1}')"
if [[ -n "${QDEV_ARTIFACT_TOKEN:-}" || -n "${QDEV_REPOSITORY:-}" || -n "${QDEV_HEAD_SHA:-}" || -n "${QDEV_JOB_ID:-}" ]]; then
  [[ -n "${QDEV_ARTIFACT_TOKEN:-}" && -n "${QDEV_REPOSITORY:-}" && -n "${QDEV_HEAD_SHA:-}" && -n "${QDEV_JOB_ID:-}" ]] || {
    printf '%s\n' 'incomplete self-hosted qdev artifact identity' >&2
    exit 2
  }
  curl --fail --silent --show-error --request PUT \
    --header "X-QDev-Artifact-Token: ${QDEV_ARTIFACT_TOKEN}" \
    --header "X-QDev-SHA256: ${digest}" \
    --data-binary "@${archive}" \
    "${QDEV_ARTIFACT_URL:?}/${QDEV_REPOSITORY}/${QDEV_HEAD_SHA}/${QDEV_JOB_ID}/${name}.tar.gz"
elif [[ -n "${ACTIONS_ID_TOKEN_REQUEST_URL:-}" && -n "${ACTIONS_ID_TOKEN_REQUEST_TOKEN:-}" ]]; then
  oidc_url="${ACTIONS_ID_TOKEN_REQUEST_URL}"
  if [[ "$oidc_url" == *\?* ]]; then
    oidc_url+="&audience=qdev-artifact-v1"
  else
    oidc_url+="?audience=qdev-artifact-v1"
  fi
  oidc_response="$(curl --fail --silent --show-error \
    --header "Authorization: bearer ${ACTIONS_ID_TOKEN_REQUEST_TOKEN}" \
    "$oidc_url")"
  oidc_token="$(printf '%s' "$oidc_response" | sed -n 's/.*"value"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
  [[ -n "$oidc_token" ]] || {
    printf '%s\n' 'GitHub Actions OIDC response has no token' >&2
    exit 2
  }
  curl --fail --silent --show-error --request PUT \
    --header "X-QDev-GitHub-OIDC: ${oidc_token}" \
    --header "X-QDev-SHA256: ${digest}" \
    --data-binary "@${archive}" \
    "${QDEV_ARTIFACT_URL:-https://ci.qdev.run/artifacts}/${GITHUB_REPOSITORY:?}/${GITHUB_SHA:?}/${GITHUB_RUN_ID:?}/${name}.tar.gz"
else
  printf '%s\n' 'no supported qdev artifact identity is available' >&2
  exit 2
fi
printf '\nqdev_artifact_ok name=%s sha256=%s\n' "$name" "$digest"
