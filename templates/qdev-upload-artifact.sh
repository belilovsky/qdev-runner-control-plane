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
  # GitHub exposes a workflow-run ID in the environment, while the broker
  # deliberately authorizes artifacts against the numeric *job* ID.  Resolve
  # the current job through GitHub's authenticated API instead of treating a
  # run as a job (which otherwise fails closed with a broker 404).
  [[ -n "${GITHUB_TOKEN:-}" && -n "${QDEV_GITHUB_JOB_NAME:-}" ]] || {
    printf '%s\n' 'hosted artifact uploads require GITHUB_TOKEN and QDEV_GITHUB_JOB_NAME' >&2
    exit 2
  }
  [[ "${GITHUB_RUN_ID:-}" =~ ^[1-9][0-9]*$ ]] || {
    printf '%s\n' 'GITHUB_RUN_ID must be a positive integer' >&2
    exit 2
  }
  [[ "${QDEV_GITHUB_JOB_NAME}" =~ ^[A-Za-z0-9][A-Za-z0-9\ ._:/\(\)-]{0,127}$ ]] || {
    printf '%s\n' 'QDEV_GITHUB_JOB_NAME is invalid' >&2
    exit 2
  }
  github_api="${GITHUB_API_URL:-https://api.github.com}"
  [[ "$github_api" == https://* ]] || {
    printf '%s\n' 'GITHUB_API_URL must use HTTPS' >&2
    exit 2
  }
  github_jobs="$(curl --fail --silent --show-error \
    --header "Authorization: Bearer ${GITHUB_TOKEN}" \
    --header 'Accept: application/vnd.github+json' \
    --header 'X-GitHub-Api-Version: 2022-11-28' \
    "${github_api%/}/repos/${GITHUB_REPOSITORY:?}/actions/runs/${GITHUB_RUN_ID}/jobs?per_page=100")"
  github_job_id="$(printf '%s' "$github_jobs" | python3 -c '
import json
import sys

expected_name, expected_run, expected_sha = sys.argv[1:]
try:
    payload = json.load(sys.stdin)
except json.JSONDecodeError as error:
    raise SystemExit("GitHub jobs response is invalid") from error
jobs = payload.get("jobs") if isinstance(payload, dict) else None
if not isinstance(jobs, list):
    raise SystemExit("GitHub jobs response is invalid")
matches = [job for job in jobs if isinstance(job, dict) and job.get("name") == expected_name]
if len(matches) != 1:
    raise SystemExit("current hosted job is not uniquely discoverable")
job = matches[0]
job_id = job.get("id")
if isinstance(job_id, bool) or not isinstance(job_id, int) or job_id < 1:
    raise SystemExit("GitHub returned an invalid numeric job ID")
if str(job.get("run_id")) != expected_run or job.get("head_sha") != expected_sha:
    raise SystemExit("GitHub job identity does not match this attempt")
if job.get("status") not in {"queued", "in_progress"}:
    raise SystemExit("current hosted job is not active")
print(job_id)
' "${QDEV_GITHUB_JOB_NAME}" "${GITHUB_RUN_ID}" "${GITHUB_SHA:?}")"
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
    "${QDEV_ARTIFACT_URL:-https://ci.qdev.run/artifacts}/${GITHUB_REPOSITORY:?}/${GITHUB_SHA:?}/${github_job_id}/${name}.tar.gz"
else
  printf '%s\n' 'no supported qdev artifact identity is available' >&2
  exit 2
fi
printf '\nqdev_artifact_ok name=%s sha256=%s\n' "$name" "$digest"
