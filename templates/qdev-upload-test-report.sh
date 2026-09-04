#!/usr/bin/env bash
set -euo pipefail

# Upload a normalized qdev-test-run-v1 receipt after the native test command.
# The worker owns the short-lived token; this helper never creates a token or
# sends credentials to the browser.
: "${QDEV_ARTIFACT_URL:?QDEV_ARTIFACT_URL is required}"
: "${QDEV_ARTIFACT_TOKEN:?QDEV_ARTIFACT_TOKEN is required}"
: "${QDEV_REPOSITORY:?QDEV_REPOSITORY is required}"
: "${QDEV_HEAD_SHA:?QDEV_HEAD_SHA is required}"
: "${QDEV_JOB_ID:?QDEV_JOB_ID is required}"
: "${QDEV_TEST_REPORT:?QDEV_TEST_REPORT is required}"

test -f "$QDEV_TEST_REPORT"
sha256="$(shasum -a 256 "$QDEV_TEST_REPORT" | awk '{print $1}')"
url="${QDEV_ARTIFACT_URL%/}/${QDEV_REPOSITORY}/${QDEV_HEAD_SHA}/${QDEV_JOB_ID}/qdev-test-run.json"

curl --fail-with-body --silent --show-error --retry 1 \
  --header "X-Qdev-Artifact-Token: ${QDEV_ARTIFACT_TOKEN}" \
  --header "X-Qdev-SHA256: ${sha256}" \
  --header "Content-Type: application/json" \
  --upload-file "$QDEV_TEST_REPORT" \
  "$url"
