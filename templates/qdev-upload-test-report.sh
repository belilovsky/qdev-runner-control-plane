#!/usr/bin/env bash
set -euo pipefail

# Upload native test evidence after the native test command.  The controller
# normalizes JUnit/LCOV/Cobertura; this helper only streams files and never
# creates a token or sends credentials to the browser.
: "${QDEV_ARTIFACT_URL:?QDEV_ARTIFACT_URL is required}"
: "${QDEV_ARTIFACT_TOKEN:?QDEV_ARTIFACT_TOKEN is required}"
: "${QDEV_REPOSITORY:?QDEV_REPOSITORY is required}"
: "${QDEV_HEAD_SHA:?QDEV_HEAD_SHA is required}"
: "${QDEV_JOB_ID:?QDEV_JOB_ID is required}"

upload_report() {
  report_path="$1"
  report_format="$2"
  test -f "$report_path"

  report_name="${report_path##*/}"
  test -n "$report_name"
  sha256="$(shasum -a 256 "$report_path" | awk '{print $1}')"
  attempt="${QDEV_TEST_ATTEMPT:-1}"
  suite="${QDEV_TEST_SUITE:-}"
  if [[ "$report_format" != "qdev-test-run" && "$report_format" != "json" && -z "$suite" ]]; then
    echo "QDEV_TEST_SUITE is required for native test reports" >&2
    return 2
  fi

  if [[ -n "$suite" ]]; then
    url="${QDEV_ARTIFACT_URL%/}/${QDEV_REPOSITORY}/${QDEV_HEAD_SHA}/${QDEV_JOB_ID}/${attempt}/${suite}/${report_name}"
  else
    # Preserve the original route for already-normalized legacy receipts.
    url="${QDEV_ARTIFACT_URL%/}/${QDEV_REPOSITORY}/${QDEV_HEAD_SHA}/${QDEV_JOB_ID}/${report_name}"
  fi

  content_type="application/json"
  case "$report_format" in
    junit|cobertura) content_type="application/xml" ;;
    lcov) content_type="text/plain" ;;
  esac
  curl_args=(
    curl --fail-with-body --silent --show-error --retry 1
    --header "X-Qdev-Artifact-Token: ${QDEV_ARTIFACT_TOKEN}"
    --header "X-Qdev-SHA256: ${sha256}"
    --header "Content-Type: ${content_type}"
  )
  if [[ -n "$suite" ]]; then
    curl_args+=(--header "X-Qdev-Test-Suite: ${suite}")
    curl_args+=(--header "X-Qdev-Test-Attempt: ${attempt}")
  fi
  if [[ -n "${QDEV_TEST_WORKFLOW:-}" ]]; then
    curl_args+=(--header "X-Qdev-Test-Workflow: ${QDEV_TEST_WORKFLOW}")
  fi
  if [[ -n "${QDEV_TEST_PROFILE:-}" ]]; then
    curl_args+=(--header "X-Qdev-Test-Profile: ${QDEV_TEST_PROFILE}")
  fi
  curl_args+=(--header "X-Qdev-Test-Format: ${report_format}" --upload-file "$report_path" "$url")
  "${curl_args[@]}"
}

uploaded=0
if [[ -n "${QDEV_TEST_REPORT:-}" ]]; then
  upload_report "$QDEV_TEST_REPORT" "${QDEV_TEST_FORMAT:-qdev-test-run}"
  uploaded=1
fi
if [[ -n "${QDEV_TEST_JUNIT:-}" ]]; then
  upload_report "$QDEV_TEST_JUNIT" "junit"
  uploaded=1
fi
if [[ -n "${QDEV_TEST_LCOV:-}" ]]; then
  upload_report "$QDEV_TEST_LCOV" "lcov"
  uploaded=1
fi
if [[ -n "${QDEV_TEST_COBERTURA:-}" ]]; then
  upload_report "$QDEV_TEST_COBERTURA" "cobertura"
  uploaded=1
fi
if (( uploaded == 0 )); then
  # qdev-test-run.json remains the documented legacy normalized receipt.
  echo "one of QDEV_TEST_REPORT (qdev-test-run.json), QDEV_TEST_JUNIT, QDEV_TEST_LCOV or QDEV_TEST_COBERTURA is required" >&2
  exit 2
fi
