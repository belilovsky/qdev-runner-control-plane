#!/usr/bin/env bash
set -euo pipefail

root=/var/lib/qdev-runner/artifacts
retention_days="${QDEV_ARTIFACT_RETENTION_DAYS:-7}"

[[ -d "$root" ]] || exit 0
find "$root" -type f -mtime "+$retention_days" -print -delete
find "$root" -depth -type d -empty -delete

