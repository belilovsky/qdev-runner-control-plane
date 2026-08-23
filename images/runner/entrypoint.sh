#!/usr/bin/env bash
set -euo pipefail

if [[ -z "${QDEV_JIT_CONFIG:-}" ]]; then
  echo "QDEV_JIT_CONFIG is required" >&2
  exit 64
fi

if [[ -n "${DOCKER_HOST:-}" && -n "${QDEV_REGISTRY_PASSWORD:-}" ]]; then
  printf '%s' "${QDEV_REGISTRY_PASSWORD}" | docker login \
    --username "${QDEV_REGISTRY_USERNAME:?}" \
    --password-stdin "${QDEV_REGISTRY_URL:?}" >/dev/null
fi

cleanup() {
  unset QDEV_JIT_CONFIG
  find /home/runner/actions-runner/_work -mindepth 1 -maxdepth 1 -exec rm -rf -- {} + 2>/dev/null || true
}
trap cleanup EXIT INT TERM

exec ./run.sh --jitconfig "${QDEV_JIT_CONFIG}"
