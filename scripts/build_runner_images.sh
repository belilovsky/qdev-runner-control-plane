#!/usr/bin/env bash
set -euo pipefail

engine="${QDEV_CONTAINER_ENGINE:-docker}"
registry="${QDEV_REGISTRY:-registry.ci.qdev.run/qdev}"
version="${QDEV_RUNNER_VERSION:-2.337.0-r4}"

"$engine" build --pull --target general \
  --tag "${registry}/actions-runner:${version}" images/runner
"$engine" build --pull --target browser \
  --tag "${registry}/actions-runner-browser:${version}" images/runner
"$engine" build --pull --target docker \
  --tag "${registry}/actions-runner-buildkit:${version}" images/runner

if [[ "${QDEV_PUSH_IMAGES:-false}" == true ]]; then
  "$engine" push "${registry}/actions-runner:${version}"
  "$engine" push "${registry}/actions-runner-browser:${version}"
  "$engine" push "${registry}/actions-runner-buildkit:${version}"
fi

for image in actions-runner actions-runner-browser actions-runner-buildkit; do
  "$engine" image inspect "${registry}/${image}:${version}" \
    --format '{{.Id}} {{join .RepoDigests " "}}'
done
