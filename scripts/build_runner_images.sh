#!/usr/bin/env bash
set -euo pipefail

engine="${QDEV_CONTAINER_ENGINE:-docker}"
registry="${QDEV_REGISTRY:-registry.ci.qdev.run/qdev}"
version="${QDEV_RUNNER_VERSION:-2.337.0-r7}"
browser_image="${registry}/actions-runner-browser:${version}"
browser_staging_image="${browser_image}-rootfs"
browser_export_root=""
browser_container=""

cleanup_browser_export() {
  if [[ -n "${browser_container}" ]]; then
    "$engine" rm --force "${browser_container}" >/dev/null 2>&1 || true
  fi
  if [[ -n "${browser_export_root}" ]]; then
    rm -rf -- "${browser_export_root}"
  fi
  "$engine" image rm "${browser_staging_image}" >/dev/null 2>&1 || true
}

trap cleanup_browser_export EXIT

"$engine" build --pull --target general \
  --tag "${registry}/actions-runner:${version}" images/runner

# The pinned upstream Playwright image contains deleted npm-cache credentials in
# historical layers.  A Dockerfile whiteout, including a scratch-stage COPY,
# does not hide those bytes from layer-aware secret scanners.  Export the
# validated final rootfs and import it as one new layer so the published image
# cannot carry inaccessible credential material in its history.
# Build the fully validated source rootfs directly. Building the scratch
# `browser` target here would materialize a second copy of the whole
# Playwright filesystem before the export/import flattening below, doubling
# peak disk usage without changing the published artifact.
"$engine" build --pull --target browser-build \
  --tag "${browser_staging_image}" images/runner
browser_export_root=$(mktemp -d)
browser_container=$("$engine" create "${browser_staging_image}")
"$engine" export --output "${browser_export_root}/rootfs.tar" "${browser_container}"
"$engine" import \
  --change 'ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 LC_ALL=C.UTF-8 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright' \
  --change 'LABEL org.opencontainers.image.version=24.04' \
  --change 'USER runner' \
  --change 'WORKDIR /home/runner/actions-runner' \
  --change 'ENTRYPOINT ["/usr/local/bin/qdev-runner-entrypoint"]' \
  "${browser_export_root}/rootfs.tar" "${browser_image}"
"$engine" rm "${browser_container}" >/dev/null
browser_container=""
rm -rf -- "${browser_export_root}"
browser_export_root=""
"$engine" image rm "${browser_staging_image}" >/dev/null
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
