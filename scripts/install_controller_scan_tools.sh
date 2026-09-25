#!/usr/bin/env bash
set -euo pipefail

# Only the ephemeral Linux builder installs these versioned tools.
[[ "${GITHUB_ACTIONS:-}" == true && "$(uname -sm)" == 'Linux x86_64' ]] || exit 64
directory="$(mktemp -d "${RUNNER_TEMP:?}/controller-scanners.XXXXXX")"
# The controller recovery build may run either on an ephemeral GitHub-hosted
# builder (where the job user needs sudo) or inside the rootless QDev
# self-hosted worker container (where sudo does not exist and the job already
# runs as root).  Install into a job-scoped directory that always works and
# publish it on PATH for the following steps instead of writing to
# /usr/local/bin.
bin_directory="${RUNNER_TEMP:?}/controller-scanners-bin"
mkdir -p "$bin_directory"
trap 'rm -rf -- "$directory"' EXIT
cd "$directory"
trivy_version=0.74.0
syft_version=1.32.0
for tool in trivy syft; do
  if [[ "$tool" == trivy ]]; then
    version="$trivy_version"
    repository=aquasecurity/trivy
    archive="trivy_${version}_Linux-64bit.tar.gz"
    checksums="trivy_${version}_checksums.txt"
  else
    version="$syft_version"
    repository=anchore/syft
    archive="syft_${version}_linux_amd64.tar.gz"
    checksums="syft_${version}_checksums.txt"
  fi
  base="https://github.com/$repository/releases/download/v$version"
  curl --fail --silent --show-error --location "$base/$archive" -o "$archive"
  curl --fail --silent --show-error --location "$base/$checksums" -o "$checksums"
  awk -v archive="$archive" '$2 == archive {print}' "$checksums" > selected.sha256
  test "$(wc -l < selected.sha256)" -eq 1
  sha256sum --check selected.sha256
  tar -xzf "$archive" "$tool"
  install -m 0755 "$tool" "$bin_directory/$tool"
done
printf '%s\n' "$bin_directory" >> "${GITHUB_PATH:?}"
