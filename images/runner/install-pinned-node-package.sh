#!/usr/bin/env bash
set -euo pipefail

node_modules_root=${1:?node_modules root is required}
package_name=${2:?package name is required}
package_version=${3:?package version is required}
package_sha512=${4:?package sha512 is required}
archive=/tmp/${package_name}-${package_version}.tgz
package_root=${node_modules_root}/${package_name}

case "${package_name}" in
  brace-expansion|ip-address|tar) ;;
  *)
    echo "unsupported pinned package: ${package_name}" >&2
    exit 2
    ;;
esac

curl --fail --location --retry 5 \
  "https://registry.npmjs.org/${package_name}/-/${package_name}-${package_version}.tgz" \
  --output "${archive}"
echo "${package_sha512}  ${archive}" | sha512sum --check -
rm -rf "${package_root}"
mkdir -p "${package_root}"
tar -xzf "${archive}" -C "${package_root}" --strip-components=1
rm "${archive}"

actual_name=$(node -p "require('${package_root}/package.json').name")
actual_version=$(node -p "require('${package_root}/package.json').version")
test "${actual_name}" = "${package_name}"
test "${actual_version}" = "${package_version}"
