#!/usr/bin/env bash
set -euo pipefail

node_root=${1:?node runtime root is required}
npm_version=${2:?npm version is required}
npm_sha512=${3:?npm sha512 is required}
archive=/tmp/npm-${npm_version}.tgz
npm_root=${node_root}/lib/node_modules/npm

curl --fail --location --retry 5 \
  "https://registry.npmjs.org/npm/-/npm-${npm_version}.tgz" \
  --output "${archive}"
echo "${npm_sha512}  ${archive}" | sha512sum --check -
rm -rf "${npm_root}"
mkdir -p "${npm_root}"
tar -xzf "${archive}" -C "${npm_root}" --strip-components=1
rm "${archive}"
ln -sfn ../lib/node_modules/npm/bin/npm-cli.js "${node_root}/bin/npm"
ln -sfn ../lib/node_modules/npm/bin/npx-cli.js "${node_root}/bin/npx"

actual_version=$(PATH="${node_root}/bin:${PATH}" npm --version)
test "${actual_version}" = "${npm_version}"
