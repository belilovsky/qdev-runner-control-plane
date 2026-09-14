#!/usr/bin/env bash

# Kept separate so the source-binding and filesystem invariants can be tested
# without starting a privileged worker installation. The caller supplies the
# pinned BuildKit values after loading its verified deployment configuration.
validate_buildkit_materialization() {
  local root="$1"
  local marker value mode owner
  [[ -d "$root" && ! -L "$root" ]] || return 1
  mode="$(stat -c '%a' "$root")"
  owner="$(stat -c '%u:%g' "$root")"
  [[ "$mode" == "755" && "$owner" == "0:0" ]] || return 1
  [[ -d "$root/bin" && ! -L "$root/bin" ]] || return 1
  mode="$(stat -c '%a' "$root/bin")"
  owner="$(stat -c '%u:%g' "$root/bin")"
  [[ "$mode" == "755" && "$owner" == "0:0" ]] || return 1
  for binary in buildkitd buildctl; do
    [[ -f "$root/bin/$binary" && ! -L "$root/bin/$binary" && -x "$root/bin/$binary" ]] || return 1
    mode="$(stat -c '%a' "$root/bin/$binary")"
    owner="$(stat -c '%u:%g' "$root/bin/$binary")"
    [[ "$mode" == "555" && "$owner" == "0:0" ]] || return 1
  done
  for marker in source-revision source-sha256; do
    [[ -f "$root/$marker" && ! -L "$root/$marker" ]] || return 1
    mode="$(stat -c '%a' "$root/$marker")"
    owner="$(stat -c '%u:%g' "$root/$marker")"
    [[ "$mode" == "444" && "$owner" == "0:0" ]] || return 1
  done
  value="$(tr -d '\r\n' < "$root/source-revision")"
  [[ "$value" == "$buildkit_source_revision" ]] || return 1
  value="$(tr -d '\r\n' < "$root/source-sha256")"
  [[ "$value" == "$buildkit_source_sha256" ]]
}
