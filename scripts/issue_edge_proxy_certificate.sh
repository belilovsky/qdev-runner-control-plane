#!/usr/bin/env bash
set -euo pipefail

# Issue the one-day mTLS client identity used only by the local qdev-edge
# reverse proxy when it reaches the controller's internal broker.  This is not
# a worker credential: workers keep their private keys on their own hosts.
if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi
if [[ "$#" -ne 0 ]]; then
  printf 'usage: %s\n' "$0" >&2
  exit 64
fi

ca_dir="${QDEV_MTLS_CA_DIR:-/etc/qdev-runner/mtls/controller}"
proxy_dir="${QDEV_EDGE_PROXY_MTLS_DIR:-/etc/qdev-runner/mtls/edge-proxy}"
certificate="$proxy_dir/edge-proxy-cert.pem"
private_key="$proxy_dir/edge-proxy-key.pem"

for required in "$ca_dir/ca.pem" "$ca_dir/ca-key.pem"; do
  [[ -f "$required" && ! -L "$required" ]] || {
    printf 'controller CA material is unavailable\n' >&2
    exit 66
  }
done
[[ -r "$ca_dir/ca-key.pem" ]] || {
  printf 'controller CA key is not readable by root\n' >&2
  exit 66
}

install -d -o root -g root -m 0700 "$proxy_dir"
for protected_path in "$certificate" "$private_key"; do
  [[ ! -e "$protected_path" && ! -L "$protected_path" ]] || {
    printf 'refusing to overwrite existing edge proxy credential material\n' >&2
    exit 73
  }
done

exec 9>"$proxy_dir/.issue.lock"
flock -x 9
temporary_key="$(mktemp "$proxy_dir/.edge-proxy.XXXXXX.key")"
temporary_csr="$(mktemp "$proxy_dir/.edge-proxy.XXXXXX.csr")"
temporary_certificate="$(mktemp "$proxy_dir/.edge-proxy.XXXXXX.pem")"
extension_file="$(mktemp "$proxy_dir/.edge-proxy.XXXXXX.ext")"
cleanup() {
  rm -f -- "$temporary_key" "$temporary_csr" "$temporary_certificate" "$extension_file"
}
trap cleanup EXIT

openssl genpkey -algorithm ED25519 -out "$temporary_key"
openssl req -new -key "$temporary_key" -subj '/CN=qdev-edge-proxy' -out "$temporary_csr"
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=critical,clientAuth' \
  'subjectKeyIdentifier=hash' \
  'authorityKeyIdentifier=keyid,issuer' >"$extension_file"

openssl x509 -req -sha256 -days 1 \
  -in "$temporary_csr" -CA "$ca_dir/ca.pem" -CAkey "$ca_dir/ca-key.pem" \
  -CAserial "$proxy_dir/ca.srl" -CAcreateserial \
  -out "$temporary_certificate" -extfile "$extension_file"
openssl verify -purpose sslclient -CAfile "$ca_dir/ca.pem" "$temporary_certificate" >/dev/null
openssl x509 -in "$temporary_certificate" -noout -text | \
  grep -A 1 'Extended Key Usage' | grep -F 'TLS Web Client Authentication' >/dev/null
install -o root -g root -m 0600 -- "$temporary_key" "$private_key"
install -o root -g root -m 0644 -- "$temporary_certificate" "$certificate"
fingerprint="$(openssl x509 -in "$certificate" -outform DER | sha256sum | awk '{print $1}')"
printf 'certificate_sha256=%s\n' "$fingerprint"
