#!/usr/bin/env bash
set -euo pipefail

# Sign a public CSR for one short-lived, certificate-bound recovery worker.
# The private key is created on the worker and never copied to this host.
if [[ "${EUID}" -ne 0 ]]; then
  printf 'run as root\n' >&2
  exit 1
fi
if [[ "$#" -ne 3 ]]; then
  printf 'usage: %s WORKER_NAME CSR_PATH CERT_PATH\n' "$0" >&2
  exit 64
fi

worker_name="$1"
csr_path="$(realpath -e -- "$2")"
cert_path="$3"
ca_dir="${QDEV_MTLS_CA_DIR:-/etc/qdev-runner/mtls/controller}"
scope_dir="$ca_dir/scoped"

if [[ ! "$worker_name" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{2,63}-(primary|reserve)$ ]]; then
  printf 'worker name is unsafe or has no primary/reserve tier suffix\n' >&2
  exit 64
fi
if [[ ! -f "$csr_path" || -L "$csr_path" ]]; then
  printf 'CSR must be a regular, non-symlink file\n' >&2
  exit 66
fi
for required in "$ca_dir/ca.pem" "$ca_dir/ca-key.pem"; do
  [[ -f "$required" && ! -L "$required" ]] || {
    printf 'controller CA material is unavailable\n' >&2
    exit 66
  }
done
if [[ ! -r "$ca_dir/ca-key.pem" ]]; then
  printf 'controller CA key is not readable by root\n' >&2
  exit 66
fi

install -d -o root -g root -m 0700 "$scope_dir"
cert_dir="$(dirname -- "$cert_path")"
case "$cert_path" in
  "$scope_dir"/*-cert.pem) ;;
  *)
    printf 'certificate path must be below %s and end in -cert.pem\n' "$scope_dir" >&2
    exit 64
    ;;
esac
[[ "$cert_dir" == "$scope_dir" ]] || {
  printf 'certificate path must be directly below %s\n' "$scope_dir" >&2
  exit 64
}
[[ ! -e "$cert_path" && ! -L "$cert_path" ]] || {
  printf 'refusing to overwrite an existing certificate\n' >&2
  exit 73
}

subject="$(openssl req -in "$csr_path" -noout -subject -nameopt RFC2253)"
if [[ "$subject" != "subject=CN=$worker_name" ]]; then
  printf 'CSR subject must be exactly CN=%s\n' "$worker_name" >&2
  exit 64
fi

exec 9>"$scope_dir/.issue.lock"
flock -x 9
extension_file="$(mktemp "$scope_dir/.${worker_name}.XXXXXX.ext")"
temporary_cert="$(mktemp "$scope_dir/.${worker_name}.XXXXXX.pem")"
cleanup() {
  rm -f -- "$extension_file" "$temporary_cert"
}
trap cleanup EXIT
printf '%s\n' \
  'basicConstraints=critical,CA:FALSE' \
  'keyUsage=critical,digitalSignature' \
  'extendedKeyUsage=critical,clientAuth' \
  'subjectKeyIdentifier=hash' \
  'authorityKeyIdentifier=keyid,issuer' >"$extension_file"

openssl x509 -req -sha256 -days 1 \
  -in "$csr_path" -CA "$ca_dir/ca.pem" -CAkey "$ca_dir/ca-key.pem" \
  -CAserial "$scope_dir/ca.srl" -CAcreateserial \
  -out "$temporary_cert" -extfile "$extension_file"
openssl verify -purpose sslclient -CAfile "$ca_dir/ca.pem" "$temporary_cert" >/dev/null
openssl x509 -in "$temporary_cert" -noout -text | \
  grep -A 1 'Extended Key Usage' | grep -F 'TLS Web Client Authentication' >/dev/null
install -o root -g root -m 0644 -- "$temporary_cert" "$cert_path"
fingerprint="$(openssl x509 -in "$cert_path" -outform DER | sha256sum | awk '{print $1}')"
printf 'certificate_sha256=%s\n' "$fingerprint"
