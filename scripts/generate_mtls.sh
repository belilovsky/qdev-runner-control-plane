#!/usr/bin/env bash
set -euo pipefail

target="${1:-/etc/qdev-runner/mtls/controller}"
controller_ip="${QDEV_CONTROLLER_IP:-186.240.148.129}"
install -d -m 0700 "$target"

if [[ ! -f "$target/ca-key.pem" ]]; then
  openssl genrsa -out "$target/ca-key.pem" 4096
  openssl req -x509 -new -sha256 -days 825 \
    -key "$target/ca-key.pem" -out "$target/ca.pem" \
    -subj '/CN=QDev runner internal CA'
fi

issue_certificate() {
  local name="$1"
  local extension="$2"
  openssl genrsa -out "$target/${name}-key.pem" 3072
  openssl req -new -sha256 -key "$target/${name}-key.pem" \
    -out "$target/${name}.csr" -subj "/CN=${name}"
  openssl x509 -req -sha256 -days 397 \
    -in "$target/${name}.csr" -CA "$target/ca.pem" -CAkey "$target/ca-key.pem" \
    -CAcreateserial -out "$target/${name}-cert.pem" -extfile <(printf '%s\n' "$extension")
  rm -- "$target/${name}.csr"
}

[[ -f "$target/controller-cert.pem" ]] || issue_certificate controller \
  "subjectAltName=DNS:worker.ci.qdev.run,IP:${controller_ip}"
[[ -f "$target/primary-cert.pem" ]] || issue_certificate primary \
  'extendedKeyUsage=clientAuth'
[[ -f "$target/reserve-cert.pem" ]] || issue_certificate reserve \
  'extendedKeyUsage=clientAuth'
chown root:9020 "$target"
chmod 0750 "$target"
chown root:root "$target/ca-key.pem"
chmod 0600 "$target/ca-key.pem"
chown root:9020 "$target/controller-key.pem"
chmod 0640 "$target/controller-key.pem"
chown root:root "$target"/primary-key.pem "$target"/reserve-key.pem
chmod 0600 "$target"/primary-key.pem "$target"/reserve-key.pem
chmod 0644 "$target"/*-cert.pem "$target/ca.pem"
openssl verify -CAfile "$target/ca.pem" \
  "$target/controller-cert.pem" "$target/primary-cert.pem" "$target/reserve-cert.pem"
