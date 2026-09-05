"""Root-owned activation check for the pre-provisioned QMT release host-agent.

This command is reached only through the fixed SSH forced-command identity. It
does not accept a host, executable, path or credential from the caller and does
not issue or rotate certificates. Existing QDev CA material is verified in
place before the already registered service is enabled.
"""

from __future__ import annotations

import hashlib
import json
import os
import ssl
import stat
import subprocess
import sys
import urllib.error
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID

from .fleet_bootstrap_operation_executor import RESULT_SCHEMA
from .host_agent_enrolment_adapter import QMT_TARGET
from .host_enrolment_challenge import HostEnrolmentChallenge

CONFIG = Path("/etc/qdev-release-agents/qmt.env")
SERVICE = "qdev-release-qmt.service"
EXPECTED_IDENTITY = "qdev-host-agent:srv138jump"
SYSTEMCTL = Path("/usr/bin/systemctl")


class QmtHostEnrolmentError(RuntimeError):
    """The fixed QMT agent is not safely provisioned."""


def _challenge_nonce(
    *,
    controller_revision: str,
    operation_fence: str,
    certificate_fingerprint_sha256: str,
) -> str:
    """Derive a retry-stable nonce for one immutable enrolment operation."""

    return hashlib.sha256(
        (
            "qdev-host-enrolment-v1\x00"
            f"qdev-release-qmt\x00{QMT_TARGET['project_id']}\x00"
            f"{QMT_TARGET['placement']}\x00{controller_revision}\x00"
            f"{operation_fence}\x00{certificate_fingerprint_sha256}"
        ).encode()
    ).hexdigest()


def _private_file(path: Path) -> bytes:
    if not path.is_absolute() or path.is_symlink():
        raise QmtHostEnrolmentError("QMT enrolment file path is unsafe")
    try:
        metadata = path.stat()
        data = path.read_bytes()
    except OSError as error:
        raise QmtHostEnrolmentError("QMT enrolment file is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or stat.S_IMODE(metadata.st_mode) & 0o077
        or not data
    ):
        raise QmtHostEnrolmentError("QMT enrolment file is unsafe")
    return data


def _config() -> dict[str, str | Path]:
    values: dict[str, str] = {}
    for line in _private_file(CONFIG).decode("utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or not value:
            raise QmtHostEnrolmentError("QMT agent config is invalid")
        values[key] = value
    required = {
        "QDEV_RELEASE_CONTROLLER_URL",
        "QDEV_RELEASE_AGENT_CERT",
        "QDEV_RELEASE_AGENT_KEY",
        "QDEV_RELEASE_CONTROLLER_CA",
        "QDEV_RELEASE_STATE_PATH",
        "QDEV_RELEASE_LOCK_PATH",
    }
    if (
        set(values) != required
        or values["QDEV_RELEASE_CONTROLLER_URL"] != "https://worker.ci.qdev.run"
    ):
        raise QmtHostEnrolmentError("QMT agent config is not fixed")
    return {
        "controller_url": values["QDEV_RELEASE_CONTROLLER_URL"],
        "certificate": Path(values["QDEV_RELEASE_AGENT_CERT"]),
        "key": Path(values["QDEV_RELEASE_AGENT_KEY"]),
        "ca": Path(values["QDEV_RELEASE_CONTROLLER_CA"]),
    }


def _verify_certificate(paths: dict[str, str | Path]) -> str:
    raw_certificate_path = paths["certificate"]
    raw_key_path = paths["key"]
    raw_ca_path = paths["ca"]
    if not (
        isinstance(raw_certificate_path, Path)
        and isinstance(raw_key_path, Path)
        and isinstance(raw_ca_path, Path)
    ):
        raise QmtHostEnrolmentError("QMT agent certificate paths are invalid")
    certificate_path = raw_certificate_path
    key_path = raw_key_path
    ca_path = raw_ca_path
    certificate_bytes = _private_file(certificate_path)
    key_bytes = _private_file(key_path)
    ca_bytes = _private_file(ca_path)
    try:
        certificate = x509.load_pem_x509_certificate(certificate_bytes)
        authority = x509.load_pem_x509_certificate(ca_bytes)
        private_key = serialization.load_pem_private_key(key_bytes, password=None)
        names = certificate.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.UniformResourceIdentifier)
        leaf_constraints = certificate.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        authority_constraints = authority.extensions.get_extension_for_class(
            x509.BasicConstraints
        ).value
        leaf_usage = certificate.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    except (ValueError, x509.ExtensionNotFound) as error:
        raise QmtHostEnrolmentError("QMT agent certificate is invalid") from error
    now = datetime.now(UTC)
    if (
        certificate.not_valid_before_utc > now
        or certificate.not_valid_after_utc <= now
        or authority.not_valid_before_utc > now
        or authority.not_valid_after_utc <= now
    ):
        raise QmtHostEnrolmentError("QMT agent certificate is not current")
    if (
        names != [EXPECTED_IDENTITY]
        or leaf_constraints.ca
        or not authority_constraints.ca
        or ExtendedKeyUsageOID.CLIENT_AUTH not in leaf_usage
        or ExtendedKeyUsageOID.SERVER_AUTH in leaf_usage
        or certificate.issuer != authority.subject
    ):
        raise QmtHostEnrolmentError("QMT agent certificate identity is invalid")
    certificate_public = certificate.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    private_public = private_key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    if certificate_public != private_public:
        raise QmtHostEnrolmentError("QMT agent key does not match certificate")
    public_key = authority.public_key()
    signature_hash_algorithm = certificate.signature_hash_algorithm
    if signature_hash_algorithm is None:
        raise QmtHostEnrolmentError("QMT agent certificate signature is unsupported")
    try:
        if isinstance(public_key, rsa.RSAPublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                padding.PKCS1v15(),
                signature_hash_algorithm,
            )
        elif isinstance(public_key, ec.EllipticCurvePublicKey):
            public_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,
                ec.ECDSA(signature_hash_algorithm),
            )
        else:
            raise QmtHostEnrolmentError("QMT CA key type is unsupported")
    except (InvalidSignature, ValueError) as error:
        raise QmtHostEnrolmentError("QMT agent certificate is not signed by QDev CA") from error
    return hashlib.sha256(certificate.public_bytes(serialization.Encoding.DER)).hexdigest()


def _controller_challenge(
    config: dict[str, str | Path],
    *,
    controller_revision: str,
    operation_fence: str,
    certificate_fingerprint_sha256: str,
) -> dict[str, Any]:
    controller_url = config.get("controller_url")
    certificate = config.get("certificate")
    key = config.get("key")
    authority = config.get("ca")
    if (
        controller_url != "https://worker.ci.qdev.run"
        or not isinstance(certificate, Path)
        or not isinstance(key, Path)
        or not isinstance(authority, Path)
    ):
        raise QmtHostEnrolmentError("QMT controller challenge config is invalid")
    challenge = HostEnrolmentChallenge.model_validate(
        {
            "schema": "qdev-host-enrolment-challenge-v1",
            "release_lane": "qdev-release-qmt",
            "project_id": QMT_TARGET["project_id"],
            "placement": QMT_TARGET["placement"],
            "controller_revision": controller_revision,
            "operation_fence": operation_fence,
            "certificate_fingerprint_sha256": certificate_fingerprint_sha256,
            # A retry after a lost HTTP response must reproduce the exact
            # challenge for this immutable operation.  The fence is already
            # controller-generated and unique; binding every other identity
            # field makes the nonce deterministic without weakening replay
            # protection across operations.
            "nonce": _challenge_nonce(
                controller_revision=controller_revision,
                operation_fence=operation_fence,
                certificate_fingerprint_sha256=certificate_fingerprint_sha256,
            ),
        }
    )
    context = ssl.create_default_context(cafile=str(authority))
    context.load_cert_chain(certfile=str(certificate), keyfile=str(key))
    url = (
        f"{controller_url}/internal/v1/release-hosts/{QMT_TARGET['placement']}/enrolment-challenge"
    )
    request = urllib.request.Request(  # noqa: S310 - exact HTTPS controller URL
        url,
        data=json.dumps(
            challenge.model_dump(mode="json", by_alias=True),
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, context=context, timeout=15) as response:  # noqa: S310
            if response.status != 200:
                raise QmtHostEnrolmentError("QMT controller challenge was rejected")
            payload = response.read(65537)
    except (OSError, ssl.SSLError, urllib.error.URLError) as error:
        raise QmtHostEnrolmentError("QMT controller challenge failed") from error
    if len(payload) > 65536:
        raise QmtHostEnrolmentError("QMT controller challenge response is too large")
    try:
        acknowledgement = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QmtHostEnrolmentError("QMT controller challenge response is invalid") from error
    if not isinstance(acknowledgement, dict):
        raise QmtHostEnrolmentError("QMT controller challenge response is invalid")
    return acknowledgement


def _validate_request(envelope: dict[str, Any]) -> tuple[str, str]:
    if set(envelope) != {"schema", "operation", "request", "target", "active_jobs"}:
        raise QmtHostEnrolmentError("QMT enrolment request shape is invalid")
    request = envelope.get("request")
    operation = envelope.get("operation")
    if (
        envelope.get("schema") != "qdev-fleet-bootstrap-adapter-request-v1"
        or not isinstance(request, dict)
        or request.get("action") != "enrol-host-agent"
        or request.get("release_lane") != "qdev-release-qmt"
        or request.get("worker_name") is not None
        or envelope.get("target") != QMT_TARGET
        or envelope.get("active_jobs") is not None
        or not isinstance(operation, dict)
        or not isinstance(operation.get("payload"), dict)
        or not isinstance(request.get("controller_revision"), str)
        or len(request["controller_revision"]) != 40
    ):
        raise QmtHostEnrolmentError("QMT enrolment request is not allowlisted")
    fence = operation["payload"].get("fence")
    if not isinstance(fence, str) or not 24 <= len(fence) <= 128:
        raise QmtHostEnrolmentError("QMT enrolment fence is invalid")
    return fence, request["controller_revision"]


def enrol(envelope: dict[str, Any]) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise QmtHostEnrolmentError("QMT host enrolment requires root")
    fence, controller_revision = _validate_request(envelope)
    config = _config()
    fingerprint = _verify_certificate(config)
    for arguments in (
        [str(SYSTEMCTL), "enable", "--now", "qdev-release-qmt.timer"],
        [str(SYSTEMCTL), "start", SERVICE],
        [str(SYSTEMCTL), "show", "--property=Result", "--value", SERVICE],
    ):
        completed = subprocess.run(arguments, capture_output=True, check=False)  # noqa: S603
        if completed.returncode != 0 or (
            arguments[1] == "show" and completed.stdout.strip() != b"success"
        ):
            raise QmtHostEnrolmentError("QMT release host-agent is not active")
    acknowledgement = _controller_challenge(
        config,
        controller_revision=controller_revision,
        operation_fence=fence,
        certificate_fingerprint_sha256=fingerprint,
    )
    return {
        "schema": RESULT_SCHEMA,
        "status": "completed",
        "action": "enrol-host-agent",
        "target_id": QMT_TARGET["target_id"],
        "result": {
            "release_lane": "qdev-release-qmt",
            "host_agent_identity": EXPECTED_IDENTITY,
            "certificate_fingerprint_sha256": fingerprint,
            "service_status": "active",
            "enrolment_ack": acknowledgement,
        },
        "operation_fence": fence,
    }


def main() -> int:
    try:
        value = json.load(sys.stdin)
        if not isinstance(value, dict):
            raise QmtHostEnrolmentError("QMT enrolment request is not an object")
        result = enrol(value)
    except (QmtHostEnrolmentError, UnicodeError, json.JSONDecodeError):
        return 1
    print(json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
