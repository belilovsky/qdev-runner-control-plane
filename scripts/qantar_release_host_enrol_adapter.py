#!/usr/bin/python3
"""Enroll the fixed Qantar production host through the QDev Fleet bootstrap."""

from __future__ import annotations

import base64
import fcntl
import hashlib
import io
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path
from typing import Any

ACTIVE = Path("/opt/qdev-runner-control-plane/current")
STATUS = Path("/var/lib/qdev-runner/controller-status/controller-release.json")
IDENTITY_ROOT = Path("/etc/qdev-runner/worker-recovery-dispatch")
IDENTITY = IDENTITY_ROOT / "id_ed25519"
KNOWN_HOSTS = IDENTITY_ROOT / "known_hosts"
DISPATCH_SECRET = Path(
    "/etc/qdev-runner/host-dispatch-secrets/qdev-host-agent-qantar-production-controller.secret"
)
DISPATCH_SECRET_ROOT = Path("/etc/qdev-runner/host-dispatch-secrets")
DISPATCH_SECRET_MAP = Path("/etc/qdev-runner/release-host-dispatch-keys.json")
CONTROLLER_CA_ROOT = Path("/etc/qdev-runner/mtls/controller")
SCOPED_CA_ROOT = CONTROLLER_CA_ROOT / "scoped"
CA = CONTROLLER_CA_ROOT / "ca.pem"
CA_KEY = CONTROLLER_CA_ROOT / "ca-key.pem"
SSH = Path("/usr/bin/ssh")
SCP = Path("/usr/bin/scp")
TARGET_HOST = "186.240.148.129"
TARGET_LANE = "qdev-release-qantar"
TARGET_PROJECT = "qantar"
TARGET_PLACEMENT = "qantar-production-controller"
TARGET_IDENTITY = "qdev-host-agent:qantar-production-controller"
TARGET_ADAPTER = "qantar-transactional-release-v1"
TARGET_ROLLBACK = (
    "scripts/deploy.sh automatic recovery and scripts/rollback.sh retained-release activation"
)
REMOTE_ROOT = "/var/lib/qdev-release-agents/enrol/qantar"
REMOTE_HELPER = Path("scripts/qantar_release_host_enrol_apply.py")
CHILD_SCHEMA = "qdev-fleet-bootstrap-adapter-result-v1"
REMOTE_SCHEMA = "qantar-release-host-enrol-apply-result-v1"
BUNDLE_SCHEMA = "qantar-release-host-enrol-bundle-v1"
SHA = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
HEX = re.compile(r"^[0-9a-f]{64}$")
CSR_LIMIT = 65536
ACCESS_ERRORS = {
    "controller_ca_material_unavailable",
    "controller_ssh_identity_unavailable",
    "controller_ssh_host_trust_unavailable",
    "fixed_host_access_unavailable",
}
FILE_SOURCES = {
    "agent.py": Path("scripts/qdev_admin_platform_release_host_agent.py"),
    "native-adapter.py": Path("scripts/qantar_native_release_adapter.py"),
    "service.unit": Path("deploy/qdev-release-qantar.service"),
    "timer.unit": Path("deploy/qdev-release-qantar.timer"),
}


class EnrolError(RuntimeError):
    """A fixed host enrollment operation failed without exposing secrets."""


def _root_regular(path: Path, *, private: bool) -> bytes:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        if path in {IDENTITY, KNOWN_HOSTS}:
            code = "controller_ssh_identity_unavailable"
        elif path in {CA, CA_KEY}:
            code = "controller_ca_material_unavailable"
        else:
            code = "controller_file_unavailable"
        raise EnrolError(code) from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_uid != 0
            or (private and stat.S_IMODE(metadata.st_mode) & 0o077)
            or (not private and stat.S_IMODE(metadata.st_mode) & 0o022)
        ):
            code = (
                "controller_ssh_identity_unavailable"
                if path in {IDENTITY, KNOWN_HOSTS}
                else "controller_file_permissions_invalid"
            )
            raise EnrolError(code)
        with os.fdopen(descriptor, "rb") as source:
            descriptor = -1
            return source.read()
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _active_release(revision: str, release_digest: str) -> Path:
    try:
        link = ACTIVE.lstat()
        root = ACTIVE.resolve(strict=True)
        releases = (ACTIVE.parent / "releases").resolve(strict=True)
        status = json.loads(STATUS.read_text(encoding="utf-8"))
        status_info = STATUS.lstat()
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EnrolError("active_controller_release_unavailable") from error
    if (
        not stat.S_ISLNK(link.st_mode)
        or link.st_uid != 0
        or root.parent != releases
        or root.name != revision
        or not SHA.fullmatch(root.name)
        or not stat.S_ISREG(status_info.st_mode)
        or stat.S_ISLNK(status_info.st_mode)
        or status_info.st_uid != 0
        or stat.S_IMODE(status_info.st_mode) & 0o022
        or not isinstance(status, dict)
        or status.get("schema") != "qdev-controller-release-status-v2"
        or status.get("state") != "active"
        or status.get("revision") != revision
        or status.get("release_digest") != release_digest
        or not DIGEST.fullmatch(release_digest)
    ):
        raise EnrolError("active_controller_release_identity_mismatch")
    return root


def _dispatch_secret_path() -> Path:
    if not DISPATCH_SECRET_MAP.exists() and not DISPATCH_SECRET_MAP.is_symlink():
        return DISPATCH_SECRET
    try:
        value = json.loads(_root_regular(DISPATCH_SECRET_MAP, private=True))
    except json.JSONDecodeError as error:
        raise EnrolError("controller_dispatch_secret_unavailable") from error
    if not isinstance(value, dict) or any(
        not isinstance(identity, str) or not isinstance(path, str)
        for identity, path in value.items()
    ):
        raise EnrolError("controller_dispatch_secret_unavailable")
    selected = value.get(TARGET_IDENTITY)
    if not isinstance(selected, str):
        raise EnrolError("controller_dispatch_secret_unavailable")
    path = Path(selected)
    if not path.is_absolute() or path.parent != DISPATCH_SECRET_ROOT:
        raise EnrolError("controller_dispatch_secret_unavailable")
    return path


def _parse() -> tuple[dict[str, Any], dict[str, str], dict[str, str], dict[str, Any]]:
    payload = sys.stdin.buffer.read(65537)
    if not payload or len(payload) > 65536:
        raise EnrolError("request_size_invalid")
    try:
        envelope = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EnrolError("request_json_invalid") from error
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"schema", "request", "target"}
        or envelope.get("schema") != "qdev-fleet-bootstrap-adapter-request-v1"
    ):
        raise EnrolError("request_envelope_invalid")
    request = envelope.get("request")
    target = envelope.get("target")
    expected_request_fields = {
        "schema",
        "action",
        "source_sha",
        "run_id",
        "job_id",
        "attempt",
        "claim_ttl_seconds",
        "controller_revision",
        "controller_release_digest",
        "release_lane",
        "worker_name",
        "controller_rollback",
    }
    expected_target = {
        "release_lane": TARGET_LANE,
        "project_id": TARGET_PROJECT,
        "placement": TARGET_PLACEMENT,
        "host_agent_mtls_identity": TARGET_IDENTITY,
        "native_host_adapter": TARGET_ADAPTER,
        "rollback_reference": TARGET_ROLLBACK,
    }
    if (
        not isinstance(request, dict)
        or set(request) != expected_request_fields
        or not isinstance(target, dict)
        or target != expected_target
        or request.get("schema") != "qdev-fleet-bootstrap-request-v1"
        or request.get("action") != "enrol-host-agent"
        or request.get("release_lane") != TARGET_LANE
        or request.get("worker_name") is not None
        or request.get("source_sha") != request.get("controller_revision")
        or not isinstance(request.get("controller_revision"), str)
        or not SHA.fullmatch(request["controller_revision"])
        or not isinstance(request.get("controller_release_digest"), str)
        or not DIGEST.fullmatch(request["controller_release_digest"])
        or any(
            isinstance(request.get(name), bool)
            or not isinstance(request.get(name), int)
            or request[name] < 1
            for name in ("run_id", "job_id", "attempt", "claim_ttl_seconds")
        )
    ):
        raise EnrolError("request_identity_invalid")
    rollback = request.get("controller_rollback")
    if (
        not isinstance(rollback, dict)
        or set(rollback)
        != {
            "source_sha",
            "artifact_digest",
            "internal_artifact_digest",
            "policy_digest",
            "generation",
        }
        or not isinstance(rollback.get("source_sha"), str)
        or not SHA.fullmatch(rollback["source_sha"])
        or not isinstance(rollback.get("artifact_digest"), str)
        or not DIGEST.fullmatch(rollback["artifact_digest"])
        or not isinstance(rollback.get("internal_artifact_digest"), str)
        or not DIGEST.fullmatch(rollback["internal_artifact_digest"])
        or not isinstance(rollback.get("policy_digest"), str)
        or not DIGEST.fullmatch(rollback["policy_digest"])
        or isinstance(rollback.get("generation"), bool)
        or not isinstance(rollback.get("generation"), int)
        or rollback["generation"] < 0
    ):
        raise EnrolError("controller_rollback_identity_invalid")
    return envelope, dict(request), dict(target), dict(rollback)


def _ssh_base() -> list[str]:
    return [
        str(SSH),
        "-F",
        "/dev/null",
        "-i",
        str(IDENTITY),
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        f"UserKnownHostsFile={KNOWN_HOSTS}",
        "-o",
        "ConnectTimeout=15",
        f"root@{TARGET_HOST}",
    ]


def _fixed_env() -> dict[str, str]:
    return {"PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "LC_ALL": "C"}


def _run(command: list[str], *, input_bytes: bytes | None = None, timeout: int = 300) -> bytes:
    try:
        result = subprocess.run(
            command,
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=timeout,
            env=_fixed_env(),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise EnrolError("fixed_host_access_unavailable") from error
    if result.returncode != 0:
        if result.returncode == 255:
            raise EnrolError("fixed_host_access_unavailable")
        raise EnrolError("fixed_host_enrolment_failed")
    return result.stdout


def _remote_result(raw: bytes) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise EnrolError("remote_enrolment_response_invalid") from error
    if (
        not isinstance(value, dict)
        or set(value) != {"schema", "status", "result"}
        or value.get("schema") != REMOTE_SCHEMA
        or value.get("status") != "completed"
        or not isinstance(value.get("result"), dict)
    ):
        raise EnrolError("remote_enrolment_response_invalid")
    return value["result"]


def _target_phase(
    helper: Path,
    helper_digest: str,
    revision: str,
    release_digest: str,
    phase: str,
    *,
    bundle: bytes | None = None,
) -> dict[str, Any]:
    remote_helper = f"{REMOTE_ROOT}/apply-{helper_digest}.py"
    command = [
        *(_ssh_base()),
        "/usr/bin/python3",
        "-I",
        remote_helper,
        "--phase",
        phase,
        "--self-sha256",
        helper_digest,
        "--controller-revision",
        revision,
        "--controller-release-digest",
        release_digest,
    ]
    return _remote_result(_run(command, input_bytes=bundle, timeout=900))


def _sign_csr(csr_bytes: bytes) -> bytes:
    if (
        not csr_bytes
        or len(csr_bytes) > CSR_LIMIT
        or b"-----BEGIN CERTIFICATE REQUEST-----" not in csr_bytes
        or b"-----END CERTIFICATE REQUEST-----" not in csr_bytes
    ):
        raise EnrolError("host_csr_invalid")
    ca_bytes = _root_regular(CA, private=False)
    _root_regular(CA_KEY, private=True)
    if not SCOPED_CA_ROOT.exists():
        try:
            SCOPED_CA_ROOT.mkdir(mode=0o700)
            os.chown(SCOPED_CA_ROOT, 0, 0)
        except FileExistsError:
            pass
    info = SCOPED_CA_ROOT.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or stat.S_ISLNK(info.st_mode)
        or info.st_uid != 0
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise EnrolError("controller_ca_material_unavailable")
    with tempfile.TemporaryDirectory(prefix="qantar-host-enrol-", dir=SCOPED_CA_ROOT) as name:
        work = Path(name)
        csr = work / "host.csr"
        certificate = work / "host-cert.pem"
        extensions = work / "host.ext"
        csr.write_bytes(csr_bytes)
        ca_copy = work / "ca.pem"
        ca_copy.write_bytes(ca_bytes)
        csr.chmod(0o600)
        ca_copy.chmod(0o600)
        subject = (
            _run(
                [
                    "/usr/bin/openssl",
                    "req",
                    "-in",
                    str(csr),
                    "-noout",
                    "-subject",
                    "-nameopt",
                    "RFC2253",
                ]
            )
            .decode("ascii", "strict")
            .strip()
        )
        if subject != f"subject=CN={TARGET_IDENTITY}":
            raise EnrolError("host_csr_identity_invalid")
        extensions.write_text(
            "\n".join(
                (
                    "basicConstraints=critical,CA:FALSE",
                    "keyUsage=critical,digitalSignature",
                    "extendedKeyUsage=critical,clientAuth",
                    "subjectKeyIdentifier=hash",
                    "authorityKeyIdentifier=keyid,issuer",
                )
            )
            + "\n",
            encoding="ascii",
        )
        lock_path = SCOPED_CA_ROOT / ".issue.lock"
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchown(descriptor, 0, 0)
            os.fchmod(descriptor, 0o600)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            _run(
                [
                    "/usr/bin/openssl",
                    "x509",
                    "-req",
                    "-sha256",
                    "-days",
                    "397",
                    "-in",
                    str(csr),
                    "-CA",
                    str(CA),
                    "-CAkey",
                    str(CA_KEY),
                    "-CAserial",
                    str(SCOPED_CA_ROOT / "ca.srl"),
                    "-CAcreateserial",
                    "-out",
                    str(certificate),
                    "-extfile",
                    str(extensions),
                ]
            )
            _run(
                [
                    "/usr/bin/openssl",
                    "verify",
                    "-purpose",
                    "sslclient",
                    "-CAfile",
                    str(CA),
                    str(certificate),
                ]
            )
        finally:
            os.close(descriptor)
        return certificate.read_bytes()


def _load_controller_payload(release: Path) -> dict[str, bytes]:
    payloads: dict[str, bytes] = {}
    for name, relative in FILE_SOURCES.items():
        path = release / relative
        data = _root_regular(path, private=False)
        if not data:
            raise EnrolError("controller_release_payload_invalid")
        payloads[name] = data
    helper = release / REMOTE_HELPER
    payloads["remote-helper.py"] = _root_regular(helper, private=False)
    return payloads


def _config_bytes() -> bytes:
    values = {
        "QDEV_RELEASE_CONTROLLER_URL": "https://worker.ci.qdev.run",
        "QDEV_RELEASE_AGENT_CERT": "/etc/qdev-release-agents/mtls/agent-cert.pem",
        "QDEV_RELEASE_AGENT_KEY": "/etc/qdev-release-agents/mtls/agent-key.pem",
        "QDEV_RELEASE_CONTROLLER_CA": "/etc/qdev-release-agents/mtls/ca.pem",
        "QDEV_RELEASE_HOST_IDENTITY": TARGET_IDENTITY,
        "QDEV_RELEASE_DISPATCH_SECRET_FILE": "/etc/qdev-release-agents/dispatch.secret",
    }
    return "".join(f"{key}={value}\n" for key, value in values.items()).encode("ascii")


def _bundle(
    payloads: dict[str, bytes],
    *,
    revision: str,
    release_digest: str,
    certificate: bytes,
    ca: bytes,
    dispatch_secret: bytes,
) -> bytes:
    files = {
        **{name: payload for name, payload in payloads.items() if name != "remote-helper.py"},
        "admin-platform.env": _config_bytes(),
        "agent-cert.pem": certificate,
        "ca.pem": ca,
        "dispatch.secret": dispatch_secret,
    }
    manifest = {
        "schema": BUNDLE_SCHEMA,
        "controller_revision": revision,
        "controller_release_digest": release_digest,
        "host_identity": TARGET_IDENTITY,
        "files": {
            name: f"sha256:{hashlib.sha256(value).hexdigest()}"
            for name, value in sorted(files.items())
        },
    }
    files["manifest.json"] = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode(
        "ascii"
    )
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as archive:
        for name, content in sorted(files.items()):
            info = tarfile.TarInfo(name)
            info.size = len(content)
            info.mode = 0o600
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.mtime = 0
            archive.addfile(info, io.BytesIO(content))
    return output.getvalue()


def _response(
    request: dict[str, Any],
    target: dict[str, Any],
    rollback: dict[str, Any],
    *,
    status: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    return {
        "schema": CHILD_SCHEMA,
        "status": status,
        "action": "enrol-host-agent",
        "controller_revision": request["controller_revision"],
        "controller_release_digest": request["controller_release_digest"],
        "release_lane": target["release_lane"],
        "host_agent_mtls_identity": target["host_agent_mtls_identity"],
        "rollback_source_sha": rollback["source_sha"],
        "rollback_artifact_digest": rollback["artifact_digest"],
        "result": result,
    }


def _safe_result(value: object) -> bool:
    return isinstance(value, dict) and all(
        isinstance(key, str)
        and not any(part in key.lower() for part in ("token", "password", "secret", "key"))
        and not isinstance(item, (dict, list))
        for key, item in value.items()
    )


def _enrol(request: dict[str, Any], target: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    revision = request["controller_revision"]
    release_digest = request["controller_release_digest"]
    release = _active_release(revision, release_digest)
    identity_bytes = _root_regular(IDENTITY, private=True)
    known_hosts_bytes = _root_regular(KNOWN_HOSTS, private=True)
    if not identity_bytes or not known_hosts_bytes:
        raise EnrolError("controller_ssh_host_trust_unavailable")
    ca = _root_regular(CA, private=False)
    _root_regular(CA_KEY, private=True)
    dispatch_secret = _root_regular(_dispatch_secret_path(), private=True).strip()
    if not 32 <= len(dispatch_secret) <= 4096:
        raise EnrolError("controller_dispatch_secret_unavailable")
    payloads = _load_controller_payload(release)
    helper = release / REMOTE_HELPER
    helper_digest = hashlib.sha256(payloads["remote-helper.py"]).hexdigest()
    remote_directory = f"{REMOTE_ROOT}"
    _run(
        _ssh_base()
        + ["/usr/bin/install", "-d", "-o", "root", "-g", "root", "-m", "0700", remote_directory]
    )
    remote_helper = f"{REMOTE_ROOT}/apply-{helper_digest}.py"
    _run(
        [
            str(SCP),
            "-F",
            "/dev/null",
            "-i",
            str(IDENTITY),
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "StrictHostKeyChecking=yes",
            "-o",
            f"UserKnownHostsFile={KNOWN_HOSTS}",
            "-q",
            str(helper),
            f"root@{TARGET_HOST}:{remote_helper}",
        ]
    )
    prepared = _target_phase(
        helper,
        helper_digest,
        revision,
        release_digest,
        "prepare",
    )
    if prepared.get("state") == "certificate_ready":
        try:
            certificate = base64.b64decode(prepared["certificate_b64"], validate=True)
        except (KeyError, ValueError) as error:
            raise EnrolError("host_certificate_response_invalid") from error
    elif prepared.get("state") == "csr_required":
        try:
            csr = base64.b64decode(prepared["csr_b64"], validate=True)
        except (KeyError, ValueError) as error:
            raise EnrolError("host_csr_response_invalid") from error
        certificate = _sign_csr(csr)
    else:
        raise EnrolError("host_certificate_response_invalid")
    bundle = _bundle(
        payloads,
        revision=revision,
        release_digest=release_digest,
        certificate=certificate,
        ca=ca,
        dispatch_secret=dispatch_secret,
    )
    result = _target_phase(
        helper,
        helper_digest,
        revision,
        release_digest,
        "install",
        bundle=bundle,
    )
    expected_fields = {
        "schema",
        "controller_revision",
        "controller_release_digest",
        "host_identity",
        "bootstrap_heartbeat",
        "timer_state",
        "certificate_fingerprint",
        "active_source_sha",
    }
    if (
        set(result) != expected_fields
        or result.get("schema") != "qdev-release-host-agent-enrolment-receipt-v1"
        or result.get("controller_revision") != revision
        or result.get("controller_release_digest") != release_digest
        or result.get("host_identity") != target["host_agent_mtls_identity"]
        or result.get("bootstrap_heartbeat") != "accepted"
        or result.get("timer_state") != "active"
        or not isinstance(result.get("certificate_fingerprint"), str)
        or not HEX.fullmatch(result["certificate_fingerprint"])
        or not isinstance(result.get("active_source_sha"), str)
        or not SHA.fullmatch(result["active_source_sha"])
    ):
        raise EnrolError("host_enrolment_receipt_invalid")
    return "completed", {
        "bootstrap_heartbeat": "accepted",
        "controller_revision": revision,
        "controller_release_digest": release_digest,
        "host_identity": target["host_agent_mtls_identity"],
        "active_source_sha": result["active_source_sha"],
        "certificate_fingerprint": result["certificate_fingerprint"],
        "timer_state": "active",
    }


def main() -> int:
    if os.geteuid() != 0:
        raise EnrolError("root_identity_required")
    _envelope, request, target, rollback = _parse()
    try:
        _status, result = _enrol(request, target)
        status = "completed"
    except EnrolError as error:
        status = "access_blocked" if str(error) in ACCESS_ERRORS else "failed"
        result = {"error_code": str(error)}
    if not _safe_result(result):
        raise EnrolError("host_enrolment_result_invalid")
    print(
        json.dumps(
            _response(request, target, rollback, status=status, result=result),
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (
        EnrolError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        subprocess.TimeoutExpired,
    ) as error:
        print(str(error), file=sys.stderr)
        raise SystemExit(1) from error
