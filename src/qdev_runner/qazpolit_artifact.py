"""Strict, side-effect-free validation for a QazPolit GitHub release artifact.

The controller must verify the release payload before it may mint delivery
coordinates for a host.  This module deliberately does not download, store,
or publish artifacts: it validates one already obtained ZIP byte stream and
returns deterministic evidence for the admission layer.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any


class QazPolitArtifactError(ValueError):
    """Raised when a release artifact is not safe or does not match its contract."""


_SHA256 = re.compile(r"[0-9a-f]{64}")
_GIT_SHA = re.compile(r"[0-9a-f]{40}")
_RELEASE_ID = re.compile(r"runner-[0-9]+-[0-9]+")
_WHEEL = re.compile(r"qazstack-([0-9]+(?:\.[0-9]+){1,3})-py3-none-any\.whl")
_IMAGE_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REQUIRED_MEMBERS = frozenset(
    {
        "images.oci.tar.zst",
        "provenance.json",
        "SHA256SUMS",
        "source-sha.txt",
        "sbom.cdx.json",
        "trivy.json",
        "trivy-postgres.json",
    }
)
_MAX_MEMBER_BYTES = 4 * 1024 * 1024 * 1024
_MAX_TOTAL_BYTES = 6 * 1024 * 1024 * 1024
_MAX_METADATA_BYTES = 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024


@dataclass(frozen=True)
class QazPolitArtifactEvidence:
    """Verified release facts, safe to bind into a later admission receipt."""

    archive_sha256: str
    payload_sha256: str
    source_sha: str
    release_id: str
    members: tuple[tuple[str, str, int], ...]
    provenance: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "schema": "qazpolit-release-artifact-evidence-v1",
            "archive_sha256": self.archive_sha256,
            "payload_sha256": self.payload_sha256,
            "source_sha": self.source_sha,
            "release_id": self.release_id,
            "members": [
                {"name": name, "sha256": digest, "size": size}
                for name, digest, size in self.members
            ],
            "provenance": self.provenance,
        }


def validate_qazpolit_release_archive(
    archive_bytes: bytes, *, expected_source_sha: str | None = None
) -> QazPolitArtifactEvidence:
    """Validate the exact QazPolit release ZIP produced by the CI workflow.

    ``archive_sha256`` binds the downloaded GitHub ZIP bytes.  The separate
    ``payload_sha256`` binds a canonical manifest of every verified inner
    member, so a host can detect a changed payload after extracting the ZIP.
    """

    if not archive_bytes:
        raise QazPolitArtifactError("release archive is empty")
    return _validate_archive(
        BytesIO(archive_bytes),
        archive_sha256=hashlib.sha256(archive_bytes).hexdigest(),
        expected_source_sha=expected_source_sha,
    )


def validate_qazpolit_release_archive_file(
    archive_path: Path, *, expected_source_sha: str | None = None
) -> QazPolitArtifactEvidence:
    """Validate a private archive file without loading its payload into memory."""

    try:
        metadata = archive_path.lstat()
    except OSError as error:
        raise QazPolitArtifactError("release archive file is unavailable") from error
    if stat.S_ISLNK(metadata.st_mode) or not stat.S_ISREG(metadata.st_mode):
        raise QazPolitArtifactError("release archive file must be a regular file")
    if metadata.st_size <= 0:
        raise QazPolitArtifactError("release archive is empty")

    digest = hashlib.sha256()
    try:
        with archive_path.open("rb") as stream:
            for chunk in iter(lambda: stream.read(_HASH_CHUNK_BYTES), b""):
                digest.update(chunk)
        with archive_path.open("rb") as stream:
            return _validate_archive(
                stream,
                archive_sha256=digest.hexdigest(),
                expected_source_sha=expected_source_sha,
            )
    except OSError as error:
        raise QazPolitArtifactError("release archive file cannot be read") from error


def _validate_archive(
    archive_stream: Any, *, archive_sha256: str, expected_source_sha: str | None
) -> QazPolitArtifactEvidence:
    if expected_source_sha is not None and _GIT_SHA.fullmatch(expected_source_sha) is None:
        raise QazPolitArtifactError("expected source SHA must be a lowercase 40-character commit")

    try:
        with zipfile.ZipFile(archive_stream) as archive:
            infos = archive.infolist()
            names = _validate_members(infos)
            infos_by_name = {info.filename: info for info in infos}
            checksums = _parse_checksums(_read_metadata(archive, infos_by_name["SHA256SUMS"]))
            member_digests = {
                name: _hash_member(archive, infos_by_name[name]) for name in names - {"SHA256SUMS"}
            }
            provenance = _parse_provenance(
                _read_metadata(archive, infos_by_name["provenance.json"])
            )
            source_sha_payload = _read_metadata(archive, infos_by_name["source-sha.txt"])
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile) as error:
        raise QazPolitArtifactError("release artifact is not a readable ZIP archive") from error

    expected_checksum_members = names - {"SHA256SUMS"}
    if set(checksums) != expected_checksum_members:
        raise QazPolitArtifactError("SHA256SUMS must cover every payload member and nothing else")

    members: list[tuple[str, str, int]] = []
    for name in sorted(expected_checksum_members):
        digest, size = member_digests[name]
        if checksums[name] != digest:
            raise QazPolitArtifactError(f"SHA256SUMS does not match {name}")
        members.append((name, digest, size))

    source_sha = _validate_provenance(
        provenance,
        names=names,
        member_digests=member_digests,
        source_sha_payload=source_sha_payload,
        expected_source_sha=expected_source_sha,
    )
    payload_descriptor = {
        "schema": "qazpolit-release-payload-v1",
        "source_sha": source_sha,
        "members": [
            {"name": name, "sha256": digest, "size": size} for name, digest, size in members
        ],
    }
    payload_sha256 = hashlib.sha256(
        json.dumps(payload_descriptor, separators=(",", ":"), sort_keys=True).encode("utf-8")
    ).hexdigest()
    return QazPolitArtifactEvidence(
        archive_sha256=archive_sha256,
        payload_sha256=payload_sha256,
        source_sha=source_sha,
        release_id=str(provenance["release_id"]),
        members=tuple(members),
        provenance=provenance,
    )


def _read_metadata(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> bytes:
    if info.file_size > _MAX_METADATA_BYTES:
        raise QazPolitArtifactError("release artifact metadata exceeds its safe size limit")
    return archive.read(info)


def _hash_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    with archive.open(info) as stream:
        for chunk in iter(lambda: stream.read(_HASH_CHUNK_BYTES), b""):
            digest.update(chunk)
            size += len(chunk)
    if size != info.file_size:
        raise QazPolitArtifactError("release artifact member size changed while being read")
    return digest.hexdigest(), size


def _validate_members(infos: list[zipfile.ZipInfo]) -> set[str]:
    if not infos:
        raise QazPolitArtifactError("release archive has no members")
    names: set[str] = set()
    total_bytes = 0
    for info in infos:
        name = info.filename
        if (
            not name
            or "/" in name
            or "\\" in name
            or "\x00" in name
            or name.startswith(".")
            or name in names
        ):
            raise QazPolitArtifactError("release archive has an unsafe or duplicate member name")
        kind = stat.S_IFMT(info.external_attr >> 16)
        if info.is_dir() or kind not in (0, stat.S_IFREG):
            raise QazPolitArtifactError("release archive may contain regular files only")
        if info.file_size < 0 or info.file_size > _MAX_MEMBER_BYTES:
            raise QazPolitArtifactError("release archive member exceeds its safe size limit")
        total_bytes += info.file_size
        if total_bytes > _MAX_TOTAL_BYTES:
            raise QazPolitArtifactError("release archive exceeds its safe extracted size limit")
        names.add(name)

    wheels = [name for name in names if _WHEEL.fullmatch(name)]
    if len(wheels) != 1 or names != _REQUIRED_MEMBERS | {wheels[0]}:
        raise QazPolitArtifactError(
            "release archive does not match the QazPolit artifact member contract"
        )
    return names


def _parse_checksums(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise QazPolitArtifactError("SHA256SUMS must be UTF-8 text") from error
    if not text.endswith("\n") or "\r" in text:
        raise QazPolitArtifactError("SHA256SUMS must use newline-terminated Unix records")

    checksums: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  \./([A-Za-z0-9._-]+)", line)
        if match is None or match.group(2) in checksums:
            raise QazPolitArtifactError("SHA256SUMS contains an invalid or duplicate record")
        checksums[match.group(2)] = match.group(1)
    if not checksums:
        raise QazPolitArtifactError("SHA256SUMS has no records")
    return checksums


def _parse_provenance(payload: bytes) -> dict[str, Any]:
    try:
        provenance = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise QazPolitArtifactError("provenance.json must be a JSON object") from error
    if not isinstance(provenance, dict):
        raise QazPolitArtifactError("provenance.json must contain an object")
    return provenance


def _validate_provenance(
    provenance: dict[str, Any],
    *,
    names: set[str],
    member_digests: dict[str, tuple[str, int]],
    source_sha_payload: bytes,
    expected_source_sha: str | None,
) -> str:
    required = {
        "schema",
        "source_sha",
        "release_id",
        "release_tier",
        "platform_admission",
        "platform_registry_override_reason",
        "image_ref",
        "image_digest",
        "postgres",
        "qazstack",
        "avds",
    }
    if set(provenance) != required:
        raise QazPolitArtifactError(
            "provenance.json keys do not match the QazPolit release contract"
        )
    source_sha = provenance["source_sha"]
    if not isinstance(source_sha, str) or _GIT_SHA.fullmatch(source_sha) is None:
        raise QazPolitArtifactError("provenance source SHA is invalid")
    if expected_source_sha is not None and source_sha != expected_source_sha:
        raise QazPolitArtifactError("provenance source SHA does not match the requested release")
    if source_sha_payload != f"{source_sha}\n".encode("ascii"):
        raise QazPolitArtifactError("source-sha.txt does not match provenance")
    if provenance["schema"] != "qazpolit.release-provenance.v1":
        raise QazPolitArtifactError("provenance schema is not supported")
    if (
        not isinstance(provenance["release_id"], str)
        or _RELEASE_ID.fullmatch(provenance["release_id"]) is None
    ):
        raise QazPolitArtifactError("provenance release ID is invalid")
    if provenance["release_tier"] != "production":
        raise QazPolitArtifactError("only production QazPolit artifacts are eligible")
    if (
        not isinstance(provenance["platform_admission"], str)
        or not provenance["platform_admission"]
    ):
        raise QazPolitArtifactError("provenance platform admission is invalid")
    if (
        not isinstance(provenance["platform_registry_override_reason"], str)
        or not provenance["platform_registry_override_reason"].strip()
    ):
        raise QazPolitArtifactError("provenance platform override reason is missing")
    if provenance["image_ref"] != f"qazpolit-app:{source_sha}" or not _is_digest(
        provenance["image_digest"]
    ):
        raise QazPolitArtifactError("application image provenance is invalid")

    postgres = provenance["postgres"]
    if (
        not isinstance(postgres, dict)
        or set(postgres) != {"image_ref", "image_digest"}
        or postgres["image_ref"] != f"qazpolit-postgres-walg:{source_sha}"
        or not _is_digest(postgres["image_digest"])
    ):
        raise QazPolitArtifactError("PostgreSQL image provenance is invalid")

    qazstack = provenance["qazstack"]
    if not isinstance(qazstack, dict) or set(qazstack) != {
        "version",
        "source_revision",
        "wheel_sha256",
    }:
        raise QazPolitArtifactError("QazStack provenance is invalid")
    wheel_names = [name for name in names if _WHEEL.fullmatch(name)]
    if len(wheel_names) != 1:
        raise QazPolitArtifactError("QazStack wheel provenance is invalid")
    wheel_name = wheel_names[0]
    wheel_match = _WHEEL.fullmatch(wheel_name)
    if wheel_match is None:
        raise QazPolitArtifactError("QazStack wheel provenance is invalid")
    if (
        qazstack["version"] != wheel_match.group(1)
        or not isinstance(qazstack["source_revision"], str)
        or _GIT_SHA.fullmatch(qazstack["source_revision"]) is None
        or qazstack["wheel_sha256"] != member_digests[wheel_name][0]
    ):
        raise QazPolitArtifactError("QazStack wheel provenance is invalid")

    avds = provenance["avds"]
    if (
        not isinstance(avds, dict)
        or set(avds) != {"assessment_version", "package_version", "source_commit"}
        or not isinstance(avds["assessment_version"], str)
        or not avds["assessment_version"]
        or not isinstance(avds["package_version"], str)
        or not avds["package_version"]
        or not isinstance(avds["source_commit"], str)
        or _GIT_SHA.fullmatch(avds["source_commit"]) is None
    ):
        raise QazPolitArtifactError("AVDS provenance is invalid")
    return source_sha


def _is_digest(value: object) -> bool:
    return isinstance(value, str) and _IMAGE_DIGEST.fullmatch(value) is not None
