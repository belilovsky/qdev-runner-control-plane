"""Controller-owned immutable storage for verified QazPolit release archives.

The artifact verifier deliberately has no side effects.  This module is the
next boundary: it persists only an archive that has just passed that verifier,
under a location derived exclusively from validated digests.  It does not
download an archive or make it available to a release host.
"""

from __future__ import annotations

import hashlib
import os
import secrets
import stat
from dataclasses import dataclass
from pathlib import Path

from qdev_runner.qazpolit_artifact import (
    QazPolitArtifactError,
    QazPolitArtifactEvidence,
    validate_qazpolit_release_archive,
)


class QazPolitArtifactStorageError(QazPolitArtifactError):
    """Raised when the controller-owned archive store is unsafe or inconsistent."""


@dataclass(frozen=True)
class StoredQazPolitReleaseArtifact:
    """Validated artifact evidence and its controller-private immutable path."""

    evidence: QazPolitArtifactEvidence
    archive_path: Path


class QazPolitArtifactStore:
    """Persist verified archives without accepting caller-controlled paths."""

    def __init__(self, artifact_root: Path) -> None:
        self.root = artifact_root / "qazpolit-release-archives"
        self._create_private_directory(self.root)

    @staticmethod
    def _create_private_directory(path: Path) -> None:
        if path.is_symlink():
            raise QazPolitArtifactStorageError("QazPolit artifact store must not be a symlink")
        path.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            path.chmod(0o700)
        except OSError as error:
            raise QazPolitArtifactStorageError(
                "QazPolit artifact store permissions cannot be set"
            ) from error
        try:
            metadata = path.stat()
        except OSError as error:
            raise QazPolitArtifactStorageError("QazPolit artifact store is unavailable") from error
        if not stat.S_ISDIR(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise QazPolitArtifactStorageError("QazPolit artifact store must be private")

    def ingest(
        self, archive_bytes: bytes, *, expected_source_sha: str
    ) -> StoredQazPolitReleaseArtifact:
        """Validate and atomically retain an exact GitHub Actions ZIP archive."""

        evidence = validate_qazpolit_release_archive(
            archive_bytes, expected_source_sha=expected_source_sha
        )
        source_root = self.root / evidence.source_sha
        self._create_private_directory(source_root)
        archive_path = source_root / f"{evidence.archive_sha256}.zip"

        if archive_path.exists() or archive_path.is_symlink():
            self._verify_existing(archive_path, evidence.archive_sha256)
            return StoredQazPolitReleaseArtifact(evidence=evidence, archive_path=archive_path)

        temporary = source_root / f".{evidence.archive_sha256}.{secrets.token_hex(8)}.tmp"
        descriptor: int | None = None
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as stream:
                descriptor = None
                stream.write(archive_bytes)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(temporary, archive_path)
            except FileExistsError:
                self._verify_existing(archive_path, evidence.archive_sha256)
            else:
                self._fsync_directory(source_root)
        except OSError as error:
            raise QazPolitArtifactStorageError(
                "unable to store verified QazPolit archive"
            ) from error
        finally:
            if descriptor is not None:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise QazPolitArtifactStorageError(
                    "unable to remove temporary QazPolit archive"
                ) from error

        self._verify_existing(archive_path, evidence.archive_sha256)
        return StoredQazPolitReleaseArtifact(evidence=evidence, archive_path=archive_path)

    @staticmethod
    def _verify_existing(path: Path, expected_digest: str) -> None:
        if path.is_symlink():
            raise QazPolitArtifactStorageError("stored QazPolit archive must not be a symlink")
        try:
            metadata = path.stat()
        except OSError as error:
            raise QazPolitArtifactStorageError("stored QazPolit archive is unavailable") from error
        if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) & 0o077:
            raise QazPolitArtifactStorageError(
                "stored QazPolit archive is not a private regular file"
            )
        digest = hashlib.sha256()
        try:
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                    digest.update(chunk)
        except OSError as error:
            raise QazPolitArtifactStorageError("stored QazPolit archive cannot be read") from error
        if digest.hexdigest() != expected_digest:
            raise QazPolitArtifactStorageError(
                "stored QazPolit archive digest does not match its path"
            )

    @staticmethod
    def _fsync_directory(path: Path) -> None:
        descriptor = os.open(path, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
