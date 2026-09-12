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
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from qdev_runner.qazpolit_artifact import (
    QazPolitArtifactError,
    QazPolitArtifactEvidence,
    validate_qazpolit_release_archive,
    validate_qazpolit_release_archive_file,
)

_COPY_CHUNK_BYTES = 1024 * 1024


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

    def ingest_file(
        self, archive_file: Path, *, expected_source_sha: str
    ) -> StoredQazPolitReleaseArtifact:
        """Copy, validate, and retain an untrusted download without retaining it in RAM.

        The caller-owned path is never validated in place: it could be replaced
        while the controller is inspecting it.  A regular file is first copied
        through a no-follow descriptor into a private controller-owned
        temporary file.  Validation and immutable promotion operate only on
        that stable private copy.
        """

        temporary = self.root / f".incoming.{secrets.token_hex(16)}.tmp"
        try:
            self._copy_regular_file_to_private_temporary(archive_file, temporary)
            evidence = validate_qazpolit_release_archive_file(
                temporary, expected_source_sha=expected_source_sha
            )
            return self._retain_private_temporary(temporary, evidence)
        except OSError as error:
            raise QazPolitArtifactStorageError(
                "unable to copy QazPolit release archive into private storage"
            ) from error
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise QazPolitArtifactStorageError(
                    "unable to remove temporary QazPolit archive"
                ) from error

    def ingest_download(
        self,
        download_to: Callable[[Path], None],
        *,
        expected_source_sha: str,
    ) -> StoredQazPolitReleaseArtifact:
        """Accept one controller-directed streaming download into private storage.

        The downloader receives a newly allocated private path and must create
        one regular private file there. The path is never supplied by an API
        caller. Validation and immutable promotion occur before the file can
        become a release candidate.
        """

        temporary = self.root / f".incoming.{secrets.token_hex(16)}.tmp"
        try:
            download_to(temporary)
            self._verify_private_temporary(temporary)
            evidence = validate_qazpolit_release_archive_file(
                temporary, expected_source_sha=expected_source_sha
            )
            return self._retain_private_temporary(temporary, evidence)
        finally:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
            except OSError as error:
                raise QazPolitArtifactStorageError(
                    "unable to remove temporary QazPolit archive"
                ) from error

    def _retain_private_temporary(
        self, temporary: Path, evidence: QazPolitArtifactEvidence
    ) -> StoredQazPolitReleaseArtifact:
        source_root = self.root / evidence.source_sha
        self._create_private_directory(source_root)
        archive_path = source_root / f"{evidence.archive_sha256}.zip"

        if archive_path.exists() or archive_path.is_symlink():
            self._verify_existing(archive_path, evidence.archive_sha256)
            return StoredQazPolitReleaseArtifact(evidence=evidence, archive_path=archive_path)

        try:
            os.link(temporary, archive_path)
        except FileExistsError:
            self._verify_existing(archive_path, evidence.archive_sha256)
        except OSError as error:
            raise QazPolitArtifactStorageError(
                "unable to retain validated QazPolit archive"
            ) from error
        else:
            self._fsync_directory(source_root)

        self._verify_existing(archive_path, evidence.archive_sha256)
        return StoredQazPolitReleaseArtifact(evidence=evidence, archive_path=archive_path)

    @staticmethod
    def _copy_regular_file_to_private_temporary(source: Path, destination: Path) -> None:
        """Copy a caller-owned regular file via no-follow descriptors only."""

        try:
            source_metadata = source.lstat()
        except OSError as error:
            raise QazPolitArtifactStorageError(
                "downloaded QazPolit archive is unavailable"
            ) from error
        if stat.S_ISLNK(source_metadata.st_mode) or not stat.S_ISREG(source_metadata.st_mode):
            raise QazPolitArtifactStorageError("downloaded QazPolit archive must be a regular file")

        nofollow = getattr(os, "O_NOFOLLOW", None)
        if nofollow is None:
            raise QazPolitArtifactStorageError(
                "platform does not support safe QazPolit archive acquisition"
            )
        source_descriptor = os.open(source, os.O_RDONLY | nofollow)
        destination_descriptor: int | None = None
        try:
            if not stat.S_ISREG(os.fstat(source_descriptor).st_mode):
                raise QazPolitArtifactStorageError(
                    "downloaded QazPolit archive must be a regular file"
                )
            destination_descriptor = os.open(
                destination, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600
            )
            with os.fdopen(source_descriptor, "rb") as source_stream:
                source_descriptor = -1
                with os.fdopen(destination_descriptor, "wb") as destination_stream:
                    destination_descriptor = None
                    for chunk in iter(lambda: source_stream.read(_COPY_CHUNK_BYTES), b""):
                        destination_stream.write(chunk)
                    destination_stream.flush()
                    os.fsync(destination_stream.fileno())
        finally:
            if source_descriptor >= 0:
                os.close(source_descriptor)
            if destination_descriptor is not None:
                os.close(destination_descriptor)

    @staticmethod
    def _verify_private_temporary(path: Path) -> None:
        try:
            metadata = path.lstat()
        except OSError as error:
            raise QazPolitArtifactStorageError(
                "downloaded QazPolit archive is unavailable"
            ) from error
        if (
            stat.S_ISLNK(metadata.st_mode)
            or not stat.S_ISREG(metadata.st_mode)
            or stat.S_IMODE(metadata.st_mode) & 0o077
        ):
            raise QazPolitArtifactStorageError(
                "downloaded QazPolit archive must be a private regular file"
            )

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
