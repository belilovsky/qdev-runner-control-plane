import hashlib
import io
import json
import warnings
import zipfile
from pathlib import Path
from typing import Any

import pytest

from qdev_runner.qazpolit_artifact import (
    QazPolitArtifactError,
    validate_qazpolit_release_archive,
    validate_qazpolit_release_archive_file,
)
from qdev_runner.qazpolit_artifact_store import (
    QazPolitArtifactStorageError,
    QazPolitArtifactStore,
)
from qdev_runner.qazpolit_github_artifact import (
    QazPolitActionsArtifactRequest,
    QazPolitGitHubArtifactError,
    acquire_qazpolit_actions_artifact,
)

SOURCE_SHA = "a" * 40


def _archive(*, mutate: str | None = None) -> bytes:
    wheel_name = "qazstack-1.37.0-py3-none-any.whl"
    files: dict[str, bytes] = {
        "images.oci.tar.zst": b"oci-image-bytes",
        "source-sha.txt": f"{SOURCE_SHA}\n".encode(),
        wheel_name: b"qazstack-wheel",
        "sbom.cdx.json": b'{"bomFormat":"CycloneDX"}',
        "trivy.json": b"[]",
        "trivy-postgres.json": b"[]",
    }
    files["provenance.json"] = json.dumps(
        {
            "schema": "qazpolit.release-provenance.v1",
            "source_sha": SOURCE_SHA,
            "release_id": "runner-123-1",
            "release_tier": "production",
            "platform_admission": "owner_authorized_registry_pending",
            "platform_registry_override_reason": "owner-authorized continuity release",
            "image_ref": f"qazpolit-app:{SOURCE_SHA}",
            "image_digest": "sha256:" + "b" * 64,
            "postgres": {
                "image_ref": f"qazpolit-postgres-walg:{SOURCE_SHA}",
                "image_digest": "sha256:" + "c" * 64,
            },
            "qazstack": {
                "version": "1.37.0",
                "source_revision": "d" * 40,
                "wheel_sha256": hashlib.sha256(files[wheel_name]).hexdigest(),
            },
            "avds": {
                "assessment_version": "4.7.0",
                "package_version": "4.7.0",
                "source_commit": "e" * 40,
            },
        },
        separators=(",", ":"),
    ).encode()
    checksums = "".join(
        f"{hashlib.sha256(payload).hexdigest()}  ./{name}\n"
        for name, payload in sorted(files.items())
    )
    files["SHA256SUMS"] = checksums.encode()
    if mutate == "missing":
        del files["trivy.json"]
    if mutate == "tampered":
        files["sbom.cdx.json"] = b"tampered"

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in files.items():
            archive.writestr(name, payload)
        if mutate == "duplicate":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", UserWarning)
                archive.writestr("trivy.json", b"duplicate")
        if mutate == "traversal":
            archive.writestr("../outside", b"unsafe")
    return buffer.getvalue()


def test_valid_qazpolit_release_archive_returns_deterministic_evidence() -> None:
    evidence = validate_qazpolit_release_archive(_archive(), expected_source_sha=SOURCE_SHA)

    assert evidence.source_sha == SOURCE_SHA
    assert evidence.release_id == "runner-123-1"
    assert len(evidence.members) == 7
    assert len(evidence.archive_sha256) == 64
    assert len(evidence.payload_sha256) == 64
    assert evidence.as_dict()["schema"] == "qazpolit-release-artifact-evidence-v1"


@pytest.mark.parametrize("mutation", ["missing", "tampered", "duplicate", "traversal"])
def test_rejects_missing_tampered_duplicate_or_unsafe_members(mutation: str) -> None:
    with pytest.raises(QazPolitArtifactError):
        validate_qazpolit_release_archive(_archive(mutate=mutation), expected_source_sha=SOURCE_SHA)


def test_rejects_requested_source_sha_that_does_not_match_provenance() -> None:
    with pytest.raises(QazPolitArtifactError, match="does not match"):
        validate_qazpolit_release_archive(_archive(), expected_source_sha="f" * 40)


def test_rejects_damaged_zip_bytes() -> None:
    with pytest.raises(QazPolitArtifactError, match="readable ZIP"):
        validate_qazpolit_release_archive(b"not a ZIP", expected_source_sha=SOURCE_SHA)


def test_file_validation_matches_in_memory_validation(tmp_path: Path) -> None:
    payload = _archive()
    archive_path = tmp_path / "release.zip"
    archive_path.write_bytes(payload)

    assert validate_qazpolit_release_archive_file(
        archive_path, expected_source_sha=SOURCE_SHA
    ) == validate_qazpolit_release_archive(payload, expected_source_sha=SOURCE_SHA)


def test_file_validation_refuses_a_symlink(tmp_path: Path) -> None:
    archive_path = tmp_path / "release.zip"
    archive_path.write_bytes(_archive())
    symlink_path = tmp_path / "release-link.zip"
    symlink_path.symlink_to(archive_path)

    with pytest.raises(QazPolitArtifactError, match="regular file"):
        validate_qazpolit_release_archive_file(symlink_path, expected_source_sha=SOURCE_SHA)


def test_store_retains_validated_archive_idempotently(tmp_path) -> None:
    payload = _archive()
    store = QazPolitArtifactStore(tmp_path / "controller-artifacts")

    first = store.ingest(payload, expected_source_sha=SOURCE_SHA)
    second = store.ingest(payload, expected_source_sha=SOURCE_SHA)

    assert first.archive_path == second.archive_path
    assert first.archive_path.read_bytes() == payload
    assert first.archive_path.parent.name == SOURCE_SHA
    assert first.archive_path.name == f"{first.evidence.archive_sha256}.zip"
    assert first.archive_path.stat().st_mode & 0o777 == 0o600


def test_store_copies_and_validates_a_downloaded_archive_file(tmp_path: Path) -> None:
    downloaded_archive = tmp_path / "downloaded-release.zip"
    payload = _archive()
    downloaded_archive.write_bytes(payload)
    store = QazPolitArtifactStore(tmp_path / "controller-artifacts")

    stored = store.ingest_file(downloaded_archive, expected_source_sha=SOURCE_SHA)
    downloaded_archive.unlink()

    assert stored.archive_path.read_bytes() == payload
    assert stored.archive_path.stat().st_mode & 0o777 == 0o600


def test_store_validates_a_controller_directed_download(tmp_path: Path) -> None:
    payload = _archive()
    store = QazPolitArtifactStore(tmp_path / "controller-artifacts")

    def download_to(destination: Path) -> None:
        destination.write_bytes(payload)
        destination.chmod(0o600)

    stored = store.ingest_download(download_to, expected_source_sha=SOURCE_SHA)

    assert stored.archive_path.read_bytes() == payload
    assert stored.archive_path.stat().st_mode & 0o777 == 0o600


def test_store_refuses_non_private_controller_directed_download(tmp_path: Path) -> None:
    store = QazPolitArtifactStore(tmp_path / "controller-artifacts")

    def download_to(destination: Path) -> None:
        destination.write_bytes(_archive())
        destination.chmod(0o644)

    with pytest.raises(QazPolitArtifactStorageError, match="private regular file"):
        store.ingest_download(download_to, expected_source_sha=SOURCE_SHA)


def test_store_refuses_a_symlinked_downloaded_archive_file(tmp_path: Path) -> None:
    downloaded_archive = tmp_path / "downloaded-release.zip"
    downloaded_archive.write_bytes(_archive())
    symlink = tmp_path / "downloaded-release-link.zip"
    symlink.symlink_to(downloaded_archive)
    store = QazPolitArtifactStore(tmp_path / "controller-artifacts")

    with pytest.raises(QazPolitArtifactStorageError, match="must be a regular file"):
        store.ingest_file(symlink, expected_source_sha=SOURCE_SHA)


def test_store_refuses_to_replace_a_tampered_archive(tmp_path) -> None:
    payload = _archive()
    store = QazPolitArtifactStore(tmp_path / "controller-artifacts")
    stored = store.ingest(payload, expected_source_sha=SOURCE_SHA)
    stored.archive_path.write_bytes(b"tampered")
    stored.archive_path.chmod(0o600)

    with pytest.raises(QazPolitArtifactStorageError, match="digest does not match"):
        store.ingest(payload, expected_source_sha=SOURCE_SHA)


def test_store_refuses_a_symlinked_root(tmp_path) -> None:
    target = tmp_path / "outside"
    target.mkdir(mode=0o700)
    artifact_root = tmp_path / "controller-artifacts"
    artifact_root.mkdir(mode=0o700)
    (artifact_root / "qazpolit-release-archives").symlink_to(target, target_is_directory=True)

    with pytest.raises(QazPolitArtifactStorageError, match="must not be a symlink"):
        QazPolitArtifactStore(artifact_root)


class _GitHubActionsArtifactClient:
    def __init__(
        self, archive: bytes, *, run: dict[str, Any], artifacts: list[dict[str, Any]]
    ) -> None:
        self.archive = archive
        self.run = run
        self.artifacts = artifacts
        self.download_calls: list[tuple[int, str, int, int]] = []

    def repository_installation_id(self, repository: str) -> int:
        assert repository == "belilovsky/qazpolit"
        return 17

    def workflow_run(self, installation_id: int, repository: str, run_id: int) -> dict[str, Any]:
        assert (installation_id, repository, run_id) == (17, "belilovsky/qazpolit", 123)
        return self.run

    def workflow_run_artifacts(
        self, installation_id: int, repository: str, run_id: int
    ) -> list[dict[str, Any]]:
        assert (installation_id, repository, run_id) == (17, "belilovsky/qazpolit", 123)
        return self.artifacts

    def download_actions_artifact_to_file(
        self,
        installation_id: int,
        repository: str,
        artifact_id: int,
        destination: Path,
        *,
        maximum_bytes: int,
    ) -> None:
        self.download_calls.append((installation_id, repository, artifact_id, maximum_bytes))
        destination.write_bytes(self.archive)
        destination.chmod(0o600)


def _actions_request(archive: bytes) -> QazPolitActionsArtifactRequest:
    return QazPolitActionsArtifactRequest(
        repository="belilovsky/qazpolit",
        source_sha=SOURCE_SHA,
        run_id=123,
        run_attempt=1,
        artifact_id=456,
        artifact_size_bytes=len(archive),
    )


def _workflow_run() -> dict[str, Any]:
    return {
        "id": 123,
        "head_sha": SOURCE_SHA,
        "run_attempt": 1,
        "status": "completed",
        "conclusion": "success",
        "repository": {"full_name": "belilovsky/qazpolit"},
    }


def _workflow_artifact(archive: bytes) -> dict[str, Any]:
    return {
        "id": 456,
        "name": f"qazpolit-production-{SOURCE_SHA}-123",
        "size_in_bytes": len(archive),
        "expired": False,
        "workflow_run": {"id": 123, "head_sha": SOURCE_SHA},
    }


def test_acquire_qazpolit_actions_artifact_binds_exact_successful_run(tmp_path: Path) -> None:
    archive = _archive()
    client = _GitHubActionsArtifactClient(
        archive, run=_workflow_run(), artifacts=[_workflow_artifact(archive)]
    )
    store = QazPolitArtifactStore(tmp_path / "controller-artifacts")

    stored = acquire_qazpolit_actions_artifact(client, store, _actions_request(archive))

    assert stored.archive_path.read_bytes() == archive
    assert client.download_calls == [(17, "belilovsky/qazpolit", 456, len(archive))]


@pytest.mark.parametrize(
    ("target", "key", "value", "message"),
    [
        ("run", "head_sha", "f" * 40, "source SHA"),
        ("run", "run_attempt", 2, "attempt"),
        ("run", "conclusion", "failure", "did not succeed"),
        ("artifact", "name", "other", "name"),
        ("artifact", "expired", True, "expired"),
        ("artifact", "size_in_bytes", 1, "size"),
    ],
)
def test_acquire_qazpolit_actions_artifact_rejects_unbound_metadata(
    tmp_path: Path, target: str, key: str, value: Any, message: str
) -> None:
    archive = _archive()
    run = _workflow_run()
    artifact = _workflow_artifact(archive)
    (run if target == "run" else artifact)[key] = value
    client = _GitHubActionsArtifactClient(archive, run=run, artifacts=[artifact])

    with pytest.raises(QazPolitGitHubArtifactError, match=message):
        acquire_qazpolit_actions_artifact(
            client,
            QazPolitArtifactStore(tmp_path / "controller-artifacts"),
            _actions_request(archive),
        )

    assert client.download_calls == []


def test_acquire_qazpolit_actions_artifact_rejects_ambiguous_id_and_size_mismatch(
    tmp_path: Path,
) -> None:
    archive = _archive()
    client = _GitHubActionsArtifactClient(
        archive,
        run=_workflow_run(),
        artifacts=[_workflow_artifact(archive), _workflow_artifact(archive)],
    )

    with pytest.raises(QazPolitGitHubArtifactError, match="missing or ambiguous"):
        acquire_qazpolit_actions_artifact(
            client,
            QazPolitArtifactStore(tmp_path / "controller-artifacts"),
            _actions_request(archive),
        )

    assert client.download_calls == []


def test_acquire_qazpolit_actions_artifact_refuses_provider_bytes_that_differ_from_metadata(
    tmp_path: Path,
) -> None:
    archive = _archive()
    provider_archive = archive + b"extra"
    client = _GitHubActionsArtifactClient(
        provider_archive, run=_workflow_run(), artifacts=[_workflow_artifact(archive)]
    )

    with pytest.raises(QazPolitArtifactStorageError, match="size does not match"):
        acquire_qazpolit_actions_artifact(
            client,
            QazPolitArtifactStore(tmp_path / "controller-artifacts"),
            _actions_request(archive),
        )
