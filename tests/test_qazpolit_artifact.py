import hashlib
import io
import json
import warnings
import zipfile

import pytest

from qdev_runner.qazpolit_artifact import QazPolitArtifactError, validate_qazpolit_release_archive

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
