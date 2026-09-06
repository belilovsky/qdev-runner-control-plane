import hashlib
import importlib.util
import json
import os
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load_module():
    path = ROOT / "scripts/validate_controller_image_binding.py"
    spec = importlib.util.spec_from_file_location("controller_image_binding", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


binding = _load_module()


def _blob(value: object) -> tuple[str, bytes]:
    raw = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return "sha256:" + hashlib.sha256(raw).hexdigest(), raw


def _fixtures(*, runtime_platform: str | None = None, ambiguous: bool = False):
    config_digest, config = _blob({"architecture": "amd64", "os": "linux"})
    layer_digest, layer = _blob({"layer": "content"})
    platform_digest, platform = _blob(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": config_digest,
                "size": len(config),
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                    "digest": layer_digest,
                    "size": len(layer),
                }
            ],
        }
    )
    descriptor = {
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "digest": platform_digest,
        "size": len(platform),
        "platform": {"architecture": "amd64", "os": "linux"},
    }
    expected_attestation, _ = _blob({"attestation": "expected"})
    runtime_attestation, _ = _blob({"attestation": "runtime"})
    expected_digest, expected = _blob(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                descriptor,
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": expected_attestation,
                    "size": 10,
                    "platform": {"architecture": "unknown", "os": "unknown"},
                },
            ],
        }
    )
    runtime_manifests = [
        {
            **descriptor,
            "digest": runtime_platform or platform_digest,
        },
        {
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": runtime_attestation,
            "size": 10,
            "platform": {"architecture": "unknown", "os": "unknown"},
        },
    ]
    if ambiguous:
        runtime_manifests.append(
            {**descriptor, "platform": {"architecture": "arm64", "os": "linux"}}
        )
    runtime_digest, runtime = _blob(
        {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": runtime_manifests,
        }
    )
    blobs = {
        expected_digest: expected,
        runtime_digest: runtime,
        platform_digest: platform,
    }
    return expected_digest, runtime_digest, platform_digest, blobs


def test_accepts_indices_with_same_single_runnable_manifest() -> None:
    expected, runtime, platform, blobs = _fixtures()

    binding.validate_binding(expected, runtime, platform, loader=blobs.__getitem__)


def test_accepts_exact_index_without_containerd_lookup() -> None:
    digest = "sha256:" + "a" * 64

    binding.validate_binding(
        digest,
        digest,
        "sha256:" + "b" * 64,
        loader=lambda _: (_ for _ in ()).throw(AssertionError("unexpected load")),
    )


def test_rejects_content_that_does_not_match_index_digest() -> None:
    expected, runtime, platform, blobs = _fixtures()
    blobs[expected] += b"\n"

    with pytest.raises(binding.ImageBindingError, match="does not match"):
        binding.validate_binding(expected, runtime, platform, loader=blobs.__getitem__)


def test_reads_orphaned_containerd_blob_fail_closed(tmp_path, monkeypatch) -> None:
    digest, raw = _blob({"schemaVersion": 2})
    monkeypatch.setattr(binding, "CONTENT_STORE", tmp_path)
    (tmp_path / digest.removeprefix("sha256:")).write_bytes(raw)

    assert binding._content_store_loader(digest) == raw


def test_rejects_symlinked_containerd_blob(tmp_path, monkeypatch) -> None:
    digest, raw = _blob({"schemaVersion": 2})
    target = tmp_path / "target"
    target.write_bytes(raw)
    os.symlink(target, tmp_path / digest.removeprefix("sha256:"))
    monkeypatch.setattr(binding, "CONTENT_STORE", tmp_path)

    with pytest.raises(binding.ImageBindingError, match="unavailable"):
        binding._content_store_loader(digest)


@pytest.mark.parametrize("case", ["different", "ambiguous", "missing"])
def test_rejects_unproven_index_transition(case: str) -> None:
    if case == "different":
        expected, runtime, platform, blobs = _fixtures(runtime_platform="sha256:" + "c" * 64)
    elif case == "ambiguous":
        expected, runtime, platform, blobs = _fixtures(ambiguous=True)
    else:
        expected, runtime, platform, blobs = _fixtures()
        blobs.pop(expected)

    with pytest.raises((binding.ImageBindingError, KeyError)):
        binding.validate_binding(expected, runtime, platform, loader=blobs.__getitem__)
