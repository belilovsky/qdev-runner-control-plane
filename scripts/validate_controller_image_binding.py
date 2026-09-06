#!/usr/bin/env python3
"""Validate a Docker/containerd OCI-index identity transition fail closed."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
from collections.abc import Callable
from pathlib import Path
from typing import Any

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
INDEX_MEDIA_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONTENT_STORE = Path("/var/lib/containerd/io.containerd.content.v1.content/blobs/sha256")
MAX_CONTENT_BYTES = 16 * 1024 * 1024


class ImageBindingError(ValueError):
    """Raised when two image identities are not unambiguously equivalent."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise ImageBindingError(f"OCI document contains duplicate key: {key}")
        value[key] = item
    return value


def _document(raw: bytes, digest: str) -> dict[str, Any]:
    if not DIGEST.fullmatch(digest):
        raise ImageBindingError("OCI content digest is invalid")
    measured = "sha256:" + hashlib.sha256(raw).hexdigest()
    if measured != digest:
        raise ImageBindingError("OCI content does not match its digest")
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ImageBindingError("OCI content is not strict JSON") from error
    if not isinstance(value, dict):
        raise ImageBindingError("OCI document must be an object")
    return value


def _descriptor(value: object, *, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ImageBindingError(f"{label} descriptor is invalid")
    digest = value.get("digest")
    size = value.get("size")
    media_type = value.get("mediaType")
    if (
        not isinstance(digest, str)
        or not DIGEST.fullmatch(digest)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or not isinstance(media_type, str)
    ):
        raise ImageBindingError(f"{label} descriptor identity is invalid")
    return value


def _runnable_descriptor(index: dict[str, Any], platform_manifest: str) -> dict[str, Any]:
    if index.get("schemaVersion") != 2 or index.get("mediaType") not in INDEX_MEDIA_TYPES:
        raise ImageBindingError("controller image content is not a supported OCI index")
    manifests = index.get("manifests")
    if not isinstance(manifests, list) or not manifests:
        raise ImageBindingError("controller image index has no manifests")

    runnable: list[dict[str, Any]] = []
    for position, item in enumerate(manifests):
        descriptor = _descriptor(item, label=f"manifest {position}")
        platform = descriptor.get("platform")
        if descriptor["mediaType"] not in MANIFEST_MEDIA_TYPES or not isinstance(platform, dict):
            continue
        os_name = platform.get("os")
        architecture = platform.get("architecture")
        if (
            isinstance(os_name, str)
            and isinstance(architecture, str)
            and os_name not in {"", "unknown"}
            and architecture not in {"", "unknown"}
        ):
            runnable.append(descriptor)

    if len(runnable) != 1:
        raise ImageBindingError("controller image index does not have one runnable manifest")
    if runnable[0]["digest"] != platform_manifest:
        raise ImageBindingError(
            "controller image index does not bind the running platform manifest"
        )
    return runnable[0]


def validate_binding(
    expected_index: str,
    runtime_index: str,
    platform_manifest: str,
    *,
    loader: Callable[[str], bytes],
) -> None:
    for value in (expected_index, runtime_index, platform_manifest):
        if not DIGEST.fullmatch(value):
            raise ImageBindingError("controller image identity is invalid")
    if expected_index == runtime_index:
        return

    expected = _document(loader(expected_index), expected_index)
    runtime = _document(loader(runtime_index), runtime_index)
    expected_descriptor = _runnable_descriptor(expected, platform_manifest)
    runtime_descriptor = _runnable_descriptor(runtime, platform_manifest)
    if expected_descriptor != runtime_descriptor:
        raise ImageBindingError("controller image indexes bind different runnable manifests")

    manifest = _document(loader(platform_manifest), platform_manifest)
    if (
        manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") not in MANIFEST_MEDIA_TYPES
        or not isinstance(manifest.get("config"), dict)
        or not isinstance(manifest.get("layers"), list)
        or not manifest["layers"]
    ):
        raise ImageBindingError("running platform manifest is invalid")
    _descriptor(manifest["config"], label="image config")
    for position, layer in enumerate(manifest["layers"]):
        _descriptor(layer, label=f"image layer {position}")


def _content_store_loader(digest: str) -> bytes:
    if not DIGEST.fullmatch(digest):
        raise ImageBindingError("containerd content digest is invalid")
    path = CONTENT_STORE / digest.removeprefix("sha256:")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ImageBindingError("containerd image content is unavailable") from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size <= 0
            or metadata.st_size > MAX_CONTENT_BYTES
        ):
            raise ImageBindingError("containerd image content metadata is invalid")
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            raw = stream.read(MAX_CONTENT_BYTES + 1)
        if len(raw) != metadata.st_size:
            raise ImageBindingError("containerd image content size changed while reading")
        return raw
    finally:
        os.close(descriptor)


def _containerd_loader(digest: str) -> bytes:
    executable = shutil.which("ctr")
    if executable is not None:
        try:
            completed = subprocess.run(
                [executable, "--namespace", "moby", "content", "get", digest],
                check=True,
                capture_output=True,
                timeout=10,
            )
        except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
            pass
        else:
            return completed.stdout
    return _content_store_loader(digest)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-index", required=True)
    parser.add_argument("--runtime-index", required=True)
    parser.add_argument("--platform-manifest", required=True)
    args = parser.parse_args()
    try:
        validate_binding(
            args.expected_index,
            args.runtime_index,
            args.platform_manifest,
            loader=_containerd_loader,
        )
    except ImageBindingError as error:
        parser.error(str(error))
    print(
        "controller_image_binding=verified "
        f"expected={args.expected_index} runtime={args.runtime_index} "
        f"platform_manifest={args.platform_manifest}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
