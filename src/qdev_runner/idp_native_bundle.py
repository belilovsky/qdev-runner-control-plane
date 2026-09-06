"""Verify published IdP bytes before loading their native helpers in memory.

Expected digests are capabilities from the host's verified signed dispatch, not
trust assertions read from these archives. This module does no download, Git
rebuild, extraction, admission, staging or deployment. The fixed host owner is
the caller; no API route or CLI accepts executable bytes or a replacement key.
"""

from __future__ import annotations

import hashlib
import io
import json
import tarfile
import types
from dataclasses import dataclass
from typing import Any

from .idp_file_runtime import canonical, hex_value, validate_component_manifest
from .release_lane import ReleaseLaneError

MAX_ARCHIVE = 250 * 1024 * 1024
MAX_TOTAL = 256 * 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MANIFEST = "qdev-release-bundle.json"
HELPERS = ("release-contract.py", "release-transaction.py")


def _require(condition: bool) -> None:
    if not condition:
        raise ReleaseLaneError("IdP published native bundle is invalid or unbound")


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        _require(key not in result)
        result[key] = value
    return result


def _tar(data: bytes, *, outer: bool) -> dict[str, tuple[int, bytes]]:
    entries: dict[str, tuple[int, bytes]] = {}
    total = 0
    try:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
            for member in archive:
                _require(len(entries) < (2 if outer else 10000))
                _require(member.name not in entries and member.isfile())
                _require(not member.pax_headers and member.uid == member.gid == member.mtime == 0)
                _require(member.mode in ({0o600} if outer else {0o644, 0o755}))
                _require(0 <= member.size <= (MAX_TOTAL if outer else MAX_FILE))
                _require(
                    member.name in {"release.tar.gz", "manifest.json"}
                    if outer
                    else member.name == MANIFEST or member.name.startswith("release/")
                )
                total += member.size
                _require(total <= MAX_TOTAL)
                stream = archive.extractfile(member)
                _require(stream is not None)
                assert stream is not None
                payload = stream.read(member.size + 1)
                _require(len(payload) == member.size)
                entries[member.name] = member.mode, payload
    except (tarfile.TarError, OSError, EOFError, ValueError, OverflowError):
        raise ReleaseLaneError("IdP published native archive is malformed") from None
    return entries


@dataclass(frozen=True)
class VerifiedNativeBundle:
    source_sha: str
    bundle_sha256: str
    manifest_sha256: str
    bundle: bytes
    # Immutable bytes, not mutable parsed objects that could change after verification.
    contract_code: bytes
    transaction_code: bytes

    def load(self) -> tuple[types.ModuleType, dict[str, str]]:
        code = dict(zip(HELPERS, (self.contract_code, self.transaction_code), strict=True))
        helper_digests = {name: _digest(data) for name, data in code.items()}
        # Compile BOTH before executing either, in isolated modules, never __main__.
        try:
            compiled = {
                name: compile(data, f"qdev-bundle:{self.source_sha}/scripts/{name}", "exec")
                for name, data in code.items()
            }
        except (SyntaxError, ValueError):
            raise ReleaseLaneError("IdP verified helper cannot be compiled") from None
        modules: dict[str, types.ModuleType] = {}
        for name in HELPERS:
            module = types.ModuleType(f"_qdev_bound_{name.replace('-', '_')}_{self.source_sha}")
            module.__file__ = f"qdev-bundle:{self.source_sha}/scripts/{name}"
            module.__dict__["__qdev_verified_helpers__"] = dict(helper_digests)
            if name == HELPERS[1]:
                module.__dict__["__qdev_verified_release_contract__"] = modules[HELPERS[0]]
            # Executable source belongs to the signed exact-SHA archive, checked
            # by the installed host before reaching this code-only capability.
            try:
                exec(compiled[name], module.__dict__)  # noqa: S102
            except Exception:
                raise ReleaseLaneError("IdP verified helper initialization failed") from None
            modules[name] = module
        native = modules[HELPERS[1]]
        _require(callable(getattr(native, "dispatch", None)))
        _require(callable(getattr(modules[HELPERS[0]], "validate_native_response", None)))
        return native, helper_digests


def verify_native_archive(
    data: bytes, *, source_sha: str, archive_sha256: str, bundle_sha256: str
) -> VerifiedNativeBundle:
    """Verify every member before any code runs; caller authenticates the digests."""
    _require(
        isinstance(data, bytes)
        and 0 < len(data) <= MAX_ARCHIVE
        and hex_value(source_sha, 40)
        and hex_value(archive_sha256)
        and hex_value(bundle_sha256)
    )
    _require(_digest(data) == archive_sha256)
    outer = _tar(data, outer=True)
    _require(set(outer) == {"release.tar.gz", "manifest.json"})
    inner, manifest_bytes = outer["release.tar.gz"][1], outer["manifest.json"][1]
    _require(_digest(inner) == bundle_sha256)
    entries = _tar(inner, outer=False)
    _require(MANIFEST in entries and entries[MANIFEST] == (0o644, manifest_bytes))
    try:
        manifest = json.loads(manifest_bytes, object_pairs_hook=_unique)
        manifest_sha256 = _digest(manifest_bytes)
        validate_component_manifest(
            manifest, {"source_sha": source_sha, "manifest_sha256": manifest_sha256}
        )
        _require(canonical(manifest) == manifest_bytes)
        components = manifest["components"]
        _require(set(entries) == {MANIFEST} | {f"release/{name}" for name in components})
        for name, metadata in components.items():
            mode, payload = entries[f"release/{name}"]
            _require(metadata == {"mode": mode, "size": len(payload), "sha256": _digest(payload)})
        _require(all(f"scripts/{name}" in components for name in HELPERS))
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ReleaseLaneError("IdP published component manifest is invalid") from None
    return VerifiedNativeBundle(
        source_sha,
        bundle_sha256,
        manifest_sha256,
        inner,
        entries[f"release/scripts/{HELPERS[0]}"][1],
        entries[f"release/scripts/{HELPERS[1]}"][1],
    )
