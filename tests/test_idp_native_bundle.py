"""Synthetic archives test the loader boundary, not native deployment or CI."""

import copy
import hashlib
import io
import tarfile

import pytest

from qdev_runner.idp_file_runtime import canonical
from qdev_runner.idp_native_bundle import MANIFEST, verify_native_archive
from qdev_runner.release_lane import ReleaseLaneError

SHA = "a" * 40
CONTRACT = b"def validate_native_response(*args, **kwargs): pass\n"
NATIVE = (
    b"contract = __qdev_verified_release_contract__\n"
    b"def dispatch(*args, **kwargs): return {'synthetic': True}\n"
)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def tar(entries):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w:gz", format=tarfile.USTAR_FORMAT) as archive:
        for name, mode, data in entries:
            info = tarfile.TarInfo(name)
            info.mode, info.size = mode, len(data)
            archive.addfile(info, io.BytesIO(data))
    return stream.getvalue()


def publish(*, files=None, change_manifest=None, change_inner=None, change_outer=None):
    if files is None:
        files = {
            "scripts/release-contract.py": CONTRACT,
            "scripts/release-transaction.py": NATIVE,
            "public/.well-known/qdev-release.json": b"{}\n",
        }
    manifest = {
        "schema_version": "qdev-idp-release-bundle-v1",
        "repository": "belilovsky/id-qdev-run",
        "source_sha": SHA,
        "tree_sha": "b" * 40,
        "generated_components": {
            "public/.well-known/qdev-release.json": "commit-time-release-identity-v1"
        },
        "components": {
            name: {"sha256": digest(data), "size": len(data), "mode": 0o644}
            for name, data in files.items()
        },
    }
    if change_manifest:
        change_manifest(manifest)
    manifest_bytes = canonical(manifest)
    entries = [(f"release/{name}", 0o644, data) for name, data in files.items()]
    entries.append((MANIFEST, 0o644, manifest_bytes))
    if change_inner:
        change_inner(entries)
    inner = tar(entries)
    outer_entries = [("release.tar.gz", 0o600, inner), ("manifest.json", 0o600, manifest_bytes)]
    if change_outer:
        change_outer(outer_entries)
    archive = tar(outer_entries)
    return archive, dict(
        source_sha=SHA, archive_sha256=digest(archive), bundle_sha256=digest(inner)
    )


def test_loads_all_verified_bytes_in_isolated_modules():
    archive, binding = publish()
    bundle = verify_native_archive(archive, **binding)
    native, helpers = bundle.load()
    assert native.dispatch() == {"synthetic": True}
    assert native.__qdev_verified_helpers__ == helpers
    assert helpers == {
        "release-contract.py": digest(CONTRACT),
        "release-transaction.py": digest(NATIVE),
    }
    assert native.contract.__name__ != "__main__"


@pytest.mark.parametrize("field", ["source_sha", "archive_sha256", "bundle_sha256"])
def test_untrusted_digest_binding_is_rejected(field):
    archive, binding = publish()
    binding[field] = "f" * len(binding[field])
    with pytest.raises(ReleaseLaneError):
        verify_native_archive(archive, **binding)


@pytest.mark.parametrize("layer", ["inner", "outer"])
@pytest.mark.parametrize("mutation", ["duplicate", "extra", "mode", "data", "missing"])
def test_archive_member_mutations_rejected_even_with_rehashed_archives(layer, mutation):
    def change(entries):
        if mutation == "duplicate":
            entries.append(entries[0])
        elif mutation == "extra":
            entries.append(("release/unlisted" if layer == "inner" else "unlisted", 0o600, b"x"))
        elif mutation == "mode":
            name, _, data = entries[0]
            entries[0] = name, 0o777, data
        elif mutation == "data":
            name, mode, _ = entries[-1]
            entries[-1] = name, mode, b"{}\n"
        else:
            entries.pop()

    archive, binding = publish(**{f"change_{layer}": change})
    with pytest.raises(ReleaseLaneError):
        verify_native_archive(archive, **binding)


@pytest.mark.parametrize("name", ["../evil", "a/../../evil", "/evil", "a//evil", ".env", "x.key"])
def test_manifest_unsafe_component_paths_rejected(name):
    archive, binding = publish(
        files={
            "scripts/release-contract.py": CONTRACT,
            "scripts/release-transaction.py": NATIVE,
            "public/.well-known/qdev-release.json": b"{}\n",
            name: b"x",
        }
    )
    with pytest.raises(ReleaseLaneError):
        verify_native_archive(archive, **binding)


@pytest.mark.parametrize("member_type", [tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE])
def test_nonregular_entries_rejected(member_type):
    archive, binding = publish()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz") as handle:
        info = tarfile.TarInfo("release.tar.gz")
        info.type, info.mode, info.linkname = member_type, 0o600, "/unsafe"
        handle.addfile(info)
    archive = output.getvalue()
    binding["archive_sha256"] = digest(archive)
    with pytest.raises(ReleaseLaneError):
        verify_native_archive(archive, **binding)


def test_compiles_both_before_executing_either():
    archive, binding = publish(
        files={
            "scripts/release-contract.py": b"raise AssertionError('must not execute')\n",
            "scripts/release-transaction.py": b"invalid syntax here\n",
            "public/.well-known/qdev-release.json": b"{}\n",
        }
    )
    with pytest.raises(ReleaseLaneError, match="compiled"):
        verify_native_archive(archive, **binding).load()


def test_component_digest_mismatch_rejected():
    def change(manifest):
        manifest["components"]["scripts/release-contract.py"]["sha256"] = "c" * 64

    archive, binding = publish(change_manifest=change)
    with pytest.raises(ReleaseLaneError):
        verify_native_archive(archive, **binding)


def test_published_input_snapshot_is_immutable():
    archive, binding = publish()
    bundle = verify_native_archive(archive, **binding)
    assert copy.copy(bundle).contract_code == CONTRACT
    with pytest.raises(AttributeError):
        bundle.contract_code = b"bad"


def test_initialization_fault_is_redacted():
    archive, binding = publish(
        files={
            "scripts/release-contract.py": b"raise RuntimeError('synthetic-private-value')\n",
            "scripts/release-transaction.py": NATIVE,
            "public/.well-known/qdev-release.json": b"{}\n",
        }
    )
    with pytest.raises(ReleaseLaneError, match="initialization failed") as caught:
        verify_native_archive(archive, **binding).load()
    assert "synthetic-private-value" not in str(caught.value)


@pytest.mark.parametrize("limit", ["MAX_ARCHIVE", "MAX_TOTAL", "MAX_FILE"])
def test_archive_resource_limits_are_enforced(monkeypatch, limit):
    import qdev_runner.idp_native_bundle as loader

    archive, binding = publish()
    monkeypatch.setattr(loader, limit, 1)
    with pytest.raises(ReleaseLaneError):
        verify_native_archive(archive, **binding)


@pytest.mark.parametrize("metadata", ["uid", "gid", "mtime", "pax_headers"])
def test_noncanonical_tar_metadata_rejected(metadata):
    _, binding = publish()
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w:gz", format=tarfile.PAX_FORMAT) as handle:
        info = tarfile.TarInfo("release.tar.gz")
        info.mode = 0o600
        setattr(info, metadata, {"comment": "not canonical"} if metadata == "pax_headers" else 1)
        handle.addfile(info)
    archive = output.getvalue()
    binding["archive_sha256"] = digest(archive)
    with pytest.raises(ReleaseLaneError):
        verify_native_archive(archive, **binding)


def test_duplicate_manifest_keys_cannot_supply_trust():
    raw = b'{"schema_version":1,"schema_version":2}\n'
    inner = tar([(MANIFEST, 0o644, raw)])
    archive = tar([("release.tar.gz", 0o600, inner), ("manifest.json", 0o600, raw)])
    with pytest.raises(ReleaseLaneError):
        verify_native_archive(
            archive, source_sha=SHA, archive_sha256=digest(archive), bundle_sha256=digest(inner)
        )
