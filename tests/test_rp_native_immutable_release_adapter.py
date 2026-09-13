import importlib.util
import sys
from pathlib import Path
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/rp_native_immutable_release_adapter.py"
SPEC = importlib.util.spec_from_file_location("rp_native_immutable_release_adapter", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
ADAPTER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = ADAPTER
SPEC.loader.exec_module(ADAPTER)

SOURCE_SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64


def _manifest() -> dict[str, Any]:
    return {
        "source_sha": SOURCE_SHA,
        "source_worktree_dirty": False,
        "deployment_profile": "reports-private",
        "dependency_lock_sha256": "1" * 64,
        "artifact_tree_sha256": "2" * 64,
        "migration_revision": "0010_reports_dispatch_binding",
        "method_bundle_digest": "sha256:" + "3" * 64,
        "project": {"project_id": "rp", "manifest_sha256": "4" * 64},
        "qazstack": {
            "expected_version": "1.53.0",
            "installed_version": "1.53.0",
            "status": "ready",
        },
        "qazstack_source": ADAPTER.QAZSTACK_SOURCE_SHA,
    }


def _record() -> dict[str, Any]:
    return {
        "release": {
            "source_sha": SOURCE_SHA,
            "artifact_digest": DIGEST,
            "artifact_ref": f"{ADAPTER.IMAGE_PREFIX}@{DIGEST}",
        },
        "evidence": ADAPTER.manifest_evidence(_manifest(), "5" * 64),
    }


def test_manifest_evidence_requires_the_pinned_reports_profile() -> None:
    evidence = ADAPTER.manifest_evidence(_manifest(), "5" * 64)
    assert evidence["migration_revision"] == "0010_reports_dispatch_binding"
    for key, value in (
        ("source_worktree_dirty", True),
        ("deployment_profile", "public"),
        ("qazstack_source", "a" * 40),
        ("method_bundle_digest", "not-a-digest"),
    ):
        invalid = _manifest()
        invalid[key] = value
        with pytest.raises(ADAPTER.AdapterError, match="approved dependency profile"):
            ADAPTER.manifest_evidence(invalid, "5" * 64)


def test_release_record_and_receipt_bind_one_fixed_immutable_tuple() -> None:
    record = _record()
    assert ADAPTER.validate_record(record) == record
    receipt = ADAPTER.receipt(record)
    assert receipt["dependency_identity"] == {
        "deployment_profile": "reports-private",
        "qazstack_version": "1.53.0",
        "qazstack_source_sha": ADAPTER.QAZSTACK_SOURCE_SHA,
    }
    assert receipt["artifact_provenance"] == record["evidence"]
    with pytest.raises(ADAPTER.AdapterError, match="fixed RP immutable artifact"):
        ADAPTER.release_tuple(SOURCE_SHA, DIGEST, f"registry.invalid/rp@{DIGEST}")


def test_deployment_environment_rejects_missing_or_unknown_values(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    required = {
        "RP_RELEASE_ID",
        "RP_COMPOSE_PROJECT",
        "RP_IMAGE_REF",
        "RP_BIND_PORT",
        "RP_ENV_FILE",
        "RP_DATABASE_ENV_FILE",
        "RP_MIGRATION_ENV_FILE",
        "RP_SOURCE_SHA",
        "RP_LOCK_SHA256",
        "RP_ARTIFACT_TREE_SHA256",
        "RP_RELEASE_MANIFEST_SHA256",
        "RP_MIGRATION_REVISION",
        "RP_PROJECT_ID",
        "RP_PROJECT_MANIFEST_SHA256",
        "RP_METHOD_BUNDLE_DIGEST",
        "RP_CAPACITY_BUDGET",
        "RP_POSTGRES_CONTAINER",
        "RP_PROFILE_ROOT",
        "RP_BACKUP_BUNDLE_SHA256",
    }
    environment = tmp_path / "deployment.env"
    environment.write_text(
        "\n".join(f"{key}=value" for key in sorted(required)) + "\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(ADAPTER, "immutable_file", lambda *_args, **_kwargs: None)

    assert set(ADAPTER.read_deployment_env(environment)) == required
    environment.write_text("UNKNOWN=value\n", encoding="utf-8")
    with pytest.raises(ADAPTER.AdapterError, match="environment"):
        ADAPTER.read_deployment_env(environment)
