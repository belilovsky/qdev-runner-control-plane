from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Any

import pytest
from bootstrap_support import candidate_receipt, operation, policy, register, request

from qdev_runner import controller_activation_adapter as adapter
from qdev_runner import privileged_bootstrap_executor as privileged
from qdev_runner.controller_release_bundle import build as build_bundle
from qdev_runner.controller_transaction import Paths
from qdev_runner.fleet_bootstrap import FleetBootstrapRequest
from qdev_runner.store import Store

ROOT = Path(__file__).resolve().parents[1]
REVISION = "a" * 40
IMAGE_DIGEST = "sha256:" + "b" * 64
IMAGE_ID = "sha256:" + "c" * 64
BUNDLE_DIGEST = "d" * 64
REFERENCE = f"{adapter.IMAGE_REPOSITORY}@{IMAGE_DIGEST}"


def _envelope(tmp_path: Path) -> dict[str, Any]:
    controller = Store(tmp_path / "controller.db")
    register(controller)
    value = request().model_dump(mode="json")
    value.update(
        {
            "action": "activate-controller",
            "worker_name": None,
            "release_lane": None,
            "controller_candidate_receipt": candidate_receipt(),
        }
    )
    req = FleetBootstrapRequest.model_validate(value)
    authorized = operation(controller, req)
    return {
        "schema": "qdev-fleet-bootstrap-adapter-request-v1",
        "operation": authorized.directive,
        "request": req.model_dump(mode="json", by_alias=True),
        "target": privileged._target(policy(), req),
        "active_jobs": 0,
    }


def _image_record(*, revision: str = REVISION) -> list[dict[str, Any]]:
    return [
        {
            "Id": IMAGE_ID,
            "RepoDigests": [REFERENCE],
            "Config": {
                "Labels": {
                    "org.opencontainers.image.revision": revision,
                    "run.qdev.controller.bundle-digest": BUNDLE_DIGEST,
                    "run.qdev.controller.schema": adapter.IMAGE_SCHEMA,
                }
            },
        }
    ]


def test_validated_request_accepts_only_exact_policy_derived_tuple(tmp_path: Path) -> None:
    envelope = _envelope(tmp_path)
    assert adapter._validated_request(envelope) == (
        REVISION,
        IMAGE_DIGEST,
        REFERENCE,
        envelope["operation"]["payload"]["fence"],
        envelope["operation"]["payload"]["candidate_provenance"]["provenance_digest"],
        BUNDLE_DIGEST,
        envelope["target"]["rollback_revision"],
        envelope["target"]["rollback_release_digest"],
    )

    envelope["active_jobs"] = 1
    with pytest.raises(adapter.ActivationAdapterError, match="tuple"):
        adapter._validated_request(envelope)


def test_image_identity_requires_exact_digest_and_release_labels(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(adapter, "_run", lambda argv, **kwargs: json.dumps(_image_record()))
    assert adapter._image_identity(REFERENCE, REVISION) == (IMAGE_ID, BUNDLE_DIGEST)

    monkeypatch.setattr(
        adapter,
        "_run",
        lambda argv, **kwargs: json.dumps(_image_record(revision="e" * 40)),
    )
    with pytest.raises(adapter.ActivationAdapterError, match="identity mismatch"):
        adapter._image_identity(REFERENCE, REVISION)


def test_install_bundle_transports_and_verifies_declared_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source_bundle = tmp_path / "source-bundle"
    manifest = build_bundle(ROOT, source_bundle, REVISION)
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: object) -> str:
        calls.append(argv)
        if argv[:2] == ["docker", "create"]:
            return "c" * 64
        if argv[:2] == ["docker", "cp"]:
            shutil.copytree(source_bundle, Path(argv[-1]), dirs_exist_ok=True)
        return ""

    monkeypatch.setattr(adapter, "_run", run)
    monkeypatch.setattr(adapter, "_root_owned_tree", lambda root: None)
    installed = adapter._install_bundle(
        reference=REFERENCE,
        revision=REVISION,
        bundle_digest=manifest["bundle_digest"],
        releases=tmp_path / "releases",
    )

    assert installed.is_dir()
    assert calls[0] == ["docker", "create", REFERENCE]
    assert calls[-1] == ["docker", "rm", "-f", "c" * 64]


def test_execute_pulls_exact_digest_and_binds_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    calls: list[list[str]] = []
    release = tmp_path / "release"
    captured: dict[str, Any] = {}

    def run(argv: list[str], **kwargs: object) -> str:
        calls.append(argv)
        return ""

    monkeypatch.setattr(adapter, "_run", run)
    monkeypatch.setattr(
        adapter,
        "_image_identity",
        lambda reference, revision: (IMAGE_ID, BUNDLE_DIGEST),
    )
    monkeypatch.setattr(adapter, "_install_bundle", lambda **kwargs: release)
    monkeypatch.setattr(adapter, "_actual_runtime", lambda reference, image_id: None)

    def activate(paths: Paths, candidate: Path, **kwargs: Any) -> dict[str, str]:
        captured.update({"paths": paths, "candidate": candidate, **kwargs})
        return {"id": "1" * 32}

    monkeypatch.setattr(adapter, "activate", activate)
    paths = Paths(
        releases=tmp_path / "releases",
        current=tmp_path / "current",
        config=tmp_path / "config",
        state=tmp_path / "state",
        owner_uid=0,
    )
    result = adapter.execute(envelope, paths=paths)

    assert calls == [["docker", "pull", REFERENCE]]
    assert captured["candidate"] == release
    assert captured["candidate_image_ref"] == REFERENCE
    assert captured["expected_artifact_digest"] == IMAGE_DIGEST
    assert captured["expected_release_digest"] == BUNDLE_DIGEST
    assert captured["expected_previous_revision"] == envelope["target"]["rollback_revision"]
    assert (
        captured["expected_previous_artifact_digest"]
        == envelope["target"]["rollback_release_digest"]
    )
    assert result["status"] == "completed"
    assert result["result"]["actual_image_id"] == IMAGE_ID
    assert (
        result["result"]["candidate_provenance_digest"]
        == (envelope["operation"]["payload"]["candidate_provenance"]["provenance_digest"])
    )


def test_execute_rejects_image_bundle_that_differs_from_signed_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    calls: list[list[str]] = []

    def run(argv: list[str], **kwargs: object) -> str:
        calls.append(argv)
        return ""

    monkeypatch.setattr(adapter, "_run", run)
    monkeypatch.setattr(
        adapter,
        "_image_identity",
        lambda reference, revision: (IMAGE_ID, "e" * 64),
    )

    with pytest.raises(adapter.ActivationAdapterError, match="signed provenance"):
        adapter.execute(envelope, paths=Paths(state=tmp_path / "state"))

    assert calls == [["docker", "pull", REFERENCE]]


def test_execute_rolls_back_accepted_transaction_when_runtime_identity_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    envelope = _envelope(tmp_path)
    release = tmp_path / "release"
    rolled_back: list[str] = []

    monkeypatch.setattr(adapter, "_run", lambda argv, **kwargs: "")
    monkeypatch.setattr(
        adapter,
        "_image_identity",
        lambda reference, revision: (IMAGE_ID, BUNDLE_DIGEST),
    )
    monkeypatch.setattr(adapter, "_install_bundle", lambda **kwargs: release)
    monkeypatch.setattr(adapter, "activate", lambda *args, **kwargs: {"id": "2" * 32})
    monkeypatch.setattr(
        adapter,
        "_actual_runtime",
        lambda *args: (_ for _ in ()).throw(
            adapter.ActivationAdapterError("active identity mismatch")
        ),
    )
    monkeypatch.setattr(
        adapter,
        "rollback_accepted",
        lambda paths, identity: rolled_back.append(identity),
    )

    with pytest.raises(adapter.ActivationAdapterError, match="identity mismatch"):
        adapter.execute(envelope, paths=Paths(state=tmp_path / "state"))

    assert rolled_back == ["2" * 32]


def test_actual_runtime_rejects_container_started_from_other_reference(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    record = [
        {
            "Image": IMAGE_ID,
            "Config": {"Image": "registry.ci.qdev.run/other@" + IMAGE_DIGEST},
            "State": {"Running": True},
        }
    ]
    monkeypatch.setattr(adapter, "_run", lambda argv, **kwargs: json.dumps(record))

    with pytest.raises(adapter.ActivationAdapterError, match="identity mismatch"):
        adapter._actual_runtime(REFERENCE, IMAGE_ID)
