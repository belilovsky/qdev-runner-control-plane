import base64
import hashlib
import hmac
import importlib.util
import json
import sys
import time
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/qdev_product_release_host_agent.py"
SPEC = importlib.util.spec_from_file_location("qdev_product_release_host_agent", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
AGENT = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = AGENT
SPEC.loader.exec_module(AGENT)

SHA = "a" * 40
DIGEST = "sha256:" + "b" * 64
QAZSTACK_SHA = "c" * 40
AVDS_SHA = "d" * 40
AVDS_DIGEST = "e" * 64
NOW = 2_000_000_000
DISPATCH_SECRET = b"qgeo-host-dispatch-test-secret-32-bytes"


def _signed_qgeo_document(
    tmp_path: Path,
    *,
    private_key: Ed25519PrivateKey | None = None,
    issued_at: int = NOW - 30,
    expires_at: int = NOW + 300,
) -> tuple[dict[str, object], Ed25519PrivateKey]:
    source = tmp_path / "qazstack-source"
    source.mkdir(exist_ok=True)
    (source / "pyproject.toml").write_text("[project]\nname='qazstack'\n", encoding="utf-8")
    release = tmp_path / "release"
    release.mkdir(exist_ok=True)
    compose = release / "docker-compose.yml"
    runtime_env = release / ".env"
    overlay = release / "compose-runtime.override.yml"
    for path in (compose, runtime_env, overlay):
        path.write_text("verified fixture\n", encoding="utf-8")
    profile: dict[str, object] = {
        "name": "qazgeo",
        "lane": "qdev-release-qazgeo",
        "project": "qazgeo",
        "placement": "qazgeo-app-runtime",
        "repository": "belilovsky/qazgeo",
        "candidate_source_sha": SHA,
        "candidate_artifact_digest": DIGEST,
        "release_dir": str(release),
        "compose_files": [str(compose)],
        "runtime_env": str(runtime_env),
        "services": ["db", "redis", "app", "martin", "photon", "valhalla", "nginx"],
        "local_ready_url": "http://127.0.0.1:18280/health",
        "local_readiness_url": "http://127.0.0.1:18280/health/ready",
        "public_release_url": "https://qgeo.tech/health",
        "public_identity_path": ["source_revision"],
        "image_environment": "QAZGEO_APP_IMAGE",
        "controller_overlay": str(overlay),
        "static_directory_root": str(AGENT._QGEO_STATIC_ROOT),
        "rollback_static_directory": str(tmp_path / "rollback-static"),
        "rollback_image_reference": AGENT._QGEO_ROLLBACK_IMAGE,
        "rollback_release": {
            "source_sha": AGENT._QGEO_RECOVERY_SHA,
            "artifact_digest": AGENT._QGEO_RECOVERY_DIGEST,
            "artifact_ref": (
                f"registry.ci.qdev.run/belilovsky/qazgeo@{AGENT._QGEO_RECOVERY_DIGEST}"
            ),
        },
        "qazstack_source_directory": str(source),
        "qazstack_version": "candidate-bound",
        "qazstack_source_ref": QAZSTACK_SHA,
        "qazstack_source_manifest_sha256": AGENT._directory_manifest_digest(source),
        "avds_source_sha": AVDS_SHA,
        "avds_artifact_sha256": AVDS_DIGEST,
    }
    unsigned: dict[str, object] = {
        "schema": AGENT.QGEO_PROFILE_SCHEMA,
        "issued_at": issued_at,
        "expires_at": expires_at,
        "profile": profile,
    }
    signer = private_key or Ed25519PrivateKey.generate()
    signature = signer.sign(AGENT._canonical_json(unsigned))
    document = {
        **unsigned,
        "signature": base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii"),
    }
    return document, signer


def _qgeo_profile(tmp_path: Path) -> object:
    document, signer = _signed_qgeo_document(tmp_path)
    return AGENT.verify_qgeo_profile_document(document, signer.public_key(), now=NOW)


def _qgeo_config(tmp_path: Path) -> object:
    return AGENT.Config(
        "https://worker.ci.qdev.run",
        tmp_path / "client.crt",
        tmp_path / "client.key",
        tmp_path / "controller-ca.crt",
        tmp_path / "state.json",
        tmp_path / "agent.lock",
        None,
        None,
        "qdev-host-agent:qazgeo-app-runtime",
        DISPATCH_SECRET,
    )


def _qgeo_job(
    profile: object, release: dict[str, str], *, now: int | None = None
) -> dict[str, object]:
    issued_at = int(time.time()) if now is None else now
    rollback = profile.rollback_release
    assert rollback is not None
    provenance = AGENT._expected_qgeo_artifact_provenance(profile)
    candidate_evidence = {
        "schema": "qdev-release-candidate-evidence-v1",
        "candidate_receipt_sha256": "1" * 64,
        "artifact_provenance": provenance,
    }
    job: dict[str, object] = {
        "schema": "qdev-release-host-agent-job-v1",
        "release_id": "release-1",
        "release_lane": profile.lane,
        "project_id": profile.project,
        "placement": profile.placement,
        "lease_id": "lease-0123456789",
        "fence": "f" * 24,
        "lease_expires_at": issued_at + 300,
        "rollback_anchor": rollback,
        "candidate_evidence": candidate_evidence,
        "artifact_provenance": provenance,
        **release,
    }
    claim = {
        "schema": AGENT.HOST_DISPATCH_CLAIM_SCHEMA,
        "repository": profile.repository,
        "workflow": "CI - QazGeo",
        "job": "docker-build",
        "exact_sha": release["source_sha"],
        "run_id": 123,
        "job_id": 456,
        "attempt": 1,
        "runner_profile": "qdev-ci-docker",
        "host_identity": "qdev-host-agent:qazgeo-app-runtime",
        "release_id": job["release_id"],
        "release_lane": profile.lane,
        "project_id": profile.project,
        "placement": profile.placement,
        "artifact_digest": release["artifact_digest"],
        "artifact_ref": release["artifact_ref"],
        "lease_id": job["lease_id"],
        "fence": job["fence"],
        "lease_expires_at": job["lease_expires_at"],
        "rollback_anchor": rollback,
        "candidate_evidence": candidate_evidence,
        "issued_at": issued_at,
        "expires_at": issued_at + 120,
        "nonce": "qgeo-dispatch-nonce-0123456789abcdef",
    }
    job["dispatch_claim"] = claim
    job["dispatch_claim_signature"] = hmac.new(
        DISPATCH_SECRET,
        AGENT._canonical_json(claim),
        hashlib.sha256,
    ).hexdigest()
    return job


@pytest.mark.parametrize("name", ["qaz-fund", "qaz-events", "qmt"])
def test_product_agent_binds_jobs_to_fixed_lane_and_registry(name: str) -> None:
    profile = AGENT.PROFILES[name]
    reference = f"registry.ci.qdev.run/{profile.repository}@{DIGEST}"
    release = {"source_sha": SHA, "artifact_digest": DIGEST, "artifact_ref": reference}
    assert AGENT._release(release, profile) == release
    with pytest.raises(AGENT.AgentError):
        AGENT._release({**release, "artifact_ref": "unsafe:latest"}, profile)
    job = {
        "schema": "qdev-release-host-agent-job-v1",
        "release_id": "release-1",
        "release_lane": profile.lane,
        "project_id": profile.project,
        "placement": profile.placement,
        **release,
    }
    assert AGENT.validate_job(job, profile) == ("release-1", release)
    with pytest.raises(AGENT.AgentError):
        AGENT.validate_job({**job, "placement": "other-host"}, profile)


def test_product_agent_is_no_build_and_has_no_guessed_qgeo_target() -> None:
    script = SCRIPT.read_text(encoding="utf-8")
    assert '"--no-build"' in script
    assert '"--pull", "never"' in script
    assert "https://qaz.fund/.well-known/release.json" in script
    assert "https://qaz.events/.well-known/qdev-ecosystem.json" in script
    assert "https://qmt.digital/release.json" in script
    assert "qdev-release-qmt" in script
    assert "QMT_IMAGE" in script
    assert "preloaded_image_required" in script
    assert "docker system prune" not in script
    assert "docker image prune" not in script
    assert "runtime_proof(profile, previous_active)" in script
    assert "qazgeo" not in AGENT.PROFILES
    assert "qazgeo-primary-187" not in script
    assert "1.21.1" not in script


def test_qmt_requires_a_preloaded_digest_and_never_pulls(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = AGENT.PROFILES["qmt"]
    release = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/kaztilshi@{DIGEST}",
    }
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> bytes:
        commands.append(command)
        if any("RepoDigests" in token for token in command):
            return f'["{release["artifact_ref"]}"]'.encode()
        return SHA.encode()

    monkeypatch.setattr(AGENT, "_run", fake_run)
    AGENT.verify_image(release, profile)
    assert ["docker", "pull", release["artifact_ref"]] not in commands


def test_qgeo_profile_is_externally_signed_and_candidate_bound(tmp_path: Path) -> None:
    profile = _qgeo_profile(tmp_path)
    assert profile.placement == "qazgeo-app-runtime"
    assert profile.candidate_source_sha == SHA
    assert profile.candidate_artifact_digest == DIGEST
    assert profile.signed_profile_digest.startswith("sha256:")
    assert profile.qazstack_version == "candidate-bound"
    assert AGENT._qgeo_artifact_provenance(profile) == {
        "qazstack_source_sha": QAZSTACK_SHA,
        "qazstack_version": "candidate-bound",
        "qazstack_source_manifest_sha256": profile.qazstack_source_manifest_sha256,
        "avds_source_sha": AVDS_SHA,
        "avds_artifact_sha256": AVDS_DIGEST,
    }


def test_qgeo_profile_rejects_forgery_wrong_key_and_noncanonical_signature(
    tmp_path: Path,
) -> None:
    document, signer = _signed_qgeo_document(tmp_path)
    forged = json.loads(json.dumps(document))
    forged["profile"]["candidate_source_sha"] = "f" * 40
    with pytest.raises(AGENT.AgentError, match="signature is invalid"):
        AGENT.verify_qgeo_profile_document(forged, signer.public_key(), now=NOW)
    with pytest.raises(AGENT.AgentError, match="signature is invalid"):
        AGENT.verify_qgeo_profile_document(
            document,
            Ed25519PrivateKey.generate().public_key(),
            now=NOW,
        )
    noncanonical = {**document, "signature": f"{document['signature']}="}
    with pytest.raises(AGENT.AgentError, match="not canonical"):
        AGENT.verify_qgeo_profile_document(noncanonical, signer.public_key(), now=NOW)


def test_qgeo_profile_rejects_expiry_and_foreign_placement(tmp_path: Path) -> None:
    expired, signer = _signed_qgeo_document(
        tmp_path,
        issued_at=NOW - 500,
        expires_at=NOW - 1,
    )
    with pytest.raises(AGENT.AgentError, match="not currently valid"):
        AGENT.verify_qgeo_profile_document(expired, signer.public_key(), now=NOW)
    foreign, signer = _signed_qgeo_document(tmp_path)
    foreign_profile = foreign["profile"]
    assert isinstance(foreign_profile, dict)
    foreign_profile["placement"] = "unproven-host"
    unsigned = {key: foreign[key] for key in ("schema", "issued_at", "expires_at", "profile")}
    foreign["signature"] = (
        base64.urlsafe_b64encode(signer.sign(AGENT._canonical_json(unsigned)))
        .rstrip(b"=")
        .decode("ascii")
    )
    with pytest.raises(AGENT.AgentError, match="fixed identity"):
        AGENT.verify_qgeo_profile_document(foreign, signer.public_key(), now=NOW)


def test_qgeo_job_requires_signed_candidate_provenance_and_fence(tmp_path: Path) -> None:
    profile = _qgeo_profile(tmp_path)
    release = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/belilovsky/qazgeo@{DIGEST}",
    }
    job = _qgeo_job(profile, release, now=NOW)
    config = _qgeo_config(tmp_path)
    assert AGENT.validate_job(job, profile, config, now=NOW) == ("release-1", release)
    without_fence = {key: value for key, value in job.items() if key != "fence"}
    with pytest.raises(AGENT.AgentError, match="fencing is missing"):
        AGENT.validate_job(without_fence, profile, config, now=NOW)
    mismatched = dict(job)
    mismatched["artifact_provenance"] = {
        **job["artifact_provenance"],
        "avds_source_sha": "0" * 40,
    }
    with pytest.raises(AGENT.AgentError, match="candidate evidence"):
        AGENT.validate_job(mismatched, profile, config, now=NOW)
    with pytest.raises(AGENT.AgentError, match="does not bind the exact job"):
        AGENT.validate_job({**job, "source_sha": "0" * 40}, profile, config, now=NOW)


def test_qgeo_profile_public_key_is_verification_only(tmp_path: Path) -> None:
    document, signer = _signed_qgeo_document(tmp_path)
    public_pem = signer.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key = AGENT._profile_public_key(public_pem)
    assert AGENT.verify_qgeo_profile_document(document, key, now=NOW).candidate_source_sha == SHA
    private_pem = signer.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(AGENT.AgentError, match="public key"):
        AGENT._profile_public_key(private_pem)


def test_qgeo_materializes_static_from_candidate_image_idempotently(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = replace(
        _qgeo_profile(tmp_path),
        static_directory_root=tmp_path / "static",
        rollback_static_directory=tmp_path / "rollback",
    )
    release = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/belilovsky/qazgeo@{DIGEST}",
    }
    commands: list[list[str]] = []

    def fake_run(command: list[str], **_kwargs: object) -> bytes:
        commands.append(command)
        if command[:2] == ["docker", "create"]:
            return b"candidate-container\n"
        if command[:2] == ["docker", "cp"]:
            destination = Path(command[-1])
            (destination / "css").mkdir()
            (destination / "css" / "app.css").write_text("candidate", encoding="utf-8")
            return b""
        if command[:3] == ["docker", "rm", "--force"]:
            return b""
        raise AssertionError(command)

    monkeypatch.setattr(AGENT, "_run", fake_run)
    first = AGENT.materialize_static(release, profile)
    second = AGENT.materialize_static(release, profile)
    assert first == second
    assert first is not None and first["digest"].startswith("sha256:")
    assert (tmp_path / "static" / SHA / "css" / "app.css").read_text() == "candidate"
    assert sum(command[:2] == ["docker", "create"] for command in commands) == 1


def test_qgeo_materialization_rejects_unproven_existing_static_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = replace(
        _qgeo_profile(tmp_path),
        static_directory_root=tmp_path / "static",
        rollback_static_directory=tmp_path / "rollback",
    )
    release = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/belilovsky/qazgeo@{DIGEST}",
    }
    target = profile.static_directory_root / SHA
    assert target is not None
    target.mkdir(parents=True)
    (target / "app.css").write_text("unknown", encoding="utf-8")
    monkeypatch.setattr(AGENT, "_run", lambda *_args, **_kwargs: b"")
    with pytest.raises(AGENT.AgentError, match="without proof"):
        AGENT.materialize_static(release, profile)


def test_qgeo_unexpected_post_mutation_error_still_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _qgeo_profile(tmp_path)
    candidate = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/belilovsky/qazgeo@{DIGEST}",
    }
    rollback = profile.rollback_release
    assert rollback is not None
    job = _qgeo_job(profile, candidate)
    config = _qgeo_config(tmp_path)
    requests: list[tuple[str, str]] = []
    rolled_back: list[tuple[dict[str, str], dict[str, str]]] = []

    def fake_request(
        _config: object,
        method: str,
        path: str,
        _payload: object = None,
        **_kwargs: object,
    ) -> tuple[int, bytes]:
        requests.append((method, path))
        if method == "GET":
            return 200, json.dumps(job).encode()
        return 200, b"{}"

    def fake_rollback(
        _config: object,
        _profile: object,
        _release_id: str,
        failed: dict[str, str],
        restored: dict[str, str],
        _previous_rollback: dict[str, str],
        lease_id: str,
        fence: str,
        **_kwargs: object,
    ) -> dict[str, object]:
        assert lease_id == job["lease_id"]
        assert fence == job["fence"]
        rolled_back.append((failed, restored))
        return {"status": "rolled_back"}

    monkeypatch.setattr(AGENT, "read_state", lambda *_args: (rollback, rollback))
    monkeypatch.setattr(AGENT, "heartbeat", lambda *_args: {"capacity_free_gib": 40})
    monkeypatch.setattr(AGENT, "request", fake_request)
    monkeypatch.setattr(AGENT, "verify_image", lambda *_args: None)
    monkeypatch.setattr(AGENT, "materialize_static", lambda *_args: None)
    monkeypatch.setattr(AGENT, "_compose", lambda *_args: None)
    monkeypatch.setattr(
        AGENT,
        "runtime_proof",
        lambda *_args: (_ for _ in ()).throw(ValueError("malformed runtime JSON")),
    )
    monkeypatch.setattr(AGENT, "_managed_rollback", fake_rollback)

    with pytest.raises(AGENT.AgentError, match="operational error"):
        AGENT.run_once(config, profile)

    assert requests[0][0] == "POST"
    assert requests[1][0] == "GET"
    assert rolled_back == [(candidate, rollback)]


def test_qgeo_completion_response_loss_reconciles_verified_controller(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _qgeo_profile(tmp_path)
    candidate = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/belilovsky/qazgeo@{DIGEST}",
    }
    restored = profile.rollback_release
    assert restored is not None
    receipt = AGENT._completion_receipt(
        profile,
        candidate,
        restored,
        readiness={"app": "ok", "public": "ok"},
    )
    submits: list[dict[str, object]] = []

    def lost_response(*_args: object, **_kwargs: object) -> None:
        submits.append(receipt)
        raise AGENT.ControllerTransportError("response lost")

    monkeypatch.setattr(AGENT, "_submit_completion", lost_response)
    monkeypatch.setattr(
        AGENT,
        "_read_controller_status",
        lambda *_args, **_kwargs: {"status": "verified", "runtime_receipt": receipt},
    )

    AGENT._resolve_completion(
        object(),
        profile,
        "release-1",
        candidate,
        restored,
        receipt,
        "lease-0123456789",
        "f" * 24,
    )
    assert submits == [receipt]


def test_qgeo_definite_completion_rejection_remains_rollbackable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _qgeo_profile(tmp_path)
    candidate = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/belilovsky/qazgeo@{DIGEST}",
    }
    restored = profile.rollback_release
    assert restored is not None
    receipt = AGENT._completion_receipt(
        profile,
        candidate,
        restored,
        readiness={"app": "ok", "public": "ok"},
    )
    monkeypatch.setattr(
        AGENT,
        "_submit_completion",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(AGENT.AgentError("rejected")),
    )
    monkeypatch.setattr(
        AGENT,
        "_read_controller_status",
        lambda *_args, **_kwargs: {"status": "accepted"},
    )

    with pytest.raises(AGENT.CompletionRejected):
        AGENT._resolve_completion(
            object(),
            profile,
            "release-1",
            candidate,
            restored,
            receipt,
            "lease-0123456789",
            "f" * 24,
        )


def test_qgeo_verified_completion_journal_failure_never_rolls_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _qgeo_profile(tmp_path)
    candidate = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/belilovsky/qazgeo@{DIGEST}",
    }
    restored = profile.rollback_release
    assert restored is not None
    job = _qgeo_job(profile, candidate)
    config = _qgeo_config(tmp_path)
    writes: list[str] = []
    rollback_calls: list[object] = []

    def fake_request(
        _config: object,
        method: str,
        _path: str,
        _payload: object = None,
        **_kwargs: object,
    ) -> tuple[int, bytes]:
        if method == "GET":
            return 200, json.dumps(job).encode()
        return 200, b"{}"

    def fake_pending(_config: object, document: dict[str, object]) -> None:
        phase = str(document["phase"])
        writes.append(phase)
        if phase == "completion_confirmed":
            raise OSError("fsync failed")

    monkeypatch.setattr(AGENT, "read_state", lambda *_args: (restored, restored))
    monkeypatch.setattr(AGENT, "_recover_pending", lambda *_args: None)
    monkeypatch.setattr(AGENT, "heartbeat", lambda *_args: {"capacity_free_gib": 40})
    monkeypatch.setattr(AGENT, "request", fake_request)
    monkeypatch.setattr(AGENT, "verify_image", lambda *_args: None)
    monkeypatch.setattr(AGENT, "materialize_static", lambda *_args: None)
    monkeypatch.setattr(AGENT, "_compose", lambda *_args: None)
    monkeypatch.setattr(
        AGENT,
        "runtime_proof",
        lambda *_args: {"readiness": {"app": "ok", "public": "ok"}},
    )
    monkeypatch.setattr(AGENT, "_resolve_completion", lambda *_args: None)
    monkeypatch.setattr(AGENT, "_write_pending", fake_pending)
    monkeypatch.setattr(
        AGENT, "_managed_rollback", lambda *_args, **_kwargs: rollback_calls.append(object())
    )

    with pytest.raises(AGENT.ControllerOutcomeUnresolved, match="journal finalization"):
        AGENT.run_once(config, profile)
    assert writes == ["prepared", "completion_submitting", "completion_confirmed"]
    assert rollback_calls == []


def test_qgeo_restart_finishes_local_state_after_verified_completion(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _qgeo_profile(tmp_path)
    candidate = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/belilovsky/qazgeo@{DIGEST}",
    }
    restored = profile.rollback_release
    assert restored is not None
    receipt = AGENT._completion_receipt(
        profile,
        candidate,
        restored,
        readiness={"app": "ok", "public": "ok"},
    )
    pending = {
        "phase": "completion_submitting",
        "release_id": "release-1",
        "lease_id": "lease-0123456789",
        "fence": "f" * 24,
        "candidate": candidate,
        "previous_active": restored,
        "previous_rollback": restored,
        "runtime_receipt": receipt,
    }
    state_writes: list[tuple[dict[str, str], dict[str, str]]] = []
    cleared: list[bool] = []
    config = AGENT.Config(
        "https://worker.ci.qdev.run",
        tmp_path / "client.crt",
        tmp_path / "client.key",
        tmp_path / "controller-ca.crt",
        tmp_path / "state.json",
        tmp_path / "agent.lock",
        None,
        None,
    )
    monkeypatch.setattr(AGENT, "_read_pending", lambda *_args: pending)
    monkeypatch.setattr(
        AGENT,
        "_read_controller_status",
        lambda *_args: {"status": "verified", "runtime_receipt": receipt},
    )
    monkeypatch.setattr(AGENT, "runtime_proof", lambda *_args: {"readiness": {}})
    monkeypatch.setattr(
        AGENT,
        "write_state",
        lambda _path, active, rollback: state_writes.append((active, rollback)),
    )
    monkeypatch.setattr(AGENT, "_clear_pending", lambda *_args: cleared.append(True))

    result = AGENT._recover_pending(config, profile, restored, restored)
    assert result == {
        "status": "verified",
        "release_id": "release-1",
        "recovered": True,
        **candidate,
    }
    assert state_writes == [(candidate, restored)]
    assert cleared == [True]


def test_legacy_completion_keeps_optional_fencing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    profile = AGENT.PROFILES["qaz-events"]
    release = {
        "source_sha": SHA,
        "artifact_digest": DIGEST,
        "artifact_ref": f"registry.ci.qdev.run/{profile.repository}@{DIGEST}",
    }
    receipt = AGENT._completion_receipt(
        profile,
        release,
        release,
        readiness={"app": "ok", "public": "ok"},
    )
    seen: list[dict[str, str] | None] = []

    def fake_request(*_args: object, **kwargs: object) -> tuple[int, bytes]:
        seen.append(kwargs.get("headers"))
        return 200, json.dumps(receipt, sort_keys=True, separators=(",", ":")).encode()

    monkeypatch.setattr(AGENT, "request", fake_request)
    AGENT._submit_completion(object(), profile, "release-1", receipt, lease_id=None, fence=None)
    assert seen == [{}]
