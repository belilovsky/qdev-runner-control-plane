"""Provider/CI fixtures, not evidence of real IdP acceptance or admission."""

import copy
import hashlib
import json
import os

import pytest
from test_file_apply_authorization import NOW
from test_file_apply_authorization import fixture as binding_fixture

from qdev_runner.file_apply_authorization import canonical_bytes
from qdev_runner.idp_file_evidence import QUALITY_STEPS, observe_idp_ci
from qdev_runner.release_lane import ReleaseLaneError


class Provider:
    def __init__(self, binding):
        self.calls = []
        self.run_reads = 0
        self.mutate_after_archive = False
        self.runs = {}
        self.jobs = {}
        for key in ("quality", "runner_contract"):
            ci = binding["ci_observation"][key]
            quality = key == "quality"
            self.runs[ci["run_id"]] = {
                "id": ci["run_id"],
                "run_attempt": ci["attempt"],
                "head_sha": ci["source_sha"],
                "repository": {"full_name": binding["repository"]},
                "head_repository": {"full_name": binding["repository"]},
                "path": f".github/workflows/{ci['workflow']}",
                "event": "pull_request",
                "status": "completed",
                "conclusion": "success",
            }
            suffix = "static-contracts" if quality else "contract"
            self.jobs[ci["job_id"]] = {
                "id": ci["job_id"],
                "run_id": ci["run_id"],
                "run_attempt": ci["attempt"],
                "head_sha": ci["source_sha"],
                "name": "static-contracts" if quality else "qdev-runner-contract",
                "status": "completed",
                "conclusion": "success",
                "started_at": ci["started_at"],
                "completed_at": ci["completed_at"],
                "labels": [
                    "self-hosted",
                    "Linux",
                    "X64",
                    ci["profile"],
                    f"qdev-job-{ci['run_id']}-{ci['attempt']}-{suffix}",
                ],
                "steps": [
                    {"name": name, "status": "completed", "conclusion": "success"}
                    for name in (QUALITY_STEPS if quality else ("Validate QDev runner contract",))
                ],
            }
        self.log = (
            b"2026-09-05T11:00:00.1234567Z QDEV_IDP_CI_BUNDLE "
            + json.dumps(binding["ci_observation"]["artifact"]).encode()
            + b"\n"
        )

    def repository_installation_id(self, repository):
        assert repository == "belilovsky/id-qdev-run"
        self.calls.append("installation")
        return 7

    def workflow_run(self, installation, repository, run_id):
        self.calls.append("run")
        self.run_reads += 1
        run = copy.deepcopy(self.runs[run_id])
        if self.mutate_after_archive and self.run_reads > 2:
            run["run_attempt"] += 1
        return run

    def workflow_run_attempt(self, installation, repository, run_id, attempt):
        self.calls.append("attempt")
        return copy.deepcopy(self.runs[run_id])

    def workflow_job(self, installation, repository, job_id):
        self.calls.append("job")
        return copy.deepcopy(self.jobs[job_id])

    def workflow_job_log(self, installation, repository, job_id):
        self.calls.append("log")
        return self.log


@pytest.fixture
def observation_fixture(tmp_path):
    binding, _, _, _ = binding_fixture.__wrapped__()
    root = tmp_path.resolve() / "artifacts"
    archive = root / binding["ci_observation"]["artifact"]["storage_key"]
    archive.parent.mkdir(parents=True)
    archive.write_bytes(b"test fixture outer archive, not a deployable bundle")
    archive.chmod(0o600)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    binding["ci_observation"]["artifact"]["artifact_sha256"] = digest
    return binding, Provider(binding), root, archive


def observe(data, clock=lambda: NOW):
    binding, provider, root, _ = data
    return observe_idp_ci(
        canonical_bytes(binding), github=provider, artifact_root=root, clock=clock
    )


def test_provider_observation_reads_actual_archive_and_rechecks_current_attempt(
    observation_fixture,
):
    result = observe(observation_fixture)
    provider = observation_fixture[1]
    assert (
        provider.calls
        == ["installation"]
        + ["run", "attempt", "job"] * 2
        + ["log"]
        + ["run", "attempt", "job"] * 2
    )
    assert result["status"] == "provider_ci_archive_verified"
    assert result["archive_size"] == observation_fixture[3].stat().st_size
    for field in ("controller_admission", "native_runtime", "bundle_components", "rollback"):
        assert result[field] == "not_verified"
    assert result["acceptance"] == "not_run"
    assert "snapshot_sha256" not in json.dumps(result)
    assert "ci-0123456789abcdef.json" not in json.dumps(result)


@pytest.mark.parametrize(
    "key,value",
    [
        ("status", "queued"),
        ("conclusion", "failure"),
        ("head_sha", "f" * 40),
        ("run_attempt", 2),
        ("id", True),
        ("repository", None),
        ("head_repository", {"full_name": "someone/else"}),
        ("path", ".github/workflows/smoke.yml"),
        ("event", "workflow_dispatch"),
    ],
)
def test_rejects_false_provider_run(observation_fixture, key, value):
    observation_fixture[1].runs[1][key] = value
    with pytest.raises(ReleaseLaneError):
        observe(observation_fixture)
    assert "log" not in observation_fixture[1].calls


@pytest.mark.parametrize(
    "key,value",
    [
        ("status", "queued"),
        ("conclusion", "failure"),
        ("head_sha", "f" * 40),
        ("run_attempt", True),
        ("run_id", 9),
        ("id", 9),
        ("name", "smoke"),
        ("labels", ["qdev-ci"]),
        ("steps", []),
        ("steps", None),
        ("started_at", "2020-01-01T00:00:00Z"),
    ],
)
def test_rejects_false_provider_job(observation_fixture, key, value):
    observation_fixture[1].jobs[2][key] = value
    with pytest.raises(ReleaseLaneError):
        observe(observation_fixture)


@pytest.mark.parametrize("mutation", ["skipped", "duplicate", "running"])
def test_rejects_nonterminal_or_duplicate_required_step(observation_fixture, mutation):
    steps = observation_fixture[1].jobs[2]["steps"]
    if mutation == "duplicate":
        steps.append(copy.deepcopy(steps[0]))
    elif mutation == "running":
        steps[0]["status"] = "in_progress"
    else:
        steps[0]["conclusion"] = "skipped"
    with pytest.raises(ReleaseLaneError):
        observe(observation_fixture)


def test_rejects_attempt_change_after_archive_observation(observation_fixture):
    observation_fixture[1].mutate_after_archive = True
    with pytest.raises(ReleaseLaneError, match="attempt mismatch"):
        observe(observation_fixture)
    assert "log" in observation_fixture[1].calls


@pytest.mark.parametrize("change", ["digest", "duplicate", "duplicate_key", "secret", "utf8"])
def test_rejects_untrusted_log_without_echoing_it(observation_fixture, change):
    provider = observation_fixture[1]
    if change == "digest":
        provider.log = provider.log.replace(b'"bundle_sha256": "b', b'"bundle_sha256": "c')
    elif change == "duplicate":
        provider.log *= 2
    elif change == "duplicate_key":
        provider.log = provider.log.replace(b'{"schema_version"', b'{"attempt": 1,"schema_version"')
    elif change == "secret":
        provider.log = b'QDEV_IDP_CI_BUNDLE {"client_secret":"fixture-sensitive-value"}'
    else:
        provider.log = b"\xff"
    with pytest.raises(ReleaseLaneError) as error:
        observe(observation_fixture)
    assert "fixture-sensitive-value" not in str(error.value)
    assert error.value.__cause__ is None


@pytest.mark.parametrize("change", ["bytes", "mode", "symlink", "parent_symlink", "hardlink"])
def test_rejects_unsafe_or_modified_archive(observation_fixture, change, tmp_path):
    archive = observation_fixture[3]
    if change == "bytes":
        archive.write_bytes(b"modified")
    elif change == "mode":
        archive.chmod(0o644)
    elif change == "hardlink":
        os.link(archive, tmp_path / "duplicate")
    elif change == "symlink":
        target = archive.with_suffix(".original")
        archive.rename(target)
        archive.symlink_to(target)
    else:
        target = archive.parent.with_name("original")
        archive.parent.rename(target)
        archive.parent.symlink_to(target, target_is_directory=True)
    with pytest.raises(ReleaseLaneError):
        observe(observation_fixture)


def test_rejects_stale_binding_before_network(observation_fixture):
    with pytest.raises(ReleaseLaneError):
        observe(observation_fixture, clock=lambda: NOW + 301)
    assert observation_fixture[1].calls == []


def test_rejects_verification_expiring_during_read(observation_fixture):
    times = iter((NOW, NOW + 301))
    with pytest.raises(ReleaseLaneError):
        observe(observation_fixture, clock=lambda: next(times))


def test_rejects_archive_mutation_during_hash(observation_fixture, monkeypatch):
    real_read = os.read
    mutated = False

    def changing_read(fd, count):
        nonlocal mutated
        chunk = real_read(fd, count)
        if chunk and not mutated:
            mutated = True
            observation_fixture[3].write_bytes(b"changed under reader")
        return chunk

    monkeypatch.setattr(os, "read", changing_read)
    with pytest.raises(ReleaseLaneError, match="changed during"):
        observe(observation_fixture)
