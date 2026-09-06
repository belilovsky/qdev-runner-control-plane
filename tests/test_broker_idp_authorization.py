"""Private endpoint with real journal, issuer and provider/archive verifier."""

import json
from dataclasses import asdict, replace

import pytest
import yaml
from fastapi.testclient import TestClient
from test_broker_surface import _settings
from test_file_apply_authorization import KEY, NOW
from test_idp_file_issuer import make_issuer

from qdev_runner.broker import create_app
from qdev_runner.file_apply_authorization import canonical_bytes
from qdev_runner.idp_file_issuer import MAX_NATIVE_OBSERVATION
from qdev_runner.policy import Policy
from qdev_runner.release_lane import ReleaseStore
from qdev_runner.store import Store


@pytest.fixture
def api(tmp_path, policy_files, monkeypatch):
    data = make_issuer(tmp_path)
    root = tmp_path.resolve()
    lane = asdict(data.lane)
    lane.pop("name")
    lane["runtime_endpoints"] = ["https://id.qdev.run/.well-known/qdev-release.json"]
    lane["required_readiness"] = list(lane["required_readiness"])
    policy_path = root / "lanes.yml"
    policy_path.write_text(
        yaml.safe_dump({"schema_version": "qdev-release-lanes-v2", "lanes": {data.lane.name: lane}})
    )
    key_file = root / "dispatch-key"
    key_file.write_bytes(KEY)
    key_file.chmod(0o600)
    key_map = root / "dispatch-keys.json"
    key_map.write_text(json.dumps({data.lane.host_agent_mtls_identity: str(key_file)}))
    key_map.chmod(0o600)
    inventory, profiles = policy_files
    settings = replace(
        _settings(root, inventory, profiles, surface="internal"),
        artifact_root=data.artifact_root,
        release_lanes_path=policy_path,
        release_jobs_root=data.store.root,
        release_host_dispatch_keys_file=key_map,
    )
    original = ReleaseStore.authorize_idp_file_apply

    def deterministic_clock(self, *args, **kwargs):
        return original(self, *args, **kwargs, clock=lambda: NOW)

    monkeypatch.setattr(ReleaseStore, "authorize_idp_file_apply", deterministic_clock)

    def factory(**overrides):
        current = replace(settings, **overrides)
        return create_app(
            current,
            store=Store(current.database_path),
            policy=Policy(inventory, profiles),
            github=data.provider,
        )

    data.factory = factory
    data.settings = settings
    data.key_file = key_file
    data.key_map = key_map
    data.url = (
        f"/internal/v1/release-hosts/{data.lane.placement}/jobs/"
        f"{data.claim['release_id']}/idp-file-authorization"
    )
    data.headers = {
        "X-QDev-mTLS-Identity": data.lane.host_agent_mtls_identity,
        "X-QDev-Release-Lease": data.claim["lease_id"],
        "X-QDev-Release-Fence": data.claim["fence"],
    }
    return data


def test_private_endpoint_observes_and_authorizes_existing_dispatch(api):
    before = api.store.operation_events(api.lane)
    with TestClient(api.factory()) as client:
        response = client.post(api.url, content=canonical_bytes(api.native), headers=api.headers)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["schema"] == "qdev-controller-idp-file-authorization-receipt-v1"
    assert result["dispatch_claim"] == api.claim
    assert result["acceptance"] == "not_run"
    assert api.store.operation_events(api.lane)[:-1] == before
    assert "log" in api.provider.calls
    assert KEY not in response.content


def test_native_map_in_trusted_config_root_with_separate_private_key_directory(api):
    config = api.key_map.parent / "native-config"
    config.mkdir(mode=0o755)
    secrets = config / "host-dispatch-secrets"
    secrets.mkdir(mode=0o700)
    key = secrets / "idp.secret"
    api.key_file.rename(key)
    mapping = config / "release-host-dispatch-keys.json"
    api.key_map.rename(mapping)
    mapping.write_text(json.dumps({api.lane.host_agent_mtls_identity: str(key)}))
    with TestClient(api.factory(release_host_dispatch_keys_file=mapping)) as client:
        response = client.post(api.url, content=canonical_bytes(api.native), headers=api.headers)
    assert response.status_code == 200, response.text
    assert config.stat().st_mode & 0o777 == 0o755
    assert secrets.stat().st_mode & 0o777 == 0o700


def test_map_parent_cannot_be_writable_by_other_users(api):
    config = api.key_map.parent / "unsafe-config"
    config.mkdir(mode=0o755)
    config.chmod(0o777)
    mapping = config / "release-host-dispatch-keys.json"
    api.key_map.rename(mapping)
    with TestClient(api.factory(release_host_dispatch_keys_file=mapping)) as client:
        response = client.post(api.url, content=canonical_bytes(api.native), headers=api.headers)
    assert response.status_code == 409
    assert not api.provider.calls


@pytest.mark.parametrize("identity", [None, "operator", "qdev-host-agent:other"])
def test_host_identity_precedes_body_and_key_lookup(api, identity):
    headers = dict(api.headers)
    if identity is None:
        headers.pop("X-QDev-mTLS-Identity")
    else:
        headers["X-QDev-mTLS-Identity"] = identity
    api.key_file.unlink()
    before = api.store.operation_events(api.lane)
    with TestClient(api.factory()) as client:
        response = client.post(api.url, content=b"untrusted", headers=headers)
    assert response.status_code == 403
    assert not api.provider.calls
    assert api.store.operation_events(api.lane) == before


def test_public_endpoint_hidden_even_for_configured_identity(api):
    with TestClient(api.factory(surface="public")) as client:
        response = client.post(api.url, content=canonical_bytes(api.native), headers=api.headers)
    assert response.status_code == 404
    assert not response.content
    assert not api.provider.calls


@pytest.mark.parametrize("field", ["X-QDev-Release-Lease", "X-QDev-Release-Fence"])
def test_no_admission_is_created_for_missing_lease_or_fence(api, field):
    headers = {key: value for key, value in api.headers.items() if key != field}
    before = api.store.operation_events(api.lane)
    with TestClient(api.factory()) as client:
        response = client.post(api.url, content=canonical_bytes(api.native), headers=headers)
    assert response.status_code == 409
    assert not api.provider.calls
    assert api.store.operation_events(api.lane) == before


@pytest.mark.parametrize("body", [b"private-fixture", b'{"secret":"private-fixture"}', b"\xff"])
def test_malformed_native_body_is_redacted(api, body):
    with TestClient(api.factory()) as client:
        response = client.post(api.url, content=body, headers=api.headers)
    assert response.status_code == 409
    assert response.json() == {"detail": "IdP file release was not authorized"}
    assert not api.provider.calls


def test_oversize_body_precedes_signing_key_and_provider(api):
    api.key_file.unlink()
    with TestClient(api.factory()) as client:
        response = client.post(
            api.url, content=b"x" * (MAX_NATIVE_OBSERVATION + 1), headers=api.headers
        )
    assert response.status_code == 413
    assert not api.provider.calls


@pytest.mark.parametrize("defect", ["missing", "symlink", "mode", "duplicate_map", "root"])
def test_unsafe_runtime_key_or_state_rejected_before_constructor(api, defect):
    sentinel = None
    if defect == "missing":
        api.key_file.unlink()
    elif defect == "symlink":
        api.key_map.unlink()
        api.key_map.symlink_to(api.key_file)
    elif defect == "mode":
        api.key_file.chmod(0o644)
    elif defect == "duplicate_map":
        identity = json.dumps(api.lane.host_agent_mtls_identity)
        path = json.dumps(str(api.key_file))
        api.key_map.write_text(f"{{{identity}:{path},{identity}:{path}}}")
    else:
        original = api.store.root
        sentinel = original.with_name("state-sentinel")
        original.rename(sentinel)
        sentinel.chmod(0o755)
        original.symlink_to(sentinel, target_is_directory=True)
    with TestClient(api.factory()) as client:
        response = client.post(api.url, content=canonical_bytes(api.native), headers=api.headers)
    assert response.status_code == 409
    assert not api.provider.calls
    assert KEY not in response.content
    if sentinel is not None:
        assert sentinel.stat().st_mode & 0o777 == 0o755


def test_queued_provider_ci_cannot_issue_authorization(api):
    api.provider.runs[1]["status"] = "queued"
    before = api.store.operation_events(api.lane)
    with TestClient(api.factory()) as client:
        response = client.post(api.url, content=canonical_bytes(api.native), headers=api.headers)
    assert response.status_code == 409
    assert api.store.operation_events(api.lane) == before


def test_other_release_id_does_not_reuse_current_dispatch(api):
    with TestClient(api.factory()) as client:
        response = client.post(
            api.url.replace(api.claim["release_id"], "release-other"),
            content=canonical_bytes(api.native),
            headers=api.headers,
        )
    assert response.status_code == 409
    assert not api.provider.calls
