import importlib.util
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_recovery_binding_provisioner():
    path = ROOT / "scripts/provision_worker_recovery_bindings.py"
    spec = importlib.util.spec_from_file_location("recovery_binding_provisioner", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_controller_activation_is_targeted_and_rollback_aware() -> None:
    script = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")

    assert "broker-public broker-internal" in script
    assert "--no-deps" in script
    assert script.count("--force-recreate") == 3
    assert "compose down" not in script
    assert "systemctl daemon-reload" in script
    assert "systemctl enable --now qdev-fleet-host-dispatch.path" in script
    assert "mv -Tf" in script
    assert "rollback" in script
    assert "QDEV_CONTROLLER_MIN_FREE_GIB:-8" in script
    assert "QDEV_CONTROLLER_MAX_DISK_USED_PCT:-94" in script
    assert "QDEV_CONTROLLER_ALLOW_BUILD_CAPACITY_OVERRIDE" in script
    assert (
        "capacity overrides require QDEV_CONTROLLER_NO_BUILD=true or an explicit build override"
        in script
    )
    assert "min_free_gib * 1048576" in script
    assert "previous_public_image" in script
    assert "previous_internal_image" in script
    assert "compose -p qdev-runner" in script
    assert "compose -p deploy" not in script
    assert "qdev-runner-broker-internal" in script
    assert "deploy-broker-internal-1" not in script
    assert 'docker image tag "$previous_public_image"' in script
    assert 'docker image tag "$previous_internal_image"' in script
    assert 'rollback_public_ref="qdev-runner-rollback-public:$$"' in script
    assert 'rollback_internal_ref="qdev-runner-rollback-internal:$$"' in script
    assert 'docker image tag "$rollback_public_ref" "$previous_public_ref"' in script
    assert 'docker image tag "$rollback_internal_ref" "$previous_internal_ref"' in script
    assert "cleanup_rollback_images" in script
    assert "config/profiles.yml" in script
    assert "config/release-lanes.yml" in script
    assert "config/fleet-bootstrap.yml" in script
    assert "config/managed-registry.yml" in script
    assert "config/admin-platform-ledger.yml" not in script
    assert "config/admin-platform-ledger-v2.yml" not in script
    assert "config/managed-release-ledger.yml" in script
    assert "scripts/provision_operator_identity.sh" in script
    assert "scripts/qaz_tours_release_host_agent.py" in script
    assert "deploy/qdev-release-qaz-tours.service" in script
    assert "scripts/qdev_product_release_host_agent.py" in script
    assert "deploy/qdev-release-qaz-fund.service" in script
    assert "deploy/qdev-release-qaz-events.service" in script
    assert "deploy/qdev-release-qmt.service" in script
    assert "deploy/qdev-release-qmt.compose.yml" in script
    assert "scripts/qdev_admin_platform_release_host_agent.py" in script
    assert "deploy/qdev-release-ortcom.service" in script
    assert "deploy/qdev-release-cmnt.service" in script
    assert "deploy/qdev-release-total.service" in script
    assert "deploy/qdev-release-qazposter.service" in script
    assert "scripts/dispatch_fleet_bootstrap.py" in script
    assert "scripts/bootstrap_admin_platform_ledger_v3.py" in script
    assert "scripts/prepare_controller_candidate.py" in script
    assert "src/qdev_runner/controller_candidate.py" in script
    assert "scripts/qdev_controller_activation_adapter.py" in script
    assert "scripts/qdev_release_host_agent_enrol_adapter.py" in script
    assert "scripts/qdev_fleet_worker_recovery_adapter.py" in script
    assert "src/qdev_runner/durable_state.py" in script
    assert "scripts/qdev_runner_recovery_host_agent.py" in script
    assert "scripts/install_qdev_runner_recovery_host_agent.sh" in script
    assert "scripts/issue_scoped_worker_certificate.sh" in script
    assert "scripts/provision_fleet_host_dispatch_state.py" in script
    assert "deploy/qdev-runner-recovery-platform.service" in script
    assert "deploy/qdev-runner-recovery-qazstack.service" in script
    assert "/usr/local/sbin/qdev-controller-activate" in script
    assert "/usr/local/sbin/qdev-release-host-agent-enrol" in script
    assert "/usr/local/sbin/qdev-fleet-worker-recovery" in script
    assert "/usr/local/sbin/qdev-fleet-host-dispatch-state-provision" in script
    assert "deploy/qdev-fleet-host-dispatch.service" in script
    assert "deploy/qdev-fleet-host-dispatch.path" in script
    assert '"$release/config/profiles.yml" /etc/qdev-runner/profiles.yml' in script
    assert '"$release/config/release-lanes.yml" /etc/qdev-runner/release-lanes.yml' in script
    assert '"$release/config/fleet-bootstrap.yml" /etc/qdev-runner/fleet-bootstrap.yml' in script
    assert '"$release/config/managed-registry.yml" /etc/qdev-runner/managed-registry.yml' in script
    assert 'rollback_mode="${QDEV_CONTROLLER_ROLLBACK:-false}"' in script
    assert 'if [[ "$rollback_mode" != true ]]; then' in script
    assert "qdev-controller-rollback-anchor-v1" in script
    assert "controller rollback anchor ownership or permissions are unsafe" in script
    assert "stat.S_IMODE(metadata.st_mode) != 0o600" in script
    assert "validate_durable_admin_platform_ledger()" in script
    assert "durable Admin Platform v3 ledger is missing" in script
    assert "root-controlled exact-candidate migration" in script
    assert "will not install a packaged snapshot" in script
    assert "intentionally neither installed nor" in script
    assert "admin_platform_ledger_backup" not in script
    assert (
        '"$release/config/managed-release-ledger.yml" /etc/qdev-runner/managed-release-ledger.yml'
        in script
    )
    assert '"$profiles_backup" /etc/qdev-runner/profiles.yml' in script
    assert '"$fleet_bootstrap_backup" /etc/qdev-runner/fleet-bootstrap.yml' in script
    assert 'operations_root="${QDEV_OPERATIONS_ROOT:-/var/lib/qdev-runner/operations}"' in script
    assert (
        'release_jobs_root="${QDEV_RELEASE_JOBS_ROOT:-/var/lib/qdev-runner/release-jobs}"' in script
    )
    assert 'runtime_uid="${QDEV_CONTROLLER_RUNTIME_UID:-9020}"' in script
    assert 'runtime_gid="${QDEV_CONTROLLER_RUNTIME_GID:-9020}"' in script
    assert 'install -d -o "$runtime_uid" -g "$runtime_gid" -m 0700' in script
    assert '"$operations_root" \\\n' in script
    assert '"$release_jobs_root" \\\n' in script
    assert '"$broker_state_root" \\\n' in script
    assert '"$control_state_root" \\\n' in script
    assert '"$admin_platform_receipt_root" \\\n' in script
    assert '"$artifact_root"; do' in script
    assert 'stat -c %u -- "$durable_root"' in script
    assert 'stat -c %g -- "$durable_root"' in script
    assert "ensure_artifact_token_key()" in script
    assert "prepare_broker_state()" in script
    assert "legacy and canonical controller state conflict" in script
    assert "legacy claim-scope stores disagree" in script
    assert "restore_operator_identity_metadata()" in script
    assert '"$release/scripts/provision_operator_identity.sh"' in script
    assert "operator mTLS identity is not usable" in script


def test_controller_provisions_only_the_operator_identity_permissions() -> None:
    script = (ROOT / "scripts/provision_operator_identity.sh").read_text(encoding="utf-8")
    provisioning = (ROOT / "scripts/provision_controller.sh").read_text(encoding="utf-8")

    assert "operator-key.pem" in script
    assert "never creates, reads, copies, or rotates key material" in script
    assert '-L "$path"' in script
    assert "install -d -o root -g 9020 -m 0750" in script
    assert "chown root:9020" in script
    assert "chmod 0640" in script
    assert "/etc/qdev-runner/mtls/operator" in provisioning
    assert "scripts/bootstrap_admin_platform_ledger_v3.py" in provisioning
    assert "/usr/local/sbin/qdev-admin-platform-ledger-bootstrap" in provisioning
    assert "/var/lib/qdev-runner/admin-platform-bootstrap" in provisioning
    assert "/var/lib/qdev-runner/admin-platform-ledger-migrations" in provisioning
    assert "install -d -o root -g 9020 -m 0750 /var/lib/qdev-runner" in provisioning
    assert "/var/lib/qdev-runner/controller-status" in provisioning
    assert "/var/lib/qdev-runner/admin-platform-state" in provisioning
    assert "/var/lib/qdev-runner/controller-status-migrations" in provisioning


def test_controller_provisions_root_owned_admission_signer() -> None:
    provisioning = (ROOT / "scripts/provision_controller.sh").read_text(encoding="utf-8")
    activation = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")
    wrapper = (ROOT / "scripts/qdev_controller_admission_host.sh").read_text(
        encoding="utf-8"
    )

    assert "/etc/qdev-runner/admission" in provisioning
    assert "/run/qdev-controller" in provisioning
    assert "/usr/local/sbin/qdev-controller-admission" in provisioning
    assert "scripts/qdev_controller_admission_host.sh" in activation
    assert "admission_host_tool_backup" in activation
    assert "admission_host_tool_was_present" in activation
    assert "--network none" in wrapper
    assert "--read-only" in wrapper
    assert "--user 0:0" in wrapper
    assert "--cap-drop ALL" in wrapper
    assert "qdev-runner-broker-internal" in wrapper
    assert "--entrypoint qdev-controller-admission" in wrapper


def test_controller_provisions_and_activates_qazcoop_release_guard() -> None:
    provisioning = (ROOT / "scripts/provision_controller.sh").read_text(encoding="utf-8")
    activation = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")

    assert "scripts/provision_qazcoop_release_signing_key.py" in provisioning
    assert "/etc/qdev-runner/qazcoop-release-signing" in provisioning
    assert "install_qazcoop_release_guard()" in activation
    assert "scripts/build_qazcoop_release_guard_bundle.py" in activation
    assert "scripts/install_qazcoop_release_guard.py" in activation
    assert "-o StrictHostKeyChecking=yes" in activation
    assert activation.index("if ! verify_controller_runtime_health; then") < activation.index(
        "if ! install_qazcoop_release_guard; then"
    )
    guard_function = activation.split("install_qazcoop_release_guard() {", 1)[1].split(
        "\n}\n", 1
    )[0]
    assert '[[ "$rollback_mode" != true ]] || return 0' in guard_function
    assert "currently deployed product remains available" in guard_function


def test_controller_activation_publishes_revertible_exact_release_status() -> None:
    script = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")

    assert "controller-release.json" in script
    assert "QDEV_CONTROLLER_RELEASE_REVISION" in script
    assert "controller activation requires a source-bound git release checkout" in script
    assert 'git -C "$release" diff --quiet "$release_revision" -- .' in script
    assert "controller release contains untracked files" in script
    assert "write_release_status()" in script
    assert "restore_release_status()" in script
    assert "validate_previous_release_status()" in script
    assert "controller_release_receipt=active" in script
    assert "qdev-controller-release-status-v2" in script
    assert "runtime_identity" in script
    assert "dependency_identity" in script
    assert "measure_runtime_identity()" in script
    assert "docker exec qdev-runner-broker-public" in script
    assert "docker exec qdev-runner-broker-internal" in script
    assert "public_image_id" in script
    assert "internal_image_id" in script
    assert "python3 -m qdev_runner.controller_release" in script
    assert 'release_digest="$anchor_release_digest"' in script
    assert script.index('if ! "${compose[@]}" "${compose_action[@]}"; then') < script.index(
        "if ! write_release_status; then"
    )
    assert script.index("if ! measure_runtime_identity; then") < script.index(
        "if ! write_release_status; then"
    )
    assert script.index("if ! write_release_status; then") < script.index(
        "if ! verify_controller_runtime_health; then"
    )
    assert "qdev-controller-release-status-v1" in script
    assert 'urllib.request.urlopen("https://ci.qdev.run/health", timeout=5)' in script
    assert "legacy public health is not bound to the active revision" in script
    rollback = script.split("rollback() {", 1)[1].split("\n}\n\nif !", 1)[0]
    previous_rollback = rollback.split('activate_link "$previous"', 1)[1]
    assert previous_rollback.index("up -d --force-recreate --no-build") < previous_rollback.index(
        "restore_release_status"
    )
    assert "docker rm -f qdev-runner-broker-public qdev-runner-broker-internal" in rollback
    assert 'rm -f -- "$current"' in rollback
    assert "rollback restored an unexpected public broker image" in rollback
    assert "rollback restored an unexpected internal broker image" in rollback
    assert "rollback runtime does not satisfy the previous controller receipt" in rollback


def test_controller_forward_activation_is_serialized_and_compare_and_swap_bound() -> None:
    script = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")

    assert "QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION" in script
    assert "activation requires QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION" in script
    assert 'release_lock_path="${QDEV_CONTROLLER_RELEASE_LOCK:-/run/lock/' in script
    assert "flock -n 9" in script
    assert "read_active_release_revision()" in script
    assert "qdev-controller-release-status-v1" in script
    assert "qdev-controller-release-status-v2" in script
    assert "controller release compare-and-swap rejected" in script
    assert script.count("assert_expected_current_revision") == 3
    assert script.index("assert_expected_current_revision\n# Forward activation") < script.index(
        'install -d -o "$runtime_uid" -g "$runtime_gid"'
    )
    assert script.index("# Recheck at the last non-mutating boundary") < script.index(
        'install -m 0644 -- "$release/inventory/repos.json"'
    )
    assert "metadata.st_uid != runtime_uid" in script
    assert "metadata.st_gid != runtime_gid" in script
    assert "stat.S_IMODE(metadata.st_mode) != 0o600" in script


def test_controller_rollback_reuses_existing_images() -> None:
    script = (ROOT / "scripts/rollback_controller_release.sh").read_text(encoding="utf-8")
    activation = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")

    assert "^[0-9a-f]{40}$" in script
    assert "QDEV_CONTROLLER_NO_BUILD=true" in script
    assert "QDEV_CONTROLLER_ROLLBACK=true" in script
    assert 'QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION="$current_revision"' in script
    assert 'rollback_anchor_path="${QDEV_CONTROLLER_ROLLBACK_ANCHOR:-' in activation
    assert "qdev-controller-rollback-anchor-v1" in activation
    assert "metadata.st_uid != 0" in activation
    assert "stat.S_IMODE(metadata.st_mode) != 0o600" in activation
    assert "prepare_saved_rollback_images()" in activation
    assert "saved controller rollback images do not match the anchor" in activation
    assert 'docker image tag "$anchor_public_saved_ref" "$anchor_public_image_ref"' in activation
    assert (
        'docker image tag "$anchor_internal_saved_ref" "$anchor_internal_image_ref"' in activation
    )


def test_controller_rollback_accepts_clean_historical_anchor_without_modern_dispatcher() -> None:
    activation = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")

    base_required = activation.split("required=(", 1)[1].split(")\nif [[", 1)[0]
    forward_marker = 'if [[ "$rollback_mode" != true ]]; then\n  required+=('
    forward_required = activation.split(forward_marker, 1)[1].split("\n  )", 1)[0]
    for modern_path in (
        "config/controller-capacity.json",
        "scripts/bootstrap_admin_platform_ledger_v3.py",
        "scripts/prepare_controller_candidate.py",
        "scripts/dispatch_fleet_bootstrap.py",
        "deploy/qdev-fleet-host-dispatch.service",
        "deploy/qdev-fleet-host-dispatch.path",
    ):
        assert modern_path not in base_required
        assert modern_path in forward_required

    assert 'if [[ -z "$detected_release_root" ||' in activation
    assert 'git -C "$release" diff --quiet "$release_revision" -- .' in activation
    assert 'git -C "$release" ls-files --others --exclude-standard -- .' in activation

    install_call = activation.split("if ! prepare_broker_state; then", 1)[1].split(
        'if ! "${compose[@]}"', 1
    )[0]
    assert install_call.count('if [[ "$rollback_mode" != true ]]; then') == 1
    assert install_call.count("if ! install_fleet_host_dispatch; then") == 1


def test_historical_controller_rollback_does_not_require_or_replace_admission_wrapper() -> None:
    script = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")

    base_required = script.split("required=(", 1)[1].split(")\nif [[", 1)[0]
    forward_required = script.split(
        'if [[ "$rollback_mode" != true ]]; then\n  required+=(', 1
    )[1].split("\n  )", 1)[0]
    assert "qdev_controller_admission_host.sh" not in base_required
    assert "scripts/qdev_controller_admission_host.sh" in forward_required
    assert "scripts/build_qazcoop_release_guard_bundle.py" in forward_required
    assert (
        'if [[ "$rollback_mode" != true ]]; then\n'
        '  install -d -o root -g root -m 0700 /etc/qdev-runner/admission /run/qdev-controller'
    ) in script


def test_controller_compose_project_is_namespaced() -> None:
    compose = (ROOT / "deploy/compose.yml").read_text(encoding="utf-8")
    service = (ROOT / "deploy/qdev-runner-broker.service").read_text(encoding="utf-8")

    assert compose.startswith("name: qdev-runner\n")
    assert service.count("--project-name qdev-runner") == 2


def test_recovery_binding_provisioner_is_installed_without_exposing_secrets() -> None:
    provision = (ROOT / "scripts/provision_controller.sh").read_text(encoding="utf-8")
    helper = (ROOT / "scripts/provision_worker_recovery_bindings.py").read_text(
        encoding="utf-8"
    )

    assert "qdev-worker-recovery-bindings-provision" in provision
    assert "recovery-controller.env" in helper
    assert "recovery-edge.env" in helper
    assert '"QDEV_OPERATOR_PROXY_SECRET": proxy_secret' in helper
    assert '"QDEV_RECOVERY_AGENT_SIGNING_KEY": signing_key' in helper
    assert "secrets_rotated" in helper


def test_recovery_binding_provisioner_accepts_active_prefixed_release_digest(
    tmp_path: Path,
) -> None:
    helper = _load_recovery_binding_provisioner()
    status = tmp_path / "controller-release.json"
    status.write_text(
        json.dumps(
            {
                "state": "active",
                "revision": "a" * 40,
                "release_digest": "sha256:" + "b" * 64,
            }
        ),
        encoding="utf-8",
    )

    assert helper._active_release(status) == {
        "revision": "a" * 40,
        "release_digest": "b" * 64,
    }


def test_controller_atomically_replaced_records_use_directory_mounts() -> None:
    compose = (ROOT / "deploy/compose.yml").read_text(encoding="utf-8")
    activation = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")
    public = compose.split("  broker-public:", 1)[1].split("  broker-internal:", 1)[0]

    assert "/etc/qdev-runner/controller-release.json:" not in compose
    assert "/etc/qdev-runner/admin-platform-ledger.yml:" not in compose
    assert "/var/lib/qdev-runner/controller-status:" in compose
    assert "/var/lib/qdev-runner/controller-status:" in public
    assert "/var/lib/qdev-runner/admin-platform-state:" in compose
    assert "QDEV_CONTROLLER_RELEASE_STATUS: /var/lib/qdev-runner/controller-status/" in compose
    assert "QDEV_ADMIN_PLATFORM_LEDGER: /var/lib/qdev-runner/admin-platform-state/" in compose
    assert 'python3 -I "$durable_state_helper"' in activation
    assert "controller durable-state parent ownership or permissions are unsafe" in activation


def test_internal_broker_is_not_host_published_or_its_own_mtls_terminator() -> None:
    compose = (ROOT / "deploy/compose.yml").read_text(encoding="utf-8")

    internal = compose.split("  broker-internal:", 1)[1].split("  registry:", 1)[0]
    assert "network_mode: host" not in internal
    assert "- qdev_runner_internal" in internal
    assert "- qdev_runner_egress" in internal
    assert "QDEV_TLS_CERT" not in internal
    assert "QDEV_TLS_KEY" not in internal
    assert "QDEV_TLS_CLIENT_CA" not in internal
    assert "qdev_runner_internal:" in compose
    assert "internal: true" in compose
    assert "qdev_runner_egress:" in compose


def test_registry_keeps_human_account_separate_from_job_account() -> None:
    caddyfile = (ROOT / "deploy/Caddyfile").read_text(encoding="utf-8")

    assert "qdev {$QDEV_REGISTRY_PASSWORD_HASH}" in caddyfile
    assert "qdev-runner {$QDEV_RUNNER_REGISTRY_PASSWORD_HASH}" in caddyfile


def test_controller_defers_public_worker_route_to_source_owned_edge() -> None:
    caddyfile = (ROOT / "deploy/Caddyfile").read_text(encoding="utf-8")

    assert "worker.ci.qdev.run" not in caddyfile


def test_edge_proxy_issuer_keeps_credential_local_and_short_lived() -> None:
    script = (ROOT / "scripts/issue_edge_proxy_certificate.sh").read_text(encoding="utf-8")

    assert "a worker credential" in script
    assert "openssl genpkey -algorithm ED25519" in script
    assert "-days 1" in script
    assert "extendedKeyUsage=critical,clientAuth" in script
    assert "refusing to overwrite existing edge proxy credential material" in script
    assert "install -o root -g root -m 0600" in script


def test_scoped_certificate_issuer_accepts_only_public_csr_and_short_client_certificate() -> None:
    script = (ROOT / "scripts/issue_scoped_worker_certificate.sh").read_text(encoding="utf-8")

    assert "The private key is created on the worker" in script
    assert "openssl genrsa" not in script
    assert "-days 1" in script
    assert "extendedKeyUsage=critical,clientAuth" in script
    assert '-CAkey "$ca_dir/ca-key.pem"' in script
    assert "refusing to overwrite an existing certificate" in script
