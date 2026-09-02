from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_controller_activation_is_targeted_and_rollback_aware() -> None:
    script = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")

    assert "broker-public broker-internal" in script
    assert "--no-deps" in script
    assert script.count("--force-recreate") == 3
    assert "compose down" not in script
    assert "systemctl" not in script
    assert "mv -Tf" in script
    assert "rollback" in script
    assert "QDEV_CONTROLLER_MIN_FREE_GIB:-30" in script
    assert "QDEV_CONTROLLER_MAX_DISK_USED_PCT:-85" in script
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
    assert "scripts/provision_operator_identity.sh" in script
    assert "scripts/qaz_tours_release_host_agent.py" in script
    assert "deploy/qdev-release-qaz-tours.service" in script
    assert '"$release/config/profiles.yml" /etc/qdev-runner/profiles.yml' in script
    assert '"$release/config/release-lanes.yml" /etc/qdev-runner/release-lanes.yml' in script
    assert '"$profiles_backup" /etc/qdev-runner/profiles.yml' in script
    assert 'operations_root="${QDEV_OPERATIONS_ROOT:-/var/lib/qdev-runner/operations}"' in script
    assert (
        'release_jobs_root="${QDEV_RELEASE_JOBS_ROOT:-/var/lib/qdev-runner/release-jobs}"' in script
    )
    assert 'runtime_uid="${QDEV_CONTROLLER_RUNTIME_UID:-9020}"' in script
    assert 'runtime_gid="${QDEV_CONTROLLER_RUNTIME_GID:-9020}"' in script
    assert 'install -d -o "$runtime_uid" -g "$runtime_gid" -m 0700' in script
    assert 'for durable_root in "$operations_root" "$release_jobs_root"; do' in script
    assert 'stat -c %u -- "$durable_root"' in script
    assert 'stat -c %g -- "$durable_root"' in script
    assert "restore_operator_identity_metadata()" in script
    assert '"$release/scripts/provision_operator_identity.sh"' in script
    assert "operator mTLS identity is not usable" in script


def test_controller_provisions_only_the_operator_identity_permissions() -> None:
    script = (ROOT / "scripts/provision_operator_identity.sh").read_text(encoding="utf-8")
    provisioning = (ROOT / "scripts/provision_controller.sh").read_text(encoding="utf-8")

    assert "operator-key.pem" in script
    assert "never creates, reads, copies, or rotates key material" in script
    assert "-L \"$path\"" in script
    assert "install -d -o root -g 9020 -m 0750" in script
    assert "chown root:9020" in script
    assert "chmod 0640" in script
    assert "/etc/qdev-runner/mtls/operator" in provisioning


def test_controller_activation_publishes_revertible_exact_release_status() -> None:
    script = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")

    assert "controller-release.json" in script
    assert "QDEV_CONTROLLER_RELEASE_REVISION" in script
    assert "write_release_status()" in script
    assert "restore_release_status()" in script
    assert "controller_release_receipt=active" in script
    assert "for release_file in" in script
    assert '"$release/scripts/qaz_tours_release_host_agent.py"' in script
    assert '"$release/deploy/qdev-release-qaz-tours.service"' in script
    assert 'sha256sum -- "$release_file"' in script
    assert script.index('if ! "${compose[@]}" "${compose_action[@]}"; then') < script.index(
        "if ! write_release_status; then"
    )


def test_controller_rollback_reuses_existing_images() -> None:
    script = (ROOT / "scripts/rollback_controller_release.sh").read_text(encoding="utf-8")

    assert "QDEV_CONTROLLER_NO_BUILD=true" in script


def test_controller_compose_project_is_namespaced() -> None:
    compose = (ROOT / "deploy/compose.yml").read_text(encoding="utf-8")
    service = (ROOT / "deploy/qdev-runner-broker.service").read_text(encoding="utf-8")

    assert compose.startswith("name: qdev-runner\n")
    assert service.count("--project-name qdev-runner") == 2


def test_internal_broker_is_not_host_published_or_its_own_mtls_terminator() -> None:
    compose = (ROOT / "deploy/compose.yml").read_text(encoding="utf-8")

    internal = compose.split("  broker-internal:", 1)[1].split("  registry:", 1)[0]
    assert "network_mode: host" not in internal
    assert "- qdev_runner_internal" in internal
    assert "QDEV_TLS_CERT" not in internal
    assert "QDEV_TLS_KEY" not in internal
    assert "QDEV_TLS_CLIENT_CA" not in internal
    assert "qdev_runner_internal:" in compose
    assert "internal: true" in compose


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
