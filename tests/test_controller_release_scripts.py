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
    assert "config/profiles.yml" in script
    assert "install_atomic()" in script
    assert 'install -m "$mode" -- "$source" "$temporary"' in script
    assert 'mv -f -- "$temporary" "$target"' in script
    assert (
        'install_atomic "$release/config/profiles.yml" /etc/qdev-runner/profiles.yml 0644'
        in script
    )
    assert 'install_atomic "$release/config/project-priority.json"' in script
    assert 'install_atomic "$profiles_backup" /etc/qdev-runner/profiles.yml 0644' in script
    assert 'install_atomic "$priority_backup" /etc/qdev-runner/project-priority.json 0644' in script


def test_controller_rollback_reuses_existing_images() -> None:
    script = (ROOT / "scripts/rollback_controller_release.sh").read_text(encoding="utf-8")

    assert "QDEV_CONTROLLER_NO_BUILD=true" in script


def test_controller_compose_project_is_namespaced() -> None:
    compose = (ROOT / "deploy/compose.yml").read_text(encoding="utf-8")
    service = (ROOT / "deploy/qdev-runner-broker.service").read_text(encoding="utf-8")

    assert compose.startswith("name: qdev-runner\n")
    assert service.count("--project-name qdev-runner") == 2


def test_registry_keeps_human_account_separate_from_job_account() -> None:
    caddyfile = (ROOT / "deploy/Caddyfile").read_text(encoding="utf-8")

    assert "qdev {$QDEV_REGISTRY_PASSWORD_HASH}" in caddyfile
    assert "qdev-runner {$QDEV_RUNNER_REGISTRY_PASSWORD_HASH}" in caddyfile
