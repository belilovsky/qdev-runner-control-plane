from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_controller_activation_is_targeted_and_rollback_aware() -> None:
    script = (ROOT / "scripts/activate_controller_release.sh").read_text(encoding="utf-8")

    assert "broker-public broker-internal" in script
    assert "--no-deps" in script
    assert "compose down" not in script
    assert "systemctl" not in script
    assert "mv -Tf" in script
    assert "rollback" in script
    assert "free < 31457280" in script
    assert "previous_public_image" in script
    assert "previous_internal_image" in script
    assert "compose -p qdev-runner" in script
    assert "compose -p deploy" not in script
    assert "qdev-runner-broker-internal" in script
    assert "deploy-broker-internal-1" not in script
    assert 'docker image tag "$previous_public_image"' in script
    assert 'docker image tag "$previous_internal_image"' in script


def test_controller_rollback_reuses_existing_images() -> None:
    script = (ROOT / "scripts/rollback_controller_release.sh").read_text(encoding="utf-8")

    assert "QDEV_CONTROLLER_NO_BUILD=true" in script


def test_controller_compose_project_is_namespaced() -> None:
    compose = (ROOT / "deploy/compose.yml").read_text(encoding="utf-8")
    service = (ROOT / "deploy/qdev-runner-broker.service").read_text(encoding="utf-8")

    assert compose.startswith("name: qdev-runner\n")
    assert service.count("--project-name qdev-runner") == 2
