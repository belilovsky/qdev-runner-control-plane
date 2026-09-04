from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_python_setup_prerequisite_is_in_general_and_browser_images() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.count("lsb-release") == 2


def test_native_build_toolchain_is_in_general_and_browser_images() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.count("build-essential") == 2


def test_browser_image_pins_the_playwright_1_62_1_chromium_bundle() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert "Playwright clients installed by browser jobs must stay in lockstep" in dockerfile
    assert (
        "mcr.microsoft.com/playwright@sha256:"
        "c091b21d9fae78c76e85cd4356431e9b018402f172a214fc7d7a5e9a7e29d8ac"
    ) in dockerfile


def test_worker_defaults_match_the_immutable_runner_image_release() -> None:
    settings = (ROOT / "src/qdev_runner/settings.py").read_text(encoding="utf-8")
    builder = (ROOT / "scripts/build_runner_images.sh").read_text(encoding="utf-8")
    worker_audit = (ROOT / "scripts/audit_worker_runtime.py").read_text(encoding="utf-8")

    assert "_required_immutable_image" in settings
    assert "@sha256 content-addressed reference" in settings
    assert "image_not_immutable" in worker_audit
    assert "QDEV_RUNNER_VERSION:-2.336.0-r2" in builder


def test_docker_profile_has_compose_plugin() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert "docker.io docker-buildx docker-compose-v2" in dockerfile


def test_docker_profile_logs_in_with_job_scoped_registry_credentials() -> None:
    entrypoint = (ROOT / "images/runner/entrypoint.sh").read_text(encoding="utf-8")

    assert "QDEV_REGISTRY_PASSWORD" in entrypoint
    assert "--password-stdin" in entrypoint
    assert "QDEV_REGISTRY_URL" in entrypoint
