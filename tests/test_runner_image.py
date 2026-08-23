from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_python_setup_prerequisite_is_in_general_and_browser_images() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.count("lsb-release") == 2


def test_native_build_toolchain_is_in_general_and_browser_images() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.count("build-essential") == 2


def test_docker_profile_has_compose_plugin() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert "docker.io docker-buildx docker-compose-v2" in dockerfile
