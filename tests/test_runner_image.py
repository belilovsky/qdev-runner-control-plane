from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_python_setup_prerequisite_is_in_general_and_browser_images() -> None:
    dockerfile = (ROOT / "images/runner/Dockerfile").read_text(encoding="utf-8")

    assert dockerfile.count("lsb-release") == 2
