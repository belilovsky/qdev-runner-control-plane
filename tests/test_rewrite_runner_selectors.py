import importlib.util
from pathlib import Path

SCRIPT = Path(__file__).parents[1] / "scripts" / "rewrite_runner_selectors.py"
SPEC = importlib.util.spec_from_file_location("rewrite_runner_selectors", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(MODULE)


def test_rewrites_hosted_and_existing_qdev_selectors() -> None:
    source = """jobs:
  lint:
    runs-on: ubuntu-latest
  image_build:
    runs-on: [self-hosted, Linux, X64, qdev-ci]
"""
    rewritten = MODULE.rewrite(
        source,
        docker_jobs=[MODULE.re.compile("image")],
        browser_jobs=[],
        convert_jobs=[],
    )
    assert "qdev-ci, \"qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-lint\"" in rewritten
    assert "qdev-ci-docker" in rewritten
    assert "ubuntu-latest" not in rewritten


def test_preserves_product_runner_unless_job_is_selected() -> None:
    source = """jobs:
  deploy:
    runs-on: [self-hosted, Linux, X64, product-release]
"""
    preserved = MODULE.rewrite(source, docker_jobs=[], browser_jobs=[], convert_jobs=[])
    assert preserved == source
    converted = MODULE.rewrite(
        source,
        docker_jobs=[],
        browser_jobs=[],
        convert_jobs=[MODULE.re.compile("deploy")],
    )
    assert "qdev-ci" in converted
    assert "product-release" not in converted
