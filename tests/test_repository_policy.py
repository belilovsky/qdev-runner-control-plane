from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parents[1]


def load_installer() -> ModuleType:
    path = ROOT / "scripts/apply_repository_policy.py"
    spec = importlib.util.spec_from_file_location("apply_repository_policy", path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def repository(tmp_path: Path, workflow: str) -> Path:
    root = tmp_path / "repo"
    (root / ".github/workflows").mkdir(parents=True)
    (root / ".github/qdev-runner.yml").write_text(
        "schema_version: qdev-runner-v1\nprofiles:\n  - qdev-ci\ngithub_hosted_fallback: false\n",
        encoding="utf-8",
    )
    (root / ".github/workflows/ci.yml").write_text(workflow, encoding="utf-8")
    return root


GOOD_WORKFLOW = """jobs:
  test:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - \"qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-test\"
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
"""


def run_guard(root: Path) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(root / ".github/scripts/qdev-runner-policy.py"), "--root", str(root)],
        check=False,
        capture_output=True,
        text=True,
    )


def test_installer_is_idempotent_and_preserves_existing_agents(tmp_path: Path) -> None:
    root = repository(tmp_path, GOOD_WORKFLOW)
    (root / "AGENTS.md").write_text("# Product rules\n\nKeep this.\n", encoding="utf-8")
    installer = load_installer()
    assert installer.install(root)
    first = (root / "AGENTS.md").read_text(encoding="utf-8")
    assert "Keep this." in first
    assert first.count("<!-- qdev-runner-policy:start -->") == 1
    assert installer.install(root) == []
    assert run_guard(root).returncode == 0


def test_installer_is_idempotent_without_existing_agents(tmp_path: Path) -> None:
    root = repository(tmp_path, GOOD_WORKFLOW)
    installer = load_installer()
    assert installer.install(root)
    first = (root / "AGENTS.md").read_text(encoding="utf-8")
    assert not first.startswith("\n")
    assert installer.install(root) == []
    assert (root / "AGENTS.md").read_text(encoding="utf-8") == first


def test_installer_uses_broker_scoped_artifact_identity(tmp_path: Path) -> None:
    root = repository(tmp_path, GOOD_WORKFLOW)
    load_installer().install(root)
    uploader = (root / ".github/scripts/qdev-upload-artifact.sh").read_text(encoding="utf-8")
    assert "${QDEV_REPOSITORY:?}/${QDEV_HEAD_SHA:?}/${QDEV_JOB_ID:?}" in uploader
    assert "${GITHUB_REPOSITORY:?}/${GITHUB_SHA:?}" not in uploader


def test_guard_rejects_hosted_services_and_unpinned_actions(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/cache@v4
      - uses: actions/upload-artifact@v4
      - run: docker pull ghcr.io/example/image:latest
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    for marker in ("hosted-runner", "github-cache", "github-artifact", "ghcr", "unpinned-action"):
        assert marker in result.stdout


def test_guard_rejects_dynamic_runner_and_missing_unique_label(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  dynamic:
    runs-on: ${{ vars.RUNNER || 'ubuntu-latest' }}
  general:
    runs-on: [self-hosted, Linux, X64, qdev-ci]
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "dynamic-runner-selector" in result.stdout
    assert "missing-unique-job-label" in result.stdout


def test_guard_rejects_static_or_incomplete_job_labels(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  static:
    runs-on: [self-hosted, Linux, X64, qdev-ci, qdev-job-test]
  incomplete:
    runs-on: [self-hosted, Linux, X64, qdev-ci, \"qdev-job-${{ github.run_id }}-test\"]
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert result.stdout.count("missing-unique-job-label") == 2


def test_guard_enforces_contract_profiles(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  browser:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci-browser
      - \"qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-browser\"
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "profile-not-allowed" in result.stdout


def test_guard_rejects_quoted_setup_cache_and_mutable_container_action(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  test:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - \"qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-test\"
    steps:
      - uses: actions/setup-node@11d5960a326750d5838078e36cf38b85af677262
        with:
          cache: \"npm\"
      - uses: docker://vendor/tool:latest
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "github-cache" in result.stdout
    assert "unpinned-container-action" in result.stdout


def test_guard_allows_digest_pinned_container_action(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  test:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - \"qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-test\"
    steps:
      - uses: docker://vendor/tool@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""",
    )
    load_installer().install(root)
    assert run_guard(root).returncode == 0


def test_guard_allows_product_specific_release_label(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  deploy:
    runs-on: [self-hosted, Linux, X64, product-release]
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
""",
    )
    load_installer().install(root)
    assert run_guard(root).returncode == 0


def test_guard_allows_explicit_dynamic_deployment_labels(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  deploy:
    runs-on: ${{ fromJSON(inputs.deployment_labels) }}
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
""",
    )
    load_installer().install(root)
    assert run_guard(root).returncode == 0
