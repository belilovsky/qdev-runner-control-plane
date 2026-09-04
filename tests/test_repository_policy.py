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


def hosted_repository(tmp_path: Path, workflow: str) -> Path:
    root = repository(tmp_path, workflow)
    (root / ".github/qdev-runner.yml").write_text(
        "schema_version: qdev-runner-v2\n"
        "execution_mode: github-hosted-primary\n"
        "self_hosted_recovery: true\n"
        "recovery_workflows:\n  - runner-smoke.yml\n"
        "profiles:\n  - qdev-ci\n",
        encoding="utf-8",
    )
    (root / ".github/workflows/runner-smoke.yml").write_text(
        "on:\n  workflow_dispatch:\njobs: {}\n", encoding="utf-8"
    )
    return root


def declare_release_registry_workflow(root: Path, name: str = "deploy.yml") -> None:
    contract = root / ".github/qdev-runner.yml"
    contract.write_text(
        contract.read_text(encoding="utf-8")
        + "release_registry_workflows:\n"
        + f"  - {name}\n",
        encoding="utf-8",
    )


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
    assert first.startswith("# Repository instructions\n\n")
    assert installer.install(root) == []
    assert (root / "AGENTS.md").read_text(encoding="utf-8") == first


def test_installer_repairs_managed_only_agents_without_heading(tmp_path: Path) -> None:
    root = repository(tmp_path, GOOD_WORKFLOW)
    managed = (ROOT / "templates/AGENTS.qdev-runner.md").read_text(encoding="utf-8")
    (root / "AGENTS.md").write_text(managed, encoding="utf-8")

    installer = load_installer()
    assert installer.install(root)
    first = (root / "AGENTS.md").read_text(encoding="utf-8")
    assert first.startswith("# Repository instructions\n\n")
    assert first.count("<!-- qdev-runner-policy:start -->") == 1
    assert installer.install(root) == []


def test_installer_supports_broker_and_github_hosted_artifact_identities(tmp_path: Path) -> None:
    root = repository(tmp_path, GOOD_WORKFLOW)
    load_installer().install(root)
    uploader = (root / ".github/scripts/qdev-upload-artifact.sh").read_text(encoding="utf-8")
    assert "${QDEV_REPOSITORY}/${QDEV_HEAD_SHA}/${QDEV_JOB_ID}" in uploader
    assert "${GITHUB_REPOSITORY:?}/${GITHUB_SHA:?}/${GITHUB_RUN_ID:?}" in uploader
    assert "ACTIONS_ID_TOKEN_REQUEST_URL" in uploader
    assert "X-QDev-GitHub-OIDC" in uploader
    assert "[A-Za-z0-9._-]{0,127}" in uploader


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


def test_v2_allows_hosted_primary_and_self_hosted_recovery(tmp_path: Path) -> None:
    root = hosted_repository(
        tmp_path,
        """jobs:
  primary:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
""",
    )
    (root / ".github/workflows/runner-smoke.yml").write_text(
        """on:
  workflow_dispatch:
jobs:
  recovery:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-recovery"
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
""",
        encoding="utf-8",
    )
    load_installer().install(root)
    assert run_guard(root).returncode == 0


def test_v2_rejects_self_hosted_job_outside_declared_recovery_workflow(
    tmp_path: Path,
) -> None:
    root = hosted_repository(tmp_path, GOOD_WORKFLOW)
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "self-hosted-runner-outside-recovery" in result.stdout


def test_v2_rejects_automatic_declared_recovery_workflow(tmp_path: Path) -> None:
    root = hosted_repository(tmp_path, "jobs: {}\n")
    (root / ".github/workflows/runner-smoke.yml").write_text(
        "on:\n  schedule:\n    - cron: '0 * * * *'\njobs: {}\n", encoding="utf-8"
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "recovery-workflow-not-manual-only" in result.stdout


def test_v2_accepts_manual_recovery_inputs_but_not_an_extra_trigger(tmp_path: Path) -> None:
    root = hosted_repository(tmp_path, "jobs: {}\n")
    workflow = root / ".github/workflows/runner-smoke.yml"
    trigger = (
        "on:\n  workflow_dispatch:\n    inputs:\n      execution_lane:\n"
        "        type: choice\n        options: [hosted, recovery]\n"
        "        default: hosted\n"
    )
    load_installer().install(root)
    workflow.write_text(trigger + "jobs: {}\n", encoding="utf-8")
    assert run_guard(root).returncode == 0
    for event in ("push", "pull_request", "workflow_run", "schedule"):
        workflow.write_text(trigger + f"  {event}:\njobs: {{}}\n", encoding="utf-8")
        result = run_guard(root)
        assert result.returncode == 1
        assert "recovery-workflow-not-manual-only" in result.stdout


def test_v2_allows_ghcr_only_in_declared_non_pr_release_workflow(
    tmp_path: Path,
) -> None:
    root = hosted_repository(
        tmp_path,
        """jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11d5960a326750d5838078e36cf38b85af677262
""",
    )
    (root / ".github/workflows/deploy.yml").write_text(
        """on:
  workflow_dispatch:
permissions:
  contents: read
  packages: write
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: docker build -t ghcr.io/example/product:${{ github.sha }} .
      - run: docker push ghcr.io/example/product:${{ github.sha }}
""",
        encoding="utf-8",
    )
    declare_release_registry_workflow(root)
    load_installer().install(root)
    assert run_guard(root).returncode == 0


def test_v2_rejects_ghcr_in_undeclared_ci_workflow(tmp_path: Path) -> None:
    root = hosted_repository(
        tmp_path,
        """jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - run: docker pull ghcr.io/example/product:${{ github.sha }}
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "ghcr" in result.stdout


def test_release_registry_workflow_rejects_pull_request_trigger(tmp_path: Path) -> None:
    root = hosted_repository(tmp_path, "jobs: {}\n")
    (root / ".github/workflows/deploy.yml").write_text(
        """on:
  pull_request:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: docker pull ghcr.io/example/product:${{ github.sha }}
""",
        encoding="utf-8",
    )
    declare_release_registry_workflow(root)
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "release-registry-workflow-pull-request" in result.stdout


def test_release_registry_workflow_does_not_exempt_cache_or_artifacts(
    tmp_path: Path,
) -> None:
    root = hosted_repository(tmp_path, "jobs: {}\n")
    (root / ".github/workflows/deploy.yml").write_text(
        """on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - run: docker pull ghcr.io/example/product:${{ github.sha }}
      - uses: actions/cache@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
""",
        encoding="utf-8",
    )
    declare_release_registry_workflow(root)
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "github-cache" in result.stdout
    assert "ghcr" not in result.stdout


def test_release_registry_workflow_applies_to_its_local_composite_actions(
    tmp_path: Path,
) -> None:
    root = hosted_repository(tmp_path, "jobs: {}\n")
    (root / ".github/workflows/deploy.yml").write_text(
        """on:
  workflow_dispatch:
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: ./.github/actions/release
""",
        encoding="utf-8",
    )
    action = root / ".github/actions/release/action.yml"
    action.parent.mkdir(parents=True)
    action.write_text(
        """runs:
  using: composite
  steps:
    - run: docker pull ghcr.io/example/product:${{ github.sha }}
      shell: bash
""",
        encoding="utf-8",
    )
    declare_release_registry_workflow(root)
    load_installer().install(root)
    assert run_guard(root).returncode == 0


def test_release_registry_workflow_requires_v2_and_existing_file(
    tmp_path: Path,
) -> None:
    v1 = repository(tmp_path, GOOD_WORKFLOW)
    declare_release_registry_workflow(v1, "missing.yml")
    load_installer().install(v1)
    result = run_guard(v1)
    assert result.returncode == 1
    assert "release-registry-requires-v2" in result.stdout
    assert "release-registry-workflow-missing missing.yml" in result.stdout


def test_guard_ignores_commented_action_reference(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        GOOD_WORKFLOW + "    # uses: vendor/example@v1 was replaced\n",
    )
    load_installer().install(root)
    assert run_guard(root).returncode == 0


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


def test_guard_rejects_malformed_unique_job_label_order(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  test:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - "qdev-job-${{ github.run_attempt }}-${{ github.run_id }}-test"
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "missing-unique-job-label" in result.stdout


def test_guard_requires_matrix_index_in_unique_job_label(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  lint:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-lint"
    strategy:
      matrix:
        python-version: ['3.11', '3.12']
""",
    )
    load_installer().install(root)

    result = run_guard(root)

    assert result.returncode == 1
    assert "matrix-job-label-not-unique" in result.stdout


def test_guard_accepts_matrix_index_in_unique_job_label(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  lint:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-lint-${{ strategy.job-index }}"
    strategy:
      matrix:
        python-version: ['3.11', '3.12']
""",
    )
    load_installer().install(root)

    assert run_guard(root).returncode == 0


def test_guard_rejects_flow_style_runner_selector(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  deploy: {runs-on: production-runner, steps: [{run: echo ok}]}
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "unapproved-runner-profile" in result.stdout


def test_guard_rejects_unguarded_pull_request_job(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """on:
  pull_request:
jobs:
  test:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-test"
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "unguarded-public-fork-job" in result.stdout


def test_guard_allows_same_repository_pull_request_job(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """on:
  pull_request:
jobs:
  test:
    if: >-
      github.event_name != 'pull_request' ||
      github.event.pull_request.head.repo.full_name == github.repository
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-test"
""",
    )
    load_installer().install(root)
    assert run_guard(root).returncode == 0


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
      - uses : actions/setup-node@v4
        with:
          \"cache\" : \"npm\"
      - uses: docker://vendor/tool:latest
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "github-cache" in result.stdout
    assert "unpinned-action" in result.stdout
    assert "unpinned-container-action" in result.stdout


def test_guard_rejects_missing_base_runner_labels(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  test:
    runs-on:
      - qdev-ci
      - \"qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-test\"
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "missing-required-runner-label" in result.stdout


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
    contract = root / ".github/qdev-runner.yml"
    contract.write_text(
        contract.read_text(encoding="utf-8") + "release_runner: product-release\n",
        encoding="utf-8",
    )
    load_installer().install(root)
    assert run_guard(root).returncode == 0


def test_guard_allows_explicit_release_runner_list(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  deploy:
    runs-on: [self-hosted, Linux, X64, product-release-secondary]
""",
    )
    contract = root / ".github/qdev-runner.yml"
    contract.write_text(
        contract.read_text(encoding="utf-8")
        + "release_runners:\n"
        + "  - product-release-primary\n"
        + "  - product-release-secondary\n",
        encoding="utf-8",
    )
    load_installer().install(root)
    assert run_guard(root).returncode == 0


def test_guard_rejects_undeclared_self_hosted_runner(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        """jobs:
  bypass:
    runs-on: [self-hosted, Linux, X64, repository-runner]
""",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "unapproved-runner-profile" in result.stdout


def test_guard_rejects_unconstrained_dynamic_deployment_labels(tmp_path: Path) -> None:
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
    result = run_guard(root)
    assert result.returncode == 1
    assert "dynamic-runner-selector" in result.stdout


def test_guard_ignores_commented_profile_and_parses_only_contract_profile_block(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path, GOOD_WORKFLOW)
    contract = root / ".github/qdev-runner.yml"
    contract.write_text(
        "schema_version: qdev-runner-v1\n"
        "profiles:\n  - qdev-ci\n"
        "notes:\n  - qdev-ci-browser\n"
        "github_hosted_fallback: false\n",
        encoding="utf-8",
    )
    (root / ".github/workflows/ci.yml").write_text(
        GOOD_WORKFLOW + "    # qdev-ci-browser is documentation only\n",
        encoding="utf-8",
    )
    load_installer().install(root)
    assert run_guard(root).returncode == 0


def test_guard_rejects_flow_style_action_cache_and_github_packages(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        GOOD_WORKFLOW
        + "      - { uses: actions/setup-node@v4, with: { cache: npm } }\n"
        + "      - run: dotnet nuget add source https://nuget.pkg.github.com/acme/index.json\n",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "unpinned-action" in result.stdout
    assert "github-cache" in result.stdout
    assert "github-packages" in result.stdout


def test_guard_rejects_multiple_profiles_unknown_selector_and_duplicate_label(
    tmp_path: Path,
) -> None:
    root = repository(
        tmp_path,
        """jobs:
  first:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - qdev-ci-browser
      - "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-same"
  second:
    runs-on:
      - self-hosted
      - Linux
      - X64
      - qdev-ci
      - "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-same"
  unknown:
    runs-on: mystery-runner
""",
    )
    contract = root / ".github/qdev-runner.yml"
    contract.write_text(
        "schema_version: qdev-runner-v1\nprofiles:\n  - qdev-ci\n  - qdev-ci-browser\n"
        "github_hosted_fallback: false\n",
        encoding="utf-8",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "multiple-runner-profiles" in result.stdout
    assert "duplicate-unique-job-label" in result.stdout
    assert "unapproved-runner-profile" in result.stdout


def test_guard_recursively_checks_local_composite_actions(tmp_path: Path) -> None:
    root = repository(
        tmp_path,
        GOOD_WORKFLOW + "      - uses: ./.github/actions/local\n",
    )
    action = root / ".github/actions/local/action.yml"
    action.parent.mkdir(parents=True)
    action.write_text(
        "runs:\n  using: composite\n  steps:\n"
        "    - { uses: vendor/example@v1 }\n"
        "    - run: docker pull containers.pkg.github.com/acme/image:latest\n",
        encoding="utf-8",
    )
    load_installer().install(root)
    result = run_guard(root)
    assert result.returncode == 1
    assert "unpinned-action" in result.stdout
    assert "github-packages" in result.stdout


def test_uploader_accepts_dangling_symlink_and_excludes_its_own_archive(
    tmp_path: Path,
) -> None:
    root = repository(tmp_path, GOOD_WORKFLOW)
    load_installer().install(root)
    uploader = (root / ".github/scripts/qdev-upload-artifact.sh").read_text(encoding="utf-8")
    assert '[[ -e "$path" || -L "$path" ]]' in uploader
    assert '--exclude="$archive"' in uploader
