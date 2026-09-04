# QDev GitHub Actions execution

Paid GitHub-hosted compute is the normal execution path. The centralized,
ephemeral QDev runner pool is the explicit recovery path when the hosted
compute or billing lane is unavailable. Both paths still depend on GitHub as
the workflow orchestrator and on the GitHub API.

Normal jobs use a static GitHub-hosted selector:

```yaml
runs-on: ubuntu-latest
```

Do not use a dynamic selector as an implicit fallback. A queued job cannot
reliably change pools after dispatch. Keep a separately dispatchable recovery
workflow or reusable workflow and record which lane ran the exact SHA.

## Recovery labels

Every general CI job selects exactly one profile and a unique job label:

```yaml
runs-on:
  - self-hosted
  - Linux
  - X64
  - qdev-ci
  - qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-test
```

Matrix jobs must also include `${{ strategy.job-index }}` in that label. The
run ID, attempt and job name are shared by every expansion of one matrix job;
without the index, a JIT runner created for one job ID may accept a sibling:

```yaml
runs-on: [self-hosted, Linux, X64, qdev-ci, "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-test-${{ strategy.job-index }}"]
```

Use `qdev-ci` for Node, Python, and static checks, `qdev-ci-browser` for
Playwright/Chromium, and `qdev-ci-docker` for builds using the job-scoped
rootless Docker/BuildKit service. Never mount the host Docker socket.

Install the requested language runtime with a commit-SHA-pinned setup action.
Do not assume that Node, npm, or a specific Python version is globally present.

## Recovery job examples

Node:

```yaml
runs-on: [self-hosted, Linux, X64, qdev-ci, "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-node"]
steps:
  - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
    with: {persist-credentials: false}
  - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
    with: {node-version: "22"}
  - run: npm ci && npm test
```

Python:

```yaml
runs-on: [self-hosted, Linux, X64, qdev-ci, "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-python"]
steps:
  - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
    with: {persist-credentials: false}
  - uses: actions/setup-python@a26af69be951a213d495a4c3e4e4022e16d87065 # v5
    with: {python-version: "3.12"}
  - run: python -m pip install -r requirements.txt && python -m pytest
```

Browser:

```yaml
runs-on: [self-hosted, Linux, X64, qdev-ci-browser, "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-browser"]
steps:
  - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
    with: {persist-credentials: false}
  - uses: actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020 # v4
    with: {node-version: "22"}
  - run: npm ci && npx playwright install chromium && npm test
```

Docker/BuildKit:

```yaml
runs-on: [self-hosted, Linux, X64, qdev-ci-docker, "qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-image"]
steps:
  - uses: actions/checkout@fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09 # v5
    with: {persist-credentials: false}
  - run: |
      docker compose version
      docker build -t "${QDEV_REGISTRY_URL}/${GITHUB_REPOSITORY}:${GITHUB_SHA}" .
      docker push "${QDEV_REGISTRY_URL}/${GITHUB_REPOSITORY}:${GITHUB_SHA}"
```

The Docker profile is logged into `registry.ci.qdev.run` before the job starts.
Its narrow registry credential exists only in the disposable runner environment
and is removed with the runner container and private env-file after the job.

## Storage and security

- Upload transient evidence through `.github/scripts/qdev-upload-artifact.sh`.
  Artifact names must start with an ASCII letter or digit and contain only
  letters, digits, `.`, `_`, or `-` (maximum 128 characters).
  Artifacts are addressed by repository, SHA, and job, checked with SHA-256,
  and retained according to `.github/qdev-runner.yml`.
- Push OCI images required by CI to `registry.ci.qdev.run`; deployment images
  and rollback digests retain their product-specific release policy.
- A v2 repository that must publish or resolve protected deployment images in
  GHCR declares only the exact workflow filenames under
  `release_registry_workflows` in `.github/qdev-runner.yml`. The checker permits
  `ghcr.io` only in those declared, non-`pull_request` workflows (including
  local composite actions reached from them). GitHub cache/artifact actions and
  `pkg.github.com` remain forbidden there. This is a release-registry boundary,
  not a general CI exception.
- Public fork pull requests do not execute fork code on the general pool. They
  require an isolated no-secrets path or trusted maintainer approval.
- Product-specific deployment labels are not general CI profiles and must keep
  their existing secrets, environment, and root-owned helper gates.

## Adding or changing workflows

Keep `.github/qdev-runner.yml`, this document, the root `AGENTS.md` policy, and
`.github/workflows/qdev-runner-contract.yml` together. Run the local checker:

```bash
python3 .github/scripts/qdev-runner-policy.py --root .
```

The required `qdev-runner-contract` check runs on GitHub-hosted compute. QDev
self-hosted profiles may appear only in filenames declared under
`recovery_workflows`, and those workflows must be manual-only. The separate
`runner-smoke` workflow proves the QDev recovery path. New repositories
must be registered through the canonical starter bundle in
`belilovsky/qdev-runner-control-plane`; do not register a standalone runner.

Example for an existing protected deploy workflow:

```yaml
release_registry_workflows:
  - deploy.yml
```

The hosted checks remain the primary lane. A repository may explicitly declare
`recovery_ci_alternative` in `.github/qdev-runner.yml` as a fail-closed release
policy, but a recovery run alone never substitutes for hosted checks. The
alternative is valid only with a terminal full recovery run and a signed
`qdev-controller-receipt-v2` with `enforcement: enforced`, bound exactly to
repository, source SHA, run/job/attempt, recovery profile, and artifact digest.
A missing, stale, or mismatched receipt leaves release admission pending.
