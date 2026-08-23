# QDev self-hosted GitHub Actions

This repository uses the centralized, ephemeral QDev runner pool. GitHub is
the workflow orchestrator; paid GitHub-hosted compute, GitHub cache/artifact
storage, GitHub Packages, and GHCR are not availability dependencies.

## Required labels

Every general CI job selects exactly one profile and a unique job label:

```yaml
runs-on:
  - self-hosted
  - Linux
  - X64
  - qdev-ci
  - qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-test
```

Use `qdev-ci` for Node, Python, and static checks, `qdev-ci-browser` for
Playwright/Chromium, and `qdev-ci-docker` for builds using the job-scoped
rootless Docker/BuildKit service. Never mount the host Docker socket.

Install the requested language runtime with a commit-SHA-pinned setup action.
Do not assume that Node, npm, or a specific Python version is globally present.

## Storage and security

- Upload transient evidence through `.github/scripts/qdev-upload-artifact.sh`.
  Artifacts are addressed by repository, SHA, and job, checked with SHA-256,
  and retained according to `.github/qdev-runner.yml`.
- Push OCI images required by CI to `registry.ci.qdev.run`; deployment images
  and rollback digests retain their product-specific release policy.
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

New repositories must be registered through the canonical starter bundle in
`belilovsky/qdev-runner-control-plane`; do not register a standalone runner.
