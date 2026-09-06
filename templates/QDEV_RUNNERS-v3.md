# QDev controller-managed GitHub Actions execution

Repositories using `qdev-runner-v3` run required checks only on the centralized,
ephemeral QDev runner pool. There is no GitHub-hosted fallback. GitHub remains
the workflow orchestrator; the controller independently admits the exact
repository, run, job, attempt, SHA, event, ref, profile, and unique lease label.

Every job selects one static profile and a unique label:

```yaml
runs-on:
  - self-hosted
  - Linux
  - X64
  - qdev-ci
  - qdev-job-${{ github.run_id }}-${{ github.run_attempt }}-test
```

Matrix jobs also include `${{ strategy.job-index }}`. Use `qdev-ci` for Python,
Node, and static checks, `qdev-ci-browser` for browser checks, and
`qdev-ci-docker` for builds with a disposable job-scoped rootless
Docker/BuildKit sidecar. Never mount the host Docker socket.

Public fork pull requests must not execute on this pool. Each pull-request job
uses this guard:

```yaml
if: github.event_name != 'pull_request' || github.event.pull_request.head.repo.full_name == github.repository
```

Third-party actions are pinned to full commit SHAs. GitHub cache, GitHub
Artifacts, GitHub Packages, and GHCR are not CI dependencies; evidence and
images use the QDev artifact and immutable registry services. Job credentials
exist only in the disposable runner environment and are removed with the job.

Keep `.github/qdev-runner.yml`, this document, the root `AGENTS.md` policy, and
`.github/workflows/qdev-runner-contract.yml` together. Validate changes with:

```bash
python3 .github/scripts/qdev-runner-policy.py --root .
```

New repositories and workers are enrolled through the controller. Do not
register a persistent repository runner or add a hosted fallback.
