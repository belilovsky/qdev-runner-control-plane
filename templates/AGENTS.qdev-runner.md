<!-- qdev-runner-policy:start -->
## QDev GitHub Actions runner policy

- General CI uses a static GitHub-hosted runner as the normal path. Keep the
  centralized ephemeral self-hosted pool as a separately dispatchable recovery
  path; do not implement a silent dynamic selector fallback.
- A recovery job selects one approved profile (`qdev-ci`, `qdev-ci-browser`,
  `qdev-ci-compose`, or `qdev-ci-docker`) together with `self-hosted`, `Linux`, `X64`, and a
  job-unique `qdev-job-*` label. Matrix jobs also include
  `${{ strategy.job-index }}` so each expansion has a distinct runner lease.
- Treat `.github/qdev-runner.yml` as the machine-readable source of truth. Do
  not create a repository-specific runner or change execution mode without
  migrating the contract and its smoke evidence.
- Pin third-party actions to a full 40-character commit SHA. Do not make
  `actions/cache`, GitHub Artifacts, GitHub Packages, or GHCR an availability
  dependency; use the QDev artifact and registry services documented in
  `.github/QDEV_RUNNERS.md`.
- Public fork pull requests must not execute fork code on production-connected
  runners. Keep product-specific deployment labels and their credential gates
  separate from the general CI pool.
- Any new or changed workflow must pass the hosted `qdev-runner-contract`
  check. Recovery acceptance additionally requires `runner-smoke` on the same
  default-branch SHA.
<!-- qdev-runner-policy:end -->
