# Repository instructions

<!-- qdev-runner-policy:start -->
## QDev GitHub Actions runner policy

- The repository contract selects either hosted-primary v2 or
  controller-managed self-hosted v3. Never introduce an implicit or dynamic
  fallback between those execution modes.
- Every controller-managed job selects one approved profile (`qdev-ci`,
  `qdev-ci-browser`, or `qdev-ci-docker`) together with `self-hosted`, `Linux`,
  `X64`, and a job-unique `qdev-job-*` label. Matrix jobs also include
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
- Any new or changed workflow must pass `qdev-runner-contract` in the execution
  mode declared by the repository. Hosted-primary v2 recovery acceptance also
  requires `runner-smoke` on the same default-branch SHA.
<!-- qdev-runner-policy:end -->
