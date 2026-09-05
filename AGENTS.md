# Repository instructions

<!-- qdev-runner-policy:start -->
## QDev GitHub Actions runner policy

- General CI and `qdev-runner-contract` use the existing centralized ephemeral
  self-hosted pool under the supported `qdev-runner-v1` contract. This is an
  owner-authorized migration from billing-blocked hosted compute; do not add a
  hosted or dynamic selector fallback.
- A CI job selects one contract-approved profile (`qdev-ci` here) together
  with `self-hosted`, `Linux`, `X64`, and a
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
- Keep `cancel-in-progress: false` and run/attempt-specific concurrency groups
  so new runs do not replace pending or active controller FIFO entries.
- Any new or changed workflow must pass the self-hosted `qdev-runner-contract`
  check without changing its name or validation content. Runner activation
  acceptance additionally requires `runner-smoke` on the same default-branch
  SHA; local validation is not live runner evidence.
<!-- qdev-runner-policy:end -->
