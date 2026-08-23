<!-- qdev-runner-policy:start -->
## QDev GitHub Actions runner policy

- General CI must use the centralized ephemeral self-hosted pool. Select one
  approved profile (`qdev-ci`, `qdev-ci-browser`, or `qdev-ci-docker`) together
  with `self-hosted`, `Linux`, `X64`, and a job-unique `qdev-job-*` label.
- Treat `.github/qdev-runner.yml` as the machine-readable source of truth. Do
  not create a repository-specific runner or add a GitHub-hosted fallback.
- Pin third-party actions to a full 40-character commit SHA. Do not make
  `actions/cache`, GitHub Artifacts, GitHub Packages, or GHCR an availability
  dependency; use the QDev artifact and registry services documented in
  `.github/QDEV_RUNNERS.md`.
- Public fork pull requests must not execute fork code on production-connected
  runners. Keep product-specific deployment labels and their credential gates
  separate from the general CI pool.
- Any new or changed workflow must pass the `qdev-runner-contract` check.
<!-- qdev-runner-policy:end -->
