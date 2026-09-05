# QDev runner control-plane CI

The centralized self-hosted pool is the primary execution lane for this
repository. `CI / verify` and `QDev runner contract / qdev-runner-contract`
are provider checks, are allowlisted in `.github/qdev-runner.yml`, reject fork
pull requests, and must be evaluated on the exact pull-request SHA. Paid
GitHub-hosted compute is not a fallback. Capacity failures remain visible as
infrastructure state. Dispatch `.github/workflows/runner-smoke.yml` only after
controller, worker, capacity, executor-image and pause-owner gates pass.

Each job uses one static QDev profile and a unique lease label. Matrix
jobs also include `${{ strategy.job-index }}` so a JIT runner cannot bind to a
sibling matrix job.
