# QDev runner control-plane CI

`CI / verify` and `QDev runner contract / qdev-runner-contract` run on the
existing `qdev-ci` pool while provider-hosted jobs are unavailable. They are
allowlisted in `.github/qdev-runner.yml`, reject fork pull requests, use unique
job labels, and must be evaluated on the exact pull-request SHA.

The self-hosted pool is an explicit bounded lane. Workflows listed in
`recovery_workflows` are manual-only; exact workflows listed in
`primary_self_hosted_workflows` may use the same controller-owned capacity for
ordinary exact-SHA verification. Dispatch `.github/workflows/runner-smoke.yml`
only after controller, worker, capacity, executor-image and pause-owner gates
pass. A successful recovery run does not substitute for an unexecuted required
check.

Each recovery job uses one static QDev profile and a unique lease label. Matrix
jobs also include `${{ strategy.job-index }}` so a JIT runner cannot bind to a
sibling matrix job.
