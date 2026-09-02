# QDev runner control-plane CI

Paid GitHub-hosted compute is the normal lane for this repository. `CI / verify`
and `QDev runner contract / qdev-runner-contract` are provider checks and must
be evaluated on the exact pull-request SHA.

The self-hosted pool is an explicit recovery lane. Only workflows listed in
`recovery_workflows` may select a QDev self-hosted profile, and each must be
manual-only. Dispatch `.github/workflows/runner-smoke.yml` only after controller, worker,
capacity, executor-image and pause-owner gates pass. A successful recovery run
does not substitute for the hosted checks.

Each recovery job uses one static QDev profile and a unique lease label. Matrix
jobs also include `${{ strategy.job-index }}` so a JIT runner cannot bind to a
sibling matrix job.
