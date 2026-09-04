# QDev runner control-plane CI

Paid GitHub-hosted compute is the normal lane for this repository. `CI / verify`
and `QDev runner contract / qdev-runner-contract` are provider checks and must
be evaluated on the exact pull-request SHA.

The self-hosted pool is an explicit recovery lane. Only workflows listed in
`recovery_workflows` may select a QDev self-hosted profile, and each must be
manual-only. Dispatch `.github/workflows/runner-smoke.yml` only after controller, worker,
capacity, executor-image and pause-owner gates pass. A successful recovery run
does not substitute for the hosted checks. This repository's
`recovery_ci_alternative` is an explicit, fail-closed release policy: it can be
used only after a terminal full recovery run and a signed
`qdev-controller-receipt-v2` with `enforcement: enforced`, bound exactly to the
repository, source SHA, run/job/attempt, recovery profile, and artifact digest.
The receipt is evidence of a controller-owned admission, not a green hosted
check; a missing, stale, or mismatched receipt leaves release admission
pending.

Each recovery job uses one static QDev profile and a unique lease label. Matrix
jobs also include `${{ strategy.job-index }}` so a JIT runner cannot bind to a
sibling matrix job.
