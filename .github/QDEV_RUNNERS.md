# QDev controller-managed GitHub Actions execution

Required checks run only on the centralized, ephemeral QDev runner pool. There
is no GitHub-hosted fallback. GitHub remains the workflow orchestrator; the
controller independently admits the exact repository, run, job, attempt, SHA,
event, ref, profile, and unique lease label.

The self-hosted pool is an explicit bounded lane. Workflows listed in
`recovery_workflows` are manual-only; exact workflows listed in
`primary_self_hosted_workflows` may use the same controller-owned capacity for
ordinary exact-SHA verification. Dispatch `.github/workflows/runner-smoke.yml`
only after controller, worker, capacity, executor-image and pause-owner gates
pass. A successful recovery run does not substitute for an unexecuted required
check.

The manual runner smoke is a controller recovery verification lane, not an
alternate registration path. Dispatch it only through a signed, exact-SHA
claim after controller, worker, capacity, executor-image, and pause-owner gates
pass. The provider runner is removed after its terminal receipt.
