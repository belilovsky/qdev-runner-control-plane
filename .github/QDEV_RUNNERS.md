# QDev controller-managed GitHub Actions execution

Required checks run only on the centralized, ephemeral QDev runner pool. There
is no GitHub-hosted fallback. GitHub remains the workflow orchestrator; the
controller independently admits the exact repository, run, job, attempt, SHA,
event, ref, profile, and unique lease label.

This repository uses the `qdev-runner-v3` controller-managed mode. Every job
uses the enrolled self-hosted pool with a run, attempt and job-specific lease
label; there are no GitHub-hosted selectors or fallback. The controller admits
the exact repository, run, job, attempt, SHA, event, ref, profile and lease.
Public fork pull requests cannot execute on the pool.

The manual runner smoke is a controller recovery verification lane, not an
alternate registration path. Dispatch it only through a signed, exact-SHA
claim after controller, worker, capacity, executor-image, and pause-owner gates
pass. The provider runner is removed after its terminal receipt.

The declared `github_artifact_recovery_workflows` list is a narrower storage
exception. Only the manual controller recovery build may retain already-scanned,
sealed output in GitHub for seven days when the QDev artifact store is
unavailable. Its compute still runs on `qdev-ci-docker`; the stored artifact is
not an activation identity and remains unusable until exact provider and
cryptographic reconciliation.
