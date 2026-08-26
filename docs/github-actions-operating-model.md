# GitHub Actions operating model

## Execution lanes

1. **Normal:** GitHub-hosted compute runs the required checks. Billing,
   payment method, Actions budget, GitHub queue, and the exact-SHA check are
   independent evidence.
2. **Recovery:** the central QDev broker starts one ephemeral runner container
   per job. The primary worker receives work first; the reserve worker may
   claim when no healthy primary slot is free.
3. **Release:** a product-specific deploy runner or native deploy helper stays
   separate from both general CI lanes and keeps its own credential gates.

The QDev pool is not an offline replacement for GitHub. Webhook delivery, the
GitHub App, JIT registration, workflow orchestration, and the GitHub API must
still work. A complete GitHub outage therefore remains an external blocker.

## Failure taxonomy

Record each lane independently; do not infer a green lane from another one.

| Lane | Minimum evidence |
| --- | --- |
| workflow | workflow file, event, selector, permissions, exact SHA |
| hosted billing | payment status, positive Actions budget, stop-usage intent, current spend |
| GitHub queue | run ID, job ID, status, timestamps, annotations |
| webhook/broker | signed delivery accepted, pending count, database state |
| primary worker | fresh heartbeat, capacity gate, concurrency, free slots |
| reserve worker | fresh heartbeat, correct `reserve` tier, capacity gate, free slots |
| artifacts/registry | endpoint health, scoped credentials, retention state |
| required check | context name and conclusion bound to the exact SHA |
| release | deployed SHA/release, runtime health, public smoke, rollback target |

`primary_present` and `primary_capacity_allowed` do not mean
`primary_available`: a healthy worker may have no free execution slot. The
same distinction applies to reserve.

## Recovery sequence

1. Preserve the failed run and inspect its annotations. Classify workflow,
   billing/provider, queue, broker, worker, capacity, or application failure.
2. For a billing/provider failure, verify payment and a positive Actions
   budget. Rerun one known job once. Do not loop retries.
3. Audit `https://ci.qdev.run/health`. Both tiers must be present and pass
   capacity. A pending queue with a busy primary must be claimable by reserve.
4. Dispatch only the repository's reviewed recovery workflow on the same SHA.
   Public fork code never runs on the recovery pool.
5. Record run ID, job ID, SHA, runner name, queue time, conclusion, and the
   broker health receipt. Resume release only from the repository's normal
   authorization boundary.
6. Restore the normal hosted lane and verify its required check separately.

There is no silent automatic fallback: GitHub assigns a job from its declared
`runs-on` selector, so recovery uses an explicit workflow dispatch or reviewed
reusable workflow. Recovery evidence must not be reported as a hosted check.

## Runtime changes

- Never restart a worker while it reports an active job.
- Worker names end in their tier (`-primary` or `-reserve`); startup rejects a
  mismatch.
- Reserve stands down only while a fresh, capacity-allowed primary slot is
  free. A merely present or busy primary does not block reserve.
- Preserve the previous controller release and host configuration before a
  bounded activation. Do not broad-prune shared Docker data.
- Requeued transient jobs move to the FIFO tail so one failing job cannot
  starve the queue.

Run the public-safe audit before and after recovery:

```bash
python3 scripts/audit_runtime.py --output runner-runtime-receipt.json
```

Use `--require-primary-slot` or `--require-reserve-slot` only for a controlled
idle failover test; a busy but healthy tier is not otherwise a defect.
