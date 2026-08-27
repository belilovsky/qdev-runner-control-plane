# GitHub Actions operating model

## Execution lanes

1. **Dedicated:** the central QDev broker starts one ephemeral, rootless runner
   container per job on the profile-compatible dedicated line. GitHub-hosted
   fallback is not part of this contract.
2. **Reserve:** shared production workers may claim only as an explicitly
   enabled emergency reserve after the compatible dedicated line has no free,
   capacity-allowed slot.
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
| GitHub provider | webhook delivery, JIT registration and exact-SHA job status |
| GitHub queue | run ID, job ID, status, timestamps, annotations |
| webhook/broker | signed delivery accepted, pending count, database state |
| primary worker | fresh heartbeat, capacity gate, concurrency, free slots |
| reserve worker | fresh heartbeat, correct `reserve` tier, capacity gate, free slots |
| executor images | every configured immutable runner and sidecar digest exists on the worker |
| artifacts/registry | endpoint health, scoped credentials, retention state |
| required check | context name and conclusion bound to the exact SHA |
| release | deployed SHA/release, runtime health, public smoke, rollback target |

`primary_present` and `primary_capacity_allowed` do not mean
`primary_available`: a healthy worker may have no free execution slot. The
same distinction applies to reserve.

## Recovery sequence

1. Preserve the provider job and inspect its annotations. Classify workflow,
   provider, queue, broker, worker, capacity, or application failure.
2. For a provider failure, verify signed webhook delivery, JIT registration,
   and the exact-SHA job status. Do not replay or requeue the job.
3. Audit `https://ci.qdev.run/health`. The compatible dedicated line must be
   present and pass capacity. On each worker, run
   `scripts/audit_worker_runtime.py` as a trusted administrator with that
   worker's rootless Docker environment before removing a pause marker. A
   heartbeat is not executor proof: every configured immutable runner and
   sidecar image must exist.
4. Record run ID, job ID, SHA, runner name, queue time, conclusion, and the
   broker health receipt. Resume release only from the repository's normal
   authorization boundary.
5. Use a shared worker only through the emergency-reserve gate when no
   compatible dedicated slot is available; return it to reserve after the
   dedicated line is verified.

There is no silent fallback: GitHub assigns the job from its declared
`runs-on` selector, and the broker preserves the accepted job for its
profile-compatible self-hosted line. Provider evidence must name the exact
self-hosted runner.

## Runtime changes

- Never restart a worker while it reports an active job.
- Acquire the worker gate with a stable incident/release owner before drain.
  Resume through the same gate owner only. The unit validates the permit owner,
  enabled state, and referenced passing audit on every start; direct marker
  removal or an empty permit file is not an accepted release path.
- Worker names end in their tier (`-primary` or `-reserve`); startup rejects a
  mismatch.
- Matrix jobs include `${{ strategy.job-index }}` in their `qdev-job-*` label;
  run ID, attempt and job name alone collide across matrix expansions and can
  bind a JIT runner to the wrong provider job ID.
- Reserve stands down only while a fresh, capacity-allowed primary slot is
  free for the exact pending profile. Claim admission preserves the configured
  free-space floor plus that profile's declared disk budget; a merely present,
  busy, or undersized primary does not block reserve.
- Preserve the previous controller release and host configuration before a
  bounded activation. Do not broad-prune shared Docker data.
- A runner-image cleanup allowlist is configuration-bound. Inspect every image
  referenced by the enabled worker profiles before unpausing; missing cached
  digests are restored from the trusted registry or last-known-good export.
- Do not accept a broker heartbeat or an internal `complete` callback as a
  canary. The GitHub job itself must leave `queued`, name the expected runner,
  and complete successfully on the exact SHA.
- Inventory every executable Actions lane, including repository-specific
  `actions.runner.*` services and direct deployment workflows.
  A standalone runner can bypass the broker gate and invalidate a capacity
  window even while both shared workers are paused. Drain its active job, then
  retire it with an explicit service guard and retained runner data.
- A capacity receipt covers a full declared interval, not an instant snapshot.
  Include periodic application cycles, swap-in and swap-out deltas, free space,
  effective gates and runtime health. Diagnostic scans are load too: stop
  self-created inventory processes before the window and use each application's
  native maintenance/drain control for recurring producers.
- Read all effective systemd conditions immediately before start. When the
  owner-bound gate replaces a known existence-only rollout permit, archive the
  exact legacy drop-in and permit through the provisioned migration; never
  satisfy the obsolete condition by creating an empty file.
- Transient retry uses a bounded `retry_not_before` backoff without changing a
  job's immutable GitHub FIFO key or its approved project tier.

Run the public-safe audit before and after recovery:

```bash
python3 scripts/audit_runtime.py --output runner-runtime-receipt.json

# Run locally as a trusted admin with the worker's rootless Docker environment.
python3 scripts/audit_worker_runtime.py --output worker-runtime-receipt.json

sudo qdev-runner-worker-gate acquire \
  --owner QDEV-INCIDENT-ID --reason 'bounded runner maintenance'

sudo qdev-runner-worker-gate release \
  --owner QDEV-INCIDENT-ID --reason 'verified recovery canary' \
  --runtime-receipt /var/lib/qdev-runner-worker/worker-runtime-receipt.json
```

Use `--require-primary-slot` or `--require-reserve-slot` only for a controlled
idle failover test; a busy but healthy tier is not otherwise a defect.
