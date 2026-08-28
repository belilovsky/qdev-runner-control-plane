# `claim-scope-v1`

`claim-scope-v1` is the broker-side, short-lived allowlist for a bounded
recovery worker. It narrows a normal authenticated claim; it never replaces
the worker token, GitHub webhook validation, repository policy, profile policy,
or the SQLite atomic transition.

```json
{
  "schema": "claim-scope-v1",
  "worker_name": "qdev-recovery-primary",
  "repository": "belilovsky/qazagents",
  "head_sha": "<40 lowercase hexadecimal characters>",
  "job_ids": [123456789, 123456790],
  "expected_profiles": ["qdev-ci", "qdev-ci-docker"],
  "expires_at": "2026-08-28T12:15:00Z"
}
```

The broker accepts exactly two unique positive provider job IDs, the canonical
QazAgents repository, one exact lowercase Git SHA, and one or two unique
profiles from the recovery set (`qdev-ci` and `qdev-ci-docker`). `expires_at`
must be timezone-aware, in the future, and no more than 15 minutes ahead of the
broker's UTC clock. The claim request's worker name and profile set must match
the scope exactly.

For a scoped request, the broker passes all four constraints (job IDs,
repository, SHA, and profiles) into the store's single writer transaction. The
candidate order is the order of `job_ids`, not a project-priority or broad FIFO
fallback. A job can be claimed only once; a second worker sees no pending
matching row. The broker performs a second identity check before contacting
GitHub and requeues an unexpected match without creating a JIT runner.

Workers listed in `QDEV_CLAIM_SCOPE_WORKERS` must send a scope. Missing,
malformed, expired, future-dated, worker-mismatched, profile-mismatched, or
foreign scopes fail closed and do not mutate queue state. Ordinary workers keep
the existing request and FIFO behavior. A temporary worker reads the scope
from `QDEV_CLAIM_SCOPE_FILE` on every claim, so deleting or expiring the file
stops future claims without changing ordinary workers. The file is local
private state and must not be committed or exposed in logs.

Scope lifecycle is intentionally external to the queue: mint the two exact
GitHub job IDs and SHA after provider scheduling, configure the named worker
and `QDEV_CLAIM_SCOPE_WORKERS`, then revoke by removing the worker from the
allowlist and deleting the scope file. No hosted fallback or selector change
is implied by this contract.
