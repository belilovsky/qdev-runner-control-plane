# Controller-owned capacity recovery

This procedure recovers one paid, trusted QDev CI worker without changing a
queued job. It is deliberately narrower than runner maintenance: the broker
issues a signed, expiring directive and the existing worker applies it only to
the named profiles.

## Invariants

- Preserve repository, run ID, job ID, attempt, exact SHA, profile and FIFO.
- Do not create a provider retry, duplicate or change `runs-on`.
- Do not mutate broker rows, leases, webhooks, priorities or job timestamps
  except for the provider-reconciled stale-worker operation below. That
  operation preserves the original FIFO timestamp.
- Do not restart an active worker or remove active images, releases, rollback
  material, databases, volumes or backups.
- Do not use direct product-task SSH, systemd, a global Docker prune or a
  permanent threshold change.
- Keep at least 4.5 GiB free and at most 95% disk use. An override lasts at most
  900 seconds.

## Host configuration

Set these values in `/etc/qdev-runner/broker.env` and recreate only the broker
services through the guarded controller release:

```text
QDEV_OPERATOR_TOKEN=<random operator API token>
QDEV_OPERATOR_RECEIPT_KEY=<random receipt HMAC key>
QDEV_OPERATOR_DIRECTIVE_KEY=<random worker-directive HMAC key>
QDEV_OPERATIONS_ROOT=/var/lib/qdev-runner/operations
```

Set the exact same directive key in `/etc/qdev-runner/worker.env`:

```text
QDEV_CAPACITY_DIRECTIVE_KEY=<same worker-directive HMAC key>
```

The three broker values are atomic: partial configuration prevents broker
startup. Removing all three disables the operator endpoints. Secrets never
appear in receipts or repository files.

## Operator session

Use a controller-issued `qdev-fleet-operations` mTLS identity:

```bash
export QDEV_CONTROLLER_URL=https://worker.ci.qdev.run
export QDEV_OPERATOR_TOKEN=...
export QDEV_OPERATOR_RECEIPT_KEY=...
export QDEV_OPERATOR_MTLS_CA=/secure/controller-ca.pem
export QDEV_OPERATOR_MTLS_CERT=/secure/operator.pem
export QDEV_OPERATOR_MTLS_KEY=/secure/operator-key.pem
```

Read the signed state first:

```bash
qdev-runner-operator audit > worker-audit-receipt.json
```

An override is admitted only when the worker heartbeat is fresh, it has no
active task, the named repository/profile is registered and allowed, all
baseline blockers are disk-only, raw metrics are present, measured free space
covers the requested floor plus profile headroom, disk use is below the
requested ceiling, and no other override is active.

Create exactly one bounded override:

```bash
qdev-runner-operator override srv1879763-light-primary \
  --repository belilovsky/qazlake \
  --profile qdev-ci-docker \
  --min-disk-free-gib 4.5 \
  --max-disk-used-pct 95 \
  --duration-seconds 900 \
  --owner qdev-fleet-operations \
  --reason 'paid trusted worker; bounded exact-SHA FIFO recovery' \
  > capacity-override-receipt.json
```

The worker receives the directive on its normal authenticated heartbeat. It
verifies the signature, worker identity, repository/profile scope, hard limits and
expiry, then performs an ordinary FIFO claim. No job is dispatched by the
operator endpoint.

Cancel early after the provider-visible terminal result, or let expiry restore
the normal thresholds automatically:

```bash
qdev-runner-operator cancel srv1879763-light-primary \
  > capacity-override-cancelled-receipt.json
```

## Stale worker reconciliation

A missing worker heartbeat is not proof that its provider job stopped. The
broker therefore never auto-requeues an omitted, claimed or running job. First
capture the signed read-only candidate set:

```bash
qdev-runner-operator stale-audit --timeout-seconds 300 \
  > stale-job-audit-receipt.json
```

For one candidate only, perform a provider-bound reconciliation:

```bash
qdev-runner-operator recover-stale 123456789 \
  --timeout-seconds 300 \
  --owner qdev-fleet-operations \
  --reason 'worker heartbeat stale; reconcile immutable tuple with provider' \
  > stale-job-recovery-receipt.json
```

The controller requires an exact match of provider run ID, the job's parent run
ID, job ID, attempt and SHA. If the provider job is still `in_progress`, or any
identity field differs, recovery fails without mutation. A provider-completed
job is closed from provider evidence. Only a provider-queued job whose parent
run is not terminal is released to the ordinary queue, preserving its original
`created_at` and FIFO position. This operation does not create a run, retry a
job, change labels, rewrite a lease, or select a runner.

Validate every saved receipt offline:

```bash
python3 scripts/validate_operation_receipt.py worker-audit-receipt.json
```

The validator reads `QDEV_OPERATOR_RECEIPT_KEY`, recomputes the canonical
payload digest and HMAC, and fails on missing fields, payload changes or an
invalid signature. The schemas are in `docs/schemas/`.

## Acceptance and rollback

Capacity recovery is accepted only when a provider-visible job receipt binds
the same run, job, attempt, exact SHA, profile and expected runner and reaches a
terminal conclusion. A healthy heartbeat alone is not completion. Release
admission remains a separate signed product-specific decision.

Rollback is either explicit cancellation or automatic expiry. If the worker
does not report the directive in its next effective heartbeat, do not retry the
job: cancel the operation, retain the queued tuple and investigate the
controller/worker identity or key configuration.
