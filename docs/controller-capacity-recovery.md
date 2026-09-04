# Existing CI worker recovery

This runbook covers the only supported recovery path for the two registered
workers used by the Markdown-first release:

- `qdev-platform-ci-187` → `actions.runner.belilovsky-platform-portal.qdev-platform-ci-187`
- `qdev-qazstack-01` → `actions.runner.belilovsky-qazstack.qdev-qazstack-01`

The mapping is stored in `config/fleet-bootstrap.yml`. `worker_name` is a
logical request name; the controller resolves the target id, service unit,
host binding and labels from that file and its private registry. A workflow
cannot choose a host, service, executable, certificate or CA key.

## Procedure

1. Run the signed `.github/workflows/fleet-bootstrap.yml` validation request
   for one existing worker. Save its exact request JSON, source SHA, run id,
   job id, attempt and idempotency key. Validation is evidence only; it does
   not claim that a worker was restored.
2. From the controller operator session, invoke
   `qdev-runner-operator recover-existing-worker --request REQUEST.json
   --idempotency-key KEY --active-jobs 0`. The operator client uses the
   mTLS-protected `/internal/v1/operations/fleet-bootstrap/recover-existing-worker`
   endpoint. The controller supplies the policy, durable state paths and the
   controller-installed `/usr/local/sbin/qdev-fleet-worker-recovery` adapter.
3. Verify the signed receipt and the private append-only receipt. Only an
   adapter result of `completed` or `already_completed` changes durable
   operation state to `completed`. Retries with the same idempotency key are
   safe; a different request under that key is rejected.
4. Recheck GitHub runner `online` and `busy=false`, the expected permanent
   labels, a fresh `qdev-ci` admission and a native canary on that runner.

The controller refuses recovery when active work is reported, when the target
is not registered, when identity returned by the adapter does not exactly
match the allowlist, or when the adapter is unavailable. Those outcomes are
recorded as `active_work`, `target_unregistered`, `failed` or
`access_blocked`; they must not be converted into a green workflow result.
There is no direct SSH/systemd fallback and no manual mutation of FIFO jobs or
leases. The production runner remains reserved for production operations.

The adapter is an existing, reviewed controller primitive and must be
installed by the control-plane provisioning/release process with root-owned
permissions. This repository deliberately does not ship a substitute adapter:
absence is a visible `access_blocked` condition rather than permission to run
arbitrary shell from a workflow.

## Existing capacity controls

The existing bounded capacity operations remain available and keep their
original invariants. Preserve repository, run id, job id, attempt, exact SHA,
profile and FIFO. Do not create a provider retry or duplicate, change
`runs-on`, mutate broker rows, leases, webhooks, priorities or job timestamps,
restart an active worker, remove active images/releases/rollback material, or
perform a global Docker prune. Disk-only overrides keep the controller's hard
floor of 4.5 GiB free and 95% maximum use, and expire within 900 seconds.

Set operator values only in the root-owned `/etc/qdev-runner/broker.env` and
the worker directive key in `/etc/qdev-runner/worker.env`; secrets never enter
receipts or repository files:

```text
QDEV_OPERATOR_TOKEN=<random operator API token>
QDEV_OPERATOR_RECEIPT_KEY=<random receipt HMAC key>
QDEV_OPERATOR_DIRECTIVE_KEY=<random worker-directive HMAC key>
QDEV_OPERATIONS_ROOT=/var/lib/qdev-runner/operations
```

Use a controller-issued `qdev-fleet-operations` mTLS identity and read the
signed state first:

```bash
export QDEV_CONTROLLER_URL=https://worker.ci.qdev.run
export QDEV_OPERATOR_TOKEN=...
export QDEV_OPERATOR_RECEIPT_KEY=...
export QDEV_OPERATOR_MTLS_CA=/secure/controller-ca.pem
export QDEV_OPERATOR_MTLS_CERT=/secure/operator.pem
export QDEV_OPERATOR_MTLS_KEY=/secure/operator-key.pem
qdev-runner-operator audit > worker-audit-receipt.json
```

An override is admitted only for a fresh, idle worker with a registered
repository/profile, disk-only blockers, measured metrics and no other active
override. It is applied by the worker's normal authenticated heartbeat; the
operator endpoint never dispatches a job. Cancel it after the provider-visible
terminal result or let expiry restore normal thresholds:

```bash
qdev-runner-operator override srv1879763-light-primary \
  --repository belilovsky/qazlake \
  --head-sha 0123456789abcdef0123456789abcdef01234567 \
  --profile qdev-ci-docker \
  --min-disk-free-gib 4.5 --max-disk-used-pct 95 \
  --duration-seconds 900 --owner qdev-fleet-operations \
  --reason 'bounded exact-SHA FIFO recovery' \
  > capacity-override-receipt.json
qdev-runner-operator cancel srv1879763-light-primary \
  > capacity-override-cancelled-receipt.json
```

## Stale-job reconciliation

A missing heartbeat is not proof that a provider job stopped. Capture the
read-only candidate set first, then reconcile one candidate only:

```bash
qdev-runner-operator stale-audit --timeout-seconds 300 \
  > stale-job-audit-receipt.json
qdev-runner-operator recover-stale 123456789 --timeout-seconds 300 \
  --owner qdev-fleet-operations \
  --reason 'worker heartbeat stale; reconcile immutable tuple with provider' \
  > stale-job-recovery-receipt.json
```

The controller requires an exact provider run/job/attempt/SHA match. An
in-progress job or identity mismatch fails without mutation. A provider-
completed job is closed from provider evidence; only a provider-queued job
whose parent run is not terminal is released to the ordinary queue, preserving
its original creation time and FIFO position. Validate saved receipts with
`scripts/validate_operation_receipt.py`; a healthy heartbeat alone is never
completion evidence.
