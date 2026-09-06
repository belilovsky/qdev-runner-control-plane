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

1. Stage the clean, root-owned exact release directly below
   `/opt/qdev-runner-control-plane/releases/` with the directory name equal to
   its 40-character source SHA. Before activation, advance the durable
   controller candidate with the release-owned, lock-serialized operation:

   ```bash
   /opt/qdev-runner-control-plane/releases/SHA/scripts/prepare_controller_candidate.py \
     /opt/qdev-runner-control-plane/releases/SHA
   ```

   The operation measures the active runtime receipt and the target Git tree,
   signs the blocked supersession and new source admission locally, and never
   accepts either SHA from the caller. It is crash-resumable and a replay after
   completion returns `already_completed` without a new receipt. Preserve the
   returned private receipt URIs and ledger digest.
2. Activate that same exact controller release containing the typed recovery API and
   the two fixed host-agent profiles. Enrol each already assigned host with its
   own root-owned configuration and certificate. Activation and enrolment use
   the existing managed fleet adapters; GitHub workflows never receive SSH,
   the QDev CA, agent keys or a general command primitive.
3. From the certificate-authenticated operator session, prepare exactly one
   target. The client first reads the live `/bindings` projection and binds a
   fresh request to the active controller revision, release, policy, agent and
   interface digests:

   ```bash
   qdev-runner-operator recovery-prepare qdev-platform-ci-187 \
     --idempotency-key recovery-platform-20260905-01 \
     --reason 'restore existing dedicated Platform CI runner'
   ```

   Save the returned `operation_id` and `request_fingerprint`. For saved-
   configuration recovery, the controller requires the unique same-name
   provider runner. For replacement recovery, it accepts either that idle
   runner or a signed observation that the name is absent and has no active
   provider jobs. It refuses preparation when the runner is busy, has active
   jobs or has a conflicting identity.
4. Start the already installed one-shot service on the fixed target host:

   ```bash
   systemctl start qdev-runner-recovery-platform.service
   # or, for the other fixed host:
   systemctl start qdev-runner-recovery-qazstack.service
   ```

   The platform profile verifies and restores its saved runner configuration.
   The QazStack profile obtains a short-lived registration token only inside
   the controller transaction and uses `--replace` for the same runner name.
   Each agent persists private native proof before reconciling it to the
   controller. A retry resumes pending reconciliation or returns idle; it does
   not repeat a completed mutation.
5. Run controller acceptance and then read the exact transaction:

   ```bash
   qdev-runner-operator recovery-accept \
     --operation-id OPERATION_ID \
     --request-fingerprint REQUEST_FINGERPRINT
   qdev-runner-operator recovery-status \
     --operation-id OPERATION_ID \
     --request-fingerprint REQUEST_FINGERPRINT
   ```

   Acceptance requires the expected permanent labels, GitHub `online` and
   `busy=false`, zero active jobs, a controller-dispatched exact-default-SHA
   canary on the same runner, and a successful provider-visible terminal job.
   Only `completed` or `already_completed` closes recovery. Replay the same
   prepare request and confirm `idempotent_replay=true` without a new mutation.

The controller refuses recovery when active work is reported, when a saved-
configuration target is not registered, when identity returned by the adapter
does not exactly match the allowlist, or when the adapter is unavailable. A
missing replacement target is admitted only from the signed absence
observation described above; it is never inferred from a timeout or stale
heartbeat. Refusals are recorded as `active_work`, `target_unregistered`,
`failed` or `access_blocked`; they must not be converted into a green workflow
result.
There is no direct SSH/systemd fallback and no manual mutation of FIFO jobs or
leases. The production runner remains reserved for production operations.

The external recovery edge must authenticate client mTLS, remove any incoming
identity/proxy headers, and inject both
`X-QDev-Operator-Proxy-Auth` and
`X-QDev-Verified-Client-Certificate-SHA256` from verified connection state.
The operator client deliberately does not set those headers. The controller
matches the operator or fixed host-agent certificate against its private
allowlist and fails closed on missing or mismatched release bindings.

The fixed adapter, host agent, installer and service units are shipped by this
repository and installed by the controller release. Their actions, paths,
services, repositories, runner names and labels are compiled into the release;
HTTP callers cannot alter them. Missing host enrolment or an unavailable
external edge is a visible `access_blocked` condition, not permission to run
arbitrary shell from a workflow.

Set recovery values only in root-owned private controller/agent environment
files. In addition to the existing operator settings, the controller requires:

```text
QDEV_OPERATOR_PROXY_SECRET=<edge-to-controller secret>
QDEV_RECOVERY_OPERATOR_CERTIFICATE_SHA256S=<allowlisted operator fingerprints>
QDEV_RECOVERY_PLATFORM_AGENT_CERTIFICATE_SHA256=<fixed host fingerprint>
QDEV_RECOVERY_QAZSTACK_AGENT_CERTIFICATE_SHA256=<fixed host fingerprint>
QDEV_RECOVERY_POLICY_DIGEST=<checked-in policy digest>
QDEV_RECOVERY_AGENT_RELEASE_DIGEST=<activated immutable agent release digest>
QDEV_RECOVERY_AGENT_SIGNING_KEY=<controller/agent reconciliation key>
```

Provision these values after issuing the two fixed agent certificates. The
source-owned helper preserves existing secrets on replay and emits only public
binding metadata; use `--rotate-secrets` only as an explicit coordinated
rotation because both agents and the edge must be updated in the same
transaction:

```bash
qdev-worker-recovery-bindings-provision \
  --operator-cert /etc/qdev-runner/mtls/operator/operator-cert.pem \
  --platform-agent-cert /etc/qdev-runner/mtls/controller/scoped/qdev-platform-ci-187-cert.pem \
  --qazstack-agent-cert /etc/qdev-runner/mtls/controller/scoped/qdev-qazstack-01-cert.pem
```

`recovery-controller.env` is loaded only by the internal broker;
`recovery-edge.env` contains only the edge-to-controller proxy secret. The
public broker explicitly blanks every recovery authority even if an operator
accidentally adds one to the shared broker environment.

The release status file supplies the active controller revision and release
digest. Host configuration pins the same values plus the recovery interface
version/digest and keeps state, lock and receipt paths under private `/var` and
`/run` locations. Never copy these secrets or private receipt payloads into a
workflow artifact.

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
qdev-runner-operator queue-audit > durable-queue-audit-receipt.json
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
  --operation-id "$OPERATION_ID_FROM_CREATE_RECEIPT" \
  > capacity-override-cancelled-receipt.json
```

Creation is serialized per worker and must name the signed durable FIFO head.
Cancellation is compare-and-swap: if another controller transaction has
replaced the operation ID, it returns a conflict and leaves that operation
untouched. Expiry closes admission for new jobs; it does not terminate the
exact job already admitted under the directive. That job retains the validated
disk hard floor captured at admission and remains bounded by its immutable
profile timeout. Crossing that hard floor still stops the runner immediately.

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

A non-zero worker exit can leave the controller terminal while GitHub still
reports the exact job as queued. Audit and recover that narrower state through
the dedicated operation:

```bash
qdev-runner-operator failed-audit \
  > failed-job-audit-receipt.json
qdev-runner-operator recover-failed 123456789 \
  --owner qdev-fleet-operations \
  --reason 'worker exited while provider retained the exact queued job' \
  > failed-job-recovery-receipt.json
```

The same immutable provider tuple and parent-run checks apply. Recovery is an
atomic compare-and-swap against the observed failed row; policy failures and
other terminal states are not eligible. A successful release clears the old
worker binding and terminal timestamp while preserving the original FIFO
creation time.
