# Incident watchdog

The incident watchdog is the always-on SLO monitor for the four-VPS CI control
plane. It runs as a root `oneshot` unit every two minutes from the immutable
release tree and reads one aggregate observation document. It never reads
runner identity, repository names, job ids, SHAs or secrets into the documents
it publishes.

```bash
install -m 0644 deploy/qdev-incident-watchdog.service /etc/systemd/system/
install -m 0644 deploy/qdev-incident-watchdog.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now qdev-incident-watchdog.timer
```

`qdev_incident_observation.py` builds
`/var/lib/qdev-runner/incident-watchdog/observation.json` from the public
`/health` document plus the optional aggregate internal document
`/var/lib/qdev-runner/incident-watchdog/internal-observation.json`.
`qdev_incident_watchdog.py` evaluates that observation and appends only state
transitions to `/var/lib/qdev-runner/incident-watchdog/alerts.jsonl`.

## Published SLO limits

These limits are an operational contract. They are identical in the scripts,
the units, the tests and this document.

| Condition | Limit | Code | Severity |
| --- | --- | --- | --- |
| `controller_activation` not `active` | 120 s | `controller_activation_not_active` | critical |
| pending jobs with zero eligible slots | 120 s | `pending_without_eligible_slot` | critical |
| FIFO head wait | 300 s / 900 s | `fifo_head_delayed` / `fifo_head_critical` | warning / critical |
| worker heartbeat age | 90 s | `worker_heartbeat_stale` | critical |
| claim age | 300 s | `claim_stale` | critical |
| free disk below 4.5 GiB or usage above 90% | 4.5 GiB / 90% | `resource_floor_crossed` | critical |
| immutable runner or controller image missing | - | `immutable_image_missing` | critical |
| provider or billing block | - | `provider_block` | warning |

An unmeasured value is never read as zero: a missing disk measurement does not
raise `resource_floor_crossed`, and the two dwell conditions
(`controller_activation_not_active`, `pending_without_eligible_slot`) are timed
by a durable clock that survives a collector restart.

## Alerting contract

Alerts are deduplicated by `incident_id + state_digest + audience`. The state
digest covers the breach code and severity set plus bucketed aggregates only,
so an unchanged state stays silent. Exactly three transitions are published:

- `start` - the first breach after an unknown or healthy state;
- `change` - a material change of the breach set or the buckets;
- `recovery` - the first healthy observation after a non-healthy state.

Two audiences are tracked independently: `qdev-fleet-operations` receives the
breaches raised by the control plane and `codex-tasks` follows the whole
incident. A publication contains only `incident_id`, `schema`, `audience`,
`state_digest`, `dedupe_key`, `severity`, `codes` and `observed_at`. Repository,
run id, job id, runner name, host, SHA and secrets are never included.

The watchdog writes an audit `job-status` record only after the job actually
starts: an entry with `started: false` or provider status `queued` is never
eligible for recovery notification. A status change carries the exact
repository, run id and job id of the started job, plus a deterministic
`delivery_id`.

The durable delivery spool is
`/var/lib/qdev-runner/incident-watchdog/job-delivery-outbox.json`, not
`alerts.jsonl`. It is root-owned `0600`, atomically rebuilt from pending
deliveries, and is safe for at-least-once consumption by the fixed root-owned
task delivery adapter. The adapter uses `delivery_id` as its idempotency key
and writes a matching `qdev-ci-incident-delivery-receipt-v1` JSONL receipt to
`delivery-receipts.jsonl` only after its message gateway confirms delivery.
On the next watchdog pass, the exact tuple is checked and moved to the
acknowledged ledger. Until then it remains pending and is never reported as
notified. A mismatched, insecure, symlinked or unknown receipt fails closed.

The watchdog does not accept an arbitrary endpoint, executable or task mapping
from an observation. The task mapping and adapter remain fixed root-owned
configuration; no job is considered delivered merely because an audit record
or an outbox entry exists.

## Reserve escalation

When the FIFO head has waited at least 300 s, no slot is eligible, the
heartbeat is healthy and at least one healthy worker is executing at least one
job, the watchdog emits at most one `reserve-decision` record for the sealed
`mail-general-reserve` target. It refuses to select an arbitrary reserve name
from an observation; an unexpected name is a critical topology-drift alert.
The decision requires a `host-audit` and a `capacity-calculation` follow-up,
and the target is never used while a compatible slot is available.

## Internal observation document

The optional internal document supplies the aggregate measurements the public
surface does not carry. It is written by the controller's internal operations
path, is root-owned `0600`, and contains only aggregates:
`worker_heartbeat_age_seconds`, `oldest_claim_age_seconds`, `disk_free_gib`,
`disk_used_pct`, `missing_images`, `provider_block`, `healthy_workers`,
`active_jobs`, `registered_reserve_hosts` and the per-job delivery tuples
(`repository`, `run_id`, `job_id`, `status`, `started`).

## Immediate rollback triggers

Stop issuing new claims and roll back only the affected control-plane component
when the watchdog reports a SHA or digest mismatch, a canary on the wrong
runner, a FIFO violation, a duplicate or lost job, or a crossed resource floor.
Active jobs are never interrupted by a rollback. The watchdog is observation
only: it never mutates queue state, never dispatches a job and never touches an
immutable image, volume, release or backup.
