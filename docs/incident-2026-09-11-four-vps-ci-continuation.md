# QDev CI four-VPS incident — continuation runbook (2026-09-11)

Closure work for the 2026-09-11 QDev CI incident across the four existing VPS.
Single operator, one queue owner at a time; no parallel queue operators, no
sub-agents, no invented hosts and no purchased capacity.

This runbook is written to be resumed from a cold start. Read it top to bottom
before issuing any claim or touching a host.

## 1. Status at handoff

Done and verified:

- Root cause identified and fixed in the candidate artifact (PR #188, squash
  merged to `main`). The blocker that made **every** activation impossible is
  removed.
- Local verification green: `ruff check .` clean, `ruff format --check .` clean,
  `pytest -q` -> 1205 passed (+2 new tests over the 1203 baseline).
- GitHub CI on the PR: `verify` pass, `qdev-runner-contract` pass.

In flight:

- Hosted recovery build for the new `main` revision, run
  `34588295309` (`controller-recovery-build.yml`, `expected_sha` =
  `7433e4909bc92d23cc26fd3d6bf9fe939b99ebd8`). **Status was `in_progress` at
  handoff.** Resume by checking the run, then download the sealed artifact
  `controller-recovery-7433e49...`.

Not started (the whole operational remainder, sections 4-9 below).

Safety invariant honoured so far: **nothing on any host was mutated**. All VPS
work in this run was read-only. The active runtime is still the incumbent
`eb9eea64...` and the broker containers were never restarted.

## 2. Pinned identities

| Item | Value |
| --- | --- |
| Candidate revision (new `origin/main`) | `7433e4909bc92d23cc26fd3d6bf9fe939b99ebd8` |
| Previous `origin/main` | `7d9542023e7f74690ad27ae4d681fb5f8f6caca5` |
| Active runtime (rollback candidate) | `eb9eea64cb35abf1a2bbc53dfe1ec1a8a10f6dbf` |
| Active release digest | `sha256:cae88721bc7ac756fa3cb87f61d7ba3d549b21991af03e1a067f9cb406e7a91a` |
| Active runtime images (public = internal) | `sha256:7b293fe650049099f4e5bfc2115fc1e7d57ea82f2fdf3f0154a823b4d3bd8341` |
| Active policy bundle | `f193628c0387d8cd2d35c4209e75334fff6428fdd54641c0beb7e607fbccddde` |
| R1 transaction (closure target) | `controller-eb9eea64-34515000659-r1` |
| R2 transaction (historical, no-mutation) | `controller-eb9eea64-34537511259-r2` |
| Cancelled terminal Platform job | `102459781441` (terminal `cancelled`, recoverable = no) |
| Failed activation transaction | `controller-7d954202-34586195052-r1` |
| Fixed Platform runner | `qdev-platform-ci-187`, GitHub runner ID `278` |

Release pointer semantics on the controller host:

- Canonical release symlink: `/opt/qdev-runner-control-plane/current` ->
  `/opt/qdev-runner-control-plane/releases/<sha>` (currently `eb9eea64...`).
- Activation status:
  `/var/lib/qdev-runner/controller-activation/activation-status.json`.
- Public projection:
  `/var/lib/qdev-runner/controller-status/controller-activation.json`.
- Transaction material:
  `/var/lib/qdev-runner/controller-activation-transactions/<transaction>/`.

## 3. Root cause (verified live and in git)

Activation of any candidate failed with `activation_failed` and exit 75.

1. The adapter `_trusted_current` resolves the **active** release and execs
   `$ACTIVE/scripts/activate_controller_release.sh <candidate>`; that wrapper
   execs the **active (incumbent)** payload
   `$ACTIVE/scripts/activate_controller_release_payload.sh`.
2. The immutable incumbent payload (`eb9eea64...`) reads
   `max_disk_used_pct="${QDEV_CONTROLLER_MAX_DISK_USED_PCT:-96}"` and passes
   `--max-disk-used-pct 96` to the capacity gate.
3. It invokes the **candidate's** gate (`$release/scripts/controller_capacity_gate.py`,
   absolute candidate path) whose `HARD_MAX_DISK_USED_PCT = 90.0` rejected `96`
   with `SystemExit` -> payload `exit 75` -> adapter `activation_failed`.
4. No mutation occurred. Host metrics already passed every other bound.

The earlier diagnosis blaming a gate *default* of 96 was wrong:
`--max-disk-used-pct` is `required=True` and the payload always passes it
explicitly, so the default is dead code. The transmitted **argument** was the
problem, not any default.

**Do not** work around this with a host-side env override
(`QDEV_CONTROLLER_MAX_DISK_USED_PCT`, or an allow-build override). The incumbent
guards overrides behind an explicit build override, and forcing a rebuild of the
incumbent is out of scope. The fix belongs in the candidate artifact.

### Fix shipped

`scripts/controller_capacity_gate.py` now accepts exactly the legacy incumbent
default `96`, clamps it to the published `90%` ceiling and records the clamp on
stderr. Every other above-ceiling value (`91`-`95`, `97`) still fails closed
before any measurement or mutation. The operator override surface continues to
refuse anything above `90%`. Contract documented in
`docs/controller-capacity-recovery.md` under "Legacy incumbent activation
ceiling" and pinned by tests in `tests/test_capacity_contract.py`.

## 4. Remaining work — activation (P2)

1. Confirm the hosted recovery build succeeded and fetch the sealed artifact:

   ```
   gh run view 34588295309 --repo belilovsky/qdev-runner-control-plane
   gh run download 34588295309 --repo belilovsky/qdev-runner-control-plane \
     --name controller-recovery-7433e4909bc92d23cc26fd3d6bf9fe939b99ebd8
   ```

   Alternatively build locally:
   `scripts/controller_recovery_artifact.py build --release-root . --output <dir> --confirm-non-production-build-host`.

2. Reconcile/verify the artifact on the controller host (`verify-artifact`,
   manifest digest report) and CAS-install the adapter if its digest changed.
   Current adapter digest: `sha256:382c85ec601d...` (`/usr/local/sbin/qdev-controller-activate`, mode 0700).

3. Re-issue activation assets with a **new** transaction ID via
   `qdev-controller-activation-assets` (`issue-unsigned` -> `sign-envelope` ->
   `stage`). Envelope TTL must be <= 1800 s. Re-check the generation counter
   before issuing (was 12).
   - Signing key: `/etc/qdev-runner/controller-activation-signing/ed25519-private.pem`
   - Receipt key: `/root/controller-receipt-key.txt` (0600)
   - Public key: `/etc/qdev-runner/trust/controller-activation-ed25519.pub`
   - Tool path: `/usr/local/sbin/qdev-controller-activation-assets`

4. Rebuild the adapter request JSON using the same `REQUEST_FIELDS`/`TARGET_FIELDS`
   shape as `/root/activate-7d954202-request.json`, with
   `rollback_revision = eb9eea64cb35abf1a2bbc53dfe1ec1a8a10f6dbf` and
   `rollback_release_digest = sha256:cae88721bc7ac756fa3cb87f61d7ba3d549b21991af03e1a067f9cb406e7a91a`,
   then:

   ```
   sudo /usr/local/sbin/qdev-controller-activate < request.json
   ```

   Adapter env: `PATH=/usr/local/sbin:...`, `LANG=LC_ALL=C.UTF-8`,
   `PYTHONNOUSERSITE=1`, `QDEV_CONTROLLER_ACTIVATION_ENVELOPE`,
   `QDEV_CONTROLLER_ACTIVATION_PUBLIC_KEY`, `QDEV_CONTROLLER_ARTIFACT_MANIFEST`.
   The wrapper holds `flock -n 9 /run/lock/qdev-controller-activation.lock`.
   Exit codes: 64 usage, 66 missing inputs, 74 images unavailable, 75 lock held,
   77 ownership/material unsafe, 78 attestation/identity mismatch.
   Success is `status: completed` with `qdev-fleet-bootstrap-adapter-result-v2`.

5. Post-activation verification:
   - `/opt/qdev-runner-control-plane/current` -> new release;
   - broker containers on `qdev-runner-broker:controller-<newsha>`;
   - `/health` `controller_activation.state == "active"` plus additive
     aggregate fields only;
   - `controller_release.revision == <newsha>`.

6. Close R1 only through the fixed signed root-dispatch operation
   `reconcile-controller-activation`, which accepts **only** an existing
   immutable transaction ID and digest envelope — no shell commands, URLs,
   hosts, labels or free parameters. It must verify activation status, runtime
   SHA, public/internal image digests, current release link, health and staged
   material before any change, and finish R1 only when the runtime already
   matches the candidate exactly. A stale rollback anchor may only be
   atomically re-published from the already staged and verified R1 anchor; any
   foreign, missing or mismatched anchor chain is fail-closed with no rollback,
   no runtime change and no new claims.
   **Never dispatch reconcile while the runtime is still `eb9eea64...`** — it
   raises `reconciliation_runtime_mismatch`. Re-verify that the R1 transaction
   sentinel state is what a reconcile expects before dispatching.

7. R2 is a historical `unknown outcome`: verify it was not applied, produce a
   `resolved_no_mutation` receipt, do **not** replay its activation, do not
   change runtime and do not delete its material before retention expires. An
   expired recovery envelope must never be plain-replayed. Envelope
   `8d611aae...` already expired at 2026-09-11T10:11:32Z (issued 10:01:32Z,
   TTL 600 s) — re-issue, never edit timestamps.

## 5. Remaining work — capacity (P8, critical path)

There are **zero eligible slots**, so capacity is on the critical path for any
canary or queue drain.

Four existing VPS (never invent hosts):

| Name | Address | Notes |
| --- | --- | --- |
| `srv1879763` (controller) | `186.240.148.129` | 4 CPU, 193G disk 74%, 52G free, load 3.1-3.8 |
| `mail.qdev.run` | `187.55.228.239` | hosts `qdev-platform-ci-187`; 4 CPU, 193G disk 74%, 51G free |
| `srv1626458` | `148.230.117.131` | 8 CPU, 387G disk 73%, 105G free |
| `srv138jump` | `62.72.32.112` | reachable only via `-o ProxyJump=root@187.55.228.239`; last audit call returned no output — re-audit |

Procedure, strictly one host at a time: drain -> change -> re-audit -> return
intake. Never stop active jobs. Remove the temporary 97% thresholds and
unscoped overrides. Allow only allowlist cleanup of unused intermediate CI
layers and expired temporary data; **no** general Docker prune, no removal of
referenced images, volumes, rollback releases, databases or backups.

Target topology: at least 6 slots on three independent hosts (two slots each),
at least two Docker-capable hosts, at most one Docker job per host; the fourth
VPS is the N+1 reserve. Primary and reserve run in parallel; the reserve takes a
job only when the primary has no compatible free slot. FIFO is preserved
per profile.

Sizing: `ceil(p95 hourly arrivals x p95 duration minutes / 60 / 0.7)` plus one
N+1 host; fall back to a minimum of six slots when the 7-day history is
incomplete. Relocate runner/BuildKit storage only if the primary cannot reach
40 GiB free after safe cleanup, and only through the controller-managed
procedure. Long-term contract: shared worker 10 GiB/90%, ordinary worker
30 GiB/85%. Single capacity contract everywhere: at minimum 4.5 GiB free and at
most 90% usage for an exact TTL claim.

## 6. Remaining work — Platform and queue closure (P9)

1. Take a **fresh** full queue snapshot before opening intake; never use
   historical queue numbers as current.
2. Provider-terminal reconciliation for job `102459781441`: verify the tuple,
   close the associated hold/claim without requeue and without creating a second
   identity. Delete the one-off registration only after retention and with no
   durable references.
3. Restore `qdev-platform-ci-187` only through the standard controller recovery
   path; confirm GitHub runner ID `278`, labels
   `[self-hosted, Linux, X64, qdev-platform-ci]`, and idle/online status.
4. Run its canonical `runner-smoke.yml` on the default branch as a separate
   Platform recovery canary.
5. If Platform needs a new required check to replace the cancelled terminal
   job, allow exactly one new controller-authorized run on the same SHA after
   the activation/capacity gate. This is the only exception caused by the
   provider cancellation: no mass reruns, no manual requeue, no FIFO reorder,
   no label substitution.
6. Exact-SHA canaries for `qdev-ci`, `qdev-ci-browser`, `qdev-ci-docker` and the
   Platform recovery. Each must start on the expected profile/runner and finish
   with a provider-terminal receipt.
7. Open intake and let the current queue drain naturally. Record project test
   failures after start separately from the runner incident.

## 7. Remaining work — observability and closeout (P10)

- Two-minute watchdog: activation not `active` for > 2 min; pending with zero
  eligible slots for > 2 min; FIFO head older than 5/15 min; heartbeat older
  than 90 s; claim older than 300 s; resource violation; missing image;
  provider/billing block.
- If the queue head waits more than 5 min on healthy busy workers, bring in one
  pre-registered reserve host at a time, then repeat the audit and capacity
  calculation.
- Deduplicate alerts by `incident_id + state_digest + audience`; emit only
  start, material change and recovery.
- After each pending deployment job actually starts, send the exact run/job
  status to the linked active Codex tasks. Never send "fixed" for a queued job.
- Create an incident heartbeat monitor: silent while healthy and unchanged,
  notifies on SLO breach, recovery, or operator action required.
- Signed incident receipt: controller release/activation, immutable digests,
  queues and claims, runner registrations, host audits, capacity, temporary
  overrides, R1/R2 activation transactions. No secrets, no raw stderr, no
  private runner data on public surfaces.

## 8. Required checks before closeout

- R1 expired-but-committed reconciliation; stale/foreign anchor rejection; wrong
  SHA/digest/current-link rejection; idempotent repeat; R2 no-mutation
  reconciliation.
- FIFO, profile concurrency, no double claim, restart/replay without queue loss.
- Offline one-off identity recovery for a still-queued exact job and
  provider-terminal closure without requeue.
- `claim-scope-v2` expiry/replay, OIDC failure, activation SHA mismatch,
  TTL > 900 s, and 91/95/97% override rejection.
- Primary/reserve offline, both busy, disk floor, missing immutable image, drain
  of an active job.
- Alert start/change/recovery deduplication and delivery of statuses to waiting
  tasks.
- Default-branch audit of active repositories: zero critical runner-label or
  fallback contract violations (`scripts/audit_workflows.py`).

## 9. Abort, rollback and closeout gate

Stop issuing new claims immediately and roll back only the affected
control-plane component — without interrupting active jobs — on: SHA/digest
mismatch, wrong runner for a canary, FIFO violation, duplicate or lost job, or
crossing a resource floor.

The incident closes only after all of: `controller_activation=active`;
confirmed R1 transaction closure; six safe slots; four successful canaries;
natural queue start; no infrastructure holds; and a 24-hour soak with no
activation failure, stale claims, duplicate/lost jobs or head-of-queue SLO
breach.

## 10. Environment notes

- Controller host release root: `/opt/qdev-runner-control-plane`; broker state
  `/var/lib/qdev-runner`.
- Broker `/health` is only reachable on the container network, port `9020`:

  ```
  ip=$(docker inspect qdev-runner-broker-public \
    --format '{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}' | awk '{print $1}')
  curl -s "http://$ip:9020/health"
  ```

- Internal detail (`/internal/v1/operations/*`) is mTLS-only and returns nothing
  unauthenticated.
- `/health` and `qdev-runner-health-v1` must stay backward compatible; only
  additive aggregate fields are allowed (activation aggregate, eligible-slot
  counts, oldest pending age). Never add repository, SHA, job ID, runner name or
  secrets.
- New and recovery claims must use `claim-scope-v2`: TTL <= 900 s, scope bound
  strictly to the immutable job tuple. `claim-scope-v1` is history only.
- Tooling on the operator Mac: no `rg`, no `timeout`, no local `sqlite3` — use
  `grep -rn`. Run Python tooling as `.venv/bin/python -m ruff|pytest`. Quote
  globs for zsh.
