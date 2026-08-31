# QDev runner control plane

This repository is the recovery control plane for ephemeral self-hosted GitHub
Actions runners used by the active `belilovsky` repositories. Paid
GitHub-hosted compute is the normal execution path. The QDev pool is the
explicit recovery path when hosted compute or its billing lane is unavailable;
it still depends on GitHub orchestration and the GitHub API.

## Contract

- A v2 repository contract declares `github-hosted-primary` and keeps a
  separately dispatchable self-hosted recovery workflow. Legacy v1 contracts
  remain valid until their repository is deliberately migrated.
- Recovery jobs select exactly one of `qdev-ci`, `qdev-ci-browser` or
  `qdev-ci-docker` together with `self-hosted`, `Linux`, `X64`.
- A queued `workflow_job` webhook is accepted only for a repository in
  `inventory/repos.json` and a profile allowed by `.github/qdev-runner.yml`.
- The broker creates a JIT registration. A worker starts one rootless,
  resource-limited container for one job and removes it afterwards.
- `qdev-ci-docker` receives a job-scoped Docker/BuildKit daemon inside a
  disposable privileged sidecar of the rootless worker engine. The runner
  shares only that sidecar's network namespace and socket; the worker's Docker
  socket is never mounted into a job. The broker injects the narrow registry
  credential through the private job env-file, and the runner logs into the
  private registry only inside its disposable container.
  This uses the dedicated `qdev-runner` registry account; the existing `qdev`
  account is not rotated or exposed to jobs.
- Public repositories may use the recovery pool only for pull requests whose
  head repository ID equals the allowlisted base repository ID. Public fork
  pull requests and missing head-repository provenance are rejected. Dedicated
  release labels remain product-specific and are not assigned to the general
  pool.
- The capacity gate stops claims above 85% disk usage, below 30 GiB free disk,
  below 4 GiB available memory or above load-15 equal to twice the CPU count.
  Worker-specific floors can be raised with `QDEV_WORKER_MIN_FREE_GIB`,
  `QDEV_WORKER_MAX_DISK_USED_PCT`, `QDEV_WORKER_MIN_MEMORY_AVAILABLE_GIB`,
  `QDEV_WORKER_MAX_LOAD_PER_CPU` and `QDEV_WORKER_MAX_CPU_PSI_AVG10`.
  A source-reviewed `repository_admission_disk_mb` entry may lower only one
  exact repository/profile reservation, never below 12 GiB. All other jobs keep
  the profile default, and the worker rechecks its hard disk floor throughout
  execution and terminates a job before that floor is crossed.
- Every registered repository carries the managed root `AGENTS.md` policy,
  `.github/QDEV_RUNNERS.md`, and the local `qdev-runner-contract` check. Future
  agents must install this starter bundle instead of creating a standalone
  runner or silently changing execution lanes.
- An exceptional temporary worker may be given a `claim-scope-v1` document.
  Its scope binds one worker name and tier to a short expiry, one repository
  and exact Git SHA, and an explicit job-ID/profile map. Certificate-bound
  scopes additionally pin the Caddy-verified mTLS client-certificate SHA-256;
  the normal shared worker token is not a fallback credential for those scopes.
  Generate the private key and CSR on the scoped VPS; the controller signs only
  that public CSR with `scripts/issue_scoped_worker_certificate.sh` and returns
  the public certificate fingerprint for the scope record. Once a worker supplies
  a scope ID, a missing, expired, malformed, or mismatched scope fails closed;
  it cannot fall back to the shared queue. Unscoped workers retain ordinary
  FIFO behavior. Scope documents are operational secrets only insofar as they
  describe an in-flight release and belong in `/etc/qdev-runner/`, never Git.

The operating model, failure taxonomy, recovery sequence, and evidence
contract are in `docs/github-actions-operating-model.md`.

## Repository onboarding

Start from `templates/qdev-runner.yml` and `templates/runner-smoke.yml`, then
install the managed policy into the repository checkout:

```bash
python3 scripts/apply_repository_policy.py /path/to/checkout
python3 /path/to/checkout/.github/scripts/qdev-runner-policy.py \
  --root /path/to/checkout
```

For v2 products whose protected release workflow uses GHCR, declare the exact
workflow filename under `release_registry_workflows` in
`.github/qdev-runner.yml`. The exemption is limited to `ghcr.io` inside that
non-PR release lane; caches, Actions artifacts, and GitHub Packages remain
policy violations.

Register the repository in `inventory/repos.json`, install the GitHub App, and
run `runner-smoke` on its default branch. The installer is idempotent and
preserves repository-specific instructions outside its marked `AGENTS.md`
section.

After the policy workflow is present on the default branch, preserve the
repository's existing classic branch-protection settings and add only the
managed check:

```bash
python3 scripts/configure_required_check.py --repository owner/repository
python3 scripts/configure_required_check.py --apply --repository owner/repository
```

The first command is a dry run. Repositories without classic branch protection
are reported and left unchanged.

## Services

- `https://ci.qdev.run/github/workflow-job` — signed GitHub App webhook.
- `https://ci.qdev.run/health` — public-safe broker health.
- `https://worker.ci.qdev.run/internal/v1/*` — mTLS worker API, published by
  the source-owned `qdev-edge` release. The controller exposes only its
  internal mTLS broker on port 9443; `scripts/issue_edge_proxy_certificate.sh`
  creates the one-day, client-auth-only backhaul credential locally on that
  host. It must never be copied to a worker or committed.
- `https://worker.ci.qdev.run/internal/v1/operations/*` — mTLS operator API
  for signed audits and one expiring, disk-only capacity override.
- `https://ci.qdev.run/artifacts/...` — checksum-verified, short-lived artifacts.
- `https://registry.ci.qdev.run/v2/` — private OCI registry.

## Guarded controller release

Stage each revision in its own directory below
`/opt/qdev-runner-control-plane/releases/`. Activate it with the revision's
own script:

```bash
sudo scripts/activate_controller_release.sh \
  /opt/qdev-runner-control-plane/releases/REVISION
```

Activation requires at least 30 GiB free disk, less than 85% disk use, at
least 4 GiB available RAM, and load-15 no greater than twice the CPU count. It
atomically changes `current`, refreshes the repository inventory and runner
profiles, and recreates only `broker-public` and `broker-internal`. The prior
profile file is restored together with the previous release if activation
fails. It does not restart a worker, stop the registry, remove Compose or Docker
objects, or touch product containers. If either Compose or the public health
check fails, the script restores the previous release and its configuration.

For an inventory-only revision that reuses the already verified broker images,
the owner may make a bounded capacity override together with
`QDEV_CONTROLLER_NO_BUILD=true`. The defaults remain 85% disk use, 30 GiB free
disk, 4 GiB available memory and load-15 at two times CPU count. Override only
the measured failing floor, keep the previous immutable release available and
record the live health receipt.

For a source release that must rebuild the broker, the same bounded override
also requires `QDEV_CONTROLLER_ALLOW_BUILD_CAPACITY_OVERRIDE=true`. It is an
explicit one-release acknowledgement, not a default: set only the measured
failing limits, retain the rollback release, and record the capacity and health
receipts before activation. The worker service is still outside this path.

To select a previously staged revision without rebuilding its cached images:

```bash
sudo scripts/rollback_controller_release.sh REVISION
```

Runner images are built from the pinned definitions in `images/runner` and
published only after the same capacity gate is healthy:

```bash
QDEV_PUSH_IMAGES=true scripts/build_runner_images.sh
```

Record the three resulting registry digests in rollout evidence. Do not reuse
a mutable image from an unverified build.

Before removing a worker pause after any image cleanup, run the local executor
audit as a trusted administrator with the worker's rootless Docker environment.
It fails if the configured tier/name identity is inconsistent or an enabled
profile's immutable runner/sidecar image is absent:

```bash
python3 scripts/audit_worker_runtime.py --output worker-runtime-receipt.json
```

Workers use a default-deny, owner-bound execution gate. Provisioning does not
create the run permit. Acquire the gate before maintenance, then release it
with the same owner and a fresh passing runtime-audit receipt; never resume by
deleting the compatibility pause marker directly. The service validates the
permit owner, enabled gate state, and referenced passing audit before every
start, so creating an empty permit file cannot bypass the gate.

The provisioning script keeps the 30 GiB free-space minimum by default. A
single owner-authorized bootstrap may lower only that provisioning minimum by
setting both `QDEV_WORKER_PROVISION_MIN_FREE_GIB` (an integer from 20 through
30) and `QDEV_WORKER_ALLOW_PROVISION_CAPACITY_OVERRIDE=true`. It does not
relax the 85% disk-use, memory, or load gates, and does not start the worker.
Before the owner-bound execution permit is released, `worker.env` must carry
the normal runtime gate or a separate, source-validated runtime override.

When a scoped worker must run a profile whose explicit disk reservation cannot
fit above the default runtime floor, its owner may make a second, independent
runtime override. It requires all of `QDEV_CLAIM_SCOPE_ID`,
`QDEV_WORKER_ALLOW_RUNTIME_CAPACITY_OVERRIDE=true`, a free-space floor from 4
through 30 GiB, and a disk-use ceiling no higher than 90%. Memory and load
gates cannot be relaxed. The active override is reported in the worker
heartbeat, and the broker still requires the configured floor plus the claimed
profile's disk reservation before assigning a job.

Worker provisioning archives the exact obsolete
`qdev-runner-worker.rollout-permit` and its existence-only drop-in. Do not
recreate that compatibility permit: the executable owner/audit validator is
the only accepted start boundary.

A green heartbeat is only broker/capacity evidence. Recovery closes only when
the same-SHA GitHub canary leaves `queued`, reports the expected runner name,
and succeeds.

## Signed capacity and stale-worker recovery

The capacity endpoint never changes a job, FIFO order, lease, label, profile or
`runs-on`. It can issue one signed override for a fresh, idle worker only when
the baseline blocker is disk-only and measured headroom still covers the hard
4.5 GiB floor plus the exact repository/profile's declared requirement. The directive
expires after at most 15 minutes and the worker verifies its signature, worker
name, repository/profile scope and timestamps before using it.

The broker never automatically releases a claimed or running job merely
because its worker heartbeat disappeared. Stale candidates are read-only until
an mTLS-authenticated operator reconciles the complete immutable tuple with the
GitHub provider. A provider-active job remains untouched. A provider-completed
job is closed locally, and only a provider-queued job may be released for an
ordinary claim while retaining its original `created_at` and FIFO position.
This is the sole stale-worker mutation path; it never creates or retries a
provider run.

Configure all three broker values atomically:

- `QDEV_OPERATOR_TOKEN`
- `QDEV_OPERATOR_RECEIPT_KEY`
- `QDEV_OPERATOR_DIRECTIVE_KEY`

Set the same directive key on the worker as
`QDEV_CAPACITY_DIRECTIVE_KEY`. Keep all values in the host environment files,
never Git. Operator calls additionally require the existing mTLS client
identity. See `docs/controller-capacity-recovery.md` for the audited procedure,
receipt schemas and rollback.

## Portfolio rollout

Use `scripts/rollout_repository_policy.py` from isolated temporary clones and
merge in bounded waves. Preserve every existing required check and add
`qdev-runner-contract` only after that workflow is present on the default
branch. Run `runner-smoke` on each resulting default SHA and record repository,
SHA, run ID, queue time, and runner name. Deployment workflows and dedicated
release labels are never dispatched as part of this validation.

After a wave is merged, dispatch and record only the smoke workflow in bounded
batches:

```bash
.venv/bin/python scripts/run_smoke_rollout.py --apply --batch-size 15 \
  --output runner-smoke-receipt.json
```

The script resolves each repository's current default SHA before dispatch and
fails unless every recorded `runner-smoke` job completes successfully.

## Local verification

```bash
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/ruff check .
.venv/bin/mypy
.venv/bin/pytest
python3 scripts/refresh_inventory.py
python3 scripts/audit_workflows.py --allow-migration
```

Secrets are provisioned only on the broker/worker hosts. GitHub App keys,
webhook secrets, worker tokens, registry passwords and client certificates
must never be committed.
