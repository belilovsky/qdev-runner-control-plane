# QDev runner control plane

This repository is the recovery control plane for ephemeral self-hosted GitHub
Actions runners used by the active `belilovsky` repositories. Paid
GitHub-hosted compute is the normal execution path. Exact workflows may declare
the existing QDev pool as a bounded primary lane while hosted compute or its
billing lane is unavailable; it still depends on GitHub orchestration and the
GitHub API.

## Contract

- A v2 repository contract declares `github-hosted-primary`, keeps a separately
  dispatchable self-hosted recovery workflow, and may allowlist exact primary
  self-hosted workflow filenames. Legacy v1 contracts remain valid until their
  repository is deliberately migrated.
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
- The capacity gate defaults to stopping claims above 85% disk usage or below
  30 GiB free disk. A continuously monitored shared worker may use a durable
  floor down to 10 GiB and a ceiling up to 90% when profile disk reservations
  are still added before every claim; this is baseline capacity, not a scoped
  override. Claims also stop
  below 4 GiB available memory or above load-15 equal to twice the CPU count.
  Worker-specific floors can be raised with `QDEV_WORKER_MIN_FREE_GIB`,
  `QDEV_WORKER_MAX_DISK_USED_PCT`, `QDEV_WORKER_MIN_MEMORY_AVAILABLE_GIB`,
  `QDEV_WORKER_MAX_LOAD_PER_CPU` and `QDEV_WORKER_MAX_CPU_PSI_AVG10`.
  A source-reviewed `repository_admission_disk_mb` entry may lower only one
  exact repository/profile reservation within its validated bounds. An
  optional `repository_admission_constraints` entry adds a server-owned
  absolute free-space floor and concurrency ceiling that no capacity override
  can weaken. All other jobs keep the profile default, and the worker rechecks
  its hard disk floor throughout execution and terminates a job before that
  floor is crossed.
- Every registered repository carries the managed root `AGENTS.md` policy,
  `.github/QDEV_RUNNERS.md`, and the local `qdev-runner-contract` check. Future
  agents must install this starter bundle instead of creating a standalone
  runner or silently changing execution lanes.
- An exceptional temporary worker may be given a short-lived claim-scope
  document. `claim-scope-v1` remains valid for already-issued QazAgents
  scopes. New `claim-scope-v2` documents bind every admitted job to its exact
  repository, workflow run, job ID, attempt, Git SHA, profile, worker and
  expiry. For v2, the broker admits only the current FIFO head of each allowed
  profile; a scope cannot reorder a job, substitute a SHA or change `runs-on`.
  Certificate-bound
  scopes additionally pin the Caddy-verified mTLS client-certificate SHA-256;
  the normal shared worker token is not a fallback credential for those scopes.
  Generate the private key and CSR on the scoped VPS; the controller signs only
  that public CSR with `scripts/issue_scoped_worker_certificate.sh` and returns
  the public certificate fingerprint for the scope record. Once a worker supplies
  a scope ID, a missing, expired, malformed, or mismatched scope fails closed;
  it cannot fall back to the shared queue. Unscoped workers retain ordinary
  FIFO behavior. Scope documents are operational secrets only insofar as they
  describe an in-flight release and belong in `/etc/qdev-runner/`, never Git.

  A queued managed row whose `admin-platform` ledger entry is no longer the
  active exact tuple cannot hold an unrelated profile queue. During FIFO
  scanning the broker records that row, its source tuple, and the explicit
  `admin-platform-candidate-not-active` or
  `admin-platform-candidate-tuple-not-admitted` reason in the signed
  `fifo_skipped` receipt field and the controller-written claim scope, then
  continues to the next eligible row. The worker may ignore only those exact
  repository, run, job, attempt, SHA and profile tuples while enforcing FIFO.
  A direct claim request for that stale managed row still fails closed; this is
  an observational queue repair, not a priority or requeue mechanism.

The operating model, failure taxonomy, recovery sequence, and evidence
contract are in `docs/github-actions-operating-model.md`.

### Repository CI source evidence

The normal `CI` and `qdev-runner-contract` checks use the GitHub-hosted
lane declared in `.github/qdev-runner.yml`. The QDev pool is reserved for the
explicit owner-dispatched `runner-smoke` recovery lane. GitHub-hosted checks do
not receive the controller-issued short-lived artifact credential, so this
repository's ordinary CI is not registered as a native test-report source.

For an internal pull request, checkout and verification use the exact head SHA
from the provider event, with matching base/head repository IDs and branch
refs. The execution receipt preserves GitHub's separate provider merge SHA;
`GITHUB_SHA` is never overwritten. Push and owner-authorized dispatch evidence
remain bound to the exact provider SHA. Missing or conflicting provenance is
an error. A native CI receipt is unsigned execution evidence, not controller
admission, an image scan, or a runtime activation receipt.

For a registered `qdev-ci` test workflow, the controller derives the required
native reports from `config/profiles.yml`. The current controller profile
requires both the JUnit result and Cobertura coverage source. A successful
execution is recorded as `incomplete` until both immutable source reports are
present; it cannot satisfy readiness as a passed test result. Source reports
are keyed by the exact provider repository, SHA, workflow, run, attempt, job
and path. An identical redelivery is idempotent in either delivery order, and
a changed report at the same identity is rejected.

## Repository onboarding

Start from `templates/qdev-runner.yml` and `templates/runner-smoke.yml`, then
install the managed policy into the repository checkout:

```bash
python3 scripts/apply_repository_policy.py /path/to/checkout
python3 /path/to/checkout/.github/scripts/qdev-runner-policy.py \
  --root /path/to/checkout
```

For v2 products, declare manual-only self-hosted recovery workflow filenames
under `recovery_workflows`. A bounded existing-capacity primary lane must be
listed by exact filename under `primary_self_hosted_workflows`; unlisted normal
CI remains GitHub-hosted. For v2 products whose protected release workflow uses
GHCR, declare the exact workflow filename under `release_registry_workflows` in
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
  for signed audits and one expiring, disk-only capacity override bound to one
  repository, runner profile and exact source SHA.
- `https://worker.ci.qdev.run/internal/v1/releases/qaz-tours` — the separate,
  product-specific Qaz.Tours release admission. It accepts only an exact SHA,
  immutable artifact digest and completed candidate receipt from the enrolled
  product client. The mTLS host agent at `vps-hostinger-186` consumes the job,
  proves 60 GiB capacity plus a distinct verified rollback, and returns the
  runtime receipt. It is deliberately outside the shared GitHub runner queue.
- `https://worker.ci.qdev.run/internal/v1/releases/qdev-release-qaz-fund`,
  `/qdev-release-qaz-events` and `/qdev-release-qmt` — controller-owned immutable release admission
  for the existing `vps-apps-148` and `vps-main` placements. These lanes have
  the same mTLS, candidate-receipt, fresh-heartbeat and verified-rollback
  requirements as Qaz.Tours; a missing enrollment is a closed release lane,
  never a reason to fall back to SSH or a source build.
- `https://ci.qdev.run/artifacts/...` — checksum-verified, short-lived artifacts.
- `https://registry.ci.qdev.run/v2/` — private OCI registry.

The controller also exposes four Admin Platform mTLS lanes:
`qdev-release-ortcom`, `qdev-release-cmnt`, `qdev-release-total`, and
`qdev-release-qazposter`. Each is bound in `release-lanes.yml` to one
canonical repository, artifact prefix, mTLS placement, runtime endpoint set,
native host adapter and rollback reference. The Total lane contains only
`total.qdev.run`; `total.kz` is not a controller target.

### Qaz.Tours immutable host agent

`qdev-release-qaz-tours` is a controller-owned release lane for the existing
`vps-hostinger-186` host. The controller admits only an exact source SHA plus
`registry.ci.qdev.run/qaz-tours@sha256:…` after completed candidate CI and a
fresh mTLS heartbeat from that host. The root-owned, one-shot host agent is
defined by `deploy/qdev-release-qaz-tours.service`; it is not a timer and must
be invoked by the existing controller/host-agent path.

Before enrollment, QDev Fleet must place these private, root-owned files
through the host-agent only, never source control: the configuration
`/etc/qdev-release-agents/qaz-tours.env`; the referenced agent certificate,
key and controller CA; and `/var/lib/qdev-release-agents/qaz-tours-state.json`
with distinct, previously verified active and rollback release tuples.

The agent refuses absent state, capacity below 60 GiB, mutable images, absent
OCI source revision, unavailable lock and failed public health. It starts only
the supplied immutable image with `docker compose --no-build --pull never`.
On a failed candidate it restores and re-proves the verified rollback; it never
creates hosts, cleans Docker state or reads runtime secret values.

### QAZ.FUND and Qaz.Events immutable host agents

`qdev-release-qaz-fund` and `qdev-release-qaz-events` use the generic,
profile-compiled `scripts/qdev_product_release_host_agent.py`, invoked by the
matching service unit under `deploy/`.  The fixed profiles accept only
`registry.ci.qdev.run/qaz-fund@sha256:…` on `vps-apps-148` and
`registry.ci.qdev.run/qaz-events@sha256:…` on `vps-main` respectively. They
require root-owned private mTLS config and state from QDev Fleet, use only the
product's `docker-compose.controller-release.yml` immutable overlay, and prove
the source identity through each public release contract before completing the
controller job. They never invoke either product's legacy source-build deploy
script.

### QMT immutable host agent

`qdev-release-qmt` is the fixed `kaztilshi` lane for the existing
`srv138jump` placement. Its only accepted artifact is
`registry.ci.qdev.run/kaztilshi@sha256:…`; its client and host-agent mTLS
identities are allowlisted in `config/release-lanes.yml` and are valid only
after enrollment through the existing QDev CA. QDev Fleet installs the
root-owned `/etc/qdev-release-agents/qmt.env`, its referenced certificate,
key and CA, and the distinct verified active/rollback state through the
host-agent path. The root-owned `qmt-native-release-v1` adapter may pull only
`registry.ci.qdev.run/kaztilshi` by an exact OCI digest; mutable tags and
production builds remain forbidden. Before mutation it measures capacity for
both images, retains the verified rollback tuple and writes a recovery journal.
It completes a candidate only after the actual running container, local and
public health/readiness, and `/release.json` all prove QMT `4.4.2`, matching
source, OCI, migration, candidate-receipt and contract identities. A failed
pull, start, identity check or durable-state transition restores and verifies
the previous release by that release's own version and digests.

### Admin Platform native host agents

ORTCOM, CMNT, Total and QazPoster use the separate,
profile-compiled `scripts/qdev_admin_platform_release_host_agent.py` and the
matching one-shot unit under `deploy/`. The agent accepts no host path,
registry, public URL, command or rollback target from configuration or a
controller request. It invokes only the matching root-owned dispatcher under
`/usr/local/sbin/`, then requires the adapter's typed native receipt to bind
source SHA, artifact digest, artifact reference and `native`, `public`, and
`identity` readiness.

QDev Fleet enrolls a lane only after it has installed the product's reviewed
native release, rollback and receipt dispatchers, a distinct verified active
and rollback tuple at `/var/lib/qdev-release-agents/admin-platform/`, and the
private mTLS configuration at `/etc/qdev-release-agents/admin-platform.env`.
Controller activation ships policy and unit definitions only: it never
installs a product dispatcher, starts a host unit, uses SSH, or creates a host
path. An absent dispatcher, state proof or mTLS enrollment leaves the lane
closed.

## Guarded controller release

Stage each revision in its own directory below
`/opt/qdev-runner-control-plane/releases/`. Activate it with the revision's
own script:

```bash
sudo scripts/activate_controller_release.sh \
  /opt/qdev-runner-control-plane/releases/REVISION
```

Forward activation also requires
`QDEV_CONTROLLER_EXPECTED_CURRENT_REVISION` to equal the signed active runtime
revision. A host-local release lock serializes activation and rollback, and the
expected revision is checked again immediately before configuration mutation.
If another release has changed the runtime, the stale transaction stops without
changing the current release. The controller-owned rollback helper remains able
to restore a previously staged revision under the same lock.

Activation requires at least 30 GiB free disk, less than 85% disk use, at
least 4 GiB available RAM, and load-15 no greater than twice the CPU count. It
atomically changes `current`, refreshes the repository inventory and runner
profiles, and recreates only `broker-public` and `broker-internal`. The prior
profile file is restored together with the previous release if activation
fails. It does not restart a worker, stop the registry, remove Compose or Docker
objects, or touch product containers. If either Compose or the public health
check fails, the script restores the previous release and its configuration.
The activation also installs the versioned `release-lanes.yml` policy and
creates the controller-owned, mode-0700 release-job state before replacing the
broker, so an unavailable release lane cannot be mistaken for a CI slot.

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
published only after the same capacity gate is healthy. A pushed tag is an
unreleased candidate, not a worker identity:

```bash
QDEV_PUSH_IMAGES=true scripts/build_runner_images.sh
```

The signed image-release publisher must then create a
`qdev-runner-image-release-v1` manifest for the three executor images and the
Docker sidecar. Every artifact is identified by `@sha256` and carries SBOM,
provenance, signature and vulnerability-review digests. Critical findings are
rejected; High findings need an immutable remediation receipt. Initialize the
host-local Ed25519 identity once, then scan and publish an exact clean source
revision with `scripts/release_runner_images.py`. The private key must remain
mode 0600 on the controller host and is never copied into the evidence root.
The publisher refuses mutable references, dirty source, a revision mismatch,
Critical findings, and unreviewed High findings.

The worker provisioner does not download a BuildKit release archive.  The
Docker executor image is built from the pinned BuildKit source and carries
`/usr/local/share/qdev-buildkit/source-revision` and `source-sha256` markers.
Before provisioning, the release operator must either stage that exact
materialization as a root-owned artifact directory (with `bin/buildkitd`,
`bin/buildctl`, and the two read-only markers) and set
`QDEV_BUILDKIT_ARTIFACT_ROOT`, or provide the immutable
`QDEV_BUILDKIT_IMAGE_REF` digest so the stopped worker can copy and validate
the binaries from the published image.  The installer rejects symlinks,
unexpected ownership or permissions, marker mismatches, mutable image tags,
and any existing unverified materialization.

Validate both the envelope and its protected files before placing matching
references in `worker.env`:

```bash
python3 scripts/validate_runner_image_release.py \
  --manifest /etc/qdev-runner/runner-images.json \
  --expected-revision RUNNER_IMAGE_SOURCE_SHA \
  --verify-evidence
```

Do not reuse a mutable image or an image that is absent from this verified
manifest.

Before removing a worker pause after any image cleanup, run the local executor
audit as a trusted administrator with the worker's rootless Docker environment.
It fails if the configured tier/name identity is inconsistent or an enabled
profile's immutable runner/sidecar image is absent:

```bash
python3 scripts/audit_worker_runtime.py \
  --image-release-manifest /etc/qdev-runner/runner-images.json \
  --output worker-runtime-receipt.json
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

An unscoped shared worker may use a durable runtime baseline from 10 through
30 GiB and a disk-use ceiling no higher than 90%. The broker still adds the
claimed profile's disk reservation, so a 10 GiB baseline admits a 20 GiB Docker
profile only while at least 30 GiB is actually free.

When a scoped worker must run one exact candidate below that durable baseline,
the controller may issue a separate signed `claim-scope-v2` capacity directive.
The worker configuration must contain its matching `QDEV_CLAIM_SCOPE_ID`; the
directive alone selects a free-space floor from 4.5 through 30 GiB and a
disk-use ceiling no higher than 90%. `QDEV_WORKER_ALLOW_RUNTIME_CAPACITY_OVERRIDE`
is retired and is rejected at startup. Memory and load gates cannot be relaxed.
The active directive is reported in the worker heartbeat.

Worker provisioning archives the exact obsolete
`qdev-runner-worker.rollout-permit` and its existence-only drop-in. Do not
recreate that compatibility permit: the executable owner/audit validator is
the only accepted start boundary.

A green heartbeat is only broker/capacity evidence. Recovery closes only when
the same-SHA GitHub canary leaves `queued`, reports the expected runner name,
and succeeds.

## Signed capacity and stale-worker recovery

Recovery of the two named long-lived CI runners uses the separate typed
controller transaction in `docs/controller-capacity-recovery.md`. The operator
can select only `qdev-platform-ci-187` or `qdev-qazstack-01`; the controller and
certificate-bound host agents own the repository, permanent labels, native
action and service identity. A prepared operation fences admission until the
provider reports the runner online and idle and an owner-dispatched,
controller-correlated exact-SHA canary succeeds. Replaying an accepted
operation is idempotent. The controller GitHub App remains read-only for
Actions correlation; it never receives repository Contents or Actions-write
permission for recovery dispatch.

A recovery command is one-shot because it can contain a short-lived runner
registration credential. An interrupted host retries only a persisted pending
reconciliation. A locally persisted claim without an outcome remains fenced as
`manual_reconciliation_required`; it cannot reclaim the command or mint a
second credential from stale provider evidence.

The retired
`/internal/v1/operations/fleet-bootstrap/recover-existing-worker` route always
returns `410`. It is not a fallback to the typed recovery API. Controller
activation packages the fixed host agents and one-shot units, but an operator
must install their private certificate/release bindings on the already
assigned hosts; no workflow receives SSH, CA material or a general command.
Use `qdev-runner-operator recovery-prepare`, start the corresponding fixed
one-shot host service, then use `recovery-accept` with the exact default-branch
SHA, dispatch the persisted canary intent with owner-scoped repository
credentials, and finish with `recovery-accept` and `recovery-status`. The
operator reads live source bindings before every typed request and never
self-asserts the edge-owned proxy or verified-certificate headers.

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
