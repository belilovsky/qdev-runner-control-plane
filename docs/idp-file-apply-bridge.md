# IdP file-apply binding adapter — source-only

This implementation does not enroll IdP, issue a live authorization, install a
host agent, or dispatch a release. Existing release/claim APIs and their schemas
are unchanged. The separate private read-only CI observation endpoint is not
admission. The file-authorization endpoint below combines actual CI/archive and
authenticated native observations with an already admitted signed dispatch.
Neither endpoint creates a release claim or installs this source candidate.
It adds no AVDS or IdP profiles. Existing host-agent lock opening now rejects
link substitution and unsafe ancestry, retaining the native sticky `/run/lock`.

`qdev_runner.file_apply_authorization.FileApplyBridge` implements the native IdP
`authorize_apply(binding_bytes)` callback. Serialization is sorted compact JSON
with one LF. The input is `qdev-idp-controller-apply-binding-v1`, with repository,
source SHA, native transaction, previous SHA, bundle/manifest/snapshot digests and
the full CI observation (quality, runner_contract and outer artifact provenance).
All input/nested fields are strict; both successful CI tuples bind the source SHA.
CI observation is at most 300 seconds old, with at most 30 seconds clock skew.
Each native CI tuple retains the producer's `workflow`, exact GitHub run/job
`url`, `started_at` and `completed_at`. These fields are validated, not stripped:
quality and contract have their own exact workflow, the locator must match the
repository/run/job, and UTC start <= completion <= observation. The former
seven-field synthetic CI fixture did not model the IdP producer's actual output;
that incomplete shape is rejected. Additional unknown fields remain forbidden.

## New authorization, not an upgraded dispatch v2

The existing signed `qdev-controller-host-dispatch-claim-v2` remains unchanged.
It alone does not authorize a file-apply binding. A second controller-signed
document is required:

```json
{
  "schema": "qdev-controller-file-apply-authorization-v1",
  "binding_sha256": "<sha256 of exact native binding bytes including LF>",
  "dispatch_sha256": "<sha256 of canonical dispatch JSON including LF>"
}
```

`authorization_payload(binding_bytes, dispatch_claim)` builds this document only.
Its signature uses the existing controller canonical JSON HMAC primitive and
protected configured signing key; the envelope signature itself covers canonical
JSON without LF, exactly as the existing signing primitive specifies. The schema
provides domain separation. No signing key or signature implementation goes into
IdP. No JSON boolean, CLI flag or SSH invocation substitutes for this envelope.

## Mandatory native integration boundary

The fixed installed controller host adapter constructs `FileApplyBridge` with:

- its allowlisted `ReleaseLane`, signed dispatch and signed authorization;
- the full immutable native candidate receipt: its existing signed
  `candidate_evidence` digest is recomputed, not trusted or synthesized from
  a seven-field CI subset; quality.yml/static-contracts, both archive digests
  and exact provider tuple must also match the independently observed binding;
- its protected signing key, never passed by the IdP caller;
- `dispatch_transaction(claim) -> ContextManager[NativeDispatchGuard]`.

There is deliberately no default/no-op transaction. This factory is trusted
controller code, not an entrypoint accepted over the network. It must validate
the live lease/fence and current rollback state, reject replay and interrupted
operations, durably write `dispatch_accepted` and `release_started` before yield,
and retain the host operation/journal lock through apply and its outcome.
`validate_job` by itself does not meet this contract. The existing host-agent
module now provides `JournaledFileApplyTransaction(config, profile, signed_job)`
for this boundary. It snapshots the job, holds the native `flock`, validates the
signed job and current rollback/runtime, rejects consumed nonces and pending
operations, and writes into the existing fsynced hash-chain journal. Every guard
check rereads the current job through the authenticated controller status path
with the exact lease and fence. It reuses `_recover_pending` to finish
completion/state recording, including reconciliation after an uncertain
controller response. Existing dispatcher-based profiles retain their default
native receipt inspection. A locked in-process adapter instead supplies
`FileApplyObservations(before_apply=..., after_apply=...)`: the first reader
measures the prepared previous runtime, and the second measures the installed
candidate. The latter is called again for fresh reconciliation evidence, not
cached from the first post-apply observation. Every document still passes the
same exact compiled-profile runtime/provenance validation before it can affect
completion. A reader failure or drift cannot fall back to a subprocess or to
an earlier successful observation. Explicit recovery accepts a fixed
`observe_current` reader for the same reason.
It never invokes the native release or rollback dispatcher itself.

The code-only `IdPFileApplyAdapter` now binds that journal factory to a fixed
`id-qdev-run` / `belilovsky/id-qdev-run` / `idp-file-v1` identity. Its installed
owner supplies the full immutable candidate separately; the existing signed job
schema does not gain a caller-supplied candidate or executable field. Lane,
placement, artifact prefix and host identity must agree before construction.
This is source implementation, not a compiled IdP profile or installed integration.
Existing admin-platform profiles are not an IdP enrollment adapter.

The yielded native guard implements `assert_current()` to recheck live lease/fence
without consuming again. The public callback yields a `FileApplyGuard` that checks
both that guard and signed evidence expiry. IdP calls `guard.assert_current()`
immediately before `apply_started` and each managed-file write. It cannot be used
after context exit. Exceptions, including those incorrectly suppressed by a
native context manager, do not become successful apply results.

Lock ordering: IdP native global lock first, controller dispatch/journal lock
second. The controller transaction must not re-enter IdP dispatch or acquire its
native global lock again. In particular, an IdP adapter must supply these
in-process readers instead of using the default receipt dispatcher. The verified
IdP helper's `controller_adapter(reader)` provides its already-locked
`observe_prepared()` / `observe_installed()` capability; a fixed controller
adapter must validate and translate those **actual** native observations into
typed IdP evidence. These callbacks are code-only capabilities, not JSON fields,
CLI paths or authorization envelopes. Their Python type is not proof of
provider provenance. Native bundle/helper integrity and storage/current SHA
checks remain with the IdP wrapper. A local host lock does not freeze remote
revocation. The existing controller cannot replace an active job implicitly;
explicit revocation is observed on the next guard check. Each individual atomic
file replacement is bounded by that check, not presented as a distributed lock.

## Typed native observations

`qdev_runner.idp_file_runtime` validates both native prepared and installed
observations and retains their complete redacted content with its canonical
digest in `qdev-idp-file-runtime-provenance-v1`. A verified previous release is
associated using `qdev-idp-file-runtime-provenance-v2`. Host and controller use the same
validator. It checks the component manifest, exact CI tuples/download binding,
transaction hash chain, phase-specific evidence, unchanged container identities,
file and PostgreSQL capacity observations, disposable restore result, retained
rollback and installed component/public rechecks. A digest alone, a rehashed
contradictory observation, or an `accepted` flag cannot pass. Native dispatch,
verified bundle/helper provenance and the authenticated journal/transport remain
the trust boundary: arbitrary JSON is not authenticated by these shape checks.

Prepared files bind the **previous SHA and retained snapshot**, explicitly marked
`observed_files_only_not_retroactive_ci`; installed files bind the candidate SHA
and downloaded CI artifact. Neither observation establishes protected acceptance.
The first-baseline signed rollback anchor must match that exact native previous
snapshot before any dispatch is consumed. It cannot silently replace an already
known active artifact with a new snapshot digest.

For subsequent releases, native observation v2 includes `rollback_snapshot`: the
canonical retained index and previous installed component manifest, reread from
the actual retained blobs. It covers the union of old and new component paths,
including removed files and the private installed manifest; new-only paths must
have been absent. Private runtime configuration stays outside this observation.
The controller loads the previous installed observation only from an exact
`verified` completion in its protected native journal, verifies it, and rereads
that association under the dispatch lock before admission. An active-state
identity alone or a caller-selected observation is insufficient.

The v2 provenance retains that raw previous observation and its digest, not its
translated provenance or recursively embedded release history. Its manifest must
match every previous snapshot component, SHA and unchanged container identity.
The current snapshot retains its own digest; the prepared runtime and completion
rollback anchor retain the previous CI archive identity. Installed runtime binds
the new CI archive. Both host and controller recompute this association. Missing
history, changed snapshot content, a substituted manifest or a downgraded receipt
cannot redefine the existing rollback anchor. This is implemented source logic,
not live enrollment or proof of any historical production release.

## Provider-backed CI observation (not release admission)

`POST /internal/v1/releases/{lane}/idp-ci-observation` is exposed only on the
private broker surface. It requires the lane's existing exact mTLS operator
identity, a configured observation signer, and the fixed IdP repository/project/
`idp-file-v1` adapter. It does not enroll a missing lane. Public callers receive
404, including callers supplying a forged identity header. As for existing
private APIs, only the configured certificate-authenticating edge may supply
that header.

The request is the bounded (32 KiB), canonical native binding above. Authentication
precedes reading/parsing; validation errors do not echo input values. The handler
does **not** sign supplied CI-success flags. `qdev_runner.idp_file_evidence` uses
the existing GitHub App identity to read the current run, exact attempt and exact
job for **both** quality and runner-contract workflows. Repository, source SHA,
workflow, job name, attempt, successful terminal result, time, required steps and
job-specific profile labels must agree. Quality requires `qdev-ci-docker`;
runner-contract requires its own `qdev-ci` job, not a substitute profile.

The verifier reads exactly one `QDEV_IDP_CI_BUNDLE` record from the quality job's
provider-hosted log, compares every field with the request, and hashes the
existing controller CI-store archive. It neither uploads nor rebuilds an
artifact. Store roots come from broker configuration, not caller paths. Reads
walk no-follow directory handles; directories must be root/controller-owned
and non-writable by others. The archive must be a regular controller-owned 0600
file with one link and at most 250 MiB. Changes during hashing are rejected.
Both current attempts are reread after hashing; an intervening retry or a
verification lasting over 300 seconds invalidates the observation.

The GitHub log redirect is allowed only once, to HTTPS port 443 on a declared
GitHub Actions/Azure Blob storage hostname, without userinfo or fragments.
No authorization header or cookie is forwarded. The 16 MiB bounded log stays
in memory and is never returned. Credential-bearing HTTP transport diagnostics
are suppressed in that request's context, including INFO URLs and DEBUG headers;
unrelated threads' diagnostics and post-request logging remain unchanged.
Unknown hosts, extra redirects, ambiguous records and failures are redacted.

The returned wrapper is `qdev-controller-idp-ci-signed-observation-v1`, containing
a `qdev-controller-idp-ci-observation-v1` observation, a 120-second expiry and
HMAC-SHA256 over compact sorted JSON **with one LF**, using the existing protected
controller key. The distinct schema/serialization is not a release claim or
host-dispatch signature. No lease, journal entry or release state is allocated.
The result attests `provider_ci_archive_verified` only; inner bundle/components,
native runtime, rollback and controller admission remain `not_verified`, and
acceptance remains `not_run`. It does not attest a caller's snapshot or local
CI-observation file digest. This must be combined with separately verified
native evidence and real admission by the separately enrolled issuer.

Tests cover the actual private handler/verifier with synthetic provider/store
fixtures, archive mutation, current-attempt drift, mandatory steps/profiles,
redirection, privacy and public-surface isolation. They are not live CI proof.

## Fixed private issuer for an existing dispatch

`POST /internal/v1/release-hosts/{placement}/jobs/{release_id}/idp-file-authorization`
requires the configured lane's exact **host-agent** mTLS identity, live
`X-QDev-Release-Lease` and `X-QDev-Release-Fence`. An operator identity is not a
host identity. The internal certificate-authenticating edge remains the sole
trusted source of the identity header; the public surface returns empty 404.
Unknown lanes are not created, and no client-provided key, candidate, collector,
executable or source-of-truth path is accepted. The body is canonical native
`qdev-idp-prepared-observation-v2`, bounded to 2 MiB after authentication.

The issuer validates storage before constructing the generic release store:
root/agents/jobs/locks/operations are private 0700, journal/lock/snapshot are
private regular 0600 single-link files, and every path component is opened
no-follow and must be root/broker-owned. Other-writable ancestry is forbidden
except non-final root-owned sticky directories. The configured host-key map and
selected key use the same private-file reader with bounded, stable reads.
The non-secret path map may retain the native provisioner's trusted 0755 config
parent; actual keys must retain their separate 0700 parent. Both files remain
0600, no-follow and single-link; duplicate mapping keys are rejected.
A request cannot cause an unsafe directory
to be chmodded by the generic constructor.

Under the existing lane lock, the issuer reads the hash-chain-authoritative job,
verifies current dispatch/lease/fence, exact immutable candidate and signature,
native snapshot/transaction evidence and any previous accepted native history.
It then releases the lock for actual provider/archive observation, so revocation
does not wait on network I/O. After reacquiring the lock it rejects any job change
or expired CI/dispatch, and revalidates the full native/dispatch binding before
signing the file-authorization envelope above. A missing job snapshot may be
repaired from the journal; a missing journal or unverifiable previous archive
association cannot be substituted with a caller claim.

The existing journal durably appends
`qdev-controller-idp-file-authorization-observation-v1`, containing the redacted
native observation and digest, its configured mTLS origin, prior-history digest,
actual CI/archive observation and signed envelope. The job is pinned to that
native transaction. The returned
`qdev-controller-idp-file-authorization-receipt-v1` includes the envelope,
signature, original dispatch/signature/candidate and durable journal locator.
This signature authorizes only the exact binding and still requires the installed
guard's live lease/fence/replay checks; it is not a completed apply or acceptance.
`acceptance` remains `not_run`.

Neither issuance nor retry changes status, operation phase, nonce, lease or TTL.
A retry rereads actual evidence and appends a separate observation; the original
receipt remains immutable. A journal append followed by a lost HTTP response or
snapshot-write failure is reconciled from the durable journal. Concurrent
requests cannot sign against a changed journal: the loser must reread and retry
without renewal. No new runner, queue admission or workflow dispatch is involved.

## Fixed host collection and issuance

`ControllerIssuedIdPFileApplyAdapter` connects the protected native reader to
the issuer without accepting an executable, key path or provider flags from
the native bundle. Verified native dispatch must already hold its global IdP
lock. Under the existing host journal lock the adapter rejects pending work and
consumed nonces, verifies the current signed job, previous installed anchor and
fresh prepared-v2 observation, and checks live controller lease/fence status.
It sends the exact canonical native bytes, including the terminal LF, through
the configured host-agent mTLS path. The host journal lock is released during
provider IO; the native global lock remains held by dispatch.

The returned envelope is bounded, duplicate-key rejecting and exact-schema.
Its original dispatch must match the supplied job. The existing
`IdPFileApplyAdapter` independently verifies both signatures, the full candidate
and file binding, reacquires the host lock, rereads native state and checks live
authority before consuming the dispatch. Journal locators alone are not proof.
Every write remains fenced by the native/host guard; a changed lease, controller
status, previous runtime or pending operation rejects application.

No HTTP request retries automatically. An unconfirmed issuance has no local
apply side effect; an explicit retry obtains a fresh observation without
renewing the claim. Once local application starts, unknown outcomes require
native reconciliation before another issuance or application. The transport
preserves existing JSON callers unchanged; raw bytes are restricted to the fixed
IdP authorization endpoint with lease/fence headers. These are source-level
integration tests using the real local controller store and host journals, with
synthetic provider/native observations, not live authorization or deployment.

## Signed archive to native invocation

`IdPNativeInvocation` now provides the fixed in-process boundary. The installed
owner supplies its protected config, profile, lane and retained signed job plus
candidate; no request selects the executable, state root, target or key. It
checks the original dispatch signature and the full candidate digest, source
SHA, repository, quality workflow/job/run/job/attempt and `qdev-ci-docker`.
`idp_native_bundle` verifies the published outer archive, inner bundle, canonical
component manifest and every component before loading either helper. Helpers
are compiled together and loaded as isolated modules, never imported from the
staging directory. Archive limits, duplicate members/keys, links, unsafe paths,
extra components and mismatched content or permissions fail closed.

Only `apply`, `inspect`, `reconcile` and `observe` are exposed by this code-only
boundary. Apply rechecks current dispatch expiry after archive verification and
injects the fixed `ControllerIssuedIdPFileApplyAdapter`; native dispatch then
owns the global lock and obtains fresh controller/provider authorization before
the existing fenced write transaction. An expired signed dispatch may identify
the historical archive for inspection/reconciliation, but cannot authorize apply
or rollback. Native checks still require that exact retained stage/active binding.
This does not renew a lease, consume another claim or repeat an unknown action.
The versioned native response must match the exact source, previous revision,
transaction and both inner digests. Unknown native results require retained-state
inspection, without exposing helper exception contents or automatically retrying.

Portable tests use synthetic archives and native dispatch. A separate local
interoperability check against IdP `4e52d00115f7d0fad50cf1719da19dc41a367eeb`
loaded all 123 actual components and passed 12 incomplete-staging recovery
observations, including an untrusted staged helper and interruption before mkdir.
That local Git-produced fixture is NOT a published CI artifact or release proof.

The native `reconcile` invocation now supplies a fixed code-only recovery reader.
Under native-global then host-journal locks it matches the retained release,
lease, fence, nonce, expiry, rollback anchor and full candidate to the signed job.
It revalidates the archive/CI binding at the recorded cutover time, independently
reobserves installed files and reconciles the existing controller job. Historical
validation grants no new write authority. A not-yet-completed expired lease
remains unresolved; a controller-verified job may repair local bookkeeping after
expiry without another completion request or installation.

Both retained and fresh completion receipts pass full content/digest validation
before comparison. Only the collector's later observation time and its enclosing
digest may differ; journal, CI, rollback, components, scope and public checks stay
exact. The original receipt remains immutable. This permits recovery after lost
completion replies or failed state writes without accepting changed evidence.
The native active pointer is finalized only after host/controller recovery returns.
Tests exercise both baseline and subsequent releases with real local locks and
journals; their runtime/provider inputs remain synthetic, not production proof.

## Retained archive and restart entrypoint

The code-only `IdPNativeInvocation.retain` verifies the signed job, complete
candidate and actual published outer archive (including inner bundle and all
components) before retaining them beneath `/var/lib/qdev-idp/dispatches`.
`qdev-oidc` secrets, operator credentials and browser sessions are not inputs.
Retention status is `retained`, never admission, deployment or acceptance.
First publication requires a live signed dispatch; an exact immutable replay
can finish a failed directory sync after expiry, without renewing authority.

`idp_retained_dispatch` traverses root-owned no-follow descriptors, requires
private directories 0700 and files 0600 with one link, and uses a nonblocking
intake lock. Complete archive and metadata writes are fsynced before one atomic
directory rename publishes the set; the parent is then fsynced. Interrupted
temporary sets remain private and are never executable publications. Existing
final sets cannot be overwritten or silently repaired; conflicting job,
candidate or archive bytes are rejected. No automatic cleanup removes history.

`invoke_retained_idp` is the fixed restart entrypoint for installed code, not a
new CLI, enrollment or polling service. It re-authenticates all retained bindings
before loading verified helpers. Intake never holds its lock over native-global
or host-journal locks. An `inspect` before completed publication returns the
distinct `inputs_not_published` storage status without helper execution; it is
not a successful native inspection or acceptance. Reconcile uses the existing
native/controller journals, not another apply. Missing or corrupt inputs and
unknown outcomes fail closed with redacted errors, without automatic retries.
Tests cover complete replay, concurrent intake, every fsync boundary, before/
after each write and rename, mode/owner/link violations, restart tampering,
expiry, lock ordering and missing initial publication. All use synthetic
artifacts and authority; they do not prove production enrollment or execution.

## Still required before enrollment or production use

1. Release and enroll the implemented fixed issuer through the existing controller
   recovery/release transaction with exact-SHA CI and configured host identity.
   Its source-level tests use synthetic admission/provider/native state; no live
   authorization or operational enrollment has been performed here.
2. Install the fixed IdP invocation through the native verified-helper/global-lock
   boundary and complete exact-target enrollment, baseline/snapshot reconciliation
   and the explicit installed inspect/recovery entrypoint. The code-only invocation,
   factory, immutable retention and restart entrypoint above are implemented,
   but the polling owner must still acquire the full authenticated job/candidate
   and published archive and call those fixed entrypoints.
   Native reconciliation is now connected to its existing pending host journal
   in the code-only invocation; the installed polling owner must use it. They are
   not an installed executable integration.
   No source from the IdP caller may replace the controller transaction, profile
   or protected key. No AVDS/QAK evidence is invented and no runtime validation
   is waived.
3. Normal source-bound release and exact-target enrollment must install the adapter
   and select its protected key/material references. None are installed here.

Bridge unit tests use an explicitly fake in-memory native transaction. Separate
host-agent tests use the real on-disk journal and file locks, faults before and
after each durable phase, file/directory fsync failures and actual child-process
death without exception unwinding. They verify replay denial and native recovery
without a second apply. Native runtime inspection and controller HTTP responses
are controlled test sources; these tests do not establish live admission,
production deployment or acceptance. No workflow dispatch is added.
In-process observation tests additionally assert the real controller lock at
each read, forbid any receipt subprocess, reject failed/unmeasured/drifting
observations at all three boundaries and recover lost completion without a
second apply. Typed IdP tests retain full native-shaped observations, including
rehashed drift, wrong CI attempts, missing database capacity, failed restore,
wrong profile and a conflicting known active artifact. They exercise the fixed
adapter with the real host journal and lock, with synthetic controller/runtime
sources; they are not IdP production evidence.
Two-release tests also cover added/removed components, missing protected history,
association drift under the lock, rehashed contradictory indexes, receipt
downgrades and completion recovery without a second apply. Native collector
tests independently hash actual temporary snapshot files before and after apply.
