# IdP file-apply binding adapter — source-only

This implementation does not enroll IdP, issue a live authorization, install a
host agent, or dispatch a release. Existing release/claim APIs and their schemas
are unchanged. A separate private read-only CI observation endpoint is described
below; its signature is explicitly not a claim or an apply authorization.
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
native evidence and real admission by the future enrolled issuer.

Tests cover the actual private handler/verifier with synthetic provider/store
fixtures, archive mutation, current-attempt drift, mandatory steps/profiles,
redirection, privacy and public-surface isolation. They are not live CI proof.

## Still required before enrollment or production use

1. An approved controller issuer must bind freshly verified provider CI and native
   snapshot/transaction evidence into this envelope. The new read-only HTTP CI
   observation verifies provider/archive provenance, but does not issue this
   envelope, verify native snapshots, or allocate a release claim.
2. Install the fixed IdP adapter through the native verified-helper/global-lock
   boundary and complete exact-target enrollment, baseline/snapshot reconciliation
   and the explicit inspect/recovery entrypoint. The code-only factory and typed
   observations above are implemented, but not an installed executable integration.
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
