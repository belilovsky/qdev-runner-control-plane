# IdP file-apply binding adapter — source-only

This module does not enroll IdP, issue a live authorization, install a host agent,
or dispatch a release. Existing release/claim APIs and their schemas are unchanged.
It adds no AVDS or IdP profiles. Existing host-agent lock opening now rejects
link substitution and unsafe ancestry, retaining the native sticky `/run/lock`.

`qdev_runner.file_apply_authorization.FileApplyBridge` implements the native IdP
`authorize_apply(binding_bytes)` callback. Serialization is sorted compact JSON
with one LF. The input is `qdev-idp-controller-apply-binding-v1`, with repository,
source SHA, native transaction, previous SHA, bundle/manifest/snapshot digests and
the full CI observation (quality, runner_contract and outer artifact provenance).
All input/nested fields are strict; both successful CI tuples bind the source SHA.
CI observation is at most 300 seconds old, with at most 30 seconds clock skew.

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
with the exact lease and fence. After apply it independently invokes the native
receipt dispatcher and reuses `_recover_pending` to finish completion/state
recording, including reconciliation after an uncertain controller response.
It never invokes the native release or rollback dispatcher itself.

This is still a generic source adapter, not a compiled IdP profile or installed
integration. Existing admin-platform profiles are not an IdP enrollment adapter.

The yielded native guard implements `assert_current()` to recheck live lease/fence
without consuming again. The public callback yields a `FileApplyGuard` that checks
both that guard and signed evidence expiry. IdP calls `guard.assert_current()`
immediately before `apply_started` and each managed-file write. It cannot be used
after context exit. Exceptions, including those incorrectly suppressed by a
native context manager, do not become successful apply results.

Lock ordering: IdP native global lock first, controller dispatch/journal lock
second. The controller transaction must not re-enter IdP dispatch or acquire its
native global lock again. Native bundle/helper integrity and storage/current SHA
checks remain with the IdP wrapper. A local host lock does not freeze remote
revocation. The existing controller cannot replace an active job implicitly;
explicit revocation is observed on the next guard check. Each individual atomic
file replacement is bounded by that check, not presented as a distributed lock.

## Still required before enrollment or production use

1. An approved controller issuer must bind freshly verified provider CI and native
   snapshot/transaction evidence into this envelope. This source helper is not
   an HTTP issuer endpoint and does not establish provider provenance itself.
2. A fixed IdP host adapter must connect the journal-backed factory above to the
   IdP global lock and its verified in-process helper, typed native runtime/rollback
   receipts and explicit inspect/reconciliation. No source from the IdP caller
   may supply or replace the controller transaction, profile or protected key.
3. Normal source-bound release and exact-target enrollment must install the adapter
   and select its protected key/material references. None are installed here.

Bridge unit tests use an explicitly fake in-memory native transaction. Separate
host-agent tests use the real on-disk journal and file locks, faults before and
after each durable phase, file/directory fsync failures and actual child-process
death without exception unwinding. They verify replay denial and native recovery
without a second apply. Native runtime inspection and controller HTTP responses
are controlled test sources; these tests do not establish live admission,
production deployment or acceptance. No workflow dispatch is added.
