# IdP file-apply binding adapter — source-only

This module does not enroll IdP, issue a live authorization, install a host agent,
or dispatch a release. Existing release/claim APIs and their schemas are unchanged.
It adds no AVDS profiles or changes to existing host-agent execution.

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
- its protected signing key, never passed by the IdP caller;
- `dispatch_transaction(claim) -> ContextManager[NativeDispatchGuard]`.

There is deliberately no default/no-op transaction. This factory is trusted
controller code, not an entrypoint accepted over the network. It must validate
the live lease/fence and current rollback state, reject replay and interrupted
operations, durably write `dispatch_accepted` and `release_started` before yield,
and retain the host operation/journal lock through apply and its outcome.
`validate_job` by itself does not meet this contract. Existing admin-platform
profiles are not an IdP enrollment adapter and are not changed by this patch.

The yielded native guard implements `assert_current()` to recheck live lease/fence
without consuming again. The public callback yields a `FileApplyGuard` that checks
both that guard and signed evidence expiry. IdP calls `guard.assert_current()`
immediately before `apply_started` and each managed-file write. It cannot be used
after context exit. Exceptions, including those incorrectly suppressed by a
native context manager, do not become successful apply results.

Lock ordering: IdP native global lock first, controller dispatch/journal lock
second. The controller transaction must not re-enter IdP dispatch or acquire its
native global lock again. Native bundle/helper integrity and storage/current SHA
checks remain with the IdP wrapper. Controller locks serialize lease mutation;
there must be no uncontrolled lease revocation between the guard and write.

## Still required before enrollment or production use

1. An approved controller issuer must bind freshly verified provider CI and native
   snapshot/transaction evidence into this envelope. This source helper is not
   an HTTP issuer endpoint and does not establish provider provenance itself.
2. A fixed IdP host adapter must implement the durable transaction and guard above,
   using the existing host-agent journal lifecycle (not a second replay database),
   plus inspect/reconciliation for unknown outcomes. Native journal concurrency,
   crash/restart, lease renewal/revocation and fsync tests are required there.
3. Normal source-bound release and exact-target enrollment must install the adapter
   and select its protected key/material references. None are installed here.

Unit tests here use an explicitly fake in-memory native transaction to test the
adapter boundary; they do not prove real durable replay, current worker admission,
production deployment or live acceptance. No workflow dispatch is added.
