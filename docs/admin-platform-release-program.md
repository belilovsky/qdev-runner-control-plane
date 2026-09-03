# Admin Platform managed release program

`config/managed-registry.yml` is the controller-owned, versioned registry for
the AVDS `@av/admin-shell` artifact and the ORTCOM, CMNT, Total, and QazPoster
product releases.  It contains only canonical source identity, approved runner
profiles, native release profile, runtime endpoints, rollback reference and
owner. It must never contain credentials, tokens, cookies, or personal data.

`config/admin-platform-ledger.yml` is the ordered program ledger. The only
allowed statuses are `candidate`, `ci_queued`, `ci_passed`, `deploying`,
`live_accepted`, `rolled_back`, and `blocked`. A managed v2 claim is admitted
only when its repository/profile is registered and its exact source SHA is the
ledger's active candidate. All later entries remain blocked until the prior
entry has a terminal receipt.

## Controller procedure

1. Preserve the existing GitHub run. Never retry, cancel, duplicate, or create
   a provider job to recover queue capacity.
2. With the existing `qdev-fleet-operations` mTLS identity, record signed
   `qdev-runner-operator audit`, `release-audit`, and
   `admin-platform-audit` receipts. The receipts establish queue capacity,
   the currently activated controller identity, and the exact non-secret
   managed registry/ordered ledger tuple. The latter is read-only and never
   advances admission by itself.
3. Issue a `claim-scope` only for the current FIFO job after the managed
   registry and ledger validation succeed. The signed receipt binds repository,
   exact SHA, workflow run, job, attempt, runner profile and both registry
   markers.
4. Use the named product-native controller release profile for deployment. No
   direct SSH, manual runner operation, ad-hoc provider job or local fallback
   is an alternative release path.
5. Bind the terminal release receipt to artifact checksum, CI, runtime/image
   identity, route/browser evidence, rollback result and health window before
   moving the ledger to the next candidate.

## Current AVDS gate

The active entry is `avds-admin-shell`, source
`975a725fd96edff73f3f171f155362e97482177e`, with GitHub run `33665883402`.
Its immutable `@av/admin-shell@0.2.0` publication may proceed only after that
same run has a terminal success receipt and the controller-signed audit/claim
path is available. Until then all four product entries are blocked.

Total runtime binding is deliberately limited to `https://total.qdev.run`.
`total.kz` is outside this program's release profile and must not be used for
deployment, smoke tests, or runtime identity verification.
