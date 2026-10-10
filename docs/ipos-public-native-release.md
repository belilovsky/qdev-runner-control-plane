# Public IPOS CMS native release

## Identity and scope

The public CMS is registry entry `ipos`, project `ipos`, lane
`qdev-release-ipos-public`, placement `ipos-public-runtime`, and adapter
`ipos-public-native-immutable-release-v1`. Its canonical source is
`belilovsky/ipos`, `main`. The fixed production target is the existing shared
application host `148.230.117.131`; the public origin is `https://ipos.qdev.run`.
The app artifact namespace is `registry.ci.qdev.run/belilovsky/ipos-app`;
the worker namespace is `registry.ci.qdev.run/belilovsky/ipos-worker`.
Both immutable digests must be bound by the project's native release bundle,
manifest and independently verified provenance to the same exact source.

The separate RP entry/lane/placement, data and endpoints are preserved. The
repository-level GitHub CI claim default remains RP, as before. Explicit
release lookup uses the entry ID and lane; adding a second runtime must never
silently redirect existing queued jobs. A shared repository has exactly one
CI claim default, distinct projects, host identities and native adapters, and
identical source ref, allowed runner profiles and admission ledger. A missing
or ambiguous default is rejected. Public native continuity evidence does not
claim that RP's GitHub CI admission passed.

## Native execution and admission

Build on the existing QDev executor, upload immutable app and worker images
through the existing registry, and verify actual QDev provenance using the
independently enrolled controller public key. Do not invent GitHub job IDs,
OIDC identities, provider success, host heartbeats or accepted rollback tuples.

Use the canonical IPOS helpers: `scripts/build-capacity-budget.py`,
`scripts/build-release-bundle.py`, `deploy/stage-immutable.sh`,
`deploy/verify-runtime-identity.sh`, and `deploy/rollback-immutable.sh`.
The exact staging command contract is
`deploy/stage-immutable.sh RELEASE_ID APP_DIGEST_REF WORKER_DIGEST_REF BIND_PORT`.
Inputs and paths are fixed to `/opt/ipos/source`, `/opt/ipos/releases`,
`/opt/ipos/shared/ipos.env`, `/opt/ipos/shared/migration.env` and the source's
`artifacts/release-manifest.json` and `artifacts/release-bundle.json`.
Keep the existing release lock and journal, predecessor images/data and old
route. Readiness includes the worker separately from the app/public identity.

The public lane is configuration, not host enrollment or installation. Its
mTLS target may be admitted only after an actual fixed adapter, credentials,
fresh heartbeat and rehearsed runtime/rollback receipts exist. First bootstrap
has no standalone predecessor today, so it must retain and prove the old-route
rollback separately before normal immutable rollback is applicable. A policy
row must never be substituted for that proof.

If controller automation is unavailable, the owner's already authorized
bounded manual equivalent uses these same native helpers, the fixed target,
exact SHA, operation identity, exclusive delivery lock, audit journal and
verified artifacts. Reconcile the real operation into the controller afterward;
do not fabricate an mTLS receipt to imitate automation.

## Resource and stateful prerequisites

The lane's ordinary floor is 40 GiB. The native operation budget additionally
measures missing image layers, backup, staging, migration, isolated restore,
candidate and retained rollback; it also checks inodes, available memory and
current swap I/O/pressure. The owner has authorized a release-specific reserve
exception. Bind it to the actual source, target, measured operation minimum and
recovery material; do not change unrelated lane floors or host capacity guard.
A percentage exception cannot manufacture bytes or runnable recovery capacity.
Use an existing separate restore target when that reduces production pressure.

Before migration/cutover, verify a fresh scoped backup, offsite byte identity,
and restoration in a working isolated app, including records/relations/assets.
Rehearse migration `0014`, idempotent ten-record draft import and quarantine.
Then complete protected Site Factory acceptance, single-writer bootstrap,
old-route return, app/data rollback separately, editor/public/retry/restart
acceptance and the real 48-hour canary. No production acceptance is implied by
source configuration, image signing or a health response.

## Operator home

The public CMS element's protected home is the existing Platform CMS home
tracked by Platform PR #985, with navigation to IPOS and Site Factory. It must
show purpose, actual version, deployment state/freshness, useful results and
permitted actions. The home remains unaccepted until personally inspected with
an authorized session after actual IPOS installation. A raw endpoint or this
repository document does not satisfy the visible-home requirement.
