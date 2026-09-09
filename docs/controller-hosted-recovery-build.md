# Controller artifact recovery when worker admission is unavailable

The owner may manually dispatch `controller-recovery-build.yml` on `main`, with
`expected_sha` equal to the exact current commit. This uses the existing
GitHub-hosted controller CI capacity; it does not admit product jobs or alter
self-hosted worker admission.

The job builds the clean checkout, generates an SBOM, scans source and image,
retains the sealed recovery directory temporarily as a GitHub Actions artifact.
Scanner versions are pinned and their release checksums verified. Hosted jobs
never upload directly to controller artifact storage and their GitHub OIDC token
is not accepted by that storage. The retained artifact exists only to break a
controller-store bootstrap failure after the build and scans have passed; it is
not an activation identity or a substitute for reconciliation. Failed builds or
scans never produce usable recovery material.

Reconcile the downloaded artifact using `controller_recovery_artifact.py reconcile`
with the exact successful run, job, attempt and source SHA. The reconciler checks
GitHub provider metadata for the owner, repository, workflow, main branch, source,
job name and hosted runner labels. Authentication uses the supplied GitHub token
or the existing GitHub App identity in memory. Never print credentials.

This hosted lane does not take a self-hosted claim receipt because it is only a
bootstrap build. It cannot restore worker admission or stand in for the separate
signed `runner-smoke.yml` claim tuple. After signed controller activation and
health verification, obtain that exact self-hosted tuple before restoring normal
worker admission. Reconciliation creates a 15-minute identity; the normal
offline-signed activation envelope, artifact verification, capacity checks and
rollback apply. Download only the retained artifact from that exact successful
workflow run and reconcile it with the same provider metadata checks. Do not use
an artifact from another run, branch, repository, source SHA, or job attempt.
Activate only through the existing controller release wrapper, then verify live
source and health before restoring worker admission and queued product checks.

## Issue and stage signed controller activation assets

The fleet adapter accepts only the fixed root-owned activation spool.  Do not
copy a reconciled manifest, a signed envelope, or its sibling artifacts into
that spool by hand.  Use `qdev-controller-activation-assets`: it captures the
current controller status and all six effective configuration inputs while it
holds the same lifecycle lock used by activation, creates a transaction-scoped
unsigned envelope, and publishes verified assets atomically without replacing
existing paths.

For a normally active release, invoke `/usr/local/sbin/qdev-controller-activation-assets`.
When bootstrapping the first release that contains this tool, invoke its exact,
reconciled release copy instead; the release directory must be the root-owned
archive named for the exact source SHA.  The tool has no argument for the
current SHA: it reads the durable activation state when available, otherwise
the measured runtime status, at the moment `issue-unsigned` holds the lock.

```sh
release=/opt/qdev-runner-control-plane/releases/<exact-40-character-sha>
assets=/var/lib/qdev-runner/controller-activation
artifact=/root/<root-only-reconciled-artifact>/controller-artifact-manifest.json
transaction_id=<new-8-to-128-character-transaction-id>
tool="$release/scripts/controller_activation_assets.py" # bootstrap only

sudo "$tool" issue-unsigned \
  --release "$release" \
  --artifact-manifest "$artifact" \
  --transaction-id "$transaction_id" \
  --ttl-seconds 600
```

That command prints the unsigned envelope path, the frozen status path and
the frozen configuration root.  Sign exactly those frozen inputs, using the
existing root-only activation signing key and controller receipt key.  Neither
key is printed or copied by these commands.

```sh
sudo env PYTHONDONTWRITEBYTECODE=1 PYTHONPATH="$release/src" /usr/bin/python3 \
  "$release/scripts/controller_recovery_artifact.py" sign-envelope \
  --unsigned "$assets/unsigned/$transaction_id.json" \
  --artifact-manifest "$artifact" \
  --release-root "$release" \
  --current-status "$assets/snapshots/$transaction_id/status.json" \
  --current-config-root "$assets/snapshots/$transaction_id/current-config" \
  --private-key <root-only-activation-private-key-path> \
  --controller-receipt-key <root-only-controller-receipt-key-path> \
  --output "$assets/signed/$transaction_id.json"

sudo "$tool" stage \
  --release "$release" \
  --artifact-manifest "$artifact" \
  --signed-envelope "$assets/signed/$transaction_id.json"
```

`stage` checks the restored admission-key trust binding, the signed envelope,
the exact release digest, the reconciled entrypoint digest, and every manifest
member before it writes anything.  It publishes the manifest and sibling
assets before the envelope, so the envelope is the final commit point.  Its
receipt supplies `activation_envelope_digest`, `artifact_manifest_digest`,
`controller_release_digest`, image digests, policy digest, and the reconciled
workflow run, job, and attempt for the existing fleet bootstrap request.  Existing paths are accepted only when byte-identical;
otherwise staging fails closed.  If the identity expires or current status
changes before dispatch, reconcile a fresh successful hosted artifact and
repeat with a new transaction ID; do not edit timestamps or reuse a snapshot.

## Repair the installed activation adapter before a signed activation

If the root dispatcher and the installed activation adapter disagree about a
new signed request shape, do not bypass the dispatcher or launch queued jobs by
hand.  A reconciled controller recovery release contains the narrowly-scoped
`repair-adapter` bridge.  It replaces only
`/usr/local/sbin/qdev-controller-activate`; it does not change the active
controller release, services, queue, or policy.

Use it only from a clean, root-owned exact release archive whose hosted recovery
artifact has passed reconciliation.  Record the measured installed adapter
hash and the candidate adapter hash first.  The operation rejects a changed
installed adapter, verifies the artifact's source, policy and entrypoint
bindings, stores a digest-addressed rollback copy, atomically replaces the
fixed adapter, and writes a root-only receipt.

```sh
release=/opt/qdev-runner-control-plane/releases/<exact-40-character-sha>
artifact=/root/<root-only-reconciled-artifact>/controller-artifact-manifest.json
tool="$release/scripts/controller_activation_assets.py"
old=$(/usr/bin/sha256sum /usr/local/sbin/qdev-controller-activate | awk '{print $1}')
new=$(/usr/bin/sha256sum "$release/scripts/qdev_controller_activation_adapter.py" | awk '{print $1}')

sudo "$tool" repair-adapter \
  --release "$release" \
  --artifact-manifest "$artifact" \
  --transaction-id <new-8-to-128-character-transaction-id> \
  --expected-installed-sha256 "$old" \
  --expected-candidate-sha256 "$new"
```

Reconcile the receipt under
`/var/lib/qdev-runner/controller-activation/adapter-repairs/receipts/` before
issuing a fresh signed activation envelope.  If the command reports that the
installed adapter has already changed, stop and reconcile its existing receipt;
do not overwrite it or retry against a different digest.  The backup is under
`adapter-repairs/backups/` and is retained for the normal documented rollback
procedure.
