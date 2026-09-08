# Controller artifact recovery when worker admission is unavailable

The owner may manually dispatch `controller-recovery-build.yml` on `main`, with
`expected_sha` equal to the exact current commit. This uses the existing
GitHub-hosted controller CI capacity; it does not admit product jobs or alter
self-hosted worker admission.

The job builds the clean checkout, generates an SBOM, scans source and image,
retains the sealed recovery directory temporarily as a GitHub Actions artifact,
and delivers the archive through the existing OIDC-authenticated artifact store.
Scanner versions are pinned and their release checksums verified. The QDev store
is the normal recovery transport. The GitHub artifact exists only to break a
controller-store bootstrap failure after the build and scans have passed; it is
not an activation identity or a substitute for reconciliation. Failed builds or
scans never produce usable recovery material, and a failed delivery never yields
a successful recovery identity.

Reconcile the downloaded artifact using `controller_recovery_artifact.py reconcile`
with the exact successful run, job, attempt and source SHA. The reconciler checks
GitHub provider metadata for the owner, repository, workflow, main branch, source,
job name and hosted runner labels. Authentication uses the supplied GitHub token
or the existing GitHub App identity in memory. Never print credentials.

This hosted lane does not take a self-hosted claim receipt. The existing
`runner-smoke.yml` lane still requires its signed claim receipt and admission
nonce. Reconciliation creates a 15-minute identity; the normal offline-signed
activation envelope, artifact verification, capacity checks and rollback apply.
When the QDev delivery has failed because the running controller cannot yet
accept hosted artifacts, download only the retained artifact from that exact
workflow run and reconcile it with the same provider metadata checks. Do not use
an artifact from another run, branch, repository, source SHA, or job attempt.
Activate only through the existing controller release wrapper, then verify live
source and health before restoring worker admission and queued product checks.
