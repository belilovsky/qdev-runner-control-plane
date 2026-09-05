# Exact-source controller admission receipts

The controller signs `qdev-ci-controller-admission/v1` receipts with an
Ed25519 key held only on the controller host. A receipt binds the repository
numeric ID and full name, protected branch, functional source SHA, workflow
run and attempt, successful required jobs and their controller profiles, the
controller revision, and the admission and claim IDs. Receipts are valid for
at most 24 hours.

Create the key pair once in a root-controlled directory:

```console
qdev-controller-admission generate-keypair \
  --private-key /etc/qdev-runner/admission/private.pem \
  --public-key /etc/qdev-runner/admission/public.pem
```

The private key must be owner-only and never leaves the controller. Distribute
the public key to the root-owned product release verifier through the immutable
controller bundle.

Sign a controller-generated payload only after every required job has reached
the successful terminal state:

```console
qdev-controller-admission sign \
  --payload /run/qdev-controller/qazcoop-admission.payload.json \
  --private-key /etc/qdev-runner/admission/private.pem \
  --output /run/qdev-controller/qazcoop-admission.receipt.json
```

Read-only verification can omit the replay ledger. Every command that changes
release state must verify exact expected values and atomically consume the
receipt:

```console
qdev-controller-admission verify \
  --receipt /run/qdev-controller/qazcoop-admission.receipt.json \
  --public-key /etc/qazcoop/release-controller/public.pem \
  --repository-id 1357887516 \
  --repository belilovsky/qazcoop \
  --protected-ref refs/heads/codex/qazcoop-mvp \
  --functional-source-sha "$FUNCTIONAL_SOURCE_SHA" \
  --controller-revision "$CONTROLLER_REVISION" \
  --require-job reuse-first=qdev-ci \
  --require-job postgres-migrations=qdev-ci-docker \
  --consume-ledger /var/lib/qazcoop/release/consumed-admissions.sqlite3 \
  --consumer "$RELEASE_ID"
```

Verification fails on malformed or duplicate JSON fields, an unknown key,
tampering, a source or job mismatch, future or expired timestamps, and replay
of a receipt, admission ID, or claim ID. The consuming verifier directory and
ledger must be owned by the verifier account and must not be writable by group
or other users.
