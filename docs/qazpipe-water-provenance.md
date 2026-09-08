# QazPipe water provenance receipts

`qdev-qazpipe-water-provenance/v1` is the dedicated controller receipt for a
completed QazPipe water collection that QazLake is about to accept. It is an
Ed25519 envelope, separate from controller admission and image-provenance
receipt families. HMAC and every other schema value fail verification.

The formal fixed shape is in
[`qdev-qazpipe-water-provenance-v1.schema.json`](schemas/qdev-qazpipe-water-provenance-v1.schema.json).
Every object rejects unknown and missing fields. The runtime verifier also
enforces the relationships JSON Schema cannot express: `collector.id` is
`geo-003`; `result.state` is `complete`; completed and expected query counts
are equal; timestamps are causal; and expiry is at most 24 hours after issue.
The workflow profile is a bounded identifier and is compared exactly with the
verifier input, so QazLake can require `qazpipe.geo-003.v1` without making this
receipt family specific to one producer workflow.

## Envelope and canonical bytes

The JSON envelope has exactly three top-level fields:

```json
{
  "schema": "qdev-qazpipe-water-provenance/v1",
  "payload": {
    "repository": {"id": 1202131289, "full_name": "belilovsky/qazpipe"},
    "protected_ref": "refs/heads/main",
    "source_sha": "<40 lowercase hex>",
    "collector": {"id": "geo-003"},
    "workflow": {
      "name": "CI",
      "run_id": 33949265063,
      "run_attempt": 2,
      "job_id": 725144011,
      "profile": "qazpipe.geo-003.v1"
    },
    "artifact": {
      "uri": "qazpipe://artifacts/water/2026-09-08/manifest.json",
      "sha256": "sha256:<64 lowercase hex>",
      "size_bytes": 4096
    },
    "result": {
      "water_run_id": "water-20260908-001",
      "state": "complete",
      "query_plan_sha256": "sha256:<64 lowercase hex>",
      "expected_query_count": 18,
      "completed_query_count": 18,
      "manifest_sha256": "sha256:<64 lowercase hex>",
      "records_sha256": "sha256:<64 lowercase hex>",
      "record_count": 413,
      "source_observed_at": "2026-09-08T11:20:00Z",
      "started_at": "2026-09-08T11:25:00Z",
      "completed_at": "2026-09-08T11:30:00Z"
    },
    "controller_revision": "<40 lowercase hex>",
    "receipt": {"id": "water-receipt-20260908", "claim_id": "water-claim-20260908"},
    "issued_at": "2026-09-08T11:35:00Z",
    "expires_at": "2026-09-08T12:35:00Z"
  },
  "signature": {
    "algorithm": "Ed25519",
    "key_id": "sha256:<64 lowercase hex>",
    "payload_sha256": "sha256:<64 lowercase hex>",
    "value": "<86-character unpadded base64url Ed25519 signature>"
  }
}
```

`signature.value` signs the UTF-8 canonical payload bytes: `json.dumps` with
sorted keys, compact `,` and `:` separators, `ensure_ascii=False`, and
`allow_nan=False`. `signature.payload_sha256` is SHA-256 of those same bytes,
prefixed with `sha256:`. The receipt digest QazLake retains is SHA-256 of the
whole envelope encoded the same way. The command writes compact canonical JSON
with sorted object keys; field order in the illustrative object above is only
for readability.

`signature.key_id` is SHA-256 of the raw 32-byte Ed25519 public key, also
prefixed with `sha256:`. A verifier requires both a pinned PEM and its pinned
key ID; it rejects a PEM whose derived ID differs from the pin.

## Controller issuance

Create an isolated controller key pair once. The private key is owner-only;
distribute only the public PEM to the QazLake verifier.

```console
qdev-qazpipe-water-provenance generate-keypair \
  --private-key /etc/qdev-runner/qazpipe-water/private.pem \
  --public-key /etc/qdev-runner/qazpipe-water/public.pem

qdev-qazpipe-water-provenance sign \
  --payload /run/qdev-controller/qazpipe-water.payload.json \
  --private-key /etc/qdev-runner/qazpipe-water/private.pem \
  --output /run/qdev-controller/qazpipe-water.receipt.json
```

Successful `generate-keypair` stdout is:

```json
{"key_id":"sha256:<64 lowercase hex>","state":"created"}
```

Successful `sign` stdout is:

```json
{"key_id":"sha256:<64 lowercase hex>","receipt":"<path>","receipt_sha256":"sha256:<64 lowercase hex>","state":"signed"}
```

## QazLake verification and one-time consumption

The standalone verifier is suitable for a product deployment with its source
tree available. It always performs the exact comparisons shown below, including
the source artifact hash, records hash, and the declared QazPipe receipt hash.
Read-only verification does not alter a ledger:

```console
python3 scripts/verify_qazpipe_water_provenance.py \
  --receipt /srv/qazlake/incoming/qazpipe-water.receipt.json \
  --trusted-key-pem /etc/qazlake/qazpipe-water/public.pem \
  --trusted-key-id "$QAZPIPE_WATER_KEY_ID" \
  --repository-id 1202131289 \
  --repository-full-name belilovsky/qazpipe \
  --protected-ref refs/heads/main \
  --source-sha "$QAZPIPE_SOURCE_SHA" \
  --collector-id geo-003 \
  --workflow-name CI \
  --workflow-run-id "$GITHUB_RUN_ID" \
  --workflow-run-attempt "$GITHUB_RUN_ATTEMPT" \
  --workflow-job-id "$GITHUB_JOB_ID" \
  --workflow-profile qazpipe.geo-003.v1 \
  --artifact-uri "$QAZPIPE_ARTIFACT_URI" \
  --artifact-sha256 "$QAZPIPE_ARTIFACT_SHA256" \
  --artifact-size-bytes "$QAZPIPE_ARTIFACT_SIZE_BYTES" \
  --water-run-id "$QAZPIPE_WATER_RUN_ID" \
  --water-state complete \
  --query-plan-sha256 "$QAZPIPE_QUERY_PLAN_SHA256" \
  --expected-query-count "$QAZPIPE_EXPECTED_QUERY_COUNT" \
  --completed-query-count "$QAZPIPE_COMPLETED_QUERY_COUNT" \
  --manifest-sha256 "$QAZPIPE_MANIFEST_SHA256" \
  --records-sha256 "$QAZPIPE_RECORDS_SHA256" \
  --record-count "$QAZPIPE_RECORD_COUNT" \
  --source-observed-at "$QAZPIPE_SOURCE_OBSERVED_AT" \
  --started-at "$QAZPIPE_STARTED_AT" \
  --completed-at "$QAZPIPE_COMPLETED_AT" \
  --controller-revision "$QDEV_CONTROLLER_REVISION" \
  --receipt-id "$QAZPIPE_RECEIPT_ID" \
  --claim-id "$QAZPIPE_CLAIM_ID" \
  --issued-at "$QAZPIPE_ISSUED_AT" \
  --expires-at "$QAZPIPE_EXPIRES_AT" \
  --expected-receipt-sha256 "$QAZPIPE_RECEIPT_SHA256"
```

On success, read-only verification writes exactly this compact JSON line to
stdout:

```json
{"artifact_sha256":"sha256:<64 lowercase hex>","claim_id":"<claim id>","receipt_id":"<receipt id>","receipt_sha256":"sha256:<64 lowercase hex>","records_sha256":"sha256:<64 lowercase hex>","state":"verified","water_run_id":"<water run id>"}
```

For the state-changing publication step, append both options:

```console
  --consume-ledger /var/lib/qazlake/water/consumed-provenance.sqlite3 \
  --consumer "$QAZLAKE_PUBLICATION_ID"
```

The consuming form returns the same stdout fields with `"state":"consumed"`.
`--consume-ledger` and `--consumer` must appear together. The ledger is an
owner-controlled SQLite file and atomically records the canonical envelope
digest, receipt ID, claim ID, key ID, source SHA, artifact SHA-256, records
SHA-256, water run ID, and consumer. A duplicate envelope digest, receipt ID,
or claim ID is rejected, including a reissued receipt after signing-key
rotation. This is the only verifier form that changes state.
