# Markdown-first closure record

Updated: 2026-09-04 (Asia/Almaty)

This file is an append-only operational summary for the current closure pass. It is not a substitute for provider, controller, or deployment receipts.

## Pass 1 — controller and CI capacity

- Implementation source: `da2d0ab198759e2dcf8bfa6c9606f8eab6d9f192` (`feat(controller): execute existing worker recovery`), PR [#51](https://github.com/belilovsky/qdev-runner-control-plane/pull/51).
- Controller release activated on the existing host `srv1879763` (`186.240.148.129`) from the exact release tree. The active release status reported revision `da2d0ab198759e2dcf8bfa6c9606f8eab3d9f192` and release digest `dfdd995a0735fe373be311a4521336cf0c82229bfe5ed02d72ad8326c290b3b4` (the host writes the full revision in its private receipt). The activation created no worker and did not change queues, jobs, or leases.
- Fleet policy was installed from `config/fleet-bootstrap.yml`; policy SHA-256: `f6710c2d4b152515bb7db901202450ba835231e14cfd6651ba02448adca10725`.
- Exact allowed target mappings are preserved for `qdev-platform-ci-187` and `qdev-qazstack-01`, including their existing GitHub service-unit names and labels. The controller route is mTLS/operator protected and the workflow cannot access the CA or private keys.
- Administrative recovery calls for both targets were executed with `active_jobs=0` and distinct idempotency keys. Both returned `status=access_blocked`, `operation_status=pending`, `error_code=recovery_adapter_unavailable`; replaying the first key returned the identical fingerprint and result. This is a fail-closed result: the controller has no installed `/usr/local/sbin/qdev-fleet-worker-recovery` adapter and no registered target host/service records. No direct SSH/systemd fallback was used.
- The existing target observations remain external to the controller registry: `qdev-platform-ci-187` is an intentionally retired/inactive service on `187.55.228.239` and `qdev-qazstack-01` is not registered on the inspected `148.230.117.131` host. These facts are recorded as access/registration evidence, not as permission to start or recreate runners.
- Provider-side verification workflow `33877212566` and PR checks were rejected before job steps with the account billing/spending restriction. The provider rejection is retained as an external blocker; no green CI result is asserted.

Local controller proof on the exact release tree:

```text
ruff check src tests scripts        PASS
mypy src                            PASS
pytest -q                           252 passed, 2 warnings
```

## Pass 2 — QazStack intake

- Source is the immutable `v1.53.0` tag (`e9d8c7a32d83e3ba822b541185ebfeb3d9704367`), peeled source `64e1ba4d65c3e2b5368636fafb0cdb4645c749b6`. Historical `v1.52.0` remains untouched.
- The pinned document runtime used MarkItDown `0.1.7` and the locked optional Docling entry `2.70.0`; `markitdown[ocr]` is absent. Originals were hashed before and after conversion and remained unchanged.
- Runtime fixtures: DOCX, text PDF, and XLSX converted successfully; text PDF took the text path and did not invoke OCR. Binary unsupported input returned `unsupported`. Scan PDF and image used the QazStack/Tesseract backend and returned honest `failed` with `OCRDependencyError` because this environment has no native Tesseract executable. No invented Markdown was returned. Opt-in complex-table fallback returned `needs_review` when Docling was not installed; no automatic fallback or cloud/LLM conversion occurred.
- The current immutable release also treats arbitrary plain bytes with a `.docx` suffix as text. A malformed ZIP-like fixture must be tracked as a follow-up compatibility defect; it was not promoted to a successful production conversion.

## Remaining acceptance state

- QazLake public receipt/catalog endpoints still return HTTP 404; no verified snapshot exists and no synthetic records were published.
- QazReport PR [#28](https://github.com/belilovsky/kz-report/pull/28) contains explicit-dispatch/push-auth and same-origin catalog-state fixes. Local native tests (32), build, and local browser acceptance (63/63) pass, but provider checks are queued/blocked while self-hosted capacity is unavailable.
- QazLake PR [#66](https://github.com/belilovsky/qazlake/pull/66) contains the producer endpoints and receipt-bound catalog path. Targeted tests (5) and repository verification pass locally; its GitHub checks were rejected by the same billing restriction.
- Platform live `/api/release` was previously verified at current master `3fdaab578754e1bacc6254dd47eb0c65d0f83a79`; the old `563c873…` candidate is not a release target. A new exact-SHA release still requires provider CI/production workflow admission and public post-cutover evidence.

## Closure rule

The work is not `complete` until the two existing runners are online/idle with completed controller receipts, QazStack scan runtime proof is available, a real QazLake snapshot produces a public-verified QazReport catalog, and a fresh Platform candidate has a green release workflow, matching live SHA, route/artifact checks, and a retained rollback target.
