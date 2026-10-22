# Scanner service retries

Marketplace scans are asynchronous. Retrying a timed-out client request without
an idempotency key can otherwise create duplicate downloads and analyses of the
same release.

Send a new `Idempotency-Key` with each logical scan request. It may contain
letters, digits, `.`, `_`, `:`, and `-`, and is limited to 128 characters.
Reuse that key only when retrying the same extension ID, version, and target
platform.

```bash
curl --fail-with-body \
  -H "Authorization: Bearer $IDE_SCANNER_API_TOKEN" \
  -H "Content-Type: application/json" \
  -H "Idempotency-Key: release-review-2026-10-22" \
  -d '{"extension_id":"publisher.extension","version":"1.2.3"}' \
  https://scanner.example/v1/scans/marketplace
```

The first accepted request returns `202`. A matching retry returns the same job
and includes `Idempotent-Replayed: true`. Reusing the key for different request
data returns `409`; create a new key rather than treating that response as a
scan result.

When the bounded service queue is full, it returns `429` and `Retry-After: 30`.
Wait, then retry with a new key: a rejected request is terminal evidence that
the service did not accept that job. Poll `/v1/jobs/{job_id}` until the job is
complete or failed, and fetch the report only from the authenticated report
endpoint.

## Retained evidence history

`GET /v1/jobs` returns at most 100 newest retained Marketplace job summaries
for an authenticated service client. Use it to discover a previous job ID or
confirm retention status, then fetch a completed report with its `report_ref`.
The history response contains only job metadata; it deliberately omits report
bodies, idempotency keys, request fingerprints, and webhook secrets.

Retention is operator-configured and expired jobs return `404`. A history entry
is not a permanent archive or an approval result; copy a reviewed canonical
report bundle to the team's immutable evidence store before its retention
window ends.

## Exact report identity

Completed jobs include `report_sha256`, the SHA-256 of the exact persisted
report bytes. `GET /v1/reports/{job_id}` sends the same identity as a quoted
`ETag` (`"sha256-<hex>"`). Record that value beside a release-review decision
or CI attestation; it proves which report bytes were reviewed, not that an
extension is safe.

Clients can send the recorded value in `If-None-Match`. The service responds
with `304` when the retained report is unchanged, avoiding a needless transfer
while preserving the authenticated read boundary. The value is an integrity
identifier, not a report signature or a substitute for preserving the report
in immutable team storage.
