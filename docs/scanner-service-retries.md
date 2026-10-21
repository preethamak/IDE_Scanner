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
