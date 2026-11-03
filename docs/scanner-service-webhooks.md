# Scanner service webhooks

The private scanner service can notify a trusted internal endpoint when a
Marketplace job reaches `complete` or `failed`. Webhooks are configured by the
operator, not submitted by API callers, so a scan request cannot turn the
service into an outbound request primitive.

Set all three values together:

```bash
export IDE_SCANNER_WEBHOOK_URL=https://events.example.com/guardrails
export IDE_SCANNER_WEBHOOK_SECRET=replace-with-a-random-shared-secret
export IDE_SCANNER_WEBHOOK_ALLOWED_HOSTS=events.example.com
```

The endpoint must use HTTPS on port 443, contain no credentials, and exactly
match the comma-separated host allow-list. Invalid partial configuration stops
the service at startup. Delivery retries only transient HTTP and transport
errors, at most three times. A delivery failure never changes the scanner's
completed or failed job result; it is recorded on the authenticated job record.
On service startup, failed terminal deliveries are retried from that record.
The service caps attempts at nine across restarts, then records
`dead_lettered` for explicit operator follow-up.

Each request includes:

- `X-GuardRails-Event`: `scan.completed` or `scan.failed`
- `X-GuardRails-Delivery`: a unique delivery ID for deduplication
- `X-GuardRails-Timestamp`: RFC 3339 timestamp
- `X-GuardRails-Signature`: `sha256=<hex HMAC>`

Verify the HMAC over the exact byte sequence
`X-GuardRails-Timestamp + "." + request_body` with the shared secret. Reject
stale timestamps and retain delivery IDs to prevent replay. The JSON body has
only the terminal job identity, status, artifact coordinates, report reference,
and bounded error field. It intentionally excludes the report, API token,
idempotency key, and request fingerprint.
