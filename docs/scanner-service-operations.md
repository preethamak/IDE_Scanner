# Scanner service operations

## Health and readiness

`GET /health` is a liveness response: a `200` means the HTTP process is
running. `GET /readyz` is the admission signal for a load balancer or
orchestrator. It returns `200` only when the durable jobs/reports directories
are available, every configured worker thread is alive, and the bounded queue
has capacity. A `503` readiness response means an instance should not receive
another new scan; the Marketplace API still returns its documented `429` to a
caller that reaches an at-capacity instance.

The readiness payload includes configured/alive worker counts and aggregate
queue depth only. It intentionally contains no job identities, report data,
tokens, or webhook configuration.

The private scanner service persists asynchronous job records and canonical
reports locally. Configure these environment variables deliberately:

| Variable | Default | Range | Meaning |
| --- | --- | --- | --- |
| `IDE_SCANNER_JOB_RETENTION_SECONDS` | 604800 | 3600 to 7776000 | Lifetime for local job and report files. |
| `IDE_SCANNER_MAINTENANCE_INTERVAL_SECONDS` | 3600 | 60 to 86400 | Cadence for expiry cleanup and failed-webhook recovery. |
| `IDE_SCANNER_JOB_TIMEOUT` | 600 | 30 to 3600 | Maximum execution time for a queued Marketplace scan. |

The service runs maintenance once before accepting requests and then on the
configured daemon interval. Expiry removes local job and report files together;
the service intentionally returns `404` after retention rather than retaining
stale evidence indefinitely. Only failed webhook receipts are retried, with the
existing total-attempt cap. Health reports the active retention and maintenance
settings under `operations`.

For longer retention, copy immutable report bundles to an encrypted external
artifact store before expiry. Do not use a service-local job ID as a permanent
evidence archive.

## API token rotation

The scanner service authenticates private API routes with bearer tokens. Set
`IDE_SCANNER_API_TOKEN` for the backwards-compatible single-token setup. For a
rotation, set `IDE_SCANNER_API_TOKENS` to a comma-separated set of active
tokens; the service accepts the union of the two variables. It never returns
the configured values in health, readiness, job, or error responses.

1. Mint a new high-entropy secret in the deployment secret manager.
2. Deploy the service with the old and new values in `IDE_SCANNER_API_TOKENS`.
3. Move each trusted caller to the new token and verify authenticated requests.
4. Remove the old value, then deploy once more.

Do not send more than a short overlap set and do not place tokens in source,
workflow logs, job idempotency keys, or webhook configuration. A non-loopback
bind still refuses to start unless either variable yields at least one token.
