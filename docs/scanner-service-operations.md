# Scanner service operations

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
