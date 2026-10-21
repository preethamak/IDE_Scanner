# GuardRails scanner service API

The scanner service is a private execution boundary for GuardRails Deep Scan
and MCP assessment jobs. It accepts one exact Marketplace extension identity,
performs a bounded scan, and stores the resulting immutable report locally.
It is not a public Marketplace proxy and a `complete` job is evidence about
the requested artifact, not a guarantee that the extension is safe.

## Run it safely

The service binds to loopback by default. It refuses a non-loopback bind unless
`IDE_SCANNER_API_TOKEN` is set, or an operator explicitly sets
`IDE_SCANNER_ALLOW_INSECURE_BIND=1` for a trusted local network.

```bash
export IDE_SCANNER_API_TOKEN="replace-with-a-long-random-secret"
PYTHONPATH=src python -m ide_scanner.service --host 127.0.0.1 --port 8787
```

For a remote deployment, terminate TLS and restrict network access in front of
the service. `IDE_SCANNER_ALLOWED_ORIGIN` controls the CORS response header;
it is not an authorization mechanism. Keep the service private and send the
token using `Authorization: Bearer <token>`.

The public metadata endpoints are intentionally readable without a token:

```bash
curl http://127.0.0.1:8787/health
curl http://127.0.0.1:8787/v1/rules
```

`GET /health` reports the service and ruleset version plus provider
availability. `GET /v1/rules` returns the versioned rule catalog, including
evidence class, scanner engine, decision effect, confidence basis, and
false-positive notes. Neither endpoint runs a scan or exposes a stored report.

## Marketplace Deep Scan workflow

Submit a single extension ID in `publisher.extension` form. `version` and
`target_platform` are optional, but pinning both available values is the right
choice for a release decision: a report applies only to its exact downloaded
artifact.

```bash
curl -X POST http://127.0.0.1:8787/v1/scans/marketplace \
  -H "Authorization: Bearer $IDE_SCANNER_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data '{
    "extension_id": "GitHub.copilot",
    "version": "1.388.0",
    "target_platform": "linux-x64"
  }'
```

The `202` response is a job record. It contains an opaque `job_<32 lowercase
hex characters>` ID, the requested identity, and `status: "queued"`. A `202`
is not a scan result and must never be used as an allow decision.

Poll the job until it reaches a terminal state:

```bash
curl http://127.0.0.1:8787/v1/jobs/job_0123456789abcdef0123456789abcdef \
  -H "Authorization: Bearer $IDE_SCANNER_API_TOKEN"
```

Job states are:

| State | Meaning | Integration action |
| --- | --- | --- |
| `queued` | The bounded worker pool accepted the request. | Continue polling; do not install or approve. |
| `running` | The scanner owns the job. | Continue polling; do not retry the same request blindly. |
| `complete` | A canonical report bundle was committed. | Fetch `report_ref`, then verify identity, coverage, and decision policy. |
| `failed` with `stage: rejected` | The queue was at capacity. | Back off and submit a new job later. |
| `failed` with `stage: timeout` | The scan exceeded its configured wall-clock budget. | Treat as incomplete evidence; investigate before retrying. |
| `failed` with `stage: interrupted` | The service restarted while the job was active. | Submit a new job; the old result is not usable. |
| `failed` | Download, analysis, or persistence failed. | Treat as incomplete evidence and surface `error` to the operator. |

For a completed job, `report_ref` is a relative API path. Fetch it with the
same authorization header:

```bash
curl http://127.0.0.1:8787/v1/reports/job_0123456789abcdef0123456789abcdef \
  -H "Authorization: Bearer $IDE_SCANNER_API_TOKEN"
```

Before a CI gate, workspace policy, or AI assistant uses the report, verify:

1. The extension ID, version, target platform, artifact SHA-256, and scan ID
   are the release the user asked to review.
2. The report is complete and required provider coverage is present. Missing
   evidence must remain unavailable, not become a passing result.
3. The scanner build, policy version, and ruleset version are present and meet
   the organization’s pinned policy.
4. The decision is interpreted as evidence under the organization’s policy;
   an `allow` does not prove absence of malicious behavior.

## MCP assessment workflow

`POST /v1/scans/mcp` accepts one MCP assessment JSON object and returns the
complete analysis synchronously. It is authenticated and limited to
`IDE_SCANNER_MCP_MAX_BYTES` bytes (512 KiB by default; configurable from 16
KiB through 2 MiB).

```bash
curl -X POST http://127.0.0.1:8787/v1/scans/mcp \
  -H "Authorization: Bearer $IDE_SCANNER_API_TOKEN" \
  -H "Content-Type: application/json" \
  --data @mcp-assessment-input.json
```

A malformed or oversized JSON body returns `400`. A valid request whose
assessment cannot be completed returns `422` with a bounded error message.
Callers must not turn either response into a clean or approved outcome.

## Limits and error responses

The service returns JSON for all routes. Authenticated routes return `401` for
missing or incorrect tokens, `404` for unknown jobs/reports/routes, and `429`
when the scanner queue is full. Scan submission bodies are limited to 16 KiB.

Set these variables deliberately for the host’s available CPU, memory, and
Marketplace bandwidth:

| Variable | Default | Allowed range | Purpose |
| --- | --- | --- | --- |
| `IDE_SCANNER_MAX_WORKERS` | `2` | `1` to `16` | Concurrent scanner workers. |
| `IDE_SCANNER_MAX_QUEUE` | `32` | `1` to `1024` | Waiting scan jobs before requests are rejected with `429`. |
| `IDE_SCANNER_JOB_TIMEOUT` | `600` seconds | `30` to `3600` seconds | Per-job deadline before the record is terminally failed. |
| `IDE_SCANNER_MCP_MAX_BYTES` | `512 KiB` | `16 KiB` to `2 MiB` | Maximum MCP assessment request body. |
| `IDE_SCANNER_ALLOWED_ORIGIN` | `http://127.0.0.1:8765` | One configured origin | CORS response origin only. |

Jobs and reports live in `.ide-scanner-data` unless the service is started
with `--data-dir`. Restart cleanup marks queued or running jobs as
`interrupted` and removes records older than seven days. Persist the data
directory on durable private storage when an audit trail is required, and
export finished report bundles to the GuardRails evidence system before the
retention window expires.

## Integration checklist

- **Web app:** submit the exact requested version, poll to a terminal state,
  and display the returned `report_ref` as immutable evidence rather than an
  inferred reputation score.
- **CI gate:** fail closed for `failed`, missing report identity, unavailable
  required coverage, or a report outside the pinned policy/ruleset range.
- **Codex or Claude workflow:** present the release identity and evidence
  boundaries; use the result to explain review work, never to make an
  unconditional safety claim.
- **Operations:** alert on sustained `429`, timeouts, or `interrupted` jobs;
  those conditions describe unavailable evidence, not benign releases.
