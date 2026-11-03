# Guardrails Scanner Runtime

The proprietary extension-security runtime used by Guardrails CLI and
Guardrails Deep Scan.

## Guardrails CLI

Install the local extension scanner:

```bash
pipx install guardlens
```

Run it with:

```bash
guardrails
```

Guardrails CLI performs deterministic static analysis by default. Use the
capability-gated `--runtime` pass, or `--profile deep --runtime` for a
publication-grade scan, to execute eligible extension paths inside a bounded
Bubblewrap namespace with networking disabled. The host never executes the
extension directly, and packages that do not expose an executable security
surface are recorded as runtime not-applicable rather than forced through a
meaningless entrypoint.

For repository-level review, use the [workspace extension scan
workflow](docs/workspace-extension-scan.md) to discover VS Code and Dev
Container recommendations and inspect their published Marketplace artifacts.

Use the [GitHub workspace extension scan action](docs/github-workspace-scan-action.md)
to preserve that evidence as a pull-request artifact and optionally gate on the
highest recorded decision.

Examples:

```bash
guardrails scan --file extension.vsix --runtime --format json --output report.json
guardrails scan --file extension.vsix --profile deep --runtime --format zip --output report.zip
guardrails scan --file extension.vsix --format cyclonedx.json --output extension.cdx.json
```

`cyclonedx.json` emits a CycloneDX 1.5 SBOM from the resolved scan result. It
binds each exact scanned extension to its resolved npm dependencies, preserves
direct/transitive relationships, and records artifact SHA-256, scanner build,
and ruleset identity when available. It does not include source previews or raw
finding evidence.

guardrails scan --file extension.vsix --format sarif --output guardrails.sarif.json
```

SARIF export is for code-scanning integrations. It includes only scanner-recorded
locations and preserves exact artifact identity in each result; a clean SARIF
log is evidence of completed checks, not a guarantee that an extension is safe.

Use [the GitHub Code Scanning action](docs/github-sarif-action.md) to emit and
upload that exact-artifact SARIF evidence in a repository workflow.

### Related extension releases

VS Code extension packs and `extensionDependencies` can install other
extensions alongside the release being reviewed. To inspect those declarations
as well, opt into bounded relationship traversal:

```bash
PYTHONPATH=src python -m ide_scanner scan \
  --extension-id publisher.extension --version 1.2.3 \
  --expand-extension-relationships --max-related-extensions 20 \
  --format json --out report.json
```

The requested extension remains the exact, version-pinned primary artifact.
Related manifest entries do not contain a version, so each additional scan is
recorded as `latest_available` evidence with `version_pinned: false`. The walk
is cycle-safe and stops at the configured release budget; a truncated walk is
reported explicitly. See [relationship scanning](docs/relationship-scanning.md)
for the review procedure and report fields.

Website: [abscissa.dev](https://abscissa.dev)

## MCP assessment service

The Python service exposes the complete MCP catalog assessment at
`POST /v1/scans/mcp` and a bounded catalog endpoint at
`POST /v1/scans/mcp/batch`. Deploy the service separately from the web Worker and set
the same `IDE_SCANNER_API_TOKEN` on both sides. For a no-downtime credential
rotation, use the documented `IDE_SCANNER_API_TOKENS` overlap set. The production image must also
provide the `gitleaks` and `osv-scanner` executables; `owasp-depscan` is installed
by the package dependencies. Without those providers the report keeps the
affected metrics unavailable instead of converting missing evidence into a
passing result.

Marketplace scan clients should use the documented [idempotent retry
contract](docs/scanner-service-retries.md) so network retries do not create
duplicate exact-artifact analysis jobs.

Trusted internal systems can receive signed terminal-job notifications through
the [scanner service webhook contract](docs/scanner-service-webhooks.md).

GitHub repositories can submit and enforce a pinned Marketplace release with
the [Marketplace service action](docs/github-marketplace-service-action.md).

See [scanner service operations](docs/scanner-service-operations.md) for local
job retention, periodic maintenance, and evidence-lifetime controls.

Use `GET /health` as a liveness probe. Use unauthenticated `GET /readyz` as a
readiness probe: it verifies that the persistent job store accepts atomic
writes and that every configured scan worker is alive. A non-ready service
returns `503` and a bounded JSON reason; it never includes queued job data or
report content.

The free production fallback is `.github/workflows/mcp-scan.yml`. It executes
the same Python pipeline on a GitHub-hosted runner, verifies the native SCA
providers, and publishes a short-lived encrypted report artifact. Configure
`MCP_SCAN_ENCRYPTION_KEY` as a repository Actions secret; the web Worker uses
the same secret when dispatching and reading MCP assessments.

For VS Code workspace governance, use the reusable [GitHub extension policy
action](docs/github-extension-policy-action.md). It resolves the exact
published VSIX for repository-recommended extensions and enforces
version-and-SHA-256 approvals in CI.

```bash
PYTHONPATH=src .venv/bin/python -m ide_scanner.service --host 0.0.0.0 --port 8787
```

For the authenticated service contract, polling workflow, exact-artifact
checks, and production limits, see [the scanner service API guide](docs/scanner-service-api.md).

The running service publishes its machine-readable contract at
`GET /v1/openapi.json`.

MCP results retain the server's declared tool title, annotations, and output
schema as review evidence. Hints such as `readOnlyHint` and `destructiveHint`
are not treated as proof of runtime behavior or as a way to lower a GuardRails
decision. Objectively contradictory declarations are disclosed in the tool's
`declaration.issues` field.

For repository-local descriptor reviews, use the [GitHub MCP assessment
action](docs/github-mcp-assessment-action.md). It produces the same
machine-readable evidence contract without installing or executing the server.
For assistant-safe review patterns in Codex- and Claude-style workflows, use
the [MCP assistant workflow guide](docs/mcp-assistant-workflows.md).

## License

Proprietary. Copyright © 2026 Preetham AK. All rights reserved.
