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
`POST /v1/scans/mcp`. Deploy the service separately from the web Worker and set
the same `IDE_SCANNER_API_TOKEN` on both sides. The production image must also
provide the `gitleaks` and `osv-scanner` executables; `owasp-depscan` is installed
by the package dependencies. Without those providers the report keeps the
affected metrics unavailable instead of converting missing evidence into a
passing result.

The free production fallback is `.github/workflows/mcp-scan.yml`. It executes
the same Python pipeline on a GitHub-hosted runner, verifies the native SCA
providers, and publishes a short-lived encrypted report artifact. Configure
`MCP_SCAN_ENCRYPTION_KEY` as a repository Actions secret; the web Worker uses
the same secret when dispatching and reading MCP assessments.

```bash
PYTHONPATH=src .venv/bin/python -m ide_scanner.service --host 0.0.0.0 --port 8787
```

## License

Proprietary. Copyright © 2026 Preetham AK. All rights reserved.
