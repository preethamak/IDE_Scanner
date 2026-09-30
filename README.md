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
```

Website: [abscissa.dev](https://abscissa.dev)

## MCP assessment service

The Python service exposes the complete MCP catalog assessment at
`POST /v1/scans/mcp`. Deploy the service separately from the web Worker and set
the same `IDE_SCANNER_API_TOKEN` on both sides. The production image must also
provide the `gitleaks` and `osv-scanner` executables; `owasp-depscan` is installed
by the package dependencies. Without those providers the report keeps the
affected metrics unavailable instead of converting missing evidence into a
passing result.

```bash
PYTHONPATH=src .venv/bin/python -m ide_scanner.service --host 0.0.0.0 --port 8787
```

## License

Proprietary. Copyright © 2026 Preetham AK. All rights reserved.
