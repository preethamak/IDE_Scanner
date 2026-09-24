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

## License

Proprietary. Copyright © 2026 Preetham AK. All rights reserved.
