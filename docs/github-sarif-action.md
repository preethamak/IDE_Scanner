# GitHub code scanning action

Use the GuardRails action to scan the exact extension artifact or directory
present in a repository checkout and publish its scanner findings as SARIF.
The action produces release evidence; GitHub Code Scanning remains responsible
for storing and presenting the SARIF results.

```yaml
name: GuardRails extension evidence

on:
  pull_request:
  workflow_dispatch:

permissions:
  contents: read
  security-events: write

jobs:
  scan-extension:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v5
      - id: guardrails
        uses: preethamak/IDE_Scanner@main
        with:
          path: ./dist/publisher.extension-1.2.3.vsix
          profile: deep
          runtime: true
          output: guardrails.sarif.json
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ${{ steps.guardrails.outputs.sarif_file }}
```

Pin the action to an immutable commit in a production workflow. Pinning the
extension version and preserving its VSIX SHA-256 in the scan result are also
necessary: scanning a repository tree is not proof that it matches a published
Marketplace artifact.

The `deep` profile requires `runtime: true`; the action rejects the invalid
combination before scanning. A failed or incomplete deep scan must fail the
workflow. For local triage, use `standard` or `smart` and interpret a SARIF
result as recorded evidence, not an unconditional safety approval.

The action does not upload results itself. Give `security-events: write` only
to the dedicated `github/codeql-action/upload-sarif` step, and keep the
workflow permissions limited to the scopes shown above.
