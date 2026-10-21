# GitHub workspace extension scan action

`GuardRails workspace extension scan` discovers extensions recommended by a
repository's VS Code and Dev Container configuration, then scans the matching
published Marketplace artifacts. It is an evidence workflow; the companion
extension policy action is the stricter exact-version-and-hash approval control.

```yaml
name: Workspace extension evidence

on:
  pull_request:
    paths:
      - ".vscode/extensions.json"
      - ".devcontainer/**"
      - "**/*.code-workspace"
      - ".ide-scanner/extensions.lock.json"

permissions:
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: guardrails
        uses: preethamak/IDE_Scanner/.github/actions/workspace-extension-scan@main
        with:
          lock: .ide-scanner/extensions.lock.json
          fail_on: review
      - uses: actions/upload-artifact@v4
        with:
          name: guardrails-workspace-evidence
          path: ${{ steps.guardrails.outputs.report_file }}
```

The action reports `extension_count` and `highest_decision`. `fail_on: review`
rejects `review`, `block`, and `incomplete`; `fail_on: block` rejects `block`
and `incomplete`. Use `profile: deep` and `runtime: "true"` only on a hardened
runner where the bounded runtime requirements are available.
