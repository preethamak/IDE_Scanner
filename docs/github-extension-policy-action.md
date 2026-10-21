# GitHub extension policy action

`GuardRails extension policy` makes the repository extension-policy gate
reusable in GitHub Actions. It finds recommendations in VS Code workspace,
Dev Container, and `.code-workspace` files; downloads the exact published
VSIX; and evaluates the release against a version-and-SHA-256 approval policy.
It statically analyzes the package and never runs extension code.

Use it on pull requests that change developer-environment configuration:

```yaml
name: GuardRails extension policy

on:
  pull_request:
    paths:
      - ".vscode/extensions.json"
      - ".devcontainer/**"
      - "**/*.code-workspace"
      - ".ide-scanner/**"

permissions:
  contents: read

jobs:
  extension-policy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: guardrails
        uses: preethamak/IDE_Scanner/.github/actions/extension-policy@main
        with:
          policy: .ide-scanner/policy.json
          lock: .ide-scanner/extensions.lock.json
      - run: echo "Checked ${{ steps.guardrails.outputs.total }} extensions"
```

The action fails the job when a release is `review`, `block`, or `incomplete`
without a matching, unexpired approval. A matching exception must name the
exact extension version and SHA-256. `block` additionally requires
`allow_block_override: true`; that is deliberate and should be rare.

## Bootstrap a reviewed lock

Run the action manually with `write_lock: true`, then review and commit the
produced lock and policy in a pull request. This mode resolves current releases
but does not silently approve them: approvals remain a separate human decision.

```yaml
on:
  workflow_dispatch:

jobs:
  refresh-lock:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: preethamak/IDE_Scanner/.github/actions/extension-policy@main
        with:
          write_lock: "true"
      - uses: actions/upload-artifact@v4
        with:
          name: guardrails-extension-policy
          path: |
            .ide-scanner/extensions.lock.json
            ide-scanner-policy-result.json
```

The `result_file`, `total`, and `failed` outputs are available for annotations,
artifacts, or a follow-up approval workflow. Keep the policy and lock in source
control; the action is a reproducible enforcement point, not an approval system.
