# GitHub Marketplace service action

`marketplace-service-scan` lets a repository gate a pinned VS Marketplace
extension release against a private GuardRails scanner service. It submits one
exact `publisher.extension` and version, polls the authenticated job record,
downloads the canonical report bundle, and applies a declared decision policy.

The action is designed for release evidence, not as a claim that a clean scan
guarantees safety. `incomplete` evidence fails every enabled policy.

```yaml
name: Review extension release

on:
  workflow_dispatch:

jobs:
  guardrails:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: preethamak/IDE_Scanner/.github/actions/marketplace-service-scan@<pinned-commit-sha>
        id: extension
        with:
          service-url: https://scanner.example
          token: ${{ secrets.GUARDRAILS_SCANNER_TOKEN }}
          extension-id: publisher.extension
          version: 1.2.3
          target-platform: linux-x64
          fail-on: review
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: guardrails-release-evidence
          path: ${{ steps.extension.outputs.report-file }}
```

`fail-on` values are:

- `never`: return the report and decision without failing the job.
- `review`: fail for `review`, `block`, or `incomplete`.
- `block`: fail for `block` or `incomplete`.

The action outputs `job-id`, `report-file`, `decision`, and `report-sha256`.
When the scanner service exposes report evidence identities, the action verifies
the returned `ETag` and job digest against the exact report bytes before it
returns a decision. Record `report-sha256` with the release review or downstream
attestation. Supply a stable
`idempotency-key` when a workflow may retry the same release; otherwise the
default key is scoped to the GitHub run and job. The scanner service controls
the webhook destination and report retention. This action never supplies a
webhook URL and never logs the service token.

Pin the action by commit SHA in production workflows. The scanner service
must be reachable from the GitHub runner and configured with the same bearer
token used by the action.
