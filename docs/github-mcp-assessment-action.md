# GitHub MCP assessment action

Use `GuardRails MCP assessment` to assess a committed MCP server descriptor in
CI. It writes the complete machine-readable evidence report as an artifact and
exposes the decision and coverage as action outputs. The action assesses the
descriptor; it does not install, execute, or grant the server access.

```yaml
name: MCP assessment

on:
  pull_request:
    paths:
      - "mcp/**"
      - ".github/workflows/mcp-assessment.yml"

permissions:
  contents: read

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - id: guardrails
        uses: preethamak/IDE_Scanner/.github/actions/mcp-assessment@main
        with:
          descriptor: mcp/server.json
          fail_on: review
      - uses: actions/upload-artifact@v4
        with:
          name: guardrails-mcp-assessment
          path: ${{ steps.guardrails.outputs.report_file }}
```

`fail_on` is deliberately explicit:

- `never` records evidence but never fails the workflow.
- `review` fails for `review`, `block`, or `incomplete`.
- `block` fails for `block` or `incomplete`.

An assessment decision is evidence, not a guarantee. Review the report's
coverage and unavailable metrics before using it as a release approval.
