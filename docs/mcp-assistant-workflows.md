# MCP assistant review workflows

GuardRails assesses a declared MCP server descriptor and emits evidence. It
does not install the server, invoke its tools, authenticate to it, or approve
it on behalf of a person. These workflows keep an AI assistant inside that
boundary.

Start with a committed descriptor containing metadata, never credentials:

```json
{
  "name": "example-mcp-server",
  "url": "https://mcp.example.com",
  "transport": "streamable-http",
  "repo_url": "https://github.com/example/mcp-server",
  "auth_modes": ["oauth"],
  "tools": [
    {"name": "search", "description": "Search an approved product catalog."}
  ]
}
```

Use the [descriptor contract](mcp-descriptor-contract.md) for every accepted
field. A descriptor must not contain bearer tokens, API keys, client secrets,
or copied authorization headers.

## Codex-style repository review

1. Ask the assistant to add or update the descriptor and the GitHub workflow,
   not to connect to or execute the MCP server.
2. Run the [GitHub MCP assessment action](github-mcp-assessment-action.md) with
   `fail_on: review` for a new remote server, or `block` only when a documented
   review process accepts `review` evidence.
3. Attach the generated report to the pull request. Have the assistant extract
   the decision, coverage percentage, unavailable metrics, authentication
   evidence, tool-risk findings, and any required human review from that
   report.
4. A human owner decides whether the stated tools, data access, and identity
   model match the intended use. The assistant should preserve this decision in
   the review record instead of treating a non-blocking result as approval.

An appropriate instruction is:

> Assess this committed MCP descriptor only. Do not install, call, or
> authenticate to the server. Summarize the GuardRails report as evidence,
> including decision, coverage gaps, unknowns, and required human decisions.

## Claude-style change review

Use the same committed descriptor and CI artifact. Give the assistant the
report JSON rather than a credentialed server URL. Ask it to compare the
proposed descriptor with the previous reviewed version and identify changes to
transport, repository, authentication modes, declared tools, and coverage.

An appropriate instruction is:

> Compare these two versioned GuardRails MCP reports. Flag material changes in
> server identity, declared capability, authentication, coverage, and decision
> basis. Do not make a safety guarantee or recommend credentials.

This keeps the review reproducible: assistants reason over a versioned report,
while people retain authority for access grants and exceptions.

## Local pre-review

For a repository-local check before CI, run:

```bash
python -m ide_scanner.cli mcp \
  --input mcp/example-server.json \
  --output guardrails-mcp-assessment.json
```

The output is the machine-readable `guardrails.mcp-risk-report.v1` evidence
record. Treat `incomplete` as missing evidence, not a passing result. A clean
or `allow` result lowers a specific set of measured risks; it does not prove
that a remote server, future release, or tool result is safe.
