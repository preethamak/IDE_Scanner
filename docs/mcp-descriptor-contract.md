# MCP descriptor contract

The GuardRails MCP assessment CLI and GitHub Action accept a JSON server
descriptor. The packaged schema is
`ide_scanner/contracts/mcp-descriptor.schema.json` and uses the identifier
`guardrails-mcp-descriptor.v1`.

Every descriptor needs a non-empty `name`. It must then declare either a remote
`mcp_url`/`url`, or explicitly identify itself as local with `is_local: true` or
`transport: "stdio"`, `"local"`, or `"command"`.

```json
{
  "name": "example-server",
  "url": "https://example.com/mcp",
  "transport": "streamable-http",
  "repo_url": "https://github.com/example/server",
  "auth_modes": ["oauth"],
  "tools": []
}
```

Remote URLs may use HTTP or HTTPS because transport security is a measured
assessment input. URLs with embedded credentials are rejected; provide auth
metadata, never credentials, in the descriptor. Tool entries must be objects.
Malformed or ambiguous descriptors fail before assessment instead of being
silently interpreted as a local server.
