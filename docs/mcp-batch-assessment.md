# MCP catalog batch assessment

`POST /v1/scans/mcp/batch` assesses a small MCP catalog through the same
authenticated service boundary as the single-descriptor endpoint. It accepts
one JSON object with a `servers` array containing one through ten descriptor
objects.

```json
{
  "servers": [
    {"name": "internal-docs", "transport": "stdio", "tools": []},
    {"name": "remote-search", "url": "https://example.invalid/mcp", "tools": []}
  ]
}
```

Results preserve request order and include `index`, `status`, and either an
`assessment` or a bounded error. One descriptor failure does not discard the
other results. This endpoint is intentionally synchronous and bounded; use the
single endpoint for interactive calls and split larger inventories into batches
of ten. A result is review evidence, not an authorization to connect an agent.
