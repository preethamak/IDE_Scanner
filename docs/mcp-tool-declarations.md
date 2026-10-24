# MCP tool declaration evidence

GuardRails records the MCP tool declarations returned by a server so a review
can distinguish the server's stated interface from scanner-derived evidence.
Each serialized tool includes `declaration`, with the human-facing title,
annotation hints, output schema, and any internally contradictory hints.

```json
{
  "name": "lookup_customer",
  "declaration": {
    "title": "Lookup customer",
    "annotations": {
      "readOnlyHint": true,
      "idempotentHint": true,
      "openWorldHint": false
    },
    "output_schema": {"type": "object"},
    "issues": []
  }
}
```

Annotations are claims supplied by the MCP server. They never suppress a
metadata-security finding, alter capability classification, or lower a
GuardRails decision. `issues` is intentionally narrow: it reports factual
inconsistencies in the declaration, such as setting both `readOnlyHint` and
`destructiveHint` to `true`; it is not a behavioral assessment.
