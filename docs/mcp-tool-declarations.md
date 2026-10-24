# MCP tool declaration evidence

GuardRails records the MCP tool declarations returned by a server so a review
can distinguish the server's stated interface from scanner-derived evidence.
Each serialized tool includes `declaration`, with the human-facing title,
annotation hints, output schema, an interface SHA-256 fingerprint, and any
internally contradictory hints.

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
    "sha256": "a stable 64-character SHA-256 declaration fingerprint",
    "issues": []
  }
}
```

Annotations are claims supplied by the MCP server. They never suppress a
metadata-security finding, alter capability classification, or lower a
GuardRails decision. `issues` is intentionally narrow: it reports factual
inconsistencies in the declaration, such as setting both `readOnlyHint` and
`destructiveHint` to `true`; it is not a behavioral assessment.

The fingerprint is a canonical SHA-256 digest of the tool name, title,
description, input and output schemas, and annotation hints. It intentionally
does not include scanner findings or generated explanations, so a changed digest
identifies a declared tool-interface change that should be reviewed.

Compare two completed assessment JSON files locally or in CI:

```bash
PYTHONPATH=src .venv/bin/python -m ide_scanner mcp-declarations \
  --before assessment-before.json --after assessment-after.json --fail-on-drift
```

The command reports `added`, `removed`, `changed`, and `unchanged` tool names.
With `--fail-on-drift`, it exits `1` whenever a declared interface changes. It
requires the fingerprinted declaration evidence described above and makes no
claim about runtime behavior or safety.
