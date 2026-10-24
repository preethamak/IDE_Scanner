# Report Bundle Integrity

Every `report.zip` written by GuardRails includes `integrity.json`. It records
the SHA-256 digest and byte size for every report member, including the
CycloneDX export.

Verify a transferred report before importing or reviewing it:

```sh
guardrails report verify --bundle guardrails-report.zip
```

The verifier rejects missing, altered, duplicate, unlisted, and unsafe archive
members. A successful result proves that the members match the report's own
integrity manifest.

This is transfer and storage tamper detection, not publisher authentication.
Someone who can replace the entire ZIP can replace `integrity.json` too. Treat
an unsigned manifest as evidence of internal consistency only; distribute
publisher trust through a separate signing and trusted-key workflow.
