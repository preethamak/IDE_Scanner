# Report bundle integrity

Every `report.zip` written by GuardRails includes `integrity.json`. It contains
the SHA-256 and byte size for every report member except the manifest itself.

Verify a downloaded or transferred bundle before importing or reviewing it:

```sh
python -m ide_scanner report verify --bundle guardrails-report.zip
```

The verifier rejects missing, altered, duplicated, or unlisted members. A
successful result means the archive members match its embedded integrity
manifest.

This is **not** publisher authentication. An attacker who can replace the
entire ZIP can also replace `integrity.json`. Treat this manifest as
tamper-detection during transfer and storage; use a future signed provenance
record to establish who produced a bundle.
