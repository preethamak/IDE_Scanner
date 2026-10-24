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
Someone who can replace the entire ZIP can replace `integrity.json` too.

For controlled CI or scanner workers, sign the manifest with an Ed25519 private
PEM held in the secret manager:

```sh
guardrails scan --path extension.vsix --format report.zip --output report.zip \
  --signing-key "$GUARDRAILS_REPORT_SIGNING_KEY" --signing-key-id guardrails-prod
guardrails report verify --bundle report.zip --public-key guardrails-prod.pub.pem \
  --expected-key-id guardrails-prod --require-signature
```

The signature covers the exact `integrity.json` bytes. `--require-signature`
fails closed for unsigned reports, an unexpected signer ID, an invalid
signature, or a public key that does not match the recorded signer.
