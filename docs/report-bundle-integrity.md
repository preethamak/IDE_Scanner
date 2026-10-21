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
entire ZIP can also replace `integrity.json`. Treat an unsigned manifest as
tamper-detection during transfer and storage.

## Signed provenance

For a release, CI job, or controlled scanner worker, sign the bundle with an
approved Ed25519 private key. The private key must be an unencrypted PEM file;
keep it in the CI secret store and never place it in a repository or report.

Generate a new keypair only on a controlled operator workstation or secure CI
bootstrap environment. GuardRails refuses to overwrite either path and writes
the private PEM with owner-only permissions:

```sh
python -m ide_scanner keys generate-report-signing-key \
  --private-key ./guardrails-prod-2026.pem \
  --public-key ./guardrails-prod-2026.pub.pem \
  --key-id guardrails-prod-2026
```

Move the private PEM immediately into the CI secret manager, retain the public
PEM in the organization's trusted-key channel, and remove the local private
file when the handoff is complete. The command prints the public-key fingerprint
to make that distribution checkable.

```sh
python -m ide_scanner scan --path extension.vsix --format report.zip \
  --output guardrails-report.zip \
  --signing-key "$GUARDRAILS_SIGNING_KEY" \
  --signing-key-id guardrails-prod-2026
```

Signing adds `provenance.json`. It signs the exact bytes of `integrity.json`,
which in turn hashes every report member. The provenance record carries an
Ed25519 public-key SHA-256 fingerprint and a key ID, but not the public key
itself. Distribute trusted public keys through a separately controlled channel
such as the organization security repository or key-management system.

Authenticate a received report against one of those trusted public keys:

```sh
python -m ide_scanner report verify --bundle guardrails-report.zip \
  --public-key guardrails-prod-2026.pub.pem \
  --expected-key-id guardrails-prod-2026 \
  --require-signature
```

`--require-signature` fails closed: unsigned bundles, missing trusted keys,
unknown signer IDs, key mismatches, and invalid signatures all exit with code
`2`. A successful authenticated result means both the member hashes and the
signature made by the selected trusted key were verified. It does not establish
that an extension is safe, only who produced the evidence bundle.
