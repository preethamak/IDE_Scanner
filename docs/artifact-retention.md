# Marketplace artifact retention

Marketplace scans can preserve the exact downloaded VSIX in a private, content-addressed filesystem vault. Pass `scan --artifact-store /secure/guardrails-artifacts` or set `IDE_SCANNER_ARTIFACT_STORE` for worker-wide configuration. Without either setting, scanning retains its previous temporary-download behavior.

Objects are stored by SHA-256 at `sha256/<prefix>/<sha256>.vsix`; extension metadata is used only in the SQLite observation catalog, never in paths. The scanner verifies stored bytes and publishes only relative storage keys in reports.

Search history with:

```sh
python -m ide_scanner artifacts --store /secure/guardrails-artifacts \
  --extension-id ms-python.python --version 2026.1.0 --target-platform linux-x64
```

Filters also include `--registry` and `--sha256`. Rescan a result using its storage key:

```sh
python -m ide_scanner scan --path /secure/guardrails-artifacts/sha256/ab/<sha256>.vsix
```

## Operations and limitations

The vault may contain hostile code. Put it on encrypted persistent storage, restrict access to scanner operators, back it up, audit downloads, and apply quarantine and retention policy. The GitHub Actions workflow uploads a private recovery copy for 90 days; that is not permanent production retention. A production deployment should copy objects into encrypted object storage and keep observations in its database.

Retention begins only after successful acquisition. Extensions removed before GuardRails captured them cannot be recovered by this feature.
