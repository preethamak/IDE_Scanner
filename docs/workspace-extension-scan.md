# Workspace extension scan

GuardRails discovers extension recommendations from `.vscode/extensions.json`,
Dev Container configuration, and `*.code-workspace` files, then scans the
published Marketplace artifact for every declared extension.

```bash
python -m ide_scanner.cli workspace --root . --lock .ide-scanner/extensions.lock.json --output guardrails-workspace.json
```

Without `--lock`, the scanner resolves the current Marketplace release, useful
for discovery but not a reproducible approval. A reviewed lock pins each
extension's `version` and optional `target_platform`. The output records the
declaration files, requested release coordinates, and full scanner evidence.
Use the GitHub extension policy action for version-and-hash approval enforcement
in pull requests.

For publication-grade evidence on a hardened runner, opt into the complete
provider and bounded runtime path explicitly:

```bash
python -m ide_scanner.cli workspace --root . --lock .ide-scanner/extensions.lock.json --profile deep --runtime --runtime-timeout 30 --output guardrails-workspace-deep.json
```

`--profile deep` rejects incomplete required-provider coverage and requires
`--runtime`; it is not a label for a static-only scan. The runtime pass executes
only eligible extension paths in the scanner's bounded environment.
