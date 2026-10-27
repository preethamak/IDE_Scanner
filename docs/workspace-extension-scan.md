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
