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

Every workspace report includes `lock_coverage`: declared and pinned counts,
unpinned recommendations, and lock entries that no longer match the workspace.
For an approval or release workflow, require a complete reviewed set instead of
silently scanning whichever current release the Marketplace returns:

```bash
python -m ide_scanner.cli workspace --root . --lock .ide-scanner/extensions.lock.json --require-lock --output guardrails-workspace.json
```

`--require-lock` fails before any Marketplace download if a declared extension
lacks a version pin. It does not fail merely because a lock has an unused entry;
the report records that drift for cleanup and review.

## Generate a candidate reviewed lock

After reviewing a completed workspace evidence report, generate pins from the
exact artifact coordinates that were assessed:

```bash
python -m ide_scanner.cli workspace-lock \
  --report guardrails-workspace.json \
  --output .ide-scanner/extensions.lock.json
```

The command refuses incomplete, failed, missing-version, or ambiguous scan
evidence. Review the generated diff before committing it; generation preserves
the assessed version and target platform, but it is not an automatic approval.

Compare a proposed update locally or in CI:

```bash
python -m ide_scanner.cli workspace-lock-diff --before current-lock.json --after proposed-lock.json --fail-on-drift
```

It reports added, removed, changed, and unchanged exact release pins. A nonzero
exit from `--fail-on-drift` signals a required human review, not a verdict.

GitHub workflows can use `.github/actions/workspace-lock-diff` to publish the
same JSON diff and the `drift_detected` / `changed_extension_count` outputs.
Its default blocks lock changes after writing evidence; use `fail-on-drift:
false` during a staged rollout.

For publication-grade evidence on a hardened runner, opt into the complete
provider and bounded runtime path explicitly:

```bash
python -m ide_scanner.cli workspace --root . --lock .ide-scanner/extensions.lock.json --profile deep --runtime --runtime-timeout 30 --output guardrails-workspace-deep.json
```

`--profile deep` rejects incomplete required-provider coverage and requires
`--runtime`; it is not a label for a static-only scan. The runtime pass executes
only eligible extension paths in the scanner's bounded environment.
