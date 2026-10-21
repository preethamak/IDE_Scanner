# Related extension scanning

## Purpose

A VS Code extension can declare `extensionPack` and `extensionDependencies` in
its published manifest. Those declarations can cause other extensions to be
installed alongside the release a team intended to review. GuardRails records
those declarations on every scanned artifact and can optionally scan the
related Marketplace releases.

This is supplementary supply-chain evidence. It does not turn an unversioned
manifest declaration into evidence that a particular related artifact was
reviewed with the primary release.

## Run a bounded traversal

```bash
PYTHONPATH=src python -m ide_scanner scan \
  --extension-id publisher.extension --version 1.2.3 \
  --expand-extension-relationships --max-related-extensions 20 \
  --artifact-store /secure/guardrails-artifacts --out report.json
```

`--max-related-extensions` accepts `1` through `100` and defaults to `20`.
Traversal is opt-in because it downloads additional Marketplace artifacts.
The scanner de-duplicates identifiers across the complete walk, so packs and
dependencies cannot create a cycle or scan the same release repeatedly.

## Evidence semantics

The primary target requested with `--extension-id --version` remains exact
release evidence. Its report contains:

- `artifact_inventory.declared_extension_relationships`: normalized manifest
  references with either `extension_pack` or `extension_dependency` direction.
- contextual `declared-extension-relationships` capability evidence. A
  relationship by itself is not malware, a vulnerability, or a block verdict.

Each related artifact added by traversal has:

- `artifact_identity.relationship_scan.selection: "latest_available"`
- `artifact_identity.relationship_scan.version_pinned: false`
- parent extension ID/version, relationship type, and traversal depth.

Marketplace metadata resolves the related artifact at scan time because VS Code
manifest references have no version field. Retain the downloaded artifact when
the relationship matters to a decision; its SHA-256 and scan timestamp make a
later review reproducible.

## Review procedure

1. Pin and review the primary release first. Do not substitute a child scan for
   the package version a developer plans to install.
2. Inspect declared relationships, especially `extensionPack` entries and
   high-impact child findings.
3. Treat every `latest_available` child as a separate release decision. If a
   deployment pins a child version through a managed extension list, scan that
   exact child version independently.
4. Check `relationship_expansion.truncated`. When it is true, the scan budget
   stopped before all declarations were followed; increase the bounded limit or
   review the remaining IDs independently.
5. Preserve decision-relevant VSIX files in a private artifact store. A clean
   current child release says nothing about an older child release that was
   installed previously.

## Limits

Relationship traversal checks declared install relationships only. It does not
infer hidden runtime downloads, repository dependencies, or other marketplace
accounts. The scanner's existing static, runtime, advisory, and dependency
coverage is applied to each fetched child artifact independently.
