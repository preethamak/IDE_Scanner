# AzureCdnInfo.edrtester 1.0.4

Status: independently reported malicious artifact added to the exact-hash
publication holdout. This is corroboration and reproduction material, not a
claim that GuardRails discovered the campaign first.

## Identity

- Extension: `AzureCdnInfo.edrtester`
- Version: `1.0.4`
- Marketplace artifact SHA-256: `d4101a5bc86747f499ef347548e92eb3e1b09ce6acaf34bd1ee07f66400b18af`
- GuardRails advisory: `CLR-2026-3045`
- Policy: `block`

The primary report is [Codelake Research's advisory](https://research.codelake.dev/advisories/clr-2026-3045-edrtester/).
The artifact is also listed in the [OSV VS Code ecosystem index](https://osv.dev/list?ecosystem=VSCode).
The corresponding [Marketplace listing](https://marketplace.visualstudio.com/items?itemName=AzureCdnInfo.edrtester)
is retained as the official acquisition source in the frozen holdout manifest.

## Evidence boundary

Codelake describes host and Active Directory reconnaissance, immediate and
delayed beaconing, and dormant reverse-shell capability. The advisory snapshot
therefore blocks this exact version/hash before a behavioral inference is used.
The publication holdout separately acquires the Marketplace bytes, verifies the
SHA-256, runs the deep capability-gated runtime, and replays the artifact with
an empty advisory snapshot. The second replay is a false-negative regression
check; it must not be presented as proof of first discovery.

If acquisition, hash verification, runtime isolation, or external syscall
tracing fails, the holdout remains incomplete and cannot activate a registry
release.
