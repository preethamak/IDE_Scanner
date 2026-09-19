# GuardRails case study: Nx Console 18.95.0

Status: independently reported supply-chain compromise; GuardRails exact-hash
holdout and policy corroboration. This is not a claim that GuardRails
discovered the incident first.

## Exact release

- Extension: `nrwl.angular-console`
- Compromised version: `18.95.0`
- Malicious VSIX SHA-256: `1a4afce34918bdc74ae3f31edaffffaa0ee074d83618f53edfd88137927340b8`
- Maintainer advisory: [GHSA-c9j4-9m59-847w](https://github.com/nrwl/nx-console/security/advisories/GHSA-c9j4-9m59-847w)
- Independent artifact/hash report: [Phoenix Security](https://phoenix.security/vs-code-extension-malware-github-breach-teampcp-2026/)

The maintainer advisory identifies `18.95.0` as the compromised release and
describes credential theft and persistence. The independent report publishes
the exact malicious VSIX hash. GuardRails keeps that hash in the fresh labelled
holdout and accepts the Trail of Bits VSIX Zoo copy only after the downloaded
bytes match it.

## GuardRails treatment

The exact-hash advisory is represented as `known-malicious-extension` with a
`block` policy action. When the exact artifact is acquired in the production
holdout workflow, the expected result is:

- decision: `block`
- verdict: `malicious`
- malware score: `100`
- analysis status: `complete`
- artifact identity: the SHA-256 above

The adjacent clean release `18.94.0` is retained as a separate safe control.
This prevents a publisher or product name match from blocking every release;
the decision is tied to the exact bytes and version.

## Safe publication language

> GuardRails blocks the independently documented Nx Console 18.95.0
> compromise when the exact malicious artifact hash matches its verified
> advisory. The adjacent 18.94.0 release remains a separate safe control.

Do not say “GuardRails discovered the compromise first.” The evidence supports
exact-artifact reproduction, corroboration, and release-specific blocking—not
an original discovery claim or a guarantee that every adjacent release is safe.

The exact bytes are intentionally acquired by CI rather than committed to the
repository. The local holdout definition is
`benchmarks/holdouts/real-evidence-2026-source.json`, and the workflow that
freezes and scans it is `.github/workflows/publication-holdout.yml`.
