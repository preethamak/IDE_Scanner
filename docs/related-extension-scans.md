# Related extension scans

VS Code manifests can declare `extensionPack` and `extensionDependencies`. A
scan of the root VSIX does not automatically analyze those separate packages.

Use `--scan-related` when acquiring a Marketplace extension to inspect one
declared relationship hop as separately identified artifacts:

```sh
python -m ide_scanner scan \
  --extension-id publisher.extension \
  --scan-related \
  --artifact-store /secure/guardrails-artifacts
```

Each related package is downloaded and reported independently. The root
artifact records the declaration, relationship type, resolved extension id,
version, and SHA-256. A related report records its parent artifact references.

The mode is intentionally bounded to 50 unique related extension ids and does
not recurse. A manifest declaration contains no immutable related-package
version or hash, so the result is evidence of the Marketplace artifact resolved
at scan time, not proof of what a future Marketplace installation will fetch.
Entries skipped due to a self-reference, direct requested target, acquisition
failure, or fan-out limit remain explicit in the root artifact's relationship
resolution data.

For an installed extension inventory, the local agent can preserve the same
one-hop relationship evidence in the uploaded workspace report:

```sh
python -m ide_scanner agent --all --scan-related --server https://abscissa.dev
```

The agent still redacts source preview content before upload. Related packages
remain separate report entries with their own exact artifact identity; they are
not folded into the parent extension's decision or coverage.
