# Source-to-VSIX provenance comparison

Use the `provenance` command when a release review needs evidence about the
relationship between a source snapshot and the exact VSIX being considered.

```bash
guardrails provenance --source ./extension-repository --vsix ./publisher.extension-1.2.3.vsix --out provenance.json
```

The comparison hashes files under the VSIX `extension/` payload without
extracting the archive. It reports common files with matching or changed bytes,
plus source-only and artifact-only paths. Source-only files are normal when
packaging excludes tests or development assets. Artifact-only or changed files
are review prompts, not automatic malware findings.

The command refuses malformed paths and VSIX archives with more than 20,000
members or more than 512 MiB of declared unpacked data. It compares a supplied
snapshot only; it does not fetch a repository, prove a build is reproducible,
or establish publisher identity.
