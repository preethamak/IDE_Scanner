# Production Readiness Gate

The scanner is released by evidence, not by increasing finding weights. The
version-pinned corpus at `benchmarks/production-corpus.json` separates:

- `known_safe`: artifacts that must not be preventively blocked;
- `gray`: legitimate, powerful artifacts whose capabilities require context;
- `known_malicious`: abuse fixtures or confirmed artifacts that must not be
  allowed.

Each corpus entry binds an extension id and exact version to its artifact
source, SHA-256 when retained, functional category, expected outcomes, required
rules, forbidden rules, score bounds, and analysis coverage. Entries with
`gate_required=false` are an explicit acquisition/calibration backlog and do
not silently disappear from the benchmark.

## Run the deterministic gate

```bash
PYTHONPATH=src python -m ide_scanner.cli scan \
  --fixtures \
  --threat-feed benchmarks/threat-feed.json \
  --format json \
  --out /tmp/production-fixtures.json

PYTHONPATH=src python -m ide_scanner.cli benchmark production \
  --corpus benchmarks/production-corpus.json \
  --report /tmp/production-fixtures.json \
  --fail-on-regression \
  --out /tmp/production-gate.json
```

The command exits non-zero when a required artifact violates its allowed
verdict, decision, coverage, rule, score, or artifact identity constraints. It
also enforces corpus-wide thresholds for safe blocking, malicious allows, and
incomplete required scans.

## Promotion checklist

Before changing an optional real-world artifact to `gate_required=true`:

1. Retain the exact VSIX in the private artifact vault.
2. Verify the artifact SHA-256 against registry or authoritative intelligence.
3. Record the exact target platform when applicable.
4. Manually review the expected capability and behavior findings.
5. Define allowed and forbidden outcomes.
6. Demonstrate a complete scan on the production worker configuration.

Source snapshots and rebuilt packages must never be represented as original
Marketplace artifacts. A missing artifact remains visible as `not_scanned`.

## Next gates

This first gate establishes deterministic decision invariants. Production work
continues in this order:

1. finish artifact-processing worker isolation; executable source is now
   processed sequentially, AST input is capped at 32 MiB per file, the Node
   heap is capped at 1 GiB, and Semgrep/YARA execute with process, timeout,
   memory, and output-file boundaries;
2. uploaded, installed, archived, and pinned-source acquisition;
3. versioned extension classification and capability contracts;
4. cross-file and interprocedural data flow;
5. signature and source-to-VSIX provenance verification;
6. OS-isolated dynamic analysis with credential canaries;
7. expansion to held-out safe, gray, and malicious corpora.

An AST resource skip is a required-provider failure and makes the scan
incomplete. Raw-text and YARA coverage are not presented as equivalent to a
successful structural parse. The limit is included in provider metadata for
reproducibility.

`yara-python` is never imported into the scanner process during artifact
analysis. A dedicated worker receives a validated relative-path manifest,
limits match/error output, and returns bounded JSON. Worker crashes, timeouts,
resource exhaustion, malformed output, or per-file errors fail the YARA
provider closed while preserving the parent scan and its other evidence.

# Current hardening increment: archive isolation

Untrusted gzip unwrapping, ZIP-member extraction, and complete artifact hashing now execute
outside the scanner process under explicit memory and time bounds. Inventory
targets are passed as relative paths and revalidated against the artifact root;
symlinks are hashed as link metadata rather than followed. Archive anomalies remain visible
as incomplete coverage, while worker crashes and invalid protocol responses
abort the artifact scan. Gzip expansion additionally enforces expanded-byte and
compression-ratio limits and replaces the downloaded input only after the
worker returns a valid, complete response. The next reliability increment is a
first-class artifact-input abstraction for uploaded, installed, archived, and
pinned-source inputs with explicit provenance labels.

## Artifact input provenance

Local scans now record one of `user_uploaded_vsix`, `installed_directory`,
`local_directory`, `archive_artifact`, or `source_snapshot` in both artifact
identity and inventory metadata. The CLI accepts `--artifact-origin` for
`--path` inputs and rejects labels that are structurally incompatible with the
input (for example, a VSIX cannot be labeled as a source snapshot). Only an
artifact acquired directly from a live registry is marked
`original_registry_artifact=true`; an archived VSIX remains an unverified
archive claim until its hash is independently tied to registry or authoritative
intelligence metadata.

Hash-pinned non-registry VSIX acquisition is available through
`--artifact-url` plus the mandatory `--artifact-sha256`. The downloader accepts
only final public HTTPS URLs on port 443, rejects embedded credentials and
redirects, resolves and rejects non-public network addresses, streams with a
512 MiB limit, and deletes bytes that do not match the required digest. URL
details are not persisted in the extension report, and a successfully acquired
artifact is still labeled `archive_artifact`, not a registry original.

## Capability contracts

Functional classification and capability expectations now come from the
packaged, versioned `capability-contracts-1.0.0` policy. The classifier reports
its class, confidence, and supporting text/capability signals, while contract
evaluation reports expected, unexpected, and explicitly forbidden observed
capabilities. Classification alone never establishes trust: the
`expected_capability` outcome still requires an exact extension profile,
verified publisher evidence, matching repository ownership, consistent
artifact identity, complete analysis, and no unexplained actionable evidence.
Unknown or merely inferred classes receive context only and cannot become an
allowlist.

The semantic rule set now also blocks an unverified remote VSIX installation
chain when the same source file downloads remote content, writes a local VSIX,
and calls `workbench.extensions.installExtension` without visible hash or
signature verification. This is reported as high-specificity correlated static
evidence and remains `non_authoritative`; independently verified update flows
are a negative control rather than being globally suppressed by publisher or
extension class.

The first cross-file semantic flow is also implemented for this updater chain.
The scanner builds a bounded, directed relative-import graph and only correlates
download, write, and install stages when they occur on one forward import path.
Unrelated and sibling modules containing the same tokens are negative controls.
Integrity suppression requires a hash/signature verification gate—including
digest production, a trusted expected value, and comparison—rather than a stray
`createHash` token. This is the
foundation for broader interprocedural source-to-sink analysis, not yet a full
JavaScript/TypeScript call graph or value-level taint engine.

The same directed-module foundation now covers systematic credential
harvesting split across files. It requires a credential-file read covering at
least three independent families, serialization, and an explicit network-body
write on one forward import path. Single-credential clients and sibling-module
co-occurrence are negative controls. The evidence reports the import path,
credential families, and files responsible for each source/transform/sink
stage; value identity across function parameters remains future taint-engine
work.

Cross-file findings are now restricted to modules reachable from declared
extension entrypoints, and stage order must be source → transformation → sink
along the forward import path. Dead repository code and reversed-stage module
layouts are negative controls. This improves package-boundary precision while
keeping packaged-but-unreachable code visible to ordinary contextual rules.

Module-flow resource budgets are now part of required provider coverage. If
module count or path exploration exceeds the configured bound, the flow engine
fails explicitly and the overall scan becomes `incomplete`; budget exhaustion
can no longer silently appear as “no abuse chain found.” Reports include the
module, depth, and path limits used for reproducibility.
Import-depth exhaustion also fails closed. A flow that continues beyond the
configured depth can no longer be truncated and reported as though semantic
analysis completed successfully.
The provider also reports reachable-module and resolved-edge counts. A relative
JavaScript/TypeScript import reachable from an entrypoint but absent from the
analyzed module set fails required coverage, because downstream behavior could
otherwise be silently omitted. Non-executable assets such as JSON imports do
not create this limitation.

The first value-linked flow is implemented within a source file for credential
exfiltration. A credential-file read taints its assigned identifier, taint is
propagated through bounded alias/serialization assignments, and an actionable
finding requires that exact lineage to reach an explicit network request body.
Unrelated telemetry bodies and ordinary workspace-file uploads are negative
controls. Cross-function parameters, object properties, callbacks, promises,
and cross-module exported values remain the next taint-analysis milestone.
Direct calls to locally declared functions are now summarized as well: when a
tainted argument is passed into a parameter that the function writes to an
explicit network-body sink, the evidence records the function and parameter
handoff. Unused parameters and unrelated call arguments are negative controls.
Nested callbacks, method dispatch, returned values, object fields, and
cross-module calls are still outside this bounded first implementation.
Credential taint now also propagates when a tainted identifier is assigned to
an object property and the containing object is later serialized or sent. All
assignment and sink propagation is source-order aware: a sink or alias that
appears before the credential read cannot be tainted retroactively. Unrelated
object properties remain a negative control. Computed properties, collection
elements, mutation through aliases, and destructuring still require AST-level
object identity.
Local function return summaries now distinguish pass-through or recognized
serialization returns from calls that discard a secret. Assignment propagation
is intentionally allowlisted: direct aliases, recognized transformations, and
summarized returns propagate taint, while an arbitrary expression that merely
mentions a secret does not. This closes a major false-positive path such as
`const ok = validate(secret)` when `validate` returns only a boolean.
