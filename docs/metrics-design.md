# IDE Scanner Metrics Design

This document defines how `ide-scanner` should score IDE extensions without overstating static heuristics as confirmed malware. The design goal is a scanner that is aggressive about evidence collection, conservative about malware labels, and explicit about confidence.

## Design Principles

1. **Separate malware confidence from operational risk.** A debugger, language server, AI coding agent, or Docker extension can legitimately read files, spawn processes, open terminals, and use the network. Those capabilities increase operational risk, but they are not malware proof.
2. **Use authoritative labels only for authoritative evidence.** `malicious` must require a trusted source or artifact-level proof: marketplace removal for malware, OSV `MAL-*`, a trusted threat-feed hit, or a hash/version match against known-bad artifacts.
3. **Use behavior chains, not isolated tokens.** A standalone `fetch`, `process.env`, `child_process`, or filesystem read is weak. A same-path chain such as credential reference + file read + outbound write is meaningful.
4. **Record suppressors as evidence, not blind allowlists.** Verified publisher, signed VSIX, expected vendor domain, pinned checksum, reproducible build, and user-triggered command path should reduce risk only when the scanner can show why.
5. **Every score must be explainable.** Reports should expose the metric id, evidence class, source, files, extracted features, suppressors, and score contribution.
6. **Calibrate against real corpora.** Thresholds should be tuned on known removed/malicious extensions, known-safe first-party extensions, and gray extensions that need human review.

## External Metric Sources Studied

- Socket.dev: supply-chain alerts such as malware, typosquatting, install scripts, obfuscated code, telemetry, native code, shell access, network access, privileged capability, risky AI skills, maintenance, quality, license, and extension-specific OpenVSX alerts.
- OpenSSF Scorecard: repository posture checks such as maintained status, code review, branch protection, dangerous workflows, token permissions, signed releases, binary artifacts, and security policy.
- OSV and OSV-Scanner: authoritative vulnerability and malicious package identifiers, including `MAL-*` records.
- deps.dev: package versions, dependency graphs, advisories, provenance, attestations, and dependency requirement metadata.
- GuardDog: static rules and metadata checks for malicious packages, including obfuscation, download-exec behavior, suspicious lifecycle hooks, repository mismatch, and typosquatting.
- OpenSSF package-analysis: dynamic sandbox observation of install/runtime behavior such as network, process, file, and environment access.
- Microsoft VS Marketplace removed packages: ground-truth removal events for VS Code extensions, including malware, impersonation, suspicious, and untrustworthy classifications.
- Phylum and similar threat-feed products: curated malicious package intelligence and package behavior analysis.

## Output Model

The scanner should expose these top-level outputs for each extension.

| Field | Meaning | False-positive rule |
| --- | --- | --- |
| `verdict` | `clean`, `review`, `suspicious`, or `malicious` | `malicious` is gated to confirmed intelligence only. |
| `malware_authority` | `authoritative`, `non_authoritative`, or `none` | Static heuristics can never produce `authoritative`. |
| `malware_score` | 0-100 confidence that the artifact is malware | 90+ requires confirmed or dynamically observed malicious behavior. |
| `risk_score` | 0-100 operational risk if installed | Can be high for powerful legitimate extensions. |
| `confidence` | `high`, `medium`, or `low` | High confidence requires exact artifact/version/source evidence. |
| `basis` | Dominant evidence family | Must name the strongest evidence class. |
| `score_details` | Component scores, counts, suppressors, and rationale | Must be sufficient for audit and triage. |

The current implementation already has `verdict`, `malware_authority`, `risk_score`, and `score_details`. The next model should add a separate `malware_score` while keeping `risk_score` as the operational score.

## Evidence Classes

| Class | Used for | Authority |
| --- | --- | --- |
| `confirmed` | Marketplace removed as malware, OSV `MAL-*`, trusted malware feed, known-bad hash | Can produce `malicious` and `authoritative`. |
| `observed` | Dynamic sandbox observed malicious chain: secret read + exfil, download + execute, persistence, destructive behavior | Can produce `suspicious`; `authoritative` only if tied to known-bad artifact or trusted feed. |
| `correlated` | Static same-path abuse chain | Can produce `suspicious`, not `malicious`. |
| `capability` | Sensitive extension capability: terminal/debug/task/webview/auth/agent/MCP/native/lifecycle | Produces `review` unless paired with abuse evidence. |
| `provenance` | Signature, source-to-VSIX match, attestations, repo mismatch, impossible publish metadata | Strong context; can become `suspicious` when artifact integrity fails. |
| `reputation` | Publisher age, verified publisher, installs, ratings, name similarity, publish freshness | Modifier only. Never blocks alone. |
| `weak` | Standalone network, env, file, process, minification, low popularity, old repo | Modifier only. Never blocks alone. |

## Verdict Gates

| Verdict | Required condition |
| --- | --- |
| `malicious` | At least one `confirmed` malware finding: known malware extension, OSV `MAL-*`, trusted feed, or hash/version match. |
| `suspicious` | High-confidence `observed` or `correlated` abuse chain without confirmed intelligence. |
| `review` | Sensitive capability, vulnerable dependency, provenance anomaly, install-time behavior, or medium dynamic behavior needing human context. |
| `clean` | No actionable confirmed, observed, correlated, capability, or provenance findings. Weak standalone indicators may still be reported with score 0. |

## Metric Families

### 1. Confirmed Intelligence

| Metric id | Extraction | Malware score | Risk score | FP controls |
| --- | --- | ---: | ---: | --- |
| `marketplace_removed_malware` | Extension id and version match Microsoft removed list with type `Malware` or trusted marketplace blocklist. | 100 | 100 | Store source URL, date, type, extension id, version if available. |
| `marketplace_removed_non_malware` | Removed as impersonation, suspicious, untrustworthy, policy, spam, or abuse. | 80-95 | 90-100 | Do not call malware unless source type says malware. Label as removed/high-risk. |
| `osv_malicious_dependency` | Runtime dependency exact package+version has OSV id beginning `MAL-`. | 95-100 | 95-100 | Require exact resolved dependency from lockfile or package metadata where possible. |
| `trusted_threat_feed_hit` | Socket, Phylum, vendor feed, or internal feed identifies artifact/package as malware. | 95-100 | 95-100 | Require feed name, timestamp, package id, version/hash, and reason. |
| `known_bad_hash` | VSIX/package file hash matches known-bad corpus. | 100 | 100 | Hash over canonical artifact; record algorithm and source. |

These are the only metrics allowed to set `verdict=malicious`.

### 2. Marketplace Integrity and Reputation

| Metric id | Extraction | Score behavior | FP controls |
| --- | --- | --- | --- |
| `publisher_verified` | Marketplace publisher verification. | Risk reducer, never proof of safety. | Treat as suppressor only for reputation, not code behavior. |
| `extension_unavailable` | Extension id no longer exists or version disappeared. | Review or suspicious if paired with fresh reports/removal. | Distinguish unpublished, renamed, and removed-for-abuse states. |
| `publisher_age_low` | Publisher created recently or first release recent. | Weak +2 to +8. | Never actionable alone; new projects are not suspicious by default. |
| `install_rating_anomaly` | Very low installs, sudden spike, low rating, review spam, rating/install mismatch. Implemented as `install-rating-mismatch`: high install count (>50k) paired with a low average rating (<2.5) across at least 5 ratings. | Weak +2 to +10 (reputation, score 10). | Use as context only; never actionable alone. |
| `name_impersonation` | Extension id, display name, icon, README, or publisher similar to high-install trusted extension. | Review; suspicious only with behavior or removal evidence. | Allow forks/localization; require similarity target and features. |
| `marketplace_signature_missing` | VSIX not signed where marketplace signing is expected. | Review/provenance risk. | Some ecosystems or sources may not sign; source must be known. |

### 3. Source and Artifact Provenance

| Metric id | Extraction | Score behavior | FP controls |
| --- | --- | --- | --- |
| `repo_url_mismatch` | `package.json` repository differs from marketplace metadata, npm metadata, or publisher website. | Review, higher if paired with impersonation. | Normalize GitHub/Git URLs; account for mirrors. |
| `source_vsix_diff_unexplained` | Build declared repo and compare expected files to VSIX artifact. | Review to suspicious depending on sensitive additions. | Ignore expected generated bundles when source map/build config matches. |
| `attestation_missing` | deps.dev/SLSA/provenance missing for packages that normally provide it. | Weak/context. | Absence is not abuse. |
| `attestation_violation` | Attestation says artifact was not built from declared source or builder. | Suspicious/provenance. | Require exact version/artifact and verifiable statement. |
| `binary_without_origin` | `.node`, `.dll`, `.so`, `.dylib`, `.exe`, archive, or bundled server lacks source, signature, checksum, or expected path. Implemented as `binary-without-origin`: fires when a native artifact from the artifact inventory has no companion `.sha256`/`.sig`/`.asc`/`.p7s` file and is not referenced by name in `SECURITY.md`/`README.md`. | Review (provenance, MEDIUM). | Language servers often ship binaries; reduce when signed and checksum-pinned. |
| `reproducible_hash_match` | Local built artifact matches published VSIX/package hash. | Risk reducer. | Reducer only; does not override confirmed malware. |

### 4. Install-Time Behavior

Install-time behavior is high value because it executes before users interact with extension UI.

| Metric id | Extraction | Score behavior | FP controls |
| --- | --- | --- | --- |
| `lifecycle_script_present` | `preinstall`, `install`, `postinstall`, `prepublish`, `vscode:prepublish`, `vscode:uninstall`. | Review. | Native packages and generated assets often need scripts. |
| `install_download_execute` | Lifecycle path downloads bytes and executes/spawns or writes executable. | Suspicious; high risk. | Reduce if vendor domain, TLS, pinned version, checksum, and signature validation exist. |
| `install_secret_access` | Lifecycle path reads env vars, `.npmrc`, SSH, cloud creds, git credentials, keychain, or token files. | Suspicious. | Package managers expose some env vars; require sensitive variable/file class. |
| `install_network_telemetry` | Lifecycle path sends host/user/package metadata to remote endpoint. | Review to suspicious depending on payload. | Expected telemetry must be declared and opt-out capable. |
| `install_shell_obfuscation` | Lifecycle command obfuscated, base64 shell, remote shell pipe, shortlink, or dynamic URL. | Suspicious when paired with network/exec. | Obfuscation alone is weak; generated code suppressors apply. |

### 5. Runtime IDE Capability Surface

These metrics answer: "What can this extension do if compromised or malicious?"

| Metric id | Extraction | Score behavior | FP controls |
| --- | --- | --- | --- |
| `broad_activation` | `activationEvents: ["*"]` or very broad startup triggers. | Capability/review. | Reduce if first-party and no risky code paths. |
| `startup_activation` | `onStartupFinished` or equivalent auto-run. | Capability/review. | Startup alone is common; pair with code behavior. |
| `terminal_task_debugger` | Contributions to terminal, task provider, debug adapter, shell integration. | Capability/review. | Developer tools often need these. |
| `uri_auth_webview` | `onUri`, auth provider, webview, custom editor, remote content. | Capability/review. | Review CSP, domain allowlists, token handling. |
| `webview_csp_missing` / `webview_csp_unsafe_directive` | A file that opens a webview (`createWebviewPanel`, `registerWebviewViewProvider`, or `.webview.html =`) is scanned for a `Content-Security-Policy` meta tag; missing entirely, or present with `unsafe-inline`/`unsafe-eval`/wildcard `script-src`. | Capability/review (MEDIUM). | Only fires when a webview surface is actually detected in the same file; strict CSPs with scoped `script-src`/`style-src` do not trigger. |
| `workspace_trust_bypass` | Runs sensitive behavior in untrusted workspaces or does not declare workspace trust limits. | Review/suspicious if paired with file or exec behavior. | Use VS Code workspace trust metadata when present. |
| `agentic_tooling` | `languageModelTools`, chat participants, MCP servers, autonomous command tools. | Capability/review, higher with shell/file/network tools. | Require tool schemas and approval mode evidence. |

### 6. Static Behavior Chains

Static chain rules are the main low-false-positive improvement over isolated regexes. A chain should be same-file, same function, same call graph path, or same lifecycle/runtime entrypoint where possible.

| Metric id | Required features | Score behavior | FP controls |
| --- | --- | --- | --- |
| `credential_exfiltration_chain` | Sensitive credential reference + file/env/keychain read + outbound write. | Suspicious, malware score 70-88. | Reduce only with documented user-triggered sync/export flow and expected domain. |
| `download_and_execute` | Network download + executable write/process spawn/dynamic import/eval. | Suspicious, malware score 65-85. | Reduce for pinned URL, checksum, signature, vendor domain, declared binary install. |
| `destructive_transfer_chain` | Destructive file operation + archive/encrypt/encode + outbound network. | Suspicious, malware score 70-85. | Backup/migration tools need explicit docs and user command trigger. |
| `obfuscation_execution_network` | Obfuscation/decode + eval/dynamic import/process + network. | Suspicious. | Ignore minified/generated/bundled files unless hidden executable logic exists. |
| `persistence_chain` | Writes shell profile, cron, service, startup folder, extension settings, or autorun + executes or phones home. | Suspicious. | Legit installers must be declared and reversible. |
| `supply_chain_dropper_chain` | Fetches package/archive from mutable URL + extracts/loads into extension runtime. | Review to suspicious. | Reduce with immutable version, checksum, signature, and trusted host. |
| `agent_data_exfil_chain` | Agent/MCP tool can read workspace/secrets + sends to external service without explicit user approval. | Suspicious. | Require tool-call evidence, approval mode, destination, and declared purpose. |

### 7. Dynamic Sandbox Behavior

Dynamic execution should be run in a disposable VM/container with no real secrets, fake credential canaries, controlled network, and filesystem tracing. For IDE extensions, run at least install, activation, representative command invocation, webview open, language server start, and uninstall.

| Metric id | Observation | Score behavior | FP controls |
| --- | --- | --- | --- |
| `observed_secret_read` | Reads canary `.env`, `.npmrc`, `.ssh`, cloud creds, git credentials, or keychain mock. | Review; suspicious with network. | Canary paths must not be referenced by test harness accidentally. |
| `observed_secret_exfil` | Reads canary secret then sends it over network or writes to external process. | Suspicious high; can be confirmed if matched known-bad artifact. | Capture destination, payload hash, process tree, and trigger path. |
| `observed_download_execute` | Downloads bytes then executes, loads, or marks executable. | Suspicious. | Reduce for signed/checksummed first-party language servers. |
| `observed_persistence` | Writes autorun locations or persistent shell/config hooks. | Suspicious. | Some installers add PATH or shell integration; require user-visible docs. |
| `observed_destructive_behavior` | Deletes/encrypts user files outside extension directory. | Suspicious high. | Use disposable canary files and require trace evidence. |
| `observed_unexpected_network` | Contacts domains not declared in package, docs, telemetry policy, or known vendor list. | Review to suspicious based on payload and trigger. | Maintain expected domain registry with evidence. |

Dynamic findings are stronger than static findings, but still should not become `malicious` unless backed by trusted intelligence, a known-bad hash, or an explicit malware verdict from a trusted source.

### 8. Dependency and SCA Metrics

| Metric id | Extraction | Score behavior | FP controls |
| --- | --- | --- | --- |
| `runtime_vulnerable_dependency_exact` | Lockfile or exact runtime dependency version matches OSV/GHSA. | Review/high risk depending severity. | Vulnerability existence is authoritative; exploitability in extension is not. |
| `runtime_vulnerable_dependency_range` | Manifest range can resolve to vulnerable version. | Review/lower confidence. | Prefer lockfile, installed node_modules, or marketplace package metadata. |
| `dev_dependency_vulnerable` | Dev-only dependency vulnerable. | Report in build posture, not runtime risk. | Current scanner correctly excludes devDeps from runtime dependency risk. |
| `malicious_dependency` | OSV `MAL-*` or feed-confirmed malicious runtime dependency. | Malicious if exact/resolved; review if unresolved range. | Require exact version for authoritative verdict. |
| `mutable_dependency_source` | Git, HTTP, tarball URL, unpinned branch, file/workspace dependency. | Review/weak. | Internal extensions may use workspaces; distinguish local scan vs marketplace artifact. |
| `dependency_delta_spike` | New release adds many deps or high-risk deps. | Review/context. | Compare to previous version; avoid penalizing first release heavily. |
| `bundled_dependency_hidden` | Bundled/minified dependency not declared in manifest/lockfile. | Review/provenance. | Bundles are common; require inventory and source map/build config. |

### 9. Repository and Maintainer Posture

These metrics should reduce or increase review priority, not decide malware.

| Metric id | Extraction | Score behavior | FP controls |
| --- | --- | --- | --- |
| `repo_maintained` | Recent commits/releases/issues response. | Reducer if healthy; weak risk if stale. | Stable extensions may be intentionally quiet. |
| `code_review_branch_protection` | OpenSSF Scorecard checks. | Posture score. | Small solo projects can be benign. |
| `dangerous_github_workflows` | Pull request target, untrusted checkout, broad tokens, script injection. | Review/supply-chain risk. | Needs repo access and workflow parsing. |
| `token_permissions_broad` | GitHub Actions token permissions too broad. Implemented as `workflow-token-permissions-broad`: fires when a workflow grants both `id-token: write` and `contents: write`, or uses `GITHUB_TOKEN` without an explicit `permissions:` block. | Posture risk (LOW, score up to 34). | Build-time risk, not runtime malware; distinct rule id from `dangerous-github-workflow` so the two triage separately. |
| `security_policy_missing` | No security policy, no vulnerability reporting. | Weak. | Not meaningful for tiny projects alone. |
| `license_missing` | No `LICENSE`/`LICENSE.md`/`LICENSE.txt` found in the packaged artifact. | Weak/reputation (score up to 6). | Not meaningful for tiny/internal projects alone; never actionable by itself. |
| `binary_artifacts_in_repo` | OpenSSF binary artifacts check or repo inventory. Implemented as `repo-binary-artifacts`, sourced from the artifact inventory's `native`-kind entries (was previously registered but never emitted — now wired up). | Review (posture, score up to 32). | Language servers and native extensions may need binaries. |

### 10. AI and Agent-Specific Metrics

AI coding extensions can bridge prompts, tools, terminals, source code, secrets, and network APIs. Their scoring needs a separate surface model.

| Metric id | Extraction | Score behavior | FP controls |
| --- | --- | --- | --- |
| `agent_shell_tool` | Tool schema can run shell/terminal/process commands. | Review/high capability. | Lower if always requires explicit approval and command preview. |
| `agent_filesystem_tool` | Tool schema can read/write broad workspace or home files. | Review. | Lower with workspace-only scope and user approval. |
| `agent_network_tool` | Tool can send arbitrary HTTP or connect to arbitrary hosts. | Review. | Lower with fixed domains and payload limits. |
| `agent_prompt_injection_sink` | Webview/README/remote content flows into tool instructions without sanitization. | Review/suspicious with tool execution. | Needs dataflow evidence. |
| `agent_auto_approve` | Extension or user posture allows autonomous command execution. | Risk multiplier. | Report environment/posture source. |
| `mcp_server_untrusted` | Extension registers MCP server from untrusted package/path. | Review. | Reduce if signed, pinned, and local-only. |

### 11. Environment and Posture Modifiers

The same extension has different risk in different environments.

| Modifier | Effect |
| --- | --- |
| Workspace Trust disabled or ignored | Increase runtime risk for file/process/network findings. |
| Agent command auto-approval enabled | Increase risk for agent shell/file/network tools. |
| Extensions auto-update enabled | Increase supply-chain risk from publisher compromise. |
| Trusted publisher policy enabled | Reduce reputation risk, not code behavior risk. |
| Corporate proxy/domain allowlist | Reduce unexpected network risk if destination is approved. |
| Sandbox install mode | Reduce blast radius; keep finding severity but lower deployment urgency. |

## Scoring Model

The scanner should calculate two independent 0-100 scores.

### Malware Score

Malware score estimates confidence that the extension or one of its runtime dependencies is malicious.

```text
malware_score = max(
  confirmed_intelligence_score,
  observed_malicious_behavior_score,
  correlated_static_chain_score + bounded_context_boost
)
```

Rules:

- `confirmed_intelligence_score` can reach 100.
- `observed_malicious_behavior_score` should usually max at 90 unless a known-bad artifact/source also matches.
- `correlated_static_chain_score` should usually max at 88.
- Weak/reputation/context signals can add at most 10 points and only when there is observed, correlated, capability, or provenance evidence.
- Standalone weak signals produce malware score 0.

Recommended bands:

| Malware score | Meaning |
| ---: | --- |
| 0 | No malware evidence. |
| 1-39 | Weak context only; no actionable malware suspicion. |
| 40-64 | Review: risky capability or provenance/dependency issue. |
| 65-89 | Suspicious: observed or correlated abuse path. |
| 90-100 | Confirmed or near-confirmed malicious artifact/dependency. |

### Operational Risk Score

Operational risk estimates the blast radius if the extension is malicious, compromised, or vulnerable.

```text
risk_score = clamp(
  capability_surface_score
  + install_time_score
  + dependency_score
  + provenance_score
  + observed_behavior_score
  + posture_modifiers
  - suppressors,
  0,
  100
)
```

Operational risk can be high even when malware score is low. For example, an official debugger with terminal, network, process, and filesystem access may deserve `risk_score=55` but `malware_score=0`.

### Suppressors

Suppressors reduce risk but must never hide evidence. Each suppressor should appear in `score_details.suppressors`.

| Suppressor | Applies to | Max reduction |
| --- | --- | ---: |
| Verified publisher | Reputation only | 5 |
| Signed VSIX or signed binary | Native/provenance risk | 8 |
| Checksum-pinned download | Download-exec/install risk | 12 |
| Expected vendor domain | Network/download/telemetry risk | 8 |
| Reproducible source-to-VSIX match | Provenance/bundle risk | 12 |
| User-triggered command path | Runtime behavior risk | 8 |
| Workspace-only scope | Agent/filesystem risk | 6 |
| Explicit approval required | Agent/shell/network risk | 10 |

Confirmed malware evidence should ignore suppressors for verdict purposes.

## Accuracy Strategy

To make the scanner reliable, metrics must be tested against a labeled corpus and measured by label, not by anecdote.

### Corpora

| Corpus | Examples | Purpose |
| --- | --- | --- |
| Known bad | Microsoft removed packages, OSV `MAL-*`, GuardDog samples, trusted malware feeds, known-bad hashes | Measure recall for confirmed threats. |
| Known safe | Microsoft, GitHub, Red Hat, Docker, HashiCorp, Python, ESLint, Prettier, official language extensions | Measure false positives on powerful but legitimate extensions. |
| Gray/moderate | Low-install extensions with sensitive capabilities, old dependencies, native binaries, lifecycle scripts | Tune `review` thresholds. |
| Synthetic fixtures | Purpose-built credential exfil, download-exec, benign language server, benign telemetry, benign native binary | Regression tests for every metric. |
| Time-series releases | Same extension across versions | Detect new suspicious deltas and dependency spikes. |

### Measurements

- Track precision and recall separately for `malicious`, `suspicious`, and `review`.
- Optimize `malicious` for very high precision. False positives here are product-breaking.
- Optimize `suspicious` for high precision with acceptable manual-review recall.
- Allow `review` to be broader, but keep reports clear so users understand it is not a malware claim.
- Maintain confusion matrices by metric family so noisy metrics can be demoted or converted to context.
- Require a regression fixture for every false positive fix.

### Calibration Workflow

1. Run all metrics on the known-safe corpus and record any `malicious` or `suspicious` label as a blocking bug.
2. Run known-bad corpus and record misses by evidence family.
3. Add suppressors only when they are backed by verifiable evidence.
4. Tune thresholds with versioned calibration files, not ad hoc constants hidden in rules.
5. Re-run benchmark before every release and publish aggregate precision/recall for trust.

## Implementation Roadmap

### Phase 1: Formalize current scoring

- Keep current evidence classes: `confirmed`, `correlated`, `capability`, `weak`.
- Add this document to the repo as the scoring contract.
- Add `malware_score` alongside current `risk_score`.
- Add `score_details.suppressors` and `score_details.metric_families`.
- Keep current rule that weak-only findings produce `clean` and score 0.

### Phase 2: Better registry and artifact intelligence

- Resolve exact runtime dependency versions from lockfiles and installed package metadata.
- Fetch marketplace metadata: publisher verification, install counts, rating, publish/update time, signature state.
- Cache Microsoft removed packages with type-specific interpretation.
- Add OSV querybatch for resolved runtime deps and distinguish vulnerability from malicious package.
- Add VSIX hash inventory and known-bad hash matching.

### Phase 3: Provenance and source comparison

- Download VSIX into quarantine, never install into the user's real IDE.
- Extract and inventory files, native binaries, minified bundles, scripts, and dependencies.
- Compare VSIX to declared source repo when reproducible build instructions exist.
- Verify signatures, checksums, attestations, and declared binary origins.

### Phase 4: Dynamic sandbox

- Run install, activation, command invocation, webview open, language server startup, and uninstall in a disposable sandbox.
- Instrument process tree, filesystem, environment reads, network destinations, DNS, and payload hashes.
- Seed fake credential canaries and detect exfiltration.
- Use dynamic observations to corroborate static chains.

### Phase 5: Benchmark and calibration

- Build known-safe, known-bad, gray, synthetic, and time-series corpora.
- Emit per-metric confusion matrices.
- Store thresholds in a calibration file.
- Require test fixtures for every metric and every false-positive suppressor.

## Mapping to Current Implementation

Current `ide-scanner` behavior already matches the most important safety rules:

- `known-bad-artifact`, `marketplace-removed-malware`, and `malicious-npm-dependency` are `confirmed`.
- non-malware `marketplace-removed-package` findings are `provenance`.
- `credential-exfiltration-chain`, `destructive-transfer-chain`, and `download-and-execute` are `correlated`.
- `agentic-tooling`, lifecycle scripts, native artifacts, broad/startup/sensitive activation, and powerful IDE contributions are `capability`.
- vulnerable runtime dependencies, mutable dependency sources, and unpinned dependencies are `dependency`.
- packed archive artifacts are `provenance`.
- marketplace found/not-found, verified publisher, install count, rating, and stale-update findings are `reputation`.
- verified publisher is emitted as a suppressor for reputation risk only.
- local folders and VSIX files produce artifact inventory with package hash, file counts, risky artifact hashes, and VSIX hash when applicable.
- known-bad SHA-256 feed matches produce `known-bad-artifact` confirmed evidence.
- install-time script chains produce `install-download-execute`, `install-secret-access`, `install-network-telemetry`, and `install-shell-obfuscation`.
- static behavior chains now include obfuscation+execution+network, persistence, and agent data exfiltration.
- dynamic sandbox observations can be imported as `observed-*` evidence from an external runner.
- repository posture and agent-specific tool surface metrics are implemented as review/context evidence.
- `repo-binary-artifacts` (posture) is now emitted from the artifact inventory's native-kind entries; it was previously registered in scoring/evidence-class sets but never produced a finding.
- `binary-without-origin` (provenance) fires for native artifacts lacking a companion checksum/signature file or documented origin in `SECURITY.md`/`README.md`.
- `install-rating-mismatch` (reputation) fires for high-install, low-rating marketplace metadata combinations, distinct from the existing flat low-install/low-rating thresholds.
- `webview-csp-missing` and `webview-csp-unsafe-directive` (capability) detect webview surfaces lacking a Content-Security-Policy or declaring an unsafe one.
- `license-missing` (reputation) flags packaged artifacts with no local LICENSE file; kept out of `posture` deliberately, since posture evidence is always verdict-actionable and license absence alone must not escalate a clean extension to `review`.
- `workflow-token-permissions-broad` (posture) flags GitHub Actions workflows with broad token scopes or an implicit default token, separate from `dangerous-github-workflow`.
- Standalone secret, network, filesystem, execution, dynamic code, and obfuscation indicators are `weak` unless they form a chain.
- `malicious` currently requires confirmed evidence.
- Correlated static abuse paths produce `suspicious` with `malware_authority=non_authoritative`.
- Capability findings produce `review`.
- Weak-only findings stay `clean` with score 0.

The main gap is that current `risk_score` is doing double duty. The next version should report:

```json
{
  "malware_score": 0,
  "risk_score": 0,
  "score_details": {
    "basis": "none",
    "confidence": "high",
    "components": {
      "confirmed_intelligence": 0,
      "observed_behavior": 0,
      "correlated_behavior": 0,
      "sensitive_capability": 0,
      "provenance": 0,
      "dependency": 0,
      "reputation": 0,
      "weak_context": 0
    },
    "suppressors": [],
    "counts": {
      "confirmed": 0,
      "observed": 0,
      "correlated": 0,
      "capability": 0,
      "provenance": 0,
      "reputation": 0,
      "weak": 0
    }
  }
}
```

## Metric Acceptance Checklist

Before adding a metric to the scanner:

1. Define whether it affects malware score, risk score, or only context.
2. Define the evidence class.
3. Define exact extracted features and required files/API sources.
4. Define suppressors and their maximum reduction.
5. Add at least one malicious/suspicious fixture and one benign fixture.
6. Run against known-safe real extensions and confirm it does not create a false `malicious` label.
7. Add an explanation string that a user can understand without reading code.

## Source Links

- Socket.dev alert types: https://docs.socket.dev/docs/alert-types
- Socket.dev package scores: https://docs.socket.dev/docs/package-scores
- Socket.dev malware alert: https://socket.dev/alerts/malware
- OpenSSF Scorecard checks: https://github.com/ossf/scorecard/blob/main/docs/checks.md
- OSV documentation: https://google.github.io/osv.dev/
- OSV-Scanner documentation: https://google.github.io/osv-scanner/
- deps.dev API: https://docs.deps.dev/api/v3/
- GuardDog: https://github.com/DataDog/guarddog
- OpenSSF package-analysis: https://github.com/ossf/package-analysis
- Microsoft VS Marketplace removed packages: https://github.com/microsoft/vsmarketplace/blob/main/RemovedPackages.md
- VS Code extension runtime security: https://code.visualstudio.com/docs/configure/extensions/extension-runtime-security
