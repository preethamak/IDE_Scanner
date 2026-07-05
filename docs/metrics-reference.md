# Metrics Reference

This document explains how `ide-scanner` metrics should be interpreted by users, product surfaces, and future scanner implementations.

## Can These Metrics Detect Malware?

Yes, but only with the right claim boundary.

`ide-scanner` should classify **confirmed malware** only when it has confirmed intelligence or artifact-level proof. Static code patterns can identify suspicious behavior and security flaws, but they must not be marketed as authoritative malware proof by themselves.

The scanner should answer four different questions:

| Question | Output | Required evidence |
| --- | --- | --- |
| Is this known malware? | `verdict=malicious` | Confirmed source, known-bad hash, marketplace malware removal, OSV `MAL-*`, trusted feed. |
| Does this behave like malware? | `verdict=suspicious` | Dynamic observation or static behavior chain such as credential read + exfiltration. |
| Does this create security risk? | `verdict=review` | Sensitive IDE capability, vulnerable dependency, lifecycle script, native binary, provenance gap. |
| Is there no actionable evidence? | `verdict=clean` | No confirmed, observed, correlated, capability, or provenance finding. |

## Enough or Not Enough?

The metrics are enough for a strong first version if the product is honest about verdicts:

- Good enough now: classify installed/local extensions into `clean`, `review`, `suspicious`, and `malicious`.
- Good enough now: identify risky capabilities, static abuse chains, known removed extensions, and vulnerable or malicious runtime dependencies.
- Not enough yet: guarantee every malicious extension is found.
- Not enough yet: guarantee zero false positives for `review` or `suspicious`.
- Not enough yet: call static heuristic hits authoritative malware.

The right goal is **near-zero false positives for `malicious`**, not zero findings overall. `review` and `suspicious` are intentionally triage labels.

## Verdicts

### `clean`

No actionable malware, abuse-chain, capability, dependency, or provenance evidence was found.

Weak standalone findings can still be shown, but they should not raise the score. Example: one `process.env.API_TOKEN` reference without file read or network exfiltration.

### `review`

The extension has sensitive capability or supply-chain risk that needs context. This is not a malware accusation.

Examples:

- broad startup activation
- lifecycle install script
- native binary
- debugger/task/terminal contribution
- agentic tool or MCP server
- vulnerable runtime dependency
- unsigned or unexplained binary artifact

### `suspicious`

The scanner found a realistic abuse path, but not confirmed malware intelligence.

Examples:

- credential reference + local file read + outbound network write
- download + execute
- obfuscation + dynamic execution + network
- destructive file operation + archive/encrypt + network
- sandbox-observed secret read followed by external network transfer

### `malicious`

The scanner matched confirmed intelligence or artifact-level proof.

Allowed evidence:

- Microsoft/marketplace removed as malware
- OSV `MAL-*` malicious package
- trusted malware feed match
- known-bad VSIX/package hash
- exact artifact/version from internal confirmed corpus

Static behavior alone should not produce `malicious`.

## Scores

### Malware Score

`malware_score` should represent confidence that the artifact is malicious.

| Score | Meaning |
| ---: | --- |
| 0 | No malware evidence. |
| 1-39 | Weak context only. |
| 40-64 | Review-grade risk. |
| 65-89 | Suspicious abuse path. |
| 90-100 | Confirmed or near-confirmed malicious artifact. |

Recommended rule: `malware_score >= 90` should require confirmed intelligence, known-bad hash, or strong dynamic evidence plus corroboration.

### Risk Score

`risk_score` should represent blast radius if the extension is malicious, compromised, or vulnerable.

A legitimate extension can have:

```json
{
  "verdict": "review",
  "malware_score": 0,
  "risk_score": 55
}
```

That means it is powerful, not necessarily malicious.

## Evidence Classes

| Evidence class | Meaning | Can mark malicious? |
| --- | --- | --- |
| `confirmed` | Trusted malware/removal/feed/hash evidence. | Yes. |
| `observed` | Dynamic sandbox observed an abuse chain. | No, unless corroborated by confirmed evidence. |
| `correlated` | Static same-path abuse chain. | No. |
| `capability` | Sensitive IDE/runtime capability. | No. |
| `provenance` | Artifact/source/signature/integrity evidence. | No, unless tied to known-bad artifact. |
| `reputation` | Publisher/install/age/name-similarity context. | No. |
| `weak` | Standalone code or metadata indicator. | No. |

## Metric Groups

### Confirmed Intelligence

Purpose: identify known bad extensions and known malicious dependencies.

Metrics:

- `marketplace_removed_malware`
- `marketplace_removed_non_malware`
- `osv_malicious_dependency`
- `trusted_threat_feed_hit`
- `known_bad_hash`

Product behavior:

- Can produce `malicious` when the evidence says malware.
- Non-malware removal types should be high risk, but the report should preserve the exact removal type.

### Static Behavior Chains

Purpose: detect code paths that look like real abuse.

Metrics:

- `credential_exfiltration_chain`
- `download_and_execute`
- `destructive_transfer_chain`
- `obfuscation_execution_network`
- `persistence_chain`
- `supply_chain_dropper_chain`
- `agent_data_exfil_chain`

Product behavior:

- Produces `suspicious`.
- Should show file refs, functions or entrypoints, source/sink, and network destination if known.
- Should not produce `malicious` without confirmed intelligence.

### Sensitive IDE Capabilities

Purpose: identify extensions with high blast radius.

Metrics:

- `broad_activation`
- `startup_activation`
- `terminal_task_debugger`
- `uri_auth_webview`
- `workspace_trust_bypass`
- `agentic_tooling`

Product behavior:

- Produces `review`.
- Score increases when paired with network, file, shell, credential, or agent automation evidence.

### Install-Time Behavior

Purpose: catch risky behavior that runs before normal user interaction.

Metrics:

- `lifecycle_script_present`
- `install_download_execute`
- `install_secret_access`
- `install_network_telemetry`
- `install_shell_obfuscation`

Product behavior:

- Lifecycle script alone is `review`.
- Install-time download-exec or secret access is `suspicious`.

### Dependency and Vulnerability Metrics

Purpose: identify vulnerable or malicious runtime dependencies.

Metrics:

- `runtime_vulnerable_dependency_exact`
- `runtime_vulnerable_dependency_range`
- `dev_dependency_vulnerable`
- `malicious_dependency`
- `mutable_dependency_source`
- `dependency_delta_spike`
- `bundled_dependency_hidden`

Product behavior:

- Exact runtime vulnerabilities are stronger than range-derived ones.
- Dev dependency vulnerabilities should not affect runtime malware verdict.
- Malicious runtime dependency can produce `malicious` only when exact/resolved.

### Provenance and Artifact Integrity

Purpose: detect mismatch between claimed source and shipped artifact.

Metrics:

- `repo_url_mismatch`
- `source_vsix_diff_unexplained`
- `attestation_missing`
- `attestation_violation`
- `binary_without_origin`
- `reproducible_hash_match`

Product behavior:

- Most provenance issues are `review`.
- Attestation violation or unexplained sensitive artifact additions can become `suspicious`.

### Dynamic Sandbox Metrics

Purpose: observe what the extension actually does in a safe environment.

Metrics:

- `observed_secret_read`
- `observed_secret_exfil`
- `observed_download_execute`
- `observed_persistence`
- `observed_destructive_behavior`
- `observed_unexpected_network`

Product behavior:

- Dynamic findings are stronger than static findings.
- Dynamic malicious behavior should usually be `suspicious`.
- It becomes `malicious` only with confirmed intelligence, known-bad hash, or trusted analyst verdict.

### Reputation and Posture

Purpose: prioritize review and reduce noise.

Metrics:

- verified publisher
- publisher age
- install/rating anomaly
- name impersonation
- maintained repo
- branch protection
- dangerous workflows
- broad CI token permissions
- security policy

Product behavior:

- Reputation and posture are modifiers.
- They should never mark malware alone.
- Marketplace reputation-only findings should not move an otherwise clean extension to `review`.
- Verified publisher is a suppressor for reputation risk only; it does not hide confirmed malware or abuse-chain evidence.

## Suppressors

Suppressors reduce risk but must remain visible in the report.

| Suppressor | Reduces |
| --- | --- |
| Verified publisher | Reputation risk. |
| Signed VSIX or binary | Artifact/native-code risk. |
| Checksum-pinned download | Download-exec risk. |
| Expected vendor domain | Network/telemetry risk. |
| Reproducible source-to-VSIX match | Provenance risk. |
| User-triggered command path | Runtime behavior risk. |
| Workspace-only scope | Filesystem/agent risk. |
| Explicit approval required | Agent shell/network risk. |

Suppressors must not override confirmed malware.

## Current Implementation Coverage

Implemented now:

- local manifest scan
- local static code scan
- install-time chain detection for download-execute, secret access, telemetry, and obfuscated shell behavior
- static behavior-chain detection for obfuscation+execution+network, persistence, and agent data exfiltration
- local artifact inventory with package hash, file count, byte count, and risky artifact hashes
- VSIX quarantine extraction and scanning without installing the extension
- VSIX artifact hash capture and known-bad VSIX hash matching
- skipped vendored/generated/minified paths for lower noise
- runtime dependencies only, not dev dependencies
- exact local dependency resolution from `package-lock.json`
- exact direct dependency resolution from installed `node_modules/*/package.json` when no lockfile exists
- mutable dependency source detection for Git, URL, file, link, and workspace dependency specs
- unpinned runtime dependency detection for `latest`, `*`, and `x` specs
- native binary and packed archive artifact findings
- repository/maintainer posture findings for missing repository metadata, missing security policy, and dangerous GitHub workflows
- agent-specific tool surface findings for shell, filesystem, network, MCP server, and prompt-injection sink risk
- dynamic sandbox observation import through `--sandbox-observations` or `IDE_SCANNER_SANDBOX_OBSERVATIONS_FILE`
- known-bad SHA-256 hash feed matching through `--known-bad-hashes` or `IDE_SCANNER_KNOWN_BAD_HASHES_FILE`
- Microsoft removed package check when online mode is enabled
- marketplace removal type splitting, so `Malware`, `Suspicious`, and non-malware removals are not treated the same
- marketplace metadata scoring when online mode is enabled: found/not found, verified publisher, install count, rating, and stale update context
- verified publisher suppressor in `score_details.suppressors`
- OSV dependency check when online mode is enabled
- report-level environment posture checks for Workspace Trust, automatic tasks, agent auto-approval, terminal auto-approval, and extension trust overrides
- evidence classes: `confirmed`, `observed`, `correlated`, `capability`, `dependency`, `posture`, `provenance`, `reputation`, `weak`
- separate `malware_score` and `risk_score`
- current `score_details`
- `malware_authority`

Not implemented yet:

- verified publisher/signature scoring
- source-to-VSIX provenance comparison
- calibration benchmark corpus
- full dynamic sandbox runner execution

## Recommended Next Build Order

1. Add marketplace signature state and VSIX signature verification.
2. Add source-to-VSIX provenance comparison.
3. Add dynamic sandbox runner with fake credential canaries.
4. Build benchmark corpora and publish precision/recall for each verdict.

## User-Facing Explanation Template

Use this shape in reports:

```text
Verdict: suspicious
Malware authority: non_authoritative
Malware score: 82
Risk score: 74
Reason: Static analysis found a credential exfiltration chain.
Evidence: extension.js references SSH keys, reads local files, and writes to an outbound network request.
Why this is not called malicious: no confirmed malware feed, known-bad hash, or marketplace malware removal matched this artifact.
Next action: install only in a sandbox or block until manually reviewed.
```

This keeps the product trustworthy because the explanation matches the evidence strength.
