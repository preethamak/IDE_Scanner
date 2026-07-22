# Classification calibration — 30 exact website artifacts

## Objective

Calibrate actionable evidence separately from expected capability power, while
preserving exact artifact identity and historical reports. CLI and website Deep
Scan must render the same canonical result.

Provisional distribution hypothesis:

| Decision | Severity | Target |
|---|---|---:|
| Allow | Informational | 12 |
| Allow | Low | 7 |
| Review | Low | 5 |
| Review | Medium | 5 |
| Block | High | 1 |

The target is not a quota. Evidence-supported deviations must be recorded rather
than forced.

## Frozen baseline

- Corpus manifest: `benchmarks/website-corpus/v1/manifest.json`
- Normalized benchmark result: `benchmarks/website-corpus/v1/results.json`
- Canonical raw result: `../ide-scanner-benchmark-store/website-v1/results-final/static-scan.json`
- Canonical security-field digest: `cff4799b2104f09b890933d6351942f007dfde22ac6489664632619b78bf15d7`
- Artifacts: 30 exact VSIX files, with identity hashes recorded in the manifest
- Coverage: 30/30 complete
- Baseline distribution: 4 Allow/Informational, 25 Review/Medium, 1 Review/High
- Malware score: 0 for all 30 baseline artifacts

## Iterations

| Iteration | Scanner build | Ruleset | Policy | Distribution | Notes |
|---|---|---|---|---|---|
| 0 | `d1b0b47` | pre-v3 | legacy | 4 A/I, 25 R/M, 1 R/H | Frozen development baseline; capability and actionable severity are conflated. |
| 1-replay | local | `2026.07.22-policy-v3-calibration.1` | `3.0.0-calibration.1` | 9 A/I, 16 A/L, 5 R/L | Deterministic replay of the 30 complete baseline finding sets. No advisory snapshot applied. |
| 1-clean | local container | `2026.07.22-policy-v3-calibration.1` | `3.0.0-calibration.1` | 8 A/I, 11 A/L, 1 R/L, 10 incomplete | Fresh isolated scan. Ten large artifacts exceeded the JavaScript AST provider's fixed eight-second per-file timeout; this is a coverage defect, not a classification result. |
| 2-selected | local container | `2026.07.22-policy-v3-calibration.1` | `3.0.0-calibration.1` | 1 A/I, 6 A/L, 4 R/L, 1 B/H | Reran the ten prior AST failures plus Code Runner with the corrected AST resource boundary. All 11 completed; Code Runner matched the exact hash-pinned advisory snapshot with malware score zero. |
| 2-full | local container | `2026.07.22-policy-v3-calibration.1` | `3.0.0-calibration.1` | 8 A/I, 16 A/L, 5 R/L, 1 B/H | All 30 completed. Review/Low is entirely the general unattributed-binary provenance gate. No Review/Medium result was supported. |
| 3-full-rejected | local container | `2026.07.22-policy-v3-calibration.3` | `3.0.0-calibration.3` | 14 A/I, 9 A/L, 3 R/L, 4 B/H | Rejected. File-local proximity inside generated bundles falsely blocked Continue, Copilot, and Copilot Chat. Paired benign/malicious controls replaced this with same-variable/high-specificity generated-flow handling. |
| 4-classification | image `7e8d058cdb4a…` | `2026.07.22-policy-v3-calibration.5` | `3.0.0-calibration.3` | 15 A/I, 10 A/L, 4 R/L, 1 B/H | Accepted classification semantics. All 30 completed. The three generated-bundle false blocks disappeared while the direct malicious-flow control and exact Code Runner advisory still fired. Superseded for publication only because raw JSON did not yet embed the image identity. |
| 5-final | image `2356416992f9…` | `2026.07.22-policy-v3-calibration.5` | `3.0.0-calibration.3` | 15 A/I, 10 A/L, 4 R/L, 1 B/H | Accepted. Two independent, network-disabled runs completed all 30 artifacts and produced the same normalized security-field digest. Raw reports embed the immutable image identity and advisory snapshot `2026-07-22.2`. |

Final reproducibility digest:
`aada621572d2502063cb7a5973f9cfe3c5de701eb3192cc322e67124b241d248`.
The normalization includes artifact identity, coverage, capabilities, findings,
scores, status, severity, decision, scanner build, ruleset, policy, and
intelligence snapshot; it excludes only scan IDs and timestamps.

The final distribution deliberately differs from the provisional hypothesis.
No `Review/Medium` label survived source-level adjudication, and one native
artifact set had sufficient package origin. Forcing the requested counts would
have introduced unsupported review decisions.

Coverage follow-up: the largest failing entrypoint (`Continue.continue`, about
56 MiB) was measured independently. It exhausted Node's default heap, but
completed in 55 seconds with a fixed 2 GiB old-space limit. Iteration 2 therefore
uses a documented 90-second per-file timeout, 2 GiB Node old-space boundary, and
3 GiB isolated-runner memory limit.

Iteration 1 confirms that the five `Review/Low` rows arise from the general
`binary-without-origin` provenance gate. It does **not** support five
`Review/Medium` rows: the proposed candidates currently contain capability or
weak proximity evidence, not a demonstrated trust-boundary violation. Those
labels remain unaccepted pending source-level evidence.

Source-level adjudication rejected all five provisional `Review/Medium`
labels. Git Graph's credential prompt is its bounded Git askpass flow; Copilot
Chat's prompt-injection finding is a manifest-declared tool capability; Cline's
credential-file-read hit is a read of `.vscodeignore`; Roo's SSH-key hit is a
weak string reference without a sink; and Trivy's credential-configuration hit
crossed unrelated expressions in a 621 KiB one-line generated bundle. None
establishes an untrusted source reaching a sensitive sink. The Trivy case led
to a general minified-bundle threshold regression, not an artifact exception.

## Artifact adjudication ledger

`Final` records the evidence-supported calibration result. It is documentation,
not a scanner fixture or extension-specific exception.

| Exact artifact | Baseline | Final | Adjudication basis |
|---|---|---|---|
| `PKief.material-icon-theme@5.36.1` | Allow/Info | Allow/Info | Theme capabilities are contextual; no actionable evidence. |
| `esbenp.prettier-vscode@12.4.0` | Allow/Info | Allow/Info | No actionable evidence. |
| `usernamehw.errorlens@3.28.0` | Allow/Info | Allow/Info | No actionable evidence. |
| `dbaeumer.vscode-eslint@3.0.33` | Review/Medium | Allow/Info | Process and lifecycle behavior is expected capability context. |
| `ms-python.python@2026.5.2026070801` | Review/Medium | Allow/Info | Agent and process observations are capability context. |
| `golang.go@0.56.0` | Review/Medium | Allow/Low | Mutable dependency source remains a concrete low supply-chain note. |
| `redhat.java@1.56.2026071508` | Review/Medium | Allow/Info | Shell/process observations lack an untrusted source-to-sink flow. |
| `rust-lang.rust-analyzer@0.4.2976` | Review/Medium | Allow/Info | Configured tool execution is capability context. |
| `ms-vscode-remote.remote-ssh@0.125.2026062315` | Review/Medium | Allow/Info | SSH and lifecycle behavior is expected; no abuse path was established. |
| `ms-azuretools.vscode-docker@2.0.0` | Allow/Info | Allow/Info | Declarative extension-pack metadata has no actionable evidence. |
| `ms-vscode.azure-account@0.13.0` | Review/Medium | Allow/Info | Authentication command surfaces are capability context. |
| `SonarSource.sonarlint-vscode@5.5.0` | Review/Medium | Allow/Info | Packed tooling presence is capability context without an origin discrepancy. |
| `eamodio.gitlens@2026.7.160544` | Review/Medium | Allow/Low | Mutable dependency sources remain a concrete low supply-chain note. |
| `ritwickdey.LiveServer@5.7.10` | Review/Medium | Allow/Low | Package-attributable native code is contextual; mutable dependency and repository-binary posture remain low. |
| `humao.rest-client@0.25.1` | Review/Medium | Allow/Low | Credential UI and network use is expected; an unsafe webview CSP directive remains low. |
| `ms-vscode-remote.remote-containers@0.467.0` | Review/Medium | Allow/Low | Mutable dependency sources remain low; lifecycle and credential surfaces lack an unsafe flow. |
| `ms-kubernetes-tools.vscode-kubernetes-tools@1.4.0` | Review/Medium | Allow/Low | Dangerous workflow triggers and broad token permissions are low repository hardening notes. |
| `amazonwebservices.aws-toolkit-vscode@4.10.0` | Review/Medium | Allow/Low | Credential use is expected; mutable dependency sources remain low. |
| `GitHub.vscode-pull-request-github@0.159.2026071604` | Review/Medium | Allow/Info | Agent surfaces are expected and generated-bundle CSP text has no actionable path. |
| `ms-vscode.cpptools@1.33.4` | Review/Medium | Review/Low | Unattributed native artifacts require provenance review. |
| `GitHub.copilot@1.388.0` | Review/Medium | Review/Low | Unattributed native artifacts require provenance review. |
| `Continue.continue@2.1.0` | Review/Medium | Review/Low | Unattributed native artifacts require provenance review. |
| `Semgrep.semgrep@1.17.0` | Review/Medium | Review/Low | Unattributed native artifacts require provenance review. |
| `snyk-security.snyk-vulnerability-scanner@2.31.0` | Review/Medium | Allow/Low | Missing webview CSP remains a low hardening note; credential command surfaces are contextual. |
| `mhutchie.git-graph@1.30.0` | Review/Medium | Allow/Low | Git askpass is bounded and expected; the unsafe CSP directive remains a low hardening note. |
| `GitHub.copilot-chat@0.48.1` | Review/Medium | Allow/Info | Manifest-declared agent tooling is capability context; no unsafe prompt-to-tool flow was established. |
| `saoudrizwan.claude-dev@4.0.8` | Review/Medium | Allow/Info | The credential-file hit was `.vscodeignore`; no sensitive source-to-sink flow was established. |
| `RooVeterinaryInc.roo-cline@3.54.0` | Review/Medium | Allow/Low | SSH-key text was weak context; mutable dependency sources remain a low note. |
| `AquaSecurityOfficial.trivy-vulnerability-scanner@1.8.11` | Review/High | Allow/Info | The credential update crossed neighboring minified calls; balanced-call parsing removed it. |
| `formulahendry.code-runner@0.12.2` | Review/Medium | Block/High | Exact affected version and artifact hash match the versioned authoritative advisory snapshot. |

## Required gates

- No extension-ID or artifact-hash verdict branches in scanner logic.
- Every classification change cites a general rule and source-level evidence.
- Exact advisories enter through versioned intelligence data, not source-code
  conditionals.
- Existing reports are never overwritten.
- CLI/service parity covers decision, severity, findings, scores, status,
  artifact hash, scanner build, ruleset, and policy version.
- A fresh untuned corpus is required before accuracy or recall claims.
