# IDE Scanner precision audit — 2026-07-16

## Executive result

The scanner's native static rules and verdict policy were audited for false-positive and false-negative failure modes, corrected in five checkpoint commits, and validated against the local installed-extension cohort and the labeled fixture benchmark.

Final installed cohort:

| Result | Instances | Unique extension IDs |
|---|---:|---:|
| Clean | 59 | 42 |
| Review | 92 | 49 |
| Suspicious | 0 | 0 |
| Malicious | 0 | 0 |
| Total | 151 | 90 |

One extension ID can appear in both clean and review counts when different installed versions receive different verdicts. The cohort contains multiple versions and installations across VS Code-compatible clients.

The result does **not** prove that every installed extension is benign. It means this scan found no evidence meeting the scanner's corrected threshold for suspicious behavior or authoritative malware. Eight instances had incomplete executable coverage and therefore received an `incomplete` policy decision even when their static verdict was clean or review.

## What changed

The audit corrected these root causes:

1. Ambiguous execution matching
   - Bare `exec()` matched `RegExp.prototype.exec()` and unrelated application methods.
   - Process capability now requires an identifiable process API.
   - Shell execution now requires explicit shell configuration or a direct `child_process.exec*` call.

2. File-wide and minified-bundle co-occurrence
   - Proximity is measured in character offsets, not source-line numbers.
   - Credential input/state and clipboard rules require bounded local evidence.
   - Features merely appearing in the same bundled file no longer imply a behavior path.

3. Proximity mislabeled as data flow
   - Native credential source/sink proximity now produces review-only exposure findings such as `credential-source-near-network`.
   - The verdict-driving `credential-dataflow-to-network` identifier is reserved for a provider that establishes a source-to-sink flow.
   - Agent surface + environment reference + networking proximity is now review context, not an exfiltration claim.

4. Weak destructive and obfuscation indicators
   - Ordinary `unlinkSync`/`rmdirSync` cleanup is no longer called destructive activity.
   - Native decoded-execution detection requires a direct decode-to-execution shape.
   - Base64 use, networking, and regex `.exec()` near one another no longer form an obfuscation/execution chain.
   - Marker-only YARA evidence is contextual; it cannot independently produce a suspicious verdict.

5. Review inflation
   - Generic computed dispatch (`obj[key]()`), startup activation, standard activation events, and standard IDE contributions are contextual.
   - They remain visible in findings but do not independently force review.

6. False-negative coverage
   - A new manifest-aware rule detects a declared workspace setting used as an `execFile` executable when the setting is not restricted in untrusted workspaces.
   - The equivalent extension with `capabilities.untrustedWorkspaces.restrictedConfigurations` remains clean.

7. Preventive decision policy
   - Confirmed intelligence still produces `malicious / block`.
   - High-confidence behavioral abuse chains now produce a preventive `block` while retaining the honest, non-authoritative `suspicious` verdict.
   - Generic `download-and-execute` remains `review` by itself because legitimate language servers and tool installers can share that shape.
   - It becomes a preventive block only when the same extension also has automatic activation and credential-handling evidence.

8. Common process-alias evasions
   - Destructured CommonJS aliases such as `const {execFile: run} = require('child_process')` are resolved.
   - ESM aliases such as `import {spawn as run} from 'child_process'` are resolved.
   - A malformed `fetch(...)` download regex boundary was corrected.
   - Regression tests retain the earlier false-positive guard: ordinary `RegExp.exec()` is not process execution.

## Residual suspicious-case triage

Before the final correction, six installed instances remained suspicious. Direct source inspection showed that all six were false-suspicious classifications:

| Extension | Original trigger | Source-level interpretation | Final verdict |
|---|---|---|---|
| `qwtel.sqlite-viewer` | Credential source near network/file sinks | User-entered license/access token used by documented activation flows | Review |
| `selfagency.opilot` 1.8.3 and 1.8.4 | Credential source near network sink | User-entered Ollama authentication token used for authenticated API requests | Review |
| `nrwl.angular-console` | Agent/data-exfil and obfuscation chains | Bundled dotenv loading, Nx/MCP settings, provenance networking, and unrelated execution helpers | Review |
| `ms-python.python` 2025.6.1 | Destructive-transfer chain | Language-server cancellation-file cleanup using ordinary deletion APIs | Review |
| `James-Yu.latex-workshop` 10.13.1 | Obfuscation/execution/network chain | Base64 URL decoding, local config fetch, and keyboard regex `.exec()` | Review |

These extensions retain review findings where the behavior is security-relevant, but their malware score is now zero and the report no longer alleges an abuse chain that static evidence did not establish.

## Why review remains common

The final cohort contains 92 review instances. Review is not a malware label. The most common actionable review reasons, counted once per extension instance, are:

| Rule | Review instances |
|---|---:|
| Lifecycle script | 33 |
| Native binary without documented origin | 32 |
| Native or packed artifact | 32 |
| Repository binary artifact | 32 |
| Credential-like input prompt | 27 |
| Webview CSP unsafe directive | 25 |
| Webview CSP missing | 20 |
| Agent-facing tooling | 17 |
| Mutable dependency source | 12 |
| Packed artifact | 11 |

These categories are intentionally review-worthy: they identify executable supply-chain surfaces, concrete webview hardening gaps, credential handling, or agent tool boundaries. They do not increase malware score without stronger evidence.

## Exported rule catalog

The audit also found that 26 native rules could emit findings without appearing in the exported `rules.json` catalog. The catalog now includes all literal native `_finding()` rules, and a regression test compares scanner emissions with registered metadata. The exported catalog contains 73 documented rules after this correction.

## Validation

- Unit/integration suite: **93/93 passing**.
- Labeled fixture benchmark: **8/8 correct**.
- Fixture benchmark false positives: **0**.
- Fixture benchmark false negatives: **0**.
- Fixture benchmark malicious recall: **100%**.
- Focused residual rescan: all six prior false-suspicious instances became review with malware score 0.
- Final installed scan: 151 instances, no suspicious or malicious verdicts.

The fixture benchmark is small and partially synthetic. Its perfect result is regression evidence, not a general estimate of scanner accuracy on the ecosystem.

## Hash-pinned malicious VSIX adversarial check

An exact externally labeled malicious artifact, `bingcha.bcai-tools@4.0.37`, was acquired by its pre-recorded SHA-256 (`b1b9785cdc7be479061f121f282391fba9be013d896d9a54f395621634709216`) and scanned without installation or execution. Acquisition used a disposable container. Static scanning used a separate network-disabled, read-only, capability-dropped container running as UID 65534.

| Scanner state | Verdict | Decision | Malware score | Risk score |
|---|---|---|---:|---:|
| Before preventive-policy correction | Suspicious | Review | 82 | 87 |
| After correction | Suspicious | Block | 82 | 87 |

The scanner identified a high-severity `download-and-execute` chain plus automatic activation and credential-handling evidence. The verdict intentionally remains `suspicious`, not `malicious`, because static behavior does not establish identity or intent with authoritative certainty. The `block` is a preventive execution policy.

Three retained non-malicious control artifacts were rescanned in the same sandbox after the correction:

| Artifact | Verdict | Decision | Malware score | Risk score |
|---|---|---|---:|---:|
| `redhat.vscode-yaml@1.24.0` | Clean | Allow | 0 | 0 |
| `streetsidesoftware.code-spell-checker@4.5.6` | Review | Review | 0 | 51 |
| `rust-lang.rust-analyzer@0.3.2971` | Review | Review | 0 | 41 |

This is an adversarial regression check, not a publishable accuracy estimate: the malicious sample informed the policy correction and is therefore development data, not a holdout. The three controls are useful false-positive sentinels but are not a representative benign population. A fresh, frozen, independently labeled holdout is still required before publishing ecosystem recall or false-positive rates.

## Coverage and limitations

- This cohort run used the required native static and JavaScript AST engines.
- Optional Semgrep and YARA providers were unavailable in the execution environment.
- Online marketplace and dependency-intelligence checks were not enabled.
- No runtime sandbox observations were supplied.
- Eight instances were incomplete because one or more executable files exceeded the 10 MiB analysis limit:
  - `tamasfe.even-better-toml` 0.21.2
  - `GitHub.copilot-chat` 0.48.1
  - `figma.figma-vscode-extension` 0.4.5
  - `sourcegraph.cody-ai` 1.153.0 and 1.155.0 (multiple installations)
  - `google.geminicodeassist` 2.82.0 and 2.86.0
- Static analysis cannot determine malicious intent. A clean verdict means no actionable evidence was found within completed coverage, not a guarantee of safety.
- The installed cohort is a convenience sample from one workstation and is not representative prevalence data.

## Reproduction

```bash
PYTHONPATH=src .venv/bin/python -m unittest discover -s tests
PYTHONPATH=src .venv/bin/python -m ide_scanner benchmark --out /tmp/ide-scanner-benchmark.json
PYTHONPATH=src .venv/bin/python -m ide_scanner scan --all --format json --out reports/installed-audit.json
```

## Audit commits

- `5d7da19` — reduce review noise from ambiguous execution signals
- `c1fefd2` — require local evidence for credential control chains
- `8b8a83f` — calibrate static-provider evidence for verdicts
- `4d08a18` — separate proximity exposure from proven abuse flow; add workspace CLI-path coverage
- `d1a2f4d` — keep standard activation capabilities contextual
- Rule-catalog completeness fix — committed with this audit report

The earlier verdict-level bundle fixes are in `9f3096f`.
