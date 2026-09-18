# Real-artifact calibration snapshot — 2026-09-19

This is a diagnostic calibration snapshot, not the production publication gate.
It uses six retained exact VSIX artifacts: five independently labelled safe
controls and one independently reported malicious artifact. The run was
static-only and used an empty advisory snapshot for behavior calibration.

| Artifact | Label | Decision | Verdict | Risk | Interpretation |
| --- | --- | --- | --- | ---: | --- |
| `nrwl.angular-console@18.94.0` | known safe | allow | clean | 0 | contextual capabilities only |
| `streetsidesoftware.code-spell-checker@4.5.6` | known safe | allow | clean | 0 | contextual capabilities only |
| `redhat.vscode-yaml@1.24.0` | known safe | allow | clean | 0 | contextual capabilities only |
| `rust-lang.rust-analyzer@0.3.2971` | known safe | allow | clean | 0 | contextual capabilities only |
| `ms-python.python@2026.5.2026070801` | known safe | allow | clean | 0 | agent/process/network capabilities remained contextual |
| `bingcha.bcai-tools@4.0.37` | known malicious | review | suspicious | 85 | correlated download-and-execute evidence without intelligence |

Observed rates in this snapshot:

- known-safe block rate: `0/5 = 0%`
- known-safe review rate: `0/5 = 0%`
- malicious detection rate: `1/1 = 100%` (`suspicious/review`)
- malicious prevention rate without intelligence: `0/1 = 0%` (the policy correctly refused to convert static corroboration into a malware block)
- malicious prevention rate with the exact BCAI advisory: `1/1 = 100%`

The BCAI artifact is documented independently in
[the BCAI case study](bcai-rosetta-4.0.37.md). Its exact SHA-256 is pinned in
`benchmarks/holdouts/real-evidence-2026-source.json`; the independent report is
[Knostic's analysis](https://www.knostic.ai/blog/agentic-threat-intelligence-feed-vs-code-extensions).

This snapshot does not justify a 10,000-extension accuracy claim. The next
promotion gate still requires the fresh labelled holdout, at least five safe
and five malicious exact artifacts, deep runtime evidence, zero safe blocks,
zero malicious allows, and complete required-provider coverage.
