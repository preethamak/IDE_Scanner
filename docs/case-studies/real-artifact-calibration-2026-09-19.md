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
| `bingcha.bcai-tools@4.0.37` | known malicious | review | review | 57 | remote credential-broker exposure without intelligence |

Observed rates in this snapshot:

- known-safe block rate: `0/5 = 0%`
- known-safe review rate: `0/5 = 0%`
- malicious detection rate: `1/1 = 100%` (`review/review`)
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

## Current replay identity

The retained six-artifact replay was originally reproduced with scanner build
`90f9f823646e25c14bd96c7835f07ea95dc7f20d`, policy
`3.1.0-calibration.4`, and ruleset
`2026.09.19-policy-v3-calibration.29-dynamic-catalog` (95 rules). It was a
static-only diagnostic run with runtime execution disabled; the report records
that limitation rather than presenting static evidence as dynamic coverage.
The exact artifact hashes were verified before scanning, including
`b1b9785cdc7be479061f121f282391fba9be013d896d9a54f395621634709216` for BCAI.

The current exact-artifact replay was rerun with scanner build
`c8f3888abe1f05d7d86338b23f179914bc952dca`, policy `3.1.0-calibration.5`,
and ruleset `2026.09.22-policy-v3-calibration.38-complete-rule-catalog` (116
rules). The BCAI behavior-only replay remains `REVIEW` without the advisory
and the exact-hash replay is `BLOCK/MALICIOUS` with the advisory enabled.
Neither run is a substitute for the required deep-runtime publication holdout.

## Latest canonical diagnostic replay

The current calibration test suite was rerun against six exact safe controls
and the exact BCAI artifact with scanner build
`c8f3888abe1f05d7d86338b23f179914bc952dca`. All retained scans completed; the safe controls
remained `allow`/`clean`, and BCAI was `block`/`malicious` with authoritative
malware score and risk score `100` when the verified advisory was enabled.
This is useful evidence that capability signals remain contextual on this small
cohort, but it is still a diagnostic replay rather than an independently
adjudicated ecosystem accuracy claim.
