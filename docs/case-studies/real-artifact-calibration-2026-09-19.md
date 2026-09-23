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
`d6b5c3629d000043965f7a2cad25b33e947b85f`, policy `3.1.0-calibration.7`,
and ruleset `2026.09.23-policy-v3-calibration.40-environment-exfiltration`
(117 rules). The BCAI behavior-only replay remains `REVIEW` without the
advisory and the exact-hash replay is `BLOCK/MALICIOUS` with the advisory
enabled. Neither run is a substitute for the required deep-runtime
publication holdout.

## Latest canonical diagnostic replay

The current calibration test suite was rerun against six exact artifacts with
scanner build `d6b5c3629d000043965f7a2cad25b33e947b85f`. All six scans
completed; the five safe controls remained `allow`/`clean` with risk and
malware scores of `0`, and BCAI was `block`/`malicious` with authoritative
scores of `100` when the verified advisory was enabled. The most frequent
capability rules on safe controls were `filesystem-access` (5),
`process-execution` (5), `network-access` (4), `security-policy-missing` (4),
`dynamic-code-loading` (4), and `powerful-ide-contribution` (4). They remained
context-only and did not create a safe block or review. The calibration also
added a bounded `environment-data-exfiltration` correlation after a source-backed
replay showed that whole-process environment serialization sent to a request
was previously clean. Selected environment telemetry and environment values
used to configure child processes remain clean, and the retained Nx Console
safe control was explicitly replayed after this rule was narrowed for minified
bundle variable collisions. BCAI additionally triggered the high-specificity `remote-credential-broker`,
`dynamic-shell-execution`, and exact-hash advisory rules. This is useful
evidence that ordinary developer-tool capabilities remain contextual on this
small cohort, but it is still a diagnostic replay rather than an
independently adjudicated ecosystem accuracy claim.

## Latest unlabelled pilot cohort — 2026-09-23

An additional 20 exact VSIX artifacts from the retained ecosystem pilot set
were scanned with scanner build `d6b5c3629d000043965f7a2cad25b33e947b85f`,
policy `3.1.0-calibration.7`, ruleset
`2026.09.23-policy-v3-calibration.40-environment-exfiltration`, an empty
advisory snapshot, and runtime disabled. This is an unlabelled observational
cohort, not a safe/malicious accuracy sample and not a publication gate.

- 19 artifacts completed and routed `allow`/`clean`.
- 1 artifact was quarantined as `incomplete` because the required JavaScript
  AST provider could not analyze its 41.7 MB generated entrypoint.
- The completed artifacts emitted 188 observations: 155 contextual and 33
  low-actionability; no artifact had a review/block-actionable finding.
- The repeated weak capability and encoded-execution matches stayed
  contextual. They did not change the install decision or enter the review
  queue.

The incomplete artifact is Google Cloud Data Agent Kit `0.7.2`. The scanner
does not call it clean: the required provider failure remains visible and the
artifact is ineligible for public publication until a bounded structural
analysis path or an explicit reviewed exception exists. The cohort was
static-only and offline, so it provides no dynamic-runtime evidence.

## Recalibrated broad cohort — 2026-09-23

The same 146 exact VSIX artifacts were rerun after the capability-contract
calibration with scanner build
`a636637acdb201c572d01100b6b83a898c9c8ae2`, policy `3.1.0-calibration.7`,
and ruleset `2026.09.23-policy-v3-calibration.40-environment-exfiltration`.
The run was offline, static-only, and used an explicit empty advisory
snapshot. It is still an unlabelled diagnostic cohort, not an ecosystem
accuracy claim or a publication gate.

- 140 artifacts completed; 5 were incomplete and 1 timed out and was isolated.
- Public routing was 137 eligible `clean`, 1 eligible `review`, and 2
  eligible `suspicious`; 6 artifacts were quarantined as `incomplete`.
- The five review decisions were `mcpspend.mcpspend-vscode`,
  `pdragon.azure-rbs-workbench`, `northLo.penny-vscode`,
  `mcpbundles.mcpbundles-remote-browser`, and `devoszhang.uix`.
- The known capability-classification false positive for
  `artipartylartiii.a-lsp@1.0.5` changed from `review`/`clean` to
  `allow`/`clean` without changing its contextual binary/process findings.
- `pdragon.azure-rbs-workbench@1.5.0` remained `review`/`suspicious` with
  both `destructive-transfer-chain` and `download-and-execute`; the
  calibration did not weaken those correlated high-risk rules.

The rerun reduced the broad-cohort review queue by one known false positive,
but it does not establish false-negative or malicious-detection rates because
the cohort has no independent labels and has no runtime evidence. The timeout,
provider failures, and missing entrypoints remain visible and ineligible for
public publication.
