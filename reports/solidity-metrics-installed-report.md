# Solidity Metrics Extension Scan Report

Generated: 2026-07-06

Scanner: `ide-scanner`

Targets:

- `/home/akprajwal/.vscode/extensions/tintinweb.solidity-metrics-0.0.26`
- `/home/akprajwal/.cursor/extensions/tintinweb.solidity-metrics-0.0.25-universal`

JSON report:

- `reports/solidity-metrics-installed-report.json`

## Summary

| Metric | Value |
| --- | ---: |
| Total extensions scanned | 2 |
| Review verdicts | 2 |
| Malicious verdicts | 0 |
| Max risk score | 41 |
| Max malware score | 0 |
| Max severity | MEDIUM |
| IDE posture score | 78 |
| IDE posture status | failure |

## Result

Both installed Solidity Metrics extensions were classified as `review`, not `malicious`.

The scanner found review-grade capability and packaging concerns:

- missing packaged security policy
- filesystem access in extension code
- webview without a detected Content-Security-Policy meta tag
- network access in bundled visualization code
- obfuscation indicators in bundled visualization code

No confirmed malware evidence was found.

## Extension Findings

### `tintinweb.solidity-metrics@0.0.26`

Install path:

`/home/akprajwal/.vscode/extensions/tintinweb.solidity-metrics-0.0.26`

| Field | Value |
| --- | --- |
| Source | vscode |
| Verdict | review |
| Severity | MEDIUM |
| Risk score | 41 |
| Malware score | 0 |

Findings:

- `LOW security-policy-missing`: No local security policy file was found in the packaged artifact.
- `LOW filesystem-access`: Extension reads or writes local files. Reference: `src/extension.js`.
- `LOW filesystem-access`: Extension reads or writes local files. Reference: `src/features/interactiveWebview.js`.
- `MEDIUM webview-csp-missing`: Extension creates a webview in `src/features/interactiveWebview.js` without a detected Content-Security-Policy meta tag.
- `LOW network-access`: Extension performs network requests. Reference: `content/js/d3graphviz/viz.js`.
- `LOW obfuscation`: Extension contains obfuscation indicators. Reference: `content/js/d3graphviz/viz.js`.

### `tintinweb.solidity-metrics@0.0.25`

Install path:

`/home/akprajwal/.cursor/extensions/tintinweb.solidity-metrics-0.0.25-universal`

| Field | Value |
| --- | --- |
| Source | vscode |
| Verdict | review |
| Severity | MEDIUM |
| Risk score | 41 |
| Malware score | 0 |

Findings:

- `LOW security-policy-missing`: No local security policy file was found in the packaged artifact.
- `LOW filesystem-access`: Extension reads or writes local files. Reference: `src/extension.js`.
- `LOW filesystem-access`: Extension reads or writes local files. Reference: `src/features/interactiveWebview.js`.
- `MEDIUM webview-csp-missing`: Extension creates a webview in `src/features/interactiveWebview.js` without a detected Content-Security-Policy meta tag.
- `LOW network-access`: Extension performs network requests. Reference: `content/js/d3graphviz/viz.js`.
- `LOW obfuscation`: Extension contains obfuscation indicators. Reference: `content/js/d3graphviz/viz.js`.

## Recommended Action

Keep this extension in review rather than treating it as malicious. The highest-priority fix or manual review item is the webview CSP issue, because webviews are an extension surface where content isolation matters. Also confirm the bundled visualization dependency that triggered network/obfuscation indicators is expected vendor code.
