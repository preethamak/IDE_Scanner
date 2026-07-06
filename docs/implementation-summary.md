# IDE Scanner Implementation Summary

This document describes the working architecture, control flow, report model, and metrics implemented in `ide-scanner` and the hosted `ide-scanner-web` console.

## System Components

| Component | Location | Responsibility |
| --- | --- | --- |
| Hosted web console | `ide-scanner-web` | Browser UI for collecting inventory, generating reports, displaying scores, findings, icons, metadata, and scan history. |
| Local collector bridge | `ide-scanner-web/public/collect-ide-extensions.py` | Runs on the developer workstation, discovers installed IDE extensions, reads manifest metadata and icons, exposes localhost JSON endpoints for the hosted site. |
| Scanner engine | `ide-scanner/src/ide_scanner` | Performs local static scanning, artifact inventory, rule evaluation, registry enrichment, posture checks, scoring, and report generation. |
| Web bridge | `ide-scanner/src/ide_scanner/web_bridge.py` plus `ide-scanner-web/lib/pythonBridge.ts` | Lets a locally running web app invoke the Python scanner engine through `python -m ide_scanner.web_bridge`. |

## Hosted Website Control Flow

The hosted Vercel website cannot directly read `~/.vscode/extensions`, `~/.cursor/extensions`, or local package files. The user starts a local collector bridge:

```bash
curl -fsSL https://ide-scanner-web.vercel.app/collect-ide-extensions.py -o /tmp/ide-scanner-collector.py
python3 /tmp/ide-scanner-collector.py --serve
```

The collector listens on:

```text
http://127.0.0.1:17865
```

The website then uses browser requests to localhost:

| Endpoint | Method | Purpose |
| --- | --- | --- |
| `/health` | `GET` | Check collector availability and agent metadata. |
| `/inventory` | `GET` | Return installed extension inventory and rich manifest metadata. |
| `/scan` | `POST` | Return installed extension metadata used by the browser to build a report. |

The hosted flow is:

```text
User opens hosted website
  -> user starts local collector bridge
  -> website calls 127.0.0.1:17865/inventory
  -> website shows installed extensions
  -> website calls 127.0.0.1:17865/scan
  -> browser builds a collector report through buildCollectorReport()
  -> dashboard renders ranked extensions, verdicts, scores, icons, and metadata
```

The collector embeds extension icons as bounded `data:` URLs because the hosted browser cannot load local paths such as `/home/user/.vscode/extensions/.../icon.png`.

## Local Scanner Control Flow

When the web app is running locally beside the scanner repo, the deeper scanner path is:

```text
app/api/scans/route.ts
  -> lib/pythonBridge.ts
  -> python -m ide_scanner.web_bridge scan
  -> ide_scanner.core.run_scan()
  -> ide_scanner.scanner.scan_targets()
  -> JSON report
  -> ide_scanner.core.summarize_report()
  -> web dashboard
```

The scanner root defaults to `../ide-scanner` from the web app, or can be overridden with:

```text
IDE_SCANNER_ROOT
```

## Scanner Pipeline

`scan_targets()` is the main scanner orchestration function.

```text
scan_targets()
  -> discover explicit paths, local installs, fixtures, or registry IDs
  -> scan_extension() / scan_vsix()
  -> apply configured threat feed
  -> apply sandbox observations
  -> enrich with online registry checks when enabled
  -> apply registry findings
  -> build report with posture summary and version deltas
```

For each extension directory, `scan_extension()` performs:

```text
read package.json
  -> manifest and contribution checks
  -> runtime dependency source checks
  -> file walk with skip rules
  -> artifact hashing and risky artifact inventory
  -> repository posture checks
  -> text/code regex checks
  -> correlated behavior-chain checks
  -> webview CSP checks
  -> classify findings
  -> produce ExtensionReport
```

VSIX packages are handled by `scan_vsix()`:

```text
hash VSIX
  -> safe extract into temp directory
  -> locate extension/package.json
  -> scan extracted extension
  -> attach VSIX hash, size, signature status
  -> check known-bad VSIX hash
```

## Report Model

Top-level report fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Report schema version. |
| `scan_id` | Timestamp-based scan identifier. |
| `created_at` | UTC creation time. |
| `privacy_mode` | Indicates local metadata/static feature mode. |
| `registry_checks` | Online registry results and errors. |
| `summary` | Counts, max scores, and posture status. |
| `human_summary` | Short text summary for dashboards/reports. |
| `version_deltas` | Changes compared with a previous report. |
| `posture_summary` | Aggregated IDE/client posture score. |
| `posture` | Individual client posture metrics. |
| `extensions` | Full per-extension scan reports. |

Each `ExtensionReport` contains:

| Field | Meaning |
| --- | --- |
| `extension_id` | `publisher.name`. |
| `name`, `publisher`, `version`, `description`, `repository` | Package metadata. |
| `install_path`, `source` | Local path and source type, for example `vscode`, `cursor`, `vsix`, or `registry-id`. |
| `artifact_hash` | Package or VSIX hash reference. |
| `severity` | Highest finding severity. |
| `verdict` | `clean`, `review`, `suspicious`, or `malicious`. |
| `malware_authority` | `authoritative`, `non_authoritative`, or `none`. |
| `verdict_reason` | Human-readable reason for the verdict. |
| `malware_score` | 0-100 confidence that the artifact is malicious. |
| `risk_score` | 0-100 operational risk if installed or compromised. |
| `score_details` | Component scores, evidence-class counts, suppressors, basis, confidence. |
| `capabilities` | Capability evidence gathered during scanning. |
| `artifact_inventory` | File hashes, package hash, risky artifacts, known-bad matches, VSIX signature status. |
| `findings` | Full finding list. |
| `scanned_files` | Number of readable source/config files scanned. |
| `dependencies` | Runtime dependency map. |

Each finding includes:

```text
finding_id, extension_id, version, rule_id, category, severity,
confidence, score, evidence_type, evidence_summary, file_refs,
recommendation, evidence
```

## Verdict Logic

Verdicts are intentionally conservative:

| Verdict | Trigger |
| --- | --- |
| `malicious` | Confirmed malware evidence such as known-bad artifact hash, malware marketplace removal, malicious npm dependency, or trusted threat feed hit. |
| `suspicious` | High correlated static behavior chain, suspicious marketplace removal, or high/critical observed sandbox behavior. |
| `review` | Actionable non-confirmed evidence such as dependency, provenance, posture, observed behavior, or sensitive capability findings. |
| `clean` | No actionable malware, abuse-chain, dependency, provenance, posture, or sensitive-capability evidence. Weak-only or reputation-only evidence is kept contextual. |

`startup-activation` alone is not actionable review evidence. It can appear as context but should not turn an extension into `review` by itself.

## Score Model

Every finding gets an individual score from severity and confidence:

```text
base = INFO 5, LOW 20, MEDIUM 45, HIGH 78, CRITICAL 95
finding_score = min(100, round(base * confidence + base * 0.22))
```

The scanner then calculates component scores:

| Component | Meaning |
| --- | --- |
| `confirmed_intelligence` | Known-bad hashes, malware removals, malicious dependencies, threat-feed hits. |
| `observed_behavior` | Sandbox observations. |
| `correlated_behavior` | Static behavior chains that form realistic abuse paths. |
| `sensitive_capability` | Powerful IDE, agent, lifecycle, webview, native artifact capability. |
| `provenance` | Marketplace removal, packed artifacts, binary origin, source/package mismatch. |
| `dependency` | Runtime dependency risk. |
| `posture` | Repository/workflow posture risks attached to the package. |
| `reputation` | Marketplace/repository reputation context. |
| `weak_context` | Weak findings such as standalone secret references. |

Score calculation:

```text
malware_score = max(confirmed_intelligence, correlated_behavior, observed_behavior)

if correlated or observed behavior exists:
  malware_score += bounded weak_context boost
  malware_score is capped at 89 unless confirmed evidence exists

risk_score = max(component scores, excluding reputation unless actionable context exists)

if actionable context exists:
  risk_score += bounded weak_context boost
  risk_score += bounded reputation boost
  risk_score -= suppressor reductions
  risk_score is capped at 99 unless confirmed evidence reaches 100
```

Current suppressor:

| Suppressor | Reduction | Rule |
| --- | ---: | --- |
| `verified-publisher` | 5 | Present when `marketplace-verified-publisher` is found. Reduces reputation risk only. |

## Evidence Classes

Each rule maps to an evidence class:

| Evidence class | Meaning |
| --- | --- |
| `confirmed` | Authoritative malware or known-bad evidence. |
| `observed` | Runtime sandbox observation. |
| `correlated` | Static behavior chain combining multiple suspicious capabilities. |
| `capability` | Powerful extension or IDE capability. |
| `dependency` | Runtime dependency source or vulnerability risk. |
| `provenance` | Package/source provenance issue. |
| `posture` | Repository/workflow posture issue. |
| `reputation` | Marketplace/repository context that should not be decisive alone. |
| `weak` | Weak static context, such as standalone secret references. |

## Implemented Extension Metrics

### Manifest and IDE Capability Metrics

| Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- |
| `broad-activation` | `activation` | `capability` | LOW | Extension activates for every workspace via `*`. |
| `startup-activation` | `activation` | `capability` | LOW | Extension runs automatically after IDE startup. Context only by itself. |
| `sensitive-activation` | `activation` | `capability` | LOW | Activates on sensitive events such as URI, auth, terminal, task, debug, webview, or custom editor. |
| `lifecycle-script` | `supply-chain` | `capability` | MEDIUM | Package defines `preinstall`, `install`, `postinstall`, or `vscode:uninstall`. |
| `powerful-ide-contribution` | `ide-capability` | `capability` | LOW | Manifest contributes debuggers, task definitions, or terminal capability. |
| `agentic-tooling` | `agentic` | `capability` | MEDIUM | Manifest contributes language model tools, chat participants, or MCP servers. |
| `agent-shell-tool` | `agentic` | `capability` | MEDIUM | Agent-facing tool surface can run shell/process commands. |
| `agent-filesystem-tool` | `agentic` | `capability` | MEDIUM | Agent-facing tool surface can read/write files. |
| `agent-network-tool` | `agentic` | `capability` | MEDIUM | Agent-facing tool surface can reach network resources. |
| `mcp-server-command` | `agentic` | `capability` | MEDIUM | Extension registers an MCP server command or definition. |
| `agent-prompt-injection-sink` | `agentic` | `capability` | MEDIUM | Agent contribution may route untrusted content into tool execution. |

### Install-Time and Supply-Chain Chain Metrics

| Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- |
| `install-download-execute` | `install-time` | `correlated` | HIGH | Lifecycle script can download content and execute commands. |
| `install-secret-access` | `install-time` | `correlated` | HIGH | Lifecycle script references credential material. |
| `install-shell-obfuscation` | `install-time` | `correlated` | HIGH | Lifecycle script contains obfuscated or piped shell execution. |
| `install-network-telemetry` | `install-time` | `weak` | MEDIUM | Lifecycle script appears to send install-time telemetry. |

### Dependency Metrics

| Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- |
| `unpinned-dependency` | `dependency` | `dependency` | LOW | Runtime dependency uses `*`, `latest`, `x`, or similar unpinned specifier. |
| `mutable-dependency-source` | `dependency` | `dependency` | MEDIUM | Runtime dependency comes from mutable or non-registry source. |
| `vulnerable-npm-dependency` | `dependency` | `dependency` | MEDIUM/HIGH | OSV reports vulnerability in a runtime npm dependency. Exact versions score higher. |
| `malicious-npm-dependency` | `dependency` | `confirmed` | CRITICAL | OSV result contains `MAL-*` malicious package advisory. |

### Artifact and Provenance Metrics

| Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- |
| `native-or-packed-artifact` | `artifact` | `capability` | MEDIUM | Extension contains native executable artifact such as `.node`, `.dll`, `.so`, `.dylib`, `.exe`. |
| `packed-artifact` | `provenance` | `provenance` | MEDIUM | Extension contains packed archive such as `.zip`, `.asar`, `.tgz`, `.jar`, etc. |
| `binary-without-origin` | `provenance` | `provenance` | MEDIUM | Native binary lacks companion checksum/signature and documented origin. |
| `known-bad-artifact` | `confirmed-intelligence` | `confirmed` | CRITICAL | File/package/VSIX hash matches a configured known-bad hash feed. |
| `source-vsix-diff-unexplained` | `provenance` | `provenance` | Currently classified, not emitted by current scanner path | Reserved for source/package mismatch evidence. |

### Code Behavior Metrics

| Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- |
| `process-execution` | `execution` | `weak` | LOW | Code can spawn local processes. |
| `network-access` | `network` | `weak` | LOW | Code performs network requests. |
| `filesystem-access` | `filesystem` | `weak` | LOW | Code reads or writes local files. |
| `dynamic-code-loading` | `code` | `weak` | MEDIUM | Code uses eval, dynamic import, VM execution, or dynamic class loading. |
| `obfuscation` | `code` | `weak` | LOW | Code contains obfuscation indicators. |
| `destructive-file-pattern` | `filesystem` | `weak` | MEDIUM | Code contains destructive file operation patterns. |

### Credential and Correlated Static Chain Metrics

| Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- |
| `secret-reference:aws-credentials` | `credential-access` | `weak` | LOW | Code references AWS credential material. |
| `secret-reference:ssh-private-key` | `credential-access` | `weak` | LOW | Code references SSH private keys/config. |
| `secret-reference:gcp-credentials` | `credential-access` | `weak` | LOW | Code references Google Cloud credential material. |
| `secret-reference:npm-token` | `credential-access` | `weak` | LOW | Code references npm tokens or `.npmrc`. |
| `secret-reference:github-token` | `credential-access` | `weak` | LOW | Code references GitHub tokens. |
| `secret-reference:env-file` | `credential-access` | `weak` | LOW | Code references `.env` or environment variables. |
| `credential-file-read` | `credential-access` | `weak` | MEDIUM | Code can read local files and references sensitive material. |
| `credential-exfiltration-chain` | `credential-access` | `correlated` | HIGH | Code combines credential references, file reads, and outbound network writes. |
| `destructive-transfer-chain` | `destructive-activity` | `correlated` | HIGH | Code combines destructive file activity, archive/encoding, and network behavior. |
| `obfuscation-execution-network` | `execution` | `correlated` | HIGH | Code combines obfuscation, dynamic execution, and network behavior. |
| `persistence-chain` | `persistence` | `correlated` | HIGH | Code modifies persistence locations and executes or communicates externally. |
| `agent-data-exfil-chain` | `agentic` | `correlated` | HIGH | Agent-facing code combines sensitive references with outbound network behavior. |
| `download-and-execute` | `execution` | `correlated` | HIGH | Code can download content and execute local processes from the same file. |
| `supply-chain-dropper-chain` | `supply-chain` | `correlated` | Not emitted by current scanner path | Reserved correlated chain for package dropper behavior. |

### Webview Security Metrics

| Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- |
| `webview-csp-missing` | `webview` | `capability` | MEDIUM | Extension creates a webview without detected CSP meta tag. |
| `webview-csp-unsafe-directive` | `webview` | `capability` | MEDIUM | Webview CSP uses `unsafe-inline`, `unsafe-eval`, or wildcard script source. |

### Repository and Workflow Posture Metrics

| Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- |
| `repo-url-missing` | `reputation` | `reputation` | LOW | Manifest does not declare a source repository. |
| `security-policy-missing` | `repository-posture` | `reputation` | LOW | Packaged artifact has no local `SECURITY.md`. |
| `license-missing` | `repository-posture` | `reputation` | LOW | Packaged artifact has no local license file. |
| `repo-binary-artifacts` | `repository-posture` | `posture` | LOW | Packaged artifact ships committed native binaries. |
| `dangerous-github-workflow` | `repository-posture` | `posture` | MEDIUM | Workflow uses dangerous supply-chain posture such as `pull_request_target`, `write-all`, or `contents: write`. |
| `workflow-token-permissions-broad` | `repository-posture` | `posture` | LOW | Workflow grants broad token permissions or relies on implicit default token scope. |

### Online Marketplace, Registry, and Repository Metrics

These metrics are emitted only when online registry enrichment is enabled.

| Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- |
| `marketplace-removed-malware` | `registry` | `confirmed` | CRITICAL | Marketplace removal list says extension was removed as malware. |
| `marketplace-removed-package` | `registry` | `confirmed` or `provenance` | HIGH/MEDIUM | Marketplace removal list says extension was removed as suspicious, untrustworthy, impersonation, or another removal type. |
| `marketplace-extension-not-found` | `reputation` | `reputation` | LOW | Extension was not found in marketplace metadata. |
| `marketplace-verified-publisher` | `reputation` | `reputation` | INFO | Marketplace reports verified publisher. Also creates suppressor. |
| `marketplace-unverified-publisher` | `reputation` | `reputation` | LOW | Marketplace does not report verified publisher. |
| `marketplace-low-install-count` | `reputation` | `reputation` | LOW | Marketplace install count is below threshold. |
| `marketplace-low-rating` | `reputation` | `reputation` | LOW | Marketplace rating is low across enough ratings. |
| `install-rating-mismatch` | `reputation` | `reputation` | LOW | High install count but low rating. |
| `marketplace-stale-extension` | `reputation` | `reputation` | LOW | Marketplace says extension has not been updated for a long time. |
| `marketplace-name-impersonation` | `reputation` | `reputation` | LOW | Name resembles known popular extension from another publisher. |
| `repo-archived` | `reputation` | `reputation` | LOW | Declared GitHub repository is archived or disabled. |
| `repo-stale` | `reputation` | `reputation` | LOW | Declared GitHub repository has not been pushed recently. |
| `repo-maintained` | `reputation` | `reputation` | INFO | Declared GitHub repository has recent activity. |

### Threat Feed Metrics

| Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- |
| `trusted-threat-feed-hit` | `confirmed-intelligence` | `confirmed` | CRITICAL | Configured threat feed marks extension as malware or malicious. |
| `marketplace-removed-package` | `provenance` | `provenance` | HIGH | Configured threat feed marks extension as suspicious/non-malware. |

### Sandbox Observation Metrics

These are consumed from a sandbox observation JSON file, not generated directly by the static scanner.

| Observation kind | Rule id | Category | Evidence class | Severity | Purpose |
| --- | --- | --- | --- | --- | --- |
| `secret_read` | `observed-secret-read` | `dynamic-sandbox` | `observed` | MEDIUM | Sandbox saw reads of canary or sensitive credential paths. |
| `secret_exfil` | `observed-secret-exfil` | `dynamic-sandbox` | `observed` | HIGH | Sandbox saw canary or sensitive data leaving the process. |
| `download_execute` | `observed-download-execute` | `dynamic-sandbox` | `observed` | HIGH | Sandbox saw downloaded content executed or loaded. |
| `persistence` | `observed-persistence` | `dynamic-sandbox` | `observed` | HIGH | Sandbox saw persistence or autorun behavior. |
| `destructive` | `observed-destructive-behavior` | `dynamic-sandbox` | `observed` | HIGH | Sandbox saw destructive file behavior. |
| `unexpected_network` | `observed-unexpected-network` | `dynamic-sandbox` | `observed` | MEDIUM | Sandbox saw network traffic to unexpected destination. |
| `process_exec` | `observed-process-exec` | `dynamic-sandbox` | `observed` | MEDIUM | Sandbox saw process execution. |
| `filesystem_write` | `observed-filesystem-write` | `dynamic-sandbox` | `observed` | LOW | Sandbox saw filesystem writes. |

## IDE/Client Posture Metrics

Posture metrics answer a different question from extension malware scanning: whether local IDE/client configuration increases blast radius for otherwise-normal extensions, tasks, or agents.

The scanner checks VS Code, VS Code Insiders, VSCodium, Cursor, and Windsurf settings, extension roots, and selected state files.

| Metric id | Status source | Score behavior | Purpose |
| --- | --- | --- | --- |
| `clients-found` | skipped when no supported clients found | 0 | Reports no local VS Code-compatible clients were found. |
| `client-detected` | success | 0 | Records that a supported client configuration was found. |
| `settings-found` | skipped if settings unavailable | 0 | Indicates posture scan is incomplete without settings. |
| `workspace-trust` | success/warning/failure | Up to 92 | Detects disabled Workspace Trust, broad trusted paths, untrusted files opening without prompt, or disabled startup prompts. |
| `automatic-tasks` | success/warning/failure | Up to 82 | Detects automatic tasks, especially combined with broad trusted paths. |
| `agent-global-auto-approve` | success/failure | Up to 95 | Detects global agent tool auto-approval. |
| `terminal-auto-approve` | success/warning/failure | Up to 90 | Detects risky terminal auto-approval rules or ignored defaults. |
| `url-auto-approve` | success/warning/failure | Up to 72 | Detects broad or external URL auto-approval rules. |
| `extension-trust-overrides` | success/failure | Up to 76 | Detects extensions allowed to run in Restricted Mode through trust overrides. |
| `extensions-found` | skipped when no inventory found | 0 | Indicates no extension inventory was found for that client. |
| `extension-startup` | success/warning | 44 | Counts installed extensions that activate at startup or for every workspace. |
| `sideloaded-extensions` | success/failure | 78 | Detects VSIX-installed extensions that bypass marketplace/internal registry flow. |
| `agentic-extensions` | success/warning | 52 | Counts installed extensions exposing agent tools, chat participants, or MCP surfaces. |
| `native-or-packed-extension-artifacts` | success/warning | 38 | Counts installed extensions shipping native binaries or packed archives. |
| `client-risk-summary` | success/warning/failure | weighted summary | Aggregates posture metrics into top-level posture score and status. |

Posture summary uses:

```text
max_metric_score = highest individual posture score
weighted_score = weighted average across non-skipped metrics
score = max(max_metric_score, weighted_score)
status = failure if score >= 70, warning if score >= 25, else success
```

## Summary Dashboard Fields

`ide_scanner.core.summarize_report()` generates the compact object used by the web dashboard:

| Field | Meaning |
| --- | --- |
| `summary` | Raw report summary: counts, max scores, posture score/status. |
| `human_summary` | Short narrative summary. |
| `posture_summary` | Aggregated posture data. |
| `posture` | Individual posture metrics. |
| `version_deltas` | Changed versions, verdicts, scores, dependencies, or risky artifacts. |
| `top_risk_extensions` | Ranked extension cards. |
| `action_counts` | Counts by verdict. |
| `finding_counts` | Counts by rule, category, and severity. |

Ranking uses:

```text
verdict rank -> severity rank -> malware_score -> risk_score -> extension_id
```

## Privacy Boundaries

| Mode | What leaves the machine |
| --- | --- |
| Hosted website + local bridge | Manifest metadata, bounded icon data, selected collector payload returned to the browser. Files are not uploaded by default. |
| Hosted one-shot upload | Compact collector metadata posted to the hosted API. |
| Local web + scanner repo | Full scanning happens locally; reports can be stored locally or uploaded only through explicit app flows. |

The scanner is designed to be clear about evidence strength: capability and reputation findings raise review context, but `malicious` is reserved for confirmed malware intelligence.
