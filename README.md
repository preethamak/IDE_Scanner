# IDE Scanner

Evidence-first local scanner for VS Code-compatible extensions.

The scanner is built to avoid noisy false positives:

- Single powerful APIs are review evidence.
- High severity requires correlated executable behavior.
- Known removed or malicious registry/dependency evidence can become critical.
- Extension code is scanned locally and is not uploaded.

## Commands

```bash
PYTHONPATH=src python -m ide_scanner scan --fixtures
PYTHONPATH=src python -m ide_scanner scan --all --out report.json
PYTHONPATH=src python -m ide_scanner scan --path ~/.vscode/extensions
PYTHONPATH=src python -m ide_scanner scan --path extension.vsix
PYTHONPATH=src python -m ide_scanner scan --path ~/.vscode/extensions --known-bad-hashes known-bad.json
PYTHONPATH=src python -m ide_scanner scan --path ~/.vscode/extensions --threat-feed threat-feed.json
PYTHONPATH=src python -m ide_scanner scan --path extension.vsix --sandbox-observations observations.json
PYTHONPATH=src python -m ide_scanner scan --all --previous-report old-report.json
PYTHONPATH=src python -m ide_scanner sandbox --path extension-folder --out observations.json
PYTHONPATH=src python -m ide_scanner sandbox --path extension-folder --out observations.json --allow-execute
PYTHONPATH=src python -m ide_scanner benchmark
PYTHONPATH=src python -m ide_scanner benchmark normalize protect-your-secrets --input data/Ground_Truth_datasets.csv --output benchmarks/datasets/vscode-credential-exposure/normalized.json
PYTHONPATH=src python -m ide_scanner benchmark run --dataset benchmarks/datasets/vscode-credential-exposure/normalized.json --report report.zip --output benchmark.zip
PYTHONPATH=src python -m ide_scanner inventory --all
PYTHONPATH=src python -m ide_scanner agent --server http://127.0.0.1:8765 --all
PYTHONPATH=src python -m unittest discover -s tests
```

Optional online checks:

```bash
PYTHONPATH=src python -m ide_scanner scan --all --online
```

Upload a local machine report to a hosted or LAN web console:

```bash
IDE_SCANNER_AGENT_TOKEN=<shared-token> \
PYTHONPATH=src python -m ide_scanner agent \
  --server https://your-ide-scanner-web.example \
  --all
```

The `agent` command runs on the machine being scanned. It reads that machine's local IDE extension folders, builds the normal scanner report, and uploads it to `POST /api/agent/reports`.

Known-bad hash feeds can be JSON or line-based SHA-256 files:

```json
{"hashes":[{"sha256":"<64 hex chars>","source":"internal-feed","classification":"malware"}]}
```

Sandbox observations are imported from an external runner; this scanner does not execute untrusted extensions:

```json
{"extensions":{"publisher.name":[{"kind":"secret_exfil","destination":"https://example.com"}]}}
```

The built-in `sandbox` command is conservative by default. Without `--allow-execute`, it only creates a disposable plan and canary layout. With `--allow-execute`, it runs package lifecycle commands and the Node extension entrypoint in a temporary HOME/workspace. It preloads runtime instrumentation for filesystem reads/writes, process execution, DNS, TCP, HTTP, and HTTPS. Network calls are recorded and blocked by the hook. The output can be passed back to `scan --sandbox-observations`.

Threat feeds can mark extension ids as confirmed malware or high-risk review evidence:

```json
{"extensions":[{"extension_id":"publisher.name","classification":"malware","source":"internal-feed"}]}
```

Previous reports can be supplied with `--previous-report` to add `version_deltas` and human-readable summary notes without changing the core verdict gates.

`benchmark` without a subcommand scans the bundled ground-truth fixtures and reports expected-vs-actual verdict accuracy.

`benchmark normalize protect-your-secrets` converts the public "Protect Your Secrets" replication CSV into IDE Scanner's normalized credential-exposure dataset format. `benchmark run` compares a scanner report JSON/report.zip against that dataset and can write a dashboard-ready `benchmark.zip` containing:

- `metadata.json`
- `leaderboard.json`
- `benchmark_summary.json`
- `rule_coverage.json`
- `comparisons.json`
- `extensions/*.json`

Rows missing from the scanner report are counted as `not_scanned`, not false negatives, so partial benchmark runs do not produce misleading precision/recall.

## Documentation

- [Metrics reference](docs/metrics-reference.md): how verdicts, evidence classes, malware score, and risk score should be interpreted.
- [Metrics design](docs/metrics-design.md): deeper scoring model, metric families, false-positive controls, and implementation roadmap.
