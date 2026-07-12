# IDE Scanner

Evidence-first local scanner for VS Code-compatible extensions.

The scanner is built to avoid noisy false positives:

- Single powerful APIs are review evidence.
- High severity requires correlated executable behavior.
- Known removed or malicious registry/dependency evidence can become critical.
- Extension code is scanned locally and is not uploaded.

## Website scanner service

The product website can submit public Marketplace artifacts to the canonical Python engine through the file-backed HTTP job service:

```bash
PYTHONPATH=src python -m ide_scanner.service --host 127.0.0.1 --port 8787
```

Connect `ide-scanner-web` with:

```bash
IDE_SCANNER_API_URL=http://127.0.0.1:8787 npm run dev
```

Set the same `IDE_SCANNER_API_TOKEN` on both processes to require bearer authorization for scan jobs and reports. `GET /health` and `GET /v1/rules` remain public. Jobs and canonical report bundles are written beneath `IDE_SCANNER_DATA_DIR` (default `.ide-scanner-data`) so a process restart does not erase completed analysis.

Container build:

```bash
docker build -t ide-scanner .
docker run --read-only --tmpfs /tmp -v ide-scanner-data:/data -p 8787:8787 ide-scanner
```

The base container includes the native and JavaScript AST analyzers. Semgrep and YARA are optional analysis providers and must be installed in a derived image when they are required by policy; their availability is always reported rather than assumed.

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

Sandbox observations can be imported from an external, OS-isolated runner; the local scanner does not execute untrusted extensions:

```json
{"extensions":{"publisher.name":[{"kind":"secret_exfil","destination":"https://example.com"}]}}
```

The built-in `sandbox` command creates a disposable plan and canary layout only. Executable mode is disabled until the project has OS-level filesystem, process, and network isolation. Observations produced by a separate isolated runner can be passed to `scan --sandbox-observations`.

Schema 2.2 report bundles include a security decision (`allow`, `review`, `block`, or `incomplete`), exact artifact identity, complete file inventory, direct/transitive dependency inventory, six deterministic security dimensions, executable analysis coverage, provider status, and baseline changes when `--previous-report` is supplied. Declared `main` and `browser` entrypoints are analyzed even when they are bundled under generated directories.

Exact Marketplace versions and a callback-ready JSON bundle can be produced with:

```bash
IDE_SCANNER_REQUIRE_PROVIDERS=semgrep,yara,dependency_intelligence \
ide-scanner scan --extension-id publisher.extension --version 1.2.3 \
  --profile deep --online --format bundle.json --output scan-bundle.json
```

Optional local analysis providers:

```bash
python -m pip install -e '.[analysis]'
```

Semgrep supplies IDE-specific taint findings and YARA scans the complete artifact for byte-level indicators. Provider findings are normalized as evidence; provider severity alone cannot produce a confirmed-malware verdict.

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
