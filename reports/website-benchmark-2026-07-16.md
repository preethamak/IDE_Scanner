# IDE Scanner website benchmark — 2026-07-16

## Publication verdict

The benchmark methodology, artifact inventory, untouched first-pass result, defect analysis, and final regression result are suitable for public release with the limitations in this report.

The benchmark does **not** support an ecosystem-wide accuracy, false-positive, false-negative, or malicious-recall headline. The final corpus was used to identify and correct scanner defects, so its final 100% routing result is development regression evidence rather than untouched holdout performance. There is no fresh, metric-eligible malicious holdout in this dataset.

## Corpus

- 30 exact Visual Studio Marketplace VSIX artifacts.
- 697,056,453 artifact bytes (approximately 665 MiB on disk).
- 21 artifacts frozen as fresh-artifact holdouts before acquisition.
- 9 prior-exposure controls, reported separately.
- Expected decisions and exact Marketplace versions frozen at scanner commit `c1db76c`.
- Every downloaded artifact matched its embedded publisher, extension name, and version.
- Every artifact has a retained SHA-256 and source URL in `benchmarks/website-corpus/v1/manifest.json`.

Acquisition wrote archives without installing or activating them. Scanning occurred in a separate container with no network, a read-only root filesystem, no Linux capabilities, no privilege escalation, UID 65534, and fixed CPU, memory, PID, and temporary-storage limits.

## Untouched first pass

The first pass is the only result that can be treated as holdout-like evidence for this corpus. It was preserved before scanner or label corrections.

| Measure | Result | Wilson 95% interval |
|---|---:|---:|
| Complete coverage | 23/30 (76.7%) | 59.1%–88.2% |
| Exact frozen routing among completed artifacts | 20/23 (87.0%) | 67.9%–95.5% |
| Fresh-artifact exact routing among completed fresh artifacts | 13/15 (86.7%) | 62.1%–96.3% |
| Legitimate false-block rate among completed artifacts | 1/23 (4.3%) | 0.8%–21.0% |

First-pass disagreements:

1. `ms-vscode-remote.remote-ssh` was falsely blocked. A lifecycle script setting `npm_config_registry=https://registry.npmjs.org` before `npm exec ado-npm-auth` was incorrectly treated as download-and-execute.
2. `ms-vscode.azure-account` was allowed despite its credential-related login command surface. Command-only authentication activation did not produce review evidence.
3. Seven large extensions were incomplete because executable files over 10 MiB were not analyzed.
4. `ms-azuretools.vscode-docker@2.0.0` was allowed although the frozen hypothesis expected review. This was a benchmark-label error: version 2.0.0 is now a declarative Docker Extension Pack, while its Container Tools dependency provides the privileged runtime functionality. The correction is recorded separately and does not rewrite the frozen input.

## Corrections prompted by the corpus

- Lifecycle URL matching now requires an actual downloader command instead of any URL environment assignment.
- Credential-related command activation becomes reviewable exposure.
- Executable text coverage increased from 10 MiB to 64 MiB.
- Coverage size and generated-bundle confidence are independent.
- Large generated entrypoints remain fully read, inventoried, and AST-analyzed, but native file-wide proximity is not promoted into a proven abuse chain.
- Regression suite increased from 93 to 96 passing tests.

The intermediate coverage fix initially caused false blocks for Continue, GitHub Copilot, and GitHub Copilot Chat because newly parsed generated bundles were treated as single source modules. That intermediate raw report is retained and hashed; it is not presented as a successful result.

## Final development regression

| Measure | Result | Wilson 95% interval |
|---|---:|---:|
| Complete coverage | 30/30 (100%) | 88.6%–100% |
| Artifact-aware expected routing | 30/30 (100%) | 88.6%–100% |
| Legitimate false-block rate | 0/30 (0%) | 0%–11.4% |
| Fresh-artifact rows matching their frozen decisions after tuning | 21/21 (100%) | 84.5%–100% |

Final decisions were 4 `allow`, 26 `review`, 0 `block`, and 0 `incomplete`. Every legitimate artifact had malware score 0. This is a regression result on development data and must not be described as unbiased accuracy.

## Final per-artifact result

| Extension | Version | Split | Frozen expectation | Final | Coverage | M/R |
|---|---:|---|---|---|---:|---:|
| `amazonwebservices.aws-toolkit-vscode` | `4.10.0` | fresh-artifact-holdout | review | review | 100% | 0/61 |
| `aquasecurityofficial.trivy-vulnerability-scanner` | `1.8.11` | fresh-artifact-holdout | review | review | 100% | 0/71 |
| `Continue.continue` | `2.1.0` | fresh-artifact-holdout | review | review | 100% | 0/61 |
| `dbaeumer.vscode-eslint` | `3.0.33` | prior-exposure | review | review | 100% | 0/51 |
| `eamodio.gitlens` | `2026.7.160544` | prior-exposure | review | review | 100% | 0/61 |
| `esbenp.prettier-vscode` | `12.4.0` | fresh-artifact-holdout | allow | allow | 100% | 0/0 |
| `formulahendry.code-runner` | `0.12.2` | fresh-artifact-holdout | review | review | 100% | 0/47 |
| `GitHub.copilot` | `1.388.0` | fresh-artifact-holdout | review | review | 100% | 0/61 |
| `GitHub.copilot-chat` | `0.48.1` | prior-exposure | review | review | 100% | 0/63 |
| `GitHub.vscode-pull-request-github` | `0.159.2026071604` | fresh-artifact-holdout | review | review | 100% | 0/58 |
| `golang.go` | `0.56.0` | fresh-artifact-holdout | review | review | 100% | 0/61 |
| `humao.rest-client` | `0.25.1` | fresh-artifact-holdout | review | review | 100% | 0/61 |
| `mhutchie.git-graph` | `1.30.0` | prior-exposure | review | review | 100% | 0/57 |
| `ms-azuretools.vscode-docker` | `2.0.0` | prior-exposure | review | allow | 100% | 0/0 |
| `ms-kubernetes-tools.vscode-kubernetes-tools` | `1.4.0` | fresh-artifact-holdout | review | review | 100% | 0/54 |
| `ms-python.python` | `2026.5.2026070801` | prior-exposure | review | review | 100% | 0/58 |
| `ms-vscode-remote.remote-containers` | `0.467.0` | prior-exposure | review | review | 100% | 0/56 |
| `ms-vscode-remote.remote-ssh` | `0.125.2026062315` | fresh-artifact-holdout | review | review | 100% | 0/56 |
| `ms-vscode.azure-account` | `0.13.0` | fresh-artifact-holdout | review | review | 100% | 0/30 |
| `ms-vscode.cpptools` | `1.33.4` | fresh-artifact-holdout | review | review | 100% | 0/63 |
| `PKief.material-icon-theme` | `5.36.1` | prior-exposure | allow | allow | 100% | 0/0 |
| `redhat.java` | `1.56.2026071508` | fresh-artifact-holdout | review | review | 100% | 0/55 |
| `ritwickdey.LiveServer` | `5.7.10` | prior-exposure | review | review | 100% | 0/53 |
| `RooVeterinaryInc.roo-cline` | `3.54.0` | fresh-artifact-holdout | review | review | 100% | 0/61 |
| `rust-lang.rust-analyzer` | `0.4.2976` | fresh-artifact-holdout | review | review | 100% | 0/41 |
| `saoudrizwan.claude-dev` | `4.0.8` | fresh-artifact-holdout | review | review | 100% | 0/55 |
| `semgrep.semgrep` | `1.17.0` | fresh-artifact-holdout | review | review | 100% | 0/51 |
| `snyk-security.snyk-vulnerability-scanner` | `2.31.0` | fresh-artifact-holdout | review | review | 100% | 0/48 |
| `SonarSource.sonarlint-vscode` | `5.5.0` | fresh-artifact-holdout | review | review | 100% | 0/58 |
| `usernamehw.errorlens` | `3.28.0` | fresh-artifact-holdout | allow | allow | 100% | 0/0 |

## Malicious rows from the proposed matrix

- Aqua Trivy `1.8.12` and `1.8.13` were excluded. Neither version exists in VS Marketplace or Open VSX. Aqua's official 2026 advisory concerns compromise of other Trivy ecosystem components, not these VS Code extension versions. The legitimate retained control is `1.8.11`.
- Campaign placeholders without exact extension IDs, versions, hashes, retrievable VSIX artifacts, and artifact-specific evidence were excluded from rates.
- Socket publishes exact GlassWASM identities and hashes for `ExarGD.vsblack@0.0.1` and `noellee-doc.flint-debug@0.1.1`, but their removed Open VSX artifacts were unavailable at the recorded endpoints. They remain in the incident index, not the denominator.
- The retained external development sample `bingcha.bcai-tools@4.0.37` still receives `suspicious / block` with M82/R87 and complete coverage at final scanner commit `d1b0b47`. It informed prior policy work and is not a fresh malicious holdout.

The final four-artifact development regression also preserved `redhat.vscode-yaml` as `allow` and Code Spell Checker plus rust-analyzer as `review`.

## Website-safe wording

> We froze and hash-pinned 30 Visual Studio Marketplace extension artifacts before scanning. The untouched first pass completed 23 artifacts and matched the predeclared routing for 20 of those 23. The benchmark exposed one false block, one credential-routing miss, one stale label, and seven coverage gaps. After documented corrections, all 30 artifacts completed: four narrow or declarative artifacts were allowed and 26 privileged extensions were routed to review, with no legitimate blocks. The corrected result is regression evidence, not an independent estimate of ecosystem accuracy. A retained externally labeled malicious development sample was also blocked, but no fresh malicious holdout was available for a recall claim.

## Claims not supported

Do not publish:

- “100% accurate” or “zero false positives.”
- “100% malware detection.”
- “Independently audited.”
- “Proven safe” for allowed extensions.
- A malicious recall or false-negative percentage from this corpus.

## Reproducibility and raw-report integrity

- Frozen input: `benchmarks/website-corpus/v1/frozen-input.json`
- Artifact manifest: `benchmarks/website-corpus/v1/manifest.json`
- Label corrections: `benchmarks/website-corpus/v1/label-corrections.json`
- Normalized results: `benchmarks/website-corpus/v1/results.json`
- First-pass raw SHA-256: `e0040281192d0b9883b7ee95684816c0506d29ef08b11f3618017e47e76db73c`
- Intermediate raw SHA-256: `73b66cdea01dd0fd9f1f4be9a0a2456355b61472e62a103bac93b657b6c9999e`
- Final raw SHA-256: `391bb2fef6f85405d02a246e7f720daa117062937913e591bf7f9c8b6bb13979`
- Malicious-regression raw SHA-256: `cc4b0428e9241ca2b54a5dc64e986d6750db765ce7ff1b37885955993f3ae89c`

The raw reports and 30 VSIX files are retained outside Git under `/home/akprajwal/VScode/ide-scanner-benchmark-store/website-v1/`.

## Sources used to validate disputed or malicious labels

- [Docker Extension Pack listing](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-docker)
- [Aqua Trivy ecosystem advisory](https://github.com/aquasecurity/trivy/security/advisories/GHSA-69fq-xp46-6x23)
- [Socket GlassWASM report with exact VSIX hashes](https://socket.dev/blog/glasswasm-malware-open-vsx-extensions)
- [Socket GlassWorm compromised-extension report](https://socket.dev/blog/glassworm-loader-hits-open-vsx-via-suspected-developer-account-compromise)

## Remaining requirement for public efficacy claims

Freeze and acquire a new malicious holdout with exact externally supported hashes after scanner commit `d1b0b47`, then run it once without tuning. Until that exists, publish the transparent benchmark study but not a detection-accuracy headline.
