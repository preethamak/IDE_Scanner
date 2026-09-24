# GuardRails case study: BCAI Rosetta 4.0.37

Status: independently reported malicious artifact; GuardRails reproduction and
corroboration. This is not a claim that GuardRails discovered the campaign
first.

## Exact artifact

- Extension: `bingcha.bcai-tools`
- Version: `4.0.37`
- Artifact SHA-256: `b1b9785cdc7be479061f121f282391fba9be013d896d9a54f395621634709216`
- Registry: Open VSX
- Independent report: [Knostic — Agentic Threat Intelligence Feed: VS Code Extensions](https://www.knostic.ai/blog/agentic-threat-intelligence-feed-vs-code-extensions)

The independent report describes Google OAuth refresh-token theft, broad Google
Cloud access, automated account handling, and proxying through attacker-
controlled infrastructure. GuardRails retains the exact VSIX so the result is
reproducible against bytes, not only an extension name or version.

### Source evidence in the retained VSIX

The exact archive also contains the source-level trust boundary that caused
the review finding. These are observations from the pinned bytes, not an
inference from the extension name:

- `extension/bundled-rosetta/token-proxy/add-account.js` implements the Google
  OAuth authorization-code exchange, requests offline access, handles the
  returned access/refresh tokens, and persists the refresh token in the local
  account record.
- `extension/bundled-rosetta/token-proxy/index.js` defines the remote-token
  service default at `https://bcai.site/remote-token` when remote mode is
  selected.
- `extension/bundled-rosetta/relay-proxy/token-passthrough.js` requests a
  remote lease, consumes the returned `accessToken`, and forwards it as a
  bearer credential to upstream requests; it also reports lease results back
  to the configured token server.

That combination is enough to establish a high-confidence remote credential
broker trust boundary and justify review. It is not, by itself, proof that the
operator misused every token or that the extension is malware; those stronger
claims remain tied to the independently reported exact-hash advisory below.

## What GuardRails finds without the advisory

The artifact was scanned with the bundled exact-artifact advisory snapshot
replaced by an empty snapshot. The scanner still returned:

- verdict: `review`
- decision: `review`
- risk score: `57`
- malware score: `0` (no authoritative intelligence was supplied for this run)
- high-specificity exposure finding: `remote-credential-broker`
- contextual supporting evidence: broad activation, credential-oriented input,
  network access, filesystem access, process execution, shell execution, and
  environment-file references

The behavior-only replay recorded here used the final scanner engine revision
`6095e1f1f0461a2006ff40f23ea6323c6013e899`, policy `3.1.0-calibration.7`,
and ruleset `2026.09.24-policy-v3-calibration.41-transpiled-process-alias`.
The local replay completed with 100% required-provider coverage against the
exact VSIX under that scanner identity. The privileged publication holdout
must still rerun the case with the complete runtime contract before this
result is used as release evidence. The score is a diagnostic index, not a
probability of compromise.

This is the correct conservative outcome for static-only corroboration: the
scanner identifies a remote token-broker trust boundary and requires review,
but does not call the artifact confirmed malware or claim exfiltration without
independent intelligence. The shipped connectivity probes and local proxy
registry reads are not mislabeled as a download-and-execute chain.

With the bundled exact hash advisory enabled, the same artifact becomes
`block` through `known-malicious-extension`, with verdict `malicious`,
`risk_score=100`, `malware_score=100`, and public outcome
`confirmed_threat`. That separation keeps the decision explainable: behavior
evidence and authoritative artifact intelligence are not conflated. An exact
advisory that describes only a vulnerability still uses
`known-vulnerable-extension` and does not receive a malware label.

The behavior-only replay remains static-only. Its dynamic provider is
explicitly `not-requested`, so this case study does not claim that GuardRails
executed the extension or independently proved every behavior described by the
external report.

## Reproduction

```bash
PYTHONPATH=src ./.venv/bin/python -m ide_scanner.cli scan \
  --path benchmarks/external/artifacts/bcai-rosetta-4.0.37/bcai-rosetta-4.0.37.vsix \
  --offline --skip-posture \
  --profile standard \
  --format json \
  --out /tmp/bcai-rosetta-guardrails.json
```

The default bundled advisory snapshot is used by that command. To reproduce
the behavior-only result above, pass an explicit empty snapshot:

```bash
printf '%s\n' '{"snapshot_version":"empty-test","entries":[]}' \
  > /tmp/empty-extension-advisories.json
PYTHONPATH=src ./.venv/bin/python -m ide_scanner.cli scan \
  --path benchmarks/external/artifacts/bcai-rosetta-4.0.37/bcai-rosetta-4.0.37.vsix \
  --offline --skip-posture \
  --profile standard \
  --extension-advisories /tmp/empty-extension-advisories.json \
  --format json \
  --out /tmp/bcai-rosetta-behavior-only.json
```

Do not use the behavior-only mode for publication decisions. It is a
calibration and false-negative regression pass; production blocking requires
the verified intelligence snapshot and exact artifact identity.

## Publication language

Safe wording:

> GuardRails reproduced and corroborated the published BCAI Rosetta 4.0.37
> incident from the exact Open VSX artifact. Without threat intelligence, its
> static analysis independently flagged a remote credential-broker trust
> boundary and routed the release to review; with the verified exact-hash
> advisory, it blocked the artifact.

Avoid saying “GuardRails discovered” or implying that the static scan alone
proved every behavior described by the independent report. Runtime execution
was not used as evidence for this case study.
