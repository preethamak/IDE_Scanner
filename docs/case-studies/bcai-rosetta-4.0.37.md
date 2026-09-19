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

## What GuardRails finds without the advisory

The artifact was scanned with the bundled exact-artifact advisory snapshot
replaced by an empty snapshot. The scanner still returned:

- verdict: `review`
- decision: `review`
- risk score: `55`
- malware score: `0` (no authoritative intelligence was supplied for this run)
- high-specificity exposure finding: `remote-credential-broker`
- contextual supporting evidence: broad activation, credential-oriented input,
  network access, filesystem access, process execution, shell execution, and
  environment-file references

This is the correct conservative outcome for static-only corroboration: the
scanner identifies a remote token-broker trust boundary and requires review,
but does not call the artifact confirmed malware or claim exfiltration without
independent intelligence. The shipped connectivity probes and local proxy
registry reads are not mislabeled as a download-and-execute chain.

With the bundled exact hash advisory enabled, the same artifact becomes
`block` through `known-malicious-extension`, with verdict `malicious`,
`malware_score=100`, and public outcome `confirmed_threat`. That separation
keeps the decision explainable: behavior evidence and authoritative artifact
intelligence are not conflated. An exact advisory that describes only a
vulnerability still uses `known-vulnerable-extension` and does not receive a
malware label.

## Reproduction

```bash
PYTHONPATH=src ./.venv/bin/python -m ide_scanner.cli scan \
  --path benchmarks/external/artifacts/bcai-rosetta-4.0.37/bcai-rosetta-4.0.37.vsix \
  --offline --skip-posture --profile standard \
  --format json --out /tmp/bcai-rosetta-guardrails.json
```

For an advisory-free calibration run, pass a locally created JSON snapshot
with `{"snapshot_version":"empty-test","entries":[]}` using
`--extension-advisories`. Do not use that mode for publication decisions.

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
