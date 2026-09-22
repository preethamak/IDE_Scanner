# Guardlens Core Architecture

`ide_scanner` is the canonical security-decision engine. It owns artifact acquisition, static and provider analysis, policy classification, and canonical report serialization. It does not own interactive presentation or public-job persistence.

## Boundaries

- `contracts.py` defines `ScanRequest`, the immutable input shared by callers.
- `scanner.py` orchestrates acquisition, static/provider execution, capability-gated controlled runtime evidence, evidence aggregation, and report creation. `scan_targets()` is the stable public facade.
- `models.py`, `classification_policy.py`, and `public_outcomes.py` define the report and decision contract.
- `providers/` owns native/provider integration; unavailable required providers must result in incomplete analysis, never an allow decision.
- `registry.py` owns marketplace and dependency intelligence; captured snapshots are attached to reports for replayability.
- `sandbox_runner.py` owns the bounded Bubblewrap runtime. Runtime coverage is required only for artifacts whose declared or observed surface can answer a security question; ordinary declarative themes and other non-executable packages are explicitly marked not applicable.

## Versioning and trust

`ide-scanner` is the canonical development and release source for the scanner runtime. The public Guardrails CLI ships a self-contained, hash-verified copy of that runtime; CI rejects source drift before release. Consumers must record the engine version and build identity in generated reports. A policy, ruleset, or report-schema change requires contract-test coverage before release. A public release additionally requires complete controlled-runtime evidence for every runtime-required artifact and a separately labelled exact-artifact accuracy holdout.

## Consumers

The Guardrails CLI vendors the canonical runtime as part of its single installable package. The web worker invokes the canonical engine and sends a signed report bundle to the web ingestion boundary. Neither consumer may rewrite the canonical decision, score, analysis status, or provenance.
