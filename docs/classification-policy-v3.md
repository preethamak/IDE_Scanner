# Classification policy v3

Status: calibration draft. This policy does not alter historical reports.

## Independent report dimensions

The scanner reports three independent dimensions. A renderer must not infer one
dimension from another.

1. **Analysis status**: `complete`, `incomplete`, or `failed`. An incomplete or
   failed analysis has no approval decision.
2. **Decision**: `allow`, `review`, or `block`. This is the deterministic policy
   action for a completely analyzed exact artifact.
3. **Evidence severity**: `INFO`, `LOW`, `MEDIUM`, `HIGH`, or `CRITICAL`. This is
   the highest severity among decision-relevant findings. Capability observations
   do not raise evidence severity by themselves.

Capability power is reported separately. Process, filesystem, network, native
code, credential UI, lifecycle, activation, and agent-tool access describe what
an extension can do; they are not security findings without a violated trust
boundary, unexplained provenance, a vulnerable exact component, an abuse path,
or authoritative intelligence.

## Finding actionability

Every finding receives an explicit actionability value from rule metadata:

- `contextual`: capability or weak context; cannot change decision or severity.
- `low`: a concrete hardening or provenance concern with limited demonstrated
  impact.
- `review`: evidence requires a reviewer before approval.
- `block`: authoritative threat evidence or a policy-blocking abuse path.

Actionability is determined by the rule and evidence shape, never by an
extension-specific verdict branch. Registry popularity and publisher
verification may establish identity, but cannot suppress code evidence.

## Deterministic aggregation

For complete analysis:

- `block` when any finding is actionability `block`.
- `review` when any finding is actionability `review`.
- `allow` otherwise, including artifacts with only contextual or low findings.

Evidence severity is the maximum normalized severity among `low`, `review`, and
`block` findings. It is `INFO` when all findings are contextual. A low-severity
finding may coexist with `allow`; it remains visible as a non-blocking hardening
note.

For incomplete or failed analysis, decision is absent and the UI displays
`No decision`. Compatibility serializers may retain the legacy `incomplete`
decision value, but consumers must use analysis status first.

## Reproducibility contract

The canonical report records exact artifact SHA-256, scanner build, ruleset
version, policy version, provider versions and status, and normalized findings.
CLI and website Deep Scan render that report without recalculating classification.
Given the same artifact, scanner build, ruleset, policy, provider inputs, and
network intelligence snapshot, security-relevant report fields must be identical.

Historical reports remain immutable. Policy v3 creates new reports with a new
ruleset and policy version.

## Calibration boundary

The frozen 30-artifact website corpus is development data. Its proposed outcome
distribution is a hypothesis, not an optimization quota. A label changes only
after its driving evidence is adjudicated and the general rule correction passes
benign and malicious regression controls. Efficacy claims require a separate,
untuned holdout.
