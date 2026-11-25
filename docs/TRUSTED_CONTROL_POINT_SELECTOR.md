# Trusted Control Point Selector


`trusted-control-selector/1.0` is pure deterministic code. It does not call an LLM.

## Inputs

- tenant, action, provider/product/version, environment, policy and matrix versions
- action-specific `ControlRequirementProfile`
- candidate capability profiles
- validation, callback, policy, configuration, version, latency, lifecycle-event, and health state
- current bypass and acceptable degradation state

## Eligibility

A candidate is rejected for any unmet requirement, including tenant mismatch, unverified profile/claim, unsupported version, unhealthy callback, stale validation or policy, configuration drift, missing lifecycle event or action field, insufficient binding, insufficient assurance, excessive latency, or unacceptable degradation.

## Selection order

Eligible points sort by assurance, blocking strength, action fidelity, bypass resistance, latency, then stable control-point ID. The selection ID includes the evaluated state and rejection reasons, so a health or capability change creates a new explainable selection.

## Failover

A weaker point is never selected if it does not satisfy every current requirement. The result becomes `CONTROL_REQUIREMENT_UNSATISFIED`. If a previously selected point is replaced by no point or lower assurance, Hawk emits `control_point_downgraded` evidence and a `CONTROL_POINT_DOWNGRADED` finding.

## Examples

- Exact high-risk tool action requiring A5: a healthy A5 bound point wins; an A3 gateway with observed-only execution proof is rejected.
- Same action after the A5 point degrades: the A3 point remains rejected, no primary is returned, and the action fails closed when native enforce is enabled.
- Unknown local runtime: a verified explicitly bound endpoint path can provide runtime control; an unverified provider-native hook cannot enter selection.
