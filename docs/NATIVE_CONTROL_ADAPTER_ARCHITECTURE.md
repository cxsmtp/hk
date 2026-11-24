# Native Control Adapter Architecture

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


## Boundary

Native Control adapters are internal infrastructure beneath Browser, Endpoint, Runtime, and SaaS & APIs. They do not introduce a fifth deployment family or a second policy path.

Hawk remains authoritative for Discovery → AI Asset → AI Action → Policy → Decision → Evidence → Control Coverage. An adapter translates provider events and responses; it does not own tenant resolution, RBAC, authorization, approval, replay, receipts, evidence, selection, or coverage.

## Components

- `adapter_contract.py`: immutable descriptors, strict manifests, composable capability protocols, normalized events, blind spots, timeout budgets, secret references, validation reports, and errors.
- `adapter_registry.py`: validated Hawk-shipped registry with exact/compatible/ambiguous/unsupported/unknown resolution. It contains no policy or ranking logic.
- `control_point_factory.py`: projects verified adapter, integration, health, runtime-validation, and manifest facts into the existing `ControlPointCandidate`.
- `selector.py`: remains the only ranking and eligibility authority. Security requirements are mandatory; cost can break ties only among eligible points.
- `adapter_pipeline.py`: Hawk-owned callback security, replay, normalization, canonical authorization, decision translation checks, deduplication, and evidence emission.
- `reference_adapters.py`: synthetic A5, A3, and A2 adapters plus an adversarial false-A4 fixture. Reference maturity is never production eligible.
- `conformance.py`: mandatory reusable suite for every future provider implementation.

## Event path

Provider event → Hawk transport/authentication → tenant/integration binding → replay/schema limits → adapter normalization → `NativeControlEvent` → existing `AuthorizationRequest`/AI Action → requirements → `TrustedControlPointSelector` → existing authorization kernel → Hawk decision/receipt → adapter response translation → execution/result capture → existing execution receipt/evidence.

Raw provider payloads end at the normalization boundary. Only the normalized event hash, bounded canonical fields, decision, selected point, and evidence reference continue.

## Production eligibility

A component is not trusted because code exists. Production eligibility requires a non-reference descriptor, VERIFIED manifest, version compatibility, current validation, normalized healthy state, configuration integrity, authenticated workload identity, and selector eligibility. EXPERIMENTAL and UNVERIFIED controls are excluded by default.
