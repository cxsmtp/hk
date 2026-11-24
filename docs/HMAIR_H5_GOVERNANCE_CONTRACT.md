# HMAIR H5 Governance and Continuous Discovery Contract

**Status:** Accepted at the source-and-fixture boundary on 2026-09-11.
**Programme position:** H5 8 of 8; HMAIR 51 of 60. H6 remains open.

## 1. Authority and reuse

H5 is a versioned projection over the existing HMAIR canonical asset, usage,
identity-attribution, reachability, Evidence Claim, finding, Control Coverage,
Control Graph, scan, and continuous-validation authorities. It does not add a
second inventory, evidence store, findings engine, graph, policy engine, or
authorization authority. H5 projection output has no authorization effect.

No database migration is required. Existing persisted vocabularies remain
backward-compatible; H5 exposes the exact public states below through strict,
immutable contracts.

## 2. Usage truth

The six usage states are `no_usage_observed`, `historical_usage`,
`active_usage`, `high_frequency_usage`, `service_usage`, and `unknown_usage`.
An installed application, licence, catalog entry, configured connector, or
reachable destination is not usage. `no_usage_observed` requires complete
in-scope telemetry and zero events. Incomplete telemetry produces
`unknown_usage`. Service, workload, automation, and agent activity remains
distinct from human activity. Bounded views expose users by asset, assets by
user, and aggregates by business unit, geography, environment, time window,
enterprise/personal account class, sanctioned/shadow class, and human/service
actor class. Unknown identity and organization bindings remain explicit.

## 3. Explainable Shadow AI

The eight classification states are `approved`,
`approved_but_uncontrolled`, `known_unapproved`, `suspected_shadow`,
`confirmed_shadow`, `personal_account`, `owner_unknown`, and `unknown`.
Every result includes a plain-language explanation, confidence, evidence
references, limitations, and the evidence condition that would change it.
Missing catalog membership alone never establishes confirmed Shadow AI.
Confirmed Shadow AI requires observed unapproved use corroborated by at least
two independent sources. Suspected and Unknown results have conservative
confidence ceilings. Classification never grants or revokes authority.

## 4. Reachability truth

The six reachability states are `configured`, `observed`, `inferred`,
`simulated`, `blocked`, and `unknown`. Targets are restricted to the approved
model, MCP server, tool, SaaS, API, database, vector database, source
repository, secret reference, cloud identity, external network,
customer-data-system, and persistent-side-effect types.

Each projection preserves its pseudonymous target reference, source surface,
first and last seen time, confidence, evidence, observed-use truth, control
capability, and limitations. Configured, inferred, simulated, or blocked reach
never becomes observed use. Reachability does not create authorization.

## 5. Control Coverage

H5 enriches the existing Control Coverage authority using exactly seven
dimensions per asset and path: Discovery, Identity, Usage, Authorization,
Evidence, Containment, and Bypass Detection. The existing denominator and
score-withholding rules remain unchanged. Authorization requires an evidenced
inline authorization control. Containment requires an effective path control.
Evidence requires a current accepted canonical Evidence Claim. Observed reach
without those claims is not treated as covered. Missing bypass evidence remains
Unknown. No percentage is shown when the authoritative denominator is absent.

## 6. Findings and change events

H5 accepts only these 17 finding types through the existing tenant-scoped
finding lifecycle: `SHADOW_AI_CONFIRMED`, `SUSPECTED_SHADOW_AI`,
`AI_ASSET_OWNER_UNKNOWN`, `AI_USAGE_IDENTITY_UNKNOWN`,
`UNAPPROVED_AI_SAAS`, `PERSONAL_AI_ACCOUNT`,
`UNAPPROVED_DEVELOPER_AI`, `UNKNOWN_MCP_SERVER`,
`UNKNOWN_AI_RUNTIME`, `UNPROTECTED_LLM_ROUTE`,
`UNPROTECTED_MCP_ROUTE`, `AI_ENABLED_DATABASE_UNGOVERNED`,
`AI_ASSET_USAGE_WITHOUT_AUTHORIZATION`, `AI_FINGERPRINT_DRIFT`,
`HIGH_RISK_AI_CAPABILITY_DISCOVERED`, `DISCOVERY_SOURCE_STALE`, and
`AI_ESTATE_BLIND_SPOT`. The catalog supplies severity, remediation,
verification, and Control Coverage impact. Evidence, confidence, affected
asset, usage, and identities remain joined through the existing canonical
asset and Evidence Claim authorities.

Continuous comparison emits only these 11 events: `AI_ASSET_DISCOVERED`,
`AI_ASSET_CHANGED`, `AI_ASSET_BECAME_ACTIVE`, `AI_ASSET_OWNER_CHANGED`,
`AI_CAPABILITY_ADDED`, `AI_USAGE_INCREASED`, `AI_IDENTITY_CHANGED`,
`AI_REACHABILITY_CHANGED`, `AI_FINGERPRINT_DRIFT`, `SHADOW_AI_CONFIRMED`, and
`CONTROL_COVERAGE_REDUCED`. Events are deterministic, tenant-scoped,
evidence-referenced, and derived from prior and current canonical snapshots.
No unchanged input creates an event.

## 7. Graph admission

Only current, accepted canonical governance claims may become H5 Control Graph
relationships. Rejected, contradicted, stale, expired, or Unknown claims are
excluded. Inferred relationships retain their inferred evidence state and are
never displayed as verified facts. Cross-tenant claims are rejected. Graph
records reference evidence; they do not copy raw evidence payloads.

## 8. Continuous enrichment and incremental rescan

The incremental planner computes stable asset digests from bounded canonical
snapshots. It selects only new or changed assets, retains changed evidence
categories, caps each plan at 500 assets, orders work deterministically, and
creates a stable idempotency key. Unchanged assets are skipped.

An incremental rescan uses the existing scan service and only source targets
that have current canonical provenance for changed assets. It preserves the
existing tenant, safety, dry-run, requester, assignment, audit, and
idempotency rules and links the new scan to its predecessor. Missing source
provenance remains an explicit limitation rather than causing an estate-wide
rescan.

## 9. Privacy and unsupported conclusions

H5 contracts reject extra fields and do not accept raw prompts, responses,
source files, database rows, vector content, credentials, secrets, cookies,
tokens, or arbitrary customer payloads. Identity and target references are
pseudonymous where the projection does not require an existing canonical ID.

Source-and-fixture acceptance does not prove a customer source is connected or
healthy, a customer estate has an authoritative organization denominator, a
configured source completed a current scan, live surface breadth, production
deployment, retention/compaction, estate-scale performance, end-to-end
customer acceptance, or control on a path without corresponding current
evidence. Those operational and enterprise gates remain H6 or external rollout
work.
