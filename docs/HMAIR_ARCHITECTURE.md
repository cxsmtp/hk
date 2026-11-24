# Hawk Multi-Surface AI Discovery Engine Architecture

**Status:** Approved additive architecture; bounded Part 1 implementation verified locally
**Date:** 2026-08-15
**Authority:** Phase X Part 1 user brief plus the approved HMAIR path-native design

## 1. Architecture

Hawk extends its existing HMAIR discovery substrate. It does not introduce a
second product, scanner, inventory, asset database, evidence store, policy
engine, or authorization authority.

```text
Collectors
  -> immutable observations
  -> deterministic normalization
  -> evidence fusion
  -> hypotheses and Evidence Resolution Graph
  -> conservative asset resolution
  -> evidence-native AI ecosystems
  -> capability, reachability, usage and identity projections
  -> AI Action and Control Coverage projections
  -> immutable evidence and history
```

The existing authorities remain authoritative:

- `DiscoveryObservation` is raw discovery truth.
- `EvidenceNode` and `EvidenceEdge` are the evidence authority.
- `DiscoveryAssetHypothesis` and the Evidence Resolution Graph express
  unresolved and resolved relationships.
- `DiscoveryAIAsset` is the canonical asset inventory.
- Existing capability, reachability, identity, usage, ownership, finding,
  action, and coverage records remain the only projections for those domains.

No collector may create an asset, assign ownership, classify Shadow AI,
calculate risk, claim control coverage, or authorize an action.

## 2. Collector SDK

The existing strict collector SDK remains the implementation contract. A
path-native facade exposes the brief's compact lifecycle without weakening the
more precise SDK:

```text
validate()       -> validate_configuration()
enumerate()      -> test_connectivity() + enumerate_scope()
collect()        -> invoke the permitted typed collection methods internally
observe()        -> emit_observations()
health()         -> report_health()
limitations()    -> report_limitations()
schema_version() -> declaration.schema_version
```

Collection records are an internal staging boundary and do not escape
`collect()`. `observe()` is the only discovery-result boundary and accepts only
exact `DiscoveryObservationInput` objects. Returned assets, decisions, ownership
claims, risk classifications, unbounded raw data, or arbitrary mappings are
rejected. Existing default-off, read-only, bounded, tenant-scoped,
privacy-safe, and rate-limited collector rules remain mandatory.

## 3. Discovery Pipeline

1. An authorized scan freezes scope, safety profile, targets, collectors, and
   limitations.
2. Collectors emit immutable typed observations.
3. The server owns receive time, tenant binding, scan binding, collector
   binding, schema validation, and replay handling.
4. Normalization creates deterministic comparison material for paths,
   identities, providers, models, applications, frameworks, versions, SDKs,
   configuration keys, and runtime references. It does not infer equivalence.
5. Evidence fusion creates an immutable evidence bundle over persisted
   observations and exposes source diversity, direct/inferred state,
   confidence range, freshness, contradictions, and limitations.
6. Hypothesis and resolution services determine whether evidence supports a
   new asset, an existing asset, manual review, rejection, or Unknown.
7. Evidence-native ecosystem resolution joins canonical assets only through
   fresh, non-contradicted, verified graph relationships.
8. Existing projections enrich assets and ecosystems with capabilities,
   reachability, identities, dependencies, usage, ownership, actions,
   findings, and control coverage.
9. Every conclusion exposes evidence references, discovery sources,
   confidence, verification state, limitations, and last seen time.

Empty output is not absence. Missing evidence stays Unknown.

## 4. Normalization

Normalization is deterministic and versioned. It may canonicalize casing,
Unicode, separators, provider aliases, version formatting, and safe structured
identifiers. It always preserves the original observation and evidence hash.

Normalization explicitly must not:

- merge observations or assets;
- infer owner, user, business unit, risk, usage, or approval;
- treat a license as use, configuration as execution, or network reachability
  as authorization;
- inspect or persist prompts, credentials, tokens, arbitrary source files, or
  raw customer data.

## 5. Evidence Fusion

Evidence fusion consumes only persisted, tenant-scoped observation IDs. It
creates or reuses:

- one deterministic evidence node for each observation; and
- one deterministic evidence-bundle node for the exact ordered observation
  set and fusion algorithm version.

Canonical `bundle_member` edges bind the bundle to its members. Replays are
idempotent; conflicting material is rejected. Fusion reports measurable facts,
not an invented weighted score:

- independent source surfaces;
- direct and inferred observation counts;
- verification states;
- minimum and maximum source confidence;
- newest and oldest observation times;
- freshness states;
- contradictions and limitations.

Contradictory observations remain in the bundle. They are never silently
discarded or averaged away.

Each fused observation also creates or reuses an existing canonical
`DiscoveryEvidenceClaim` against the immutable bundle. The scan stores only the
current bundle pointer; older bundles, nodes, edges, and claims remain available
for replay and history.

## 6. Resolution

Resolution remains a separate authority from collection and fusion. The
existing approved conservative rules apply:

- direct strong identifiers may support automatic attachment only where an
  explicit allowlist exists;
- weak correlation hints cannot merge assets by themselves;
- stale, expired, inferred-only, unknown, or contradicted relationships cannot
  prove an ecosystem connection;
- unresolved evidence creates or updates a hypothesis, not an asset;
- merge, split, reversal, rejection, and manual review remain append-only and
  auditable.

Provider and environment equality are descriptive attributes, not identity or
relationship proof.

## 7. AI Ecosystem Model

An AI ecosystem is a deterministic, read-only projection over connected
canonical assets. It is not a new persisted inventory record.

Two assets share an ecosystem only when the Evidence Resolution Graph contains
a fresh, non-contradicted relationship whose evidence is verified or partially
verified. Unconnected assets remain separate even when their provider and
environment match.

Each ecosystem exposes:

- stable projection ID and algorithm version;
- member assets and asset types;
- provider and environment values without forcing a false single value;
- evidence references and discovery sources;
- confidence range, verification state, freshness, contradiction state, and
  last seen time;
- models, runtimes, tools, MCP servers, data assets, repositories, network
  destinations, identities, capabilities, reachability, usage, ownership,
  findings, AI actions, and control coverage when evidence exists;
- explicit Unknown and limitations when evidence does not exist.

## 8. Continuous Learning and History

Learning is append-only. New scans add observations, evidence nodes, evidence
bundles, hypotheses, graph edges, verification results, and resolution history.
They do not overwrite the prior evidence that supported an earlier conclusion.

The current ecosystem view is reproducible from its member assets, graph
evidence, algorithm version, and observation history. A changed conclusion
must point to the new evidence and preserve the previous state in history.

## 9. Migration Plan

No new database is required. The implementation reuses the schema introduced
by migrations `0047` and `0054` through `0058`:

- canonical targets, collectors, scans, assignments, and observations;
- AI assets, evidence claims, fingerprints, capability assertions, and
  resolution history;
- hypotheses, graph nodes/edges, and verification tasks;
- reachability, usage, identity, ownership, findings, and intelligence
  projections.

The implementation adds service and API behavior over those authorities. A
future schema change is permitted only when a proved requirement cannot be
represented safely by the existing tables, and must be additive with a tested
upgrade/downgrade path.

## 10. Implemented Files

- `apps/api/app/services/hmair/collector_facade.py`
- `apps/api/app/services/hmair/normalization_service.py`
- `apps/api/app/services/hmair/evidence_fusion_service.py`
- `apps/api/app/services/hmair/ecosystem_resolution_service.py`
- `apps/api/app/jobs/hmair_discovery_jobs.py`
- `apps/api/app/api/routers/discovery_ecosystems.py`
- `apps/api/tests/test_phase_x_discovery_engine.py`
- `apps/web/src/components/discovery/discovery-ecosystem-map.tsx`
- `apps/web/src/components/discovery/ai-estate-intelligence.tsx`
- `apps/web/src/lib/types.ts`
- `apps/web/tests/phase2-discovery-workspace.test.mjs`
- this architecture and its executable implementation plan
- Phase 2 validation report and master implementation ledger updates

## 11. Feature Flags

The work reuses existing HMAIR flags. It does not add an always-on collector or
hidden promotion path.

- `hmair_core`: canonical discovery substrate and APIs.
- existing collector-family flags: collection permission per surface.
- existing fingerprint/resolution/intelligence flags: deeper processing only
  where already approved and enabled.

Disabled flags produce explicit unavailable/Unknown states, never simulated
coverage.

## 12. Risks and Controls

| Risk | Required control |
|---|---|
| False asset merge | Evidence graph connection; no provider/environment grouping |
| Collector overreach | Typed observation-only facade and privacy sanitizer |
| Cross-tenant fusion | Tenant-scoped lookup for every observation/node/edge |
| Evidence replay/conflict | Deterministic IDs, digests, integrity keys, conflict rejection |
| Stale conclusion | Freshness and last-seen surfaced; stale edges do not connect |
| Contradiction loss | Preserve and expose all contradictory evidence |
| Marketing coverage | Unknown and limitations remain first-class |
| Algorithm disclosure | Expose methodology/version and evidence, keep proprietary heuristics internal |

## 13. Limitations

- Fixture-backed collectors prove contracts, not live enterprise-provider
  access.
- Enterprise-wide claims still require reconciled authoritative denominators,
  managed fleet deployment, and signed completion receipts.
- Unmanaged devices without endpoint, browser, DNS, proxy, identity, cloud,
  repository, SaaS, database, runtime, or network evidence remain Unknown.
- Ecosystem confidence cannot exceed the strongest truthful source evidence.
- This architecture does not grant authorization. Inline control remains the
  responsibility of Hawk's existing control-point selection and authorization
  services.
- Production readiness requires live provider acceptance, performance,
  retention, drift, residency, and continuous-verification evidence.
- The persistent Docker/PostgreSQL deployment has not yet been advanced through
  migrations `0054`-`0058` in this slice because Docker access was not granted
  by the execution sandbox. No volume was deleted or recreated.

## 14. H4 controlled expansion

H4 adds one closed, data-driven catalog of 31 passive metadata profiles across
managed cloud AI, Kubernetes, SaaS, identity, repository/CI, network, API
catalog, and data-platform sources. Every profile uses the existing canonical
collector SDK and observation path; no provider-specific policy or resolution
engine was added. Built-in declarations are registered deterministically, but
the existing default-off surface flags and source-readiness gates still control
execution. A declaration with no admitted source reports Unknown.

Microsoft 365 and GitHub retain their typed direct collectors. Other H4 paths
use an existing customer-owned connector or a separately attested metadata
feed. The public operating matrix is
`docs/HMAIR_H4_COLLECTOR_COVERAGE.md`. H4 source-and-fixture acceptance does not
claim a connected customer estate, production enablement, or authoritative
organization-wide coverage.

## 15. H5 governance projection and continuous enrichment

H5 adds a strict, versioned governance projection over the existing canonical
records. It does not introduce another persistence or authorization authority.
The projection exposes the exact six usage states, eight Shadow AI states, six
reachability states, seven discovery Control Coverage dimensions, seventeen
finding types, and eleven change-event types required by the HMAIR brief.

Usage remains event-backed: configuration, installation, licensing, and
catalog presence cannot become active use. Shadow classifications retain
evidence, confidence, explanation, limitations, and a change condition.
Reachability preserves configured, observed, inferred, simulated, blocked, and
unknown truth without promotion. Control Coverage continues to withhold a
score when its denominator is absent.

Only current accepted canonical claims are projected into the existing Control
Graph. Rejected, contradicted, stale, expired, or unknown claims are excluded;
inferred facts remain inferred. The existing finding lifecycle persists the
closed H5 finding catalog. Continuous enrichment compares bounded canonical
asset snapshots, emits only approved change-event types, skips unchanged
digests, and reuses the existing scan service for tenant-scoped incremental
rescans linked to their predecessor.

The normative state, admission, privacy, and limitation contract is
`docs/HMAIR_H5_GOVERNANCE_CONTRACT.md`. This architecture is accepted only at
the source-and-fixture boundary; deployment, live sources, authoritative estate
denominators, retention/compaction, scale, and end-to-end acceptance remain
open.

## H6 operational truth boundary

Every active or passive collector is admitted only with explicit permissions,
privacy exclusions, evidence provenance, confidence, freshness, and every known
blind spot. Unsupported sources remain unsupported; a configured adapter is not
coverage. H6 diagnostics expose source health and gaps but never expose
credentials or raw customer content. Scan-summary compaction preserves the
immutable evidence, asset, resolution, finding, history, and audit authorities.
