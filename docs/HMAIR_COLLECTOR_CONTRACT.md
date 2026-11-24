# HMAIR Collector Contract

**Status:** H1 Task 5 normative compatibility boundary and implementation
accepted 2026-08-02. Acceptance evidence: `collector_sdk.py` SHA-256
`d300f8676eb667faeae6896a0713dd685470b6bb7a62077167a88a148ca3f289`,
`collector_registry.py` SHA-256
`a96f3c0c2e41bc1dab165495ecfcdc555a1474298dca31a74b3249e15db2f65d`,
and `test_hmair_collector_sdk.py` SHA-256
`bb5d6112853e36b67a04e91329a71970d3bcba8c8cd9fedb4a870f2909b3afdd`.
The focused suite passed 121 tests, the combined collector regressions passed
508 tests, and independent specification and quality reviews accepted the
slice with no findings.

This document defines the collector boundary for Hawk Multi-Signal AI
Resolution (HMAIR). It is grounded in Phase 2 and Phase 20 of the approved
HMAIR brief and the H1A implementation plan. It does not accept a concrete
collector, prove collector breadth, or enable active scanning.

## 1. Boundary and invariants

An HMAIR collector is a tenant-bound source reader that produces bounded
`DiscoveryObservationInput` records. It is not an asset resolver and has no
authority to create, merge, split, approve, or assign final Hawk AI Assets.

The following rules are mandatory:

- Collectors produce observations only.
- Every collector declares permissions, privacy behavior, health, data
  residency, active and passive capabilities, and known limitations.
- Unsupported source depth is explicit. It is never reported as an empty,
  successful, or equivalent result.
- Arbitrary payloads and records containing a final asset identifier such as
  `canonical_asset_id` are rejected at the collector boundary.
- A collector cannot infer authorization or control capability from its type,
  permissions, reachability, or health.
- Collection remains within the target's tenant, scope, exclusions, permitted
  methods, safety profile, rate limit, and active-scan setting.
- An observation is a claim supported by evidence. It is not, by itself, a
  canonical asset, proof of use, proof of reachability, or proof of control.

## 2. Mandatory collector declaration

Each HMAIR v2 declaration is immutable and bounded. It contains:

| Declaration value | Required meaning |
|---|---|
| `collector_id` | Stable bounded collector identifier. |
| `collector_type` | Registered collector family; registration does not imply that an implementation is enabled. |
| `version` | Collector implementation version. |
| `supported_targets` | Exact target types supported at the declared depth. |
| `active_capabilities` | Operations that initiate source queries or enumeration to gather current target state. An empty native-v2 value means no active capability is claimed. |
| `passive_capabilities` | Operations that consume telemetry or evidence already delivered to Hawk without initiating a source query. |
| `permissions_required` | Exact permissions required before execution. Missing permission is a terminal source outcome, not absence. An empty native-v2 value is an affirmative no-permission claim. |
| `sensitive_data_accessed` | Privacy disclosure for sensitive data categories the collector may access. An empty native-v2 value is an affirmative no-category claim and must be accurate. |
| `health` | One of `healthy`, `warning`, `degraded`, `offline`, or `unknown`. Health does not grant control authority. |
| `last_success_at`, `last_failure_at` | Timezone-aware lifecycle evidence when known; `null` means unknown or never recorded. |
| `data_residency` | Declared handling location or boundary. It must not be inferred from tenant location or deployment family. |
| `control_capability` | One of `inline`, `warn_only`, `monitor_only`, `external_required`, or `unknown`, copied only from declared authority. |
| `schema_version` | Version of the collector-declaration schema, distinct from the implementation `version`. |
| `limitations` | At least one explicit limitation, including unsupported depth and source-specific blind spots. |
| `declaration_hash` | For native v2, lowercase SHA-256 digest of the bounded v2 declaration material; the v1 compatibility exception is defined in Section 6. |

The declaration is an auditable capability statement, not proof that a scan
ran successfully. `healthy` means the collector reports healthy; it does not
mean the collector is inline, has permission, covers every target, or can stop
an AI action.

### Active and passive behavior

Active and passive capabilities are disjoint for each operation. An operation
is active when it initiates a query or enumeration against a source or target
to gather current state, including a read-only metadata API request. An
operation is passive only when it consumes telemetry, events, or snapshots
already delivered to or stored by Hawk without initiating a source request. A
collector may declare either, both, or neither, but it must not classify the
same operation as both.

`test_connectivity()` is a bounded, non-mutating preflight and does not produce
discovery evidence. If the preflight contacts a source, the applicable tenant,
RBAC, permission, permitted-method, feature-flag, and source-contact gates must
already be satisfied. Active collection additionally requires target-level
`active_scan_allowed`. Intrusive or high-permission behavior remains
default-off and requires explicit tenant configuration.

## 3. Eleven-method SDK protocol

The internal `HMAIRCollector` protocol contains exactly these eleven methods,
in addition to its immutable `declaration`:

| Method | Contract |
|---|---|
| `validate_configuration(configuration)` | Validate bounded configuration before source access. Do not expose secrets in errors. |
| `test_connectivity(target)` | Perform the smallest safe, non-mutating connectivity check and return a typed result. |
| `enumerate_scope(target)` | Return bounded scope items within the target's tenant, exclusions, and permitted methods. |
| `collect_inventory(scope)` | Return bounded inventory records for the permitted scope. |
| `collect_configuration(scope)` | Return bounded configuration metadata; do not extract secrets or raw records. |
| `collect_usage(scope)` | Return privacy-approved usage metadata. Configured or installed state is not observed use. |
| `collect_identity_hints(scope)` | Return hints only; downstream identity resolution remains authoritative. |
| `collect_relationship_hints(scope)` | Return hints only; downstream reachability resolution remains authoritative. |
| `emit_observations()` | Return only validated `DiscoveryObservationInput` objects. |
| `report_health()` | Return a bounded, sanitized health report. |
| `report_limitations()` | Return bounded explicit limitations and unsupported depth. |

All SDK return models are frozen, strict, bounded, and reject undeclared
fields. Collector records are temporary typed inputs to observation
construction; they are not a channel for arbitrary source payloads.

## 4. Generic runner

`collect_assignment_observations(collector, target)` is the only generic H1
collector runner. Its safe sequence is:

1. Validate collector configuration.
2. Check for cooperative cancellation.
3. Test target connectivity.
4. Check for cooperative cancellation.
5. Enumerate permitted scope.
6. Check for cooperative cancellation.
7. For each permitted scope item, run the five collection methods in order:
   inventory, configuration, usage, identity hints, and relationship hints.
8. Check for cooperative cancellation between every invoked collection
   method and between scope items.
9. Emit and validate observations.
10. Reject an empty observation set as an explicit terminal outcome.

The orchestrator validates the declaration, assignment, feature flags, target
scope, permissions, and configuration before enqueue and before any permitted
source contact. At the execution boundary, the runner revalidates
the H1 boundary by calling `validate_configuration()` with an empty immutable
mapping. Its `(collector, target)` signature supplies no additional source
configuration. A target's `credentials_reference` remains an opaque reference;
it is never replaced by credential material at this boundary.

The runner does not widen target or scope permissions. A collection method
runs only when permitted by the target and the scope item. A skipped or denied
method cannot be represented as successful coverage.

`report_health()` and `report_limitations()` remain mandatory, bounded,
queryable protocol operations. They are validated at the declaration or
explicit query boundary; neither is invoked by the generic runner. Neither
report replaces connectivity, permission, or observation evidence in a
collection run.

### Fail-closed outcomes

Expected non-success source outcomes are typed and closed:

- `unsupported`
- `permission_denied`
- `stale`
- `rate_limited`
- `empty`
- `cancelled`

The typed terminal exception contains only the closed status and a bounded,
sanitized safe message. Raw source exceptions, credentials, tokens, personal
data, payload fragments, and target records must not cross this boundary.

An unexpected collector fault remains a distinct failed assignment handled by
orchestration. It must not be translated to `empty`, `unsupported`, or “not
found.” One collector failure supports partial scan completion when another
selected source succeeds; it does not establish false absence.

## 5. Explicit registry

The H1 registry is a tenant-independent mapping of approved collector type to
implementation. It is protected by a lock and supports only:

- `register(collector_type, collector)`;
- `get(collector_type)`; and
- `list_declarations()`.

Registration is explicit. Duplicate collector types are rejected, unknown
types are errors, and declaration listing is deterministic. The registry does
not dynamically import modules, discover entry points, execute plugins, or
load code from declaration data. Registration by itself neither enables a
collector nor grants target access.

## 6. v1 compatibility boundary

Accepted `DiscoveryCollectorContract` v1 declarations remain operational under
their existing v1 contract. `collector_declaration_from_v1` provides a narrow,
fail-closed v2 projection only where the v1 declaration supplies an exact
mapping. The bridge:

- accepts only a validated `DiscoveryCollectorContract`, not a dictionary or
  arbitrary object;
- copies declared collector identity, type, version, health, lifecycle times,
  data residency, and control capability into their v2 counterparts;
- carries the v1 `contract_hash()` into `declaration_hash`;
- projects `observation_types_emitted` into `passive_capabilities` as
  non-operational compatibility vocabulary only; it does not classify the
  source collection as passive and cannot satisfy a passive-only gate;
- uses empty active-capability, required-permission, and sensitive-data-access
  compatibility placeholders because v1 does not declare those v2 meanings;
- maps `collector_type` to the single `supported_targets` value only when it is
  exactly equal to an approved `DiscoveryTargetType` value; otherwise the
  bridge rejects the projection instead of guessing; and
- never derives inline, warn-only, monitor-only, or other control authority
  from collector type, health, permissions, source system, or observation
  types.

Every accepted projection includes an explicit compatibility limitation for
v2 information that v1 cannot express. A v1 `permissions` status map is not a
v2 required-permissions declaration. The bridge therefore must not copy it
into `permissions_required`.

The empty v2-only tuples in a v1 projection are non-authoritative compatibility
placeholders, not affirmative claims that no permission or sensitive-data
access is required. A bridged declaration cannot satisfy an execution
permission or privacy gate and cannot make a collector runnable; that requires
a source-specific native v2 declaration and acceptance evidence.

For a native v2 declaration, `declaration_hash` covers its bounded v2
declaration material. For a v1 projection, the field carries the source v1
`contract_hash()` as required by the compatibility contract. That digest
covers only the canonical v1 hash domain; it does not attest the synthesized
v2 fields or compatibility limitation. No separate projection hash is claimed
in H1.

This compatibility boundary preserves existing v1 operation; it does not
claim that every v1 collector can be converted to a broad v2 declaration, and
it does not turn a pure v1 declaration adapter into a runnable HMAIR collector.
Broader target crosswalks or an unknown-target representation require separate
approval. Unsupported v2 depth remains visible rather than inferred.

## 7. Observation, evidence, and privacy boundary

An emitted observation uses the canonical bounded observation schema and
contains candidate type, identifiers, safe summaries and hints, evidence
reference and hash, signature status, confidence, freshness, sensitivity, and
redaction status. It cannot contain a final canonical asset ID.

Collectors and their downstream ingestion boundary must:

- retain only data needed for the declared observation and evidence claim;
- use metadata and safe summaries instead of raw prompts, raw database
  records, secret values, or unrestricted source content;
- redact secrets and personal data before persistence;
- preserve source evidence references and hashes without treating a hash as
  proof of truth;
- label sensitivity, redaction, freshness, and uncertainty truthfully; and
- comply with the declared data-residency and retention boundary.

For a native v2 declaration, `sensitive_data_accessed=()` does not waive
privacy review. It is an explicit statement that the collector does not
require a declared sensitive-data category and must be corrected if source
behavior changes. The non-authoritative v1 compatibility placeholder described
in Section 6 is not that affirmative statement.

Confidence belongs to an evidence-backed observation. It does not authorize a
collector to resolve an asset or make an unsupported conclusion. Resolution,
identity attribution, usage attribution, reachability, shadow classification,
Control Coverage, Policy, Evidence, Findings, and Control Graph updates remain
downstream responsibilities.

## 8. Required per-collector limitation record

Before any concrete collector can be accepted, its implementation and
documentation must state:

1. exact targets and source systems supported;
2. inventory, configuration, usage, identity, and relationship depth that can
   be discovered;
3. depth that cannot be discovered or is provider-dependent;
4. active versus passive operations;
5. permissions and tenant roles required;
6. sensitive data categories accessed and privacy/redaction behavior;
7. evidence produced, provenance, freshness, confidence methodology, and
   confidence limitations;
8. residency and retention behavior;
9. rate limits, backoff, cancellation, and partial-failure behavior;
10. known blind spots, bypass paths, and unsupported conclusions; and
11. the feature flag and tenant enablement gate.

If the source API cannot supply a required signal, the record states
`unsupported` or `unknown`; it does not fabricate parity with another provider.

## 9. H1 non-claims

No concrete HMAIR active collector is accepted or enabled in H1. Existing pure
collector declaration adapters and the endpoint metadata-scanner foundation
may be reused later, but their presence does not satisfy the HMAIR collector
acceptance gate.

H1 and this contract do not prove:

- an AI asset exists because a target or collector is configured;
- installed or configured software was used;
- configured reachability was exercised;
- Hawk can authorize, prove, or contain an activity path;
- an unknown candidate is shadow AI;
- every source or required collector depth is implemented;
- active scanning, canonical asset resolution, user attribution, UI
  completion, production scale, or enterprise acceptance is complete; or
- a collector is safe or effective without its source-specific tests,
  permission review, privacy review, and acceptance evidence.

This document and the cited evidence accept only the Task 5 SDK compatibility
boundary and registry. They do not accept a concrete HMAIR active collector,
the Phase 20 per-collector operational-document program, or broader H1.

## 10. H4 catalog-backed metadata collectors

H4 extends this unchanged SDK with a closed profile catalog and one canonical
passive adapter. A profile fixes provider family, target type, source surface,
observation types, metadata depth, permissions, privacy exclusions, residency,
denominator behavior, supported connection modes, and limitations. Signals are
accepted only when their profile, target type, surface, observation type, and
connection mode match the catalog declaration.

Catalog registration remains non-evidence-bearing. Live-source eligibility
still requires tenant and target binding, customer authority, source health,
current evidence, and the scan-readiness contract. Generic connector inventory
is projected as `observed`, never `actively_used`; only an explicit usage signal
may establish usage. The per-profile matrix is maintained in
`docs/HMAIR_H4_COLLECTOR_COVERAGE.md`.
