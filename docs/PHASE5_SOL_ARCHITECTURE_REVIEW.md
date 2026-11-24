# Phase 5 Sol Architecture Review

## Review identity

- Contract: `PHASE5-P0-CAEIC-1`
- Approved approach: `A — Versioned additive Hawk spine`
- Architecture authority: GPT-5.6 Sol, Extra High
- Implementation model exception: GPT-5.6 Terra, explicitly approved by the
  user because Luna and Codex Spark are unavailable
- Review state: `PRE_BUILD_ARCHITECTURE_APPROVED_PENDING_PLAN_HASH`

## Repository-grounded baseline

The repository already contains the Phase 5 authority spine. Phase 5 is an
extension and compatibility program, not a greenfield rewrite.

| Concern | Existing authority | Phase 5 action |
|---|---|---|
| Canonical action | `app.core.control_engine.canonical_action` and `receipt_service` | Add a versioned V2 projection and V1 verifier |
| Policy decision | `AuthorizationRequest`/`AuthorizationResponse` | Preserve as sole decision authority |
| Principal and delegation | AI IAM and `SubjectExecutionContext` | Generalize banking leakage in place |
| Approval | `ApprovalBinding`, `ApprovalRequest`, `ToolFingerprint` | Add exact signed V2 binding; keep authorities distinct |
| Control selection | persisted Phase 4 composed ControlPlan | Extend requirements; do not duplicate |
| Decision/execution evidence | Decision Receipt, Execution Receipt, Integrity Result | Add V2 material and explicit lifecycle dimensions |
| Local OS authority | endpoint permit broker | Link consumption/non-execution into common receipts |
| Domain context | business-purpose sector/function profiles | Add reviewed semantic profiles without policy logic |
| Product evidence | Action Trace/Graph, Findings, Evidence, Coverage | Compose and repair existing projections |

## Confirmed architectural gaps

1. `SUBJECT_BINDING`, `BUSINESS_PURPOSE_BINDING`, and `AUTHORITY_BINDING`
   exist as capability dimensions but are not mandatory selector requirements.
2. No one versioned vertical-neutral target/destination resolver contract exists.
3. Material fields are duplicated across receipt, approval, banking, and
   cross-provider projections; no authoritative materiality profile exists.
4. `SubjectExecutionContext` leaks banking concepts into generic core.
5. Domain-profile persistence lacks strong uniqueness, schema version, content
   hash, and effective-period semantics.
6. No generic server-side single-use Execution Permit exists; the closest seam
   is the banking execution grant.
7. Policy currentness differs between general receipts and endpoint permits.
8. Material integrity and business outcome are conflated.
9. Async, non-execution, delegation, and persistent-effect receipt semantics are
   incomplete.
10. Native/endpoint evidence quality is not normalized for bundles and coverage.

## Frozen architecture decisions

### AD-01 — One authority spine

All Phase 5 paths reuse one canonical action, policy decision, receipt/evidence,
graph, and coverage chain. Vertical adapters and provider controls project into
that chain.

### AD-02 — Versioned V2, no reinterpretation

`canonical-ai-action/2.0`, `decision-receipt/2.0`, approval binding V2, and
execution receipt V2 are explicit versions. Existing signed evidence remains
verifiable under its original version. Backfill cannot invent proof.

### AD-03 — Execution-authoritative equivalence is closed and fail-closed

Equivalence may authorize reuse only when all material is resolved, verified,
version-compatible, current, and equal under the reviewed materiality profile.
Any `UNKNOWN`, contradiction, version drift, or missing authority is not
execution-authoritatively equivalent.

### AD-04 — Generalize subject context in place

The generic context uses represented subject and typed resource scope. Banking
account/mobile/customer fields move behind compatibility aliases and the
banking profile/adapter. No second subject authority is added.

### AD-05 — Consequential actions always require subject, purpose, and authority truth

These Phase 4 capability dimensions are mandatory for every consequential
action. A domain profile may add requirements but may never remove or weaken
core subject, purpose, authority, or materiality requirements. Unsatisfied
requirements return `CONTROL_REQUIREMENT_UNSATISFIED`; no observe-only
downgrade is presented as authorization.

### AD-06 — Profiles are declarative context, not policy

Domain profiles select vocabulary, normalized resolvers, materiality rules,
invariants, and outcome checks. They cannot return an authorization decision or
override policy.

### AD-07 — One materiality authority

Canonicalization, trusted approval rendering, permit issuance,
pre-execution revalidation, comparator logic, and conformance all consume the
same versioned materiality profile.

### AD-08 — Positive policy epoch for executable authority

New consequential V2 decisions, approvals, and permits require a positive,
current policy epoch. Material policy change invalidates incompatible unconsumed
authority.

The sole authority is the tenant-scoped `TenantPolicyEpoch` defined in
`docs/CODEX_INTERFACE_REGISTRY.md`. Material policy changes bump it in the same
transaction as the mutation; rollback activates prior content at a new higher
epoch.

### AD-09 — Execution and outcome are separate dimensions

Material integrity, execution state, and expected-outcome integrity are stored
and reported independently. `MATCHED + FAILED` is valid evidence and is never
displayed as successful completion.

### AD-10 — Generic server permit, local endpoint permit preserved

The generic record becomes the sole new V2 server execution-attempt authority.
The existing banking grant becomes a one-to-one compatibility projection when
V2 is authoritative. Endpoint permits remain broker-owned and format-compatible;
Phase 5 adds server linkage and consumption proof only.

### AD-11 — Durable complex-action lifecycle

Async transitions, multi-step progress, persistent effects, delegation edges,
and non-execution are durable, tenant-bound evidence. A process-local queue is
not an authoritative lifecycle.

### AD-12 — Existing product authorities remain distinct

`ApprovalRequest`, `ApprovalBinding`, remediation approval, direct finding
enforcement, and AGUI demo contracts are not interchangeable. Phase 5 Action
Detail links to the real authority for the action.

### AD-13 — Canonical identifier and navigation contract

Action Trace/Graph routes use the runtime event ID. Canonical action ID,
receipt action ID, selection action ID, and event ID are returned as separate
typed fields. Finding browser routes use `/discovery/findings/{id}`. API paths
are not emitted as browser hrefs.

### AD-14 — Tenant-scoped durable metrics before product exposure

Process-local unscoped counters remain internal. Phase 5 metrics exposed to the
product require tenant-safe dimensions and an existing durable/export boundary.

### AD-15 — Feature flags default off

No V2 write, generic permit, or Phase 5 product projection becomes authoritative
until migration, compatibility, regression, and Sol gates pass.

Tenant rollout modes and issuance restrictions are frozen in
`docs/CODEX_INTERFACE_REGISTRY.md`.

### AD-16 — Immutable linked V2 receipt storage

V2 Decision and Execution Receipts use existing base receipt rows plus required
one-to-one immutable extension rows created in the same transaction. V1/V1.1
signed bodies remain unchanged. Verification dispatches exactly by schema
version; a missing extension or unknown version fails verification.

### AD-17 — Purpose-separated signing

Domain profile, Decision Receipt, Approval Binding, Execution Permit, and
Execution Receipt signatures use distinct key purposes through one KMS/HSM
provider abstraction. Production cannot use the local development key provider.
Rotation, verify-only history, revocation, algorithm, tenant, and key ID remain
explicit. Approval and permit lifecycle events, execution comparisons and
transitions, action plans, persistent effects, delegation contexts, and outcome
contracts/verifications use the exact purpose/domain mappings frozen in
`docs/CODEX_INTERFACE_REGISTRY.md`. Approval-authority events and permit
transitions use their corresponding approval-binding and execution-permit
purposes under their own declared domains; the remaining listed lifecycle
objects use their separately listed purposes. An implementation may not collapse
distinct purposes or reuse active key material across them.

### AD-18 — Frozen protocol registry

The signed schemas, canonical bytes, state machines, profile envelope,
evidence/comparator mappings, Action Detail IDs, rollout authority, coverage
dimensions, and finding producers are frozen in
`docs/CODEX_INTERFACE_REGISTRY.md`. An implementation deviation requires replan
and a new plan hash.

## Migration decision

Migrations `0062`, `0063`, and `0064` are treated as the repository's intended
Phase 4 baseline for planning because current code and migration-aware tests
depend on them. After `SOL_BUILD_APPROVAL` and before WU-B begins, WU-00 performs
a non-mutating preflight against the backed-up persistent PostgreSQL database
and proves that its current migration state and the repository graph resolve to
one `0064` head. That persistent preflight may inspect metadata and migration
state but may not upgrade, downgrade, write schema/data, or alter the backup.
Fresh temporary SQLite migration proof remains separate. Failure is
`ARCHITECTURE_ESCALATION_REQUIRED`; implementation must not write `0065` or fork
the chain.

Migration ownership and contents are closed:

| Migration | Exclusive owner | Permitted contents |
|---|---|---|
| `0065` | WU-B | reviewed domain profiles and tenant selection, `TenantPolicyEpoch`, and tenant rollout authority only |
| `0066` | WU-D | immutable V2 Decision/Execution/Approval extension storage and all predeclared approval, permit, attempt, transition, action-plan, persistent-effect, delegation, and outcome lifecycle persistence required by the frozen registry |
| `0067` | WU-H | product-facing Control Coverage and product projection persistence only; no receipt, approval, permit, execution, or lifecycle authority schema |

WU-E, WU-F, and WU-G consume the schema predeclared by WU-D in `0066`; they do
not create later authority or lifecycle migrations. WU-J verifies the linear
`0064 -> 0065 -> 0066 -> 0067` chain on fresh and upgraded databases but owns no
new migration semantics. Any missing or incompatible field discovered after its
owning migration is approved requires Sol escalation and a replan rather than
schema drift in a later migration.

## Dirty-worktree ownership decision

The working tree contains user and prior-phase changes. Phase 5 uses exclusive
WorkUnit path ownership and serializes edits to architecture-critical shared
files. No reset, checkout, clean, stage, commit, merge, push, or discard action
is authorized.

Shared critical locks:

- canonical action and receipt service;
- evidence/policy/runtime models;
- migrations;
- native-control requirements and selection;
- central API schemas/types;
- central web API/types.

## Rejected approaches

- Parallel V2 service/tables: rejected because it creates two authorization and
  receipt authorities.
- Profile-only overlay: rejected because it cannot prove execution fidelity.
- Embedded domain policy engines: rejected because profiles must not decide.
- Inference-based legacy promotion: rejected because old evidence cannot gain
  missing material after signing.

## Pre-existing defects in Phase 5 scope

- action/finding investigation links can generate 404s due to route-ID and
  browser-path mismatches;
- Interaction Security “All” approvals currently resolves to Pending;
- Action Detail omits existing control-plan, blind-spot, evidence-node, and
  remediation data;
- evidence totals and native acceptance truth are incompletely projected.

These defects are corrected only as required for truthful Phase 5 product
integration. They do not authorize broad UI redesign.

## Architecture conclusion

Approach A is coherent, additive, compatible, and capable of satisfying the
Phase 5 security property. Production code remains blocked until the plan hash,
requirements traceability, security invariants, and formal Sol build approval
are complete. After that approval, WU-00's non-mutating persistent PostgreSQL
`0064` preflight and Sol review remain mandatory dependencies before WU-B or
`0065` work may begin.
