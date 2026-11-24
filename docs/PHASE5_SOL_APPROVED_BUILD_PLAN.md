# Phase 5 P0 Sol Build Plan — Revision R2 Pending Approval

> **For agentic workers:** REQUIRED SUB-SKILL: Use
> `subagent-driven-development` with test-driven development. GPT-5.6 Terra is
> the only approved production implementation model for this plan. GPT-5.6 Sol
> Extra High owns every architecture, security, review, correction, capability,
> and final-acceptance decision.

**Goal:** Extend Hawk's existing authority spine so every consequential action
has vertical-neutral, exact, versioned authorization and execution proof without
creating a parallel policy, identity, receipt, evidence, graph, or coverage
system.

**Architecture:** Add a V2 projection over the existing Canonical AI Action,
Decision/Execution Receipt, ApprovalBinding, Phase 4 ControlPlan, endpoint
permit, AI IAM, findings, and coverage authorities. Introduce reviewed
declarative domain profiles, one materiality contract, a generic server-side
execution permit, and durable execution/outcome lifecycles while preserving V1
verification and vertical adapters.

**Tech Stack:** Python 3.12, FastAPI, SQLAlchemy 2, Alembic, PostgreSQL 16,
SQLite test fixtures, Pydantic/dataclasses, pytest, Hypothesis where already
available, TypeScript, Next.js, React, existing Docker demo stack.

---

## Plan identity and gates

- Plan ID: `PH5-P0-CAEIC-A-R2`
- Recorded plan hash: `PENDING_SOL_HASH`
- Rejected R2 candidate: six-input digest
  `d196fc5112d3b8ca02b374714cd2ddd1ec7f3baf2d74fb014a78648df3bf9163`;
  rejected because it did not bind the Docker build closure or exact migration/
  restore guards. It grants no execution authority.
- Rejected R2 candidate: seven-input digest
  `57402bffd0daebe20fcb1e4777f5061dc1725658e3fbfbd81d3a8d0007aaad44`;
  rejected because it combined mutable-base image construction and database
  migration authority, misbound Docker digest semantics, used an invalid free-
  space expression, and lacked exact post-upgrade evidence. It grants no
  execution authority.
- Rejected R2 candidate: seven-input digest
  `59c67d5a609440c4c3ccdc581d42619571abe4360c28704fc49c475d00b095a6`;
  rejected because WU-00I was not a complete SGE-1.0 packet, its Compose-based
  inspection inherited database-connectable configuration, its parser treated
  the Buildx v0.36 SLSA predicate as a full in-toto statement, and WU-00M did
  not freeze deterministic success and rollback-intact health evidence. It
  grants no execution authority.
- Superseded plan: `PH5-P0-CAEIC-A-R1`, hash
  `ba7370116e883533f1ea753d80e1bab885367d81466e8b39984dae6e26225b39`.
  Its formal approval was invalidated by the WU-00 persistent-database
  escalation and permits no further execution.
- Plan hash: SHA-256 of the immutable ordered artifact manifest defined below.
  After Sol review, the computed value replaces `PENDING_SOL_HASH` on the
  recorded-plan-hash line and is also recorded in
  `docs/PHASE5_P0_EXECUTION_LEDGER.md`.
- Contract: `PHASE5-P0-CAEIC-1`
- Formal build state: `R2_PENDING_HASH_REVIEWS_AND_SOL_BUILD_APPROVAL`; no
  implementation or operational recovery WorkUnit is currently permitted
- VCS state: no staging, commits, merges, pushes, resets, checkouts, cleans, or
  discards are permitted
- Approved dirty-tree baseline substitute: the user approved
  `docs/validation/phase5-baseline-tree-manifest.md`, combined digest
  `ebd1dfe7c5aeacca320e6cca7db13e3d75015fb583e97fc75f17af27782362ab`,
  on 2026-08-24. The manifest supplements baseline commit
  `d6f5faacab5058c24f34202bcd66951eb54ae058`; it does not make the dirty tree
  clean or authorize unrelated changes.
- Approved worker-isolation variance: on 2026-08-24 the user approved the
  exclusive-path shared-workspace protocol instead of isolated branches or
  worktrees. Every WorkUnit retains exclusive allowed paths and critical-file
  locks. This variance does not authorize VCS mutation, overlapping ownership,
  automatic conflict resolution, or modification outside the active packet.
- Critical-file concurrency: one writer at a time
- Maximum active implementation agents: four, only for explicitly independent
  non-overlapping WorkUnits
- R2 initial execution gate: after and only after the new canonical hash,
  independent architecture/security/product hash reviews, stamp-invariance
  proof, and a new `SOL_BUILD_APPROVAL_PH5_P0_CAEIC_A_R2`, the sole initially
  permitted WorkUnit is the no-database-mutation image stage `PH5-WU-00I`
- R2 image gate: `PH5-WU-00M` requires `PH5-WU-00I:PASS` and both Sol image
  review envelopes recording `PH5-M0-IMAGE:APPROVED`; no database mutation is
  permitted before that checkpoint
- R2 recovery gate: `PH5-WU-00` requires `PH5-WU-00M:APPROVED`; WU-A and all
  later work retain their existing dependency and dual-Sol-review gates

Immutable plan inputs, in this exact order (seven files):

- `docs/PHASE5_SOL_APPROVED_BUILD_PLAN.md`
- `docs/PHASE5_SOL_ARCHITECTURE_REVIEW.md`
- `docs/PHASE5_SOL_SECURITY_INVARIANTS.md`
- `docs/CODEX_INTERFACE_REGISTRY.md`
- `docs/PHASE5_P0_REQUIREMENTS_TRACEABILITY.md`
- `docs/superpowers/specs/2026-08-24-phase5-vertical-agnostic-action-execution-integrity-design.md`
- `docs/validation/phase5-wu00m-build-input-manifest.md`

For each UTF-8 file, normalize line endings to LF and require exactly one final
newline. The build-plan file has one additional canonicalization step to avoid
self-reference: find exactly one line whose complete normalized content is
either `- Recorded plan hash: \`PENDING_SOL_HASH\`` or
`- Recorded plan hash: \`<64 lowercase hexadecimal characters>\`` and replace
that complete line with `- Recorded plan hash: \`PENDING_SOL_HASH\``. Reject
hash construction if the line is missing, duplicated, or has any other value.
No other byte substitution is permitted.

For each input in the order above, compute SHA-256 over its normalized canonical
bytes. The manifest is the UTF-8 concatenation
`relative_path + "\n" + lowercase_sha256 + "\n"` for each input. The plan hash
is SHA-256 of the complete manifest bytes. Stamping that final hash on the one
recorded-plan-hash line therefore does not alter the canonical plan digest. The
mutable execution ledger is excluded; it records but does not define the hash.

## File structure and ownership

### New focused modules

- `apps/api/app/core/control_engine/action_integrity_types.py` — immutable
  vertical-neutral principal, subject, resource, authority, quantity, semantics,
  and lifecycle enums/value objects.
- `apps/api/app/services/action_integrity/domain_profiles.py` — reviewed profile
  parsing, hashing, effective-date validation, tenant selection, and pure
  invariant evaluation.
- `apps/api/app/services/action_integrity/materiality.py` — the sole versioned
  material-field registry and exact projection helper.
- `apps/api/app/services/action_integrity/resolvers.py` — closed target and
  destination resolver registry and normalized results.
- `apps/api/app/services/action_integrity/canonical_v2.py` — V1-to-V2 safe
  projection, deterministic V2 bytes/hash, and semantic equivalence.
- `apps/api/app/services/action_integrity/execution_authority.py` — generic
  server-side permit issuance, append-only projection reconstruction, final-
  transaction claim/revalidation for the audited server executors, and linked
  non-server authority evidence.
- `apps/api/app/services/action_integrity/execution_proof.py` — V2 execution
  projection, comparator, evidence quality, drift, and outcome integrity.
- `apps/api/app/services/action_integrity/complex_actions.py` — multi-step,
  async, persistent-effect, delegation, and expected-outcome lifecycle.
- `apps/api/app/db/models/action_integrity.py` — WU-B first adds only reviewed
  profiles, tenant selections, policy epoch, and rollout records; WU-D then
  adds the predeclared V2 receipt/approval extensions, generic permit/attempt,
  permit/execution transition, persistent-effect, delegation, expected-outcome,
  outcome-verification, and reconstructable projection models.
- `apps/api/app/api/routers/action_integrity.py` — tenant-scoped read/mutation
  endpoints that reuse existing authorization dependencies.
- `apps/api/app/db/migrations/versions/0065_phase5_action_integrity_core.py` —
  reviewed profile, tenant selection, policy epoch, and rollout persistence
  only.
- `apps/api/app/db/migrations/versions/0066_phase5_execution_lifecycle.py` —
  V2 receipt/approval extensions plus all predeclared permit, attempt,
  approval-use, permit/execution transition, persistent-effect, delegation,
  expected-outcome/outcome-verification persistence and the one-to-one banking
  compatibility link.

### Existing critical files with serial ownership

- `apps/api/app/services/subject_execution_context_service.py`
- `apps/api/app/core/control_engine/canonical_action.py`
- `apps/api/app/services/receipt_service.py`
- `apps/api/app/db/models/evidence.py`
- `apps/api/app/db/models/policy.py`
- `apps/api/app/db/models/banking_transaction.py`
- `apps/api/app/db/models/runtime_intelligence.py`
- `apps/api/app/services/native_control/requirements.py`
- `apps/api/app/services/native_control/selector.py`
- `apps/api/app/services/native_control/selection_service.py`
- `apps/api/app/services/llm_gateway_secure/gateway.py`
- `apps/api/app/services/llm_gateway_service.py`
- `apps/api/app/services/mcp/registry.py`
- `apps/api/app/services/agui/registry.py`
- `apps/api/app/services/endpoint_agent_service.py`
- `apps/api/app/services/ai_orchestration/itsm.py`
- `apps/api/app/services/remediation/remediation_engine.py`
- `apps/api/app/api/routers/enforcement.py`
- `apps/api/app/db/models/__init__.py`
- `apps/api/app/main.py`
- `apps/web/src/lib/api.ts`
- `apps/web/src/lib/types.ts`

No WorkUnit may edit an existing critical file outside its exclusive ownership
window.

---

## Materialized SGE WorkUnit packets

The formal `SOL_BUILD_APPROVAL` materializes each template with its exact
manifest hash. `plan_hash` below therefore means exactly the hash in that
approval, not a worker-supplied value. Every path not listed is forbidden;
repository/VCS mutation and `apps/api/local_runtime.db*` are forbidden for all
packets. All packets read the seven immutable plan inputs, including the active
interface registry and the immutable build-input manifest assigned exclusively
to WU-00I. Its legacy `phase5-wu00m` filename is not WU-00M build authority and
cannot be renamed without changing its byte identity. A packet's focused
`read_context` identifies the sections
that must be applied directly; it does not weaken any other immutable contract.

The seven immutable plan inputs are governance inputs, never implementation
outputs. WU-00I, WU-00M, WU-00, and WU-A through WU-I return their bounded result/evidence packet
to the orchestrator and do not write the execution ledger. After the applicable
Sol diff review, the orchestrator owns recording that result and review state in
the mutable ledger. WU-J's exclusive ledger path permits only WU-J's final
coordination/reporting work; it does not grant any earlier worker a ledger write
or create a second lifecycle authority. PH5-WU-00I is the sole one-time image
construction and no-network inspection packet. PH5-WU-00M is a separate
one-time operational recovery packet with no repository write paths; it may
only use the unchanged M0-approved image for the controlled PostgreSQL
migration and has no build, load, pull, tag, or replacement authority.

### PH5-WU-A packet

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-A
  requirement_ids: [16,17,18,19,20,21,58,60]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: implement complete tenant-safe neutral core and remove generic banking leakage
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-00:APPROVED]
  allowed_paths: [action_integrity_types.py, subject_execution_context_service.py,
    banking_subject_context_service.py, native_control/requirements.py,
    native_control/selector.py, test_phase5_neutral_core.py,
    test_subject_execution_context.py, test_native_control_requirements.py,
    PHASE5_VERTICAL_AGNOSTIC_AUDIT.md]
  forbidden_paths: [receipts, approvals, permits, migrations, web, all unlisted]
  read_context: [interface-registry §§1,3,15; invariants SI-01..SI-13]
  frozen_interfaces: [BoundedReference, PrincipalContext,
    RepresentedSubjectContext, ResourceScope, AuthorityContext,
    ValueOrQuantity, ActionSemantics, subject/resource/purpose/authority finding
    producer contracts]
  required_invariants: [SI-01..SI-03, SI-06..SI-09, SI-11, SI-22, SI-23]
  compatibility_requirements: [banking aliases remain adapter-only and deprecated;
    unresolved legacy material maps to tagged UNKNOWN]
  acceptance: [all required fields bounded/immutable/tenant-explicit; consequential
    subject/purpose/authority mandatory; banking proof path unchanged;
    owned services emit exact subject/resource/purpose/authority finding
    code/evidence/deduplication/lifecycle payloads]
  focused_tests: [test_phase5_neutral_core.py, test_subject_execution_context.py,
    test_native_control_requirements.py, test_banking_transaction_integrity_api.py]
  risk: CRITICAL
  security_sensitivity: identity, subject, resource, authority
  parallel_safe: false
}
```

### PH5-WU-B packet

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-B
  requirement_ids: [22,23,26,29,32,54,58,62,76]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: implement signed declarative profiles, materiality/resolvers,
    purpose-separated signing, tenant policy epoch, rollout authority, and the
    profile/selection/epoch/rollout-only 0065 migration
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-A:APPROVED, PH5-WU-00:APPROVED]
  allowed_paths: [action_integrity/__init__.py,
    action_integrity/domain_profiles.py,
    action_integrity/materiality.py, action_integrity/resolvers.py,
    action_integrity/signing.py, action_integrity/policy_epoch.py,
    db/models/action_integrity.py, db/models/policy.py, db/models/__init__.py,
    core/config.py, policy_service.py, migration 0065, test_phase5_domain_profiles.py,
    test_phase5_materiality.py, test_phase5_resolvers.py,
    test_phase5_signing_key_provider.py, test_phase5_policy_epoch.py,
    test_phase5_migration_0065.py]
  forbidden_paths: [canonical V2, receipts, permits, execution, web, all unlisted]
  read_context: [interface-registry §§4,5,7,11,13,15; invariants SI-10..SI-18]
  frozen_interfaces: [DomainSemanticProfileV1, DomainInvariant result,
    ResolutionResult, MaterialityProfileV1, closed MaterialFieldPathV1 grammar,
    exact per-field/materiality/profile hashes, SigningKeyProvider and exact
    signature input/base64url/algorithm encoding,
    TenantDomainProfileSelectionV1 signed chain/reconstructable projection,
    TenantPolicyEpoch, TenantActionIntegrityRollout,
    DOMAIN_INVARIANT_FAILED finding producer contract]
  required_invariants: [SI-02, SI-03, SI-06, SI-10..SI-17, SI-22, SI-23,
    SI-25, SI-26]
  compatibility_requirements: [0065 down_revision=0064; local HMAC forbidden in
    production; epoch never decreases; flags default disabled]
  acceptance: [signed/tamper-safe tenant profile and gap-free signed selection
    chain; gap/fork/broken-prior-hash/projection-rewind or mismatch fails closed;
    exact closed path grammar, collection semantics and hashes; no executable
    profile behavior; purpose-separated keys and strict signature encoding;
    monotonic transactional epoch; rollout cannot issue V2 authority outside
    AUTHORITATIVE; 0065 contains no receipt, approval, permit, attempt,
    transition, effect, delegation, or outcome persistence; invariant evaluator
    emits exact finding evidence/dedup/lifecycle payload]
  focused_tests: [six listed Phase 5 suites plus selection-chain reconstruction,
    material-hash golden vectors, signature encoding, business-purpose and config]
  risk: CRITICAL
  security_sensitivity: signing, policy currentness, tenant configuration
  parallel_safe: false
}
```

### PH5-WU-C packet

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-C
  requirement_ids: [24,25,26,27,28,29,30,58,61]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: implement exact CanonicalAIActionV2 bytes/hash and structured equivalence
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-B:APPROVED]
  allowed_paths: [action_integrity/canonical_v2.py, canonical_action.py,
    receipt_service.py, native_control/cross_provider_conformance.py,
    test_phase5_canonical_action_v2.py, test_phase5_semantic_equivalence.py,
    test_canonical_ai_action_contract.py]
  forbidden_paths: [receipt persistence/signing, approval, permits, migrations,
    web, all unlisted]
  read_context: [interface-registry §§1,2,5,6,15;
    invariants SI-02,SI-03,SI-10,SI-11]
  frozen_interfaces: [hawk-canonical-json/2.0, CanonicalAIActionV2,
    ActionPlanBindingV1 tagged cases, closed MaterialFieldPathV1 grammar,
    exact per-field/material-fields/unbound-planned-action hashes,
    non-circular root/plan/step/child hash construction with exact child
    action_id and parent_action_id binding,
    SemanticComparisonResult, TOOL_FINGERPRINT_CHANGED and
    UNKNOWN_ACTION_SEMANTICS finding producer contracts]
  required_invariants: [SI-02, SI-03, SI-06, SI-10, SI-11, SI-13, SI-14,
    SI-22, SI-23]
  compatibility_requirements: [exact V1 verification unchanged; V1 adapter adds
    only tagged UNKNOWN; unknown/cross-version ambiguity never authorizes]
  acceptance: [cross-language golden bytes; closed material paths and collection
    semantics resolve exactly; every material mutation changes the correct
    per-field/full/unbound hash; all ActionPlanBindingV1 cases and invalid
    combinations, alternate child IDs/parents, and binding-cycle substitutes
    fail deterministically; exact/semantic/non-material/unresolved
    differences losslessly reported; canonical bytes remain the sole §7 signing
    input payload without alternate wrapping; owned canonical/fingerprint
    services emit exact finding evidence/dedup/lifecycle payloads]
  focused_tests: [three listed suites plus material-field/hash/plan-binding golden
    vectors, authorization, conformance, banking transport and approval binding]
  risk: CRITICAL
  security_sensitivity: canonicalization and authorization material
  parallel_safe: false
}
```

### PH5-WU-D packet

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-D
  requirement_ids: [31,32,33,34,35,36,58,61,62]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: implement immutable V2 receipt/approval extensions, exact signing,
    trusted ApprovalRequest binding, atomic approval decision flow, and
    migration 0066 schema
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-C:APPROVED, PH5-M1-CORE:APPROVED]
  allowed_paths: [db/models/evidence.py, db/models/policy.py,
    db/models/action_integrity.py, db/models/banking_transaction.py,
    db/models/runtime_intelligence.py,
    receipt_service.py,
    action_integrity/approval_binding.py, api/routers/enforcement.py,
    migration 0066,
    test_phase5_decision_receipt_v2.py, test_phase5_approval_binding_v2.py,
    test_phase5_approval_decision_atomicity.py, test_phase5_migration_0066.py,
    test_decision_execution_receipts.py,
    test_depth_upgrade_approval_authority.py]
  forbidden_paths: [permit service, execution comparator, web, all unlisted]
  read_context: [interface-registry §§5,7,8,10,11,12; invariants SI-03..SI-17]
  frozen_interfaces: [DecisionReceiptV2, ApprovalBindingV2, immutable extension
    storage, exact version dispatch, material fields hash and
    PermittedVariationEnvelopeV1 binding, ActionPlanBindingV1 through the bound
    canonical-action/material hashes, exact-only root envelope and root-only
    matcher material for SCOPED_PARENT_PERMIT, exact signature input/base64url/
    algorithm encoding, append-only ApprovalAuthorityEventV1 and reconstructable
    ApprovalAuthorityProjection, approval states/use envelope,
    ApprovalRequest/ApprovalBindingV2 atomic decision transaction, exact
    registry trusted-approval DTO and approval list/decision API contracts,
    APPROVAL_INVALIDATED finding producer contract]
  required_invariants: [SI-01..SI-03, SI-06, SI-09, SI-11, SI-13..SI-17,
    SI-21..SI-23, SI-25, SI-28]
  compatibility_requirements: [V1/V1.1 bytes/signatures unchanged; 0066 follows
    0065; legacy approval hash is not presented as a signature]
  acceptance: [purpose-separated signing/rotation/revocation and strict signature
    encoding; canonical trusted rendering/API schema; role/SLA/currentness
    enforced; exact-only and bounded signed variation envelopes bind every hash;
    scoped-parent approval binds only the exact plan root and cannot match or
    vary child material;
    request and binding decision commit or roll back together; approval use/
    expiry/replay enforced from a freshly reconstructed append-only projection;
    gap/fork/broken-prior-hash/rewind/projection mismatch fails closed;
    approval service emits exact invalidation finding evidence/dedup/lifecycle;
    0066 exclusively creates all frozen V2/lifecycle persistence and banking
    link; migration passes]
  focused_tests: [six listed suites plus variation envelope, signature encoding,
    approval projection reconstruction, evidence bundle, policy and tenant tests]
  risk: CRITICAL
  security_sensitivity: cryptography and approval authority
  parallel_safe: false
}
```

### PH5-WU-E packet

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-E
  requirement_ids: [32,36,37,39,58,61]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: implement the sole V2 server Execution Permit authority, wire every
    audited server-controlled final seam, and classify linked non-server authority
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-D:APPROVED]
  allowed_paths: [action_integrity/execution_authority.py,
    native_control/endpoint_permit_authority.py,
    banking_transaction_integrity_service.py, llm_gateway_secure/gateway.py,
    llm_gateway_service.py, mcp/registry.py, agui/registry.py,
    endpoint_agent_service.py, ai_orchestration/itsm.py,
    remediation/remediation_engine.py, test_phase5_execution_permit.py,
    test_phase4_native_endpoint_permit_authority.py,
    test_banking_transaction_integrity_api.py,
    test_llm_gateway_secure_hardening.py, test_llm_gateway_integration.py,
    test_llm_response_control_chain_contract.py, test_mcp_registry.py,
    test_mcp_core_tools_registry.py, test_agui_registry.py,
    test_agui_core_actions_registry.py, test_endpoint_agent.py,
    test_ai_orchestration_layer.py, test_remediation_workflow.py,
    test_phase5_server_execution_permit_integration.py]
  forbidden_paths: [canonical/schema changes, execution receipt/comparator, web,
    all migrations, all unlisted]
  read_context: [interface-registry §§5,7,8,10,15; invariants SI-03..SI-18]
  frozen_interfaces: [ExecutionPermit signed body/state and append-only
    projection reconstruction, PermittedVariationEnvelopeV1, exact material
    fields hash, ActionPlanBindingV1, two-lane SCOPED_PARENT_PERMIT root/child
    evaluation and exact root/plan/step/child digest chain, signature
    input/base64url encoding,
    claim/consume transaction, audited server-controlled final-executor seam
    classification, BankingExecutionGrant compatibility, linked endpoint/non-
    server authority evidence, EXECUTION_PERMIT_MISMATCH and
    CONTROL_PLAN_DOWNGRADED finding producer contracts]
  required_invariants: [SI-01..SI-06, SI-09..SI-11, SI-13..SI-18,
    SI-21..SI-23, SI-25, SI-26, SI-28]
  compatibility_requirements: [generic permit is sole V2 authority; legacy V1
    banking and all audited disabled/legacy paths unchanged; endpoint wire
    format unchanged; direct human/admin REST authority unchanged unless the
    request is explicitly projected as authoritative V2]
  acceptance: [exact atomic single consumer; every authoritative V2 server seam
    claims and revalidates immediately before its protected executor; mismatch
    or block never invokes; disabled/legacy and direct human/admin authority
    remain unchanged; linked non-server paths make no false server-execution
    claim; scoped-parent root/envelope/plan/step/child/count/use checks are exact
    and no envelope matcher widens child material; crash/retry/replay/expiry/revocation/policy/material/projection
    mismatch behavior proven; owned permit/final-gate service emits exact
    finding evidence/dedup/lifecycle]
  focused_tests: [all 14 listed existing/new suites plus concurrency, tenant,
    executor-spy and linked-authority classification tests]
  risk: CRITICAL
  security_sensitivity: pre-execution authority and replay prevention
  parallel_safe: false
}
```

### PH5-WU-F packet

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-F
  requirement_ids: [32,38,39,40,41,42,58]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: implement V2 execution proof, lossless comparison, drift and evidence quality
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-D:APPROVED]
  allowed_paths: [action_integrity/execution_proof.py, db/models/evidence.py,
    receipt_service.py, canonical_evidence_bundle_service.py,
    native_control/findings.py, test_phase5_execution_receipt_v2.py,
    test_phase5_execution_comparator.py, test_phase5_execution_drift_findings.py]
  forbidden_paths: [permit claim semantics, complex lifecycle, web, migrations,
    all unlisted]
  read_context: [interface-registry §§5,7,8,9,15; invariants SI-14,SI-19..SI-24]
  frozen_interfaces: [closed MaterialFieldPathV1 grammar and exact hashes,
    ExecutionReceiptV2 and
    AuthorizationExecutionComparisonV2 domains/key purposes/canonical signed
    bodies, execution/evidence/comparator and outcome-input vocabularies, central finding
    catalog, and ACTION_PARAMETER_DRIFT/ACTION_TARGET_DRIFT/
    ACTION_DESTINATION_DRIFT/ACTION_VALUE_DRIFT/EXECUTION_DRIFT_DETECTED/
    EXECUTION_UNVERIFIED producer contracts]
  required_invariants: [SI-02, SI-03, SI-06, SI-10, SI-11, SI-14, SI-15,
    SI-19, SI-20, SI-22, SI-23, SI-25]
  compatibility_requirements: [V1/V1.1 verification unchanged; provider reports
    never upgraded; OS facts preserved as verification-source details; F never
    creates or decides ExpectedOutcomeContractV1/OutcomeVerificationV1]
  acceptance: [receipt/comparison wrong-domain, wrong-purpose, wrong-key and
    wrong-tenant rejection; all material fields compared; matched+failed not
    successful; all 20 central finding codes registered; all six owned
    execution/comparator producers emit exact evidence/dedup/lifecycle payloads]
  focused_tests: [three listed suites plus bundle/findings/coverage/tenant tests]
  risk: CRITICAL
  security_sensitivity: execution truth and evidence integrity
  parallel_safe: true only after D approval and with no overlap with E
}
```

### PH5-WU-G packet

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-G
  requirement_ids: [32,39,43,44,45,46,47,58]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: implement durable multi-step/async/persistent/delegation/outcome lifecycle
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-E:APPROVED, PH5-WU-F:APPROVED]
  allowed_paths: [action_integrity/complex_actions.py,
    delegation_chain_authority_service.py, test_phase5_multistep_actions.py,
    test_phase5_async_execution.py, test_phase5_persistent_effects.py,
    test_phase5_delegation_integrity.py, test_phase5_outcome_verification.py]
  forbidden_paths: [canonical/signed schema changes, permit protocol changes,
    web, all migrations, all unlisted]
  read_context: [interface-registry §§5,7,9,10,15; invariants SI-14,SI-19..SI-24]
  frozen_interfaces: [ActionExecutionAttempt, ActionExecutionTransitionV1,
    ActionPlanV1 and exact ActionPlanBindingV1/plan/step/unbound/full material
    hashes, PersistentEffectV1 and transition, DelegationContextV1 and
    lifecycle event, ExpectedOutcomeContractV1, OutcomeVerificationV1, every
    §10 domain/key purpose/signed body and exact signature input/base64url/
    algorithm encoding, exact scoped-parent root/child material lanes,
    persistent-effect state DAG/verified-recovery/uncertainty/current-truth/
    terminal/idempotency/fold and delegation
    event-edge/projection/terminal/idempotency/fold, append-only projection reconstruction, terminal
    receipt timing, nonexecution sources, and DELEGATION_AUTHORITY_EXPANDED/
    PERSISTENT_EFFECT_CREATED/PERSISTENT_EFFECT_DRIFT/OUTCOME_MISMATCH producer
    contracts]
  required_invariants: [SI-02..SI-06, SI-08, SI-09, SI-11, SI-14, SI-15,
    SI-17, SI-19..SI-23, SI-25]
  compatibility_requirements: [DeferredSideEffect history retained; delegation
    authority source remains existing service]
  acceptance: [every §10 object rejects wrong domain/purpose/key/tenant and
    reconstructs its projection from immutable signed events; CAS/idempotency/
    order/timeout; persistent-effect and delegation projections exactly equal
    fresh folds and reject replay/conflict/illegal or terminal successors;
    effect recovery requires exact expected-state evidence and, after known
    modification, an `INDEPENDENTLY_VERIFIED` remediation action/receipt/
    satisfied outcome; UNKNOWN, stale, or future-dated evidence never becomes
    current success or closes drift;
    scoped-parent matching never evaluates or varies child material; no missing-callback nonexecution; expected-outcome contract
    and verification implemented; effect/delegation/outcome services emit exact
    finding evidence/dedup/lifecycle payloads]
  focused_tests: [five listed suites plus runtime-chain/receipt/findings/coverage]
  risk: CRITICAL
  security_sensitivity: asynchronous authority and persistent consequences
  parallel_safe: false
}
```

### PH5-WU-H packet

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-H
  requirement_ids: [34,40,42,55,56,57,58,59,62,76]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: implement truthful Action Detail, approval/findings/evidence,
    coverage/metrics, consume all upstream finding producers, and provide
    executable UI wiring
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-G:APPROVED]
  allowed_paths: [action_integrity router/metrics, runtime/findings/coverage/ops
    routers, core/model/services for control_coverage, migration 0067, main.py,
    web api/types/action-integrity mjs+d.ts modules, Action Trace/Graph,
    Interaction Security, finding detail, coverage panel, Phase 5 API/migration
    tests, web tests/*.test.mjs]
  forbidden_paths: [policy/canonical/receipt/permit semantics, package dependencies,
    all unlisted]
  read_context: [interface-registry §12 complete five-section Action Detail and
    closed ordered timeline contract, §§14,15; invariants SI-22..SI-29]
  frozen_interfaces: [ActionIntegrityDetailV1 identity plus Context/Action/
    Control/Authorisation/Execution sections, exact Action Detail API method/path
    and browser surface, exact timeline vocabulary/order/evidence/link rules,
    exact trusted-approval DTO and approval list/decision API/browser contracts,
    ID joins, ApprovalRequest binding, control-coverage/2.0, finding exposure
    and existing-remediation linkage only]
  required_invariants: [SI-02, SI-06, SI-11, SI-19, SI-20, SI-22..SI-26,
    SI-28, SI-29]
  compatibility_requirements: [runtime_event_id is route key; V1 coverage remains
    V1; existing remediation and direct enforcement stay distinct]
  acceptance: [all five Action Detail sections and every required field; all
    ordered timeline stages with explicit UNKNOWN and durable evidence/link
    semantics; exact registry Action Detail and approval routes/DTOs; 13
    dimensions; all 20 upstream-produced finding codes exposed/remediated
    without product producer or catalog synthesis; tenant-safe durable metrics;
    executable node UI tests,
    typecheck/build, live navigation acceptance]
  focused_tests: [Phase 5 action/coverage/migration API tests, npm test:ui,
    TypeScript, browser HTTP/navigation acceptance]
  risk: HIGH
  security_sensitivity: product authority truth
  parallel_safe: false
}
```

### PH5-WU-I packet

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-I
  requirement_ids: [48,49,50,51,52,53,54,63,64,65,66]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: implement six signed profiles and complete cross-vertical/security/performance evidence
  requested_model: GPT-5.3-CODEX-SPARK for fixtures; GPT-5.6-LUNA for sensitive integration
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-G:APPROVED]
  allowed_paths: [six profile JSON files, test_phase5_cross_vertical_profiles.py,
    test_phase5_security_invariants.py, test_phase5_performance.py]
  forbidden_paths: [profile engine, canonical/receipt/permit production code,
    migrations, web, all unlisted]
  read_context: [interface-registry §§2..11; invariants SI-01..SI-30]
  frozen_interfaces: [six profile envelope schemas and full table-driven scenario catalog]
  required_invariants: [SI-01..SI-30]
  compatibility_requirements: [one generic engine; no profile weakens core; no
    development benchmark becomes a marketing claim]
  acceptance: [all §63 rows across six profiles; every §64/65 negative; all §66
    operations report p50/p95/p99/throughput/timeout/error]
  focused_tests: [three listed Phase 5 suites]
  risk: HIGH
  security_sensitivity: cross-vertical correctness and attack resistance
  parallel_safe: true after G with no shared files with H
}
```

### PH5-WU-J packet

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-J
  requirement_ids: [60,61,62,67,76,77,78,79]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: integrate migrations, prove persistent deployment and complete final evidence/report
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-H:APPROVED, PH5-WU-I:APPROVED,
    PH5-M2-INTEGRATION:APPROVED]
  allowed_paths: [apps/api/tests/test_fresh_database_migrations.py,
    apps/api/tests/test_migration_0042_token_system_binding.py,
    apps/api/tests/test_deployment_family_migration.py,
    apps/api/tests/test_discovery_canonical_migrations.py,
    apps/api/tests/test_phase5_migrations.py,
    docs/PHASE5_VERTICAL_AGNOSTIC_AUDIT.md,
    docs/validation/phase5-action-execution-integrity-report.md,
    docs/PHASE5_P0_EXECUTION_LEDGER.md]
  forbidden_paths: [new architecture/features, weakened tests, unrelated code,
    destructive database/VCS actions, all unlisted]
  read_context: [all immutable plan inputs, all approved WorkUnit results/reviews]
  frozen_interfaces: [0064->0065->0066->0067 single head; final A-Q report and
    exact truth statement]
  required_invariants: [SI-01..SI-30]
  compatibility_requirements: [fresh and upgraded SQLite/PostgreSQL; V1/V1.1;
    disabled/observe/shadow; Phase 1-4 regressions]
  acceptance: [all Phase 5, relevant API/backend/frontend, security, migration
    upgrade/rollback, performance, Docker PostgreSQL smoke and report gates pass]
  focused_tests: [exact command groups recorded in WU-J detailed steps/ledger]
  risk: CRITICAL
  security_sensitivity: integration, migration, promotion truth
  parallel_safe: false
}
```

---

## Formal build-approval materialization check

Before emitting `SOL_BUILD_APPROVAL`, Sol must expand every packet shorthand to
the exact full repository paths in that WorkUnit's detailed **Files** list and
verify all of the following in the approval envelope:

- the approved baseline commit, dirty-tree manifest digest, exclusive-path
  shared-workspace variance, WU-00M bounded 0053-to-0064 recovery, and WU-00
  read-only persistent PostgreSQL backup/current-0064 proof are fixed evidence;
- requirement 58 is present for A, B, C, D, E, F, G, and H, with A–G owning
  their registry §15 producer semantics, F alone owning the central finding
  catalog, and H limited to API/product exposure/remediation;
- requirement 32 is present for B, D, E, F, and G with the exact registry
  signing domains, key purposes, tenant checks, and negative tests above;
- every WU-00I, WU-00M, WU-00, and A–J packet contains its explicit mandatory
  `required_invariants` SI IDs/ranges; `read_context` does not substitute for
  that field, and formal materialization rejects a missing or different set;
- packet IDs equal the immutable traceability exactly: WU-00I, WU-00M, and
  WU-00 are each `[9,10,11,12,13,62,67]`, E is `[32,36,37,39,58,61]`, requirement 47 is
  G-owned (F is evidence input only), and H is
  `[34,40,42,55,56,57,58,59,62,76]`;
- finding ownership is disjoint and exact: A owns subject/resource/purpose/
  authority; B domain invariant; C tool fingerprint and unknown semantics; D
  approval invalidation; E permit mismatch and ControlPlan downgrade; F only
  parameter/target/destination/value drift, execution drift, execution
  unverified, and the central 20-code catalog; G delegation expansion,
  persistent-effect creation/drift, and outcome mismatch; H only exposes those
  records and invokes existing remediation workflows;
- 0065 is exclusively B-owned and contains only profile, selection, policy
  epoch, and rollout persistence; 0066 is exclusively D-owned and contains all
  predeclared V2/lifecycle/banking-link persistence; 0067 is exclusively
  H-owned and changes only Control Coverage V2 persistence;
- D owns the exact registry approval DTO/list/decision API contract and atomic
  request/binding transaction; H owns the exact Action Detail API/browser and
  approval product contracts;
- G owns every registry §10 signed object, reconstruction proof,
  `ExpectedOutcomeContractV1`, and `OutcomeVerificationV1`;
- B/C/D/E/F/G packets consume the registry's closed material-field grammar and
  exact hashes, signed selection/approval/permit append-only reconstruction,
  `PermittedVariationEnvelopeV1`, strict §7 signature encoding, and
  `ActionPlanBindingV1` wherever applicable. Their tests include gap, fork,
  broken prior hash, projection rewind/mismatch, and exact reconstruction;
- E alone wires the generic permit final gate into the seven audited server-
  controlled files and the complete detailed test list. It proves claim/fresh
  revalidation immediately before every protected executor, zero invocation on
  block/mismatch, unchanged disabled/legacy/direct-REST authority, and truthful
  linked-non-server classification for the .NET banking gate, endpoint broker,
  native callback/live adapter, and OpenAI/customer-runtime paths;
- expanded packet paths, forbidden paths, dependencies, focused tests, M1/M2
  checkpoint dependencies, and the disjoint final Groups 1–8 agree exactly
  with the detailed WorkUnit sections;
- WU-00I materializes `forbidden_paths`, `read_context`, `frozen_interfaces`,
  `required_invariants`, and `compatibility_requirements` exactly; its required
  set is `[PH5-00I-SC-01, SI-11, SI-25, SI-30]`, covering exact supply-chain
  association, secret exclusion, fail-safe blocking, and collateral-damage
  prevention, and its inspection cannot inherit a Compose network, mount,
  credential, environment, or service lifecycle;
- the exact final-acceptance block is a field-for-field superset of the
  SGE-1.0 mandatory schema and Phase 5 status/model/usage fields, reports
  `EXTRA_HIGH`, Terra actual usage/model data, and explicit unavailable
  Luna/Spark usage without invention; and
- J may modify only migration-head tests, its Phase 5 migration test, the
  mutable execution ledger, vertical audit, and final validation report. The
  immutable traceability input is read-only throughout implementation.

Any missing field, abbreviated path set, inconsistent requirement ID,
ownership overlap, or test/dependency difference makes the formal approval
`REJECTED`; workers may not infer the intended correction.

---

## Batch evidence and Sol integration checkpoints

Every WorkUnit must run, in this order, before its dual Sol review: changed-unit
tests, at least one material security-invariant proof named below, and the named
impacted integration/regression evidence. The tests may share one pytest process
when their paths are disjoint, but the ledger must classify the three evidence
classes separately. A passing worker self-check is not approval.

| WorkUnit | Material security-invariant proof | Impacted integration/regression evidence |
|---|---|---|
| 00I | exact closure reproduction; OCI index/platform/attestation/config association; mutable-base and resolved apt/pip proof; SI-11/SI-25/SI-30 plus PH5-00I-SC-01; zero inspection-runtime network/database connection | manifest/control/secret-artifact checks; Buildx v0.36 history and SLSA v1 statement/predicate equality; canonical dpkg/pip hashes and pip check; config/layers/label; exact-ID direct containers with network none and unchanged service lifecycle; sole embedded 0064 head; PH5-M0-IMAGE dual Sol review |
| 00M | exact unchanged PH5-M0-IMAGE identities; verified custom-format backup; quiesced single-transaction upgrade with conditional restore guard | backup digest/list/full extraction, exact pre/post 0054/0062/0063/0064 SQL, session/space/size/seed/volume guards, one-shot 0064 current, bounded exact API/schema/UI/worker/beat success, and rollback-intact old-container 0053 `FAIL_NO_RETRY_NO_RESTORE` proof |
| 00 | verified custom-format backup plus read-only persistent-current/sole-head `0064`; approval-role/tenant isolation and no authority substitution | `pg_restore --list` and backup SHA-256 evidence; enforcement approval API, dashboard links, mixed-status UI/navigation |
| A | wrong-tenant subject/resource plus authority attenuation; exact `SUBJECT_BOUNDARY_VIOLATION`, `RESOURCE_SCOPE_VIOLATION`, `PURPOSE_MISMATCH`, and `AUTHORITY_EXCEEDED` producer payloads | subject context, native requirements/selector, finding evidence/dedup/lifecycle/repeat tests, banking compatibility |
| B | profile tamper/wrong tenant, selection gap/fork/prior-hash/projection rewind, material grammar/hash, signature-encoding and epoch rollback; exact `DOMAIN_INVARIANT_FAILED` producer payload | business-purpose, policy/config, signed profile-selection reconstruction, material/signing vectors, finding evidence/dedup/lifecycle/repeat tests, 0065-only migration |
| C | Unicode/number/null ambiguity, exact material/unbound hashes and `ActionPlanBindingV1`; exact `TOOL_FINGERPRINT_CHANGED` and `UNKNOWN_ACTION_SEMANTICS` producer payloads | authorization kernel, material/plan golden vectors, cross-provider conformance, finding evidence/dedup/lifecycle/repeat tests, banking transport, V1 verification |
| D | approval replay/wrong role/SLA, variation/signature/projection reconstruction, exact registry approval DTO/list/decision contract, atomic rollback, and exact `APPROVAL_INVALIDATED` producer payload | approval gap/fork/prior-hash/projection-rewind negatives, enforcement approval list/decision API, trusted rendering/browser separation, finding evidence/dedup/lifecycle/repeat tests, receipts, evidence bundle, policy and complete 0066 migration |
| E | permit replay/race/expiry/reconstruction plus immediate final-seam revalidation and protected-executor zero-call proof; exact `EXECUTION_PERMIT_MISMATCH` and `CONTROL_PLAN_DOWNGRADED` producer payloads | all six audited server seams across seven owned files and caller wiring, linked non-server classification, disabled/legacy/direct-REST compatibility, banking/endpoint authority, finding evidence/dedup/lifecycle/repeat and tenant tests |
| F | `ExecutionReceiptV2`/`AuthorizationExecutionComparisonV2` wrong domain/purpose/key/key-state/tenant negatives, provider overclaim, and exact `ACTION_PARAMETER_DRIFT`, `ACTION_TARGET_DRIFT`, `ACTION_DESTINATION_DRIFT`, `ACTION_VALUE_DRIFT`, `EXECUTION_DRIFT_DETECTED`, and `EXECUTION_UNVERIFIED` producers | canonical signed bodies, all 20 central catalog contracts, receipt/evidence bundle, finding evidence/dedup/lifecycle/repeat, coverage and tenant isolation |
| G | every registry §10 object domain/purpose/key/tenant negative, exact scoped-parent root/child lanes, persistent-effect DAG/fold/verified recovery/honest uncertainty/current-truth/idempotency, delegation event-edge/fold/terminal/atomic descendant revocation, outcome verification, callback negatives, and exact four owned producers | all eight §10 object suites, recovery/remediation and stale/unknown non-closure cases, fresh-fold equality and replay/conflict cases, `ExpectedOutcomeContractV1`/`OutcomeVerificationV1`, runtime chain, delegation, receipt, finding evidence/dedup/lifecycle/repeat and coverage regressions |
| H | UI authority substitution, cross-tenant reads/mutations, exact registry Action Detail and approval API/browser contracts, and no upstream-producer synthesis | Action Detail API, trusted approval list/decision UI, all 20 upstream finding/evidence/coverage projections, browser acceptance and 0067-only migration |
| I | every §64 and §65 negative proof | complete six-profile matrix and bounded §66 performance suite |
| J | legacy-promotion rejection, migration rollback safety and disabled/observe/shadow non-authority | the non-overlapping final command groups and controlled-runtime evidence below |

Integration checkpoints are explicit dependencies, not informal summaries:

1. `PH5-M1-CORE` runs after WU-00M, WU-00, A, B, and C receive both applicable
   WorkUnit approvals. WU-00M approval must contain the verified recovery
   evidence; WU-00 approval must contain the verified persistent PostgreSQL
   backup reference/SHA-256/`pg_restore --list` result and same-database
   read-only proof that current revision and sole code head were exactly 0064
   before B began. M1 reviews the A–C combined shared-tree diff and runs the
   neutral-core, signed
   profile/selection-chain/materiality/resolver, canonical/equivalence,
   closed path/hash/plan-binding/signature vectors, authorization-kernel,
   subject/business-purpose, cross-provider and banking compatibility suites.
   It also verifies the A–C owned finding producers' exact code, evidence,
   deduplication, lifecycle/repeated-evidence, and tenant contracts.
   The domain-profile suite includes six vertical-neutral envelope fixtures so
   this checkpoint exercises the then-available cross-vertical boundary.
   `PH5-M1-CORE:APPROVED` is required before D.
2. `PH5-M2-INTEGRATION` runs after D through I receive both WorkUnit approvals.
   It reviews the combined authority/execution/product/profile diff; proves
   0065/0066/0067 ownership and the single 0067 head; tests every D–G owned
   finding producer, WU-F's 20-code catalog, and H's consumption without
   synthesis; exercises the exact registry approval DTO/list/decision and
   Action Detail API/browser contracts; and proves every registry §10 signed
   object, reconstruction, `ExpectedOutcomeContractV1`, and
   `OutcomeVerificationV1`. It exercises every WU-E server-controlled final
   seam with claim/revalidation immediately before the protected executor,
   zero-call block/mismatch proofs, and linked-non-server capability truth. It
   also runs the subsystem integration suites, the
   complete §63 matrix, impacted Phase 1–4 regressions, and tenant/API/UI link
   and approval-authority negatives. `PH5-M2-INTEGRATION:APPROVED` is required
   before J.
3. `PH5-M3-FINAL` is WU-J's final integrated checkpoint. It runs each disjoint
   final group exactly once, verifies controlled PostgreSQL/browser evidence,
   and prepares the final packet. Only its approved result permits
   `SOL_FINAL_ACCEPTANCE` review.

Sol records M1 and M2 as:

```text
SOL_INTEGRATION_REVIEW {
  milestone_id, plan_hash, included_work_units[], approved_patch_refs[]
  commands[], results, failures_classified[]
  architecture, security, vertical_neutrality, tenant_isolation,
  compatibility, test_sufficiency, scope_conformance: PASS | FAIL
  status: APPROVED | FIX_REQUIRED | REPLAN_REQUIRED | REJECTED
  blocking_findings[], required_fixes[], next_permitted_workunits[]
  reviewed_by: GPT-5.6-SOL
  reasoning_effort: EXTRA_HIGH
  reviewed_at
}
```

Any checkpoint conflict or failure follows the same bounded fix/replan loop as
a WorkUnit; downstream work remains blocked.

---

## PH5-WU-00I: Immutable image construction and inspection

```text
IMPLEMENTATION_TASK {
  work_unit_id: PH5-WU-00I
  requirement_ids: [9,10,11,12,13,62,67]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: Reproduce the exact hash-bound Docker closure; build once for
             linux/arm64; and return OCI index, platform manifest, attestation,
             SLSA v1, package, config/layer, and embedded-head evidence without
             any inspection-runtime network/database connection or service,
             repository, backup, seed, database, or VCS mutation.
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [SOL_BUILD_APPROVAL_PH5_P0_CAEIC_A_R2:APPROVED_FOR_IMPLEMENTATION]
  allowed_paths: []
  forbidden_paths:
    - every repository path as a mutation target, including source, tests,
      dependencies, migrations, immutable inputs, mutable ledgers, .env,
      local_runtime.db*, artifacts, backups, and VCS metadata
  read_context:
    - docs/PHASE5_SOL_APPROVED_BUILD_PLAN.md plan identity, formal
      materialization check, PH5-WU-00I, PH5-M0-IMAGE, graph and guards
    - docs/PHASE5_P0_REQUIREMENTS_TRACEABILITY.md requirements 9-13,62,67 and
      immutable-image/recovery boundaries
    - docs/PHASE5_SOL_SECURITY_INVARIANTS.md SI-11, SI-25, SI-30
    - docs/validation/phase5-wu00m-build-input-manifest.md as the immutable
      legacy-named manifest assigned only to WU-00I
    - .dockerignore, infra/Dockerfile.api, infra/docker-compose.demo.yml
  frozen_interfaces:
    - exact context /Volumes/X10 Pro/New project/repo; Dockerfile
      infra/Dockerfile.api; platform linux/arm64; tag hawk-api-demo:local
    - Buildx v0.36.0-desktop.1 metadata and history/attachment interfaces;
      SLSA provenance version v1 and mode max
    - containerimage.digest equals containerimage.descriptor.digest and the OCI
      index digest; platform-manifest config.digest equals
      containerimage.config.digest and loaded image .Id
    - attestation manifest references the linux/arm64 platform manifest and its
      in-toto SLSA v1 statement has that platform manifest as its sole subject
    - Docker Compose is read only and used only through `config --format json`
      to prove the migrate image mapping; no Compose service/container starts
    - inspection entrypoints are only dpkg-query, python pip freeze/check, and
      alembic heads in bounded direct containers created from the exact image ID
  required_invariants: [PH5-00I-SC-01, SI-11, SI-25, SI-30]
  operational_invariants:
    - PH5-00I-SC-01 binds closure, OCI index, platform manifest, attestation
      manifest/layer, SLSA predicate/full statement, config, image ID, mutable
      base digest, package inventories, config/layers, label, and embedded head
    - SI-11 forbids secret material in build inputs, provenance parameters,
      evidence output, container environment, logs, and result envelopes
    - SI-25 makes missing/mismatched evidence or any possible network/database
      reachability an immediate BLOCKED result, never a waiver or green state
    - SI-30 preserves every running service identity/lifecycle record and every
      repository, database, volume, backup, seed, image other than the one
      authorized tag, and VCS state
  compatibility_requirements:
    - pre-existing hawk-demo service container IDs, running states, start
      timestamps, and restart counts remain byte-identical before versus after
    - no existing service is stopped, started, restarted, recreated, connected,
      or queried; no database or Redis command is issued
    - direct inspection containers have network none, no mounts, a read-only
      root filesystem, all Linux capabilities dropped, no-new-privileges,
      nonprivileged mode, and empty database/Redis/Celery/PostgreSQL variables
    - build manifest digest a094565e294a2f8ff72672d018e0f156f4c196c9fb3e99cbd969dd59f5685ff1,
      Dockerfile digest 9db626225840acb4c1c918c91e48402478e068acf57cf4d113e795f5c4fb46ed,
      .dockerignore digest 4e93ec846163fdd856a8196ade4422976d9b0b3ed16ddef4d2c6b8ff5c70cafc,
      and 1094-record/1090-regular/2-symlink/2-control closure remain exact
  allowed_external_state_changes:
    - build and tag hawk-api-demo:local exactly once from the reviewed closure
    - create, start once, and remove only the four named exact-ID inspection
      containers; create bounded evidence only under /tmp
  forbidden_operations:
    - any PostgreSQL/database or Redis connection/query, migration, upgrade,
      downgrade, stamp, restore, seed, schema/data write, or backup mutation
    - docker compose run/up/start/stop/restart/create/exec or any Compose action
      other than the exact read-only `config --format json` mapping proof
    - any inspection network other than none; any mount, volume, bind, host
      namespace, privilege, added/default capability, usable credential/env, or
      invocation of an image default command/entrypoint
    - HAWK_BUILD_CONTEXT, Compose context, alternate Dockerfile/platform,
      build-context substitution, second build, pull/load beyond the one build,
      or retag/replacement after evidence capture
    - source/dependency/repository/manifest edit or any VCS mutation
  acceptance:
    - exact closure identities/counts/bytes and canonical digest reproduce
    - Buildx history and attachment evidence closes OCI index -> exact
      linux/arm64 platform manifest + attestation manifest -> exact in-toto
      provenance layer; the full statement predicate equals the metadata
      `{buildDefinition,runDetails}` predicate
    - resolved dependencies contain exactly one
      pkg:docker/python@3.11-slim?platform=linux%2Farm64 entry with one nonempty
      sha256 digest; request frontend, locals, Dockerfile, platform and label
      equal the frozen values and request secrets/SSH are empty
    - loaded image ID/config/index descriptor association and closure label pass;
      canonical dpkg and pip inventories/hashes, pip check, config and ordered
      manifest/rootfs layers are recorded
    - exact-ID no-network inspection reports sole embedded head
      0064_native_control_logical_action_claims and all four containers are gone
    - Compose migrate maps to hawk-api-demo:local and that tag resolves to the
      exact loaded image ID without starting a Compose container
    - no_database_connection_evidence records network none, empty credential
      environment, zero mounts, read-only/nonprivileged/cap-drop/no-new-
      privileges, zero DB/Redis commands, and byte-identical service lifecycle
  focused_tests:
    - manifest/control/secret/AppleDouble closure reproduction
    - Buildx ref/history plus index/platform/attestation/config/SLSA association
    - exact mutable-base dependency and canonical dpkg/pip/config/layer evidence
    - direct-container isolation policy, Compose mapping-only proof, embedded
      head, container removal and service-lifecycle byte equality
  risk: HIGH
  security_sensitivity: supply chain, secrets, fail-safe isolation, mutable base,
    dependencies, database non-reachability, collateral-damage prevention
  parallel_safe: false
}
```

### PH5-M0-IMAGE mandatory Sol checkpoint

`PH5-WU-00I:PASS` does not approve its image. Two independent Sol envelopes
must cover the same evidence packet and plan hash:

```text
SOL_IMAGE_REVIEW {
  checkpoint_id: PH5-M0-IMAGE
  plan_hash
  image_tag
  loaded_image_id
  containerimage_config_digest
  containerimage_digest, oci_index_descriptor_digest
  linux_arm64_platform_manifest_digest
  provenance_attestation_manifest_digest
  provenance_in_toto_layer_digest
  provenance_full_statement_sha256, provenance_predicate_sha256
  provenance_statement_type, provenance_predicate_type
  provenance_subject_digest, provenance_subject_name
  provenance_build_definition, provenance_run_details, builder_id
  buildx_build_ref, buildx_history_sha256, platforms[]
  resolved_dependencies[]
  python_base_reference, python_base_material_digest
  build_context, dockerfile_path, dockerfile_sha256
  dockerignore_sha256, build_manifest_digest, image_manifest_label
  dpkg_inventory_sha256, dpkg_inventory_count
  pip_freeze_all_sha256, pip_inventory_count, pip_check_result
  image_config_sha256, platform_layer_descriptors[]
  rootfs_diff_ids[], platform_layer_list_sha256, rootfs_diff_id_list_sha256
  embedded_alembic_heads[]
  compose_migrate_image, compose_migrate_resolved_image_id
  inspection_container_policy_records[], inspection_container_ids[]
  inspection_containers_removed
  no_database_connection_evidence {
    network_mode, database_redis_commands, credential_environment
    mounts, host_namespaces, readonly_rootfs, privileged, cap_drop, security_opt
  }
  service_lifecycle_before_sha256, service_lifecycle_after_sha256
  service_lifecycle_delta
  digest_association, provenance_completeness, mutable_base_risk,
  dependency_risk, closure_security, secret_exclusion, fail_safe_isolation,
  collateral_damage, scope_conformance: PASS | FAIL
  status: APPROVED | FIX_REQUIRED | REJECTED
  reviewed_by: GPT-5.6-SOL
  reasoning_effort: EXTRA_HIGH
}

SOL_IMAGE_APPROVAL {
  checkpoint_id: PH5-M0-IMAGE
  plan_hash
  exact_approved_loaded_image_id
  exact_approved_config_digest
  exact_approved_containerimage_digest
  exact_approved_oci_index_descriptor_digest
  exact_approved_linux_arm64_platform_manifest_digest
  exact_approved_attestation_manifest_digest
  exact_approved_provenance_in_toto_layer_digest
  exact_approved_provenance_full_statement_sha256
  exact_approved_provenance_predicate_sha256
  exact_approved_provenance_subject_digest
  exact_approved_provenance_subject_name
  exact_approved_buildx_build_ref
  exact_approved_buildx_history_sha256
  exact_approved_python_base_material_digest
  exact_approved_dpkg_inventory_sha256
  exact_approved_pip_inventory_sha256
  exact_approved_image_config_sha256
  exact_approved_platform_layer_list_sha256
  exact_approved_rootfs_diff_id_list_sha256
  exact_approved_build_manifest_digest
  exact_approved_service_lifecycle_sha256
  exact_approved_no_database_connection_evidence_sha256
  status: APPROVED | REJECTED
  approved_by: GPT-5.6-SOL
  reasoning_effort: EXTRA_HIGH
}
```

`PH5-M0-IMAGE:APPROVED` exists only when both envelopes are `APPROVED`, every
exact digest/hash agrees, and the checkpoint explicitly accepts the index,
platform, attestation, complete SLSA statement/predicate association, mutable
base, resolved apt/pip inventories, no-database proof, and unchanged service
lifecycle. Any image replacement, retag to another ID, inventory change,
provenance mismatch, service-lifecycle delta, reachable inspection container,
or missing evidence invalidates the checkpoint and leaves all database mutation
blocked.

## PH5-WU-00M: One-time persistent PostgreSQL baseline recovery

```text
IMPLEMENTATION_TASK
  work_unit_id: PH5-WU-00M
  requirement_ids: [9,10,11,12,13,62,67]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: Recover the identified hawk-demo persistent PostgreSQL baseline
             from 0053 to the repository's sole 0064 head with one controlled
             Alembic invocation, no source edit, no seed, and a verified
             conditional restore path.
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-00I:PASS, PH5-M0-IMAGE:APPROVED]
  allowed_paths: []
  operational_targets:
    - compose project hawk-demo using infra/docker-compose.demo.yml
    - unchanged hawk-api-demo:local whose loaded ID, config, OCI index,
      linux/arm64 platform, attestation manifest/layer, SLSA statement/predicate,
      subject, base material, inventory and layer hashes exactly equal the
      values in PH5-M0-IMAGE:APPROVED
    - containers hawk-demo-api-1, hawk-demo-worker-1,
      hawk-demo-celery-beat-1, hawk-demo-migrate one-off, hawk-demo-db-1
    - PostgreSQL 16 database aicontrol on named volume hawk_demo_postgres_data
    - read-only backup infra/artifacts/backups/hawk-demo-20260824T102108Z.dump
  allowed_external_state_changes:
    - stop and start/recreate only api, worker, and celery-beat
    - create and remove only Compose one-off migrate containers
    - run exactly one alembic upgrade head from 0053 to 0064
    - conditionally restore the verified backup only after migration failure
      and only when post-failure checks prove transactional rollback is not intact
  forbidden_paths:
    - every repository file and directory as a mutation target, including
      source, tests, migrations, immutable inputs, mutable ledgers,
      local_runtime.db*, and the backup; required files remain read-only context
  forbidden_operations:
    - seed-demo, seed.py, seed_e2e_fixtures.py, or any seed command
    - alembic downgrade or stamp; a second upgrade attempt
    - docker compose down, volume removal/recreation, dropdb/database recreation,
      destructive reset, or backup mutation
    - VCS mutation, dependency/source edit, or unapproved service/container work
    - any build, rebuild, tag, retag, pull, load, replace, or mutation of
      hawk-api-demo:local or its approved image/config/layer identities
  read_context:
    - docs/PHASE5_SOL_APPROVED_BUILD_PLAN.md PH5-WU-00M
    - docs/PHASE5_P0_REQUIREMENTS_TRACEABILITY.md requirement 62 and recovery boundary
    - docs/PHASE5_SOL_SECURITY_INVARIANTS.md SI-06, SI-23, SI-25, SI-27, SI-30
    - infra/docker-compose.demo.yml, infra/Dockerfile.api,
      apps/api/app/db/migrations/env.py, migrations 0053 through 0064,
      scripts/backup_postgres.sh, infra/scripts/seed.py
  frozen_interfaces:
    - repository sole code head is 0064_native_control_logical_action_claims
    - migration chain is exactly linear 0053 -> 0054 -> ... -> 0064
    - no Phase 5 product, public API, security, tenant, or capability semantics change
    - WU-00 remains a read-only persistent-current/sole-head preflight
  required_invariants: [SI-06, SI-23, SI-25, SI-27, SI-30]
  compatibility_requirements:
    - old 0053 containers remain intact and restartable until upgrade success
    - application services are quiesced during migration
    - 0054 truth defaults remain conservative; 0062 maps the 20 existing
      safe-synthetic validation rows to SYNTHETIC_ONLY, never real acceptance
    - existing data, backup, named volume, Redis, and web image remain preserved
  acceptance:
    - backup SHA-256 remains 95033c3b65118f2080ce349f7fb16f8e62848278c109b39d38dd692514ef701d
    - pg_restore list reports custom format, PostgreSQL 16.14, and 996 TOC entries
    - full pg_restore archive extraction to /dev/null succeeds before mutation
    - every exact PH5-M0-IMAGE approved image/config/index/platform/attestation/
      SLSA/base/inventory/layer identity remains unchanged before quiescence,
      immediately before migration, and after migration
    - approved image evidence reports sole code head 0064 before mutation
    - pre-upgrade database current is exactly 0053 and no unexpected client
      backend remains after quiesce
    - exactly one controlled alembic upgrade head exits zero
    - database current is exactly 0064 and every approved image identity remains
      unchanged afterward
    - success reaches exactly api/worker/beat running+healthy with zero restarts
      within 60 seconds; schema/API JSON, UI 200 and both Redis heartbeat keys
      equal the frozen outputs
    - rollback-intact failure restarts only the three captured old container
      IDs, preserves their image IDs/restart counts, proves healthy old-image
      0053/API/UI/worker/beat state, and returns FAIL_NO_RETRY_NO_RESTORE
    - seed-demo start timestamp and hawk_demo_postgres_data identity are unchanged
    - no repository file, image, backup, seed data, database volume identity,
      or VCS state is changed; external changes are limited to service lifecycle
      and 0054-through-0064 migration effects in aicontrol
  focused_tests:
    - SHA-256 plus pg_restore --list and full no-database archive extraction
    - PH5-M0-IMAGE approval-envelope authenticity plus unchanged loaded
      identity/config/label/rootfs-layer revalidation; no inspection rebuild
    - pre/post direct alembic_version and sole code-head proof
    - changed-table row-count/precondition and unexpected-session guards
    - exact success API/schema/UI/worker/beat polling and seed/volume proof
    - exact rollback-intact old-container restart, 0053 health, identity and
      no-retry/no-restore/no-seed failure proof
  risk: CRITICAL
  security_sensitivity: persistent tenant data, append-only evidence, availability
  parallel_safe: false
```

### Immutable PH5-WU-00I and PH5-WU-00M execution guards

These are the only permitted guard commands and expected results. Run them
from `/Volumes/X10 Pro/New project/repo` with `set -euo pipefail`. Any command
error, extra/missing row, or value mismatch is `BLOCKED`; there is no worker
waiver. Commands must not print `.env` or credentials.

#### PH5-WU-00I-only build identity, provenance, and inventory guard

This subsection is executable only by PH5-WU-00I. PH5-WU-00M may read its
approved evidence but may not run any build, inspection-container, load, pull,
tag, retag, or replacement step. The immutable manifest's legacy filename does
not alter that exclusive ownership.

```bash
test "$PWD" = '/Volumes/X10 Pro/New project/repo'
test -z "${HAWK_BUILD_CONTEXT+x}"
test -z "${DOCKERFILE+x}"
test "$(uname -m)" = arm64
test "$(docker buildx version | awk '{print $2}')" = v0.36.0-desktop.1
test "$(shasum -a 256 infra/Dockerfile.api | awk '{print $1}')" = \
  9db626225840acb4c1c918c91e48402478e068acf57cf4d113e795f5c4fb46ed
test "$(shasum -a 256 .dockerignore | awk '{print $1}')" = \
  4e93ec846163fdd856a8196ade4422976d9b0b3ed16ddef4d2c6b8ff5c70cafc

snapshot_running_services() {
  local output="$1"
  docker ps --no-trunc --filter label=com.docker.compose.project=hawk-demo \
    --format '{{.ID}}' | LC_ALL=C sort | while IFS= read -r container_id; do
      test -n "$container_id"
      docker inspect --format \
        '{{.Id}}|{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Status}}|{{.State.Running}}|{{.State.StartedAt}}|{{.RestartCount}}' \
        "$container_id"
    done | LC_ALL=C sort > "$output"
  test -s "$output"
  awk -F '|' 'NF != 6 || $3 != "running" || $4 != "true" {bad=1}
    END {exit bad}' "$output"
}
snapshot_running_services /tmp/ph5-wu00i-services-before.tsv
```

Reproduce all paths, types, COPY refs, sizes, targets, hashes, counts, byte
totals, and the canonical digest in
`docs/validation/phase5-wu00m-build-input-manifest.md`; expected digest is
`a094565e294a2f8ff72672d018e0f156f4c196c9fb3e99cbd969dd59f5685ff1`.
That immutable legacy filename denotes WU-00I input only. Then, and only then,
build once with the exact command below. The `/tmp` paths are evidence, not
inputs. Do not print the full max-mode provenance because it is reviewed for
SI-11 before inclusion in any bounded Sol packet.

```bash
rm -f /tmp/ph5-wu00i-build-metadata.json \
  /tmp/ph5-wu00i-metadata-predicate.json \
  /tmp/ph5-wu00i-full-statement.json /tmp/ph5-wu00i-history.json \
  /tmp/ph5-wu00i-index.json /tmp/ph5-wu00i-platform-manifest.json \
  /tmp/ph5-wu00i-attestation-manifest.json \
  /tmp/ph5-wu00i-provenance-summary.json /tmp/ph5-wu00i-dpkg.tsv \
  /tmp/ph5-wu00i-pip-freeze-all.txt /tmp/ph5-wu00i-image-config.json \
  /tmp/ph5-wu00i-platform-layers.json /tmp/ph5-wu00i-rootfs-diff-ids.json \
  /tmp/ph5-wu00i-heads.txt /tmp/ph5-wu00i-services-after.tsv \
  /tmp/ph5-wu00i-no-database-evidence.json
env -u HAWK_BUILD_CONTEXT -u DOCKERFILE BUILDX_METADATA_PROVENANCE=max \
  docker buildx build --load --provenance=mode=max,version=v1 \
  --platform linux/arm64 \
  --metadata-file /tmp/ph5-wu00i-build-metadata.json \
  --label io.hawk.phase5.build-input-manifest=a094565e294a2f8ff72672d018e0f156f4c196c9fb3e99cbd969dd59f5685ff1 \
  --file '/Volumes/X10 Pro/New project/repo/infra/Dockerfile.api' \
  --tag hawk-api-demo:local '/Volumes/X10 Pro/New project/repo'
test -s /tmp/ph5-wu00i-build-metadata.json
python3 - <<'PY'
import hashlib, json, re
from pathlib import Path
d=json.loads(Path('/tmp/ph5-wu00i-build-metadata.json').read_text())
index_digest=d.get('containerimage.digest','')
descriptor=d.get('containerimage.descriptor')
config_digest=d.get('containerimage.config.digest','')
build_ref=d.get('buildx.build.ref','')
predicate=d.get('buildx.build.provenance')
assert re.fullmatch(r'sha256:[0-9a-f]{64}',index_digest)
assert isinstance(descriptor,dict)
assert descriptor.get('digest')==index_digest
assert descriptor.get('mediaType')=='application/vnd.oci.image.index.v1+json'
assert re.fullmatch(r'sha256:[0-9a-f]{64}',config_digest)
assert isinstance(build_ref,str) and build_ref.strip()
assert isinstance(predicate,dict) and set(predicate)=={'buildDefinition','runDetails'}
definition=predicate['buildDefinition']
run_details=predicate['runDetails']
assert isinstance(definition,dict) and isinstance(run_details,dict)
external=definition.get('externalParameters')
assert isinstance(external,dict)
assert external.get('configSource')=={'path':'Dockerfile.api'}
request=external.get('request')
assert isinstance(request,dict)
assert request.get('frontend')=='dockerfile.v0'
locals_=request.get('locals')
assert isinstance(locals_,list)
assert {item.get('name') for item in locals_ if isinstance(item,dict)}=={
    'context','dockerfile'}
args=request.get('args')
assert isinstance(args,dict)
assert args.get('platform')=='linux/arm64'
assert args.get('label:io.hawk.phase5.build-input-manifest')==(
    'a094565e294a2f8ff72672d018e0f156f4c196c9fb3e99cbd969dd59f5685ff1')
assert request.get('secrets')==[]
assert request.get('ssh')==[]
dependencies=definition.get('resolvedDependencies')
assert isinstance(dependencies,list) and dependencies
base=[item for item in dependencies if isinstance(item,dict) and
      item.get('uri')=='pkg:docker/python@3.11-slim?platform=linux%2Farm64']
assert len(base)==1
assert set(base[0].get('digest',{}))=={'sha256'}
base_digest=base[0]['digest']['sha256']
assert re.fullmatch(r'[0-9a-f]{64}',base_digest)
builder=run_details.get('builder')
assert isinstance(builder,dict) and isinstance(builder.get('id'),str)
canonical=json.dumps(predicate,sort_keys=True,separators=(',',':'))+'\n'
Path('/tmp/ph5-wu00i-metadata-predicate.json').write_text(canonical)
summary={
  'buildx_build_ref':build_ref,
  'containerimage_config_digest':config_digest,
  'containerimage_digest':index_digest,
  'oci_index_descriptor_digest':descriptor['digest'],
  'python_base_reference':base[0]['uri'],
  'python_base_material_digest':'sha256:'+base_digest,
  'provenance_predicate_sha256':hashlib.sha256(canonical.encode()).hexdigest(),
}
Path('/tmp/ph5-wu00i-provenance-summary.json').write_text(
    json.dumps(summary,sort_keys=True,separators=(',',':'))+'\n')
print('buildx_build_ref='+build_ref)
print('oci_index_digest='+index_digest)
print('config_digest='+config_digest)
print('python_base_material_digest=sha256:'+base_digest)
print('provenance_predicate_sha256='+summary['provenance_predicate_sha256'])
PY
build_ref="$(python3 -c 'import json; print(json.load(open("/tmp/ph5-wu00i-provenance-summary.json"))["buildx_build_ref"])')"
index_digest="$(python3 -c 'import json; print(json.load(open("/tmp/ph5-wu00i-provenance-summary.json"))["containerimage_digest"])')"
config_digest="$(python3 -c 'import json; print(json.load(open("/tmp/ph5-wu00i-provenance-summary.json"))["containerimage_config_digest"])')"
history_ref="${build_ref##*/}"
test -n "$history_ref"
docker buildx history inspect "$history_ref" --format json > \
  /tmp/ph5-wu00i-history.json
docker buildx history inspect attachment "$history_ref" "$index_digest" > \
  /tmp/ph5-wu00i-index.json
python3 - <<'PY'
import json, re
from pathlib import Path
h=json.loads(Path('/tmp/ph5-wu00i-history.json').read_text())
i=json.loads(Path('/tmp/ph5-wu00i-index.json').read_text())
s=json.loads(Path('/tmp/ph5-wu00i-provenance-summary.json').read_text())
assert h.get('Ref') in {s['buildx_build_ref'],s['buildx_build_ref'].rsplit('/',1)[-1]}
assert str(h.get('Status','')).lower()=='completed'
assert h.get('Platform')==['linux/arm64']
history_base=[m for m in h.get('Materials',[]) if
              m.get('URI')=='pkg:docker/python@3.11-slim?platform=linux%2Farm64']
assert len(history_base)==1
assert history_base[0].get('Digests')==[s['python_base_material_digest']]
assert i.get('schemaVersion')==2
assert i.get('mediaType')=='application/vnd.oci.image.index.v1+json'
manifests=i.get('manifests')
assert isinstance(manifests,list) and len(manifests)==2
platform=[m for m in manifests if m.get('platform')=={
    'architecture':'arm64','os':'linux'}]
attestation=[m for m in manifests if
    m.get('annotations',{}).get('vnd.docker.reference.type')=='attestation-manifest']
assert len(platform)==1 and len(attestation)==1
platform_digest=platform[0].get('digest','')
attestation_digest=attestation[0].get('digest','')
assert re.fullmatch(r'sha256:[0-9a-f]{64}',platform_digest)
assert re.fullmatch(r'sha256:[0-9a-f]{64}',attestation_digest)
assert attestation[0].get('platform')=={'architecture':'unknown','os':'unknown'}
assert attestation[0]['annotations'].get('vnd.docker.reference.digest')==platform_digest
attachments=h.get('Attachments')
assert isinstance(attachments,list) and len(attachments)==1
assert attachments[0].get('Digest')==attestation_digest
assert attachments[0].get('Type')=='https://slsa.dev/provenance/v1'
s.update({
  'linux_arm64_platform_manifest_digest':platform_digest,
  'provenance_attestation_manifest_digest':attestation_digest,
})
Path('/tmp/ph5-wu00i-provenance-summary.json').write_text(
    json.dumps(s,sort_keys=True,separators=(',',':'))+'\n')
PY
platform_digest="$(python3 -c 'import json; print(json.load(open("/tmp/ph5-wu00i-provenance-summary.json"))["linux_arm64_platform_manifest_digest"])')"
attestation_digest="$(python3 -c 'import json; print(json.load(open("/tmp/ph5-wu00i-provenance-summary.json"))["provenance_attestation_manifest_digest"])')"
docker buildx history inspect attachment "$history_ref" "$platform_digest" > \
  /tmp/ph5-wu00i-platform-manifest.json
docker buildx history inspect attachment "$history_ref" "$attestation_digest" > \
  /tmp/ph5-wu00i-attestation-manifest.json
provenance_layer_digest="$(python3 - <<'PY'
import json, re
from pathlib import Path
a=json.loads(Path('/tmp/ph5-wu00i-attestation-manifest.json').read_text())
assert a.get('schemaVersion')==2
assert a.get('mediaType')=='application/vnd.oci.image.manifest.v1+json'
layers=a.get('layers')
assert isinstance(layers,list) and len(layers)==1
layer=layers[0]
assert layer.get('mediaType','').split(';',1)[0]=='application/vnd.in-toto+json'
assert layer.get('annotations',{}).get('in-toto.io/predicate-type')==(
    'https://slsa.dev/provenance/v1')
digest=layer.get('digest','')
assert re.fullmatch(r'sha256:[0-9a-f]{64}',digest)
print(digest)
PY
)"
docker buildx history inspect attachment "$history_ref" \
  "$provenance_layer_digest" > /tmp/ph5-wu00i-full-statement.json
python3 - <<'PY'
import hashlib, json, re
from pathlib import Path
m=json.loads(Path('/tmp/ph5-wu00i-platform-manifest.json').read_text())
s=json.loads(Path('/tmp/ph5-wu00i-full-statement.json').read_text())
p=json.loads(Path('/tmp/ph5-wu00i-metadata-predicate.json').read_text())
summary=json.loads(Path('/tmp/ph5-wu00i-provenance-summary.json').read_text())
assert m.get('schemaVersion')==2
assert m.get('mediaType')=='application/vnd.oci.image.manifest.v1+json'
assert m.get('config',{}).get('digest')==summary['containerimage_config_digest']
assert s.get('_type')=='https://in-toto.io/Statement/v1'
assert s.get('predicateType')=='https://slsa.dev/provenance/v1'
subjects=s.get('subject')
assert isinstance(subjects,list) and len(subjects)==1
assert isinstance(subjects[0].get('name'),str) and subjects[0]['name']
assert subjects[0].get('digest',{}).get('sha256')==(
    summary['linux_arm64_platform_manifest_digest'].removeprefix('sha256:'))
assert s.get('predicate')==p
canonical_statement=json.dumps(s,sort_keys=True,separators=(',',':'))+'\n'
Path('/tmp/ph5-wu00i-full-statement.json').write_text(canonical_statement)
platform_layers=m.get('layers')
assert isinstance(platform_layers,list) and platform_layers
assert all(re.fullmatch(r'sha256:[0-9a-f]{64}',x.get('digest',''))
           for x in platform_layers)
canonical_layers=json.dumps(platform_layers,sort_keys=True,separators=(',',':'))+'\n'
Path('/tmp/ph5-wu00i-platform-layers.json').write_text(canonical_layers)
attestation=json.loads(Path('/tmp/ph5-wu00i-attestation-manifest.json').read_text())
summary.update({
  'provenance_in_toto_layer_digest':attestation['layers'][0]['digest'],
  'provenance_full_statement_sha256':hashlib.sha256(
    canonical_statement.encode()).hexdigest(),
  'provenance_subject_digest':summary['linux_arm64_platform_manifest_digest'],
  'provenance_subject_name':subjects[0]['name'],
  'platform_layer_list_sha256':hashlib.sha256(canonical_layers.encode()).hexdigest(),
})
Path('/tmp/ph5-wu00i-provenance-summary.json').write_text(
    json.dumps(summary,sort_keys=True,separators=(',',':'))+'\n')
PY
loaded_image_id="$(docker image inspect hawk-api-demo:local --format '{{.Id}}')"
test "$loaded_image_id" = "$config_digest"
loaded_repo_digests="$(docker image inspect hawk-api-demo:local --format '{{json .RepoDigests}}')"
python3 - "$loaded_repo_digests" "$index_digest" <<'PY'
import json, re, sys
repo_digests, index_digest = json.loads(sys.argv[1]), sys.argv[2]
assert isinstance(repo_digests, list) and repo_digests
named = [value for value in repo_digests if re.fullmatch(
    r'hawk-api-demo@sha256:[0-9a-f]{64}', value or '')]
assert named == [f"hawk-api-demo@{index_digest}"]
PY
test "$(docker image inspect hawk-api-demo:local --format '{{index .Config.Labels "io.hawk.phase5.build-input-manifest"}}')" = \
  a094565e294a2f8ff72672d018e0f156f4c196c9fb3e99cbd969dd59f5685ff1
docker image inspect "$loaded_image_id" --format '{{json .Config}}' > \
  /tmp/ph5-wu00i-image-config.json
docker image inspect "$loaded_image_id" --format '{{json .RootFS.Layers}}' > \
  /tmp/ph5-wu00i-rootfs-diff-ids.json
inspection_names=(ph5-wu00i-dpkg ph5-wu00i-pip-freeze \
  ph5-wu00i-pip-check ph5-wu00i-heads)
for name in "${inspection_names[@]}"; do
  test -z "$(docker ps -aq --filter name="^/${name}$")"
done
cleanup_wu00i_inspections() {
  local name
  for name in "${inspection_names[@]}"; do
    docker rm -f "$name" >/dev/null 2>&1 || true
  done
}
trap cleanup_wu00i_inspections EXIT
credential_env=(
  --env DATABASE_URL= --env TEST_DATABASE_URL= --env REDIS_URL=
  --env CELERY_BROKER_URL= --env CELERY_RESULT_BACKEND=
  --env POSTGRES_USER= --env POSTGRES_PASSWORD= --env POSTGRES_DB=
  --env PGHOST= --env PGPORT= --env PGUSER= --env PGPASSWORD=
  --env PGDATABASE=
)
run_wu00i_inspection() {
  local name="$1" output="$2" entrypoint="$3"
  shift 3
  test -z "$(docker ps -aq --filter name="^/${name}$")"
  local container_id
  container_id="$(docker create --name "$name" --network none --read-only \
    --cap-drop ALL --security-opt no-new-privileges=true --pids-limit 256 \
    "${credential_env[@]}" --entrypoint "$entrypoint" \
    "$loaded_image_id" "$@")"
  test -n "$container_id"
  docker inspect "$container_id" > "/tmp/${name}-inspect.json"
  python3 - "$name" "$entrypoint" "/tmp/${name}-inspect.json" \
    "/tmp/${name}-policy.json" "$loaded_image_id" <<'PY'
import json, sys
from pathlib import Path
name, entrypoint, inspect_path, output_path, image_id=sys.argv[1:]
items=json.loads(Path(inspect_path).read_text())
assert isinstance(items,list) and len(items)==1
c=items[0]; host=c['HostConfig']; config=c['Config']
assert c.get('Image')==image_id
assert host.get('NetworkMode')=='none'
assert c.get('Mounts')==[] and host.get('Binds') in (None,[])
assert host.get('Mounts') in (None,[])
assert host.get('IpcMode') in ('','private')
assert host.get('PidMode')=='' and host.get('UTSMode')==''
assert host.get('Devices') in (None,[])
assert host.get('ReadonlyRootfs') is True
assert host.get('Privileged') is False
assert host.get('CapAdd') in (None,[])
assert host.get('CapDrop')==['ALL']
assert any(str(v).startswith('no-new-privileges') for v in host.get('SecurityOpt',[]))
assert config.get('Entrypoint')==[entrypoint]
env={item.split('=',1)[0]:item.split('=',1)[1]
     for item in config.get('Env',[]) if '=' in item}
exact={'DATABASE_URL','TEST_DATABASE_URL','REDIS_URL','CELERY_BROKER_URL','CELERY_RESULT_BACKEND',
       'POSTGRES_USER','POSTGRES_PASSWORD','POSTGRES_DB','PGHOST','PGPORT',
       'PGUSER','PGPASSWORD','PGDATABASE'}
assert exact <= set(env)
for key,value in env.items():
    if (key in exact or 'DATABASE_URL' in key or key.startswith(('PG','POSTGRES_')) or
            'REDIS' in key or 'CELERY' in key):
        assert value=='',key
record={
  'cap_add':[], 'cap_drop':['ALL'], 'container_id':c['Id'],
  'credential_environment':'EMPTY', 'entrypoint':entrypoint,
  'image_id':image_id, 'mounts':[], 'name':name, 'network_mode':'none',
  'no_new_privileges':True, 'privileged':False, 'readonly_rootfs':True,
  'host_namespaces':False,
}
Path(output_path).write_text(json.dumps(record,sort_keys=True,separators=(',',':'))+'\n')
PY
  if ! docker start --attach "$container_id" > "$output"; then
    docker rm -f "$container_id" >/dev/null
    return 1
  fi
  docker rm "$container_id" >/dev/null
  test -z "$(docker ps -aq --filter name="^/${name}$")"
}
run_wu00i_inspection ph5-wu00i-dpkg /tmp/ph5-wu00i-dpkg.raw \
  /usr/bin/dpkg-query -W '-f=${binary:Package}\t${Version}\t${Architecture}\n'
LC_ALL=C sort /tmp/ph5-wu00i-dpkg.raw > /tmp/ph5-wu00i-dpkg.tsv
run_wu00i_inspection ph5-wu00i-pip-freeze \
  /tmp/ph5-wu00i-pip-freeze.raw /usr/local/bin/python -m pip freeze --all
LC_ALL=C sort /tmp/ph5-wu00i-pip-freeze.raw > \
  /tmp/ph5-wu00i-pip-freeze-all.txt
run_wu00i_inspection ph5-wu00i-pip-check \
  /tmp/ph5-wu00i-pip-check.txt /usr/local/bin/python -m pip check
test "$(cat /tmp/ph5-wu00i-pip-check.txt)" = 'No broken requirements found.'
run_wu00i_inspection ph5-wu00i-heads /tmp/ph5-wu00i-heads.txt \
  /usr/local/bin/alembic -c app/db/migrations/alembic.ini heads
test "$(cat /tmp/ph5-wu00i-heads.txt)" = \
  '0064_native_control_logical_action_claims (head)'
for name in "${inspection_names[@]}"; do
  test -s "/tmp/${name}-policy.json"
  test -z "$(docker ps -aq --filter name="^/${name}$")"
done
trap - EXIT
compose_migrate_image="$(docker compose --env-file .env -p hawk-demo \
  -f infra/docker-compose.demo.yml config --format json | python3 -c \
  'import json,sys; print(json.load(sys.stdin)["services"]["migrate"]["image"])')"
test "$compose_migrate_image" = hawk-api-demo:local
test "$(docker image inspect "$compose_migrate_image" --format '{{.Id}}')" = \
  "$loaded_image_id"
snapshot_running_services /tmp/ph5-wu00i-services-after.tsv
cmp -s /tmp/ph5-wu00i-services-before.tsv \
  /tmp/ph5-wu00i-services-after.tsv
python3 - <<'PY'
import hashlib, json
from pathlib import Path
policies=[json.loads(Path('/tmp/'+name+'-policy.json').read_text()) for name in
 ('ph5-wu00i-dpkg','ph5-wu00i-pip-freeze','ph5-wu00i-pip-check','ph5-wu00i-heads')]
before=Path('/tmp/ph5-wu00i-services-before.tsv').read_bytes()
after=Path('/tmp/ph5-wu00i-services-after.tsv').read_bytes()
assert before==after
evidence={
 'cap_drop':['ALL'], 'compose_migrate_image':'hawk-api-demo:local',
 'compose_migrate_resolved_image_id':policies[0]['image_id'],
 'credential_environment':'EMPTY', 'database_redis_commands':0,
 'inspection_container_policy_records':policies,
 'inspection_containers_removed':True, 'mounts':[], 'network_mode':'none',
 'host_namespaces':False,
 'no_new_privileges':True, 'privileged':False, 'readonly_rootfs':True,
 'service_lifecycle_after_sha256':hashlib.sha256(after).hexdigest(),
 'service_lifecycle_before_sha256':hashlib.sha256(before).hexdigest(),
 'service_lifecycle_delta':'BYTE_IDENTICAL',
}
Path('/tmp/ph5-wu00i-no-database-evidence.json').write_text(
 json.dumps(evidence,sort_keys=True,separators=(',',':'))+'\n')
PY
test -s /tmp/ph5-wu00i-dpkg.tsv
test -s /tmp/ph5-wu00i-pip-freeze-all.txt
test -s /tmp/ph5-wu00i-image-config.json
test -s /tmp/ph5-wu00i-platform-layers.json
test -s /tmp/ph5-wu00i-rootfs-diff-ids.json
printf 'loaded_image_id=%s\n' "$loaded_image_id"
printf 'loaded_repo_digests=%s\n' "$loaded_repo_digests"
printf 'oci_index_digest=%s\n' "$index_digest"
printf 'linux_arm64_platform_manifest_digest=%s\n' "$platform_digest"
printf 'provenance_attestation_manifest_digest=%s\n' "$attestation_digest"
printf 'provenance_in_toto_layer_digest=%s\n' "$provenance_layer_digest"
printf 'config_digest=%s\n' "$config_digest"
printf 'python_base_material_digest='; python3 -c \
  'import json; print(json.load(open("/tmp/ph5-wu00i-provenance-summary.json"))["python_base_material_digest"])'
printf 'provenance_predicate_sha256='; python3 -c \
  'import json; print(json.load(open("/tmp/ph5-wu00i-provenance-summary.json"))["provenance_predicate_sha256"])'
printf 'provenance_full_statement_sha256='; python3 -c \
  'import json; print(json.load(open("/tmp/ph5-wu00i-provenance-summary.json"))["provenance_full_statement_sha256"])'
printf 'provenance_subject_name='; python3 -c \
  'import json; print(json.load(open("/tmp/ph5-wu00i-provenance-summary.json"))["provenance_subject_name"])'
printf 'buildx_history_sha256='; \
  shasum -a 256 /tmp/ph5-wu00i-history.json | awk '{print $1}'
printf 'dpkg_count='; wc -l < /tmp/ph5-wu00i-dpkg.tsv | tr -d ' '
printf 'dpkg_sha256='; shasum -a 256 /tmp/ph5-wu00i-dpkg.tsv | awk '{print $1}'
printf 'pip_count='; wc -l < /tmp/ph5-wu00i-pip-freeze-all.txt | tr -d ' '
printf 'pip_sha256='; shasum -a 256 /tmp/ph5-wu00i-pip-freeze-all.txt | awk '{print $1}'
printf 'image_config_sha256='; shasum -a 256 /tmp/ph5-wu00i-image-config.json | awk '{print $1}'
printf 'platform_layer_list_sha256='; shasum -a 256 /tmp/ph5-wu00i-platform-layers.json | awk '{print $1}'
printf 'rootfs_diff_id_list_sha256='; shasum -a 256 /tmp/ph5-wu00i-rootfs-diff-ids.json | awk '{print $1}'
printf 'no_database_connection_evidence_sha256='; \
  shasum -a 256 /tmp/ph5-wu00i-no-database-evidence.json | awk '{print $1}'
printf 'service_lifecycle_sha256='; \
  shasum -a 256 /tmp/ph5-wu00i-services-before.tsv | awk '{print $1}'
```

Expected structural output contains nonempty lowercase SHA-256 identities for
the OCI index, linux/arm64 platform manifest, attestation manifest, provenance
layer, config/image ID, mutable Python material, predicate/full statement,
inventories, config/layers, no-database evidence, and one identical service-
lifecycle hash. Heads output is exactly
`0064_native_control_logical_action_claims (head)`, pip check output is exactly
`No broken requirements found.`, the Compose mapping is exactly
`hawk-api-demo:local` -> `$loaded_image_id`, all four inspection containers are
absent, and lifecycle delta is `BYTE_IDENTICAL`. Any missing field, secret
leak, reachability, container residue, lifecycle delta, or association failure
is `BLOCKED`; only PH5-M0-IMAGE can approve the captured exact values.

#### Exact target and preserved-state guard

```bash
test "$(docker inspect hawk-demo-db-1 --format '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}|{{.Config.Image}}|{{range .Mounts}}{{.Name}}|{{.Destination}}|{{.Type}}{{end}}')" = \
  'hawk-demo|/Volumes/X10 Pro/New project/repo/infra/docker-compose.demo.yml|postgres:16|hawk_demo_postgres_data|/var/lib/postgresql/data|volume'
test "$(docker volume inspect hawk_demo_postgres_data --format '{{.Name}}|{{.Driver}}|{{.CreatedAt}}')" = \
  'hawk_demo_postgres_data|local|2026-08-13T07:23:21Z'
test "$(docker inspect hawk-demo-seed-demo-1 --format '{{.Id}}|{{.State.StartedAt}}|{{.State.ExitCode}}')" = \
  'd9fd81e8150fff18fb41b02f0211a51ea49680ea0efcfddddbcdef094cf32ff4|2026-08-14T10:57:24.183275221Z|0'
test "$(docker image inspect postgres:16 --format '{{.Id}}')" = \
  'sha256:95206741a5b214807675e14165369d05b93a9cf692223b616d07cca227e74b0b'
```

The direct PostgreSQL guard is:

```bash
docker exec -i hawk-demo-db-1 psql -X -v ON_ERROR_STOP=1 \
  -U postgres -d aicontrol -AtF '|' <<'SQL'
SELECT 'identity',current_database(),current_user,current_setting('server_version'),
       current_setting('data_directory'),pg_is_in_recovery();
SELECT 'revision',version_num FROM alembic_version ORDER BY version_num;
SELECT 'count','control_capability_profiles',count(*) FROM control_capability_profiles
UNION ALL SELECT 'count','discovery_observations',count(*) FROM discovery_observations
UNION ALL SELECT 'count','native_control_integrations',count(*) FROM native_control_integrations
UNION ALL SELECT 'count','native_control_selections',count(*) FROM native_control_selections
UNION ALL SELECT 'count','native_control_validations',count(*) FROM native_control_validations ORDER BY 2;
SELECT 'observation_created_at',count(*) FILTER (WHERE created_at IS NULL),count(*) FILTER (WHERE created_at IS NOT NULL) FROM discovery_observations;
SELECT 'integration_health',health_state::text,count(*) FROM native_control_integrations GROUP BY health_state ORDER BY health_state;
SELECT 'integration_health_nulls',count(*) FROM native_control_integrations WHERE health_state IS NULL;
SELECT 'validation_distribution',safe_synthetic::text,result::text,count(*) FROM native_control_validations GROUP BY safe_synthetic,result ORDER BY safe_synthetic,result;
SELECT 'validation_safe_synthetic_nulls',count(*) FROM native_control_validations WHERE safe_synthetic IS NULL;
SELECT 'validation_evidence_text_max',coalesce(max(length(evidence_refs::text)),0) FROM native_control_validations;
SELECT 'selection_selected_at',count(*) FILTER (WHERE selected_at IS NULL),count(*) FILTER (WHERE selected_at IS NOT NULL) FROM native_control_selections;
WITH bounds(name,max_bytes) AS (VALUES
 ('control_capability_profiles',196608::bigint),('discovery_observations',131072),
 ('native_control_integrations',524288),('native_control_selections',131072),
 ('native_control_validations',262144))
SELECT 'relation_bound',name,pg_total_relation_size(name::regclass),max_bytes,
       pg_total_relation_size(name::regclass)<=max_bytes FROM bounds ORDER BY name;
SQL
```

Expected rows, in order, are:

```text
identity|aicontrol|postgres|16.14 (Debian 16.14-1.pgdg13+1)|/var/lib/postgresql/data|f
revision|0053_banking_execution_grants
count|control_capability_profiles|3
count|discovery_observations|0
count|native_control_integrations|2
count|native_control_selections|0
count|native_control_validations|20
observation_created_at|0|0
integration_health|degraded|2
integration_health_nulls|0
validation_distribution|true|failed|18
validation_distribution|true|passed|2
validation_safe_synthetic_nulls|0
validation_evidence_text_max|980
selection_selected_at|0|0
relation_bound|control_capability_profiles|98304|196608|t
relation_bound|discovery_observations|73728|131072|t
relation_bound|native_control_integrations|303104|524288|t
relation_bound|native_control_selections|32768|131072|t
relation_bound|native_control_validations|90112|262144|t
```

Thus 0062 must map exactly all `20` `safe_synthetic=true` rows (`18` failed,
`2` passed) to `SYNTHETIC_ONLY`; neither result is real acceptance.

#### Exact 0054-through-0064 collision guard

The following 40 relations are the complete new-relation absence list:

```text
discovery_ai_assets, discovery_evidence_claims, discovery_asset_history_events,
discovery_resolution_decisions, discovery_resolution_decision_observations,
discovery_observation_asset_links, discovery_asset_fingerprints,
discovery_ai_capabilities, discovery_asset_history_members,
discovery_asset_hypotheses, discovery_hypothesis_transitions,
discovery_resolution_graph_nodes, discovery_resolution_graph_edges,
discovery_verification_tasks, discovery_asset_reachability,
discovery_asset_identity_links, discovery_asset_ownership_assertions,
discovery_asset_usage_facts, discovery_shadow_classifications,
discovery_asset_findings, discovery_capability_inference_runs,
discovery_capability_evidence, discovery_capability_genomes,
discovery_capability_events, discovery_hypothesis_evaluations,
discovery_hypothesis_evaluation_edges, discovery_collector_quality_snapshots,
discovery_observation_quality_snapshots, discovery_ai_ecosystems,
discovery_ecosystem_memberships, discovery_ecosystem_resolution_events,
discovery_ecosystem_history_members, discovery_verification_policies,
discovery_verification_policy_requirements, discovery_verification_episodes,
discovery_verification_attempts, discovery_verification_results,
discovery_verification_assertions, discovery_verification_events,
native_control_logical_action_claims
```

Run this exact relation/function/trigger check; expected output is three zeros:

```bash
docker exec -i hawk-demo-db-1 psql -X -v ON_ERROR_STOP=1 -U postgres -d aicontrol -At <<'SQL'
WITH expected(name) AS (VALUES
 ('discovery_ai_assets'),('discovery_evidence_claims'),('discovery_asset_history_events'),('discovery_resolution_decisions'),('discovery_resolution_decision_observations'),('discovery_observation_asset_links'),('discovery_asset_fingerprints'),('discovery_ai_capabilities'),('discovery_asset_history_members'),('discovery_asset_hypotheses'),('discovery_hypothesis_transitions'),('discovery_resolution_graph_nodes'),('discovery_resolution_graph_edges'),('discovery_verification_tasks'),('discovery_asset_reachability'),('discovery_asset_identity_links'),('discovery_asset_ownership_assertions'),('discovery_asset_usage_facts'),('discovery_shadow_classifications'),('discovery_asset_findings'),('discovery_capability_inference_runs'),('discovery_capability_evidence'),('discovery_capability_genomes'),('discovery_capability_events'),('discovery_hypothesis_evaluations'),('discovery_hypothesis_evaluation_edges'),('discovery_collector_quality_snapshots'),('discovery_observation_quality_snapshots'),('discovery_ai_ecosystems'),('discovery_ecosystem_memberships'),('discovery_ecosystem_resolution_events'),('discovery_ecosystem_history_members'),('discovery_verification_policies'),('discovery_verification_policy_requirements'),('discovery_verification_episodes'),('discovery_verification_attempts'),('discovery_verification_results'),('discovery_verification_assertions'),('discovery_verification_events'),('native_control_logical_action_claims'))
SELECT count(*) FROM expected WHERE to_regclass('public.'||name) IS NOT NULL;
WITH expected(name) AS (VALUES ('deny_discovery_ai_asset_delete'),('hawk_reject_cie_mutation'),('hawk_reject_erg_mutation'),('hawk_validate_erg_edge_successor'),('hawk_reject_adv_mutation'),('hawk_validate_adv_policy_predecessor'),('hawk_validate_adv_episode_predecessor'),('hawk_validate_adv_result_predecessor'),('hawk_validate_adv_assertion_predecessor'),('hawk_validate_native_control_validation_scope'))
SELECT count(*) FROM expected e JOIN pg_proc p ON p.proname=e.name JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public';
SELECT count(*) FROM information_schema.triggers WHERE trigger_schema='public' AND (trigger_name LIKE 'trg_erg_%' OR trigger_name LIKE 'trg_adv_%' OR trigger_name IN ('trg_discovery_ai_assets_no_delete','trg_discovery_usage_immutable','trg_discovery_shadow_class_immutable','trg_native_validation_scope_guard'));
SQL
```

The exact added-column absence map is:

```text
discovery_observations: source_surface, subject_reference, normalized_signal_json,
received_at, observed_state, verification_state, source_trust,
collection_scope_json, parser_version, schema_version, evidence_mode,
evidence_mutability, contradiction_state, contradiction_references_json
discovery_ai_capabilities: verification_state, freshness, observed_usage,
declared_only, inferred_only
discovery_resolution_graph_edges: collector_id, source_surface, signal_class,
base_confidence, observation_quality_factor, collector_quality_factor,
relationship_weight, relationship_rule_id, relationship_rule_version,
decay_policy_id, decay_policy_version, last_validated_at, edge_schema_version,
edge_sequence, predecessor_edge_id
discovery_verification_tasks: verification_episode_id,
verification_requirement_id, task_contract_version
control_capability_profiles: runtime, supported_action_classes,
supported_control_methods, contract_hash
native_control_integrations: model_provider, model, runtime,
execution_location, deployment_reference, contract_hash
native_control_validations: acceptance_state, deployment_environment, provider,
product, runtime, model_provider, model, route_identity, deployment_identity,
execution_location, deployment_reference, action_classes, control_methods,
lifecycle_events, provider_version, adapter_version, contract_hash,
acceptance_run_id, allow_result, block_result, non_execution_result
native_control_selections: canonical_action_hash, provider_runtime_context,
provider_runtime_fingerprint, control_plan_id, control_plan_digest,
control_plan_material, mandatory_enforcement_floor_requirements,
selected_mandatory_floors, semantic_primary_control_point_id,
secondary_context_points, verification_points, unsatisfied_mandatory_floors,
rejected_mandatory_floor_candidates, control_requirement_unsatisfied,
control_plan_reason_codes, degradation_policy, failure_behavior,
plan_issued_at, plan_expires_at, contract_hashes
```

Run the exact map query below; expected output is `0`:

```bash
docker exec -i hawk-demo-db-1 psql -X -v ON_ERROR_STOP=1 -U postgres -d aicontrol -At <<'SQL'
WITH expected(table_name,columns) AS (VALUES
 ('discovery_observations',ARRAY['source_surface','subject_reference','normalized_signal_json','received_at','observed_state','verification_state','source_trust','collection_scope_json','parser_version','schema_version','evidence_mode','evidence_mutability','contradiction_state','contradiction_references_json']),
 ('discovery_ai_capabilities',ARRAY['verification_state','freshness','observed_usage','declared_only','inferred_only']),
 ('discovery_resolution_graph_edges',ARRAY['collector_id','source_surface','signal_class','base_confidence','observation_quality_factor','collector_quality_factor','relationship_weight','relationship_rule_id','relationship_rule_version','decay_policy_id','decay_policy_version','last_validated_at','edge_schema_version','edge_sequence','predecessor_edge_id']),
 ('discovery_verification_tasks',ARRAY['verification_episode_id','verification_requirement_id','task_contract_version']),
 ('control_capability_profiles',ARRAY['runtime','supported_action_classes','supported_control_methods','contract_hash']),
 ('native_control_integrations',ARRAY['model_provider','model','runtime','execution_location','deployment_reference','contract_hash']),
 ('native_control_validations',ARRAY['acceptance_state','deployment_environment','provider','product','runtime','model_provider','model','route_identity','deployment_identity','execution_location','deployment_reference','action_classes','control_methods','lifecycle_events','provider_version','adapter_version','contract_hash','acceptance_run_id','allow_result','block_result','non_execution_result']),
 ('native_control_selections',ARRAY['canonical_action_hash','provider_runtime_context','provider_runtime_fingerprint','control_plan_id','control_plan_digest','control_plan_material','mandatory_enforcement_floor_requirements','selected_mandatory_floors','semantic_primary_control_point_id','secondary_context_points','verification_points','unsatisfied_mandatory_floors','rejected_mandatory_floor_candidates','control_requirement_unsatisfied','control_plan_reason_codes','degradation_policy','failure_behavior','plan_issued_at','plan_expires_at','contract_hashes']))
SELECT count(*) FROM expected e CROSS JOIN LATERAL unnest(e.columns) c(column_name)
JOIN information_schema.columns i ON i.table_schema='public' AND i.table_name=e.table_name AND i.column_name=c.column_name;
SQL
```

This named map is closed; omission, substitution, or nonzero output is
`BLOCKED`.

#### Quiescence, transaction, and space guard

After stopping only `api`, `worker`, and `celery-beat`, run:

```bash
docker exec -i hawk-demo-db-1 psql -X -v ON_ERROR_STOP=1 -U postgres -d aicontrol -AtF '|' <<'SQL'
SELECT 'revision',string_agg(version_num,',' ORDER BY version_num) FROM alembic_version;
SELECT 'unexpected_clients',count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend';
SELECT 'open_transactions',count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend' AND xact_start IS NOT NULL;
SELECT 'prepared_transactions',count(*) FROM pg_prepared_xacts WHERE database=current_database();
SQL
space_record="$(docker exec hawk-demo-db-1 df -PkP /var/lib/postgresql/data | \
  awk 'NR==2 {print $1 "|" $2 "|" $4 "|" $6}')"
IFS='|' read -r space_filesystem space_total_kib space_available_kib space_mount \
  <<EOF
$space_record
EOF
test -n "$space_filesystem"
test "$space_mount" = '/var/lib/postgresql/data'
case "$space_total_kib:$space_available_kib" in
  *[!0-9:]*|'') exit 1 ;;
esac
test "$space_available_kib" -ge 20971520
printf 'space|filesystem=%s|unit=KiB|mount=%s|available_kib=%s|threshold_kib=20971520\n' \
  "$space_filesystem" "$space_mount" "$space_available_kib"
```

Expected SQL rows are exactly
`revision|0053_banking_execution_grants`, `unexpected_clients|0`,
`open_transactions|0`, and `prepared_transactions|0`. The `df -PkP` record is
hash-bound here as POSIX 1024-byte blocks: field 1 is a nonempty filesystem
identity, field 4 is numeric available KiB, and field 6 must be the exact mount
`/var/lib/postgresql/data`. Available space must be at least `20971520` KiB
(`21474836480` bytes); it may exceed the threshold without byte equality.
Re-run the complete target, data, collision, relation,
backup, full M0 image/supply-chain, and sole-head guards after quiescence. Only then may
the one permitted upgrade command run.

#### Exact successful post-upgrade guard

Run this block while `api`, `worker`, and `celery-beat` remain stopped and
before any application container is recreated:

```bash
docker exec -i hawk-demo-db-1 psql -X -v ON_ERROR_STOP=1 \
  -U postgres -d aicontrol -AtF '|' <<'SQL'
SELECT 'post_identity',current_database(),current_user,current_setting('server_version'),current_setting('data_directory'),pg_is_in_recovery();
SELECT 'post_revision',string_agg(version_num,',' ORDER BY version_num) FROM alembic_version;
WITH expected(table_name,columns) AS (VALUES
 ('discovery_observations',ARRAY['source_surface','subject_reference','normalized_signal_json','received_at','observed_state','verification_state','source_trust','collection_scope_json','parser_version','schema_version','evidence_mode','evidence_mutability','contradiction_state','contradiction_references_json']),
 ('control_capability_profiles',ARRAY['runtime','supported_action_classes','supported_control_methods','contract_hash']),
 ('native_control_integrations',ARRAY['model_provider','model','runtime','execution_location','deployment_reference','contract_hash']),
 ('native_control_validations',ARRAY['acceptance_state','deployment_environment','provider','product','runtime','model_provider','model','route_identity','deployment_identity','execution_location','deployment_reference','action_classes','control_methods','lifecycle_events','provider_version','adapter_version','contract_hash','acceptance_run_id','allow_result','block_result','non_execution_result']),
 ('native_control_selections',ARRAY['canonical_action_hash','provider_runtime_context','provider_runtime_fingerprint','control_plan_id','control_plan_digest','control_plan_material','mandatory_enforcement_floor_requirements','selected_mandatory_floors','semantic_primary_control_point_id','secondary_context_points','verification_points','unsatisfied_mandatory_floors','rejected_mandatory_floor_candidates','control_requirement_unsatisfied','control_plan_reason_codes','degradation_policy','failure_behavior','plan_issued_at','plan_expires_at','contract_hashes']),
 ('native_control_logical_action_claims',ARRAY['id','tenant_id','integration_instance_id','provider_event_id_hash','canonical_material_hash','policy_snapshot_id','contract_hash','configuration_fingerprint','conflicted_at','conflict_material_hash','created_at','updated_at'])), pairs AS (
 SELECT e.table_name,c.column_name FROM expected e CROSS JOIN LATERAL unnest(e.columns) c(column_name))
SELECT 'post_required_columns',count(*),count(*) FILTER (WHERE i.column_name IS NULL)
FROM pairs p LEFT JOIN information_schema.columns i ON i.table_schema='public' AND i.table_name=p.table_name AND i.column_name=p.column_name;
WITH expected(name) AS (VALUES ('deny_immutable_table_mutation'),('hawk_validate_native_control_validation_scope')), actual AS (
 SELECT p.oid,p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='public')
SELECT 'post_required_functions',count(*),count(*) FILTER (WHERE p.oid IS NULL)
FROM expected e LEFT JOIN actual p ON p.proname=e.name;
WITH expected(table_name,trigger_name) AS (VALUES
 ('discovery_observations','trg_discovery_observations_immutable'),
 ('native_control_validations','trg_native_validation_immutable'),
 ('native_control_validations','trg_native_validation_scope_guard'),
 ('native_control_selections','trg_native_control_selections_immutable'))
SELECT 'post_required_triggers',count(*),count(*) FILTER (WHERE t.oid IS NULL)
FROM expected e LEFT JOIN (SELECT c.oid,c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public') c ON c.relname=e.table_name
LEFT JOIN pg_trigger t ON t.tgrelid=c.oid AND t.tgname=e.trigger_name AND NOT t.tgisinternal;
WITH expected(name) AS (VALUES ('native_control_logical_action_claims'))
SELECT 'post_required_tables',count(*),count(*) FILTER (WHERE to_regclass('public.'||name) IS NULL) FROM expected;
WITH c AS (SELECT column_name,is_nullable,column_default FROM information_schema.columns
 WHERE table_schema='public' AND table_name='discovery_observations' AND column_name IN
 ('source_surface','subject_reference','normalized_signal_json','received_at','observed_state','verification_state','source_trust','collection_scope_json','parser_version','schema_version','evidence_mode','evidence_mutability','contradiction_state','contradiction_references_json'))
SELECT 'post_0054_columns_defaults',count(*),count(*) FILTER (WHERE NOT CASE
 WHEN column_name='subject_reference' THEN is_nullable='YES' AND column_default IS NULL
 WHEN column_name='received_at' THEN is_nullable='NO' AND lower(column_default) IN ('now()','current_timestamp')
 WHEN column_name IN ('normalized_signal_json','collection_scope_json') THEN is_nullable='NO' AND column_default LIKE '''{}''%'
 WHEN column_name='contradiction_references_json' THEN is_nullable='NO' AND column_default LIKE '''[]''%'
 WHEN column_name='parser_version' THEN is_nullable='NO' AND column_default LIKE '''legacy-unknown''%'
 WHEN column_name='schema_version' THEN is_nullable='NO' AND column_default LIKE '''1.0''%'
 ELSE is_nullable='NO' AND column_default LIKE '''unknown''%' END) FROM c;
SELECT 'post_0054_rows',count(*),count(*) FILTER (WHERE received_at IS NULL) FROM discovery_observations;
SELECT 'post_counts','control_capability_profiles',count(*),count(*)-count(DISTINCT id) FROM control_capability_profiles
UNION ALL SELECT 'post_counts','discovery_observations',count(*),count(*)-count(DISTINCT observation_id) FROM discovery_observations
UNION ALL SELECT 'post_counts','native_control_integrations',count(*),count(*)-count(DISTINCT id) FROM native_control_integrations
UNION ALL SELECT 'post_counts','native_control_logical_action_claims',count(*),count(*)-count(DISTINCT id) FROM native_control_logical_action_claims
UNION ALL SELECT 'post_counts','native_control_selections',count(*),count(*)-count(DISTINCT selection_id) FROM native_control_selections
UNION ALL SELECT 'post_counts','native_control_validations',count(*),count(*)-count(DISTINCT id) FROM native_control_validations ORDER BY 2;
SELECT 'post_profiles',count(*),count(*) FILTER (WHERE runtime IS DISTINCT FROM 'unknown' OR supported_action_classes::text<>'[]' OR supported_control_methods::text<>'[]' OR contract_hash IS NOT NULL) FROM control_capability_profiles;
SELECT 'post_integrations',count(*),count(*) FILTER (WHERE model_provider IS DISTINCT FROM 'unknown' OR model IS DISTINCT FROM 'unknown' OR runtime IS DISTINCT FROM 'unknown' OR execution_location IS DISTINCT FROM 'UNKNOWN' OR deployment_reference IS DISTINCT FROM 'unknown' OR contract_hash IS NOT NULL) FROM native_control_integrations;
SELECT 'post_integration_health',health_state::text,count(*) FROM native_control_integrations GROUP BY health_state ORDER BY health_state;
SELECT 'post_validation_distribution',acceptance_state,safe_synthetic::text,result::text,count(*) FROM native_control_validations GROUP BY acceptance_state,safe_synthetic,result ORDER BY acceptance_state,safe_synthetic,result;
SELECT 'post_real_acceptance',count(*) FROM native_control_validations WHERE acceptance_state IN ('REAL_BINARY_ACCEPTED','REAL_ENTERPRISE_TENANT_ACCEPTED','REAL_CLOUD_RUNTIME_ACCEPTED');
SELECT 'post_validation_join_mismatch',count(*) FROM native_control_validations v LEFT JOIN native_control_integrations i ON i.tenant_id=v.tenant_id AND i.id=v.integration_instance_id WHERE i.id IS NULL OR v.deployment_environment IS DISTINCT FROM i.environment OR v.provider IS DISTINCT FROM i.provider OR v.product IS DISTINCT FROM i.product OR v.provider_version IS DISTINCT FROM i.provider_version OR v.adapter_version IS DISTINCT FROM i.adapter_version;
SELECT 'post_validation_default_mismatch',count(*) FROM native_control_validations WHERE runtime IS DISTINCT FROM 'unknown' OR model_provider IS DISTINCT FROM 'unknown' OR model IS DISTINCT FROM 'unknown' OR route_identity IS DISTINCT FROM 'unknown' OR deployment_identity IS DISTINCT FROM 'unknown' OR execution_location IS DISTINCT FROM 'UNKNOWN' OR deployment_reference IS DISTINCT FROM 'unknown' OR action_classes::text<>'[]' OR control_methods::text<>'[]' OR lifecycle_events::text<>'[]' OR contract_hash IS NOT NULL OR acceptance_run_id IS NOT NULL OR allow_result IS DISTINCT FROM 'not_tested' OR block_result IS DISTINCT FROM 'not_tested' OR non_execution_result IS DISTINCT FROM 'not_tested';
SELECT 'post_0063_selections',count(*),count(*) FILTER (WHERE plan_issued_at IS NULL OR plan_expires_at IS NULL) FROM native_control_selections;
SELECT 'post_0064_claims',count(*) FROM native_control_logical_action_claims;
WITH bounds(name,max_bytes) AS (VALUES
 ('control_capability_profiles',196608::bigint),('discovery_observations',131072),('native_control_integrations',524288),('native_control_logical_action_claims',131072),('native_control_selections',131072),('native_control_validations',262144))
SELECT 'post_relation_bounds',count(*),count(*) FILTER (WHERE pg_total_relation_size(name::regclass)>max_bytes) FROM bounds;
SELECT 'post_unexpected_clients',count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend';
SELECT 'post_open_transactions',count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend' AND xact_start IS NOT NULL;
SELECT 'post_prepared_transactions',count(*) FROM pg_prepared_xacts WHERE database=current_database();
SQL
test "$(docker inspect hawk-demo-db-1 --format '{{index .Config.Labels "com.docker.compose.project"}}|{{index .Config.Labels "com.docker.compose.project.config_files"}}|{{.Config.Image}}|{{range .Mounts}}{{.Name}}|{{.Destination}}|{{.Type}}{{end}}')" = \
  'hawk-demo|/Volumes/X10 Pro/New project/repo/infra/docker-compose.demo.yml|postgres:16|hawk_demo_postgres_data|/var/lib/postgresql/data|volume'
test "$(docker volume inspect hawk_demo_postgres_data --format '{{.Name}}|{{.Driver}}|{{.CreatedAt}}')" = \
  'hawk_demo_postgres_data|local|2026-08-13T07:23:21Z'
test "$(docker inspect hawk-demo-seed-demo-1 --format '{{.Id}}|{{.State.StartedAt}}|{{.State.ExitCode}}')" = \
  'd9fd81e8150fff18fb41b02f0211a51ea49680ea0efcfddddbcdef094cf32ff4|2026-08-14T10:57:24.183275221Z|0'
post_space_record="$(docker exec hawk-demo-db-1 df -PkP /var/lib/postgresql/data | \
  awk 'NR==2 {print $1 "|" $2 "|" $4 "|" $6}')"
IFS='|' read -r post_space_filesystem post_space_total_kib \
  post_space_available_kib post_space_mount <<EOF
$post_space_record
EOF
test -n "$post_space_filesystem"
test "$post_space_mount" = '/var/lib/postgresql/data'
case "$post_space_total_kib:$post_space_available_kib" in
  *[!0-9:]*|'') exit 1 ;;
esac
test "$post_space_available_kib" -ge 20971520
printf 'post_space|filesystem=%s|unit=KiB|mount=%s|available_kib=%s|threshold_kib=20971520\n' \
  "$post_space_filesystem" "$post_space_mount" "$post_space_available_kib"
```

Expected SQL output is exactly:

```text
post_identity|aicontrol|postgres|16.14 (Debian 16.14-1.pgdg13+1)|/var/lib/postgresql/data|f
post_revision|0064_native_control_logical_action_claims
post_required_columns|77|0
post_required_functions|2|0
post_required_triggers|4|0
post_required_tables|1|0
post_0054_columns_defaults|14|0
post_0054_rows|0|0
post_counts|control_capability_profiles|3|0
post_counts|discovery_observations|0|0
post_counts|native_control_integrations|2|0
post_counts|native_control_logical_action_claims|0|0
post_counts|native_control_selections|0|0
post_counts|native_control_validations|20|0
post_profiles|3|0
post_integrations|2|0
post_integration_health|degraded|2
post_validation_distribution|SYNTHETIC_ONLY|true|failed|18
post_validation_distribution|SYNTHETIC_ONLY|true|passed|2
post_real_acceptance|0
post_validation_join_mismatch|0
post_validation_default_mismatch|0
post_0063_selections|0|0
post_0064_claims|0
post_relation_bounds|6|0
post_unexpected_clients|0
post_open_transactions|0
post_prepared_transactions|0
```

The Docker/volume/seed commands must exit zero. The post-upgrade space command
must emit one `post_space` record naming a nonempty filesystem identity,
`unit=KiB`, mount `/var/lib/postgresql/data`, numeric available KiB, and the
`20971520` KiB threshold; available space may exceed that threshold.
Immediately after this block, materialize
the exact PH5-M0-IMAGE approval fields as Sol-controlled literals and compare
the current tag's `.Id`, label, image-config hash, and layer-list hash to those
literals. A worker-supplied environment value or reference is forbidden. Any
mismatch is `FAIL` and blocks service recreation; it does not authorize rebuild.

#### Failure-only restore gate

Restore is forbidden after a zero-exit migration. After a nonzero exit, the
expected post-failure state is still exactly revision
`0053_banking_execution_grants`, zero 0054-through-0064 collision objects, and
the exact preflight row distributions. If those expectations hold, restart the
old services without restore and return `FAIL`.

If and only if they do not hold, keep writers stopped and re-run immediately
before restore: the exact Docker project/container/image/volume/database/user/
server/data-directory identities; backup SHA-256; `pg_restore --list` with
custom format, PostgreSQL 16.14 and 996 TOC entries; full extraction to
`/dev/null`; the observed post-failure revision/object set; zero unexpected
clients; zero open transactions; and zero prepared transactions. Every check
must pass, and an explicit `SOL_INCIDENT_RESTORE_APPROVAL` naming the failed
migration invocation, observed revision/object delta, backup digest, target
identities, and restore command is mandatory. Without that incident approval,
restore is forbidden. The approved restore command remains the single command
in Task 00M.4; a restore failure is an immediate stop.

Dependency graph amendment:

```text
SOL_BUILD_APPROVAL_PH5_P0_CAEIC_A_R2
  -> PH5-WU-00I
  -> PH5-M0-IMAGE:APPROVED (SOL_IMAGE_REVIEW + SOL_IMAGE_APPROVAL)
  -> PH5-WU-00M
  -> PH5-WU-00M:APPROVED (SOL_CHANGE_REVIEW + SOL_CHANGE_APPROVAL)
  -> PH5-WU-00 -> PH5-WU-A -> PH5-WU-B -> ... -> PH5-WU-J
```

No other WorkUnit may run concurrently with PH5-WU-00I or PH5-WU-00M. Only
PH5-WU-00I becomes runnable after formal R2 approval. WU-00I cannot mutate a
database; M0 cannot approve a different or partially evidenced image; WU-00M
cannot build or change the approved image. WU-00M's operational result requires
both Phase 5 Sol change-review envelopes before PH5-WU-00 becomes eligible.

### Task 00M.1: Revalidate target, backup, image, and data preconditions

- [ ] From the repository root, record the existing container/image IDs,
  `hawk_demo_postgres_data` identity, and seed container start timestamp. Prove
  the target is `hawk-demo` / PostgreSQL 16 / `aicontrol` / current `0053` and
  that the repository still has one `0064` head. Do not print `.env` or any
  credential.
- [ ] Capture the exact old application containers before stopping them. This
  record is the sole rollback-intact restart allowlist; its image IDs may be the
  pre-M0 stale image and must not be replaced by the new tag:

```bash
: > /tmp/ph5-wu00m-old-app-containers.tsv
for service in api worker celery-beat; do
  container_id="$(docker compose --env-file .env -p hawk-demo \
    -f infra/docker-compose.demo.yml ps -q "$service")"
  test -n "$container_id"
  docker inspect --format \
    '{{index .Config.Labels "com.docker.compose.service"}}|{{.Id}}|{{.Image}}|{{.State.Status}}|{{.State.Running}}|{{.State.StartedAt}}|{{.RestartCount}}' \
    "$container_id"
done | LC_ALL=C sort > /tmp/ph5-wu00m-old-app-containers.tsv
test "$(cut -d '|' -f 1 /tmp/ph5-wu00m-old-app-containers.tsv)" = \
  $'api\ncelery-beat\nworker'
test "$(cut -d '|' -f 2 /tmp/ph5-wu00m-old-app-containers.tsv | \
  LC_ALL=C sort -u | wc -l | tr -d ' ')" = 3
test "$(cut -d '|' -f 3 /tmp/ph5-wu00m-old-app-containers.tsv | \
  LC_ALL=C sort -u | wc -l | tr -d ' ')" -ge 1
awk -F '|' 'NF != 7 || $4 != "running" || $5 != "true" {bad=1}
  END {exit bad}' /tmp/ph5-wu00m-old-app-containers.tsv
```

  Expected: exactly three rows, each with a distinct nonempty container ID and
  image ID, state `running|true`, a nonempty start timestamp, and numeric
  restart count. The exact file is copied into the WU-00M result packet; no
  worker variable may substitute another container on the failure path.
- [ ] Re-hash and fully parse the existing backup without writing to a database:

```bash
set -euo pipefail
BACKUP_PATH=infra/artifacts/backups/hawk-demo-20260824T102108Z.dump
test "$(shasum -a 256 "$BACKUP_PATH" | awk '{print $1}')" = \
  95033c3b65118f2080ce349f7fb16f8e62848278c109b39d38dd692514ef701d
docker exec -i hawk-demo-db-1 pg_restore --list < "$BACKUP_PATH" | sed -n '1,12p'
docker exec -i hawk-demo-db-1 pg_restore --exit-on-error --file=/dev/null < "$BACKUP_PATH"
```

  Expected: all commands exit zero; the list header says `TOC Entries: 996`,
  `Format: CUSTOM`, and source/creator PostgreSQL `16.14`. This tests complete
  archive extraction but does not restore it or connect `pg_restore` to a
  database.
- [ ] Run every exact PH5-WU-00M read-only command and expected-result assertion
  in the immutable execution guards; do not run the PH5-WU-00I-only subsection.
  Stop with
  `ARCHITECTURE_ESCALATION_REQUIRED` if target identity differs; current is not
  exactly 0053; a 0054-through-0064 collision object already exists; any named
  row/distribution/size guard differs; or available volume space is
  below 20 GiB.
- [ ] Without creating an inspection container, use `docker image inspect` to
  prove the `hawk-api-demo:local` tag still resolves to every exact image ID,
  config digest, manifest label, config hash, and ordered-layer hash in
  `PH5-M0-IMAGE:APPROVED`. Re-hash the immutable build manifest and Docker
  controls. A mismatch invalidates M0 and is `BLOCKED`; WU-00M cannot rebuild,
  pull, load, tag, retag, replace, or repair the image.

### Task 00M.2: Quiesce and run exactly one controlled upgrade

- [ ] Stop only database-writing application processes; do not stop PostgreSQL,
  Redis, or web and do not remove/recreate any container or volume yet:

```bash
docker compose --env-file .env -p hawk-demo \
  -f infra/docker-compose.demo.yml stop --timeout 30 api worker celery-beat
```

- [ ] Run the appendix's exact post-quiescence guard and require
  `alembic_version=0053_banking_execution_grants`, zero other PostgreSQL client
  backends, zero open transactions, zero prepared transactions, every frozen
  row/distribution/object/size identity, and at least 20 GiB free. Any failed guard stops the
  WorkUnit with the old containers restartable; it does not authorize migration.
- [ ] Run the migration service once. Its compose command is only Alembic; never
  start `seed-demo` and never use `compose up` for this step:

```bash
docker compose --env-file .env -p hawk-demo \
  -f infra/docker-compose.demo.yml run --rm --no-deps migrate
```

  Expected: one invocation of
  `alembic -c app/db/migrations/alembic.ini upgrade head` exits zero. PostgreSQL
  transactional DDL and `env.py`'s single `begin_transaction()` make a failure
  non-committing; do not retry.

### Task 00M.3: Verify success and recreate only the application services

- [ ] Before recreating an application container, prove direct database current
  is exactly 0064, revalidate the unchanged PH5-M0-IMAGE identities, and run
  the exact post-upgrade 0054/0062/0063/0064 SQL and preserved-state commands
  below with exactly the frozen output.
- [ ] Recreate only API, worker, and beat from the already verified image:

```bash
docker compose --env-file .env -p hawk-demo \
  -f infra/docker-compose.demo.yml up -d --no-deps --force-recreate \
  api worker celery-beat
expected_app_states=$'api|running|healthy|0\ncelery-beat|running|healthy|0\nworker|running|healthy|0'
app_states=''
for attempt in $(seq 1 60); do
  app_states="$(for service in api worker celery-beat; do
    container_id="$(docker compose --env-file .env -p hawk-demo \
      -f infra/docker-compose.demo.yml ps -q "$service")"
    test -n "$container_id"
    docker inspect --format \
      '{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}|{{.RestartCount}}' \
      "$container_id"
  done | LC_ALL=C sort)"
  test "$app_states" = "$expected_app_states" && break
  test "$attempt" -lt 60 || exit 1
  sleep 1
done
printf '%s\n' "$app_states"
expected_http_states=$'api_health|200\napi_schema|200\nui_login|200'
http_states=''
for attempt in $(seq 1 60); do
  schema_code="$(curl -sS -o /tmp/ph5-wu00m-success-schema.json \
    -w '%{http_code}' http://127.0.0.1:8000/health/schema || true)"
  health_code="$(curl -sS -o /tmp/ph5-wu00m-success-health.json \
    -w '%{http_code}' http://127.0.0.1:8000/health || true)"
  login_code="$(curl -sS -o /tmp/ph5-wu00m-success-login.html \
    -w '%{http_code}' http://127.0.0.1:3001/login || true)"
  http_states="$(printf 'api_health|%s\napi_schema|%s\nui_login|%s\n' \
    "$health_code" "$schema_code" "$login_code")"
  test "$http_states" = "$expected_http_states" && break
  test "$attempt" -lt 60 || exit 1
  sleep 1
done
printf '%s\n' "$http_states"
python3 - <<'PY'
import json
from pathlib import Path
actual=json.loads(Path('/tmp/ph5-wu00m-success-schema.json').read_text())
expected={
 'healthy':True,
 'migration_current_heads':['0064_native_control_logical_action_claims'],
 'migration_expected_heads':['0064_native_control_logical_action_claims'],
 'pending_migrations':[], 'missing_tables':[], 'missing_columns':[], 'notes':[],
}
assert actual==expected,(actual,expected)
PY
python3 - <<'PY'
import json
from pathlib import Path
actual=json.loads(Path('/tmp/ph5-wu00m-success-health.json').read_text())
assert actual.get('status')=='ok'
assert actual.get('service')=='api'
assert actual.get('schema_healthy') is True
assert isinstance(actual.get('strict_schema'),bool)
assert set(actual)=={'status','service','strict_schema','schema_healthy'}
PY
test "$(docker compose --env-file .env -p hawk-demo \
  -f infra/docker-compose.demo.yml exec -T redis redis-cli EXISTS \
  control_plane:celery:worker_heartbeat \
  control_plane:celery:beat_heartbeat | tr -d '\r')" = 2
```

  Expected terminal service output is exactly the three frozen
  `running|healthy|0` rows. Schema JSON is exactly healthy/current/expected
  `0064` with empty pending/missing/notes arrays; API health is `status=ok`,
  `service=api`, `schema_healthy=true`; UI status is `200`; and Redis `EXISTS`
  returns `2`, proving both worker and beat heartbeat keys. Revalidate that each
  recreated container's `.Image` equals the exact literal M0-loaded image ID
  materialized by Sol in the WU-00M packet. Verify `seed-demo` was not rerun and
  the named PostgreSQL volume identity is unchanged.

### Task 00M.4: Failure-only rollback branch

- [ ] This branch is forbidden unless the single migration command exits
  nonzero. Keep API, worker, and beat stopped; record the error without secrets;
  query `alembic_version` and the appendix's exact 0054-through-0064 object set.
- [ ] If and only if the exact rollback-intact checks below pass, take the
  deterministic no-restore branch. These commands restart the three captured
  old container IDs directly; they do not recreate, retag, migrate, restore,
  seed, or retry. Immediately before the block, rerun verbatim the immutable
  **Exact target and preserved-state**, **direct PostgreSQL**, **0054-through-
  0064 collision**, **added-column absence**, and **transaction and space**
  guards and require every listed exact 0053 output; this is a closed reference
  to those commands, not worker discretion.

```bash
rollback_state="$(docker exec -i hawk-demo-db-1 psql -X -v ON_ERROR_STOP=1 \
  -U postgres -d aicontrol -AtF '|' <<'SQL'
SELECT 'revision',string_agg(version_num,',' ORDER BY version_num) FROM alembic_version;
SELECT 'unexpected_clients',count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend';
SELECT 'open_transactions',count(*) FROM pg_stat_activity WHERE datname=current_database() AND pid<>pg_backend_pid() AND backend_type='client backend' AND xact_start IS NOT NULL;
SELECT 'prepared_transactions',count(*) FROM pg_prepared_xacts WHERE database=current_database();
SQL
)"
test "$rollback_state" = $'revision|0053_banking_execution_grants\nunexpected_clients|0\nopen_transactions|0\nprepared_transactions|0'
old_api_id="$(awk -F '|' '$1=="api" {print $2}' \
  /tmp/ph5-wu00m-old-app-containers.tsv)"
old_worker_id="$(awk -F '|' '$1=="worker" {print $2}' \
  /tmp/ph5-wu00m-old-app-containers.tsv)"
old_beat_id="$(awk -F '|' '$1=="celery-beat" {print $2}' \
  /tmp/ph5-wu00m-old-app-containers.tsv)"
test -n "$old_api_id"; test -n "$old_worker_id"; test -n "$old_beat_id"
docker start "$old_api_id" "$old_worker_id" "$old_beat_id" >/dev/null
expected_old_states=$'api|running|healthy\ncelery-beat|running|healthy\nworker|running|healthy'
old_states=''
for attempt in $(seq 1 60); do
  old_states="$(for container_id in "$old_api_id" "$old_worker_id" "$old_beat_id"; do
    docker inspect --format \
      '{{index .Config.Labels "com.docker.compose.service"}}|{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}missing{{end}}' \
      "$container_id"
  done | LC_ALL=C sort)"
  test "$old_states" = "$expected_old_states" && break
  test "$attempt" -lt 60 || exit 1
  sleep 1
done
printf '%s\n' "$old_states"
for service in api worker celery-beat; do
  before="$(awk -F '|' -v service="$service" '$1==service {print $2"|"$3"|"$7}' \
    /tmp/ph5-wu00m-old-app-containers.tsv)"
  container_id="${before%%|*}"
  after="$(docker inspect --format '{{.Id}}|{{.Image}}|{{.RestartCount}}' \
    "$container_id")"
  test "$after" = "$before"
done
schema_status="$(curl -sS -o /tmp/ph5-wu00m-rollback-schema.json \
  -w '%{http_code}' http://127.0.0.1:8000/health/schema)"
test "$schema_status" = 200
python3 - <<'PY'
import json
from pathlib import Path
actual=json.loads(Path('/tmp/ph5-wu00m-rollback-schema.json').read_text())
expected={
 'healthy':True,
 'migration_current_heads':['0053_banking_execution_grants'],
 'migration_expected_heads':['0053_banking_execution_grants'],
 'pending_migrations':[], 'missing_tables':[], 'missing_columns':[], 'notes':[],
}
assert actual==expected,(actual,expected)
PY
curl -fsS http://127.0.0.1:8000/health > \
  /tmp/ph5-wu00m-rollback-health.json
python3 - <<'PY'
import json
from pathlib import Path
actual=json.loads(Path('/tmp/ph5-wu00m-rollback-health.json').read_text())
assert actual.get('status')=='ok'
assert actual.get('service')=='api'
assert actual.get('schema_healthy') is True
assert isinstance(actual.get('strict_schema'),bool)
assert set(actual)=={'status','service','strict_schema','schema_healthy'}
PY
test "$(curl -sS -o /tmp/ph5-wu00m-rollback-login.html \
  -w '%{http_code}' http://127.0.0.1:3001/login)" = 200
test "$(docker compose --env-file .env -p hawk-demo \
  -f infra/docker-compose.demo.yml exec -T redis redis-cli EXISTS \
  control_plane:celery:worker_heartbeat \
  control_plane:celery:beat_heartbeat | tr -d '\r')" = 2
test "$(docker inspect hawk-demo-seed-demo-1 \
  --format '{{.Id}}|{{.State.StartedAt}}|{{.State.ExitCode}}')" = \
  'd9fd81e8150fff18fb41b02f0211a51ea49680ea0efcfddddbcdef094cf32ff4|2026-08-14T10:57:24.183275221Z|0'
printf '%s\n' \
  'rollback_intact=true' 'migration_attempts=1' 'restore_attempts=0' \
  'seed_attempts=0' 'result=FAIL_NO_RETRY_NO_RESTORE'
```

  Expected terminal output is exact 0053 rollback state, three
  `running|healthy` old-service rows, exact old container/image/restart-count
  identity, healthy old-image schema current/expected 0053, healthy API, UI
  `200`, both heartbeat keys, unchanged seed identity, and
  `FAIL_NO_RETRY_NO_RESTORE`. Return `FAIL` with the classified migration
  evidence. Do not execute the restore branch after these checks pass.
- [ ] Only if the migration failed, those checks prove 0053 rollback is not
  intact, every fresh identity/backup/archive/session/transaction guard passes,
  and explicit `SOL_INCIDENT_RESTORE_APPROVAL` exists, execute this frozen
  restore command once while all
  application writers remain stopped:

```bash
docker exec -i hawk-demo-db-1 pg_restore \
  --clean --if-exists --exit-on-error --single-transaction \
  --no-owner --no-privileges -U postgres -d aicontrol \
  < infra/artifacts/backups/hawk-demo-20260824T102108Z.dump
```

  Then require exact 0053 current/schema health before restarting the unchanged
  old containers. Never run `alembic downgrade`, `stamp`, a second upgrade,
  any seed, `compose down`, `dropdb`, or volume deletion. A restore failure is a
  stop condition requiring immediate Sol/operator escalation.

---

## PH5-WU-00: Baseline, migration head, and scoped truth defects

```text
IMPLEMENTATION_TASK
  work_unit_id: PH5-WU-00
  requirement_ids: [9,10,11,12,13,62,67]
  plan_hash: SOL_BUILD_APPROVAL.plan_hash
  objective: Re-prove the recovered read-only 0064 baseline and repair only the
             known navigation/approval truth defects required by Phase 5;
             reverify the existing backup without changing it.
  requested_model: GPT-5.6-LUNA
  actual_model: GPT-5.6-TERRA
  model_exception_reason: user-approved unavailable-model substitution
  dependencies: [PH5-WU-00M:APPROVED]
  allowed_paths:
    - apps/api/tests/test_fresh_database_migrations.py
    - apps/api/tests/test_dashboard_command_center.py
    - apps/api/tests/test_depth_upgrade_approval_authority.py
    - apps/api/app/api/routers/enforcement.py
    - apps/api/app/services/dashboard/aggregator.py
    - apps/web/src/lib/api.ts
    - apps/web/src/components/command-center/command-center-visual-mappers.ts
    - apps/web/src/components/command-center/command-center-visual-types.ts
    - apps/web/src/components/command-center/evidence-river.tsx
    - apps/web/src/app/interaction-security/page.tsx
    - apps/web/tests/command-center-visual-mappers.test.mjs
    - apps/web/tests/evidence-river-source.test.mjs
    - apps/web/tests/navigation-deep-links.test.mjs
    - apps/web/tests/interaction-security-approvals.test.mjs
  forbidden_paths:
    - apps/api/local_runtime.db*
    - all migration files
    - canonical/receipt/policy models
  read_context:
    - docs/CODEX_INTERFACE_REGISTRY.md sections 12 and 15
    - docs/PHASE5_SOL_SECURITY_INVARIANTS.md SI-28 and SI-30
  frozen_interfaces:
    - runtime_event_id is the Action Trace/Graph route key
    - status_filter=all means no status predicate; omitted remains pending
    - the existing pre-recovery persistent PostgreSQL backup remains verified
    - persistent PostgreSQL current and sole migration head are exactly 0064
  required_invariants: [SI-06, SI-28, SI-30]
  compatibility_requirements:
    - preserve existing authorization and omitted-filter behavior
  acceptance:
    - 329 focused baseline and 47 migration tests remain green
    - one Alembic head at 0064
    - existing persistent PostgreSQL backup reference, SHA-256, and restore list reverified
    - persistent PostgreSQL current revision and sole head both equal 0064
    - mixed pending/approved/denied all-filter test passes
    - Action/finding browser links return their intended pages
  focused_tests:
    - apps/api/tests/test_fresh_database_migrations.py::test_fresh_sqlite_database_upgrades_to_current_healthy_schema
    - apps/api/tests/test_dashboard_command_center.py::test_command_center_dashboard_aggregates_cross_module_state
    - apps/api/tests/test_depth_upgrade_approval_authority.py::test_enforcement_decision_enforces_normalized_required_roles
    - apps/api/tests/test_depth_upgrade_approval_authority.py::test_enforcement_approval_list_all_includes_mixed_statuses_and_omitted_defaults_pending
    - apps/web/tests/command-center-visual-mappers.test.mjs
    - apps/web/tests/evidence-river-source.test.mjs
    - apps/web/tests/navigation-deep-links.test.mjs
    - apps/web/tests/interaction-security-approvals.test.mjs
  risk: HIGH
  security_sensitivity: authorization UI truth
  parallel_safe: false
```

### Task 00.1: Capture baseline without changing code

- [ ] Run the focused Phase 4/core baseline:

```bash
cd apps/api
.venv/bin/pytest -q \
  tests/test_canonical_ai_action_contract.py \
  tests/test_authorization_kernel_contract.py \
  tests/test_subject_execution_context.py \
  tests/test_business_purpose_boundary.py \
  tests/test_agentic_action_integrity.py \
  tests/test_mcp_tool_fingerprint_drift.py \
  tests/test_phase4_cross_provider_conformance.py \
  tests/test_banking_transport_control.py \
  tests/test_decision_execution_receipts.py \
  tests/test_native_control_requirements.py \
  tests/test_native_control_selector.py \
  tests/test_native_control_selection_persistence.py
```

Expected: all selected tests pass. Return every classified failure in the
WorkUnit result before any code edit; the orchestrator records accepted evidence
in the mutable ledger after review.

- [ ] Prove one migration head and fresh schema:

```bash
cd apps/api
.venv/bin/pytest -q \
  tests/test_fresh_database_migrations.py \
  tests/test_decision_execution_receipts_migration.py \
  tests/test_phase4_native_control_acceptance_persistence.py
```

Expected: the migration graph resolves to `0064_native_control_logical_action_claims`.
If another head exists, stop with `ARCHITECTURE_ESCALATION_REQUIRED`.

- [ ] Before any TDD or code edit, re-resolve the persistent Docker PostgreSQL
  database used by the product stack without logging credentials. Recompute the
  existing backup's SHA-256 and rerun `pg_restore --list`; require the exact
  PH5-WU-00M reference/digest/996-entry custom archive. Do not create, replace,
  chmod, or otherwise mutate the backup.
- [ ] Against that same persistent PostgreSQL connection, run read-only Alembic
  `heads` and `current` checks. Both the sole code head and persistent current
  revision must be exactly `0064_native_control_logical_action_claims` before
  any TDD/code edit and before WU-A may start. WU-00 must not run `upgrade`,
  `downgrade`, `stamp`, DDL, or any schema/data-writing command. A missing or
  changed backup, multiple head, revision mismatch, or connection ambiguity is
  `ARCHITECTURE_ESCALATION_REQUIRED` and blocks WU-A and all later work.

### Task 00.2: Write failing product-truth tests

- [ ] Add tests asserting:

```python
assert finding_href == f"/discovery/findings/{finding_id}"
assert action_trace_href == f"/runtime-intelligence/action-trace/{event_id}"
assert action_graph_href == f"/runtime-intelligence/action-graph/{event_id}"
assert backend listApprovals("all") returns pending, approved, and denied rows
assert omitted filter remains pending-only for compatibility
```

  The API mixed-status/omitted-default case is named
  `test_enforcement_approval_list_all_includes_mixed_statuses_and_omitted_defaults_pending`
  in `apps/api/tests/test_depth_upgrade_approval_authority.py`. The browser/API
  separation and three distinct finding/action-trace/action-graph link cases
  live in `command-center-visual-mappers.test.mjs`,
  `evidence-river-source.test.mjs`, and `navigation-deep-links.test.mjs`; the
  approval-filter UI case remains in
  `interaction-security-approvals.test.mjs`.

- [ ] Run the targeted API/UI tests and confirm they fail for the known defects.

### Task 00.3: Apply the minimal corrections

- [ ] Separate API references from browser hrefs and preserve explicit event,
  canonical action, receipt action, and selection action identifiers.
- [ ] In the exact three command-center source files allowed above, map the
  backend's finding, action-trace, and action-graph browser hrefs into distinct
  typed fields and render distinct links. Do not substitute an API path, merge
  graph and trace identity, or change unrelated command-center components.
- [ ] Make `all` explicit in the approvals client and normalize it in the
  backend to no status predicate. Preserve pending-only behavior for callers
  that omit the filter and preserve all existing authorization checks.
- [ ] Run the targeted tests, web type check, and navigation tests.
- [ ] Return the exact result and recommended Sol review focus to the
  orchestrator. The worker does not write the ledger. Do not start WU-A until
  Sol approves WU-00 and the orchestrator records that review state centrally.

---

## PH5-WU-A: Vertical-neutral core and subject generalization

**Files:**

- Create: `apps/api/app/core/control_engine/action_integrity_types.py`
- Modify: `apps/api/app/services/subject_execution_context_service.py`
- Modify: `apps/api/app/services/banking_subject_context_service.py`
- Modify: `apps/api/app/services/native_control/requirements.py`
- Modify: `apps/api/app/services/native_control/selector.py`
- Modify: `docs/PHASE5_VERTICAL_AGNOSTIC_AUDIT.md`
- Test: `apps/api/tests/test_phase5_neutral_core.py`
- Test: `apps/api/tests/test_subject_execution_context.py`
- Test: `apps/api/tests/test_native_control_requirements.py`

### Frozen interface

The complete tenant-explicit `PrincipalContext`, `RepresentedSubjectContext`,
`ResourceScope`, `AuthorityContext`, `ValueOrQuantity`, and `ActionSemantics`
field contracts and tagged unknown representation are frozen in
`docs/CODEX_INTERFACE_REGISTRY.md` §§1 and 3. Partial local substitutes are
forbidden.

### TDD steps

- [ ] Write failing tests for actor/subject/execution-identity separation,
  exact resource scope, authority attenuation, expiry, wrong tenant, immutable
  values, unknown provenance, and banking compatibility aliases.
- [ ] Add producer tests for `SUBJECT_BOUNDARY_VIOLATION`,
  `RESOURCE_SCOPE_VIOLATION`, `PURPOSE_MISMATCH`, and `AUTHORITY_EXCEEDED`.
  Through the owned subject/resource/requirements/selector services, assert the
  exact code, required evidence links, registry deduplication key, initial
  lifecycle state, repeated-evidence behavior, and tenant isolation. The test
  may inject the finding sink; WU-A must not change the central finding catalog.
- [ ] Run `test_phase5_neutral_core.py` and prove the new types do not exist.
- [ ] Implement the bounded frozen value objects with closed enums and safe
  references; reject blank/unbounded IDs and naive timestamps.
- [ ] Generalize `SubjectExecutionContext` to expose represented-subject and
  typed resource semantics while preserving existing banking callers through
  documented aliases.
- [ ] Add consequential-action requirements for subject, purpose, and authority
  binding for every consequential action. Profiles may add requirements but
  cannot weaken them; return unsatisfied capabilities instead of silently
  observing.
- [ ] Emit the four WU-A finding payloads through the owned service at the
  authoritative violation point. Do not synthesize them later in an API/UI
  projection.
- [ ] Run the three focused suites plus banking proof-path regression.
- [ ] Sol reviews core leakage, tenant boundaries, compatibility, and fail-closed
  behavior before WU-B.

---

## PH5-WU-B: Domain profiles, invariants, resolvers, and materiality

**Files:**

- Create: `apps/api/app/services/action_integrity/__init__.py`
- Create: `apps/api/app/services/action_integrity/domain_profiles.py`
- Create: `apps/api/app/services/action_integrity/materiality.py`
- Create: `apps/api/app/services/action_integrity/resolvers.py`
- Create: `apps/api/app/services/action_integrity/signing.py`
- Create: `apps/api/app/services/action_integrity/policy_epoch.py`
- Create: `apps/api/app/db/models/action_integrity.py`
- Create: `apps/api/app/db/migrations/versions/0065_phase5_action_integrity_core.py`
- Modify: `apps/api/app/db/models/__init__.py`
- Modify: `apps/api/app/db/models/policy.py`
- Modify: `apps/api/app/core/config.py`
- Modify: `apps/api/app/services/policy_service.py`
- Test: `apps/api/tests/test_phase5_domain_profiles.py`
- Test: `apps/api/tests/test_phase5_materiality.py`
- Test: `apps/api/tests/test_phase5_resolvers.py`
- Test: `apps/api/tests/test_phase5_signing_key_provider.py`
- Test: `apps/api/tests/test_phase5_policy_epoch.py`
- Test: `apps/api/tests/test_phase5_migration_0065.py`

### Frozen contracts

The complete signed profile/selection envelopes and reconstructable selection
projection, resolver result, closed material-field grammar/registry/collection
semantics and exact hashes, key-purpose/provider/signature encoding interface,
and tenant policy epoch authority are frozen in
`docs/CODEX_INTERFACE_REGISTRY.md` §§4, 5, 7, and 11.

### TDD steps

- [ ] Write failing tests for deterministic profile hash, unique profile ID and
  version, effective dates, tenant selection, expired/unreviewed rejection, and
  profile inability to return an authorization decision.
- [ ] Add signed-selection-chain tests for sequence one and subsequent links,
  exact profile-content and prior-envelope hashes, atomic epoch/projection CAS,
  reactivation as a new selection/epoch, and fail-closed selection gaps, forks,
  broken prior ID/hash, stale epoch, cross-tenant link, projection rewind, and
  reconstructed-projection mismatch. Repair may fold verified history only.
- [ ] Add `DOMAIN_INVARIANT_FAILED` producer tests through the owned invariant
  evaluator, asserting exact signed profile/version and normalized-input
  evidence, deduplication key, lifecycle update behavior, and tenant isolation.
  WU-B must not change the central finding catalog.
- [ ] Write failing signing tests for purpose separation, KMS/HSM provider
  routing, production rejection of local HMAC, rotation, verify-only history,
  revocation, algorithm/key ID/tenant mismatch, and active-key material reuse.
  Add cross-language vectors for the exact domain-NUL-canonical-object signing
  input and strict unpadded base64url HS256/ES256/EdDSA encoding; reject padding,
  standard base64, invalid characters/trailing bits/length, DER or high-S ES256,
  alternate wrappers, and any non-signature field omission.
- [ ] Write failing policy-epoch tests for transactional monotonic increment,
  material versus display-only change, CAS conflict, rollback-as-new-epoch,
  permit invalidation, and cross-tenant isolation.
- [ ] Write failing rollout tests for `DISABLED`, `OBSERVE`, `SHADOW`, and
  `AUTHORITATIVE`; prove only authoritative mode can issue V2 permits and only
  after migrations, signed profile, key-provider health, current epoch, global
  kill switch, and Sol-promoted capability are all satisfied.
- [ ] Write failing resolver tests for typed exact targets, ambiguous targets,
  unsupported types, destination normalization, resolver drift, bounded output,
  and no external calls.
- [ ] Write failing materiality tests for every closed `MaterialFieldPathV1`
  grammar boundary, complete P0 path registry, exact collection semantics,
  missing/null/empty/UNKNOWN distinctions, unsigned-byte ordering, duplicate
  set handling, and golden per-field/material-fields/profile-content hashes.
  Reject unknown paths, wildcard/index/map-key variants, missing consequential
  material, profile-added paths, removed core paths, or changed semantics.
- [ ] Implement reviewed declarative profile parsing and pure invariant
  evaluation without eval, imports, filesystem traversal, process spawn, or
  network access.
- [ ] Implement exact resolver registry dispatch by resolver ID/version. Do not
  select by fuzzy domain or provider name.
- [ ] Implement the sole materiality projection/hash helper used later by every
  authority component and reconstruct the current tenant selection projection
  only from its verified, append-only, gap-free signed chain.
- [ ] Implement migration 0065 only after WU-00's verified persistent backup and
  exact persistent-current/single-head 0064 evidence are accepted. Migration
  0065 creates only reviewed profile/selection, `TenantPolicyEpoch`, and tenant
  rollout records with composite tenant constraints. It must not create any V2
  receipt/approval extension, permit, attempt, transition, persistent-effect,
  delegation, outcome, or banking-link persistence. Upgrade and rollback tests
  pass before profile or policy-epoch consumers are approved.
- [ ] Emit `DOMAIN_INVARIANT_FAILED` through the invariant evaluator when its
  authoritative result is violated. Do not synthesize it in WU-H.
- [ ] Run focused tests and source-scan for `eval`, `exec`, dynamic imports, and
  policy-decision enums in profile code.
- [ ] Sol reviews profiles as non-authorizing data and freezes the materiality
  contract before WU-C.

---

## PH5-WU-C: Canonical AI Action V2 and semantic equivalence

**Files:**

- Create: `apps/api/app/services/action_integrity/canonical_v2.py`
- Modify: `apps/api/app/core/control_engine/canonical_action.py`
- Modify: `apps/api/app/services/receipt_service.py`
- Modify: `apps/api/app/services/native_control/cross_provider_conformance.py`
- Test: `apps/api/tests/test_phase5_canonical_action_v2.py`
- Test: `apps/api/tests/test_phase5_semantic_equivalence.py`
- Test: `apps/api/tests/test_canonical_ai_action_contract.py`

### Frozen result

Canonical bytes, the full CanonicalAIActionV2 schema, closed material-field
grammar/registry/collection semantics, exact field/full/unbound-plan hashes,
tagged unknowns, `ActionPlanBindingV1`, and structured
`SemanticComparisonResult` are frozen in
`docs/CODEX_INTERFACE_REGISTRY.md` §§1, 2, 5, 6, and 10.

### TDD steps

- [ ] Add golden vectors for stable ordering, Unicode, decimal quantity,
  timestamp, null versus unknown, bounded lists/maps, and domain-separated hash.
- [ ] Add property tests showing key order does not change bytes and every
  material mutation changes the exact per-field and full material hashes.
- [ ] Add golden material-hash vectors covering every closed path and collection
  semantic, unsigned-byte ordering, missing/null/empty/UNKNOWN distinctions,
  and the planned-child unbound hash that removes only
  `action_plan_binding` under its distinct domain.
- [ ] Add all `ActionPlanBindingV1` tagged-case tests: valid `STANDALONE`,
  `PLAN_ROOT`, and `PLANNED_STEP`; required/null field combinations; exact
  signed-plan and step digests; parent/child binding; and rejection of partial,
  cross-tenant, cross-plan, or alternate-root bindings.
- [ ] Add the registry §10 non-circular construction vector: preassigned root
  and child action IDs, child unbound hash with only `action_plan_binding`
  removed, signed plan digest, computed step digest, bound root, and full bound
  child hash. Prove that substituting child `action_id`, `parent_action_id`, any
  non-binding material, plan/step digest, or complete plan binding changes the
  committed hash and fails closed.
- [ ] Add V1 compatibility fixtures proving old signatures/hashes are verified
  by the V1 path and V1-to-V2 adds only explicit unknown values.
- [ ] Add equivalence tests for identical resolved action, tool-version drift,
  subject/resource/authority/purpose/target/destination/value mutation,
  cross-version ambiguity, and unresolved material.
- [ ] Add owned-producer tests for `TOOL_FINGERPRINT_CHANGED` and
  `UNKNOWN_ACTION_SEMANTICS`, asserting exact authorized/actual or unresolved
  evidence, registry deduplication key, lifecycle behavior, repeated evidence,
  and tenant isolation. WU-C must not change the central finding catalog.
- [ ] Implement the V2 projection using the WU-A types, WU-B resolvers, and one
  materiality profile. Produce the registry's canonical bytes directly so later
  signed objects can apply the sole §7 domain-NUL input rule without an
  alternate digest/JWS/wrapper. Keep V1 functions unchanged for legacy
  verification.
- [ ] Route Phase 4 conformance through the shared equivalence result without
  changing provider-specific receipt hashes.
- [ ] Emit tool-fingerprint and unknown-semantics findings through the owned
  fingerprint/canonical service at the authoritative comparison/build point;
  never defer producer semantics to the product router.
- [ ] Run canonical, authorization-kernel, conformance, banking transport, and
  approval-binding regressions.
- [ ] Sol reviews every canonical byte and compatibility boundary before WU-D.

---

## PH5-WU-D: Decision Receipt V2 and Approval Binding V2

**Files:**

- Modify: `apps/api/app/db/models/evidence.py`
- Modify: `apps/api/app/db/models/policy.py`
- Modify: `apps/api/app/db/models/action_integrity.py`
- Modify: `apps/api/app/db/models/banking_transaction.py`
- Modify: `apps/api/app/db/models/runtime_intelligence.py`
- Modify: `apps/api/app/services/receipt_service.py`
- Modify: `apps/api/app/api/routers/enforcement.py`
- Create: `apps/api/app/services/action_integrity/approval_binding.py`
- Create: `apps/api/app/db/migrations/versions/0066_phase5_execution_lifecycle.py`
- Test: `apps/api/tests/test_phase5_decision_receipt_v2.py`
- Test: `apps/api/tests/test_phase5_approval_binding_v2.py`
- Test: `apps/api/tests/test_phase5_approval_decision_atomicity.py`
- Test: `apps/api/tests/test_phase5_migration_0066.py`
- Test: `apps/api/tests/test_decision_execution_receipts.py`
- Test: `apps/api/tests/test_depth_upgrade_approval_authority.py`

### Frozen contracts and storage

DecisionReceiptV2, ApprovalBindingV2, PermittedVariationEnvelopeV1, their exact
material/profile/selection/plan hashes and signed bodies, key purposes/signature
encoding, append-only ApprovalAuthorityEventV1 chain and reconstructable
projection, trusted `ApprovalRequest` linkage, and immutable linked extension
storage are frozen in `docs/CODEX_INTERFACE_REGISTRY.md` §§5, 7, and 8.
The trusted approval DTO, approval list/decision methods and paths, response
envelopes, and API/browser separation are frozen in registry §12. Registry §10
also freezes the exact-only root envelope and root-only matcher input used by
`SCOPED_PARENT_PERMIT`, plus the lifecycle persistence shapes owned by 0066.

### TDD steps

- [ ] Add failing Decision Receipt tests for V2 schema domain, canonical hash,
  exact material-fields hash, profile/materiality IDs, versions and hashes,
  positive current policy epoch, ControlPlan digest, delegation digest, expiry,
  key ID, exact §7 signing input and strict signature encoding. Approval and
  variation tests, not the Decision Receipt body, own selection-envelope fields.
- [ ] Prove each valid `ActionPlanBindingV1` case is transitively bound by the
  receipt/approval canonical-action and material-fields hashes; any plan/step/
  authority-mode mutation invalidates the receipt, approval, and variation
  eligibility rather than being treated as permitted variation.
- [ ] Add failing approval tests for canonical trusted rendering, prompt/agent
  injection isolation, wrong role, expiry, revocation, policy/profile/tool/
  target mutation, use limit, replay, wrong tenant, wrong signature domain, and
  signing-key rotation with historical verification but no stale eligibility.
- [ ] Add `PermittedVariationEnvelopeV1` tests for an explicit empty-matcher
  exact-only envelope and every bounded `ONE_OF` path; exact base per-field/full
  hashes, sorted unique matchers/hashes, matching binding/request/tenant/profile/
  selection/epoch/plan/expiry/use limit, current key state, and fail-closed
  omitted material, disallowed matcher/path, widened value/time/use, stale
  selection/epoch, mutation, revocation, or cross-tenant reuse.
- [ ] Add scoped-parent approval tests proving the approval binding and
  exact-only (`matchers=[]`) envelope evaluate the immutable `PLAN_ROOT`
  canonical/material hashes only. Reject applying that envelope to a child,
  any root plan-binding/digest mutation, a non-empty scoped-parent matcher set,
  or any attempt to treat the envelope as child-field variation authority.
- [ ] Add approval-authority reconstruction tests folding the immutable binding
  and every signed use/expiry/revocation event. Reject gap, fork, duplicate or
  conflicting sequence/idempotency, broken prior ID/hash, bad signature/key,
  counter/state/version mismatch, terminal successor, unexpected extra event,
  stale/rewound projection, and cache/history mismatch; rebuild only from the
  verified append-only history and prove exact equality.
- [ ] Test the exact registry §12 trusted-approval request/response DTO and
  approval list/decision API method/path contracts. Assert every trusted
  canonical field, display-only profile labels, visibly separated untrusted
  agent context, pagination/status semantics, real `ApprovalRequest` ID, and no
  API-path/browser-href substitution.
- [ ] Add `APPROVAL_INVALIDATED` producer tests through the owned approval
  service, asserting invalidating material/currentness evidence, exact registry
  deduplication key, lifecycle/repeated-evidence behavior, and tenant isolation.
  WU-D must not change the central finding catalog.
- [ ] Add failing decision-flow tests proving the authoritative
  `ApprovalRequest` and its `ApprovalBindingV2` transition in one database
  transaction after role and SLA validation. Prove a binding/signing/persistence
  failure rolls back the request decision, denial cannot leave an active binding,
  duplicate decisions are idempotently rejected, and the WU-00 `all`/omitted
  filter behavior remains unchanged.
- [ ] Implement immutable one-to-one V2 extension records created atomically
  with the existing base receipt/binding rows. Retain exact V1/V1.1 verification
  dispatch; missing extensions and unknown versions fail verification.
- [ ] Implement ApprovalBindingV2 as a separately signed object; do not treat the
  legacy SHA-256 `signed_receipt` column as an external signature. Create and
  bind the exact signed variation envelope for every approval, including an
  empty-matcher envelope for exact-only approval.
- [ ] Route the existing enforcement approval-decision endpoint through the V2
  approval service when a versioned `hawk.ai_action.v2` request is present.
  Preserve the legacy decision path for non-V2 requests. Do not commit the
  request before the binding transition, audit record, and role/SLA checks are
  complete.
- [ ] Make current policy epoch, signed selection head, variation envelope and
  freshly reconstructed approval projection mandatory for new consequential
  V2 execution eligibility while reporting historical signature validity
  separately.
- [ ] Implement migration 0066 as the sole schema owner for all frozen V2 and
  lifecycle persistence: Decision/Execution Receipt V2 and ApprovalBindingV2
  extensions; approval-use events/projection; generic permit envelope,
  permit-transition/projection; action attempts/execution transitions;
  persistent-effect envelope/transitions/projection; delegation context/events;
  expected-outcome contracts/verifications; required reconstruction/CAS,
  uniqueness and tenant-composite constraints; and the one-to-one banking
  compatibility link. No later WorkUnit may modify 0066.
- [ ] Emit `APPROVAL_INVALIDATED` through the approval service at the
  authoritative invalidation transaction; do not defer it to WU-H.
- [ ] Run receipt, approval, evidence bundle, policy, and tenant-isolation tests.
- [ ] Sol performs isolated cryptography/authorization review before E or F.

---

## PH5-WU-E: Generic Execution Permit and endpoint linkage

**Files:**

- Create: `apps/api/app/services/action_integrity/execution_authority.py`
- Modify: `apps/api/app/services/native_control/endpoint_permit_authority.py`
- Modify: `apps/api/app/services/banking_transaction_integrity_service.py`
- Modify: `apps/api/app/services/llm_gateway_secure/gateway.py`
- Modify: `apps/api/app/services/llm_gateway_service.py`
- Modify: `apps/api/app/services/mcp/registry.py`
- Modify: `apps/api/app/services/agui/registry.py`
- Modify: `apps/api/app/services/endpoint_agent_service.py`
- Modify: `apps/api/app/services/ai_orchestration/itsm.py`
- Modify: `apps/api/app/services/remediation/remediation_engine.py`
- Test: `apps/api/tests/test_phase5_execution_permit.py`
- Test: `apps/api/tests/test_phase4_native_endpoint_permit_authority.py`
- Test: `apps/api/tests/test_banking_transaction_integrity_api.py`
- Test: `apps/api/tests/test_llm_gateway_secure_hardening.py`
- Test: `apps/api/tests/test_llm_gateway_integration.py`
- Test: `apps/api/tests/test_llm_response_control_chain_contract.py`
- Test: `apps/api/tests/test_mcp_registry.py`
- Test: `apps/api/tests/test_mcp_core_tools_registry.py`
- Test: `apps/api/tests/test_agui_registry.py`
- Test: `apps/api/tests/test_agui_core_actions_registry.py`
- Test: `apps/api/tests/test_endpoint_agent.py`
- Test: `apps/api/tests/test_ai_orchestration_layer.py`
- Test: `apps/api/tests/test_remediation_workflow.py`
- Test: `apps/api/tests/test_phase5_server_execution_permit_integration.py`

### Frozen permit semantics

The exact signed permit body, material/variation/plan binding, §7 signature
encoding, key purpose, append-only permit-transition chain/reconstructable
projection, approval-use consumption point, executor transaction boundary,
crash/retry behavior, banking compatibility projection, and linked non-server
authority semantics are frozen in `docs/CODEX_INTERFACE_REGISTRY.md` §§5, 7,
8, and 10.

### Frozen audited execution-seam classification

- Server-controlled final seams are the secure LLM provider call reached
  through `llm_gateway_secure/gateway.py` and `llm_gateway_service.py`, the
  registered MCP tool executor, registered AGUI action executor, server-side
  endpoint platform-action connector call, ITSM outbound ticket-create call,
  and auto-apply/rollback remediation handler. When an action is explicitly
  authoritative V2, each seam must claim and freshly revalidate the exact
  permit/material/variation/plan/projection in the final Hawk transaction
  immediately before invoking that protected executor. No mutable middleware
  or unchecked caller step may occur between commit of the claim and
  invocation.
- A mismatch, stale or invalid reconstruction, failed claim, block, expiry, or
  revoked/currentness failure returns before the protected executor. Executor-
  spy evidence must prove zero calls. Disabled Phase 5 and legacy V1 behavior
  remain byte/API/authority compatible.
- The .NET banking gate, endpoint broker, native callback and live-adapter
  paths, and OpenAI/customer-runtime paths are linked non-server authorities.
  Hawk records their permit/control/evidence/acceptance references but does not
  claim that its server invoked or prevented their executor and does not emit
  `HAWK_RUNTIME_OBSERVED` non-execution without a real Hawk server control point.
- Direct human/admin REST retains its existing authorization authority and is
  not silently converted into Phase 5 server execution. The V2 final-seam rule
  applies only when that request is explicitly projected as an authoritative
  V2 action with its exact action/attempt/permit context.

### TDD steps

- [ ] Add failing issuance tests requiring V2 decision, exact approval and
  signed `PermittedVariationEnvelopeV1` where required, current signed profile
  selection/epoch, ControlPlan, exact closed material-fields hash,
  `ActionPlanBindingV1`, bounded use, expiry, nonce, attempt, and strict §7
  signature input/base64url/algorithm encoding.
- [ ] Add `SCOPED_PARENT_PERMIT` issue/claim vectors that separately verify the
  exact root Decision Receipt and, when required, root ApprovalBindingV2 plus
  exact-only root envelope, then the one declared child's exact action ID,
  parent ID, plan binding, recomputed plan/step digests, unbound/full hashes,
  predecessors, boundaries, counts, expiry, and delegation/currentness. Prove
  the root envelope is never matched against child material, every child permit
  is a distinct attempt, and issuance atomically consumes one root approval use.
- [ ] Add atomic consumption concurrency tests; exactly one consumer succeeds.
- [ ] Add wrong tenant/principal/action/tool/parameter/target/destination/value/
  purpose/authority/profile/selection/policy/plan/variation-envelope negatives,
  plus expiry, replay, revocation, over-use, copied permit/signature, and any
  per-field/full/unbound material-hash mismatch.
- [ ] Include alternate root/child action ID, wrong `parent_action_id`, undeclared
  or wrong-authority-mode step, substituted plan/step digest, widened child
  material, root envelope matcher applied to child, and approval/step/plan count
  conflict in those fail-before-executor negatives.
- [ ] Add permit-transition reconstruction tests from the immutable permit and
  contiguous signed history. Reject gap, fork, duplicate/conflicting sequence
  or idempotency, broken prior ID/hash, bad signature/key, illegal edge,
  version/claim mismatch, unexpected extra event, stale/rewound projection, and
  projection/history mismatch immediately before claim and invocation. Repair
  may rebuild only from verified append-only history and must prove exact fold
  equality.
- [ ] Add owned-producer tests for `EXECUTION_PERMIT_MISMATCH` and
  `CONTROL_PLAN_DOWNGRADED`, asserting permit/recomputed-material or plan-diff
  evidence, exact registry deduplication key, lifecycle/repeated-evidence
  behavior, and tenant isolation. WU-E must not change the central catalog.
- [ ] In `test_phase5_server_execution_permit_integration.py`, parameterize
  executor spies across every frozen server-controlled seam and its necessary
  caller wiring. Prove an authoritative V2 call claims exactly once, recomputes
  and revalidates exact material/variation/plan/projection immediately before
  the protected call, and a block or any mismatch invokes it zero times.
- [ ] Prove disabled/legacy calls follow their existing paths unchanged and
  direct human/admin REST retains existing authority unless the caller provides
  an explicit authoritative V2 projection. No implicit action construction or
  permissive fallback may satisfy the V2 seam.
- [ ] Test the linked .NET banking gate, endpoint broker, native callback/live
  adapter, and OpenAI/customer-runtime classifications. Assert linked evidence
  and truthful unknown/provider/endpoint state without a false server-execution
  or server-observed non-execution claim.
- [ ] Add crash-before-invocation, crash-after-claim, async-provider acceptance,
  claim lease expiry, and bounded-retry tests. Missing evidence becomes
  unverified/unknown and never proves non-execution.
- [ ] Generalize the banking grant pattern through the new service while
  preserving banking API behavior and its proven function path.
- [ ] Link endpoint broker authority/consumption evidence without changing the
  endpoint permit wire format or exposing a bearer token.
- [ ] Wire the final-gate service into only the seven audited server-controlled
  files above. Pass the explicit action, attempt, permit, caller/control-point,
  and prepared-material context through necessary callers; do not duplicate
  permit validation or infer authority from correlation IDs, legacy approval,
  UI state, or provider callbacks.
- [ ] Emit permit-mismatch and ControlPlan-downgrade findings through the owned
  final-gate service before executor invocation. Consume the 0066 schema as
  frozen; do not edit any migration.
- [ ] Run all detailed WU-E tests plus permit, banking, endpoint-authority,
  tenant, replay, race, LLM, MCP, AGUI, endpoint-platform, ITSM, remediation,
  direct-REST compatibility, and linked-authority classification regressions.
- [ ] Sol reviews every audited final seam for atomicity, zero-call blocking,
  capability truth, non-server classification, secret handling, and legacy
  compatibility.

---

## PH5-WU-F: Execution Receipt V2, comparator, evidence, and drift

**Files:**

- Create: `apps/api/app/services/action_integrity/execution_proof.py`
- Modify: `apps/api/app/db/models/evidence.py`
- Modify: `apps/api/app/services/receipt_service.py`
- Modify: `apps/api/app/services/canonical_evidence_bundle_service.py`
- Modify: `apps/api/app/services/native_control/findings.py`
- Test: `apps/api/tests/test_phase5_execution_receipt_v2.py`
- Test: `apps/api/tests/test_phase5_execution_comparator.py`
- Test: `apps/api/tests/test_phase5_execution_drift_findings.py`

### Frozen state dimensions

The lossless canonical execution-state, evidence-quality, comparator-result,
outcome-input evidence, and legacy mapping contracts are frozen in
`docs/CODEX_INTERFACE_REGISTRY.md` §9. The signed ExecutionReceiptV2 body and
immutable extension storage are frozen in §8. Receipt and comparison domains,
key purposes, and signing-provider rules are frozen in §7. The closed material-
field grammar, collection semantics, and exact field/full hashes consumed by
the receipt/comparator are frozen in §5. WU-F supplies
execution/comparator evidence to WU-G but does not create or decide
`ExpectedOutcomeContractV1` or `OutcomeVerificationV1`.

### TDD steps

- [ ] Add failing receipt tests for permit consumption, actual V2 material,
  attempt, start/end, result digest, downstream object, evidence source/quality,
  terminal state, and signed schema domain.
- [ ] For both `ExecutionReceiptV2` and
  `AuthorizationExecutionComparisonV2`, add exact canonical signed-body tests
  and reject wrong domain, wrong signing purpose, wrong key ID/key state, wrong
  tenant, algorithm mismatch, mutation, and cross-object signature reuse.
- [ ] Add comparator tests mutating every material field defined in WU-B.
- [ ] Prove `MATCHED + FAILED` and `MATCHED + CANCELLED` remain non-successful.
- [ ] Prove missing callback is `UNKNOWN`, provider report cannot become
  externally verified, and OS denial is strong only for that OS consequence.
- [ ] Implement normalized evidence quality and signed V2 projections while
  preserving V1 receipt verification.
- [ ] Generate drift evidence/finding through existing findings/evidence paths;
  preserve one action chain and idempotent supersession.
- [ ] WU-F alone updates `native_control/findings.py`. Register all 20 exact §15
  codes, severities, required-evidence validation, deduplication keys, lifecycle
  update/closure rules, and remediation linkage. Add catalog contract tests for
  every code. Do not move upstream producer decisions into this central file.
- [ ] Add owned-producer tests for `ACTION_PARAMETER_DRIFT`,
  `ACTION_TARGET_DRIFT`, `ACTION_DESTINATION_DRIFT`, `ACTION_VALUE_DRIFT`,
  `EXECUTION_DRIFT_DETECTED`, and `EXECUTION_UNVERIFIED`; assert exact
  field-level evidence, registry deduplication key, lifecycle/repeated-evidence
  behavior, and tenant isolation.
- [ ] Update evidence bundles to keep material, execution, and outcome-integrity
  dimensions separate while treating outcome as input/unknown only; WU-G alone
  creates the expected-outcome contract and verification verdict.
- [ ] Run receipt, evidence-bundle, findings, coverage assertion, and tenant
  regressions.
- [ ] Sol reviews comparator completeness and capability truth before WU-G.

---

## PH5-WU-G: Multi-step, asynchronous, persistent, delegation, and outcomes

**Files:**

- Create: `apps/api/app/services/action_integrity/complex_actions.py`
- Modify: `apps/api/app/services/delegation_chain_authority_service.py`
- Test: `apps/api/tests/test_phase5_multistep_actions.py`
- Test: `apps/api/tests/test_phase5_async_execution.py`
- Test: `apps/api/tests/test_phase5_persistent_effects.py`
- Test: `apps/api/tests/test_phase5_delegation_integrity.py`
- Test: `apps/api/tests/test_phase5_outcome_verification.py`

### Frozen §10 contracts

WU-G implements every registry §10 signed object using its exact domain, key
purpose, §7 signing input/encoding, and §5 material/plan binding:
`ActionExecutionTransitionV1`, `ActionPlanV1`, `PersistentEffectV1`,
`PersistentEffectTransitionV1`, `DelegationContextV1`,
`DelegationLifecycleEventV1`, `ExpectedOutcomeContractV1`, and
`OutcomeVerificationV1`. `ActionPlanBindingV1`, the plan/step digests, and
planned-child unbound/full material hashes are exact. Mutable attempts and
projections contain no independent authority and must reconstruct from the
verified immutable envelope/event history.

### TDD steps

- [ ] Add ordered-plan tests for expected steps, per-step authority, inserted or
  reordered steps, retry limits, partial completion, and final aggregation.
  Cover every `ActionPlanBindingV1` case, exact plan/step digest and child
  unbound/full material hash, parent/root binding, predecessor/count/boundary/
  expiry checks, separate-decision versus scoped-parent authority, and reject
  insertion/deletion/reorder/re-sign/alternate-root or child-material mutation.
- [ ] For scoped-parent cases, prove the root Decision Receipt and exact-only
  root ApprovalBinding/envelope are evaluated only against root material; the
  declared step binds the preassigned child action ID, root parent ID, every
  non-binding child field, and the exact plan binding through the non-circular
  unbound/plan/step/full hash chain. Reject child envelope matching or variation
  and intersect root-use, step, and plan execution counts.
- [ ] Add async tests for authorized/queued/started/terminal transitions,
  duplicate/idempotent callback, out-of-order transition, cancellation, expiry,
  timeout, and missing callback.
- [ ] Add persistent-effect tests for owner, scope, downstream object, expiry,
  expected object state, last verification/validity, drift, revocation,
  evidence-backed recovery/remediation, and honest unknown state.
- [ ] Add delegation tests for immutable parent/child edge, attenuation,
  descendant revocation, cross-tenant rejection, and child-outcome aggregation.
- [ ] In `test_phase5_persistent_effects.py`, cover every registry legal
  state-changing edge, `VERIFICATION_OBSERVED` same-state evidence refresh, all
  four terminal states, forbidden/self/terminal-successor edges, exact
  predecessor hash and version increment, exact redelivery idempotency,
  conflicting key/sequence/replay, expiry-without-event current-truth failure,
  CAS conflict, and complete fresh-fold/projection equality before append and
  before coverage/drift/remediation exposure.
- [ ] Prove `MODIFIED -> VERIFIED_RECOVERED` requires the exact expected object
  state, evidence quality exactly `INDEPENDENTLY_VERIFIED`, authenticated
  independent sources, a current validity interval, same-tenant
  remediation action/attempt/terminal receipt, and `SATISFIED` signed outcome
  verification with `recovery_basis=REMEDIATION_EXECUTION`. Prove
  `LATE_VERIFICATION` is allowed from uncertainty only when no prior
  modification exists; the folded `recovery_requires_remediation` flag survives
  `ORPHANED`/`UNKNOWN`, and `verification_valid_until` bounds current truth.
  Add the exact negative case `evaluation_time < last_verified_at` and assert
  that future-dated verification returns current truth `UNKNOWN`. Provider
  success, stale evidence, mismatch, UNKNOWN, or projection-only recovery
  cannot close `PERSISTENT_EFFECT_DRIFT`.
- [ ] In `test_phase5_delegation_integrity.py`, cover every registry
  event/edge from the `REGISTERED` base, sequence-one `ISSUED`, both terminal
  states, exact predecessor/version fold, identical redelivery, conflicting
  idempotency/sequence/replay, terminal successor, stale/rewound projection,
  current-source-authority revalidation, and atomic all-or-nothing descendant
  approval/permit revocation through their existing authorities.
- [ ] For every registry §10 signed object, add canonical-body/domain/key-purpose
  tests and reject wrong domain, wrong purpose, wrong key/key state, wrong
  tenant, algorithm mismatch, malformed/non-round-tripping base64url, bad
  HS256/ES256/EdDSA length/encoding, alternate signing wrapper, tamper,
  replay/idempotency conflict, and signature reuse across object types.
- [ ] For every append-only §10 history, reject sequence gaps, forks,
  duplicate/conflicting sequence or idempotency, broken prior ID/hash where the
  schema declares a prior link, illegal edge, stale state/version, unexpected
  extra event, cross-tenant reference, projection rewind, and cache/history
  mismatch. Rebuild each mutable attempt/projection from the verified immutable
  envelope and complete ordered history and prove exact equality; repair may
  never invent, delete, reorder, or overwrite signed evidence.
- [ ] Add `ExpectedOutcomeContractV1` and `OutcomeVerificationV1` tests for
  deterministic satisfied/violated/partial/unknown/not-applicable results,
  verification deadlines, provider-success overclaim, source-set idempotency,
  signing, tenant isolation, and reconstruction.
- [ ] Add owned-producer tests for `DELEGATION_AUTHORITY_EXPANDED`,
  `PERSISTENT_EFFECT_CREATED`, `PERSISTENT_EFFECT_DRIFT`, and
  `OUTCOME_MISMATCH`, asserting exact evidence, §15 deduplication key,
  lifecycle/repeated-evidence behavior, and tenant isolation. WU-G must not
  change the central finding catalog.
- [ ] Implement a durable transition compare-and-set service. Do not use a
  process-local queue as authority.
- [ ] Implement the exact append-only transition signature, legal state DAG,
  strict §7 signature encoding, sequence/state-version CAS,
  idempotency/conflict behavior, persistent-effect and delegation terminal/
  fold rules, fresh-fold projection equality, one terminal receipt timing, and
  authoritative non-execution rules frozen in
  `docs/CODEX_INTERFACE_REGISTRY.md` §10.
- [ ] Implement every frozen §10 envelope/event and reconstructable projection,
  including deterministic `ExpectedOutcomeContractV1` creation and
  `OutcomeVerificationV1` evaluation. Emit delegation, persistent-effect, and
  outcome findings through their owned services; never synthesize them in H.
- [ ] Link existing `DeferredSideEffect` records to V2 action/receipt/effect
  state without deleting history.
- [ ] Run delegation, runtime-chain, receipt, findings, and coverage regressions.
- [ ] Sol reviews lifecycle completeness and revocation semantics before H/I.

---

## PH5-WU-H: Product APIs, Action Detail, findings, coverage, and metrics

**Files:**

- Create: `apps/api/app/api/routers/action_integrity.py`
- Create: `apps/api/app/services/action_integrity/metrics.py`
- Create: `apps/api/app/db/migrations/versions/0067_phase5_control_coverage.py`
- Modify: `apps/api/app/api/routers/runtime_intelligence.py`
- Modify: `apps/api/app/api/routers/findings.py`
- Modify: `apps/api/app/api/routers/control_coverage.py`
- Modify: `apps/api/app/api/routers/ops.py`
- Modify: `apps/api/app/core/control_coverage.py`
- Modify: `apps/api/app/db/models/control_coverage.py`
- Modify: `apps/api/app/services/control_coverage/assertion_evaluators.py`
- Modify: `apps/api/app/services/control_coverage/calculator.py`
- Modify: `apps/api/app/services/control_coverage/recommendations.py`
- Modify: `apps/api/app/main.py`
- Modify: `apps/web/src/lib/types.ts`
- Modify: `apps/web/src/lib/api.ts`
- Create: `apps/web/src/lib/action-integrity-links.mjs`
- Create: `apps/web/src/lib/action-integrity-links.d.ts`
- Create: `apps/web/src/lib/action-integrity-view-model.mjs`
- Create: `apps/web/src/lib/action-integrity-view-model.d.ts`
- Modify: `apps/web/src/app/runtime-intelligence/action-trace/[id]/page.tsx`
- Modify: `apps/web/src/app/runtime-intelligence/action-graph/[id]/page.tsx`
- Modify: `apps/web/src/app/interaction-security/page.tsx`
- Modify: `apps/web/src/app/discovery/findings/[id]/page.tsx`
- Modify: `apps/web/src/components/control-coverage/control-coverage-panel.tsx`
- Test: `apps/api/tests/test_phase5_action_integrity_api.py`
- Test: `apps/api/tests/test_phase5_control_coverage_v2.py`
- Test: `apps/api/tests/test_phase5_migration_0067.py`
- Test: `apps/web/tests/action-integrity-detail.test.mjs`
- Test: `apps/web/tests/interaction-security-approvals.test.mjs`
- Test: `apps/web/tests/navigation-deep-links.test.mjs`

### TDD steps

- [ ] Add API tests for tenant-scoped Action Detail composition, explicit IDs,
  control plan, rejected candidates, blind spots, approval authority, permit,
  execution/outcome dimensions, evidence nodes, findings, timeline, and coverage.
- [ ] Test and implement the exact registry §12 Action Detail API method/path,
  runtime-event route key, canonical browser surface, `ApiReferenceV1` and
  `BrowserHrefV1` contracts, trusted-approval DTO, approval list/decision API
  contracts, and approval browser behavior. No alias route or cross-ID fallback
  is permitted.
- [ ] Assert the complete registry §12 `ActionIntegrityDetailV1` contract:
  Context, Action, Control, Authorisation, and Execution each expose every
  required §55 field with explicit `UNKNOWN` where proof is absent. Assert every
  closed §57 timeline stage in registry order, stable ordering for repeated
  durable events, tenant-scoped evidence nodes, explicit unknown/not-applicable
  states, and strict separation of API references from browser hrefs.
- [ ] Freeze and test `runtime_event_id` as the route key. Expose canonical,
  receipt, selection, ControlPlan, approval-request/binding, permit, evidence,
  and finding IDs separately using the exact join contract in
  `docs/CODEX_INTERFACE_REGISTRY.md` §12.
- [ ] Add authorization tests proving read/mutation roles and tenant isolation.
- [ ] Add executable Node `.mjs` tests under the existing `npm run test:ui`
  runner for pure link/view-model modules. Prove API paths are not browser
  links, evidence rows use API totals, native `real_acceptance_current` is
  visible, and approvals target the actual `ApprovalRequest`. Use API tests plus
  browser HTTP/navigation acceptance for behavior that requires rendered Next UI.
- [ ] Add profile-label tests proving labels change display only and canonical
  values remain stable.
- [ ] Implement a composed Action Detail response from existing services plus
  the Phase 5 V2 services; do not persist a UI projection as authority.
- [ ] Expose existing remediation workflow calls for the upstream findings;
  keep direct finding enforcement separate. WU-H owns only tenant-safe
  list/filter/detail/evidence/lifecycle/remediation projections and must not
  register a code, choose severity/deduplication/lifecycle, detect a condition,
  or emit/close any A–G finding.
- [ ] Implement `control-coverage/2.0` and all 13 Phase 5 dimensions frozen in
  `docs/CODEX_INTERFACE_REGISTRY.md` §14. Migration 0067 expands the constraint
  losslessly; legacy V1 snapshots remain V1.
- [ ] Expose and consume all 20 §15 codes produced by the approved A–G services
  and central WU-F catalog. Test evidence, severity, deduplication, lifecycle,
  remediation links, tenant isolation, filters and detail projection. WU-H does
  not implement, infer, or relocate an upstream producer.
- [ ] Expose tenant-safe metrics derived from durable Decision/Execution/
  Permit/Transition/Effect records. Process-local counters remain internal and
  cannot satisfy product metrics.
- [ ] Run API/UI targeted tests, TypeScript check, lint for changed files, and
  `npm run test:ui`. Boot the local UI and run browser navigation/approval
  acceptance for Action Detail, findings, evidence, coverage, and the mixed-
  status approvals queue; record HTTP results and screenshots in the ledger.
- [ ] Sol reviews authority selection, conservative labels, and no false green.

---

## PH5-WU-I: Six profiles, cross-vertical, security, and performance

**Files:**

- Create: `apps/api/app/services/action_integrity/profiles/financial_services.json`
- Create: `apps/api/app/services/action_integrity/profiles/healthcare.json`
- Create: `apps/api/app/services/action_integrity/profiles/government.json`
- Create: `apps/api/app/services/action_integrity/profiles/real_estate_construction.json`
- Create: `apps/api/app/services/action_integrity/profiles/energy_critical_infrastructure.json`
- Create: `apps/api/app/services/action_integrity/profiles/multi_tenant_saas.json`
- Create: `apps/api/tests/test_phase5_cross_vertical_profiles.py`
- Create: `apps/api/tests/test_phase5_security_invariants.py`
- Create: `apps/api/tests/test_phase5_performance.py`

### Representative profile boundaries

- Financial Services: own authorized account/resource allowed; cross-subject or
  out-of-scope value/beneficiary blocked.
- Healthcare: authorized care-context resource allowed; wrong patient/purpose or
  prohibited disclosure blocked.
- Government: authorized case/program scope allowed; wrong citizen/case or
  classification boundary blocked.
- Real Estate/Construction: authorized project/property action allowed; wrong
  project, approval threshold, or irreversible change blocked.
- Energy/Critical Infrastructure: approved asset/maintenance scope allowed;
  safety-impacting or unapproved control target blocked.
- Multi-Tenant SaaS: same-tenant resource allowed; cross-tenant resource or
  admin-authority expansion blocked.

### TDD steps

- [ ] Add one table-driven matrix spanning all six profiles and every required
  scenario: correct/wrong subject, correct/wrong resource, authority expansion,
  parameter/target/destination/value/tool-fingerprint change, approval
  invalidation, permit mismatch, execution match/drift, async state, persistent
  effect, delegation, and cross-tenant attack. Reuse the same generic assertions
  rather than duplicating six suites.
- [ ] Add invalid/unreviewed/expired/profile-hash/resolver-version negatives.
- [ ] Add security tests for every mandatory negative proof in the invariants
  artifact, including tenant, replay, mutation, revocation, signature domain,
  key rotation, canonical collision, Unicode/number/unit/null/array ambiguity,
  target/destination aliasing, profile tamper/rollback/wrong tenant, receipt and
  action-hash substitution, cross-provider confusion, cross-runtime permit,
  execution-evidence and target-confirmation spoofing, clock skew, expired
  policy/profile, legacy promotion, and provider-evidence overclaim.
- [ ] Add bounded benchmarks for canonicalization, materiality/invariant
  evaluation, Decision Receipt generation, approval validation, permit
  generation/validation/consumption, Execution Receipt creation, comparator,
  persistent-effect registration, outcome verification, and Action Detail.
  Record p50, p95, p99, throughput, timeout rate, error rate, CPU context, and
  environment without marketing claims.
- [ ] Implement the six reviewed data profiles only after tests define exact
  vocabulary, resolvers, materiality, invariants, and outcome rules.
- [ ] Run the cross-vertical, security, privacy/source-scan, and performance
  suites.
- [ ] Sol reviews each profile for vertical leakage and all security evidence.

---

## PH5-WU-J: Migration integration, compatibility, deployment smoke, regression, and report

**Files:**

- Modify: `apps/api/tests/test_fresh_database_migrations.py`
- Modify: `apps/api/tests/test_migration_0042_token_system_binding.py`
- Modify: `apps/api/tests/test_deployment_family_migration.py`
- Modify: `apps/api/tests/test_discovery_canonical_migrations.py`
- Create: `apps/api/tests/test_phase5_migrations.py`
- Create: `docs/validation/phase5-action-execution-integrity-report.md`
- Modify: `docs/PHASE5_VERTICAL_AGNOSTIC_AUDIT.md`
- Modify: `docs/PHASE5_P0_EXECUTION_LEDGER.md`

### TDD steps

- [ ] Write failing fresh-database and upgrade tests for 0065/0066/0067, tenant
  uniqueness, composite references, check constraints, indexes, unknown
  backfills, and non-destructive downgrade.
- [ ] Verify WU-B implemented 0065 from 0064, WU-D implemented 0066 from 0065,
  and WU-H implemented 0067 from 0066; report exactly one 0067 head.
- [ ] Run fresh SQLite migration, upgrade and rollback, existing migration
  suites, and model/schema
  tests.
- [ ] Back up the persistent Docker PostgreSQL database, migrate through 0067,
  restart API/web/worker/beat, and verify health. Do not delete volumes.
- [ ] Run a PostgreSQL smoke path for each profile, allow, block,
  non-execution, permit replay, async transition, persistent effect, Action
  Detail, finding, evidence, and coverage.
- [ ] Exercise flags through disabled, observe/compare, shadow, and selectively
  authoritative states. Prove disabled preserves V1 behavior and observe/shadow
  cannot issue executable V2 authority.
- [ ] Run targeted Phase 1–4 regressions, then the complete relevant API suite,
  endpoint/.NET suites affected by authority linkage, web type checks, targeted
  UI tests, and build.

Exact final command groups:

```bash
# Group 1 — complete relevant API/backend functional and regression suite.
# Security, performance, and migration files are excluded because Groups 2–4
# own them exactly once.
cd apps/api
.venv/bin/pytest -q -m "not integration" \
  --ignore=tests/test_phase5_security_invariants.py \
  --ignore=tests/test_phase5_performance.py \
  --ignore=tests/test_phase5_migration_0065.py \
  --ignore=tests/test_phase5_migration_0066.py \
  --ignore=tests/test_phase5_migration_0067.py \
  --ignore=tests/test_phase5_migrations.py \
  --ignore=tests/test_fresh_database_migrations.py \
  --ignore=tests/test_decision_execution_receipts_migration.py \
  --ignore=tests/test_phase4_native_control_acceptance_persistence.py

# Group 2 — consolidated security and negative-architecture suite, once.
.venv/bin/pytest -q tests/test_phase5_security_invariants.py

# Group 3 — migration upgrade/rollback and compatibility suite, once.
.venv/bin/pytest -q \
  tests/test_phase5_migration_0065.py \
  tests/test_phase5_migration_0066.py \
  tests/test_phase5_migration_0067.py \
  tests/test_phase5_migrations.py \
  tests/test_fresh_database_migrations.py \
  tests/test_decision_execution_receipts_migration.py \
  tests/test_phase4_native_control_acceptance_persistence.py
.venv/bin/alembic -c app/db/migrations/alembic.ini heads

# Group 4 — bounded development performance evidence, once.
.venv/bin/pytest -q tests/test_phase5_performance.py

# Group 5 — API/backend integration-marker suite, once. It is the exact
# complement of Group 1 for the same excluded security/performance/migration
# files.
.venv/bin/pytest -q -m "integration" \
  --ignore=tests/test_phase5_security_invariants.py \
  --ignore=tests/test_phase5_performance.py \
  --ignore=tests/test_phase5_migration_0065.py \
  --ignore=tests/test_phase5_migration_0066.py \
  --ignore=tests/test_phase5_migration_0067.py \
  --ignore=tests/test_phase5_migrations.py \
  --ignore=tests/test_fresh_database_migrations.py \
  --ignore=tests/test_decision_execution_receipts_migration.py \
  --ignore=tests/test_phase4_native_control_acceptance_persistence.py

# Group 6 — web unit behavior, static checks, and production build, once.
cd ../web
npm run test:ui
npx tsc --noEmit
npm run lint
npm run build

# Group 7 — endpoint authority-linkage suite, once.
cd ../endpoint-agent
../api/.venv/bin/pytest -q tests/test_native_endpoint_permit_binding.py

# Group 8 — affected .NET integration suite, once.
cd ../../integrations/microsoft-agent-framework-dotnet
$HOME/.dotnet/dotnet test Hawk.BankFoundry.sln --configuration Release
```

The union of Groups 1–8 is the final all-Phase-5 and complete relevant
backend/frontend/endpoint/.NET run. A test file belongs to exactly one group;
the identical Group 1/5 ignores are mandatory, their markers are complements,
and `tests/test_phase5_server_execution_permit_integration.py` carries the
`integration` marker and belongs exclusively to Group 5. The file's direct
WU-E focused run is pre-approval evidence, not an additional final-group run.
No separate targeted Phase 1–4 final run is added because Groups 1 and 5
already contain those regressions. New final-gate test files must be assigned to
one group before execution and recorded in the ledger.

Controlled persistent Docker/PostgreSQL upgrade, rollback preflight, service
restart/profile smoke, and browser-navigation acceptance are separate runtime
groups because they mutate controlled runtime state rather than the source tree.
Their exact commands/URLs, backup reference, screenshots, environment and
results are recorded before execution and each group runs once after Groups 1–8
pass. Group 5 uses only its declared integration-test resources and is not
rerun by the persistent product-database smoke. The controlled runtime groups
do not rerun Groups 1–8. WU-J records `PH5-M3-FINAL` only after all
groups and their failure classifications are complete.
- [ ] Classify all failures before changes; do not weaken, skip, or delete tests.
- [ ] Update only the mutable execution ledger, final validation report, and
  vertical audit with exact commands, counts, failures, environment,
  limitations, files, migrations, and Sol reviews. The immutable requirements
  traceability input is not modified during implementation; final status lives
  in the ledger/report/audit.
- [ ] Produce the required A–Q final report and end with exactly one Phase 5
  readiness truth statement plus vertical-agnostic status.
- [ ] Sol performs final diff, security, migration, compatibility, evidence,
  capability, and report review and issues `SOL_FINAL_ACCEPTANCE`.

## Rollback and recovery strategy

- Feature rollback: disable Phase 5 tenant flags. V1 verification and existing
  Phase 4 behavior remain available; disabled/observe/shadow modes cannot issue
  new V2 executable authority.
- Authority rollback: increment the policy epoch and revoke unconsumed V2
  approvals/permits. Consumed permits and signed evidence remain immutable.
- Service rollback: deploy the previous application version only while retaining
  the additive schema. Old code must ignore new nullable/extension records.
- Database rollback: migrations have non-destructive downgrade paths that remove
  only empty Phase 5 structures after an explicit preflight proves no Phase 5
  evidence exists. Once V2 signed evidence exists, application rollback retains
  the schema; evidence is never deleted to satisfy downgrade.
- Profile rollback: activate a prior reviewed profile version with a new tenant
  selection record and policy epoch. Never overwrite a signed profile version.
- Failed PH5-WU-00M migration: rely first on PostgreSQL transactional rollback.
  The exact verified pre-migration restore command is authorized only when the
  one permitted upgrade has failed and read-only checks prove rollback did not
  preserve exact 0053 state. No success-path restore, downgrade, stamp, reset,
  seed, database drop, `compose down`, or volume deletion is permitted.
- Failed later deployment: stop new V2 issuance, preserve receipts/transitions,
  report degraded/unknown coverage, and require a new bounded recovery decision;
  PH5-WU-00M is not standing restore authority after it completes.

---

## Formal review protocol

Each WorkUnit returns the result fields required by the central ledger schema;
the orchestrator, not the worker, records them after review. Phase 5 requires
both review envelopes over the same patch and plan hash:

```text
SOL_CHANGE_REVIEW {
  batch_id, commit_or_patch
  status: APPROVED_FOR_MERGE | FIX_REQUIRED | REJECTED
  architecture, security, vertical_neutrality, tenant_isolation,
  compatibility, test_sufficiency, scope_conformance: PASS | FAIL
  findings[], required_fixes[], approved_merge_order, reviewed_at
}

SOL_CHANGE_APPROVAL {
  work_unit_id, plan_hash
  status: APPROVED | FIX_REQUIRED | REPLAN_REQUIRED | REJECTED |
          STOP_SECURITY_CONFLICT
  user_intent, scope, architecture, security, implementation_quality, tests,
  compatibility, capability_truth
  unproven_properties[], blocking_findings[], required_fixes[],
  accepted_limitations[], next_permitted_workunits[]
  reviewed_by: GPT-5.6-SOL
  reasoning_effort: EXTRA_HIGH
}
```

Only `APPROVED_FOR_MERGE` plus `APPROVED` enters the accepted implementation
set. Because VCS mutation is not currently authorized, “merge” means inclusion
in the Sol-accepted shared-tree set; it does not authorize a Git merge.

Dependent WorkUnits remain blocked until approval. A material change to any
frozen interface, invariant, migration strategy, authority, public API,
cryptographic domain, or capability claim requires a new plan revision and hash.

## Exact final acceptance contract

Only GPT-5.6 Sol may emit this block, after `PH5-M3-FINAL` and independent
verification of the critical evidence:

```text
SOL_FINAL_ACCEPTANCE {
  phase: PHASE_5_P0
  status: APPROVED_PRODUCTION_READY | REJECTED_NOT_READY
  authoritative_model: GPT-5.6-SOL
  actual_review_model: GPT-5.6-SOL
  reviewed_by: GPT-5.6-SOL
  reasoning_effort: EXTRA_HIGH
  baseline_commit: "<hash>"
  final_tree_hash: "<hash>"
  final_commit_or_tree_hash: "<hash>"
  approved_plan_hash: "<hash>"

  model_contract: PASS | FAIL
  architecture: PASS | FAIL
  implementation_quality: PASS | FAIL
  security: PASS | FAIL
  user_intent_conformance: PASS | FAIL
  scope_conformance: PASS | FAIL
  vertical_agnosticism: PASS | FAIL | NOT_APPLICABLE
  tenant_isolation: PASS | FAIL | NOT_APPLICABLE
  migration_safety: PASS | FAIL | NOT_APPLICABLE
  api_compatibility: PASS | FAIL | NOT_APPLICABLE
  provider_contracts: PASS | FAIL | NOT_APPLICABLE
  control_capability_truth: PASS | FAIL
  tests: PASS | FAIL
  regressions: PASS | FAIL
  real_acceptance: PASS | FAIL | NOT_REQUIRED
  performance: PASS | FAIL | ACCEPTED_LIMITATION
  documentation: PASS | FAIL

  canonical_action: PASS | FAIL
  materiality_and_equivalence: PASS | FAIL
  domain_profiles: PASS | FAIL
  decision_receipts: PASS | FAIL
  approval_binding: PASS | FAIL
  execution_permits: PASS | FAIL
  execution_receipts: PASS | FAIL
  execution_comparison: PASS | FAIL
  persistent_effects: PASS | FAIL
  delegation_integrity: PASS | FAIL
  privacy: PASS | FAIL
  security_tests: PASS | FAIL
  cross_vertical_tests: PASS | FAIL
  migrations: PASS | FAIL

  worker_models_used:
    - "<actual-model>"
  actual_models_by_work_unit:
    - work_unit_id: "<PH5-WU-ID>"
      requested_model: "<requested-model>"
      actual_model: "<actual-model>"
      substitution_reason: "<none-or-reason>"
  requested_models_unavailable:
    - GPT-5.6-LUNA
    - GPT-5.3-CODEX-SPARK
  implementation_agents:
    - "<agent-and-actual-model-or-unavailable>"
  parallel_work_units:
    - "<none-or-work-unit-set>"
  sol_review_windows:
    - "<review-window-or-unavailable>"
  model_escalations:
    - "<none-or-escalation>"
  rejected_implementations:
    - "<none-or-work-unit>"
  rework_cycles:
    - "<none-or-cycle>"

  token_usage:
    sol_input: "<n-or-unavailable>"
    sol_output: "<n-or-unavailable>"
    terra_input: "<n-or-unavailable>"
    terra_output: "<n-or-unavailable>"
    luna_input: "unavailable"
    luna_output: "unavailable"
    spark_input: "unavailable"
    spark_output: "unavailable"

  contract_violations:
    - "<none-or-violation>"
  blocking_findings:
    - "<none-or-finding>"
  accepted_limitations:
    - "<none-or-limitation>"
  known_limitations:
    - "<none-or-limitation>"
  rejected_capability_claims:
    - "<none-or-claim>"
  deferred_work:
    - "<none-or-item>"

  reviewed_at: "<timestamp>"
  accepted_at: "<timestamp-or-not_applicable>"
}
```

`APPROVED_PRODUCTION_READY` is forbidden while any required field is `FAIL` or
any unresolved P0 blocker exists. `final_tree_hash` and
`final_commit_or_tree_hash` must contain the same verified tree identity. Every
WorkUnit reports its requested and actual model; the user-approved Terra
substitution is recorded under `worker_models_used`,
`actual_models_by_work_unit`, `implementation_agents`, and `model_escalations`.
It is recorded as a contract violation only if the approved substitution
contract was itself breached. Luna/Spark remain explicitly unavailable, Terra
usage is reported when available, and no token/model/runtime value is invented.
`known_limitations` contains every visible limitation;
`accepted_limitations` is the exact Sol-approved subset. `accepted_at` is
`not_applicable` for `REJECTED_NOT_READY`.

## Exact A–Q final report contract

WU-J must produce these headings and content without omission:

- **A. BASELINE:** repository state, existing primitives, baseline tests, and
  pre-existing failures.
- **B. SOL ARCHITECTURE:** architecture decisions, threat boundaries, approved
  plan, plan hash, and rejected alternatives.
- **C. MODEL EXECUTION:** for every batch, worker, model, scope, usage, patch,
  tests, Sol review, and remediation cycles.
- **D. VERTICAL-NEUTRAL REFACTOR:** banking leakage removed, compatibility
  mapping, and remaining coupling.
- **E. CORE SEMANTICS:** principals, subjects, resources, authority, values,
  side effects, persistence, and reversibility.
- **F. DOMAIN PROFILES:** engine, safety, signing, tenant isolation, and all six
  profiles.
- **G. CANONICAL ACTION:** schema, canonicalisation, materiality, equivalence,
  fingerprints, and resolvers.
- **H. AUTHORISATION PROOF:** Decision Receipt, approval, standing authority,
  and permits.
- **I. EXECUTION PROOF:** Execution Receipt, state machine, comparator, drift,
  and verification.
- **J. COMPLEX ACTIONS:** multi-step, async, persistent effects, delegation, and
  outcomes.
- **K. SECURITY:** attack tests, replay, tenant isolation, profile tamper, key
  rotation, and privacy.
- **L. TESTING:** unit, integration, cross-vertical, regression, performance,
  and tests deliberately not added with the reason why.
- **M. PRODUCT:** APIs, action UI, approval UI, investigation, findings,
  metrics, and Control Coverage.
- **N. FILES AND MIGRATIONS:** complete list.
- **O. REMAINING BLOCKERS:** concrete blockers only.
- **P. SOL FINAL ACCEPTANCE:** the exact acceptance block above.
- **Q. FINAL TRUTH STATEMENT:** exactly one readiness statement and exactly one
  vertical-agnostic status block from the closed choices below, followed by a
  complete list of every remaining vertical coupling. Use an explicit empty
  list when no coupling remains.

Exactly one readiness statement:

```text
PHASE 5 P0 ACTION AND EXECUTION INTEGRITY:
PRODUCTION READY
```

or:

```text
PHASE 5 P0 ACTION AND EXECUTION INTEGRITY:
NOT PRODUCTION READY
```

Exactly one vertical status block, with one and only one value:

```text
VERTICAL-AGNOSTIC STATUS:
VERTICAL_AGNOSTIC
```

or:

```text
VERTICAL-AGNOSTIC STATUS:
PARTIALLY_VERTICAL_AGNOSTIC
```

or:

```text
VERTICAL-AGNOSTIC STATUS:
STILL_VERTICAL_COUPLED
```

The report then emits `REMAINING VERTICAL COUPLINGS:` followed by every
remaining coupling as concrete file/interface evidence, or `- none` only when
the final vertical audit proves there is no remaining coupling.

## Plan self-review

- [x] Every contract section 1–79 maps to a WorkUnit or governance gate.
- [x] The plan extends existing authorities and rejects parallel systems.
- [x] Vertical semantics are profile data; generic core remains neutral.
- [x] V1 signed evidence is preserved and never silently promoted.
- [x] Tenant isolation, policy epoch, exact material, replay, revocation,
  non-execution, evidence quality, and capability truth are explicit.
- [x] File ownership serializes architecture-critical dirty-tree paths.
- [x] Every WorkUnit starts with failing tests and ends with focused verification
  and Sol review.
- [x] WU-00I alone constructs and inspects the hash-bound image without database
  access; PH5-M0-IMAGE requires dual-Sol exact supply-chain approval; WU-00M
  then safely recovers the identified 0053 persistent PostgreSQL target with
  that unchanged image to 0064 in one controlled transaction and a failure-only
  restore guard; WU-00 then reverifies the unchanged backup and exact
  current/sole-head 0064 read-only before TDD and before WU-A; controlled
  migration through 0067 remains gated on the schema WorkUnits' Sol approvals.
- [x] Baseline/isolation variance is explicitly approved by the user, recorded
  in this plan, and required as fixed evidence in the formal build approval.
- [x] No production code is authorized by this document alone.
