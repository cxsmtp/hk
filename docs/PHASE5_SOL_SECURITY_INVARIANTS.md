# Phase 5 Sol Security Invariants

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


## Authority

These invariants are release-blocking for `PHASE5-P0-CAEIC-1`. An implementation
agent may not reinterpret, weaken, or locally waive them. Conflict requires
`ARCHITECTURE_ESCALATION_REQUIRED` and a new Sol-approved plan hash.

## Core authority invariants

### SI-01 — One decision authority

Only the existing Hawk Policy path decides `ALLOW`, `BLOCK`, approval, or
control-requirement failure. Profiles, Discovery, resolvers, adapters, UI,
evidence, and comparators never authorize.

### SI-02 — Unknown is non-authorizing

For consequential action material, `UNKNOWN`, missing, ambiguous, expired,
contradicted, unverified, or unsupported data cannot become allow, equivalence,
matched integrity, complete evidence, or verified coverage.

### SI-03 — Exact material binding

Decision, approval, and permit authority bind the same versioned materiality
set: tenant, action, principal, represented subject, resource scope, authority,
purpose, tool/service, material arguments, target, destination, value,
consequence, persistence, reversibility, policy epoch, ControlPlan, profile,
resolver, and delegation constraints.

### SI-04 — Immediate pre-execution revalidation

The final Hawk gate recomputes material immediately before execution. A
material mismatch invalidates authority and causes reauthorization or block.
No mutable middleware may run between final validation and the consequence.

### SI-05 — Non-execution guarantee

On block, invalid authority, permit mismatch, expiry, replay, revocation, or
unresolved mandatory material, Hawk must not invoke the protected executor.
Non-execution evidence states its source and quality; it is not inferred from a
missing callback.

## Identity, tenant, and delegation invariants

### SI-06 — Tenant isolation

Every authoritative record, lookup, uniqueness constraint, signature context,
permit, receipt, evidence link, and API mutation is tenant-scoped. Cross-tenant
IDs, signatures, policies, profiles, receipts, permits, or evidence hard fail.

### SI-07 — Principal is not represented subject

Execution identity, initiating principal, represented subject, and service
identity remain distinct. Model output or prompt prose cannot create or expand
represented-subject authority.

### SI-08 — Authority attenuation

Effective authority is no broader than the narrowest originating, delegated,
policy, approval, permit, and execution constraint. Workload privilege cannot
expand the represented subject's authority.

### SI-09 — Delegation is immutable material

Parent action, delegation edges, capability/token references, restrictions,
expiry, and revocation state are receipt material. Revocation invalidates
unconsumed descendant authority.

## Canonicalization and profile invariants

### SI-10 — Deterministic bounded canonicalization

Equivalent normalized inputs have one byte representation and hash. Maps are
ordered, collections and strings bounded, numbers normalized, Unicode
normalized, timestamps explicit, and unknowns tagged. No locale, provider, or
database ordering may affect the digest.

### SI-11 — No secrets or unnecessary sensitive content

Canonical actions, logs, receipts, findings, metrics, and evidence never persist
credentials, API keys, bearer/refresh tokens, cookies, passwords, private keys,
raw approval secrets, hidden reasoning, or unnecessary prompts/records. Use
safe references, classifications, hashes, and bounded reason codes.

### SI-12 — Profiles cannot execute code or decide policy

Profile and invariant definitions are reviewed declarative data. They cannot
load modules, call the network, spawn processes, traverse filesystems, execute
expressions, or return authorization decisions.

Profiles may only add domain requirements. They may not remove or weaken core
subject, resource, purpose, authority, materiality, approval, permit, execution,
or evidence requirements.

### SI-13 — Profile and resolver versions are authority material

Profile content hash, materiality version, target/destination resolver version,
and tool fingerprint are immutable receipt/approval/permit inputs. Material
change invalidates previous unconsumed authority.

## Receipt, cryptography, and permit invariants

### SI-14 — Domain- and purpose-separated signatures

Policy, domain profile, Decision Receipt, Approval Binding, Execution Permit,
Execution Receipt, provider callback, and software-update signatures use
distinct key purposes plus explicit schema/domain separation, key IDs, tenant
context, algorithm, and canonical bytes. Active key material cannot be reused
across purposes. Production requires the KMS/HSM provider; local HMAC keys are
development/test only.

### SI-15 — Historical validity differs from current eligibility

A valid historical signature proves the record was signed, not that its policy,
profile, approval, or authority is currently executable. Currentness and
revocation are checked separately.

### SI-16 — Positive policy epoch

New consequential V2 decisions, approvals, and permits require a positive,
current policy epoch. A material policy update invalidates incompatible
unconsumed permits and cached authority.

### SI-17 — Permit confinement and replay resistance

Permits are short-lived, bounded-use, tenant/action/attempt/principal/tool/
target/destination/policy/plan-bound, nonce-protected, and atomically consumed.
They are not exposed as reusable application bearer tokens.

Approval use is atomically consumed at permit issuance. Permit claim is an
atomic compare-and-set in the final Hawk transaction immediately before the
executor. A crash after claim becomes unverified/unknown and never restores
approval use or proves non-execution.

### SI-18 — Endpoint permit ownership remains local

The local endpoint broker owns endpoint permits. The server links authority and
consumption evidence but does not replace the broker format or create a remote
shell/control channel.

## Execution and evidence invariants

### SI-19 — Material integrity, execution state, and outcome are separate

`MATCHED` does not mean succeeded. Provider failure, cancellation, partial
completion, timeout, unknown execution, and outcome violation remain explicit.

### SI-20 — Provider-reported is not independently verified

Provider/runtime callbacks are classified by source. Only evidence from a
verified independent control point may make an independent non-execution or
execution claim.

### SI-21 — Durable lifecycle

Async, multi-step, persistent-effect, approval, permit, and execution
transitions that affect authority are durable, idempotent, ordered, and
tenant-scoped. Process-local queues or counters cannot be the sole proof.

The legal state DAG, monotonic state version, idempotency keys, signature body,
terminal-receipt timing, and non-execution sources are exactly those frozen in
`docs/CODEX_INTERFACE_REGISTRY.md`.

### SI-22 — One action/evidence chain

Native, endpoint, gateway, runtime, target-service, and provider evidence for
one logical action attach to one action chain. A matching valid permit avoids a
contradictory second policy decision.

### SI-23 — Evidence is append-only and reversible corrections are explicit

Signed evidence is not overwritten. Corrections and terminal results supersede
earlier provisional state through explicit links and preserve history.

### SI-24 — Coverage is evidence-backed

Implemented or configured does not mean verified. Control Coverage separates
known covered, uncovered, unknown, stale, degraded, and unverified material and
never averages away mandatory gaps.

## Operational invariants

### SI-25 — Fail-safe degradation

Unavailable policy, expired profiles, stale epochs, broken required control
points, or integrity failure cannot retain a stale green state. Consequential
operations follow the frozen degradation policy and otherwise fail closed.

### SI-26 — Feature flags are non-strengthening

Disabled flags preserve current behavior. Enabling observe mode cannot grant
authority. Authoritative V2 writes require migration and acceptance gates.

### SI-27 — No destructive migration inference

Migrations are additive. Legacy rows retain original signatures and versions.
Backfills use `UNKNOWN` for unavailable proof. Downgrade does not delete signed
legacy evidence.

### SI-28 — Approval authorities remain distinct

Runtime approval, approval binding, remediation approval, direct enforcement,
and demo/AGUI contracts cannot substitute for each other. UI mutations invoke
the exact backend authority and surface its SLA, role, expiry, and result.

### SI-29 — Metrics are tenant-safe and bounded

Exposed metrics contain no raw principal, resource, prompt, token, action ID, or
secret labels. Tenant visibility uses an authorized durable/export boundary;
unscoped process counters remain internal.

### SI-30 — No repository collateral damage

Phase 5 preserves unrelated dirty-worktree changes and performs no reset,
checkout, clean, stage, commit, merge, push, or discard operation without
separate user authorization.

## Mandatory negative proofs

Before promotion, tests must prove hard failure for:

- wrong tenant, device, principal, represented subject, or resource;
- tool/schema/version drift and post-authorization argument mutation;
- target/destination/value/side-effect/persistence mutation;
- policy/profile/resolver/materiality epoch change;
- expired, replayed, copied, over-used, or already-consumed permits;
- revoked approval or delegation;
- out-of-order/inserted multi-step execution;
- missing async callback and persistent-effect verification;
- signature/domain/key-ID mismatch;
- cross-version ambiguity and unresolved equivalence;
- provider-reported evidence presented as independent proof;
- API references presented as browser links;
- UI authority substitution;
- legacy rows silently promoted to V2.
