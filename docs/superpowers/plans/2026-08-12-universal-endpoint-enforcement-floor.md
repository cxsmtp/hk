# Universal Endpoint Enforcement Floor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Extend the existing Hawk Endpoint deployment so file, process, and network consequences can be represented as mandatory, evidence-backed enforcement floors while keeping the existing Hawk AI Action, Policy, Decision, Evidence, and Control Coverage spine authoritative.

**Architecture:** The endpoint gets a small deterministic floor domain for normalized OS primitives, cryptographically verified declarative policy, deadline-safe decisions, process attribution, correlation, and component health. The existing Trusted Control Point Selector gains an additive `resolve_control_plan()` result that selects mandatory endpoint floors independently from the semantic primary control. Native macOS and Windows source/build contracts remain capability evidence only until signed target-OS acceptance proves each primitive.

**Tech Stack:** Python 3.11+/pytest/cryptography, FastAPI/SQLAlchemy, Next.js/TypeScript, Apple Endpoint Security and Network Extension source contracts, Windows minifilter/WFP/process-notify source contracts.

---

## Locked boundaries

- No second policy engine, AI Action, evidence store, Control Coverage engine, or product surface.
- Endpoint file/process/network results are `verified`, `experimental`, or `unverified` per primitive; source presence never promotes runtime coverage.
- OS-critical callbacks use only bounded local policy. Remote enrichment is never required to meet an authorization deadline.
- Unknown or missing runtime evidence produces `CONTROL_REQUIREMENT_UNSATISFIED`, not an inferred protected state.
- TLS validation, certificate pinning, and application security are never weakened.

### Task 1: Normalized endpoint-floor contracts

**Files:**
- Create: `apps/endpoint-agent/src/hawk_endpoint_agent/endpoint_floor/contracts.py`
- Create: `apps/endpoint-agent/tests/test_endpoint_floor_contracts.py`

- [x] Write failing tests for all required primitive classes, bounded process identity, closed capability/verification states, and privacy-safe serialization.
- [x] Run the focused test and confirm the missing module is the failure.
- [x] Implement immutable contracts and strict normalization without trusting process name alone.
- [x] Re-run the focused test.

### Task 2: Signed deterministic local fast path

**Files:**
- Create: `apps/endpoint-agent/src/hawk_endpoint_agent/endpoint_floor/local_policy.py`
- Create: `apps/endpoint-agent/tests/test_endpoint_floor_local_policy.py`

- [x] Write failing tests for Ed25519 verification, tenant/device/policy binding, expiry, tamper rejection, exact scoped cache keys, deterministic matching, per-primitive degradation, and deadline exhaustion.
- [x] Run the tests and confirm the expected missing implementation.
- [x] Implement canonical signed envelopes and `EndpointPolicyFastPath` returning only `ALLOW`, `BLOCK`, `LOCAL_ESCALATION_REQUIRED`, or `REMOTE_ENRICHMENT_ALLOWED`.
- [x] Re-run the focused tests.

### Task 3: Attribution, transfer correlation, health, and anti-downgrade

**Files:**
- Create: `apps/endpoint-agent/src/hawk_endpoint_agent/endpoint_floor/correlation.py`
- Create: `apps/endpoint-agent/src/hawk_endpoint_agent/endpoint_floor/health.py`
- Create: `apps/endpoint-agent/tests/test_endpoint_floor_correlation.py`
- Create: `apps/endpoint-agent/tests/test_endpoint_floor_health.py`

- [x] Write failing tests proving timing alone is never `confirmed`, same-process file/egress is only `correlated`, semantic upload evidence can be `confirmed`, and any dead mandatory component makes the plan unsatisfied.
- [x] Implement bounded correlators and a posture evaluator with component-specific health, freshness, tamper, and deadline state.
- [x] Re-run focused tests.

### Task 4: Multi-layer trusted control plan

**Files:**
- Modify: `apps/api/app/services/native_control/contracts.py`
- Modify: `apps/api/app/services/native_control/selector.py`
- Create: `apps/api/app/services/native_control/endpoint_floor_profiles.py`
- Create: `apps/api/tests/test_native_control_endpoint_floor_plan.py`

- [x] Write failing tests for `mandatory_enforcement_floors`, `semantic_primary_control`, context, verification, containment, independent floor failure, and deterministic output.
- [x] Extend capability dimensions and add backward-compatible plan contracts.
- [x] Implement `resolve_control_plan()` by reusing the existing selector for semantics and independently evaluating required Endpoint Runtime floors.
- [x] Add eight conservative endpoint capability profiles; keep every unproven primitive unverified.
- [x] Re-run native-control selector and new plan tests.

### Task 5: Runtime posture and tenant API

**Files:**
- Modify: `apps/endpoint-agent/src/hawk_endpoint_agent/runner.py`
- Modify: `apps/api/app/services/endpoint_agent_service.py`
- Modify: `apps/api/app/api/routers/endpoint_agent.py`
- Create: `apps/api/tests/test_endpoint_enforcement_floor_status.py`

- [x] Write failing tests that a heartbeat without signed native runtime proof reports all floor components `unknown`/`unverified`, and that partial evidence never becomes overall protected.
- [x] Emit a bounded endpoint-floor posture block in existing heartbeats and accept only current signed native receipts.
- [x] Add a tenant-scoped read API that projects the latest heartbeat per endpoint and returns actual health, policy freshness, blind spots, and evidence references.
- [x] Re-run endpoint API and heartbeat tests.

### Task 6: Native platform source and build contracts

**Files:**
- Create: `apps/endpoint-agent/native/macos/endpoint-security/*`
- Create: `apps/endpoint-agent/native/macos/content-filter/*`
- Create: `apps/endpoint-agent/native/windows/minifilter/*`
- Create: `apps/endpoint-agent/native/windows/wfp/*`
- Create: `apps/endpoint-agent/native/windows/process-control/*`
- Create: `apps/endpoint-agent/tests/test_endpoint_native_floor_contracts.py`

- [x] Write source-contract tests for supported APIs, local-only decision boundaries, explicit deny semantics, bounded IPC, default-off activation, signing/MDM/attestation gates, and unverified promotion state.
- [x] Add macOS Endpoint Security auth and Network Extension filter sources without undocumented hooks.
- [x] Add minimal Windows minifilter, WFP, and process-notify sources without user-mode/cloud calls in unsafe callbacks.
- [x] Verify source/build contracts locally; leave target-OS runtime status unverified until real signed acceptance.

### Task 7: Endpoint Enforcement Floor UI

**Files:**
- Modify: `apps/web/src/components/lifecycle/deploy-workspace.tsx`
- Modify: `apps/web/src/lib/api.ts`
- Modify: `apps/web/src/lib/types.ts`

- [x] Add typed endpoint-floor API fixtures and conservative empty/error behavior.
- [x] Render File, Process, Network, Semantic Proxy, Local Policy, actual Coverage, Health, and Blind Spots without kernel details.
- [x] Run web type checking and the production build.

### Task 8: Acceptance, security, performance, and final ledger

**Files:**
- Create: `apps/endpoint-agent/tests/test_endpoint_floor_security.py`
- Create: `apps/endpoint-agent/tests/test_endpoint_floor_performance.py`
- Create: `docs/ENDPOINT_ENFORCEMENT_FLOOR_IMPLEMENTATION_REPORT.md`

- [ ] Cover spoofing, PID reuse, binary replacement, symlink/path confusion, TOCTOU, route bypass, replay, wrong tenant/device, malformed/oversized IPC, concurrency, deadlines, stale/corrupt policy, and component restart/tamper.
- [x] Record local p50/p95/p99 as development evidence only.
- [x] Run endpoint, native-control, endpoint API, type/build, and targeted regression suites.
- [x] Report every macOS and Windows FILE/PROCESS/NETWORK capability as Verified, Partial, Unverified, or Unavailable with exact evidence; never promote a platform aggregate.

## Self-review against the brief

The plan covers all 45 sections through additive domain contracts, a deterministic signed fast path, multi-layer selection, native OS integration sources, health/anti-downgrade, evidence-backed correlation, conservative UI, security/performance fixtures, and an exact final ledger. Real signing, entitlement issuance, MDM activation, Windows WDK builds, and target-OS runtime acceptance are deployment evidence gates and cannot be manufactured in this repository; affected capabilities remain Unverified until those gates produce evidence.
