# Phase 4 P0 Multi-Provider Native and Runtime Control Fabric Design

## Status and scope

This design implements the approved Phase 4 brief as an additive hardening of
Hawk's existing control spine. It does not create a provider inventory, a new
policy engine, a provider-specific AI Action schema, a duplicate receipt type,
or a fifth deployment family.

The authoritative path remains:

`Provider or runtime event -> canonical AI Action -> control requirements ->
verified ControlPlan -> existing Policy -> one Decision -> enforcement -> one
evidence and receipt chain -> Control Coverage`.

The repository already contains substantial foundations: provider adapters,
capability profiles, exact-version acceptance registries, deterministic
selection, health and validation state, Decision and Execution Receipts,
endpoint-floor plans and permits, OpenAI action-class profiles, and the four
deployment families. Phase 4 closes the gaps between those pieces instead of
replacing them.

## Baseline truth

The focused API/native-control baseline passes 365 tests. The endpoint baseline
passes 42 tests and has one live-install version-drift failure: ChatGPT Desktop
is installed as `26.715.72359`, while the reviewed manifest covers
`26.715.31925`. Hawk must keep the newer binary unverified until exact
acceptance or a reviewed compatible range exists.

Current capability truth is mixed and remains capability-level:

- Claude Code has exact `2.1.183` local hook evidence for documented events,
  but no native-to-endpoint permit proof and no ordinary Claude Desktop,
  remote Code, or direct API coverage.
- Gemini CLI `0.54.4` remains Experimental. Its accepted evidence classifies
  file reads as observed, so an inline-bound file-read manifest claim is a
  false-green defect and must be corrected.
- Microsoft Agent Framework `1.15.0` has a verified local Function execution
  gate only. Model, MCP, hosted Foundry, APIM, and direct REST remain
  Experimental or unavailable.
- Cursor, Codex, ChatGPT Desktop, and OpenAI have useful profiles and fixtures,
  but exact runtime dispatch and local/remote execution truth are incomplete.
- Bedrock, AgentCore, Vertex, Azure, Ollama, vLLM, TGI, Llama, Qwen, DeepSeek,
  and Kimi do not become native or exact tool controls merely because a generic
  API, gateway, or compatible protocol exists.
- The endpoint permit broker is strongly bounded in isolation, but no native
  adapter currently issues a permit that a verified OS enforcement point
  consumes.

## Authoritative contracts

### ProviderRuntimeContext

One bounded immutable value object carries the runtime facts used by selection:

- provider, product, application, and application version;
- runtime identity and location;
- model provider, model, route, and deployment identity;
- action class and lifecycle stage;
- execution location: `LOCAL_ENDPOINT`, `CUSTOMER_RUNTIME`, `CUSTOMER_CLOUD`,
  `PROVIDER_HOSTED`, `REMOTE_AGENT`, `MIXED`, or `UNKNOWN`;
- account and tenant mode where independently verified;
- route evidence and freshness.

Unknown values never become permissive defaults. A provider label does not
prove which runtime, account, route, model, or execution location is active.

### ProviderControlContract

The existing `adapter_contract.CapabilityManifest` becomes the concrete,
canonical ProviderControlContract. It is extended in place and remains the only
reviewed contract authority. `ProviderCapabilityManifest` and
`ControlCapabilityProfileRecord` become deterministic projections of it; they
must not add or strengthen claims. This avoids introducing a fourth contract
model. The canonical manifest records:

- provider, product, runtime, adapter, contract, and provider version ranges;
- supported action classes and lifecycle events;
- control methods and exact blocking/mutation/approval/post-action semantics;
- identity, timeout, retry, failure, privacy, and installation behavior;
- verification state and compatible-version state;
- reviewed source references, evidence references, review timestamp, contract
  hash, and schema version.

The contract is not another adapter registry or wrapper. It is the existing
adapter manifest hardened with a hashed review envelope. It uses the existing
verification levels and adds explicit provider-version compatibility states:
`EXACT_TESTED`, `VERIFIED_COMPATIBLE_RANGE`, `UNVERIFIED_NEWER`,
`UNSUPPORTED_OLDER`, `UNSUPPORTED`, `BROKEN`, and `UNKNOWN`.

Contracts are code-reviewed artifacts, not customer-supplied runtime claims.
An unknown, unsupported, broken, or drifted contract is ineligible for
authoritative enforcement.

### Deployment-bound acceptance

A reviewed static contract cannot self-assert that a deployed control was
accepted. The existing validation/profile projection therefore records one of:

- `REAL_BINARY_ACCEPTED`;
- `REAL_ENTERPRISE_TENANT_ACCEPTED`;
- `REAL_CLOUD_RUNTIME_ACCEPTED`;
- `SYNTHETIC_ONLY`;
- `DOCS_ONLY`;
- `NOT_TESTED`.

Each acceptance is immutable and binds environment, tenant-safe deployment
reference, provider, product, runtime, action class, control method, provider
and adapter versions, contract hash, acceptance run and evidence references,
tested lifecycle events, and explicit allow, block, and non-execution results.
Selection and promotion consume this deployed acceptance state in addition to
the reviewed contract and current health. Missing real acceptance never becomes
production eligibility.

### ControlRequirementProfile

The existing requirement profile is extended, not replaced. It derives the
required dimensions for the canonical action, including subject, business
purpose, authority, approval, persistence, execution, independent verification,
mandatory endpoint/runtime/target-service floors, maximum latency, privacy, and
degradation behavior.

### ControlPlan

The existing `EndpointControlPlan` evolves into the provider-neutral composed
plan while retaining backward-compatible names. A plan contains:

- canonical action ID and hash;
- provider/runtime context digest;
- mandatory enforcement floors;
- one semantic primary control;
- secondary context, verification, and containment points;
- required, satisfied, and unsatisfied dimensions;
- every rejected candidate and reason;
- assurance, degradation and failure behavior;
- policy, matrix, selector, contract, profile, and route versions;
- issued time, expiry, blind spots, and deterministic plan digest.

The complete plan is persisted in the existing native-control selection record
and projected onto the existing Decision and Execution Receipt chain. It does
not create a second policy decision or receipt.

## Selection and composition

Selection is deterministic:

1. Resolve exact provider/runtime/action context.
2. Reject unsupported version states, contract drift, unhealthy controls,
   stale policy, stale validation, route mismatch, and tenant mismatch.
3. Apply every mandatory enforcement floor. A native hook cannot remove a
   required endpoint/runtime/target-service floor.
4. Select a semantic primary only if its exact action class, lifecycle event,
   execution location, version, and blocking semantics are verified.
5. Add verification and containment points without creating another decision.
6. Confirm all required dimensions, assurance, latency, privacy, and failure
   requirements.
7. If any mandatory requirement remains unsatisfied, return
   `CONTROL_REQUIREMENT_UNSATISFIED`; never silently downgrade to observation.
8. Persist the exact plan and bind it to receipts before enforcement.

When a valid endpoint permit matches the OS primitive, the endpoint verifies
that existing Hawk authority instead of making a contradictory second policy
decision. A material file, command, destination, authority, purpose, process,
policy epoch, or route mismatch blocks or reauthorizes.

## Runtime dispatch

Callback dispatch resolves the configured integration's exact adapter ID and
contract, not a generic provider-name normalizer. The adapter registry remains
authoritative for normalization; provider aliases are accepted only before
exact product/runtime resolution. Ambiguous product or runtime dispatch fails
closed for consequential events.

Provider compatibility is explicit:

- protocol compatibility permits request/response normalization only;
- compatible OpenAI-style APIs do not inherit OpenAI provider hooks, hosted
  tool semantics, account controls, or action fidelity;
- gateway control does not imply provider-hosted execution control;
- post-action callbacks provide evidence, not prevention;
- endpoint initiation context does not imply remote cloud-work control.

## Path-native implementation slices

### Slice 1: Fabric truth and first complete plan

- Correct the Gemini file-read false-green claim.
- Add provider runtime context and evolve the existing capability manifest into
  the reviewed provider-control contract.
- Extend missing capability/control-method/version states conservatively.
- Make exact adapter dispatch authoritative.
- Persist one complete composed ControlPlan and bind it to existing receipts.
- Prove one local native path through the same action/decision/receipt chain.

### Slice 2: Existing provider revalidation

- Revalidate Claude Code, Gemini CLI, Microsoft Function middleware, Cursor,
  Codex, ChatGPT Desktop, and OpenAI action-class separation.
- Add personal-versus-enterprise negative states for Anthropic without claiming
  enterprise controls until an actual enterprise hook/restriction path exists.
- Implement the supported Enterprise Inference Hook and Tenant Restrictions
  integration boundaries separately. Code availability is reported independently
  from capability verification; both remain unverified until real
  enterprise-tenant acceptance exists.
- Keep remote, hosted, safe-mode, and unknown-version paths non-green.

### Slice 3: Direct and cloud runtime controls

- Model direct OpenAI, Azure OpenAI, Gemini/Vertex, Anthropic, Bedrock, and
  AgentCore paths by their real interception boundaries.
- Separate model request, function tool, hosted tool, MCP, background work,
  and post-execution visibility.
- Require customer-tenant acceptance before production promotion.

### Slice 4: Self-hosted and compatible runtimes

- Introduce runtime-specific contracts for one complete self-hosted proof path
  before expanding to Ollama, vLLM, TGI, Llama, Qwen, DeepSeek, and Kimi.
- Treat generic protocol compatibility as gateway/runtime normalization only.
- Add model-route drift, direct-route bypass, dynamic tool, and unsupported
  version tests.

### Slice 5: Product and operations

- Extend current Surface Coverage, Deployments, AI Asset, AI Action Trace,
  Findings, Control Coverage, and operations views.
- Add Provider Compatibility and action-specific “Why This Control?” inside
  existing navigation only.
- Expose bounded provider-control metrics and explicit unknowns/blind spots.

## Security and privacy invariants

- Provider input cannot select a more privileged adapter or contract.
- Deny is monotonic across provider, runtime, endpoint, and target-service
  controls.
- Model-request permission never authorizes a tool.
- Remote execution is never represented as local endpoint enforcement.
- Contract and route changes invalidate stale plan authority.
- Health persistence represents `POLICY_STALE`, `NOT_INSTALLED`, and `UNKNOWN`
  explicitly; none may be coerced to healthy or degraded.
- No raw prompt, secret, token, hidden reasoning, or unbounded provider payload
  is added to contract, plan, metrics, findings, or coverage records.
- Tenant, device, runtime, action, route, and receipt bindings are enforced.
- Policy, decision, AI Action, evidence, and receipt ownership remain unchanged.

## Promotion rule

Promotion is per provider, product, runtime, action class, control method,
provider version, adapter version, execution location, and capability. A row is
`PRODUCTION` only after real acceptance proves allow, block, non-execution,
mutation, timeout/failure, health, version, route, receipt, privacy, and bypass
behavior for that exact scope. Everything else remains `EXPERIMENTAL`,
`OBSERVE_ONLY`, `NOT_READY`, or `UNSUPPORTED`.

Because the repository lacks real external tenant acceptance for several cloud
and enterprise provider controls, implementation completion cannot by itself
justify the global statement `PHASE 4 PRODUCTION READY`.
