# Hawk Native Control Architecture

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


## Outcome

Native controls are additional trusted control points inside Hawk's existing product. They do not create another product, policy engine, evidence store, or deployment family.

The flow is:

1. A browser, endpoint, runtime, gateway, SDK, or provider adapter produces an existing Hawk `AuthorizationRequest`.
2. The existing deterministic Hawk authorization kernel evaluates the AI Action.
3. `ControlRequirementProfile` derives action-specific security requirements from that same request.
4. `TrustedControlPointSelector` selects the strongest currently verified and healthy eligible point.
5. Selection identity, matrix version, policy version, assurance, rejected alternatives, and blind spots are persisted in Hawk Evidence.
6. The existing Decision/Execution Receipt path binds the selection through `path_evidence`.
7. Existing Control Coverage projects only verified, healthy, current capability into Browser, Endpoint, Runtime, or SaaS & APIs.

## Reused Hawk components

- Canonical AI Action and Authorization Request
- Deterministic Policy/Authorization Engine
- Decision and Execution Receipts
- Evidence Node and Findings stores
- Control Coverage and Deployment Surface projection
- Tenant middleware, RBAC, API configuration, and audit conventions
- Existing MCP gateway, LLM gateway, and runtime pre-action services

## Added components

- Versioned Control Capability Matrix and database-backed profiles
- Deterministic Trusted Control Point Selector
- Integration lifecycle, validation, health, workload credential, replay, and selection records
- Strict signed Trusted Control Envelope
- Conservative provider adapter registry
- Signed declarative local policy and non-executable helper contracts
- Cryptographically separate software-update artifact contract
- Native-control findings and low-cardinality metrics
- Surface Coverage capability matrix and selection explanation UI

## Trust boundaries

Provider fields are untrusted. Tenant, integration, provider/product, identity, policy, approval, and risk authority come from the authenticated integration binding and Hawk server state. A provider event cannot self-select a tenant, role, approval, or policy.

Workload credentials are installation-scoped, public-key only in the database, expiring, revocable, epoch-bound, environment-bound, provider/product-bound, and event-type-bound. Replay identity is tenant + integration + event ID or nonce.

## State and rollout

The strict lifecycle is `configuring -> validating -> monitoring -> enforcing`; failed prerequisites cannot be bypassed. Provider enforcement requires both the global flag and the provider-specific flag. All flags default off.

Native provider hooks that lack repository-backed conformance evidence remain `unverified` and contribute no protected coverage. Verified Hawk gateway paths are the current enforceable fallback. Explicitly bound endpoint-runtime profiles remain non-enforceable through the integration lifecycle until a server-side endpoint validation runner exists.
