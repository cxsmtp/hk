# Agentic Action Integrity


Agentic Action Integrity is a cross-cutting Hawk capability inside the existing AI Action Control Plane. It is not a new product module, sidebar, marketplace, or orchestration system.

Hawk uses it to verify that an agentic action remains bound to the original user intent, trusted approval text, approved scope, tool metadata, JIT identity grant, taint provenance, and final execution evidence.

## Where It Sits

The capability extends the existing spine:

AI Action -> actor / authority -> intent / context -> delegation chain -> approval binding -> MCP/tool/SaaS action -> policy decision -> control mode -> evidence -> chain graph -> investigation / audit

Implemented pieces are reused through:

- Runtime Intelligence chain events and graph edges
- AI IAM JIT grant binding
- Policy approval scan and approval binding endpoints
- MCP tool fingerprinting through the Gateway router
- EvidenceNode-based redacted evidence bundles
- Agent touchpoint and blast-radius summaries

## Approval Binding

Approval text must be generated from canonical action fields, not from agent-written summaries.

Material fields include:

- tool name and version
- tool fingerprint
- arguments hash
- target resource
- affected resources
- identity scope
- data destination
- side-effect class
- persistence risk
- external destination
- time window
- requester agent

If any material field changes after approval, Hawk invalidates the approval binding and returns a blocking decision for inline surfaces.

## Delegation Integrity

Visible agent handoffs are represented as chain events and graph/touchpoint edges. Low-trust delegation, tainted source context, privilege expansion, and task expansion are policy signals. This first implementation records the chain and exposes the graph primitives; deeper A2A policy gates are deferred to the next slice.

## MCP / Tool Integrity

MCP tool metadata is fingerprinted by:

- manifest hash
- description hash
- schema hash
- examples hash

Changed metadata is marked `changed` and becomes a policy/evidence signal. This prevents tool rug-pulls from silently riding on older approvals.

MCP tool calls routed through `/gateway/mcp/authorize` also receive an inline integrity overlay:

- read-only calls with no dangerous parameters stay low-noise and can be `inline_allowed`
- changed, blocked, or under-review tool fingerprints require approval
- write/admin/execute/deploy/role-grant behavior is blocked or escalated
- secret, token, credential, private-key, `.env`, or connection-string access is blocked
- external callbacks, webhooks, scheduled jobs, and deferred side effects are flagged
- parameter summaries are stored as hashes/keys, not raw secret values

The overlay writes chain events, evidence, findings, and Agent Touchpoint Graph edges, so a blocked MCP call can be investigated as:

User / agent -> MCP server -> MCP tool -> policy decision -> evidence.

## JIT Identity Integrity

JIT grant evaluation compares requested scope against approved scope and records privilege delta. Persistent or privileged actions such as role grants, token creation, OAuth app creation, or admin changes require approval or block depending on control path.

## Deferred Side Effects

Deferred side effects include webhooks, scheduled jobs, workflow automations, API tokens, OAuth apps, service accounts, role assignments, mailbox forwarding, persistent memory, and external callbacks.

Hawk records these as chain-scoped evidence and marks approval-required side effects as `external_required` unless an inline enforcement path is present.

## Taint Tracking

Untrusted context from webpages, files, external agents, MCP outputs, SaaS records, or memory can be labeled and propagated through chain events. Tainted context cannot safely authorize sensitive actions by itself.

## Control Mode Limits

Control-mode honesty is mandatory:

- `inline_prevented` only when Hawk blocked before execution
- `inline_allowed` when Hawk evaluated and allowed in path
- `external_required` when approval or external system action is needed
- `detected_only` / `telemetry_only` for non-inline visibility
- `incomplete` when evidence or attribution is missing

Current enforcement is strongest for approval binding, MCP gateway scanning, JIT evaluation, and runtime graph/evidence APIs. SaaS/Desktop surfaces remain detected-only or external-required unless routed through an inline path.
