# Business Purpose Boundary

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


Business Purpose Boundary is Hawk AI's sector-aware AI usage control inside the existing AI Action Control Plane. It is not a new module or product area. It extends the same loop:

AI action -> actor / authority -> business purpose / sector / role -> intent / context -> policy snapshot -> decision -> control mode -> evidence -> trace.

## What It Decides

The evaluator answers:

Is this AI action aligned with the tenant sector, user business function, role, declared or inferred purpose, data sensitivity, destination, and action type?

Sensitive data and production context override purpose. A banking compliance prompt can still be blocked if it contains card data, customer rows, production SQL, secrets, or production code going to public AI.

## Where It Sits

Business Purpose Boundary lives under existing policy configuration and runtime policy evaluation:

- Policy Engine: tenant sector profile, business functions, role mappings, coding/SQL safe mode.
- AI Action: `business_purpose`, `code_context`, and `role_resolution` fields.
- Decision Explainability: evaluated business-purpose and code/SQL signals.
- Evidence: redacted summaries, counts, hashes, and metadata only.
- Findings: purpose mismatch, unresolved role, production SQL/code, and regulated data violations.

## Role Assignment Model

Role and business function resolution is server-side. The browser extension may send an authenticated user hint, but it is not trusted for role assignment.

Resolution precedence:

1. Explicit user mapping.
2. SCIM user attribute.
3. SCIM group mapping.
4. OIDC/SAML claim mapping.
5. Directory group mapping.
6. Email/domain/manual rule.
7. `default_unknown`.

Unknown role/function defaults to restricted or review behavior, never broad allow. Hawk records the mapping source, confidence, selected mapping, and whether fallback was used.

## Sector Packs

Default sector packs are configuration baselines, not separate products. Supported sectors include banking, insurance, healthcare, pharma, oil and gas, retail, government, legal, education, manufacturing, technology, telecom, defense, energy, and generic enterprise.

Banking defaults allow regulatory research, AML/KYC/compliance, risk analysis, software engineering, security analysis, internal productivity, and approved customer support drafting. They block or review unrelated personal use, customer account data, payment/card data, KYC documents, production SQL, production code, and secrets.

## Coding And SQL Safe Mode

Allowed:

- Generic coding help.
- Syntax/library/framework examples.
- Pseudocode and synthetic examples.
- Sanitized debugging snippets.
- Synthetic SQL and generic SQL learning.

Reviewed or blocked:

- Internal repo snippets.
- Production code.
- Customer code.
- Auth/payment/security code.
- CI/CD or infrastructure changes.
- Production SQL.
- Customer schemas or rows.
- Destructive SQL.
- Secrets, API keys, private keys, passwords, and connection strings.

## Deployment Surfaces

Enforced now:

- Browser extension for visible prompts, paste, uploads, and browser AI tools.

Evaluated later as inline surfaces are routed:

- LLM Gateway.
- MCP / Developer AI Control.
- SDK / App Embed.
- Local proxy or SWG integrations.

Telemetry-only or detected-only until inline control exists:

- SaaS/Copilot connectors.
- Desktop AI telemetry.
- Directory or admin inventory.

Control mode honesty remains mandatory. Hawk must not claim prevention where it only saw telemetry.

## Evidence Rules

Evidence includes actor, role resolution, sector profile, action, destination, policy snapshot, decision explanation, control mode, and trace references.

Evidence must not store raw secrets, private keys, passwords, payment credentials, customer lists, or full source files unless explicitly configured. Store redacted previews, indicator counts, metadata, and hashes.

## Example Decisions

- Bank risk analyst asks about sofa fabric for home: block/warn as unrelated consumer research.
- Bank procurement asks for fire-resistant fabric vendors for branch renovation: allow/review.
- Compliance officer asks for UAE AML rules: allow.
- Developer asks for Python CSV parser: allow.
- Developer pastes production customer SQL: block/review.
- Banking-related prompt includes card data: block.

