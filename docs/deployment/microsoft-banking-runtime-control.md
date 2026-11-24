# Microsoft Banking Runtime Control

**Status:** Phase 1 P0 local control foundation implemented; **PHASE 1 NOT PRODUCTION-POC READY**.  
**Evidence rule:** `VERIFIED` applies only to the named local Function boundary. Foundry, MCP/Toolbox, APIM, Sentinel delivery, private connectivity, bank-service attestation, production KMS/HSM, streaming, and production-scale claims remain `EXTERNAL_DEPENDENCY` until exercised in the bank-controlled environment.

This guide describes the production architecture and operating contract without treating adapter code, test fixtures, or catalog metadata as deployed protection.

## Microsoft Agent Framework integration

The Hawk package targets .NET 8 and the pinned `Microsoft.Agents.AI` `1.15.0` package. Register Hawk as the final mutation-capable Function middleware immediately around the executor:

```csharp
HawkAgentFrameworkMiddleware hawkMiddleware = new(
    new HawkFunctionExecutionGate(hawkClient),
    bankingMaterialFactory);

AIAgent governedAgent = baseAgent
    .AsBuilder()
    .Use(hawkMiddleware.InvokeAsync)
    .Build();
```

`IBankingActionMaterialFactory` must read validated function arguments and the immutable bank-issued subject context. It must not derive customer authority, account scope, destination, or consequential parameters from prompt text, RAG content, tool descriptions, or model output.

Required ordering:

```text
bank subject validation
  -> Agent Run correlation
  -> application middleware
  -> preliminary normalization
  -> other chat/function middleware
  -> final Hawk authorization and revalidation gate
  -> actual provider or Function executor
  -> execution report and integrity comparison
```

No middleware that can modify consequential material may run after the final Hawk gate. A block returns without invoking `next()`. An allow invokes `next()` exactly once with Hawk's sealed argument snapshot.

The complete local package instructions and synthetic reference proof are in [`integrations/microsoft-agent-framework-dotnet/README.md`](../../integrations/microsoft-agent-framework-dotnet/README.md).

## Foundry integration

The implemented local adapter supplies Agent Run correlation, an `IChatClient` wrapper, Function middleware, transport bindings, and deterministic response assurance. Production Foundry integration must additionally prove, against the bank's pinned application and service version:

- model request allow and block with provider non-invocation on block;
- Function allow, block, exact parameter/target binding, and non-execution;
- middleware ordering and post-authorization mutation resistance;
- timeout, cancellation, retry, and rollback behavior;
- exact managed identity, project connection, model deployment, tool, and data-source bindings;
- whether streaming is controlled. Unsupported streaming remains **Not Covered**.

Foundry metadata, provider approval flags, Toolbox metadata, or a successful model response do not prove Hawk authorization. Until the tenant-backed acceptance is retained, these capabilities remain `EXTERNAL_DEPENDENCY` and the adapter remains Experimental.

## Subject binding

The trusted bank authentication/API layer issues the short-lived, asymmetrically signed subject assertion. Hawk validates issuer, audience, key ID, ES256 signature, issued-at time, expiry, nonce, tenant, session, channel, device trust, business purpose, and approved resource/account scope.

The assertion is projected into an immutable `SubjectExecutionContext`. The model, agent, prompt, RAG source, tool, provider, or caller cannot create or expand it. Child delegation must be a strict subset of the originating customer authority.

Deterministic outcomes:

| Condition | Result |
|---|---|
| Exact customer and approved resource scope | Continue to normal Hawk policy evaluation |
| Cross-customer or cross-account target | Block before execution |
| Missing or ambiguous consequential target | Require approval or block according to the server profile |
| Expired, revoked, replayed, future-issued, or invalid assertion | Block |
| Workload identity has broader access than customer authority | Enforce the narrower originating customer authority |
| Subject, purpose, tool, arguments, target, destination, or authority changes after authorization | Reauthorize exact material or block |

Only tenant-keyed pseudonymous subject and resource references are persisted.

## MCP and Toolbox

MCP and Foundry Toolbox actions use the same canonical Hawk authorization contract as Functions. The route binds:

- existing Hawk MCP server/tool inventory reference;
- server, tool, promoted version, and exact schema fingerprint;
- Toolbox/project connection where applicable;
- typed arguments, target, destination, side-effect class, persistence, and idempotency;
- authentication mode and execution identity.

OAuth passthrough, dedicated agent identity, project managed identity, shared key, and unknown authentication are distinct states. Shared credentials are never presented as verified end-user identity.

Missing inventory, an unapproved fingerprint, schema/version/connection drift, unresolved target, unverified authentication, or a direct bypass makes the mandatory control requirement unsatisfied. Local canonical-equivalence tests are implemented; real Microsoft MCP/Toolbox allow, block, auth-mode, bypass, and protected-callback non-execution remain `EXTERNAL_DEPENDENCY`.

## Identity model

Hawk keeps these authorities separate:

- authenticated customer subject;
- initiating human or service principal;
- Agent Run and delegated-agent lineage;
- workload execution identity;
- provider/project connection identity;
- MCP server identity and authentication mode.

Execution-identity provenance, authentication quality, shared-authority state, tenant, and attenuation are server-derived. A workload identity's cloud privilege never expands the bank customer's approved scope. Unknown identity is not converted into a user attribution claim.

## APIM and direct API

REST, OpenAPI, and APIM actions use the same canonical action and policy authority. Bind method, route template, operation ID, OpenAPI document fingerprint, APIM API/revision/backend, destination, identity mode, target, side effect, persistence, and bypass state.

The bank must validate the promoted OpenAPI document and APIM revision/backend actually used in production. Policy equivalence requires the Function, MCP, REST, OpenAPI, and APIM representations of the same business action to produce the same semantic authorization material while retaining distinct execution-route bindings.

Direct API calls that bypass the approved gate must be denied by service-side revalidation or prevented by network/APIM deployment. Local adapter tests do not prove that tenant routing cannot bypass middleware; production APIM/private-route acceptance remains `EXTERNAL_DEPENDENCY`.

## Decision Receipt

Hawk reuses the existing signed Decision Receipt. It binds tenant, subject context digest, transaction, agent lineage, business purpose, action schema, tool/fingerprint, exact parameter/target/destination material, policy snapshot, decision, selected controls, and expiry.

No parallel banking receipt is introduced. A catalog entry, provider permission, or client-side success cannot substitute for the Decision Receipt.

## Execution Receipt

An allowed executor reports success, failure, cancellation, result digest, and actual execution material against the same one-time grant. Hawk reuses the existing Execution Receipt and integrity comparator to classify matched, partial, drifted, or unverified execution.

A block cannot report successful execution. Identical terminal retries are idempotent; conflicting retries are rejected or quarantined. Provider-reported execution remains weaker than independently attested bank-service evidence.

## Approval binding

Approval is short-lived, single-use, tenant-bound, subject-bound, action-bound, transaction-bound, and exact-material-bound. The approver sees the canonical action, not prompt prose.

Changing amount, beneficiary, customer, account, target, destination, tool, fingerprint, purpose, authority, or side-effect material invalidates approval. Expired or replayed approval blocks. Provider-native approval metadata is context only and never Hawk authorization.

## Response assurance

Structured response assurance compares the proposed response with typed trusted Function results and approved subject/resource scope. The server profile selects one deterministic result:

- `ALLOW`
- `REDACT`
- `REGENERATE` — one bounded retry only when explicitly enabled
- `SAFE_FALLBACK`
- `BLOCK`

Wrong amount, currency, transaction count, period, fees, beneficiary, status, result digest, subject/account scope, or excess fields cannot be silently released. Redaction and safe fallback do not call the provider again. Streaming is **Not Covered** until an exact streaming lifecycle is accepted.

## Banking policy reference

The control plane owns policy. Enabling the banking path requires Decision/Execution Receipts, a distinct pseudonymization key, at least one trusted issuer, and a complete server-owned policy profile.

Required configuration families:

```text
BANKING_TRANSACTION_INTEGRITY_ENABLED
DECISION_EXECUTION_RECEIPTS_ENABLED
BANKING_SUBJECT_PSEUDONYMIZATION_KEY
BANKING_SUBJECT_TRUST_JSON
BANKING_TRANSACTION_POLICY_PROFILE_JSON
RECEIPT_SIGNING_ACTIVE_KEY_ID
RECEIPT_SIGNING_KEYS_JSON
```

The trust map pins issuer, audience, key ID, and ES256 public key. The policy profile pins one policy snapshot plus non-empty approved AI systems, destinations, workload identities/types/authentication modes, operation types, purposes, and tool versions/fingerprints/target bindings.

Secrets and private signing keys must come from the approved Key Vault/KMS/HSM or workload-identity path. Do not commit them, place them in scripts, return them from API errors, or persist access tokens in adapter objects.

Runtime routes:

| Purpose | Route |
|---|---|
| Authorize consequential action | `POST /runtime-control/banking-actions/authorize` |
| Immediate final revalidation | `POST /runtime-control/banking-actions/pre-execution` |
| Report actual execution | `POST /runtime-control/banking-actions/execution` |
| Authorize model request | `POST /runtime-control/banking-models/authorize` |
| Validate model response | `POST /runtime-control/banking-models/response` |
| Assure structured banking response | `POST /runtime-control/banking-responses/assure` |
| CISO bounded summary | `GET /runtime-control/banking-transactions/summary/ciso` |
| One transaction projection | `GET /runtime-control/banking-transactions/{ai_transaction_id}` |

All routes are authenticated, tenant-scoped, and role-gated.

## Sentinel

Hawk's existing SIEM/Sentinel projection carries pseudonymous transaction, subject, agent, model, purpose, action, transport, target/destination class, selected controls, receipt references, integrity, drift, findings, and coverage. It does not export raw subject assertions, credentials, customer/account IDs, prompts, model responses, tool arguments, or bank transaction records by default.

The production acceptance must prove workspace delivery, schema mapping, authentication, retry/failure visibility, health monitoring, tenant isolation, and alert rules. A locally built event is not proof of Sentinel delivery; current tenant delivery remains `EXTERNAL_DEPENDENCY`.

## Control Coverage

Coverage is independent by dimension and is never averaged into an inflated score. Subject, identity, purpose, model, Function, MCP, direct API, parameter, target, destination, approval, execution visibility, execution verification, response assurance, and bypass states are each `Covered`, `Not Covered`, `Unknown`, or `Not Applicable` with evidence references.

The CISO summary at `/dashboard/command-center` uses a bounded observed-transaction denominator. The transaction page is `/runtime-intelligence/transactions/{id}`; developer diagnostics are separate at `/runtime-intelligence/transactions/{id}/diagnostics`. When the Decision Receipt carries an exact primary control-point reference, diagnostics read that control point's current health and measured latency. Without that exact binding, both values remain Unknown.

`coverage_complete=true` is permitted only when every applicable dimension for that exact transaction is covered or not applicable. It is not an enterprise-estate claim.

## Failure and degradation

Hawk fails closed when subject, target, required policy, final binding, receipt, or mandatory control-plan evidence is unavailable. Sensitive reads, writes, persistent effects, and external destinations require online control. A low-risk read may use a valid signed local policy only when the server profile permits it and every required subject/target binding remains valid.

There is no silent downgrade below required assurance:

| Failure | Required state |
|---|---|
| Invalid subject or resource scope | Block |
| Policy unavailable/stale without eligible signed local policy | Control requirement unsatisfied |
| Middleware unhealthy or selector ineligible | Degraded / Not Covered; do not route as enforced |
| MCP/APIM/Foundry route unavailable | Fail according to the action-specific mandatory control plan; consequential actions block |
| Evidence or receipt failure | Do not claim execution verified |
| Post-authorization mutation | Reauthorize exact material or block |
| Unsupported streaming | Not Covered |

## Deployment

Supported architecture is hybrid: Hawk SaaS may hold policy/evidence metadata while sensitive validation and execution remain in bank-controlled Azure, AKS, APIM, or application runtimes. Raw banking data does not need to traverse Hawk SaaS.

Production deployment prerequisites:

1. Pin and review the exact .NET, Agent Framework, Foundry, MCP/Toolbox, OpenAPI, and APIM versions.
2. Deploy the adapter and service-side revalidation in the bank-controlled runtime.
3. Use private connectivity and explicit egress policy for the control-plane route.
4. Use Entra workload identity and Key Vault/KMS/HSM references; do not deploy static tokens.
5. Apply migrations with a verified backup first. Do not delete PostgreSQL/Docker volumes during upgrade.
6. Configure and validate Sentinel export and failure telemetry.
7. Run the tenant acceptance pack before setting the control point eligible for selection.
8. Promote each capability independently; retain Unknown/Not Covered for every unproven route.

The local persistent demo stack is operated through `infra/scripts/hawk_demo_stack.sh`. Its healthy state proves only local service/schema availability, not a bank production deployment.

## Data and privacy

Persist only tenant-keyed pseudonymous subject/resource references, classifications, safe hashes, policy/receipt IDs, evidence grades, coverage state, and drift fields. Do not persist:

- access/refresh tokens, private keys, or raw assertions;
- customer or account identifiers;
- prompt, RAG, response, or conversation bodies;
- raw Function/MCP arguments or bank transaction records;
- provider secrets or connection strings.

Secrets must remain in bank-controlled Key Vault/KMS/HSM or workload-identity exchanges. The .NET client requests a fresh access token per call and does not retain it in a client field, log, exception body, or file.

## Operational runbook

### Start and health

```bash
cd "/Volumes/X10 Pro/New project/repo"
./infra/scripts/hawk_demo_stack.sh up
./infra/scripts/hawk_demo_stack.sh status
curl -fsS http://127.0.0.1:8000/health
curl -fsS -o /dev/null -w "UI HTTP %{http_code}\n" http://127.0.0.1:3001/login
```

Require API `status=ok`, `schema_healthy=true`, UI HTTP 200, and healthy API/web/worker/beat/database/Redis containers before acceptance activity.

### Observe

- CISO: `/dashboard/command-center`
- Exact transaction: `/runtime-intelligence/transactions/{id}`
- Developer contract: `/runtime-intelligence/transactions/{id}/diagnostics`
- Tenant runtime rates/counters, six endpoint latency series, and separate Function/MCP/Toolbox/REST/OpenAPI/APIM latency: authenticated `GET /ops/metrics`
- Sentinel/evidence: use the existing evidence and SIEM delivery views.

Metrics are bounded operational telemetry. They do not promote a capability. A route with no correlated latency remains Unknown.

### Change

1. Back up PostgreSQL and verify that the backup exists and is non-empty.
2. Build images and run Alembic migration.
3. Restart without deleting volumes.
4. Verify schema revision, API health, UI health, workers, and seed preservation.
5. Run the local Function allow/block/non-execution proof.
6. Run the tenant-backed Foundry/MCP/APIM/Sentinel acceptance before promotion.

### Roll back

Disable selector eligibility or the tenant control point before removing an adapter. Preserve receipts and late evidence. Restore a verified backup only under the bank's database-change procedure; never use volume deletion as rollback.

## Troubleshooting

| Symptom | Check | Safe response |
|---|---|---|
| API or schema degraded | `/health`, migration revision, database health | Stop promotion; restore service/schema health |
| 401/403 | tenant token, role, workload identity, audience | Re-enroll/reauthorize; never bypass auth |
| 422 | exact request contract, subject assertion, policy/tool/target binding | Correct authoritative material; do not weaken validation |
| Function still executes on block | final middleware ordering and `next()` count | Disable the route; treat as Not Covered until non-execution passes |
| Receipt mismatch | action hash, grant, final arguments, execution report | Quarantine conflicting evidence and investigate drift |
| Tool fingerprint drift | inventory/schema/version/project connection | Re-review and promote the new fingerprint; do not auto-trust |
| CISO view says Unknown | no bounded transaction evidence or API unavailable | Restore evidence flow; do not seed synthetic proof |
| Middleware health/latency says Unknown | no transaction-bound health or latency sample | Add authenticated measurement; do not infer from service uptime |
| Sentinel missing | exporter health, destination policy, workspace auth | Preserve local evidence; mark delivery unverified |
| Streaming requested | exact adapter coverage | Block or use an accepted non-streaming path |

## Acceptance

Local acceptance requires:

- own-customer action allowed and invoked exactly once;
- cross-customer/account action blocked before callback with callback count zero;
- exact parameter and target mutation blocked;
- Decision/Execution Receipts correlated and matched for allow;
- response mismatch handled by deterministic assurance;
- tenant isolation, privacy, idempotency, fail-safe, and negative-capability suites pass;
- web CISO and developer views show only evidence-backed values;
- source and reference projects compile with no errors.

Production POC acceptance additionally requires retained bank-controlled evidence for real Foundry model/Function behavior, real MCP/Toolbox auth and non-execution, REST/OpenAPI/APIM equivalence and bypass resistance, independent bank-service attestation through production KMS/HSM, Sentinel delivery, private connectivity, exact runtime latency/failure behavior, unrestricted .NET test execution, failover/rollback, scale, and selector health.

The authoritative result matrix is [`docs/validation/microsoft-banking-phase1-p0-report.md`](../validation/microsoft-banking-phase1-p0-report.md). Until every item in its POC blocker section is closed, the final truth remains:

**PHASE 1 NOT PRODUCTION-POC READY**
