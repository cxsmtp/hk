# Bank Foundry First Proof Path — Validation Record

**Date:** 2026-08-14  
**Status:** First local Function proof plan complete, including persistent PostgreSQL deployment; broader Foundry surfaces remain pending  
**Authoritative design:** `docs/superpowers/specs/2026-08-14-bank-foundry-transaction-integrity-dotnet-design.md`  
**Execution plan:** `docs/superpowers/plans/2026-08-14-bank-foundry-first-proof-path.md`

## Implemented and verified

- ES256 bank subject assertion verification with configured issuer, audience, key ID, signature, issue time, expiry, nonce, tenant, and ten-minute maximum lifetime.
- Tenant-keyed HMAC pseudonymization for customer, account, resource, session, device trust, destination, and workload identity.
- Durable nonce binding to one exact context digest and Hawk transaction; conflicting transaction reuse fails as replay.
- Server-owned runtime binding for AI system, tool version/schema fingerprint, destination, workload identity, purpose, and policy snapshot.
- Cross-customer mismatch blocks before execution and produces an existing Hawk Decision Receipt.
- Unregistered runtime material blocks before execution and produces an existing Hawk Decision Receipt.
- Own-account read passes the final pre-execution gate and produces matched existing Decision and Execution Receipts.
- Material target mutation after authorization is re-canonicalized and rejected with an existing drift integrity result.
- A blocked decision cannot create a successful Execution Receipt.
- The executable account is derived from the approved tool's `account_id` argument and the resource from server-owned profile configuration. A caller cannot authorize one declared account while executing another argument value.
- Final pre-execution validation issues a short-lived, single-use grant bound to tenant, Decision Receipt, execution attempt, and exact canonical-action hash. Execution evidence without that grant is rejected.
- Identical terminal report retries are idempotent; conflicting status retries are rejected and never create a second receipt.
- New schema-1.1 Execution Receipts sign chain, actor, purpose, tool, arguments, target, destination, authority, side-effect class, and policy snapshot. Existing schema-1.0 receipts remain independently verifiable against their original signed field set.
- FastAPI request-validation responses omit raw input and validation context so a malformed subject assertion cannot be reflected to a client or log collector.
- The .NET request contract deep-freezes argument material and redacts its string representation. The Agent Framework adapter executes a sealed clone of the authorized arguments, not a downstream-mutated argument dictionary.
- Function failure and cancellation report the API's canonical `failure` status with the same one-time grant before the original exception is rethrown.
- Successful but malformed Hawk HTTP responses fail closed instead of being labelled complete evidence.
- No raw synthetic customer, account, mobile-session, assertion, or private-key value is present in runtime application code.

## Verification evidence

```text
121 passed, 1 warning in 35.49s
```

Command scope:

```text
tests/test_banking_transaction_integrity_settings.py
tests/test_banking_subject_context.py
tests/test_banking_transaction_integrity_api.py
tests/test_decision_execution_receipts.py
tests/test_bank_foundry_poc_scenarios.py
tests/test_fresh_database_migrations.py
```

The single warning is the existing spaCy/Click import deprecation emitted by the bank POC fixture. Targeted `py_compile` passed for every new or modified Python module. Ruff, mypy, and pyright are not installed in the current API environment and were not claimed as run.

The secret-safe global validation projection was also checked against existing HMAIR private-input and runtime data-transfer validation contracts:

```text
8 passed, 4 existing dependency-deprecation warnings
```

Migration verification:

```text
Alembic head: 0053_banking_execution_grants
Fresh SQLite upgrade: 0001_initial -> 0053_banking_execution_grants succeeded
Fresh migration contract tests: 5 passed
```

Generated AppleDouble migration sidecars were moved, not deleted, to recoverable quarantine directories:

```text
/private/tmp/hawk-appledouble-quarantine-20260814T071205Z
/private/tmp/hawk-appledouble-quarantine-0053-20260814-a
/private/tmp/hawk-appledouble-quarantine-0053-20260814-b
/private/tmp/hawk-appledouble-quarantine-0053-20260814-c
```

Each directory contains its own restore manifest.

## .NET verification state

The trusted arm64 .NET SDK is installed at `$HOME/.dotnet`:

```text
.NET SDK: 8.0.423
Microsoft.Agents.AI: 1.15.0 (locked)
Release build: succeeded, 0 warnings, 0 errors
```

The complete current Release suite was run outside the restricted Codex sandbox:

```text
Passed: 15, Failed: 0, Skipped: 0, Total: 15, Duration: 54 ms
```

This covers the updated client, gate, middleware, deep-freeze, sealed execution
arguments, one-time grant, canonical failure reporting, and malformed-response
rejection tests.

## Live synthetic acceptance evidence

User-run acceptance against the isolated local Hawk API completed successfully
on 2026-08-14:

```text
Own account:
  decision: allow
  executed: true
  evidence_complete: true
  integrity: matched
  decision_receipt_id: 4720dfea-ef48-59ff-8c72-190451ff39b6
  execution_receipt_id: 7e2a5ba3-2bed-502a-8ab3-94d6bc712b72
  integrity_result_id: da6cbcb1-52e2-5a06-8954-044de8965015

Cross customer:
  decision: block
  executed: false
  evidence_complete: true
  decision_receipt_id: 5830addf-cd25-5069-9f67-804bdf941e7c

cross_customer_read_count: 0
```

This verifies the trusted local Function callback path and its pre-execution
non-execution guarantee. It does not promote a real Microsoft Foundry model,
hosted agent runtime, APIM, MCP/Toolbox, or production bank deployment claim.
The acceptance server used an isolated temporary SQLite database; the migration
itself was independently verified through Alembic revision
`0053_banking_execution_grants` as recorded above.

## Capability-matrix promotion

The shipped provider registry now exposes the action-scoped manifest
`microsoft:agent_framework:agent_middleware` for exactly
`Microsoft.Agents.AI` `1.15.0`. The adapter remains **Experimental** overall.
Only these locally accepted dimensions are promoted:

```text
function_tool_control: inline_bound / verified
function_tool_parameter_binding: inline_bound / verified
function_tool_target_binding: inline_bound / verified
```

The subsequent Phase 1 P0 extension added local model request/response,
MCP/Toolbox, and direct API/APIM bindings. They are now
`inline_bound / experimental`, not Verified. Post-execution verification is
`observe / experimental`; hosted MCP remains `unavailable / unverified`. A
catalog manifest alone does not create a tenant control point and does not
contribute deployment coverage.

Promotion verification:

```text
API manifest and provider projection: 9 passed
Combined banking, receipt, migration, manifest, and provider suite: 130 passed, 1 existing dependency warning
Web capability-matrix source tests: 4 passed
Web TypeScript check: passed
.NET Release suite: 15 passed, 0 failed, 0 skipped
```

One broader, pre-existing native-control API assertion remains outside this
change: the current Cursor adapter reports `experimental` while an older test
expects `unverified`. It was not changed to make this Microsoft slice pass.

## Persistent Docker/PostgreSQL deployment proof

The user-run backup-first deployment verifier completed successfully on
2026-08-14:

```text
status: passed
backup: infra/artifacts/backups/hawk-demo-20260814T105418Z.dump
backup_size_bytes: 5327599
alembic_revision: 0053_banking_execution_grants
schema_proof: present|4
api_health.status: ok
api_health.schema_healthy: true
ui_http: 200
```

At the time of this first-proof smoke test, the persistent API returned the scoped
`microsoft:agent_framework:agent_middleware` manifest with overall status
`experimental`, supported version `1.15.0`, and exactly the three Function
claims above as `inline_bound / verified`. Model request, MCP, direct API and
hosted MCP remained `unavailable / unverified`. The later Phase 1 P0 code
changes the first three of those broader bindings to Experimental while keeping
hosted MCP Unavailable; that updated manifest has not been re-promoted through
a customer tenant. The catalog-only manifest reported
`effective_for_selection=false`, so it does not silently become an active tenant
control point or inflate coverage.

The backup was created before the migration. No Docker volume was deleted and
no database reset, schema drop, merge, commit, push, or working-tree discard
was performed.

## Remaining first-plan work

None. The scoped first proof plan is complete.

## Phase 1 P0 extension record

The additive P0-A through P0-E foundation is implemented and documented in
`docs/validation/microsoft-banking-phase1-p0-report.md`:

- generic immutable subject/resource/identity/authority context;
- Agent Run and `IChatClient` model request/response wrappers;
- one canonical Function/MCP/Toolbox/REST/OpenAPI/APIM transport projection;
- deterministic structured-response assurance;
- transaction timeline, independent coverage dimensions, Sentinel projection,
  fail-safe model, latency telemetry, and a 49-scenario validation catalog;
- an evidence-backed transaction UI at
  `/runtime-intelligence/transactions/{ai_transaction_id}`;
- a bounded regulated-transaction CISO summary in the existing Command Center,
  with separate developer diagnostics and the production guide at
  `docs/deployment/microsoft-banking-runtime-control.md`.

Fresh P0 verification recorded **338 backend tests passed**, the previous
receipt-binding flake passed 10 consecutive isolated reruns, nine selected web
tests passed, TypeScript passed, and the .NET test/reference projects compiled
with zero warnings and zero errors. Fresh execution of the expanded .NET test
assembly was unavailable in the restricted session and is not inferred from the
compile result.

## Remaining production acceptance after the P0 extension

- Run the expanded .NET suite in a trusted unrestricted runner.
- Run real Foundry model, Function, ordering, mutation, timeout, and rollback acceptance.
- Run real MCP/Foundry Toolbox identity, fingerprint, drift, allow/block, and non-execution acceptance.
- Run real APIM/OpenAPI/direct REST equivalence and bypass acceptance.
- Connect production bank-service attestation through tenant KMS/HSM.
- Validate Sentinel delivery/health, private connectivity, and production latency.
- Validate A2A/remote-agent delegation and unsupported streaming boundaries.
- Configure and accept a real tenant control point before increasing Control Coverage.

## Working-tree integrity

No file was staged, committed, merged, pushed, discarded, or reset. Existing unrelated user changes remain untouched.
