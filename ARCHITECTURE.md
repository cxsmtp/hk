# Platform Architecture

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


## 1. Purpose of This Document
This document is the single source of truth for the current Hawk AI platform architecture in this repository.

It is intended to support:
- engineering onboarding and handoff
- architecture and security review
- implementation-partner alignment
- technical diligence conversations

It documents:
- actual implemented architecture (based on repository inspection)
- module boundaries and interactions
- data and control flows
- operational assumptions
- current maturity and technical risk

### Evidence Quality Legend
- **Implemented**: directly evidenced by code/routes/models/tests in this repo.
- **Partial**: implemented but with clear depth/coverage gaps.
- **Placeholder**: intentionally minimal or demo-oriented implementation.
- **Inferred**: reasonable deduction from code patterns/config; not explicitly documented in code comments.
- **Unclear**: cannot be confirmed from repository alone.

---

## 2. Platform Overview
Hawk AI is a **multi-tenant AI control plane** with governance, runtime enforcement, discovery, monitoring, validation, audit, and remediation capabilities.

### What the platform does
At a system level it provides:
- governance registry for AI systems (`Trust Center`)
- deterministic enforcement for AI interactions (`Gateway`, `Runtime Control`, browser extension hooks)
- discovery and correlation of unknown AI usage (`Shadow AI Discovery`)
- AI identity and capability controls (`AI IAM`)
- continuous monitoring and drift signaling (`Monitoring`)
- simulation-based control validation (`Simulations`)
- evidence-backed auditor snapshots and traceability (`Auditor`)
- non-blocking runtime analytics/correlation (`Runtime Intelligence`)
- centralized operational dashboard (`AI Command Center`)

### Primary personas (inferred)
- **Owner/Admin**: governance, policy, approvals, remediation, lifecycle changes
- **Operator/Security Analyst**: investigate events/findings, execute controls, run simulations
- **Auditor**: evaluate evidence lineage, posture, conflicts, exports
- **Engineering/Platform**: runtime health, dependency checks, queue operations

### Architectural characteristics
- **Backend**: modular FastAPI monolith (`apps/api`) with domain routers + service layer
- **Frontend**: Next.js App Router SPA-style control console (`apps/web`)
- **Extension surface**: Manifest V3 browser extension (`extension`)
- **Workers**: Celery + Redis for async/scheduled tasks
- **Data**: PostgreSQL (primary), Redis (queue/cache/heartbeats), filesystem artifacts
- **Pattern**: enforcement path is deterministic/fail-secure; runtime intelligence is async/non-blocking enrichment

### Architecture style classification
- **Implemented style**: modular monolith + worker subsystem + browser deployment surface
- **Not implemented**: independent microservices architecture

---

## 3. Architecture Summary
### Frontend layer
- Next.js 15 App Router UI in `apps/web/src/app`
- App shell (`Sidebar` + `Topbar`) with role-aware navigation
- API client in `apps/web/src/lib/api.ts` (JWT + tenant header + token refresh)
- Runtime Intelligence SSE subscriptions via `apps/web/src/hooks/use-runtime-intelligence-stream.ts`

### Backend / application layer
- FastAPI entrypoint: `apps/api/app/main.py`
- Broad domain routing under `apps/api/app/api/routers`
- Business logic in `apps/api/app/services`
- Strong tenant/RBAC dependency pattern (`require_tenant`, `require_role`)

### AI orchestration layer
- Primary deterministic guardians and policy engine for enforcement
- `brain` subsystem for plan/execute/summarize LLM workflows (OpenAI/Anthropic/Gemini providers)
- Model-council arbitration logic in `apps/api/app/services/brain/council.py`

### Data/storage layer
- SQLAlchemy models in `apps/api/app/db/models`
- Alembic migrations in `apps/api/app/db/migrations`
- Redis for Celery broker/results + health heartbeats
- Artifact exports persisted to filesystem (`ARTIFACT_DIR`, default `/artifacts`)

### Integration layer
- Browser extension telemetry + policy sync
- Connector subsystem (Slack/Gmail/Google Workspace + others)
- Gateway provider normalization and provider catalog
- On-prem stub for policy sync + signed evidence bundle ingest

### Security/governance layer
- JWT auth + tenant isolation + role hierarchy
- Governance resolution for AI system status (`UNKNOWN` default high risk)
- Fail-secure service for dependency/governance failures
- Immutable audit log model guards (`before_update`/`before_delete` blocked)
- Evidence graph (`evidence_nodes` + `evidence_edges`)

### Deployment/runtime model
- Docker compose stack (`db`, `redis`, `migrate-seed`, `api`, `worker`, `celery-beat`, `web`)
- Podman compose variant (`postgres`, `redis`, `api`, `worker`, `scheduler`, `web`)
- CI workflow executes unit + integration tests with Postgres/Redis services

---

## 4. Repository Structure
This is a curated breakdown by responsibility (not a raw file dump).

- `apps/api/`
  - FastAPI backend, SQLAlchemy models, migrations, Celery jobs, tests
  - `app/main.py`: API bootstrap + middleware + router wiring
  - `app/api/routers/`: module endpoints
  - `app/services/`: domain logic and cross-cutting services
  - `app/db/models/`: canonical persistent entities
  - `app/jobs/`: async/scheduled processing
  - `tests/`: unit/integration/system-level backend tests

- `apps/web/`
  - Next.js 15 frontend console
  - `src/app/`: module pages and route surfaces
  - `src/components/`: reusable UI and module-specific components
  - `src/lib/api.ts`: typed API client and fallback strategy

- `extension/`
  - Chrome/Edge Manifest V3 browser extension
  - policy sync, telemetry queueing, prompt guard, copy/paste controls, UI banners/interstitials
  - Playwright E2E tests with unpacked extension

- `infra/`
  - Docker/Podman compose and Dockerfiles
  - startup/seed/test harness scripts
  - e2e orchestration scripts and summaries

- `packages/shared/`
  - cross-language schema contracts (`.py` + `.ts`) for policy/simulation/core types

- `docs/`
  - deployment and execution plan documentation

- `.github/workflows/`
  - API test workflow (unit + integration)

---

## 5. System Architecture Breakdown
### 5.1 Presentation Layer
- Next.js pages, reusable cards/tables/graphs, sidebar/topbar shell
- Browser extension UI elements for warning/block/justification feedback
- Role-gated navigation and client-side session handling

### 5.2 API/Business Logic Layer
- Router-level request parsing and role/tenant enforcement
- Service layer for policy evaluation, governance resolution, discovery, remediation, scoring
- Cross-cutting audit and evidence writes for high-value operations

### 5.3 Orchestration Layer
- Deterministic orchestration in gateway/runtime control services
- Runtime Intelligence orchestration for event normalization -> correlation -> patterns -> recommendations -> triggers
- Brain orchestration for LLM planning/execution/arbitration (separate from deterministic enforcement)

### 5.4 Persistence Layer
- PostgreSQL as system of record for governance/enforcement/findings/evidence/audit/runtime/monitoring
- Redis for job transport/result backend + worker/beat liveness heartbeats
- Artifact filesystem for snapshots and export packs

### 5.5 External Services Layer
- LLM providers (OpenAI/Anthropic/Gemini in brain path)
- browser extension transport to backend APIs
- ticketing integration paths (Jira/ServiceNow via findings/remediation flows)
- optional on-prem evidence bundle ingestion

### 5.6 Security/Control Layer
- auth + tenant + RBAC dependencies
- governance status resolution and unknown-system handling
- fail-secure dependency checks
- immutable audit trail + evidence graph linkage

---

## 6. Module Inventory
The platform is implemented as domain modules plus cross-cutting capabilities.

| Module | Purpose | Main Files/Folders | Inputs | Outputs | Dependencies | Downstream Consumers | Maturity | Risks/Gaps |
|---|---|---|---|---|---|---|---|---|
| Trust Center / AI Systems | System-of-record AI registry, lifecycle/risk governance | `apps/api/app/api/routers/ai_systems.py`, `.../routers/trust_center.py`, `.../models/ai_system.py`, `.../services/governance_resolution.py` | AI system create/update requests, risk/lifecycle changes, governance lookups | AI system records, governance statuses, remediation state, audit/evidence | DB, policy service, remediation service | Gateway, runtime control, discovery, UI dashboards | **Implemented** | Metadata-heavy state machine in `metadata_json` increases schema drift risk |
| Policy & Guardian Contracts | Canonical policy and guardian evaluation contracts | `.../routers/policies.py`, `.../routers/guardian_contracts_v2.py`, `.../services/guardian_policy_engine.py`, `packages/shared/schemas/policy_contracts.*` | Policy packs/versions, rule conditions, framework mappings | Enforcement decisions and policy metadata | DB, shared schemas | Gateway, runtime control, simulations, auditor | **Implemented** | Multiple policy generations (legacy + v2 + canonical) create complexity |
| Gateway (LLM/MCP) | Deterministic enforcement surface for sanctioned AI traffic | `.../routers/gateway.py`, `.../services/gateway_service.py`, `.../services/llm_gateway_service.py` | Intercept/authorize requests, actor + ai system + payload metadata | EnforcementEvent, decision, EvidenceNode, AuditLog, findings/runtime feed | Governance resolution, guardian policy engine, fail-secure | Interaction Security UI, Runtime Intelligence, Auditor | **Implemented** | Provider interoperability relies on metadata quality from callers |
| Interaction Security & Runtime Control | Prompt/payload/action/copy-paste control decisions | `.../routers/runtime_control.py`, `.../services/runtime_control_data_transfer_service.py`, `.../services/runtime_control_agent_action_service.py` | Browser transfer context, agent action context, policy mode | allow/warn/block/require_* decisions + audit/evidence/findings/runtime events | Governance resolution, policy engine, AI IAM, shadow/provider catalog | Extension UX, findings, runtime intelligence, auditor | **Implemented** | Browser-only scope for copy/paste controls; no OS-level controls (explicit non-goal) |
| Browser Extension Surface | Browser deployment surface A: policy sync, telemetry, prompt/data-transfer hooks | `extension/src/*`, `extension/manifest.json`, `.../routers/extension.py`, `.../services/browser_extension_service.py` | Content-script events, copy/paste, unknown-domain signals, health pings | Backend telemetry ingestion, findings/evidence/runtime events | Backend APIs, cached policy, local storage | Discovery, findings, interaction security dashboards | **Implemented (with partial UX depth)** | Reliant on host permissions + DOM heuristics; UI flows timing-sensitive in E2E |
| Shadow AI Discovery | Multi-surface unknown AI identity discovery/correlation/reconciliation | `.../routers/shadow_ai.py`, `.../services/shadow_ai/*`, `.../models/shadow_ai.py` | Browser/gateway/connector/endpoint/dns/proxy/aiiam/monitoring signals | shadow entities/signals, candidate promotions, findings/evidence | Provider catalog, runtime normalizer, discovery service | Trust Center candidate governance, discovery UI, runtime intelligence | **Implemented** | Confidence/risk quality depends on signal richness and normalization consistency |
| AI IAM | Agent identity, scoped tokens, delegation, kill-switch controls | `.../routers/ai_iam.py`, `.../routers/agents.py`, `.../services/ai_iam_service.py`, `.../models/ai_iam.py` | Agent lifecycle/token/delegation/action intercept requests | Identity/tokens/delegations, enforcement decisions, remediation actions | DB, runtime control services, governance/fail-secure | AI IAM UI, gateway/runtime enforcement, auditor | **Implemented (UI detail partial)** | Agent detail depth in UI still event-derived and not fully modeled as policy-centric explorer |
| Continuous Monitoring | Connector operations, drift, signal cadence, telemetry ingestion | `.../routers/monitoring.py`, `.../services/monitoring_service.py`, `.../services/integration_connector_service.py`, `.../models/monitoring.py` | Connector pulls/signals and health events | MonitoringSignal, DriftAlert, findings/remediation hooks | DB, connectors, Celery schedules | Runtime intelligence, auditor, command center | **Implemented** | Connector adapters appear mostly platform-stub level, not full vendor parity |
| Runtime Intelligence | Async/non-blocking enrichment: normalize, correlate, score, trigger, recommend | `.../routers/runtime_intelligence.py`, `.../routers/runtime.py`, `.../services/runtime_intelligence/*`, `.../models/runtime_intelligence.py` | Enforcement/browser/connector/AI IAM/network events | RuntimeEvent, behavior/context graph, patterns, triggers, recommendations | Provider catalog, findings, simulations, remediation proposal, SSE broker | RI UI pages, command center, auditor | **Implemented** | In-memory SSE broker is single-process and non-durable |
| AI Control Validation (Simulations) | Template/pack-based simulation, run execution, maturity impact | `.../routers/simulations.py`, `.../services/simulation_*`, `.../models/simulation.py`, `.../models/maturity.py` | Manual or triggered simulation requests | SimulationRun, schedule decisions, maturity updates, evidence/audit | Policy controls, runtime triggers, monitoring inputs | Validation UI, trust center maturity, auditor | **Implemented** | Complex domain with large surface area; deterministic guarantees need sustained regression coverage |
| Automated Auditor | Snapshot/export/posture/proof-chain and conflict workflows | `.../routers/auditor.py`, `.../routers/audit.py`, `.../services/snapshot_service.py`, `.../models/snapshot.py`, `.../models/audit.py`, `.../models/evidence.py` | Findings, runtime refs, monitoring/drift, simulation outputs, governance data | Snapshots, traces, exports (JSON/CSV + payload models), conflict records | Artifact storage, evidence graph, control maturity | Auditor UI, external audit packs | **Implemented (export depth partial)** | PDF-ready output is payload-model oriented; visual evidence narratives in UI still table/detail heavy |
| Remediation (Cross-cutting) | Policy-driven recommend/apply/approve/rollback actions | `.../services/remediation/remediation_engine.py`, `.../routers/findings.py`, `.../models/remediation.py` | Violations, runtime patterns, drift, simulation failures, governance triggers | remediation actions + lifecycle + audit/evidence + linkage | Trust center, AI IAM, monitoring, runtime intelligence | Findings/Trust/Auditor/Command Center views | **Implemented (cross-cutting)** | High policy complexity; approval matrices and rollback safety need strict change control |
| Command Center Dashboard | Aggregated executive/operational control-plane view | `.../routers/dashboard.py`, `.../services/dashboard/aggregator.py`, `.../services/dashboard/recommendations.py`, `apps/web/src/app/dashboard/command-center/page.tsx` | Multi-module metrics/events/recommendations | Unified dashboard state | DB across modules | CISO/operator workflows | **Implemented** | Aggregation currently DB-poll based and cache-local; no dedicated time-series store |
| Brain (LLM assistant subsystem) | Plan/execute/summarize/finding analysis using model council | `.../routers/brain.py`, `.../services/brain/*`, `.../models/brain.py` | User questions, context, finding ids | Brain plans, executions, model call records, arbitration artifacts | LLM provider keys/APIs, audit/evidence | Potential analyst workflows | **Implemented (adjacent to control plane)** | Adds non-deterministic path; should remain separated from hard enforcement decisions |
| AGUI Oversight | Human review/decision actions around findings/governance/policy overrides | `.../routers/agui.py`, `.../services/agui/*`, `.../models/agui.py` | Action/decision requests | Decision records, approvals, audit/evidence | RBAC, DB | AGUI UI pages | **Implemented** | Coupling between AGUI and core module semantics can grow if not normalized |
| On-Prem Gateway Stub | Minimal sovereignty credibility stub | `.../api/routers/onprem.py`, `.../onprem_gateway/*` | policy sync requests, signed bundles | cached policy, signed chain bundles, ingest evidence references | signing secret, trust-center/policy DB | auditor evidence chain | **Placeholder / Minimal implemented** | Not production on-prem; no full offline reconciliation or hardened key management |
| Coverage & Ops | Coverage matrix and operational health/status surfaces | `.../routers/coverage.py`, `.../services/deployment_coverage_service.py`, `.../routers/ops.py`, `.../routers/system.py`, `.../services/control_plane_health_service.py` | runtime/monitoring/enforcement/job health data | coverage summaries + health posture | Redis heartbeats, migrations, DB, artifacts | command center, ops UI | **Implemented** | Health checks are strong; however strict-dependency mode may block aggressively in degraded environments |

---

## 7. Module Interaction Map
The platform is intentionally interconnected via evidence/audit/runtime normalization.

### Core control loop
1. User/agent action enters via extension, gateway, connector, or runtime control endpoint.
2. Governance and policy engines evaluate context (trust center status + guardian/workflow rules).
3. Deterministic decision is returned (`allow/warn/block/require_*`).
4. `EnforcementEvent`/`AuditLog`/`EvidenceNode` are written.
5. Runtime event normalization ingests event into canonical `RuntimeEvent`.
6. Runtime Intelligence correlates patterns, computes risk, emits findings/recommendations/triggers.
7. Remediation engine may propose/apply bounded remediations.
8. Simulations validate control posture and update maturity.
9. Auditor snapshots and trace endpoints provide proof lineage.
10. Command Center aggregates cross-module status for operator decisions.

### ASCII interaction view
```text
[Browser Ext]      [Gateway]      [Connectors/Monitoring]      [AI IAM]
      \               |                    |                      /
       \              |                    |                     /
        -----> [Policy + Governance + Runtime Control] <--------
                        |   (deterministic enforcement)
                        v
              [AuditLog + EvidenceNode + EnforcementEvent]
                        |
                        v
                [Runtime Event Normalizer]
                        |
                        v
          [Runtime Intelligence Correlation + Scoring]
                  |             |             |
                  v             v             v
              [Findings]   [Simulation Triggers] [Recommendations]
                  |             |             |
                  +-------> [Remediation Engine] <-----+
                                  |
                                  v
                        [Trust Center / AI IAM / Policy]
                                  |
                                  v
                           [Automated Auditor]
                                  |
                                  v
                         [Command Center + Module UIs]
```

---

## 8. End-to-End Data Flows
### Flow A: Browser domain/prompt telemetry -> discovery/enforcement artifacts
- **Trigger**: extension content script observes AI-domain visit, prompt action, copy/paste
- **Path**:
  - `extension/src/content-script.ts` -> service worker -> backend `POST /telemetry/browser`
  - policy sync from `GET /extension/policy-sync`
  - optional backend interaction eval `POST /telemetry/browser/interaction-eval`
  - data movement checks via `/runtime-control/data-transfer-check|justify`
- **Transformations**:
  - domain classification + policy status (approved/warn/blocked/unknown)
  - payload redaction/hash-based content treatment
  - normalized runtime event bundle attached in metadata
- **Persistence**:
  - `MonitoringSignal`, `AuditLog`, `EvidenceNode`, optional `Finding`, `RuntimeEvent`
- **Outputs**:
  - discovery applications/shadow entities, findings views, runtime intelligence streams
- **Failure points**:
  - extension/backend network failure (queue retries, degraded health state)
  - DOM interception edge cases by target site updates

### Flow B: Gateway intercept/authorize -> deterministic enforcement
- **Trigger**: app/agent calls `/gateway/llm/intercept` or `/gateway/mcp/authorize`
- **Path**:
  - governance resolution -> guardian/workflow policy evaluation -> final decision
- **Transformations**:
  - provider/model metadata normalization
  - confidence tiering and decision precedence
- **Persistence**:
  - `EnforcementEvent`, `AuditLog`, `EvidenceNode`
- **Outputs**:
  - interaction security UI, approvals queue, runtime ingestion
- **Failure points**:
  - DB/governance dependency outages invoke fail-secure behavior

### Flow C: Runtime normalization and behavior graph
- **Trigger**: gateway/extension/connector/AI IAM/network event ingestion
- **Path**:
  - `ingest_runtime_event()` in `runtime_event_normalizer.py`
  - context graph edge/node construction
  - behavior graph edge generation
- **Transformations**:
  - canonical schema mapping across source surfaces
  - provider catalog enrichment
  - correlation and risk scoring
- **Persistence**:
  - `runtime_events`, `context_nodes`, `context_edges`, `runtime_behavior_edges`, `runtime_patterns`
- **Outputs**:
  - recommendations, simulation triggers, SSE updates, runtime-intelligence UI pages
- **Failure points**:
  - enrichment failures are non-blocking by design (logged, event path continues)

### Flow D: Shadow AI discovery and trust-center candidate reconciliation
- **Trigger**: unknown or unsanctioned AI signals from any surface
- **Path**:
  - shadow signal creation -> identity resolution -> confidence/risk scoring -> reconciliation
- **Transformations**:
  - canonical provider matching + alias normalization
  - cross-surface deduplication
- **Persistence**:
  - `shadow_ai_signals`, `shadow_ai_entities`, linked findings/evidence
- **Outputs**:
  - proposed candidate/link/reject/promote workflows
- **Failure points**:
  - weak-signal false positives; confidence thresholds govern promotion

### Flow E: Remediation loop
- **Trigger**: findings, runtime patterns, drift alerts, simulation failures, trust center lifecycle/risk events
- **Path**:
  - remediation plan generation -> approval gating -> executor updates
- **Transformations**:
  - trigger-type to remediation-type mapping
  - bounded policy/permission/state mutation
- **Persistence**:
  - `remediation_actions` with status transitions + rollback payload
  - linked audit/evidence and finding relations
- **Outputs**:
  - module state changes, tickets, auditor remediation trace
- **Failure points**:
  - high coupling with multiple modules; careful idempotency required

### Flow F: Simulation execution -> maturity impact
- **Trigger**: manual run, schedule, or runtime/monitoring trigger
- **Path**:
  - simulation definition/template/pack -> runner -> assertions
- **Transformations**:
  - deterministic pass/fail checks, enforcement replay, control mapping
- **Persistence**:
  - `simulation_runs`, `simulation_schedule_decisions`, `control_maturity(_history)`
- **Outputs**:
  - validation coverage/trends/heatmap, maturity deltas, findings/remediations
- **Failure points**:
  - test DSL quality, environment parity, deterministic fixture assumptions

### Flow G: Auditor snapshot/export
- **Trigger**: explicit snapshot/export or scheduled daily pack
- **Path**:
  - ingest current control posture/findings/runtime/monitoring/simulation/remediation context
- **Transformations**:
  - evidence linkage assembly
  - export payload generation (JSON/CSV + report-ready structures)
- **Persistence**:
  - `auditor_snapshots` + artifact files
- **Outputs**:
  - auditor dashboard, trace endpoints, downloadable artifacts
- **Failure points**:
  - artifact storage permissions/path availability

### Flow H: Auth/session flow
- **Trigger**: frontend login
- **Path**:
  - `/auth/login` returns access + refresh + selected tenant
  - frontend stores session in localStorage and sends `Authorization` + `X-Tenant-ID`
  - refresh endpoint used on 401
- **Persistence**:
  - `users`, `user_tenant_roles`, `refresh_tokens`
- **Failure points**:
  - localStorage token exposure risk in browser context

---

## 9. Frontend Architecture
### Routing structure
- App Router pages under `apps/web/src/app`
- Core module routes include:
  - `/dashboard/command-center`, `/dashboard`, `/interaction-security`, `/shadow-ai`, `/ai-iam`, `/monitoring`, `/simulations`, `/auditor`, `/runtime-intelligence/*`, `/discovery/*`

### Rendering model
- Client-heavy pages (`"use client"` patterns throughout dashboards)
- Polling for many pages; SSE used for Runtime Intelligence pages

### State management patterns
- Local `useState`/`useEffect` in each page
- shared API client abstraction (`api.ts`) with typed responses
- no global state library observed

### Component organization
- shared shell/components in `src/components`
- module-specific components in nested subfolders (`runtime-intelligence/*`, `ai-iam/*`)
- UI primitive layer in `components/ui/*`

### Form handling and validation
- Mostly lightweight client validation before API calls
- server-side validation and HTTP errors drive final behavior

### Client/server boundaries
- frontend communicates directly with API using JWT bearer + tenant header
- no Next.js server actions observed as core business path

### Dashboard/page composition
- card/table-heavy operational UI
- command center provides consolidated KPI + trend + recommendations
- runtime intelligence pages include graph and timeline interactions

### Shared UI system
- Tailwind styling + component wrappers (shadcn-style primitives)
- coherent dark theme

### Notable frontend implementation traits
- `apps/web/src/lib/api.ts` includes **demo fallback mode** (`NEXT_PUBLIC_DEMO_*`) to return fallback data when backend is unavailable/empty.
  - **Risk**: can mask real backend/data issues in non-production contexts if left enabled.

---

## 10. Backend / Service Architecture
### API routing and boundaries
- Router-per-domain organization in `apps/api/app/api/routers`
- `main.py` includes broad module registration and correlation middleware

### Service abstraction model
- Domain logic in `apps/api/app/services/*`
- Services depend on SQLAlchemy session passed from routers
- Cross-cutting services: audit, evidence, governance resolution, fail-secure, remediation

### Validation patterns
- Pydantic request/response models in routers
- canonical schema helpers in shared package + service-layer canonicalization

### Background processing
- Celery app in `apps/api/app/jobs/celery_app.py`
- Queues: `default`, `monitoring`, `auditor`
- Beat schedules for 15m/hourly/daily checks and snapshot packs
- Retry/backoff + dead-letter job run recording on task failure

### Error handling
- router-level `HTTPException` handling for validation/access errors
- fail-closed behavior in middleware and fail-secure service for critical dependencies
- non-blocking guards around runtime-intelligence enrichment paths

### Config management
- Pydantic settings from `.env` (`apps/api/app/core/config.py`)
- many flags controlling strictness, governance defaults, remediation behavior, runtime intelligence, OCR mode

### Feature-flag behavior observed
- `runtime_intelligence_enabled`
- `governance_strict_mode`
- `fail_secure_mode`
- `control_plane_strict_dependency_checks`
- `remediation_auto_apply_enabled`
- `sensitive_detection_async_ocr_enabled`

---

## 11. AI / Agent / Prompt Architecture
This repository has two distinct AI execution planes:
1. **Deterministic enforcement plane** (governance + guardian/workflow policies)
2. **LLM-enabled assistance plane** (`brain` module)

### 11.1 Deterministic enforcement plane (authoritative)
- Entrypoints:
  - `/gateway/llm/intercept`
  - `/gateway/mcp/authorize`
  - `/runtime-control/data-transfer-check`
  - `/runtime-control/agent-action-intercept`
- Policy decisioning:
  - `guardian_policy_engine.py` (canonical guardian contract evaluation + precedence)
  - `workflow_policy_service.py` (workflow-specific restrictions)
- Governance gate:
  - `governance_resolution.py` ensures unknown systems are not treated as approved by default
- Evidence/audit coupling:
  - every major decision path writes audit/evidence and usually runtime normalization

### 11.2 Brain module (LLM orchestration)
- Router: `apps/api/app/api/routers/brain.py`
- Providers: OpenAI, Anthropic, Gemini via provider factory
- Router mode: default `council` with task-specific multi-model selection
- Arbitration:
  - `ModelCouncil` compares multi-model outputs
  - uses deterministic arbitration heuristics (validity, invariants, citation density, etc.)
- Persistence:
  - brain sessions/plans/tool calls/model calls/arbitration tables
  - audit and evidence nodes per brain request/model/arbitration

### 11.3 Prompt organization
- Prompt logic appears in service code (`planner`, `summarizer`, provider wrappers) rather than a dedicated prompt registry folder.
- **Inferred gap**: prompt lifecycle/versioning for brain prompts is less explicit than policy versioning.

### 11.4 Structured output and guardrails
- Brain providers use JSON generation contracts and validation paths.
- Deterministic guardians/workflow policies remain separate from non-deterministic model outputs.

### 11.5 Tool calling / agent flows
- MCP/agent actions are controlled in runtime/gateway paths and AI IAM token scope checks.
- Runtime context graph captures user->agent->tool relationships.

### 11.6 Memory/context handling
- Runtime context graph via `context_id`, `chain_id`, `parent_action_id` in runtime events.
- Brain has DB-backed plan/execution context records.

### 11.7 Retrieval / RAG
- Brain has `rag/retriever.py` and KB models.
- RAG functionality appears present but not primary in main enforcement architecture.
- Marked **implemented (partial depth unclear)** from repository-only inspection.

### 11.8 Deterministic vs generative boundaries
- Deterministic control decisions are not delegated to LLM calls.
- Brain module is auxiliary analytics/assistant path.

### 11.9 AI risks in current implementation
- Brain adds non-deterministic behavior and external dependency exposure.
- Provider-specific behavior quality depends on runtime API keys/config.
- Prompt/model policy for brain is less governed than guardian contract lifecycle.

---

## 12. Data Model and Storage
### Core entity groups
- **Identity/Tenant**: `tenants`, `users`, `user_tenant_roles`, `refresh_tokens`
- **Governance**: `ai_systems`, policy packs/versions/contracts/bindings
- **Enforcement**: `enforcement_events`, `approval_requests`
- **Discovery**: `discovery_applications`, `shadow_ai_entities`, `shadow_ai_signals`
- **Monitoring**: `connectors`, `monitoring_signals`, `drift_alerts`
- **Runtime intelligence**: `runtime_events`, `runtime_behavior_edges`, `runtime_patterns`, `runtime_simulation_triggers`, `runtime_governance_recommendations`, `context_nodes`, `context_edges`
- **Validation/Maturity**: `simulation_*`, `controls`, `control_maturity`, `control_maturity_history`, `control_conflicts`
- **Audit/Evidence**: `audit_logs`, `evidence_nodes`, `evidence_edges`, `auditor_snapshots`
- **Remediation**: `remediation_actions`
- **Brain**: `brain_session`, `brain_plan`, `brain_tool_call`, `brain_model_call`, `brain_arbitration`
- **AI IAM**: `agent_identities`, `capability_tokens`, `agent_delegations`, `agent_action_baselines`

### Representation patterns
- SQLAlchemy declarative models with UUID/string ids and JSON payload columns.
- Heavy use of `metadata_json`/`payload` JSON objects for extensibility.

### Persistent vs ephemeral
- Persistent: DB records + auditor artifacts
- Ephemeral/in-memory:
  - SSE broker queues in process memory
  - frontend React state
  - extension local queue and policy cache in browser storage

### Limitations observed
- Significant behavior/state encoded in JSON fields instead of strongly typed relational columns.
- Helps speed iteration, but raises long-term query/indexing and schema-governance complexity.

---

## 13. Authentication, Authorization, and Tenant Model
### Authentication
- JWT access token (short-lived) + refresh token flow (`/auth/login`, `/auth/refresh`)
- Bearer auth enforced by `OAuth2PasswordBearer` dependency

### Session handling
- Frontend stores access/refresh/tenant/user in browser localStorage (`apps/web/src/lib/auth.ts`)
- Token refresh performed transparently on 401

### Authorization
- RBAC role hierarchy in `core/rbac.py`:
  - `viewer < operator < auditor < admin < owner`
- Router dependencies enforce minimum role or allow-list

### Tenant model
- Multi-tenant enforcement via mandatory `X-Tenant-ID` header + membership check in `require_tenant`
- Queries usually scoped by `tenant_id`

### Data isolation model
- Implemented as application-level tenant filtering + DB foreign keys; no row-level security configured in repo.

### Gaps
- localStorage token storage introduces XSS exposure risk surface.
- SSO/OIDC/MFA are not visible in current repository implementation.

---

## 14. Integrations and External Dependencies
### LLM providers
- OpenAI, Anthropic, Gemini provider implementations (brain module)
- used by `brain` plan/ask/summarize/finding analysis paths
- operational risk: API key misconfiguration or provider downtime

### Browser extension integration
- extension policy sync and telemetry APIs:
  - `/extension/policy-sync`
  - `/telemetry/browser`
  - `/telemetry/browser/interaction-eval`
  - `/runtime-control/data-transfer-*`
- operational risk: extension versions/host permissions drift

### Data infrastructure
- PostgreSQL (system of record)
- Redis (Celery + heartbeat + queue support)
- risk: dependency outage can trigger fail-secure blocking behavior

### Ticketing/remediation integration
- Jira/ServiceNow flows exposed through findings/remediation actions
- appears implemented as payload/action generation paths (connector depth may vary by environment)

### On-prem integration
- policy sync and signed evidence bundle ingest endpoints
- minimal on-prem stub service present

### Observability tooling
- structured application logging
- request latency tracker
- no external APM/metrics stack configuration in repo (e.g., Prometheus/Grafana exporters not fully wired in code)

---

## 15. Security Architecture
### Trust boundaries
1. Browser extension -> backend APIs
2. Frontend browser -> backend APIs
3. Backend -> DB/Redis
4. Backend -> external LLM APIs (brain path)
5. On-prem bundle producers -> cloud ingest endpoint

### Secrets handling
- env-driven keys/secrets in backend
- extension stores backend URL/token/tenant in local storage
- no hardcoded production secrets observed in source, but `.env` defaults include weak dev placeholders

### Sensitive data paths
- prompt and copy/paste content processed in runtime control
- sensitive detection supports regex + optional Presidio/spaCy + OCR extraction
- default posture prefers hashes/redacted previews in extension

### Auth controls
- JWT + tenant header required on privileged APIs
- RBAC enforced per-router

### Authorization assumptions
- tenant scoping primarily enforced in service query patterns; correctness depends on consistent filtering.

### Input validation
- Pydantic models in routers and canonical normalizers in services
- policy and workflow evaluators validate modes/enum-like fields defensively

### File handling risks
- OCR extraction reads bytes/path/base64 from inputs with size limits
- async OCR fallback exists for larger payloads
- still potential resource spikes for malformed uploads if not capped upstream

### Prompt injection / AI security considerations
- deterministic guardians include prompt/jailbreak/sensitive/tool output patterns
- runtime intelligence detects repeated prompt injection and related patterns
- copy/paste and data transfer controls add browser-layer safeguards

### Logging/privacy concerns
- audit/evidence payloads can include rich context; redaction quality is module-dependent
- potential over-capture risk in metadata_json/payload fields if upstream sanitation is incomplete

### Tenancy risks
- no DB-level RLS in repository; app-layer scoping must remain consistent

### Client-side exposure risks
- localStorage session in frontend
- extension token persisted in extension storage

### Security gap priorities (practical)
1. move frontend token storage away from localStorage (HTTP-only cookie/session proxy approach)
2. tighten sensitive payload redaction and centralize payload scrubbing before audit/evidence writes
3. harden extension credential storage lifecycle and rotation workflows
4. enforce stronger production-secret checks at startup
5. add explicit DB-level tenancy guardrails where feasible

---

## 16. Runtime, Environments, and Deployment
### Local development setup (implemented)
- Docker compose in `infra/docker-compose.yml`
- Podman compose in `infra/podman-compose.yml`
- seed scripts under `infra/scripts/seed.py` (+ e2e fixture seed)

### Expected services
- DB, Redis, API, worker, scheduler/beat, web

### Key environment variables (purpose-level)
- `DATABASE_URL`, `REDIS_URL`, `CELERY_BROKER_URL`, `CELERY_RESULT_BACKEND`
- `SECRET_KEY`, token expiry and JWT settings
- LLM provider keys/models (`OPENAI_*`, `ANTHROPIC_*`, `GEMINI_*`, `LLM_*`)
- platform strictness flags (`FAIL_SECURE_MODE`, `GOVERNANCE_STRICT_MODE`, `CONTROL_PLANE_STRICT_DEPENDENCY_CHECKS`)
- runtime intelligence/remediation toggles (`RUNTIME_INTELLIGENCE_ENABLED`, `REMEDIATION_*`)
- frontend API and fallback toggles (`NEXT_PUBLIC_API_URL`, `NEXT_PUBLIC_DEMO_*`)

### Build/runtime assumptions
- backend Python env includes SQLAlchemy, Alembic, FastAPI, Celery dependencies
- web requires Node/npm
- extension requires Node toolchain for build/test

### Deployment target (inferred)
- containerized deployment model (Docker/Podman compatible)
- no Kubernetes manifests in repo; orchestration beyond compose is **unclear**

### CI/CD assumptions
- GitHub Actions workflow for API unit+integration tests
- make targets and scripts support local/CI full-suite execution

### Environment separation
- `ENV`/`TEST_PROFILE` patterns exist
- explicit dev/staging/prod deployment templates are **partial** in repo

---

## 17. Observability and Operational Readiness
### Logging
- structured JSON logs via `log_structured` with correlation IDs
- HTTP middleware logs method/path/status/latency

### Monitoring and health
- `/health`
- `/system/control-plane-health`
- module health derived from DB/migration/redis/worker/beat/artifact checks
- Redis heartbeat keys for worker and beat liveness

### Audit trails
- append-only `audit_logs` enforced at model layer
- extensive audit writes across governance, enforcement, remediation, on-prem ingest

### Evidence trails
- evidence nodes/edges used as primary trace graph
- runtime normalization links source evidence -> runtime event evidence

### Debugging patterns
- correlation IDs propagated in headers and state
- many services include non-blocking exception logging for enrichment-only failures

### Operational gaps
- no explicit external metrics exporter stack in repository
- in-memory SSE broker has no persistence/backfill queue
- absence of documented SLO/SLA instrumentation beyond queue/approval checks

---

## 18. Current State Assessment
### What is strong
- Strong domain coverage across governance/enforcement/discovery/validation/audit.
- Deterministic enforcement and fail-secure posture are intentionally implemented.
- Cross-module traceability is materially present (audit + evidence + runtime IDs).
- Runtime Intelligence is correctly modeled as non-blocking enrichment.
- Test suite breadth is high across many domains.

### What is fragile
- High reliance on JSON payload fields for important state transitions.
- Large number of cross-module couplings makes change impact broad.
- Frontend token storage and demo fallback settings are risky if misused.
- SSE streaming is process-local and not horizontally robust.

### What is overly coupled
- Findings/remediation/runtime/auditor interdependence through shared payload semantics.
- Governance metadata conventions embedded in multiple services.

### What appears scalable
- Modular service/router organization can scale functionally.
- Queue-based monitoring/auditor/simulation tasks support asynchronous growth.
- Provider-catalog normalization is a scalable pattern vs per-provider ad hoc logic.

### What remains prototype-grade
- Some UI decision/explainability depth is still table/detail heavy vs analyst-grade investigation UX.
- On-prem gateway is a minimal architecture stub, not a full sovereign runtime.
- Connector depth appears mixed (some robust paths, some stubs).

### Enterprise production readiness (direct)
- **This is advanced prototype / pre-production architecture**, not final enterprise-hard deployment.
- It is credible and substantial, but still needs security hardening, schema tightening, and ops maturity work before high-assurance production.

---

## 19. Technical Debt and Risk Register

| Issue | Impact | Severity | Affected Modules | Recommended Remediation |
|---|---|---|---|---|
| Frontend JWT in localStorage | Token theft risk via XSS/client compromise | High | Web auth/session | Move to httpOnly cookie/session proxy model; CSP and sanitization hardening |
| State encoded in JSON (`metadata_json`/`payload`) for critical workflows | Query complexity, drift, migration brittleness | High | Trust center, remediation, runtime, findings | Promote high-value fields to typed columns and add migration-safe contracts |
| In-memory SSE broker | No durability; multi-instance stream inconsistency | High | Runtime Intelligence streaming/UI | Replace with broker-backed pub/sub (Redis streams/NATS/Kafka) + replay cursor |
| Demo fallback mode in frontend API client | Can hide real API/data failures during demos/UAT | Medium | Command center + module UIs | Default `NEXT_PUBLIC_DEMO_FALLBACK=false` outside explicit demo envs |
| Extension relies on host/domain/DOM heuristics | Detection/control regressions when target apps change UI behavior | Medium | Browser extension + runtime control | Increase domain adapters + resilient selectors + watchdog tests |
| Cross-module remediation complexity | Unintended side effects during auto-apply/rollback | High | Remediation engine, trust center, AI IAM, monitoring | Add stricter idempotency keys, dry-run mode, executor isolation tests |
| App-layer tenancy only | Missed tenant filters become data-leak risk | High | All backend modules | Add guardrails: scoped query helpers, lint/checks, optional DB RLS |
| OCR and detection optional dependencies | Behavior varies by environment, inconsistent detection quality | Medium | Sensitive data detection, runtime control | Explicit capability matrix endpoint + deterministic fallback policy |
| Brain module coupled to external provider keys | Runtime failures if keys unavailable; mixed deterministic/non-deterministic expectations | Medium | Brain services/routes | Separate operational profile and feature flag in non-brain-critical deployments |
| Documentation drift vs rapid implementation | Onboarding and operations friction | Medium | Whole platform | Keep `ARCHITECTURE.md` and runbooks updated through CI guard/checklist |

---

## 20. Recommended Near-Term Refactor Priorities
1. **Security hardening first**
   - eliminate localStorage access tokens in web app
   - centralize payload redaction before audit/evidence writes
2. **Stabilize data contracts**
   - reduce critical-state dependence on free-form JSON fields
   - introduce typed state columns for lifecycle/remediation/gov transitions
3. **Harden runtime streaming architecture**
   - move SSE publish transport to shared broker with replay capability
4. **Tighten remediation safety controls**
   - idempotency keys, rollback verification contracts, stronger approval matrix tests
5. **Connector and extension reliability pass**
   - strengthen provider/domain adapters and cross-surface normalization invariants
6. **Operational maturity**
   - add external metrics/exporter integration and SLO dashboards
7. **Documentation discipline**
   - make architecture/runbook updates mandatory with major module changes

---

## 21. Handoff Notes for Future Engineers
### Where to start reading
1. `apps/api/app/main.py`
2. `apps/api/app/core/config.py`
3. `apps/api/app/api/routers/gateway.py`
4. `apps/api/app/services/governance_resolution.py`
5. `apps/api/app/services/runtime_intelligence/runtime_event_normalizer.py`
6. `apps/api/app/services/remediation/remediation_engine.py`
7. `apps/web/src/lib/api.ts`
8. `extension/src/service-worker.ts`

### Critical files and why
- Governance defaults and unknown-system handling are centralized in `governance_resolution.py`.
- Deterministic enforcement behavior is spread across gateway/runtime-control services.
- Runtime Intelligence non-blocking behavior and canonical schema are in runtime normalizer and streaming services.
- Cross-cutting audit/evidence writes are reused by nearly every module.

### Dangerous assumptions
- Assuming all lifecycle/governance state is in strongly typed DB columns (it is not).
- Assuming stream consumers can always reconstruct missed events from SSE alone (they cannot).
- Assuming demo fallback data means backend is healthy.

### Hidden coupling
- `metadata_json` conventions are shared implicitly by many services and UIs.
- Findings, runtime recommendations, remediation, and auditor traces share IDs and payload structures informally.

### What must be preserved during refactors
- Fail-secure semantics for critical enforcement paths.
- Unknown AI system default behavior should never be treated as approved by default.
- Audit/evidence traceability chain integrity.
- Runtime Intelligence must remain non-blocking.

### What should be modularized next
- Remediation executors into more explicit adapters per target domain.
- Governance/lifecycle state representation into typed models.
- Streaming/event bus abstraction for scale-out.

---

## 22. Appendix: Key Files and Their Roles
This is a curated, high-signal list.

### Backend core
- `apps/api/app/main.py` – API bootstrap, middleware, router registration.
- `apps/api/app/core/config.py` – global runtime settings and feature flags.
- `apps/api/app/core/auth.py` – JWT auth dependency.
- `apps/api/app/core/tenant.py` – tenant membership enforcement.
- `apps/api/app/core/rbac.py` – role hierarchy and route guards.
- `apps/api/app/core/observability.py` – structured logging and latency tracking.

### Governance/enforcement
- `apps/api/app/api/routers/ai_systems.py` – AI system lifecycle/risk updates and transition blocks.
- `apps/api/app/api/routers/gateway.py` – LLM/MCP gateway endpoints.
- `apps/api/app/services/governance_resolution.py` – authoritative status resolution for AI systems.
- `apps/api/app/services/guardian_policy_engine.py` – canonical guardian policy evaluation.
- `apps/api/app/services/workflow_policy_service.py` – workflow-level restrictions.
- `apps/api/app/services/fail_secure_service.py` – dependency/governance fail-secure behavior.

### Runtime intelligence
- `apps/api/app/services/runtime_intelligence/schemas.py` – canonical runtime event models.
- `apps/api/app/services/runtime_intelligence/runtime_event_normalizer.py` – multi-source normalization and enrichment.
- `apps/api/app/services/runtime_intelligence/context_graph_service.py` – context/chain graph building.
- `apps/api/app/services/runtime_intelligence/runtime_correlation_service.py` – correlation candidate generation.
- `apps/api/app/services/runtime_intelligence/runtime_risk_scoring.py` – risk scoring.
- `apps/api/app/services/runtime_intelligence/simulation_trigger_service.py` – trigger generation.
- `apps/api/app/services/runtime_intelligence/streaming.py` – SSE broker.
- `apps/api/app/api/routers/runtime_intelligence.py` – RI query + stream endpoints.

### Discovery and IAM
- `apps/api/app/api/routers/shadow_ai.py` – shadow entity/signal APIs and ingest surfaces.
- `apps/api/app/services/shadow_ai/identity_resolution_service.py` – entity correlation.
- `apps/api/app/services/provider_catalog/__init__.py` – canonical provider/surface catalog.
- `apps/api/app/api/routers/ai_iam.py` – agent identity/token/delegation/kill-switch APIs.
- `apps/api/app/services/ai_iam_service.py` – IAM logic and enforcement support.

### Remediation and audit
- `apps/api/app/services/remediation/remediation_engine.py` – cross-cutting remediation planning/execution.
- `apps/api/app/api/routers/findings.py` – findings and remediation action APIs.
- `apps/api/app/api/routers/auditor.py` – snapshots, remediation trace, control posture, exports.
- `apps/api/app/services/snapshot_service.py` – artifact and snapshot creation.
- `apps/api/app/db/models/audit.py` – immutable audit log model behavior.
- `apps/api/app/db/models/evidence.py` – evidence graph nodes/edges.

### Jobs and operations
- `apps/api/app/jobs/celery_app.py` – queues, retries, schedules, heartbeats.
- `apps/api/app/services/control_plane_health_service.py` – dependency health checks.
- `apps/api/app/api/routers/system.py` – health/platform mode APIs.

### Frontend
- `apps/web/src/components/sidebar.tsx` – module navigation and role filtering.
- `apps/web/src/components/topbar.tsx` – tenant/session display.
- `apps/web/src/lib/api.ts` – typed backend client + token refresh + demo fallback.
- `apps/web/src/hooks/use-runtime-intelligence-stream.ts` – SSE consumption and reconnect.
- `apps/web/src/app/dashboard/command-center/page.tsx` – aggregated executive dashboard.
- `apps/web/src/app/runtime-intelligence/*` – RI module pages.
- `apps/web/src/app/ai-iam/page.tsx` – IAM dashboard + activity map/timeline integration.
- `apps/web/src/app/shadow-ai/page.tsx` – shadow AI ingestion/exploration workflows.

### Extension
- `extension/manifest.json` – MV3 permissions, CSP, content scripts.
- `extension/src/service-worker.ts` – policy sync, telemetry queue, backend messaging, health reporting.
- `extension/src/content-script.ts` – domain/prompt/data-transfer interception.
- `extension/src/interactions/data-transfer-hooks.ts` – copy/paste control logic and justification handling.
- `extension/src/telemetry.ts` – event contracts and backend posting.
- `extension/tests/e2e/browser-extension*.spec.ts` – unpacked-extension Playwright tests.

### Infra and CI
- `infra/docker-compose.yml` – local multi-service runtime.
- `infra/podman-compose.yml` – rootless podman variant.
- `infra/docker-compose.test.yml` – deterministic e2e stack.
- `infra/scripts/run_e2e_harness.sh` – e2e orchestration.
- `.github/workflows/api-tests.yml` – CI unit + integration workflow.
- `Makefile` – test and platform operation entrypoints.

---

Last reviewed based on repository state: **March 29, 2026**.
