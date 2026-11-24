# Brain Phase 1 (API-Based)

> Imported reference documentation from the selected original worktree. Prior deployment, version and test claims below are historical source context, not current acceptance. See [the collaboration README](../README.md) for verified results and remaining limits. Commands require an isolated, explicitly configured environment.


## Tool Registry

`apps/api/app/services/brain/tools.py` contains the MCP-style tool registry.

Registered tools:

- `governance.list_ai_systems`
- `governance.get_ai_system`
- `policies.get_policy_version`
- `policies.get_guardian_matrix`
- `evidence.query`
- `enforcement.list_events`
- `simulations.list_for_control`
- `simulations.run`
- `auditor.create_snapshot`
- `auditor.export_snapshot`
- `ops.jobs_status`

Each tool:

- accepts JSON args
- enforces minimum role (`viewer|auditor|operator`)
- returns structured JSON only
- executes server-side against services/models (never through routers)

## Plan Schema

`apps/api/app/services/brain/schemas.py`

- `BrainPlanStep`
  - `step_id`
  - `tool`
  - `args`
  - `expect_schema`
  - `on_error` (`stop|continue_with_warning`)
- `BrainPlan`
  - `plan_id`
  - `question`
  - `steps[]`

Planner (`planner.py`) uses `LLMProvider.generate_json(...)` with strict JSON schema validation and rejects unknown tools.
Planner post-validation guardrails enforce:

- evidence-first plans (ensures `evidence.query` exists)
- enforcement questions include `enforcement.list_events`
- audit/compliance proof questions include `auditor.create_snapshot`

## Citation Rules

Executor (`executor.py`) collects citations only from:

- `evidence_node_ids` / `evidence_node_id`
- `snapshot_ids` / `snapshot_id`

Citation types:

- `evidence_node`
- `snapshot`

Summarizer (`summarizer.py`) enforces:

- answer must be based only on executed tool results
- no success response without citations
- each factual paragraph must include citation marker `[citation_id]`
- if missing evidence: answer is exactly `INSUFFICIENT EVIDENCE`

## Safety / Non-Hallucination

- Planner can only propose tool steps (no outcome claims).
- Executor stores raw tool outputs and never fabricates results.
- Summarizer refuses when evidence is missing or uncited.

## Persistence

Alembic migration:

- `apps/api/app/db/migrations/versions/0008_brain_phase1_tables.py`

Tables:

- `brain_session`
- `brain_plan`
- `brain_tool_call`

## Adding New Tools Safely

1. Add tool handler in `tools.py` that returns JSON object only.
2. Add tool to `TOOL_REGISTRY` with explicit `min_role`.
3. Keep tenant scoping in all DB queries.
4. Include output fields that expose verifiable citations (`evidence_node_ids`, `snapshot_ids`) whenever possible.
5. Add tests proving:
   - role enforcement
   - no cross-tenant access
   - deterministic output shape
