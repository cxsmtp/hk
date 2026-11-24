import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

const mapperUrl = new URL("../src/components/command-center/command-center-visual-mappers.ts", import.meta.url);
const transpiled = ts.transpileModule(readFileSync(mapperUrl, "utf8"), {
  compilerOptions: { module: ts.ModuleKind.ES2022, target: ts.ScriptTarget.ES2022 },
});
const { deriveGovernanceOverview, mapEvidenceRiverEvents } = await import(
  `data:text/javascript;base64,${Buffer.from(transpiled.outputText).toString("base64")}`
);

const evidence = {
  evidence_refs: ["receipt:1"],
  evidence_bundle_id: "bundle-1",
  trace_id: "trace-1",
};

const dashboard = {
  generated_at: "2026-08-10T08:00:00Z",
  runtime_heatmap: {
    rows: [
      { surface: "Browser", counts: { block: 1, allow: 2 }, total: 3 },
      { surface: "MCP", counts: { block: 1 }, total: 1 },
    ],
  },
  live_activity_feed: {
    items: [
      {
        event_id: "event-older",
        timestamp: "2026-08-10T07:55:00Z",
        ai_surface: "browser",
        action_type: "prompt_submit",
        policy_decision: "allow",
        risk_score: 0.1,
        trace_url: "/runtime-intelligence/action-trace?event_id=event-older",
      },
      {
        event_id: "event-newer",
        timestamp: "2026-08-10T07:59:00Z",
        ai_surface: "mcp",
        application: "Codex",
        action_type: "pull_request_read",
        tool_name: "github",
        policy_decision: "block",
        risk_score: 0.8,
        finding_id: "finding-1",
        trace_url: "/runtime-intelligence/action-trace?event_id=event-newer",
        finding_url: "/discovery/findings/finding-1",
        decision_explanation: { evidence },
      },
      {
        event_id: "event-newer",
        timestamp: "2026-08-10T07:59:00Z",
        ai_surface: "mcp",
        action_type: "duplicate",
        policy_decision: "block",
        risk_score: 0.8,
        trace_url: "/duplicate",
      },
    ],
    total: 3,
  },
  ai_action_control: {
    total_actions: 3,
    control_mode_counts: { inline_verified: 1, detected_only: 2 },
    evidence_status_counts: { complete: 1, incomplete: 2 },
    high_risk_actions: 1,
    review_required: 0,
    top_actions: [],
    drilldown: "/runtime-intelligence/overview",
  },
  surface_coverage_summary: {
    surface_rows: [
      {
        id: "browser",
        label: "Browser",
        surface_type: "browser",
        coverage: "covered",
        primary_control: "Extension",
        proof_label: "Inline receipts",
        drilldown: "/surface-coverage#browser",
        current_mode: "inline_verified",
        status: "active",
        event_count: 3,
        blocked: 1,
        warned: 0,
        inline_prevented: 1,
        inline_allowed: 2,
        shadow_would_block: 0,
        detected_only: 0,
        telemetry_only: 0,
        external_required: 0,
        external_action_triggered: 0,
        incomplete: 0,
        mode_counts: { inline_verified: 3 },
        apps: ["Chrome"],
        agents: [],
        users: ["user-1"],
      },
      {
        id: "foundry",
        label: "Microsoft Foundry",
        surface_type: "foundry",
        coverage: "partial",
        primary_control: "Collector",
        proof_label: "Inventory only",
        drilldown: "/surface-coverage#foundry",
        current_mode: "detected_only",
        status: "active",
        event_count: 1,
        blocked: 0,
        warned: 0,
        inline_prevented: 0,
        inline_allowed: 0,
        shadow_would_block: 0,
        detected_only: 1,
        telemetry_only: 0,
        external_required: 1,
        external_action_triggered: 0,
        incomplete: 0,
        mode_counts: { detected_only: 1 },
        apps: [],
        agents: [],
        users: [],
      },
    ],
    totals: { inline_verified: 3, detected_only: 1, external_required: 1 },
    drilldown: "/surface-coverage",
  },
  simulations: {
    total_runs: 4,
    pass_count: 3,
    fail_count: 1,
    fail_rate_percent: 25,
    recent_runs: [],
    drilldown: "/validation/coverage",
  },
  control_coverage: {
    average_maturity: 0.7,
    average_technical_enforcement: 0.6,
    average_simulation_pass_rate: 0.75,
    average_coverage_score: 0.65,
    status_counts: {},
    lowest_controls: [
      { control_id: "AUTH-1", maturity_score: 0.6, technical_enforcement_score: 0.5, simulation_pass_rate: 0.75, coverage_score: 0.5, status: "partial" },
      { control_id: "DATA-2", maturity_score: 0.8, technical_enforcement_score: 0.7, simulation_pass_rate: 0.5, coverage_score: 0.7, status: "partial" },
      { control_id: "TOOL-3", maturity_score: 0.7, technical_enforcement_score: 0.8, simulation_pass_rate: 1, coverage_score: 0.75, status: "covered" },
    ],
    drilldown: "/validation/coverage",
  },
  risk_over_time: { points: [], drilldown: "/runtime-intelligence/overview" },
};

test("river events are deduplicated, chronological, evidence-aware, and bounded", () => {
  const many = Array.from({ length: 14 }, (_, index) => ({
    event_id: `event-${index}`,
    timestamp: `2026-08-10T07:${String(index).padStart(2, "0")}:00Z`,
    ai_surface: "browser",
    action_type: "prompt_submit",
    policy_decision: "allow",
    risk_score: 0,
    trace_url: `/trace/${index}`,
  }));
  many.push(many[13]);

  const events = mapEvidenceRiverEvents(many, 12);
  assert.equal(events.length, 12);
  assert.equal(new Set(events.map((item) => item.id)).size, 12);
  assert.equal(events[0].id, "event-2");
  assert.equal(events.at(-1).id, "event-13");
});

test("overview separates observed estate, inline authority, monitor-only, and proof", () => {
  const overview = deriveGovernanceOverview(dashboard);

  assert.equal(overview.discovery.observedEvents, 4);
  assert.equal(overview.discovery.totalEstateKnown, false);
  assert.equal(overview.protect.inlineVerified, 1);
  assert.equal(overview.protect.monitorOnly, 1);
  assert.equal(overview.validate.executedRuns, 4);
  assert.equal(overview.validate.passRate, 75);
  assert.deepEqual(overview.validate.profile[0], { control: "AUTH-1", observed: 50, simulated: 75 });
  assert.equal(overview.prove.evidenceLinkedActions, 1);
  assert.equal(overview.river.at(-1).id, "event-newer");
  assert.equal(overview.river.at(-1).kind, "enforcement");
  assert.equal(overview.river.at(-1).evidenceState, "verified");
});

test("missing denominators and missing simulation execution remain unknown", () => {
  const overview = deriveGovernanceOverview({
    runtime_heatmap: { rows: [] },
    live_activity_feed: { items: [], total: 0 },
    surface_coverage_summary: { surface_rows: [], drilldown: "/surface-coverage" },
    simulations: { total_runs: 0, pass_count: 0, fail_count: 0, fail_rate_percent: 0, recent_runs: [], drilldown: "/validation/coverage" },
    risk_over_time: { points: [], drilldown: "/runtime-intelligence/overview" },
  });

  assert.equal(overview.discovery.totalEstateKnown, false);
  assert.equal(overview.discovery.observedEvents, 0);
  assert.equal(overview.validate.passRate, null);
  assert.equal(overview.prove.evidenceLinkedActions, 0);
  assert.equal(overview.protect.unknown, 0);
});
