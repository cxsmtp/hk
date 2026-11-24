import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import ts from "typescript";

async function loadModule() {
  const source = readFileSync(new URL("../src/lib/governed-session-state.ts", import.meta.url), "utf8");
  const result = ts.transpileModule(source, {
    compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    reportDiagnostics: true,
  });
  assert.deepEqual((result.diagnostics || []).filter((item) => item.category === ts.DiagnosticCategory.Error), []);
  return import(`data:text/javascript;base64,${Buffer.from(result.outputText).toString("base64")}`);
}

test("governed state requires inline control, identity, current policy, fresh heartbeat and evidence", async () => {
  const { deriveGovernanceState } = await loadModule();
  const proof = {
    controlMode: "inline_allowed",
    identityResolved: true,
    policyAttached: true,
    policyCurrent: true,
    heartbeatFresh: true,
    evidencePresent: true,
  };
  assert.equal(deriveGovernanceState(proof).state, "governed");
  assert.equal(deriveGovernanceState({ ...proof, controlMode: "detected_only" }).state, "monitor_only");
  assert.equal(deriveGovernanceState({ ...proof, evidencePresent: false }).state, "partially_governed");
  assert.equal(deriveGovernanceState({ ...proof, identityResolved: false }).state, "unknown");
  assert.equal(deriveGovernanceState({ ...proof, heartbeatFresh: false }).state, "disconnected");
});

test("token usage keeps exact, estimated and unknown provenance honest", async () => {
  const { deriveTokenUsage } = await loadModule();
  assert.deepEqual(deriveTokenUsage({ prompt_tokens: 12, completion_tokens: 8, total_tokens: 20 }), {
    input: 12, output: 8, cached: null, total: 20, provenance: "exact",
  });
  assert.deepEqual(deriveTokenUsage({ estimated_prompt_tokens: 9, estimated_completion_tokens: 4 }), {
    input: 9, output: 4, cached: null, total: 13, provenance: "estimated",
  });
  assert.deepEqual(deriveTokenUsage({ prompt_chars: 401, output_chars: 99 }), {
    input: 101, output: 25, cached: null, total: 126, provenance: "estimated",
  });
  assert.deepEqual(deriveTokenUsage({
    prompt_preview_redacted: "Summarize this approved client-side prompt metadata.",
    output_text_preview_redacted: "Short answer.",
  }), {
    input: 13, output: 4, cached: null, total: 17, provenance: "estimated",
  });
  assert.deepEqual(deriveTokenUsage({}), {
    input: null, output: null, cached: null, total: null, provenance: "unknown",
  });
});

test("session spend keeps billed, rate-card and unknown provenance honest", async () => {
  const { deriveCostUsage } = await loadModule();
  assert.deepEqual(deriveCostUsage({
    usage: {
      cost: { amount: 0.0042, currency: "USD", source: "PROVIDER_BILLED" },
    },
    cost_usage_verified: true,
  }), {
    amount: 0.0042,
    currency: "USD",
    provenance: "exact",
    source: "provider_billed",
  });
  assert.deepEqual(deriveCostUsage({
    usage: { input_tokens: 1000, output_tokens: 500 },
    rate_card: {
      input_usd_per_million: 3,
      output_usd_per_million: 15,
      reference: "customer-rate-card-2026-09",
    },
  }), {
    amount: 0.0105,
    currency: "USD",
    provenance: "estimated",
    source: "customer_rate_card",
  });
  assert.deepEqual(deriveCostUsage({
    prompt_chars: 400,
    output_chars: 200,
    rate_card: {
      input_usd_per_million: 2,
      output_usd_per_million: 10,
      reference: "customer-rate-card-client-estimate",
    },
  }), {
    amount: 0.0007,
    currency: "USD",
    provenance: "estimated",
    source: "customer_rate_card",
  });
  assert.deepEqual(deriveCostUsage({
    usage: { cost: { amount: 0.0019, currency: "usd", source: "CLIENT_ESTIMATE" } },
  }), {
    amount: 0.0019,
    currency: "USD",
    provenance: "estimated",
    source: "client_estimate",
  });
  assert.deepEqual(deriveCostUsage({ cost_usd: 0.5 }), {
    amount: null,
    currency: null,
    provenance: "unknown",
    source: "unknown",
  });
  assert.deepEqual(deriveCostUsage({}), {
    amount: null,
    currency: null,
    provenance: "unknown",
    source: "unknown",
  });
});

test("session grouping never merges events without a verified shared key", async () => {
  const { sessionKeyForEvent } = await loadModule();
  assert.equal(sessionKeyForEvent({ event_id: "evt-1", metadata: { session_id: "session-a" } }), "session:session-a");
  assert.equal(sessionKeyForEvent({ event_id: "evt-2", correlation_id: "corr-a" }), "correlation:corr-a");
  assert.equal(sessionKeyForEvent({ event_id: "evt-3" }), "event:evt-3");
});
